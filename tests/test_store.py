"""Transaction versioning and database migration tests."""

from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.store import Store
from app.sync import (
    ingest_payment,
    parse_ts_ms,
    retry_missing_thumbnails,
    sync_payments,
)

CAMERA_ID = "cam1aaaaaaaaaaaaaaaaaaaaa"
CAMERA_B = "cam2bbbbbbbbbbbbbbbbbbbbb"


class _ProtectStub:
    def get_snapshot(self, camera_id, ts_ms=None):
        return f"snapshot:{camera_id}:{ts_ms}".encode()


class _SquareStub:
    def __init__(self, payments, locations=("LOC_OLD",)):
        self.payments = payments
        self.params = None
        self.locations = list(locations)

    def list_locations(self):
        return [{"id": loc} for loc in self.locations]

    def iter_payment_pages(self, **params):
        yield self.list_payments(**params)

    def list_payments(self, **params):
        self.params = params
        return self.payments


def _payment(
    updated_at: str,
    *,
    amount: int,
    currency: str,
    status: str,
    location_id: str,
    card_last4: str,
    receipt_url: str,
    device_id: str = "",
    device_name: str = "",
) -> dict:
    payment = {
        "id": "PAY_VERSIONED",
        "created_at": "2026-07-16T15:00:00.000Z",
        "updated_at": updated_at,
        "amount_money": {"amount": amount, "currency": currency},
        "status": status,
        "location_id": location_id,
        "card_details": {"card": {"last_4": card_last4}},
        "receipt_url": receipt_url,
        "version_marker": status.lower(),
    }
    if device_id or device_name:
        payment["device_details"] = {
            "device_id": device_id,
            "device_name": device_name,
        }
    return payment


def test_newer_payment_refreshes_all_mutable_fields(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    pending = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/pending",
    )
    completed = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=725,
        currency="CAD",
        status="COMPLETED",
        location_id="LOC_NEW",
        card_last4="2222",
        receipt_url="https://square.example/completed",
    )
    completed.update(
        {
            "buyer_email_address": "buyer@example.com",
            "billing_address": {"address_line_1": "123 Private Street"},
            "card_details": {
                "card": {
                    "last_4": "2222",
                    "fingerprint": "CARD_FINGERPRINT_PRIVATE",
                },
                "wallet_details": {"brand": "WALLET_PRIVATE"},
            },
            "customer_id": "CUSTOMER_PRIVATE",
            "note": "private order note",
            "risk_evaluation": {"risk_level": "RISK_LEVEL_PRIVATE"},
        }
    )

    try:
        ingest_payment(store, pending, protect=_ProtectStub())
        ingest_payment(store, completed, protect=_ProtectStub())
        stored = store.get_transaction("PAY_VERSIONED")
    finally:
        store.close()

    assert stored["updated_at"] == completed["updated_at"]
    assert stored["updated_ts_ms"] == parse_ts_ms(completed["updated_at"])
    assert stored["amount"] == 725
    assert stored["currency"] == "CAD"
    assert stored["status"] == "COMPLETED"
    assert stored["location_id"] == "LOC_NEW"
    assert stored["card_last4"] == "2222"
    assert stored["receipt_url"] == "https://square.example/completed"
    # The corrected location has no camera mapping, so evidence from the old
    # location must no longer be presented as belonging to this payment.
    assert stored["camera_id"] is None
    assert stored["thumbnail_path"] is None
    assert stored["raw"] == "{}"
    database_bytes = (tmp_path / "data" / "spi.db").read_bytes()
    assert b"buyer@example.com" not in database_bytes
    assert b"123 Private Street" not in database_bytes
    assert b"CARD_FINGERPRINT_PRIVATE" not in database_bytes
    assert b"WALLET_PRIVATE" not in database_bytes
    assert b"CUSTOMER_PRIVATE" not in database_bytes
    assert b"private order note" not in database_bytes
    assert b"RISK_LEVEL_PRIVATE" not in database_bytes


def test_newer_device_correction_requeues_camera_evidence(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Location fallback")
    store.set_camera_mapping(
        "LOC_OLD",
        CAMERA_B,
        "Register B camera",
        device_id="TERM_B",
        device_name="Register B",
    )
    fallback_payment = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/original",
    )
    corrected_device = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/corrected",
        device_id="TERM_B",
        device_name="Register B",
    )

    try:
        ingest_payment(store, fallback_payment, protect=_ProtectStub())
        original = store.get_transaction("PAY_VERSIONED")
        assert original["camera_id"] == CAMERA_ID
        assert original["thumbnail_path"].startswith("PAY_VERSIONED-")

        # Webhooks persist without a Protect client; the durable queue must
        # replace the fallback evidence on its background pass.
        ingest_payment(store, corrected_device, protect=None)
        queued = store.get_transaction("PAY_VERSIONED")
        assert queued["device_id"] == "TERM_B"
        assert queued["camera_id"] == CAMERA_B
        assert queued["thumbnail_path"] is None

        assert retry_missing_thumbnails(store, _ProtectStub(), now=0) == 1
        corrected = store.get_transaction("PAY_VERSIONED")
        image = (store.thumbnail_dir / corrected["thumbnail_path"]).read_bytes()
    finally:
        store.close()

    assert corrected["camera_id"] == CAMERA_B
    assert image == f"snapshot:{CAMERA_B}:{corrected['ts_ms']}".encode()


def test_device_correction_without_name_clears_previous_device_name(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping(
        "LOC_OLD",
        CAMERA_ID,
        "Register A camera",
        device_id="TERM_A",
        device_name="Register A",
    )
    store.set_camera_mapping(
        "LOC_OLD",
        CAMERA_B,
        "Register B camera",
        device_id="TERM_B",
        device_name="Register B",
    )
    original = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/original",
        device_id="TERM_A",
        device_name="Register A",
    )
    corrected = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/corrected",
        device_id="TERM_B",
    )
    corrected["device_details"].pop("device_name")

    try:
        ingest_payment(store, original, protect=None)
        ingest_payment(store, corrected, protect=None)
        stored = store.get_transaction("PAY_VERSIONED")
    finally:
        store.close()

    assert stored["device_id"] == "TERM_B"
    assert stored["device_name"] == ""
    assert stored["camera_id"] == CAMERA_B


def test_same_device_update_without_name_preserves_device_name(tmp_path):
    store = Store(tmp_path / "data")
    original = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/original",
        device_id="TERM_A",
        device_name="Register A",
    )
    sparse = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/completed",
        device_id="TERM_A",
    )
    sparse["device_details"].pop("device_name")

    try:
        ingest_payment(store, original, protect=None)
        ingest_payment(store, sparse, protect=None)
        stored = store.get_transaction("PAY_VERSIONED")
    finally:
        store.close()

    assert stored["device_id"] == "TERM_A"
    assert stored["device_name"] == "Register A"


def test_newer_location_correction_recaptures_camera_evidence(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Old location")
    store.set_camera_mapping("LOC_NEW", CAMERA_B, "Corrected location")
    original = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/original",
    )
    corrected = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_NEW",
        card_last4="1111",
        receipt_url="https://square.example/corrected",
    )

    try:
        ingest_payment(store, original, protect=_ProtectStub())
        ingest_payment(store, corrected, protect=_ProtectStub())
        stored = store.get_transaction("PAY_VERSIONED")
        image = (store.thumbnail_dir / stored["thumbnail_path"]).read_bytes()
    finally:
        store.close()

    assert stored["location_id"] == "LOC_NEW"
    assert stored["camera_id"] == CAMERA_B
    assert image == f"snapshot:{CAMERA_B}:{stored['ts_ms']}".encode()


def test_stale_device_correction_cannot_replace_camera_evidence(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Location fallback")
    store.set_camera_mapping(
        "LOC_OLD",
        CAMERA_B,
        "Register B camera",
        device_id="TERM_B",
        device_name="Register B",
    )
    accepted = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/accepted",
    )
    stale = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=400,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="2222",
        receipt_url="https://square.example/stale",
        device_id="TERM_B",
        device_name="Register B",
    )

    class UnexpectedProtectCall:
        def get_snapshot(self, camera_id, ts_ms=None):
            raise AssertionError("stale versions must not request new evidence")

    try:
        ingest_payment(store, accepted, protect=_ProtectStub())
        before = store.get_transaction("PAY_VERSIONED")
        before_image = (store.thumbnail_dir / before["thumbnail_path"]).read_bytes()
        ingest_payment(store, stale, protect=UnexpectedProtectCall())
        after = store.get_transaction("PAY_VERSIONED")
        after_image = (store.thumbnail_dir / after["thumbnail_path"]).read_bytes()
    finally:
        store.close()

    assert after == before
    assert after_image == before_image


def test_older_payment_update_cannot_regress_state(tmp_path):
    store = Store(tmp_path / "data")
    completed = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=725,
        currency="CAD",
        status="COMPLETED",
        location_id="LOC_NEW",
        card_last4="2222",
        receipt_url="https://square.example/completed",
    )
    stale_pending = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/pending",
    )
    stale_pending["created_at"] = "2026-07-16T09:00:00.000Z"

    try:
        ingest_payment(store, completed, protect=None)
        before = store.get_transaction("PAY_VERSIONED")
        ingest_payment(store, stale_pending, protect=None)
        after = store.get_transaction("PAY_VERSIONED")
    finally:
        store.close()

    assert after == before


def test_sync_polls_old_payment_by_updated_at(tmp_path):
    store = Store(tmp_path / "data")
    old_pending = _payment(
        "2026-07-16T15:00:00.000Z",
        amount=500,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/pending",
    )
    old_pending["created_at"] = "2026-06-01T12:00:00.000Z"
    recent_payment = _payment(
        "2026-07-16T15:04:00.000Z",
        amount=900,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_NEW",
        card_last4="2222",
        receipt_url="https://square.example/recent",
    )
    recent_payment["id"] = "PAY_RECENT"
    recent_payment["created_at"] = "2026-07-16T14:59:00.000Z"
    old_completed = _payment(
        "2026-07-16T15:05:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/completed",
    )
    old_completed["created_at"] = old_pending["created_at"]
    square = _SquareStub([old_completed])

    try:
        ingest_payment(store, old_pending, protect=None)
        ingest_payment(store, recent_payment, protect=None)
        store.advance_square_poll_watermark(
            "LOC_OLD", parse_ts_ms("2026-07-16T15:00:00.000Z")
        )
        assert sync_payments(store, square, protect=None) == 0
        stored = store.get_transaction("PAY_VERSIONED")
    finally:
        store.close()

    assert square.params == {
        "updated_at_begin_time": "2026-07-16T14:55:00Z",
        "sort_field": "UPDATED_AT",
        "sort_order": "ASC",
        "location_id": "LOC_OLD",
    }
    assert stored["created_at"] == "2026-06-01T12:00:00.000Z"
    assert stored["updated_at"] == "2026-07-16T15:05:00.000Z"
    assert stored["status"] == "COMPLETED"
    assert stored["receipt_url"] == "https://square.example/completed"


def test_sync_restart_does_not_skip_older_updates_after_mid_batch_failure(
    tmp_path, monkeypatch
):
    base = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(hours=1)

    def payment(payment_id: str, minutes: int) -> dict:
        timestamp = (base + timedelta(minutes=minutes)).isoformat().replace(
            "+00:00", "Z"
        )
        return {
            "id": payment_id,
            "created_at": timestamp,
            "updated_at": timestamp,
            "amount_money": {"amount": 100, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": "LOC_OLD",
        }

    payments = [
        payment("PAY_OLDEST", 0),
        payment("PAY_MIDDLE", 10),
        payment("PAY_NEWEST", 20),
    ]

    class FilteringSquare:
        def __init__(self):
            self.calls = []

        def list_locations(self):
            return [{"id": "LOC_OLD"}]

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

        def list_payments(
            self,
            *,
            updated_at_begin_time,
            sort_field,
            sort_order,
            location_id,
        ):
            self.calls.append(
                {
                    "updated_at_begin_time": updated_at_begin_time,
                    "sort_field": sort_field,
                    "sort_order": sort_order,
                    "location_id": location_id,
                }
            )
            begin_ms = parse_ts_ms(updated_at_begin_time)
            matching = [
                item
                for item in payments
                if parse_ts_ms(item["updated_at"]) >= begin_ms
            ]
            return sorted(
                matching,
                key=lambda item: parse_ts_ms(item["updated_at"]),
                reverse=sort_order == "DESC",
            )

    data_dir = tmp_path / "data"
    square = FilteringSquare()
    store = Store(data_dir)
    original_upsert = store.upsert_transaction

    def fail_on_middle(txn, **kwargs):
        if txn["id"] == "PAY_MIDDLE":
            raise RuntimeError("simulated database interruption")
        return original_upsert(txn, **kwargs)

    monkeypatch.setattr(store, "upsert_transaction", fail_on_middle)
    try:
        with pytest.raises(RuntimeError, match="simulated database interruption"):
            sync_payments(store, square, protect=None)
        assert store.get_square_poll_watermark("LOC_OLD") is None
        assert store.get_transaction("PAY_OLDEST") is not None
        assert store.get_transaction("PAY_MIDDLE") is None
        assert store.get_transaction("PAY_NEWEST") is None
    finally:
        store.close()

    restarted_store = Store(data_dir)
    try:
        assert sync_payments(restarted_store, square, protect=None) == 2
        assert restarted_store.get_square_poll_watermark("LOC_OLD") is not None
        assert all(
            restarted_store.get_transaction(item["id"]) is not None
            for item in payments
        )
    finally:
        restarted_store.close()

    assert [call["sort_order"] for call in square.calls] == ["ASC", "ASC"]


def test_newer_timestamp_recaptures_camera_evidence(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    original = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/pending",
    )
    corrected = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/completed",
    )
    corrected["created_at"] = "2026-07-16T08:30:00.000Z"

    try:
        ingest_payment(store, original, protect=_ProtectStub())
        ingest_payment(store, corrected, protect=_ProtectStub())
        stored = store.get_transaction("PAY_VERSIONED")
        image = (store.thumbnail_dir / stored["thumbnail_path"]).read_bytes()
    finally:
        store.close()

    corrected_ts_ms = parse_ts_ms(corrected["created_at"])
    assert stored["created_at"] == corrected["created_at"]
    assert stored["ts_ms"] == corrected_ts_ms
    assert stored["camera_id"] == CAMERA_ID
    assert image == f"snapshot:{CAMERA_ID}:{corrected_ts_ms}".encode()


def test_timestamp_correction_deletes_superseded_retry_thumbnail(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    original = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/pending",
    )
    corrected = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/completed",
    )
    corrected["created_at"] = "2026-07-16T08:30:00.000Z"

    try:
        ingest_payment(store, original, protect=None)
        assert retry_missing_thumbnails(store, _ProtectStub(), now=100) == 1
        old_name = store.get_transaction("PAY_VERSIONED")["thumbnail_path"]
        old_path = store.thumbnail_dir / old_name
        assert old_path.is_file()

        ingest_payment(store, corrected, protect=_ProtectStub())

        saved = store.get_transaction("PAY_VERSIONED")
        assert saved["thumbnail_path"] != old_name
        assert not old_path.exists()
        assert (store.thumbnail_dir / saved["thumbnail_path"]).is_file()
    finally:
        store.close()


def _stored_thumbnail(
    txn_id: str,
    ts_ms: int,
    updated_ts_ms: int,
    thumbnail_path: str,
) -> dict:
    timestamp = "2026-07-16T15:00:00.000Z"
    return {
        "id": txn_id,
        "created_at": timestamp,
        "ts_ms": ts_ms,
        "updated_at": timestamp,
        "updated_ts_ms": updated_ts_ms,
        "amount": 500,
        "currency": "USD",
        "status": "COMPLETED",
        "location_id": "LOC_OLD",
        "camera_id": CAMERA_ID,
        "thumbnail_path": thumbnail_path,
    }


def test_superseded_thumbnail_cleanup_preserves_shared_reference(tmp_path):
    store = Store(tmp_path / "data")
    shared_path = store.thumbnail_dir / "shared.jpg"
    replacement_path = store.thumbnail_dir / "replacement.jpg"
    shared_path.write_bytes(b"shared")
    replacement_path.write_bytes(b"replacement")
    try:
        store.upsert_transaction(_stored_thumbnail("PAY_A", 1000, 1000, "shared.jpg"))
        store.upsert_transaction(_stored_thumbnail("PAY_B", 1000, 1000, "shared.jpg"))

        store.upsert_transaction(
            _stored_thumbnail("PAY_A", 2000, 2000, "replacement.jpg")
        )

        assert shared_path.is_file()
        assert store.get_transaction("PAY_B")["thumbnail_path"] == "shared.jpg"
    finally:
        store.close()


def test_superseded_thumbnail_cleanup_preserves_newer_race_winner(
    tmp_path, monkeypatch
):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    racing_store = Store(data_dir)
    old_path = store.thumbnail_dir / "old.jpg"
    old_path.write_bytes(b"old")
    (store.thumbnail_dir / "replacement.jpg").write_bytes(b"replacement")
    store.upsert_transaction(_stored_thumbnail("PAY_A", 1000, 1000, "old.jpg"))
    unlink_if_unreferenced = store._unlink_thumbnail_if_unreferenced

    def install_newer_winner(thumbnail_path: str) -> bool:
        racing_store.upsert_transaction(
            _stored_thumbnail("PAY_A", 3000, 3000, thumbnail_path)
        )
        return unlink_if_unreferenced(thumbnail_path)

    monkeypatch.setattr(
        store, "_unlink_thumbnail_if_unreferenced", install_newer_winner
    )
    try:
        store.upsert_transaction(
            _stored_thumbnail("PAY_A", 2000, 2000, "replacement.jpg")
        )

        assert old_path.is_file()
        assert racing_store.get_transaction("PAY_A")["thumbnail_path"] == "old.jpg"
    finally:
        store.close()
        racing_store.close()


def test_superseded_thumbnail_delete_failure_does_not_rollback_update(
    tmp_path, monkeypatch, caplog
):
    store = Store(tmp_path / "data")
    old_path = store.thumbnail_dir / "old.jpg"
    old_path.write_bytes(b"old")
    (store.thumbnail_dir / "replacement.jpg").write_bytes(b"replacement")
    store.upsert_transaction(_stored_thumbnail("PAY_A", 1000, 1000, "old.jpg"))
    unlink = Path.unlink

    def fail_old_thumbnail(path: Path, *args, **kwargs):
        if path == old_path:
            raise OSError("disk is read-only")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_old_thumbnail)
    try:
        store.upsert_transaction(
            _stored_thumbnail("PAY_A", 2000, 2000, "replacement.jpg")
        )

        assert store.get_transaction("PAY_A")["thumbnail_path"] == "replacement.jpg"
        assert old_path.is_file()
        assert "Could not delete superseded thumbnail 'old.jpg'" in caplog.text
    finally:
        store.close()


def test_store_migrates_legacy_fields_and_scrubs_raw_payment(tmp_path):
    data_dir = tmp_path / "legacy"
    data_dir.mkdir()
    db = sqlite3.connect(data_dir / "spi.db")
    db.execute(
        """
        CREATE TABLE transactions (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            ts_ms INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            currency TEXT NOT NULL,
            status TEXT NOT NULL,
            location_id TEXT NOT NULL DEFAULT '',
            card_last4 TEXT NOT NULL DEFAULT '',
            receipt_url TEXT NOT NULL DEFAULT '',
            camera_id TEXT,
            thumbnail_path TEXT,
            raw TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    created_at = "2026-07-16T14:00:00.000Z"
    ts_ms = parse_ts_ms(created_at)
    db.execute(
        """
        INSERT INTO transactions (
            id, created_at, ts_ms, amount, currency, status, location_id,
            card_last4, receipt_url, camera_id, thumbnail_path, raw
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "PAY_LEGACY",
            created_at,
            ts_ms,
            900,
            "USD",
            "COMPLETED",
            "LOC_LEGACY",
            "4242",
            "https://square.example/legacy",
            "cam1aaaaaaaaaaaaaaaaaaaaa",
            "PAY_LEGACY.jpg",
            '{"legacy":true,"buyer_email_address":"buyer@example.com"}',
        ),
    )
    db.commit()
    db.close()
    thumbnail_dir = data_dir / "thumbnails"
    thumbnail_dir.mkdir()
    (thumbnail_dir / "PAY_LEGACY.jpg").write_bytes(b"legacy image")

    store = Store(data_dir)
    try:
        stored = store.get_transaction("PAY_LEGACY")
    finally:
        store.close()

    assert stored == {
        "id": "PAY_LEGACY",
        "created_at": created_at,
        "ts_ms": ts_ms,
        "amount": 900,
        "currency": "USD",
        "status": "COMPLETED",
        "location_id": "LOC_LEGACY",
        "card_last4": "4242",
        "receipt_url": "https://square.example/legacy",
        "camera_id": "cam1aaaaaaaaaaaaaaaaaaaaa",
        "thumbnail_path": "PAY_LEGACY.jpg",
        "raw": "{}",
        "updated_at": created_at,
        "updated_ts_ms": ts_ms,
        "device_id": "",
        "device_name": "",
        "alarm_state": "sent",
        "alarm_claim_token": None,
        "alarm_claimed_at": None,
    }


def test_stale_event_with_old_timestamp_cannot_overwrite_thumbnail_file(tmp_path):
    """A delayed out-of-order event carries the uncorrected sale time. The
    versioned upsert already ignores its row; the on-disk thumbnail must not
    be recaptured at the stale timestamp either."""
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    corrected = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/completed",
    )
    corrected["created_at"] = "2026-07-16T08:30:00.000Z"
    stale = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/pending",
    )
    stale["created_at"] = "2026-07-16T16:00:00.000Z"

    try:
        ingest_payment(store, corrected, protect=_ProtectStub())
        stored = store.get_transaction("PAY_VERSIONED")
        image_path = store.thumbnail_dir / stored["thumbnail_path"]
        image_before = image_path.read_bytes()

        ingest_payment(store, stale, protect=_ProtectStub())
        after = store.get_transaction("PAY_VERSIONED")
        image_after = image_path.read_bytes()
    finally:
        store.close()

    corrected_ts_ms = parse_ts_ms(corrected["created_at"])
    assert after["ts_ms"] == corrected_ts_ms
    assert image_after == image_before
    assert image_after == f"snapshot:{CAMERA_ID}:{corrected_ts_ms}".encode()


def test_concurrent_stale_capture_cannot_overwrite_current_evidence(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    stale = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="PENDING",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/pending",
    )
    current = _payment(
        "2026-07-16T15:02:00.000Z",
        amount=725,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/completed",
    )
    stale["created_at"] = "2026-07-16T15:00:00.000Z"
    current["created_at"] = "2026-07-16T15:00:01.000Z"
    stale_ts_ms = parse_ts_ms(stale["created_at"])
    current_ts_ms = parse_ts_ms(current["created_at"])
    stale_started = threading.Event()
    release_stale = threading.Event()

    class RacingProtect:
        def get_snapshot(self, camera_id, ts_ms=None):
            if ts_ms == stale_ts_ms:
                stale_started.set()
                assert release_stale.wait(timeout=5)
                return b"stale-frame"
            assert ts_ms == current_ts_ms
            assert stale_started.wait(timeout=5)
            return b"current-frame"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            stale_future = executor.submit(
                ingest_payment, store, stale, RacingProtect()
            )
            assert stale_started.wait(timeout=5)
            current_future = executor.submit(
                ingest_payment, store, current, RacingProtect()
            )
            current_future.result(timeout=5)
            release_stale.set()
            stale_future.result(timeout=5)

        stored = store.get_transaction("PAY_VERSIONED")
        assert stored["ts_ms"] == current_ts_ms
        assert (store.thumbnail_dir / stored["thumbnail_path"]).read_bytes() == (
            b"current-frame"
        )
        assert [path.name for path in store.thumbnail_dir.iterdir()] == [
            stored["thumbnail_path"]
        ]
    finally:
        release_stale.set()
        store.close()
