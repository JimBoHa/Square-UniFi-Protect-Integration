"""Transaction versioning and database migration tests."""

from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.store import Store
from app.sync import ingest_payment, parse_ts_ms, sync_payments

CAMERA_ID = "cam1aaaaaaaaaaaaaaaaaaaaa"


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
) -> dict:
    return {
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
    assert stored["camera_id"] == CAMERA_ID
    assert stored["thumbnail_path"].startswith("PAY_VERSIONED-")
    assert json.loads(stored["raw"]) == completed


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

    def fail_on_middle(txn):
        if txn["id"] == "PAY_MIDDLE":
            raise RuntimeError("simulated database interruption")
        return original_upsert(txn)

    monkeypatch.setattr(store, "upsert_transaction", fail_on_middle)
    try:
        with pytest.raises(RuntimeError, match="simulated database interruption"):
            sync_payments(store, square, protect=None)
        assert store.get_transaction("PAY_OLDEST") is not None
        assert store.get_transaction("PAY_MIDDLE") is None
        assert store.get_transaction("PAY_NEWEST") is None
    finally:
        store.close()

    restarted_store = Store(data_dir)
    try:
        assert sync_payments(restarted_store, square, protect=None) == 2
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


def test_store_migrates_legacy_transaction_schema_without_data_loss(tmp_path):
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
            '{"legacy": true}',
        ),
    )
    db.commit()
    db.close()

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
        "raw": '{"legacy": true}',
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
