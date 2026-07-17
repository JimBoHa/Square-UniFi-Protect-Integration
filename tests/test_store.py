"""Transaction versioning and database migration tests."""

from concurrent.futures import ThreadPoolExecutor
import errno
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import app.store as store_module
from app.store import (
    ALARM_ENABLED_AFTER_SETTING,
    PROTECT_CONSOLE_GENERATION_SETTING,
    ProtectConsoleSwitchConfirmationRequired,
    ProtectSettingsConflict,
    Store,
)
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

    def fail_on_middle(txn, **kwargs):
        if txn["id"] == "PAY_MIDDLE":
            raise RuntimeError("simulated database interruption")
        return original_upsert(txn, **kwargs)

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


def _protect_settings(host: str) -> dict[str, tuple[str, bool]]:
    return {
        "protect.host": (host, False),
        "protect.username": ("protect-user", False),
        "protect.password": ("protect-password", True),
        "protect.verify_ssl": ("0", False),
    }


def _protect_switch_token(
    store: Store,
    target_host: str,
    target_console_id: str | None = None,
) -> str:
    identity = store.get_settings(
        (
            "protect.host",
            "protect.console_id",
            PROTECT_CONSOLE_GENERATION_SETTING,
        )
    )
    token = store.protect_console_switch_token(
        target_host,
        target_console_id,
        expected_host=identity["protect.host"],
        expected_generation=identity[PROTECT_CONSOLE_GENERATION_SETTING],
        expected_console_id=identity["protect.console_id"],
    )
    assert token
    return token


def test_store_adds_console_generation_to_existing_protect_configuration(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    store.update_settings(_protect_settings("existing-console.local"))
    assert store.get_setting(PROTECT_CONSOLE_GENERATION_SETTING) is None
    store.close()

    reopened = Store(data_dir)
    try:
        generation = reopened.get_setting(PROTECT_CONSOLE_GENERATION_SETTING)
        assert generation
        assert len(generation) == 32
        assert reopened.get_setting("protect.host") == "existing-console.local"
    finally:
        reopened.close()


def test_legacy_console_identity_is_backfilled_once_then_enforced(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    store.update_settings(_protect_settings("existing-console.local"))
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    store.close()

    reopened = Store(data_dir)
    try:
        generation = reopened.get_setting(PROTECT_CONSOLE_GENERATION_SETTING)
        assert generation
        assert reopened.update_protect_settings(
            _protect_settings("existing-console.local"),
            expected_host="existing-console.local",
            expected_generation=generation,
            expected_console_id=None,
            observed_console_id="nvr-a",
        ) is False
        assert reopened.get_setting("protect.console_id") == "nvr-a"
        assert reopened.get_camera_mappings()
        assert reopened.get_setting(PROTECT_CONSOLE_GENERATION_SETTING) == generation

        with pytest.raises(ProtectConsoleSwitchConfirmationRequired):
            reopened.update_protect_settings(
                _protect_settings("existing-console.local"),
                expected_host="existing-console.local",
                expected_generation=generation,
                expected_console_id="nvr-a",
                observed_console_id="nvr-b",
            )
        token = _protect_switch_token(
            reopened, "existing-console.local", "nvr-b"
        )
        assert reopened.update_protect_settings(
            _protect_settings("existing-console.local"),
            expected_host="existing-console.local",
            expected_generation=generation,
            expected_console_id="nvr-a",
            observed_console_id="nvr-b",
            console_switch_token=token,
        )
        assert reopened.get_camera_mappings() == []
    finally:
        reopened.close()


def test_protect_console_switch_rolls_back_all_state_on_database_failure(tmp_path):
    store = Store(tmp_path / "data")
    old_path = store.thumbnail_dir / "old-console.jpg"
    old_path.write_bytes(b"old console evidence")
    assert store.update_protect_settings(
        _protect_settings("old-console.local"),
        expected_host=None,
        expected_generation=None,
    ) is False
    generation = store.get_setting(PROTECT_CONSOLE_GENERATION_SETTING)
    switch_token = _protect_switch_token(store, "new-console.local")
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    store.upsert_transaction(
        _stored_thumbnail("PAY_CAPTURED", 1000, 1000, old_path.name)
    )
    store.upsert_transaction(
        _stored_thumbnail("PAY_RETRY", 2000, 2000, None)
    )
    store._db.execute(
        "CREATE TRIGGER reject_console_reset BEFORE UPDATE OF camera_id "
        "ON transactions BEGIN SELECT RAISE(ABORT, 'simulated reset failure'); END"
    )
    store._db.commit()
    try:
        with pytest.raises(sqlite3.IntegrityError, match="simulated reset failure"):
            store.update_protect_settings(
                _protect_settings("new-console.local"),
                expected_host="old-console.local",
                expected_generation=generation,
                console_switch_token=switch_token,
            )

        assert store.get_setting("protect.host") == "old-console.local"
        assert store.get_camera_mappings()[0]["camera_id"] == CAMERA_ID
        assert store.get_transaction("PAY_CAPTURED")["thumbnail_path"] == old_path.name
        assert store.get_transaction("PAY_RETRY")["camera_id"] == CAMERA_ID
        assert store._db.execute(
            "SELECT COUNT(*) FROM thumbnail_retries"
        ).fetchone()[0] == 1
        assert store._db.execute(
            "SELECT COUNT(*) FROM protect_evidence_retired"
        ).fetchone()[0] == 0
        assert store.orphan_thumbnail_cleanup_pending() is False
        assert old_path.read_bytes() == b"old console evidence"
    finally:
        store.close()


def test_protect_switch_retries_failed_orphan_cleanup_on_startup(
    tmp_path,
    monkeypatch,
):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    assert store.update_protect_settings(
        _protect_settings("old-console.local"),
        expected_host=None,
        expected_generation=None,
    ) is False
    old_path = store.thumbnail_dir / "old-console.jpg"
    old_path.write_bytes(b"old console evidence")
    store.upsert_transaction(
        _stored_thumbnail("PAY_CAPTURED", 1000, 1000, old_path.name)
    )
    generation = store.get_setting(PROTECT_CONSOLE_GENERATION_SETTING)
    token = _protect_switch_token(store, "new-console.local")
    original_unlink = Path.unlink

    def fail_old_thumbnail(path, *args, **kwargs):
        if path == old_path:
            raise OSError("simulated cleanup failure")
        return original_unlink(path, *args, **kwargs)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(Path, "unlink", fail_old_thumbnail)
            assert store.update_protect_settings(
                _protect_settings("new-console.local"),
                expected_host="old-console.local",
                expected_generation=generation,
                console_switch_token=token,
            )
        assert old_path.is_file()
        assert store.orphan_thumbnail_cleanup_pending() is True
    finally:
        store.close()

    reopened = Store(data_dir)
    try:
        assert not old_path.exists()
        assert reopened.orphan_thumbnail_cleanup_pending() is False
    finally:
        reopened.close()


def test_only_one_concurrent_protect_console_switch_can_commit(tmp_path):
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    second = Store(data_dir)
    old_path = first.thumbnail_dir / "old-console.jpg"
    old_path.write_bytes(b"old console evidence")
    assert first.update_protect_settings(
        _protect_settings("old-console.local"),
        expected_host=None,
        expected_generation=None,
    ) is False
    generation = first.get_setting(PROTECT_CONSOLE_GENERATION_SETTING)
    first.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    first.upsert_transaction(
        _stored_thumbnail("PAY_CAPTURED", 1000, 1000, old_path.name)
    )
    barrier = threading.Barrier(2)

    def switch(candidate: Store, host: str):
        switch_token = _protect_switch_token(candidate, host)
        barrier.wait(timeout=5)
        try:
            return candidate.update_protect_settings(
                _protect_settings(host),
                expected_host="old-console.local",
                expected_generation=generation,
                console_switch_token=switch_token,
            )
        except Exception as exc:
            return exc

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    lambda args: switch(*args),
                    (
                        (first, "new-a.local"),
                        (second, "new-b.local"),
                    ),
                )
            )

        assert sum(result is True for result in results) == 1
        assert sum(isinstance(result, ProtectSettingsConflict) for result in results) == 1
        assert first.get_setting("protect.host") in {"new-a.local", "new-b.local"}
        assert first.get_camera_mappings() == []
        saved = first.get_transaction("PAY_CAPTURED")
        assert saved["amount"] == 500
        assert saved["camera_id"] is None
        assert saved["thumbnail_path"] is None
        assert not old_path.exists()
        first.replace_camera_mappings(
            [("LOC_OLD", "", "", CAMERA_B, "New Console Camera")]
        )
        assert first.get_transaction("PAY_CAPTURED")["camera_id"] is None
    finally:
        second.close()
        first.close()


def test_protect_settings_guard_serializes_store_instances(tmp_path):
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    second = Store(data_dir)
    first_entered = threading.Event()
    second_attempted = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()

    def hold_first() -> None:
        with first.protect_settings_guard():
            first_entered.set()
            assert release_first.wait(timeout=5)

    def take_second() -> None:
        second_attempted.set()
        with second.protect_settings_guard():
            second_entered.set()

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(hold_first)
            assert first_entered.wait(timeout=5)
            second_future = executor.submit(take_second)
            assert second_attempted.wait(timeout=5)
            assert not second_entered.wait(timeout=0.05)
            release_first.set()
            first_future.result(timeout=5)
            second_future.result(timeout=5)
            assert second_entered.is_set()
    finally:
        release_first.set()
        second.close()
        first.close()


def test_windows_integration_guard_allows_readers_and_makes_writer_wait(
    tmp_path,
    monkeypatch,
):
    class FakeMsvcrt:
        LK_NBLCK = 1
        LK_UNLCK = 2

        def __init__(self):
            self._condition = threading.Condition()
            self._owners: dict[int, int] = {}

        def locking(self, fd: int, operation: int, length: int) -> None:
            offset = os.lseek(fd, 0, os.SEEK_CUR)
            byte_range = range(offset, offset + length)
            with self._condition:
                if operation == self.LK_NBLCK:
                    if any(
                        owner != fd
                        for byte in byte_range
                        if (owner := self._owners.get(byte)) is not None
                    ):
                        raise OSError(errno.EACCES, "simulated sharing violation")
                    for byte in byte_range:
                        self._owners[byte] = fd
                    return
                if operation == self.LK_UNLCK:
                    assert all(self._owners.get(byte) == fd for byte in byte_range)
                    for byte in byte_range:
                        del self._owners[byte]
                    self._condition.notify_all()
                    return
                raise AssertionError(f"unexpected operation {operation}")

    fake_msvcrt = FakeMsvcrt()
    monkeypatch.setattr(store_module, "_fcntl", None)
    monkeypatch.setattr(store_module, "_msvcrt", fake_msvcrt)
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    second = Store(data_dir)
    release_readers = threading.Event()
    first_reader_started = threading.Event()
    second_reader_started = threading.Event()
    writer_started = threading.Event()

    def hold_reader(candidate: Store, started: threading.Event) -> None:
        with candidate.integration_guard():
            started.set()
            assert release_readers.wait(timeout=5)

    def take_writer() -> None:
        with second.integration_guard(exclusive=True):
            writer_started.set()

    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            first_reader = executor.submit(hold_reader, first, first_reader_started)
            assert first_reader_started.wait(timeout=5)
            second_reader = executor.submit(hold_reader, second, second_reader_started)
            assert second_reader_started.wait(timeout=5)
            writer = executor.submit(take_writer)
            assert not writer_started.wait(timeout=0.05)
            release_readers.set()
            first_reader.result(timeout=5)
            second_reader.result(timeout=5)
            writer.result(timeout=5)
            assert writer_started.is_set()

        with first.integration_guard():
            pass
        assert fake_msvcrt._owners == {}
    finally:
        release_readers.set()
        second.close()
        first.close()


def test_inflight_capture_cannot_reattach_across_aba_console_switch(tmp_path):
    snapshot_started = threading.Event()
    release_snapshot = threading.Event()

    class BlockingOldProtect:
        host = "old-console.local"

        def get_snapshot(self, camera_id, ts_ms=None):
            snapshot_started.set()
            assert release_snapshot.wait(timeout=5)
            return b"old console evidence"

    store = Store(tmp_path / "data")
    assert store.update_protect_settings(
        _protect_settings("old-console.local"),
        expected_host=None,
        expected_generation=None,
    ) is False
    old_generation = store.get_setting(PROTECT_CONSOLE_GENERATION_SETTING)
    store.set_camera_mapping("LOC_OLD", CAMERA_ID, "Front Counter")
    payment = _payment(
        "2026-07-16T15:01:00.000Z",
        amount=500,
        currency="USD",
        status="COMPLETED",
        location_id="LOC_OLD",
        card_last4="1111",
        receipt_url="https://square.example/receipt",
    )
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(ingest_payment, store, payment, BlockingOldProtect())
            assert snapshot_started.wait(timeout=3)
            first_switch_token = _protect_switch_token(
                store, "new-console.local"
            )
            assert store.update_protect_settings(
                _protect_settings("new-console.local"),
                expected_host="old-console.local",
                expected_generation=old_generation,
                console_switch_token=first_switch_token,
            )
            intermediate_generation = store.get_setting(
                PROTECT_CONSOLE_GENERATION_SETTING
            )
            assert intermediate_generation
            second_switch_token = _protect_switch_token(
                store, "old-console.local"
            )
            assert store.update_protect_settings(
                _protect_settings("old-console.local"),
                expected_host="new-console.local",
                expected_generation=intermediate_generation,
                console_switch_token=second_switch_token,
            )
            assert store.get_setting("protect.console_generation") != (
                intermediate_generation
            )
            release_snapshot.set()
            future.result(timeout=5)

        saved = store.get_transaction("PAY_VERSIONED")
        assert saved["amount"] == 500
        assert saved["camera_id"] is None
        assert saved["thumbnail_path"] is None
        assert store.get_setting("protect.host") == "old-console.local"
        assert store.get_camera_mappings() == []
        assert list(store.thumbnail_dir.iterdir()) == []
        store.replace_camera_mappings(
            [("LOC_OLD", "", "", CAMERA_B, "Current Console Camera")]
        )
        assert store.get_transaction("PAY_VERSIONED")["camera_id"] is None
        assert store._db.execute(
            "SELECT COUNT(*) FROM thumbnail_retries"
        ).fetchone()[0] == 0
    finally:
        release_snapshot.set()
        store.close()


def test_console_switch_invalidates_old_alarm_claims(tmp_path):
    store = Store(tmp_path / "data")
    initial_settings = {
        **_protect_settings("old-console.local"),
        "protect.api_key": ("old-api-key", True),
        "protect.alarm_trigger_id": ("old-trigger", False),
    }
    try:
        assert store.update_protect_settings(
            initial_settings,
            expected_host=None,
            expected_generation=None,
            activate_alarm_at_ms=1000,
        ) is False
        store.upsert_transaction(
            _stored_thumbnail("PAY_ALARM", 2000, 2000, None)
        )
        claim_token = store.claim_alarm_trigger("PAY_ALARM")
        assert claim_token
        generation = store.get_setting(PROTECT_CONSOLE_GENERATION_SETTING)
        switch_token = _protect_switch_token(store, "new-console.local")

        assert store.update_protect_settings(
            _protect_settings("new-console.local"),
            expected_host="old-console.local",
            expected_generation=generation,
            console_switch_token=switch_token,
            delete_keys=(
                "protect.api_key",
                "protect.alarm_trigger_id",
                ALARM_ENABLED_AFTER_SETTING,
            ),
        )

        saved = store.get_transaction("PAY_ALARM")
        assert saved["alarm_state"] == "sent"
        assert saved["alarm_claim_token"] is None
        assert saved["alarm_claimed_at"] is None
        assert store.mark_alarm_sent("PAY_ALARM", claim_token) is False
        assert store.pending_alarm_transaction_ids() == []
        assert store.get_setting("protect.api_key") is None
        assert store.get_setting("protect.alarm_trigger_id") is None
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
