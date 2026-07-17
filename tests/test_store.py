"""Transaction versioning and database migration tests."""

import json
import sqlite3

from app.store import Store
from app.sync import ingest_payment, parse_ts_ms

CAMERA_ID = "cam1aaaaaaaaaaaaaaaaaaaaa"


class _ProtectStub:
    def get_snapshot(self, camera_id, ts_ms=None):
        return f"snapshot:{camera_id}:{ts_ms}".encode()


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
    assert stored["thumbnail_path"] == "PAY_VERSIONED.jpg"
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
    }
