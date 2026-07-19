"""Refund normalization, persistence, and transaction API tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3

import pytest

from app.square_client import payment_from_api
from app.store import Store
from app.sync import ingest_payment, parse_ts_ms, sync_payments

from .conftest import SQUARE_MERCHANT_ID, WEBHOOK_KEY, WEBHOOK_URL


def _payment(updated_at: str, refunded_amount: int) -> dict:
    return {
        "id": "PAY_REFUND",
        "created_at": "2026-07-18T10:00:00Z",
        "updated_at": updated_at,
        "total_money": {"amount": 1000, "currency": "USD"},
        "refunded_money": {"amount": refunded_amount, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
    }


def test_payment_normalizes_refunded_money_without_raw_buyer_data(tmp_path):
    payment = _payment("2026-07-18T10:01:00Z", 250) | {
        "buyer_email_address": "private-buyer@example.com",
        "refund_ids": ["PRIVATE_REFUND_ID"],
    }

    normalized = payment_from_api(payment)
    assert normalized["refunded_amount"] == 250
    assert "buyer_email_address" not in normalized
    assert "refund_ids" not in normalized

    store = Store(tmp_path / "data")
    try:
        ingest_payment(store, payment, protect=None)
        stored = store.get_transaction("PAY_REFUND")
    finally:
        store.close()

    assert stored["refunded_amount"] == 250
    assert stored["raw"] == "{}"
    database_bytes = (tmp_path / "data" / "spi.db").read_bytes()
    assert b"private-buyer@example.com" not in database_bytes
    assert b"PRIVATE_REFUND_ID" not in database_bytes


@pytest.mark.parametrize(
    "refunded_money",
    [
        [],
        {},
        {"currency": "USD"},
        {"amount": 1},
        {"amount": True, "currency": "USD"},
        {"amount": "1", "currency": "USD"},
        {"amount": 1.5, "currency": "USD"},
        {"amount": -1, "currency": "USD"},
        {"amount": 1 << 63, "currency": "USD"},
        {"amount": 1, "currency": []},
        {"amount": 1, "currency": "usd"},
        {"amount": 1, "currency": "US"},
        {"amount": 1, "currency": "US1"},
    ],
)
def test_payment_rejects_malformed_refunded_money(refunded_money):
    payment = _payment("2026-07-18T10:01:00Z", 0)
    payment["refunded_money"] = refunded_money

    with pytest.raises(ValueError, match="Payment refunded_money"):
        payment_from_api(payment)


def test_payment_rejects_refund_currency_mismatch():
    payment = _payment("2026-07-18T10:01:00Z", 100)
    payment["refunded_money"]["currency"] = "CAD"

    with pytest.raises(ValueError, match="currency does not match"):
        payment_from_api(payment)


def test_payment_without_refund_defaults_to_zero():
    payment = _payment("2026-07-18T10:01:00Z", 0)
    del payment["refunded_money"]

    assert payment_from_api(payment)["refunded_amount"] == 0


def test_store_migrates_existing_transactions_with_safe_refund_default(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database = sqlite3.connect(data_dir / "spi.db")
    database.execute(
        "CREATE TABLE transactions ("
        "id TEXT PRIMARY KEY, created_at TEXT NOT NULL, ts_ms INTEGER NOT NULL, "
        "amount INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, "
        "location_id TEXT NOT NULL DEFAULT '', card_last4 TEXT NOT NULL DEFAULT '', "
        "receipt_url TEXT NOT NULL DEFAULT '', camera_id TEXT, thumbnail_path TEXT, "
        "raw TEXT NOT NULL DEFAULT '{}')"
    )
    database.execute(
        "INSERT INTO transactions "
        "(id, created_at, ts_ms, amount, currency, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("LEGACY", "2026-07-18T10:00:00Z", 1, 1000, "USD", "COMPLETED"),
    )
    database.commit()
    database.close()

    store = Store(data_dir)
    try:
        column = next(
            row
            for row in store._db.execute("PRAGMA table_info(transactions)").fetchall()
            if row["name"] == "refunded_amount"
        )
        stored = store.get_transaction("LEGACY")
    finally:
        store.close()

    assert column["notnull"] == 1
    assert column["dflt_value"] == "0"
    assert stored["refunded_amount"] == 0


def test_newer_refund_update_wins_and_stale_update_is_rejected(tmp_path):
    store = Store(tmp_path / "data")
    try:
        ingest_payment(
            store,
            _payment("2026-07-18T10:02:00Z", 250),
            protect=None,
        )
        ingest_payment(
            store,
            _payment("2026-07-18T10:03:00Z", 1000),
            protect=None,
        )
        ingest_payment(
            store,
            _payment("2026-07-18T10:01:00Z", 100),
            protect=None,
        )
        stored = store.get_transaction("PAY_REFUND")
    finally:
        store.close()

    assert stored["updated_at"] == "2026-07-18T10:03:00Z"
    assert stored["refunded_amount"] == 1000


def test_cumulative_refund_cannot_regress_on_tied_or_newer_updates(tmp_path):
    store = Store(tmp_path / "data")
    try:
        ingest_payment(
            store,
            _payment("2026-07-18T10:03:00Z", 1000),
            protect=None,
        )
        ingest_payment(
            store,
            _payment("2026-07-18T10:03:00Z", 250),
            protect=None,
        )
        without_refund = _payment("2026-07-18T10:03:00Z", 0)
        del without_refund["refunded_money"]
        ingest_payment(store, without_refund, protect=None)
        ingest_payment(
            store,
            _payment("2026-07-18T10:04:00Z", 500),
            protect=None,
        )
        stored = store.get_transaction("PAY_REFUND")
    finally:
        store.close()

    assert stored["updated_at"] == "2026-07-18T10:04:00Z"
    assert stored["refunded_amount"] == 1000


def test_refund_migration_rehydrates_old_history_once(tmp_path, monkeypatch):
    data_dir = tmp_path / "legacy"
    data_dir.mkdir()
    earliest_updated_at = "2026-01-01T12:00:00Z"
    earliest_updated_ms = parse_ts_ms(earliest_updated_at)
    other_location_updated_ms = parse_ts_ms("2026-02-01T12:00:00Z")
    old_watermark = parse_ts_ms("2026-07-18T12:00:00Z")
    poll_boundary = parse_ts_ms("2026-07-18T12:10:00Z")
    database = sqlite3.connect(data_dir / "spi.db")
    database.executescript(
        "CREATE TABLE transactions ("
        "id TEXT PRIMARY KEY, created_at TEXT NOT NULL, ts_ms INTEGER NOT NULL, "
        "updated_at TEXT NOT NULL, updated_ts_ms INTEGER NOT NULL, "
        "amount INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, "
        "location_id TEXT NOT NULL DEFAULT '', card_last4 TEXT NOT NULL DEFAULT '', "
        "receipt_url TEXT NOT NULL DEFAULT '', camera_id TEXT, thumbnail_path TEXT, "
        "raw TEXT NOT NULL DEFAULT '{}');"
        "CREATE TABLE square_poll_watermarks ("
        "location_id TEXT PRIMARY KEY, "
        "polled_through_ms INTEGER NOT NULL CHECK (polled_through_ms >= 0));"
    )
    database.executemany(
        "INSERT INTO transactions "
        "(id, created_at, ts_ms, updated_at, updated_ts_ms, amount, currency, "
        "status, location_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            (
                "PAY_REFUND",
                earliest_updated_at,
                earliest_updated_ms,
                earliest_updated_at,
                earliest_updated_ms,
                1000,
                "USD",
                "COMPLETED",
                "LOC1",
            ),
            (
                "PAY_OTHER_LOCATION",
                "2026-02-01T12:00:00Z",
                other_location_updated_ms,
                "2026-02-01T12:00:00Z",
                other_location_updated_ms,
                500,
                "USD",
                "COMPLETED",
                "LOC_WITHOUT_WATERMARK",
            ),
        ),
    )
    database.execute(
        "INSERT INTO square_poll_watermarks "
        "(location_id, polled_through_ms) VALUES (?, ?)",
        ("LOC1", old_watermark),
    )
    database.commit()
    database.close()

    class Square:
        def __init__(self):
            self.begin_times = []

        def list_locations(self):
            return [{"id": "LOC1"}]

        def iter_payment_pages(self, **params):
            self.begin_times.append(params["updated_at_begin_time"])
            yield [_payment(earliest_updated_at, 400)]

    monkeypatch.setattr("app.sync._current_time_ms", lambda: poll_boundary)
    square = Square()
    migrated = Store(data_dir)
    try:
        assert migrated.get_square_poll_watermark("LOC1") == earliest_updated_ms
        assert (
            migrated.get_square_poll_watermark("LOC_WITHOUT_WATERMARK")
            == other_location_updated_ms
        )
        assert sync_payments(migrated, square, protect=None) == 0
        assert square.begin_times == ["2026-01-01T11:55:00Z"]
        assert migrated.get_transaction("PAY_REFUND")["refunded_amount"] == 400
        assert migrated.get_square_poll_watermark("LOC1") == poll_boundary
    finally:
        migrated.close()

    restarted = Store(data_dir)
    try:
        assert restarted.get_square_poll_watermark("LOC1") == poll_boundary
        assert restarted.get_transaction("PAY_REFUND")["refunded_amount"] == 400
    finally:
        restarted.close()


def test_payment_updated_webhook_ingests_refund_total(configured):
    body = json.dumps(
        {
            "merchant_id": SQUARE_MERCHANT_ID,
            "type": "payment.updated",
            "data": {
                "object": {
                    "payment": _payment("2026-07-18T10:03:00Z", 400),
                }
            },
        }
    ).encode()
    signature = base64.b64encode(
        hmac.new(
            WEBHOOK_KEY.encode(),
            WEBHOOK_URL.encode() + body,
            hashlib.sha256,
        ).digest()
    ).decode()

    response = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": signature},
    )

    assert response.status_code == 200
    transaction = next(
        item
        for item in configured.get("/api/transactions").json()
        if item["id"] == "PAY_REFUND"
    )
    assert transaction["refunded_amount"] == 400


def test_transactions_api_exposes_only_normalized_refund_amount(authed):
    authed.app.state.store.upsert_transaction(
        {
            "id": "PAY_REFUND_API",
            "created_at": "2026-07-18T10:00:00Z",
            "updated_at": "2026-07-18T10:01:00Z",
            "ts_ms": 1,
            "updated_ts_ms": 2,
            "amount": 1000,
            "currency": "USD",
            "refunded_amount": 250,
            "status": "COMPLETED",
        }
    )

    response = authed.get("/api/transactions")
    assert response.status_code == 200
    transaction = response.json()[0]
    assert transaction["refunded_amount"] == 250
    assert {key for key in transaction if "refund" in key} == {"refunded_amount"}
