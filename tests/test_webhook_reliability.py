"""Square webhook deduplication, timing, and account-isolation tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from app import webhook_delivery
from app.store import (
    MAX_SQUARE_WEBHOOK_RECEIPTS,
    SquareAccountSwitchRequired,
    Store,
)

from .conftest import SQUARE_MERCHANT_ID, SQUARE_TOKEN, WEBHOOK_KEY, WEBHOOK_URL
from .test_api import _wait_for_thumbnail, _webhook_signature, make_webhook_event


def _event_with_receipt(
    payment_id: str,
    *,
    event_id: str,
    event_type: str = "payment.updated",
    created_at: datetime | None = None,
) -> bytes:
    event = json.loads(make_webhook_event(payment_id, event_type=event_type))
    event["event_id"] = event_id
    event["created_at"] = (created_at or datetime.now(timezone.utc)).isoformat()
    return json.dumps(event, separators=(",", ":")).encode()


def test_non_payment_type_cannot_smuggle_payment_envelope(configured):
    body = _event_with_receipt(
        "PAY_SMUGGLED",
        event_id="evt-smuggled",
        event_type="refund.updated",
    )

    response = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "ignored": True}
    assert configured.app.state.store.get_transaction("PAY_SMUGGLED") is None


def test_duplicate_event_is_ingested_once_and_reports_delivery_lag(
    configured,
    monkeypatch,
):
    from app import main as main_module

    calls = []
    original = main_module.sync.ingest_payment

    def counted_ingest(*args, **kwargs):
        calls.append(args[1]["id"])
        return original(*args, **kwargs)

    monkeypatch.setattr(main_module.sync, "ingest_payment", counted_ingest)
    body = _event_with_receipt(
        "PAY_DEDUP",
        event_id="evt-dedup-1",
        created_at=datetime.now(timezone.utc) - timedelta(milliseconds=250),
    )
    headers = {"x-square-hmacsha256-signature": _webhook_signature(body)}

    first = configured.post("/webhooks/square", content=body, headers=headers)
    duplicate = configured.post("/webhooks/square", content=body, headers=headers)
    dashboard = configured.get("/api/dashboard").json()["webhook"]

    assert first.status_code == 200
    assert duplicate.status_code == 200
    assert duplicate.json() == {"ok": True, "ignored": True}
    assert calls == ["PAY_DEDUP"]
    assert dashboard["delivery_count"] == 2
    assert dashboard["accepted_payment_count"] == 1
    assert dashboard["duplicate_count"] == 1
    assert 0 <= dashboard["last_delivery_lag_ms"] < 5_000
    assert isinstance(dashboard["last_payment_ms"], int)


def test_duplicate_delivery_still_wakes_due_protect_queue(configured):
    body = _event_with_receipt(
        "PAY_NUDGE_SOURCE",
        event_id="evt-nudge-source",
    )
    headers = {"x-square-hmacsha256-signature": _webhook_signature(body)}
    assert configured.post(
        "/webhooks/square",
        content=body,
        headers=headers,
    ).status_code == 200
    _wait_for_thumbnail(configured, "PAY_NUDGE_SOURCE")

    configured.app.state.store.upsert_transaction(
        {
            "id": "PAY_DUE_FROM_DUPLICATE",
            "created_at": "2026-08-08T20:00:00.000Z",
            "ts_ms": 1_786_219_200_000,
            "amount": 99,
            "currency": "USD",
            "status": "COMPLETED",
            "location_id": "LOC1",
            "camera_id": "cam1aaaaaaaaaaaaaaaaaaaaa",
            "thumbnail_path": None,
            "raw": {},
        }
    )

    duplicate = configured.post(
        "/webhooks/square",
        content=body,
        headers=headers,
    )

    assert duplicate.status_code == 200
    assert duplicate.json() == {"ok": True, "ignored": True}
    assert _wait_for_thumbnail(
        configured,
        "PAY_DUE_FROM_DUPLICATE",
    )["thumbnail_url"]


def test_receipt_key_prefers_event_id_and_falls_back_to_signed_body():
    body = b'{"event_id":"not parsed here"}'

    assert webhook_delivery.receipt_key("evt-1", body) == (
        webhook_delivery.receipt_key("evt-1", b"different body")
    )
    assert webhook_delivery.receipt_key(None, body) != (
        webhook_delivery.receipt_key(None, b"different body")
    )
    assert len(webhook_delivery.receipt_key("evt-1", body)) == 64


def test_square_nanosecond_event_time_is_parsed_but_naive_time_is_ignored():
    assert webhook_delivery.event_created_at_ms(
        {"created_at": "2026-08-08T20:00:00.123456789Z"}
    ) == 1_786_219_200_123
    assert webhook_delivery.event_created_at_ms(
        {"created_at": "2026-08-08T20:00:00"}
    ) is None


def test_receipt_store_is_bounded_under_large_delivery_run(tmp_path):
    store = Store(tmp_path / "data")
    keys = [
        hashlib.sha256(str(index).encode()).hexdigest()
        for index in range(MAX_SQUARE_WEBHOOK_RECEIPTS + 1)
    ]
    try:
        for index, event_key in enumerate(keys):
            assert store.record_square_webhook_receipt(
                event_key,
                "payment.updated",
                index,
                index,
            )
        summary = store.square_webhook_metrics()
        oldest_exists = store.square_webhook_receipt_exists(keys[0])
        newest_exists = store.square_webhook_receipt_exists(keys[-1])
    finally:
        store.close()

    assert summary["accepted_payment_count"] == len(keys)
    assert summary["retained_receipts"] == MAX_SQUARE_WEBHOOK_RECEIPTS
    assert oldest_exists is False
    assert newest_exists is True


def test_slow_older_delivery_cannot_regress_freshness_or_lag(tmp_path):
    store = Store(tmp_path / "data")
    newer_key = hashlib.sha256(b"newer").hexdigest()
    older_key = hashlib.sha256(b"older").hexdigest()
    try:
        store.record_square_webhook_delivery(2_000)
        store.record_square_webhook_delivery(1_000)
        store.record_square_webhook_receipt(
            newer_key,
            "payment.updated",
            2_000,
            1_900,
        )
        store.record_square_webhook_receipt(
            older_key,
            "payment.updated",
            1_000,
            100,
        )
        summary = store.square_webhook_metrics()
    finally:
        store.close()

    assert summary["last_event_ms"] == 2_000
    assert summary["last_payment_ms"] == 2_000
    assert summary["last_delivery_lag_ms"] == 100


def test_disabling_webhook_clears_receipts_and_metrics(tmp_path):
    store = Store(tmp_path / "data")
    event_key = hashlib.sha256(b"account-a-event").hexdigest()
    try:
        store.configure_square_account(
            merchant_id=SQUARE_MERCHANT_ID,
            access_token=SQUARE_TOKEN,
            environment="sandbox",
            webhook_signature_key=WEBHOOK_KEY,
            webhook_url=WEBHOOK_URL,
        )
        store.record_square_webhook_delivery(1_000)
        store.record_square_webhook_receipt(
            event_key,
            "payment.created",
            1_000,
            900,
        )

        store.configure_square_account(
            merchant_id=SQUARE_MERCHANT_ID,
            access_token=SQUARE_TOKEN,
            environment="sandbox",
            clear_webhook=True,
        )
        summary = store.square_webhook_metrics()
        receipt_exists = store.square_webhook_receipt_exists(event_key)
    finally:
        store.close()

    assert receipt_exists is False
    assert summary == {
        "last_event_ms": None,
        "delivery_count": 0,
        "last_payment_ms": None,
        "last_delivery_lag_ms": None,
        "accepted_payment_count": 0,
        "duplicate_count": 0,
        "retained_receipts": 0,
    }


def test_confirmed_merchant_switch_cannot_inherit_webhook_receipts(tmp_path):
    store = Store(tmp_path / "data")
    event_key = hashlib.sha256(b"merchant-a-event").hexdigest()
    try:
        store.configure_square_account(
            merchant_id="MERCHANT_A",
            access_token="token-a",
            environment="sandbox",
            webhook_signature_key="key-a",
            webhook_url="https://a.example/webhooks/square",
        )
        store.record_square_webhook_delivery(1_000)
        store.record_square_webhook_receipt(
            event_key,
            "payment.created",
            1_000,
            900,
        )
        with pytest.raises(SquareAccountSwitchRequired) as required:
            store.configure_square_account(
                merchant_id="MERCHANT_B",
                access_token="token-b",
                environment="sandbox",
            )
        store.configure_square_account(
            merchant_id="MERCHANT_B",
            access_token="token-b",
            environment="sandbox",
            confirm_account_switch=True,
            account_switch_confirmation_token=(
                required.value.confirmation_token
            ),
        )
        summary = store.square_webhook_metrics()
    finally:
        store.close()

    assert summary["delivery_count"] == 0
    assert summary["accepted_payment_count"] == 0
    assert summary["retained_receipts"] == 0


@pytest.mark.parametrize("event_key", ["", "A" * 64, "f" * 63, "g" * 64])
def test_receipt_store_rejects_invalid_digest_keys(tmp_path, event_key):
    store = Store(tmp_path / "data")
    try:
        with pytest.raises(ValueError, match="Invalid webhook receipt key"):
            store.record_square_webhook_receipt(
                event_key,
                "payment.updated",
                1_000,
                900,
            )
    finally:
        store.close()
