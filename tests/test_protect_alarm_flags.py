"""Square-completion delivery status and Protect flag test controls."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from app.store import Store

from .conftest import (
    PROTECT_ALARM_CALLS,
    PROTECT_ALARM_RESPONSES,
    PROTECT_ALARM_TRIGGER_ID,
    PROTECT_API_KEY,
    PROTECT_PASS,
    PROTECT_USER,
    SQUARE_MERCHANT_ID,
    WEBHOOK_KEY,
    WEBHOOK_URL,
)


def transaction(txn_id: str, ts_ms: int) -> dict:
    return {
        "id": txn_id,
        "created_at": "2026-08-08T12:00:00.000Z",
        "ts_ms": ts_ms,
        "updated_at": "2026-08-08T12:00:00.000Z",
        "updated_ts_ms": ts_ms,
        "amount": 99,
        "currency": "USD",
        "status": "COMPLETED",
    }


def enable_transaction_flags(client) -> None:
    response = client.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": PROTECT_API_KEY,
            "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["alarm_configured"] is True


def square_webhook_body(payment_id: str) -> bytes:
    return json.dumps(
        {
            "merchant_id": SQUARE_MERCHANT_ID,
            "type": "payment.updated",
            "data": {
                "object": {
                    "payment": {
                        "id": payment_id,
                        "created_at": "2099-08-08T12:00:00.000Z",
                        "amount_money": {"amount": 99, "currency": "USD"},
                        "status": "COMPLETED",
                        "location_id": "LOC1",
                    }
                }
            },
        },
        separators=(",", ":"),
    ).encode()


def square_webhook_signature(body: bytes) -> str:
    digest = hmac.new(
        WEBHOOK_KEY.encode(),
        WEBHOOK_URL.encode() + body,
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode()


def wait_for_alarm_delivery(client, txn_id: str) -> dict:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        transaction_row = client.app.state.store.get_transaction(txn_id)
        if (
            transaction_row
            and transaction_row["alarm_state"] == "sent"
            and transaction_row["alarm_delivered_at_ms"] is not None
        ):
            return transaction_row
        time.sleep(0.01)
    raise AssertionError(f"Protect flag for {txn_id} was not delivered")


def test_store_distinguishes_actual_accepts_from_suppressed_alarm_rows(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.upsert_transaction(transaction("DELIVERED", 1000))
        store.upsert_transaction(transaction("IN_PROGRESS", 2000))
        store.upsert_transaction(transaction("PENDING", 3000))
        delivered_claim = store.claim_alarm_trigger("DELIVERED")
        in_progress_claim = store.claim_alarm_trigger("IN_PROGRESS")
        assert delivered_claim and in_progress_claim

        assert store.mark_alarm_sent(
            "DELIVERED",
            delivered_claim,
            delivered_at_ms=2345,
        )
        assert store.get_transaction("DELIVERED")["alarm_delivered_at_ms"] == 2345
        assert store.alarm_delivery_summary() == {
            "pending": 1,
            "in_progress": 1,
            "delivered": 1,
            "last_delivered_at_ms": 2345,
        }
    finally:
        store.close()


def test_admin_can_inspect_and_explicitly_test_configured_protect_flag(configured):
    unconfigured = configured.get("/api/settings/protect/alarm")
    assert unconfigured.status_code == 200
    assert unconfigured.headers["cache-control"] == "private, no-store"
    assert unconfigured.headers["x-protect-console-generation"]
    assert unconfigured.json() == {
        "configured": False,
        "trigger_id": "",
        "pending": 0,
        "in_progress": 0,
        "delivered": 0,
        "last_delivered_at_ms": None,
    }
    assert configured.post("/api/settings/protect/alarm/test").status_code == 409

    enable_transaction_flags(configured)
    status = configured.get("/api/settings/protect/alarm")
    assert status.json()["configured"] is True
    assert status.json()["trigger_id"] == PROTECT_ALARM_TRIGGER_ID
    assert PROTECT_API_KEY not in status.text

    tested = configured.post("/api/settings/protect/alarm/test")
    assert tested.status_code == 200, tested.text
    assert tested.json()["test_accepted_at_ms"] > 0
    assert tested.json()["delivered"] == 0
    assert PROTECT_ALARM_CALLS == [PROTECT_ALARM_TRIGGER_ID]

    PROTECT_ALARM_RESPONSES.append(500)
    rejected = configured.post("/api/settings/protect/alarm/test")
    assert rejected.status_code == 502
    assert "rejected" in rejected.json()["detail"]


def test_square_webhook_records_protect_accept_time_and_measured_offset(configured):
    enable_transaction_flags(configured)
    body = square_webhook_body("PAY_FLAG_STATUS")
    response = configured.post(
        "/webhooks/square",
        content=body,
        headers={
            "x-square-hmacsha256-signature": square_webhook_signature(body)
        },
    )
    assert response.status_code == 200, response.text
    stored = wait_for_alarm_delivery(configured, "PAY_FLAG_STATUS")
    assert PROTECT_ALARM_CALLS == [PROTECT_ALARM_TRIGGER_ID]

    listed = configured.get("/api/transactions").json()
    delivered = next(row for row in listed if row["id"] == "PAY_FLAG_STATUS")
    assert delivered["protect_flag_delivered_at_ms"] == stored[
        "alarm_delivered_at_ms"
    ]
    assert delivered["protect_flag_offset_ms"] == (
        stored["alarm_delivered_at_ms"] - stored["ts_ms"]
    )

    status = configured.get("/api/settings/protect/alarm").json()
    assert status["delivered"] == 1
    assert status["pending"] == status["in_progress"] == 0
    assert status["last_delivered_at_ms"] == stored["alarm_delivered_at_ms"]
    dashboard = configured.get("/api/dashboard").json()
    assert dashboard["transaction_flags"] == {
        "configured": True,
        "pending": 0,
        "in_progress": 0,
        "delivered": 1,
        "last_delivered_at_ms": stored["alarm_delivered_at_ms"],
    }

    duplicate = configured.post(
        "/webhooks/square",
        content=body,
        headers={
            "x-square-hmacsha256-signature": square_webhook_signature(body)
        },
    )
    assert duplicate.status_code == 200
    client_executor = configured.app.state.thumbnail_executor
    client_executor.submit(lambda: None).result(timeout=3)
    assert PROTECT_ALARM_CALLS == [PROTECT_ALARM_TRIGGER_ID]
