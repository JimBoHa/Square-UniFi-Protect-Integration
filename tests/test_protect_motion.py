"""Protect-native motion-zone webhook and missing-sale alert tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3

import pytest

import app.main as main_module
import app.store as store_module
from app.protect_motion import (
    MAX_FUTURE_SKEW_MS,
    PROTECT_MOTION_WEBHOOK_MAX_BODY_BYTES,
    ProtectMotionPayloadError,
    get_delivery_event_key,
    parse_protect_motion_payload,
)
from app.store import (
    MOTION_WEBHOOK_TOKEN_SETTING,
    MotionWebhookUnauthorized,
    PROTECT_CONSOLE_GENERATION_SETTING,
    SquareAccountSwitchRequired,
    Store,
)

from .conftest import PROTECT_PASS, PROTECT_USER


CAMERA_ID = "cam1aaaaaaaaaaaaaaaaaaaaa"
OTHER_CAMERA_ID = "cam2bbbbbbbbbbbbbbbbbbbbb"
MOTION_PATH = "/webhooks/protect/motion"


def motion_payload(timestamp: int, *, source: str = "motion") -> dict:
    return {
        "alarm": {
            "name": "Barn East register zone",
            "sources": [],
            "conditions": [
                {"condition": {"type": "is", "source": source}}
            ],
            "triggers": [{"key": source, "device": "74ACB99F4E24"}],
        },
        "timestamp": timestamp,
    }


def configure_motion(client, **overrides) -> tuple[dict, str]:
    body = {
        "camera_id": CAMERA_ID,
        "match_window_seconds": 15,
        "grace_seconds": 90,
        "retention_days": 30,
        **overrides,
    }
    response = client.put("/api/settings/protect/motion-webhook", json=body)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["enabled"] is True
    assert result["webhook_path"] == MOTION_PATH
    assert result["webhook_header"] == "X-SPI-Webhook-Token"
    return result, result["webhook_token"]


def transaction(txn_id: str, ts_ms: int, camera_id: str) -> dict:
    return {
        "id": txn_id,
        "created_at": "2026-07-16T15:30:00.000Z",
        "ts_ms": ts_ms,
        "updated_at": "2026-07-16T15:30:00.000Z",
        "updated_ts_ms": ts_ms,
        "amount": 99,
        "currency": "USD",
        "status": "COMPLETED",
        "location_id": "LOC1",
        "camera_id": camera_id,
    }


def configure_store(store: Store, *, grace_seconds: int = 90) -> str:
    _config, token = store.configure_motion_webhook(
        camera_id=CAMERA_ID,
        camera_name="Barn East",
        match_window_seconds=15,
        grace_seconds=grace_seconds,
        retention_days=30,
    )
    assert token is not None
    return token


def test_documented_post_payload_is_normalized_and_deduped():
    now = 1_800_000_000_000
    first = motion_payload(now - 1234)
    second = motion_payload(now - 1234)
    second["alarm"]["triggers"].append(
        {"key": "motion", "device": "SECOND-CAMERA"}
    )
    reversed_second = json.loads(json.dumps(second))
    reversed_second["alarm"]["triggers"].reverse()

    parsed = parse_protect_motion_payload(
        json.dumps(first).encode(),
        received_at_ms=now,
        oldest_allowed_ms=now - 86_400_000,
    )
    ordered = parse_protect_motion_payload(
        json.dumps(second).encode(),
        received_at_ms=now,
        oldest_allowed_ms=now - 86_400_000,
    )
    reversed_delivery = parse_protect_motion_payload(
        json.dumps(reversed_second).encode(),
        received_at_ms=now,
        oldest_allowed_ms=now - 86_400_000,
    )

    assert parsed.event_ts_ms == now - 1234
    assert parsed.alarm_name == "Barn East register zone"
    assert parsed.device_identifiers == ("74ACB99F4E24",)
    assert parsed.event_key.startswith("post:")
    assert ordered.event_key == reversed_delivery.event_key
    assert ordered.device_identifiers != reversed_delivery.device_identifiers


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        ({}, "timestamp"),
        ({"timestamp": True, "alarm": {}}, "timestamp"),
        (motion_payload(1_800_000_000_000, source="person"), "did not report motion"),
        ({"timestamp": 1_800_000_000_000, "alarm": []}, "alarm is invalid"),
    ),
)
def test_post_parser_rejects_malformed_or_nonmotion_payload(payload, message):
    with pytest.raises(ProtectMotionPayloadError, match=message):
        parse_protect_motion_payload(
            json.dumps(payload).encode(),
            received_at_ms=1_800_000_000_000,
            oldest_allowed_ms=1_799_000_000_000,
        )


def test_post_parser_bounds_time_body_and_metadata():
    now = 1_800_000_000_000
    too_old = motion_payload(now - 1001)
    too_future = motion_payload(now + MAX_FUTURE_SKEW_MS + 1)
    bad_name = motion_payload(now)
    bad_name["alarm"]["name"] = "x" * 257

    with pytest.raises(ProtectMotionPayloadError, match="too old"):
        parse_protect_motion_payload(
            json.dumps(too_old).encode(),
            received_at_ms=now,
            oldest_allowed_ms=now - 1000,
        )
    with pytest.raises(ProtectMotionPayloadError, match="future"):
        parse_protect_motion_payload(
            json.dumps(too_future).encode(),
            received_at_ms=now,
            oldest_allowed_ms=0,
        )
    with pytest.raises(ProtectMotionPayloadError, match="alarm name"):
        parse_protect_motion_payload(
            json.dumps(bad_name).encode(),
            received_at_ms=now,
            oldest_allowed_ms=0,
        )
    with pytest.raises(ProtectMotionPayloadError, match="size"):
        parse_protect_motion_payload(
            b" " * (PROTECT_MOTION_WEBHOOK_MAX_BODY_BYTES + 1),
            received_at_ms=now,
            oldest_allowed_ms=0,
        )
    with pytest.raises(ProtectMotionPayloadError, match="valid JSON|object"):
        parse_protect_motion_payload(
            b"[" * 2000 + b"0" + b"]" * 2000,
            received_at_ms=now,
            oldest_allowed_ms=0,
        )


def test_get_event_keys_coalesce_only_one_camera_and_five_second_bucket():
    assert get_delivery_event_key(CAMERA_ID, 10_001) == get_delivery_event_key(
        CAMERA_ID, 14_999
    )
    assert get_delivery_event_key(CAMERA_ID, 14_999) != get_delivery_event_key(
        CAMERA_ID, 15_000
    )
    assert get_delivery_event_key(CAMERA_ID, 10_001) != get_delivery_event_key(
        OTHER_CAMERA_ID, 10_001
    )


def test_store_encrypts_rotates_and_invalidates_webhook_token(tmp_path):
    store = Store(tmp_path / "data")
    try:
        first = configure_store(store)
        status = store.motion_webhook_config()
        assert status["enabled"] is True
        assert "webhook_token" not in status
        with sqlite3.connect(store.data_dir / "spi.db") as connection:
            row = connection.execute(
                "SELECT value, encrypted FROM settings WHERE key = ?",
                (MOTION_WEBHOOK_TOKEN_SETTING,),
            ).fetchone()
        assert row[1] == 1
        assert row[0] != first

        _config, second = store.configure_motion_webhook(
            camera_id=CAMERA_ID,
            camera_name="Barn East",
            match_window_seconds=15,
            grace_seconds=90,
            retention_days=30,
            rotate_token=True,
        )
        assert second and second != first
        with pytest.raises(MotionWebhookUnauthorized):
            store.authenticate_motion_webhook(first)
        assert store.authenticate_motion_webhook(second)["camera_id"] == CAMERA_ID

        store.disable_motion_webhook()
        assert store.motion_webhook_config()["enabled"] is False
        with pytest.raises(MotionWebhookUnauthorized):
            store.authenticate_motion_webhook(second)
    finally:
        store.close()


def test_changing_motion_camera_rotates_token_and_rejects_old_alarm(tmp_path):
    store = Store(tmp_path / "data")
    try:
        first = configure_store(store)
        _config, second = store.configure_motion_webhook(
            camera_id=OTHER_CAMERA_ID,
            camera_name="Other camera",
            match_window_seconds=15,
            grace_seconds=90,
            retention_days=30,
        )

        assert second and second != first
        with pytest.raises(MotionWebhookUnauthorized):
            store.authenticate_motion_webhook(first)
        assert (
            store.authenticate_motion_webhook(second)["camera_id"]
            == OTHER_CAMERA_ID
        )
    finally:
        store.close()


def test_motion_event_moves_pending_to_flagged_then_late_sale_resolves(tmp_path):
    store = Store(tmp_path / "data")
    now = 1_800_000_000_000
    try:
        token = configure_store(store, grace_seconds=90)
        store.record_motion_event(
            presented_token=token,
            event_key="post:event-one",
            event_ts_ms=now,
            received_at_ms=now,
            delivery_method="post",
            alarm_name="Barn East",
        )
        assert store.motion_alert_summary(now_ms=now) == {
            "matched": 0,
            "pending": 1,
            "flagged": 0,
        }
        assert store.list_motion_alerts(now_ms=now)[0]["state"] == "pending"
        assert store.list_motion_alerts(now_ms=now + 90_000)[0]["state"] == "flagged"

        store.upsert_transaction(transaction("OTHER", now + 1000, OTHER_CAMERA_ID))
        assert store.list_motion_alerts(now_ms=now + 90_000)[0]["state"] == "flagged"
        store.upsert_transaction(transaction("MATCH", now + 3000, CAMERA_ID))

        assert store.list_motion_alerts(now_ms=now + 90_000) == []
        matched = store.list_motion_alerts(
            now_ms=now + 90_000,
            include_matched=True,
        )[0]
        assert matched["state"] == "matched"
        assert matched["matched_transaction_id"] == "MATCH"
        assert matched["transaction_delta_ms"] == 3000
        assert store.motion_alert_summary(now_ms=now + 90_000) == {
            "matched": 1,
            "pending": 0,
            "flagged": 0,
        }
    finally:
        store.close()


def test_future_nvr_clock_skew_does_not_flag_before_event_grace(tmp_path):
    store = Store(tmp_path / "data")
    received_at = 1_800_000_000_000
    event_at = received_at + 60_000
    try:
        token = configure_store(store, grace_seconds=30)
        store.record_motion_event(
            presented_token=token,
            event_key="post:future-clock",
            event_ts_ms=event_at,
            received_at_ms=received_at,
            delivery_method="post",
        )

        assert (
            store.list_motion_alerts(now_ms=event_at + 29_999)[0]["state"]
            == "pending"
        )
        assert (
            store.list_motion_alerts(now_ms=event_at + 30_000)[0]["state"]
            == "flagged"
        )
    finally:
        store.close()


def test_duplicate_delivery_is_atomic_across_store_instances(tmp_path):
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    token = configure_store(first)
    second = Store(data_dir)
    now = 1_800_000_000_000

    def record(store):
        return store.record_motion_event(
            presented_token=token,
            event_key="post:same-delivery",
            event_ts_ms=now,
            received_at_ms=now,
            delivery_method="post",
        )["created"]

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            created = list(executor.map(record, (first, second)))
        assert sorted(created) == [False, True]
        assert len(first.list_motion_alerts(now_ms=now)) == 1
    finally:
        first.close()
        second.close()


def test_event_retention_and_hard_row_cap_are_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_MOTION_EVENTS", 3)
    store = Store(tmp_path / "data")
    now = 1_800_000_000_000
    try:
        token = configure_store(store, grace_seconds=0)
        for index in range(5):
            store.record_motion_event(
                presented_token=token,
                event_key=f"post:{index}",
                event_ts_ms=now + index,
                received_at_ms=now + index,
                delivery_method="post",
            )
        with store._lock:
            count = store._db.execute(
                "SELECT COUNT(*) AS count FROM protect_motion_events"
            ).fetchone()["count"]
        assert count == 3
        assert len(
            store.list_motion_alerts(now_ms=now + 30 * 86_400_000 + 5)
        ) == 0
    finally:
        store.close()


def test_protect_console_switch_clears_detector_and_old_events(tmp_path):
    store = Store(tmp_path / "data")
    now = 1_800_000_000_000
    first_settings = {
        "protect.host": ("192.168.1.10", False),
        "protect.username": ("protect", False),
        "protect.password": ("password", True),
        "protect.verify_ssl": ("0", False),
    }
    second_settings = {**first_settings, "protect.host": ("192.168.1.11", False)}
    try:
        assert store.update_protect_settings(
            first_settings,
            expected_host=None,
            expected_generation=None,
            observed_console_id="console-one",
        ) is False
        token = configure_store(store)
        store.record_motion_event(
            presented_token=token,
            event_key="post:old-console",
            event_ts_ms=now,
            received_at_ms=now,
            delivery_method="post",
        )
        generation = store.get_setting(PROTECT_CONSOLE_GENERATION_SETTING)
        confirmation = store.protect_console_switch_token(
            "192.168.1.11",
            "console-two",
            expected_host="192.168.1.10",
            expected_generation=generation,
            expected_console_id="console-one",
        )
        assert confirmation
        assert store.update_protect_settings(
            second_settings,
            expected_host="192.168.1.10",
            expected_generation=generation,
            expected_console_id="console-one",
            observed_console_id="console-two",
            console_switch_token=confirmation,
        ) is True
        assert store.motion_webhook_config()["enabled"] is False
        assert store.list_motion_alerts(now_ms=now, include_matched=True) == []
    finally:
        store.close()


def test_square_account_switch_clears_events_but_keeps_detector(tmp_path):
    store = Store(tmp_path / "data")
    now = 1_800_000_000_000
    try:
        store.configure_square_account(
            merchant_id="merchant-one",
            access_token="token-one",
            environment="sandbox",
        )
        token = configure_store(store)
        store.record_motion_event(
            presented_token=token,
            event_key="post:old-merchant",
            event_ts_ms=now,
            received_at_ms=now,
            delivery_method="post",
        )
        with pytest.raises(SquareAccountSwitchRequired) as required:
            store.configure_square_account(
                merchant_id="merchant-two",
                access_token="token-two",
                environment="sandbox",
            )
        store.configure_square_account(
            merchant_id="merchant-two",
            access_token="token-two",
            environment="sandbox",
            confirm_account_switch=True,
            account_switch_confirmation_token=required.value.confirmation_token,
        )
        assert store.motion_webhook_config()["enabled"] is True
        assert store.list_motion_alerts(now_ms=now, include_matched=True) == []
        assert store.authenticate_motion_webhook(token)["camera_id"] == CAMERA_ID
    finally:
        store.close()


def test_admin_configures_camera_and_token_is_only_revealed_once(configured):
    result, token = configure_motion(configured)
    assert result["camera_name"] == "Front Counter"
    assert token
    assert result["last_event_ms"] is None

    reloaded = configured.get("/api/settings/protect/motion-webhook")
    assert reloaded.status_code == 200
    assert reloaded.json()["token_configured"] is True
    assert "webhook_token" not in reloaded.json()
    assert reloaded.headers["x-protect-console-generation"]

    unknown = configured.put(
        "/api/settings/protect/motion-webhook",
        json={"camera_id": "unknowncamera"},
    )
    assert unknown.status_code == 422
    assert "not found" in unknown.json()["detail"]


def test_get_webhook_uses_lan_receipt_time_and_custom_or_bearer_token(
    configured,
    monkeypatch,
):
    _settings, token = configure_motion(configured, grace_seconds=0)
    now_seconds = main_module.time.time()
    monkeypatch.setattr(main_module.time, "time", lambda: now_seconds)

    first = configured.get(
        MOTION_PATH,
        headers={"X-SPI-Webhook-Token": token},
    )
    duplicate = configured.get(
        MOTION_PATH,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert first.status_code == duplicate.status_code == 204
    events = configured.get("/api/motion-alerts?include_matched=true").json()[
        "events"
    ]
    assert len(events) == 1
    assert events[0]["event_ts_ms"] == int(now_seconds * 1000)
    assert events[0]["delivery_method"] == "get"
    assert events[0]["state"] == "flagged"


def test_post_webhook_uses_protect_time_dedupes_and_late_sync_resolves(
    configured,
    monkeypatch,
):
    event_ts = 1_784_215_803_000  # PAY_001 plus three seconds.
    monkeypatch.setattr(main_module.time, "time", lambda: event_ts / 1000)
    _settings, token = configure_motion(configured, grace_seconds=90)
    headers = {"X-SPI-Webhook-Token": token}
    payload = motion_payload(event_ts)

    first = configured.post(MOTION_PATH, headers=headers, json=payload)
    duplicate = configured.post(MOTION_PATH, headers=headers, json=payload)
    assert first.status_code == duplicate.status_code == 204
    pending = configured.get("/api/motion-alerts?include_matched=true").json()
    assert pending["summary"] == {"matched": 0, "pending": 1, "flagged": 0}
    assert pending["events"][0]["event_ts_ms"] == event_ts
    assert pending["events"][0]["device_identifiers"] == ["74ACB99F4E24"]

    monkeypatch.setattr(main_module.time, "time", lambda: event_ts / 1000 + 91)
    flagged = configured.get("/api/motion-alerts").json()
    assert flagged["summary"]["flagged"] == 1
    assert flagged["events"][0]["deep_link"]

    assert configured.post("/api/sync").status_code == 200
    assert configured.get("/api/motion-alerts").json()["events"] == []
    matched = configured.get(
        "/api/motion-alerts?include_matched=true"
    ).json()
    assert matched["summary"] == {"matched": 1, "pending": 0, "flagged": 0}
    assert matched["events"][0]["matched_transaction_id"] == "PAY_001"
    assert matched["events"][0]["transaction_delta_ms"] == -3000


def test_webhook_rejects_public_peer_bad_token_query_and_ambiguous_headers(
    configured,
):
    _settings, token = configure_motion(configured)
    assert configured.get(MOTION_PATH).status_code == 401
    assert configured.get(
        MOTION_PATH,
        headers={"X-SPI-Webhook-Token": "wrong"},
    ).status_code == 401
    assert configured.get(
        MOTION_PATH,
        headers={
            "X-SPI-Webhook-Token": token,
            "Authorization": "Bearer different",
        },
    ).status_code == 401
    assert configured.get(
        MOTION_PATH,
        headers={
            "X-SPI-Webhook-Token": token,
            "X-Forwarded-For": "10.0.0.5",
        },
    ).status_code == 403
    query = configured.get(
        f"{MOTION_PATH}?token={token}",
        headers={"X-SPI-Webhook-Token": token},
    )
    assert query.status_code == 400
    assert token not in query.text

    original_client = configured._transport.client
    configured._transport.client = ("10.200.30.40", 50000)
    try:
        routed_lan = configured.get(
            MOTION_PATH,
            headers={"X-SPI-Webhook-Token": token},
        )
        configured._transport.client = ("8.8.8.8", 50000)
        public = configured.get(
            MOTION_PATH,
            headers={"X-SPI-Webhook-Token": token},
        )
    finally:
        configured._transport.client = original_client
    assert routed_lan.status_code == 204
    assert public.status_code == 403


def test_webhook_auth_precedes_body_read_and_valid_requests_use_tight_cap(
    configured,
):
    _settings, token = configure_motion(configured)
    chunks_read = 0

    def hostile_chunks():
        nonlocal chunks_read
        chunks_read += 1
        yield b"{" + b"x" * PROTECT_MOTION_WEBHOOK_MAX_BODY_BYTES

    unauthorized = configured.post(
        MOTION_PATH,
        content=hostile_chunks(),
        headers={"content-type": "application/json"},
    )
    assert unauthorized.status_code == 401
    assert chunks_read == 0

    oversized = configured.post(
        MOTION_PATH,
        content=b"{}",
        headers={
            "content-type": "application/json",
            "content-length": str(PROTECT_MOTION_WEBHOOK_MAX_BODY_BYTES + 1),
            "X-SPI-Webhook-Token": token,
        },
    )
    assert oversized.status_code == 413
    wrong_media = configured.post(
        MOTION_PATH,
        content=b"{}",
        headers={
            "content-type": "text/plain",
            "X-SPI-Webhook-Token": token,
        },
    )
    assert wrong_media.status_code == 415


def test_disabling_endpoint_invalidates_delivery_but_retains_history(configured):
    _settings, token = configure_motion(configured, grace_seconds=0)
    assert configured.get(
        MOTION_PATH,
        headers={"X-SPI-Webhook-Token": token},
    ).status_code == 204
    disabled = configured.delete("/api/settings/protect/motion-webhook")
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    assert configured.get(
        MOTION_PATH,
        headers={"X-SPI-Webhook-Token": token},
    ).status_code == 401
    assert configured.app.state.store.motion_alert_summary()["flagged"] == 1
