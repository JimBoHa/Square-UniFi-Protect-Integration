"""End-to-end API tests against mocked Square and UniFi Protect backends."""

import base64
import hashlib
import hmac
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from fastapi.testclient import TestClient

from app.main import create_app
from app.store import Store
from app.sync import enrich_transaction_thumbnail, ingest_payment

from .conftest import (
    ADMIN_PASSWORD,
    PROTECT_ALARM_CALLS,
    PROTECT_ALARM_RESPONSES,
    PROTECT_ALARM_TRIGGER_ID,
    PROTECT_API_KEY,
    PROTECT_META_KEYS,
    PROTECT_PASS,
    PROTECT_USER,
    SQUARE_TOKEN,
    WEBHOOK_KEY,
    WEBHOOK_URL,
    protect_handler,
    square_handler,
)

CAM1 = "cam1aaaaaaaaaaaaaaaaaaaaa"
CAM2 = "cam2bbbbbbbbbbbbbbbbbbbbb"


# -- setup / login flow ------------------------------------------------------------

def test_status_reports_setup_state(client):
    status = client.get("/api/status").json()
    assert status == {
        "setup_complete": False,
        "protect_configured": False,
        "square_configured": False,
        "cameras_mapped": False,
    }

def test_setup_then_login(client):
    assert client.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
    assert client.get("/api/status").json()["setup_complete"] is True
    resp = client.post("/api/login", json={"password": ADMIN_PASSWORD})
    assert resp.status_code == 200
    assert client.get("/api/camera-mapping").status_code == 200

def test_setup_rejects_short_password(client):
    assert client.post("/api/setup", json={"password": "short"}).status_code == 422

def test_login_wrong_password(client):
    client.post("/api/setup", json={"password": ADMIN_PASSWORD})
    assert client.post("/api/login", json={"password": "wrong-password"}).status_code == 401

def test_logout_invalidates_session(authed):
    assert authed.get("/api/camera-mapping").status_code == 200
    assert authed.post("/api/logout").status_code == 200
    assert authed.get("/api/camera-mapping").status_code == 401


# -- settings ------------------------------------------------------------------------

def test_protect_settings_validates_credentials(authed):
    resp = authed.put(
        "/api/settings/protect",
        json={"host": "192.168.1.1", "username": PROTECT_USER, "password": "bad-pass"},
    )
    assert resp.status_code == 401
    assert authed.get("/api/status").json()["protect_configured"] is False

def test_protect_settings_success(authed):
    resp = authed.put(
        "/api/settings/protect",
        json={"host": "192.168.1.1", "username": PROTECT_USER, "password": PROTECT_PASS},
    )
    assert resp.status_code == 200
    assert resp.json()["cameras"] == 2
    assert authed.get("/api/status").json()["protect_configured"] is True

def test_protect_alarm_settings_verify_and_encrypt_api_key(authed, tmp_path):
    bad = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": "wrong-api-key",
            "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
        },
    )
    assert bad.status_code == 401
    assert authed.app.state.store.get_setting("protect.api_key") is None

    good = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": PROTECT_API_KEY,
            "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
        },
    )
    assert good.status_code == 200
    assert good.json()["alarm_configured"] is True
    assert PROTECT_META_KEYS == ["wrong-api-key", PROTECT_API_KEY]
    assert authed.app.state.store.get_setting("protect.api_key") == PROTECT_API_KEY
    assert (
        authed.app.state.store.get_setting("protect.alarm_trigger_id")
        == PROTECT_ALARM_TRIGGER_ID
    )
    assert PROTECT_API_KEY.encode() not in (tmp_path / "data" / "spi.db").read_bytes()

    PROTECT_META_KEYS.clear()
    preserved = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
        },
    )
    assert preserved.status_code == 200
    assert preserved.json()["alarm_configured"] is True
    assert PROTECT_META_KEYS == [PROTECT_API_KEY]

def test_protect_alarm_settings_can_be_disabled(authed):
    _enable_alarm(authed)

    resp = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "disable_alarm": True,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["alarm_configured"] is False
    assert authed.app.state.store.get_setting("protect.api_key") is None
    assert authed.app.state.store.get_setting("protect.alarm_trigger_id") is None

def test_protect_settings_reject_malformed_alarm_trigger(authed):
    resp = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": PROTECT_API_KEY,
            "alarm_trigger_id": "../trigger?all=true",
        },
    )
    assert resp.status_code == 422
    assert PROTECT_META_KEYS == []

def test_square_settings_validates_token(authed):
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": "bad-token", "environment": "production"},
    )
    assert resp.status_code == 401
    assert authed.get("/api/status").json()["square_configured"] is False

def test_square_settings_success(authed):
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert resp.status_code == 200
    assert resp.json()["locations"] == [
        {"id": "LOC1", "name": "Main Store", "status": "ACTIVE"}
    ]


# -- cameras, locations, POS camera selection ------------------------------------------

def test_cameras_requires_protect_config(authed):
    assert authed.get("/api/cameras").status_code == 409

def test_camera_and_location_listing(configured):
    cameras = configured.get("/api/cameras").json()
    assert {c["name"] for c in cameras} == {"Front Counter", "Back Door"}
    locations = configured.get("/api/locations").json()
    assert locations[0]["id"] == "LOC1"

def test_camera_mapping_roundtrip(configured):
    mapping = configured.get("/api/camera-mapping").json()
    assert mapping == [
        {"location_id": "LOC1", "camera_id": CAM1, "camera_name": "Front Counter"}
    ]

def test_camera_preview_returns_jpeg(configured):
    resp = configured.get(f"/api/camera-preview/{CAM1}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/jpeg"
    assert resp.content.startswith(b"\xff\xd8")


# -- transactions: sync, thumbnails, deep links ------------------------------------------

def test_sync_ingests_square_payments(configured):
    resp = configured.post("/api/sync")
    assert resp.status_code == 200
    assert resp.json()["ingested"] == 2

    txns = configured.get("/api/transactions").json()
    assert len(txns) == 2
    # Newest first
    assert txns[0]["id"] == "PAY_002"
    assert txns[1]["id"] == "PAY_001"

    first = txns[1]
    assert first["amount"] == 1250
    assert first["currency"] == "USD"
    assert first["card_last4"] == "4242"
    assert first["created_at"] == "2026-07-16T15:30:00.000Z"
    assert first["camera_id"] == CAM1

def test_transaction_deep_link_points_at_protect_timeline(configured):
    configured.post("/api/sync")
    txn = configured.get("/api/transactions").json()[-1]
    assert txn["deep_link"] == (
        f"https://192.168.1.1/protect/timeline/{CAM1}?ts={txn['ts_ms']}"
    )

def test_transaction_thumbnail_served(configured):
    configured.post("/api/sync")
    txn = configured.get("/api/transactions").json()[0]
    assert txn["thumbnail_url"] == f"/api/thumbnails/{txn['id']}"
    resp = configured.get(txn["thumbnail_url"])
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/jpeg"
    # The mock embeds the requested ts in the image; the snapshot must have been
    # taken at the transaction's timestamp, not "now".
    assert resp.content.endswith(str(txn["ts_ms"]).encode())

def test_sync_is_idempotent(configured):
    configured.post("/api/sync")
    configured.post("/api/sync")
    assert len(configured.get("/api/transactions").json()) == 2

def test_transactions_without_camera_mapping_still_listed(authed):
    authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert authed.post("/api/sync").json()["ingested"] == 2
    txns = authed.get("/api/transactions").json()
    assert all(t["thumbnail_url"] is None for t in txns)
    assert all(t["deep_link"] is None for t in txns)

def test_thumbnail_missing_returns_404(configured):
    assert configured.get("/api/thumbnails/NOPE").status_code == 404


# -- Square webhook ---------------------------------------------------------------------

def _webhook_signature(body: bytes) -> str:
    return base64.b64encode(
        hmac.new(WEBHOOK_KEY.encode(), WEBHOOK_URL.encode() + body, hashlib.sha256).digest()
    ).decode()

def make_webhook_event(
    payment_id: str = "PAY_HOOK", status: str = "COMPLETED"
) -> bytes:
    return json.dumps(
        {
            "type": "payment.updated",
            "data": {
                "object": {
                    "payment": {
                        "id": payment_id,
                        "created_at": "2026-07-16T16:00:00.000Z",
                        "amount_money": {"amount": 500, "currency": "USD"},
                        "status": status,
                        "location_id": "LOC1",
                        "card_details": {"card": {"last_4": "9999"}},
                    }
                }
            },
        }
    ).encode()


def _wait_for_thumbnail(client, payment_id: str, timeout: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        txns = client.get("/api/transactions?limit=500").json()
        txn = next((item for item in txns if item["id"] == payment_id), None)
        if txn and txn["thumbnail_url"]:
            return txn
        time.sleep(0.01)
    raise AssertionError(f"thumbnail enrichment did not finish for {payment_id}")


def test_webhook_stores_payment_then_enriches_thumbnail(configured):
    body = make_webhook_event()
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    txns = configured.get("/api/transactions").json()
    assert txns[0]["id"] == "PAY_HOOK"
    assert txns[0]["deep_link"] is not None
    txn = _wait_for_thumbnail(configured, "PAY_HOOK")
    assert configured.get(txn["thumbnail_url"]).status_code == 200


def test_webhook_ack_and_transaction_listing_do_not_wait_for_snapshot(tmp_path):
    snapshot_started = threading.Event()
    release_snapshot = threading.Event()

    def blocking_snapshot(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/snapshot"):
            snapshot_started.set()
            if not release_snapshot.wait(timeout=10):
                raise httpx.ReadTimeout("snapshot test timed out", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_snapshot),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/camera-mapping",
                json={
                    "mappings": [
                        {
                            "location_id": "LOC1",
                            "camera_id": CAM1,
                            "camera_name": "Front Counter",
                        }
                    ]
                },
            ).status_code == 200

            body = make_webhook_event("PAY_BLOCKED")
            with ThreadPoolExecutor(max_workers=1) as requester:
                response_future = requester.submit(
                    isolated.post,
                    "/webhooks/square",
                    content=body,
                    headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
                )
                try:
                    assert snapshot_started.wait(timeout=3)
                    response = response_future.result(timeout=2)
                    assert response.status_code == 200
                    assert not release_snapshot.is_set()

                    listing = isolated.get("/api/transactions")
                    assert listing.status_code == 200
                    txn = next(
                        item for item in listing.json() if item["id"] == "PAY_BLOCKED"
                    )
                    assert txn["thumbnail_url"] is None
                    assert txn["deep_link"] is not None
                finally:
                    release_snapshot.set()

            txn = _wait_for_thumbnail(isolated, "PAY_BLOCKED")
            assert isolated.get(txn["thumbnail_url"]).status_code == 200
    finally:
        release_snapshot.set()
        app.state.store.close()


def test_thumbnail_enrichment_retries_if_camera_changes_in_flight(tmp_path):
    snapshot_started = threading.Event()
    release_snapshot = threading.Event()

    class BlockingProtect:
        def __init__(self):
            self.calls = []

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls.append((camera_id, ts_ms))
            if len(self.calls) == 1:
                snapshot_started.set()
                assert release_snapshot.wait(timeout=5)
            return b"snapshot:" + camera_id.encode()

    payment = {
        "id": "PAY_CAMERA_RACE",
        "created_at": "2026-07-16T16:00:00.000Z",
        "amount_money": {"amount": 500, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
    }
    store = Store(tmp_path / "data")
    protect = BlockingProtect()
    try:
        store.set_camera_mapping("LOC1", CAM1, "Front Counter")
        ingest_payment(store, payment, None)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                enrich_transaction_thumbnail,
                store,
                payment["id"],
                protect,
            )
            assert snapshot_started.wait(timeout=3)
            store.set_camera_mapping("LOC1", CAM2, "Back Door")
            ingest_payment(store, payment, None)
            release_snapshot.set()
            assert future.result(timeout=5) is True

        txn = store.get_transaction(payment["id"])
        assert txn["camera_id"] == CAM2
        assert protect.calls == [(CAM1, txn["ts_ms"]), (CAM2, txn["ts_ms"])]
        assert (store.thumbnail_dir / txn["thumbnail_path"]).read_bytes() == (
            b"snapshot:" + CAM2.encode()
        )
    finally:
        release_snapshot.set()
        store.close()


def test_webhook_thumbnail_queue_is_bounded(tmp_path, monkeypatch):
    max_pending = 4
    monkeypatch.setattr("app.main.WEBHOOK_THUMBNAIL_MAX_PENDING", max_pending)
    release_snapshots = threading.Event()

    def blocking_snapshot(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/snapshot"):
            assert release_snapshots.wait(timeout=10)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_snapshot),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/camera-mapping",
                json={
                    "mappings": [
                        {
                            "location_id": "LOC1",
                            "camera_id": CAM1,
                            "camera_name": "Front Counter",
                        }
                    ]
                },
            ).status_code == 200

            for index in range(max_pending + 3):
                body = make_webhook_event(f"PAY_QUEUE_{index}")
                response = isolated.post(
                    "/webhooks/square",
                    content=body,
                    headers={
                        "x-square-hmacsha256-signature": _webhook_signature(body)
                    },
                )
                assert response.status_code == 200

            assert len(app.state.thumbnail_jobs) == max_pending
            assert len(isolated.get("/api/transactions?limit=500").json()) == (
                max_pending + 3
            )
            release_snapshots.set()
    finally:
        release_snapshots.set()
        app.state.store.close()

def _enable_alarm(client):
    resp = client.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": PROTECT_API_KEY,
            "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
        },
    )
    assert resp.status_code == 200, resp.text

def test_completed_payments_trigger_once_across_sync_and_webhook(configured):
    _enable_alarm(configured)

    assert configured.post("/api/sync").status_code == 200
    assert PROTECT_ALARM_CALLS == [
        PROTECT_ALARM_TRIGGER_ID,
        PROTECT_ALARM_TRIGGER_ID,
    ]
    assert configured.post("/api/sync").status_code == 200

    body = make_webhook_event("PAY_001")
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    assert PROTECT_ALARM_CALLS == [
        PROTECT_ALARM_TRIGGER_ID,
        PROTECT_ALARM_TRIGGER_ID,
    ]

def test_enabling_alarm_does_not_replay_existing_completed_sales(configured):
    assert configured.post("/api/sync").status_code == 200
    _enable_alarm(configured)

    assert configured.post("/api/sync").status_code == 200
    assert PROTECT_ALARM_CALLS == []

def test_pending_payment_triggers_when_it_becomes_completed(configured):
    _enable_alarm(configured)

    pending = make_webhook_event("PAY_TRANSITION", status="PENDING")
    assert configured.post(
        "/webhooks/square",
        content=pending,
        headers={"x-square-hmacsha256-signature": _webhook_signature(pending)},
    ).status_code == 200
    assert PROTECT_ALARM_CALLS == []

    completed = make_webhook_event("PAY_TRANSITION", status="COMPLETED")
    assert configured.post(
        "/webhooks/square",
        content=completed,
        headers={"x-square-hmacsha256-signature": _webhook_signature(completed)},
    ).status_code == 200
    assert PROTECT_ALARM_CALLS == [PROTECT_ALARM_TRIGGER_ID]

def test_alarm_failure_persists_transaction_and_retries(configured):
    _enable_alarm(configured)
    PROTECT_ALARM_RESPONSES.extend([500, 204])
    body = make_webhook_event("PAY_RETRY")
    headers = {"x-square-hmacsha256-signature": _webhook_signature(body)}

    assert configured.post("/webhooks/square", content=body, headers=headers).status_code == 200
    transaction = configured.app.state.store.get_transaction("PAY_RETRY")
    assert transaction is not None
    assert transaction["alarm_state"] == "idle"

    assert configured.post("/api/sync").status_code == 200
    assert configured.app.state.store.get_transaction("PAY_RETRY")["alarm_state"] == "sent"
    assert len(PROTECT_ALARM_CALLS) == 4

    assert configured.post("/webhooks/square", content=body, headers=headers).status_code == 200
    assert len(PROTECT_ALARM_CALLS) == 4

def test_webhook_ignores_non_payment_events(configured):
    body = json.dumps({"type": "inventory.count.updated", "data": {}}).encode()
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    assert resp.json().get("ignored") is True
