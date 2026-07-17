"""End-to-end API tests against mocked Square and UniFi Protect backends."""

import base64
import concurrent.futures
import hashlib
import hmac
import json
import threading
import time

import httpx
from fastapi.testclient import TestClient

from app.main import create_app
from app.square_client import SquareClient, SquarePermissionError
from app.store import Store
from app.sync import ingest_payment, retry_missing_thumbnails

from app.protect_client import ProtectClient
from app.sync import ingest_payment

from .conftest import (
    ADMIN_PASSWORD,
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

def test_concurrent_setup_has_single_winner(client):
    passwords = ("first-admin-password", "second-admin-password")

    def setup(password: str):
        return password, client.post("/api/setup", json={"password": password})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(setup, passwords))

    assert sorted(response.status_code for _, response in results) == [200, 409]
    winner = next(password for password, response in results if response.status_code == 200)
    loser = next(password for password, response in results if response.status_code == 409)
    assert client.post("/api/login", json={"password": winner}).status_code == 200
    assert client.post("/api/login", json={"password": loser}).status_code == 401

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

def test_square_settings_validates_token(authed):
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": "bad-token", "environment": "production"},
    )
    assert resp.status_code == 401
    assert authed.get("/api/status").json()["square_configured"] is False

def test_square_settings_requires_payments_read_permission(authed, monkeypatch):
    def reject_payment_read(_self, begin_time=None, limit=100):
        raise SquarePermissionError("scope missing")

    monkeypatch.setattr(SquareClient, "list_payments", reject_payment_read)
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == (
        "Square access token must grant PAYMENTS_READ permission"
    )
    assert authed.get("/api/status").json()["square_configured"] is False

def test_square_settings_reports_profile_permission_separately(authed, monkeypatch):
    def reject_profile_read(_self):
        raise SquarePermissionError("scope missing")

    monkeypatch.setattr(SquareClient, "list_locations", reject_profile_read)
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == (
        "Square access token must grant MERCHANT_PROFILE_READ permission"
    )
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

def test_square_settings_require_complete_webhook_pair(authed):
    resp = authed.put(
        "/api/settings/square",
        json={
            "access_token": SQUARE_TOKEN,
            "environment": "production",
            "webhook_signature_key": WEBHOOK_KEY,
        },
    )
    assert resp.status_code == 422
    assert authed.get("/api/status").json()["square_configured"] is False


def test_protect_settings_transport_error_returns_502(tmp_path):
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive upstream details", request=request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(unavailable),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
            resp = isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            )
        assert resp.status_code == 502
        assert resp.json()["detail"] == (
            "Could not reach UniFi Protect: Network error while contacting UniFi Protect"
        )
        assert "sensitive upstream details" not in resp.text
    finally:
        app.state.store.close()


def test_square_settings_transport_error_returns_502(tmp_path):
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive upstream details", request=request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(protect_handler),
        square_transport=httpx.MockTransport(unavailable),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
            resp = isolated.put(
                "/api/settings/square",
                json={"access_token": SQUARE_TOKEN, "environment": "production"},
            )
        assert resp.status_code == 502
        assert resp.json()["detail"] == (
            "Could not reach Square: Network error while contacting Square"
        )
        assert "sensitive upstream details" not in resp.text
    finally:
        app.state.store.close()


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
        {
            "location_id": "LOC1",
            "device_id": "",
            "device_name": "",
            "camera_id": CAM1,
            "camera_name": "Front Counter",
        }
    ]

def test_camera_mapping_accepts_255_character_device_name(configured):
    device_name = "R" * 255
    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "device_id": "TERM_LONG_NAME",
                    "device_name": device_name,
                    "camera_id": CAM1,
                    "camera_name": "Front Counter",
                }
            ]
        },
    )
    assert resp.status_code == 200
    assert configured.get("/api/camera-mapping").json()[0]["device_name"] == device_name

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
    first = configured.post("/api/sync")
    second = configured.post("/api/sync")
    assert first.json()["ingested"] == 2
    assert second.json()["ingested"] == 0
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


def test_snapshot_transport_error_stores_transaction_without_thumbnail(tmp_path):
    def snapshot_unavailable(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/snapshot"):
            raise httpx.ReadTimeout("sensitive snapshot details", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(snapshot_unavailable),
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
                json={"access_token": SQUARE_TOKEN, "environment": "production"},
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

            sync_resp = isolated.post("/api/sync")
            txns = isolated.get("/api/transactions").json()

        assert sync_resp.status_code == 200
        assert sync_resp.json()["ingested"] == 2
        assert len(txns) == 2
        assert all(txn["camera_id"] == CAM1 for txn in txns)
        assert all(txn["thumbnail_url"] is None for txn in txns)
        assert all(txn["deep_link"] is not None for txn in txns)
    finally:
        app.state.store.close()

def test_sync_persists_transactions_when_thumbnail_write_fails(configured, tmp_path):
    configured.app.state.store.thumbnail_dir = tmp_path / "missing" / "thumbnails"

    resp = configured.post("/api/sync")

    assert resp.status_code == 200
    assert resp.json()["ingested"] == 2
    txns = configured.get("/api/transactions").json()
    assert len(txns) == 2
    assert all(txn["thumbnail_url"] is None for txn in txns)
    assert all(txn["deep_link"] is not None for txn in txns)

def test_thumbnail_missing_returns_404(configured):
    assert configured.get("/api/thumbnails/NOPE").status_code == 404


# -- Square webhook ---------------------------------------------------------------------

def _webhook_signature(body: bytes) -> str:
    return base64.b64encode(
        hmac.new(WEBHOOK_KEY.encode(), WEBHOOK_URL.encode() + body, hashlib.sha256).digest()
    ).decode()

def make_webhook_event(
    payment_id: str = "PAY_HOOK",
    device_id: str = "",
    device_name: str = "",
) -> bytes:
    payment = {
        "id": payment_id,
        "created_at": "2026-07-16T16:00:00.000Z",
        "amount_money": {"amount": 500, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
        "card_details": {"card": {"last_4": "9999"}},
    }
    if device_id or device_name:
        payment["device_details"] = {
            "device_id": device_id,
            "device_name": device_name,
        }
    return json.dumps(
        {
            "type": "payment.updated",
            "data": {"object": {"payment": payment}},
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as requester:
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


def test_thumbnail_retry_recaptures_after_camera_changes_in_flight(tmp_path):
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

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(retry_missing_thumbnails, store, protect)
            assert snapshot_started.wait(timeout=3)
            # Remap while the first capture is in flight; the reset queue row
            # invalidates the old lease, so the CAM1 frame cannot attach.
            store.set_camera_mapping("LOC1", CAM2, "Back Door")
            ingest_payment(store, payment, None)
            release_snapshot.set()
            assert future.result(timeout=5) == 1

        txn = store.get_transaction(payment["id"])
        assert txn["camera_id"] == CAM2
        assert protect.calls == [(CAM1, txn["ts_ms"]), (CAM2, txn["ts_ms"])]
        assert (store.thumbnail_dir / txn["thumbnail_path"]).read_bytes() == (
            b"snapshot:" + CAM2.encode()
        )
    finally:
        release_snapshot.set()
        store.close()


def test_webhook_burst_acks_immediately_and_queue_drains_all(tmp_path):
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

            # A burst of webhooks all ack while Protect is still blocked.
            for index in range(7):
                body = make_webhook_event(f"PAY_QUEUE_{index}")
                response = isolated.post(
                    "/webhooks/square",
                    content=body,
                    headers={
                        "x-square-hmacsha256-signature": _webhook_signature(body)
                    },
                )
                assert response.status_code == 200

            listed = isolated.get("/api/transactions?limit=500").json()
            assert len(listed) == 7

            release_snapshots.set()
            for index in range(7):
                txn = _wait_for_thumbnail(isolated, f"PAY_QUEUE_{index}")
                assert isolated.get(txn["thumbnail_url"]).status_code == 200
    finally:
        release_snapshots.set()
        app.state.store.close()

def test_square_settings_resave_leaves_webhook_config_untouched(configured):
    store = configured.app.state.store
    resp = configured.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert resp.status_code == 200
    assert store.get_setting("square.webhook_signature_key") == WEBHOOK_KEY
    assert store.get_setting("square.webhook_url") == WEBHOOK_URL

def test_square_settings_rejects_clear_webhook_with_new_credentials(configured):
    resp = configured.put(
        "/api/settings/square",
        json={
            "access_token": SQUARE_TOKEN,
            "environment": "production",
            "webhook_signature_key": WEBHOOK_KEY,
            "webhook_url": WEBHOOK_URL,
            "clear_webhook": True,
        },
    )
    assert resp.status_code == 422

def test_square_settings_can_disable_existing_webhook(configured):
    store = configured.app.state.store
    assert store.get_setting("square.webhook_signature_key") == WEBHOOK_KEY
    assert store.get_setting("square.webhook_url") == WEBHOOK_URL

    resp = configured.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production", "clear_webhook": True},
    )
    assert resp.status_code == 200
    assert store.get_setting("square.webhook_signature_key") is None
    assert store.get_setting("square.webhook_url") is None

    body = make_webhook_event("PAY_DISABLED_HOOK")
    webhook_resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert webhook_resp.status_code == 403

def test_two_pos_devices_map_to_distinct_camera_evidence(configured, monkeypatch):
    snapshot_requests = []

    def record_snapshot(_self, camera_id, ts_ms=None, width=640):
        snapshot_requests.append((camera_id, ts_ms))
        return b"snapshot:" + camera_id.encode()

    monkeypatch.setattr(ProtectClient, "get_snapshot", record_snapshot)
    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "device_id": "TERM_A",
                    "device_name": "Register A",
                    "camera_id": CAM1,
                    "camera_name": "Front Counter",
                },
                {
                    "location_id": "LOC1",
                    "device_id": "TERM_B",
                    "device_name": "Register B",
                    "camera_id": CAM2,
                    "camera_name": "Back Door",
                },
            ]
        },
    )
    assert resp.status_code == 200
    assert configured.get("/api/camera-mapping").json() == [
        {
            "location_id": "LOC1",
            "device_id": "TERM_A",
            "device_name": "Register A",
            "camera_id": CAM1,
            "camera_name": "Front Counter",
        },
        {
            "location_id": "LOC1",
            "device_id": "TERM_B",
            "device_name": "Register B",
            "camera_id": CAM2,
            "camera_name": "Back Door",
        },
    ]

    for payment_id, device_id, device_name in (
        ("PAY_TERM_A", "TERM_A", "Register A"),
        ("PAY_TERM_B", "TERM_B", "Register B"),
    ):
        body = make_webhook_event(payment_id, device_id, device_name)
        resp = configured.post(
            "/webhooks/square",
            content=body,
            headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
        )
        assert resp.status_code == 200

    for payment_id, device_id, camera_id in (
        ("PAY_TERM_A", "TERM_A", CAM1),
        ("PAY_TERM_B", "TERM_B", CAM2),
    ):
        # Thumbnails attach asynchronously after the webhook ack.
        txn = _wait_for_thumbnail(configured, payment_id)
        assert txn["device_id"] == device_id
        assert txn["camera_id"] == camera_id
        assert txn["deep_link"] == (
            f"https://192.168.1.1/protect/timeline/{camera_id}?ts={txn['ts_ms']}"
        )
        thumbnail = configured.get(txn["thumbnail_url"])
        assert thumbnail.status_code == 200
        assert camera_id.encode() in thumbnail.content

    assert sorted(camera_id for camera_id, _ in snapshot_requests) == [CAM1, CAM2]
    assert configured.get("/api/pos-devices").json() == [
        {"location_id": "LOC1", "device_id": "TERM_A", "device_name": "Register A"},
        {"location_id": "LOC1", "device_id": "TERM_B", "device_name": "Register B"},
    ]

def test_payment_without_device_uses_location_fallback(configured, monkeypatch):
    snapshot_requests = []

    def record_snapshot(_self, camera_id, ts_ms=None, width=640):
        snapshot_requests.append(camera_id)
        return b"snapshot:" + camera_id.encode()

    monkeypatch.setattr(ProtectClient, "get_snapshot", record_snapshot)
    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "camera_id": CAM1,
                    "camera_name": "Front Counter",
                },
                {
                    "location_id": "LOC1",
                    "device_id": "TERM_A",
                    "device_name": "Register A",
                    "camera_id": CAM2,
                    "camera_name": "Back Door",
                },
            ]
        },
    )
    assert resp.status_code == 200

    body = make_webhook_event("PAY_NO_DEVICE")
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    # Thumbnails attach asynchronously after the webhook ack.
    txn = _wait_for_thumbnail(configured, "PAY_NO_DEVICE")
    assert txn["device_id"] == ""
    assert txn["camera_id"] == CAM1
    assert f"/timeline/{CAM1}?" in txn["deep_link"]
    assert snapshot_requests == [CAM1]

def test_sparse_payment_update_preserves_device_camera_evidence(configured, monkeypatch):
    snapshot_requests = []

    def record_snapshot(_self, camera_id, ts_ms=None, width=640):
        snapshot_requests.append(camera_id)
        return b"snapshot:" + camera_id.encode()

    monkeypatch.setattr(ProtectClient, "get_snapshot", record_snapshot)
    mapping = {
        "mappings": [
            {
                "location_id": "LOC1",
                "camera_id": CAM2,
                "camera_name": "Back Door",
            },
            {
                "location_id": "LOC1",
                "device_id": "TERM_A",
                "device_name": "Register A",
                "camera_id": CAM1,
                "camera_name": "Front Counter",
            },
        ]
    }
    assert configured.put("/api/camera-mapping", json=mapping).status_code == 200

    initial_body = make_webhook_event("PAY_SPARSE", "TERM_A", "Register A")
    initial_payment = json.loads(initial_body)["data"]["object"]["payment"]
    ingest_payment(configured.app.state.store, initial_payment, protect=None)

    sparse_body = make_webhook_event("PAY_SPARSE")
    resp = configured.post(
        "/webhooks/square",
        content=sparse_body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(sparse_body)},
    )
    assert resp.status_code == 200
    txn = next(
        item
        for item in configured.get("/api/transactions").json()
        if item["id"] == "PAY_SPARSE"
    )
    original_image = configured.get(txn["thumbnail_url"]).content
    assert txn["device_id"] == "TERM_A"
    assert txn["camera_id"] == CAM1
    assert CAM1.encode() in original_image
    assert snapshot_requests == [CAM1]

    mapping["mappings"][1]["camera_id"] = CAM2
    mapping["mappings"][1]["camera_name"] = "Back Door"
    assert configured.put("/api/camera-mapping", json=mapping).status_code == 200
    snapshot_requests.clear()
    resp = configured.post(
        "/webhooks/square",
        content=sparse_body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(sparse_body)},
    )
    assert resp.status_code == 200

    txn = next(
        item
        for item in configured.get("/api/transactions").json()
        if item["id"] == "PAY_SPARSE"
    )
    assert txn["device_id"] == "TERM_A"
    assert txn["camera_id"] == CAM1
    assert f"/timeline/{CAM1}?" in txn["deep_link"]
    assert configured.get(txn["thumbnail_url"]).content == original_image
    assert snapshot_requests == []

def test_webhook_ignores_non_payment_events(configured):
    body = json.dumps({"type": "inventory.count.updated", "data": {}}).encode()
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    assert resp.json().get("ignored") is True
