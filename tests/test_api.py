"""End-to-end API tests against mocked Square and UniFi Protect backends."""

import base64
import hashlib
import hmac
import json

from app.protect_client import ProtectClient
from app.sync import ingest_payment

from .conftest import (
    ADMIN_PASSWORD,
    PROTECT_PASS,
    PROTECT_USER,
    SQUARE_TOKEN,
    WEBHOOK_KEY,
    WEBHOOK_URL,
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

def test_webhook_ingests_payment_with_thumbnail(configured):
    body = make_webhook_event()
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    txns = configured.get("/api/transactions").json()
    assert txns[0]["id"] == "PAY_HOOK"
    assert txns[0]["thumbnail_url"] is not None
    assert txns[0]["deep_link"] is not None

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

    txns = {
        txn["id"]: txn
        for txn in configured.get("/api/transactions").json()
    }
    for payment_id, device_id, camera_id in (
        ("PAY_TERM_A", "TERM_A", CAM1),
        ("PAY_TERM_B", "TERM_B", CAM2),
    ):
        txn = txns[payment_id]
        assert txn["device_id"] == device_id
        assert txn["camera_id"] == camera_id
        assert txn["deep_link"] == (
            f"https://192.168.1.1/protect/timeline/{camera_id}?ts={txn['ts_ms']}"
        )
        thumbnail = configured.get(txn["thumbnail_url"])
        assert thumbnail.status_code == 200
        assert camera_id.encode() in thumbnail.content

    assert [camera_id for camera_id, _ in snapshot_requests] == [CAM1, CAM2]
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
    txn = next(
        item
        for item in configured.get("/api/transactions").json()
        if item["id"] == "PAY_NO_DEVICE"
    )
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
