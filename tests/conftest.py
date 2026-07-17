"""Shared fixtures: the app wired to mocked Square and UniFi Protect APIs."""

from __future__ import annotations

import json
import re

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app

PROTECT_USER = "protect-admin"
PROTECT_PASS = "protect-pass-123"
PROTECT_API_KEY = "protect-api-key-secret-789"
PROTECT_ALARM_TRIGGER_ID = "square-completed-sale"
SQUARE_TOKEN = "sq-test-token-abc123"
SQUARE_MERCHANT_ID = "MERCHANT_TEST_123"
ADMIN_PASSWORD = "hunter2-hunter2"
WEBHOOK_KEY = "whsec_test_key_456"
WEBHOOK_URL = "https://shop.example.com/webhooks/square"

FAKE_JPEG = (
    b"\xff\xd8\xff\xe0JFIF-fake-image-data"
    b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00fake-scan-data\xff\xd9"
)

PROTECT_META_KEYS: list[str | None] = []
PROTECT_ALARM_CALLS: list[str] = []
PROTECT_ALARM_RESPONSES: list[int] = []

SQUARE_PAYMENTS = [
    {
        "id": "PAY_001",
        "created_at": "2026-07-16T15:30:00.000Z",
        "amount_money": {"amount": 1250, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
        "card_details": {"card": {"last_4": "4242"}},
        "receipt_url": "https://squareup.com/receipt/PAY_001",
    },
    {
        "id": "PAY_002",
        "created_at": "2026-07-16T15:45:10.000Z",
        "amount_money": {"amount": 999, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
        "card_details": {"card": {"last_4": "1111"}},
        "receipt_url": "https://squareup.com/receipt/PAY_002",
    },
]


def protect_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/api/auth/login":
        body = json.loads(request.content)
        if body.get("username") != PROTECT_USER or body.get("password") != PROTECT_PASS:
            return httpx.Response(401, json={"error": "Invalid credentials"})
        return httpx.Response(
            200,
            headers={"x-csrf-token": "csrf-token-1", "set-cookie": "TOKEN=t1; Path=/"},
            json={"id": "user1"},
        )
    if path == "/proxy/protect/integration/v1/meta/info":
        api_key = request.headers.get("x-api-key")
        PROTECT_META_KEYS.append(api_key)
        if api_key != PROTECT_API_KEY:
            return httpx.Response(401, json={"error": "Invalid API key"})
        return httpx.Response(200, json={"applicationVersion": "7.1.87"})
    alarm_match = re.fullmatch(
        r"/proxy/protect/integration/v1/alarm-manager/webhook/([^/]+)", path
    )
    if alarm_match:
        if request.headers.get("x-api-key") != PROTECT_API_KEY:
            return httpx.Response(401, json={"error": "Invalid API key"})
        PROTECT_ALARM_CALLS.append(alarm_match.group(1))
        status_code = PROTECT_ALARM_RESPONSES.pop(0) if PROTECT_ALARM_RESPONSES else 204
        return httpx.Response(status_code)
    if path == "/proxy/protect/api/bootstrap":
        return httpx.Response(
            200,
            json={
                "cameras": [
                    {"id": "cam1aaaaaaaaaaaaaaaaaaaaa", "name": "Front Counter", "state": "CONNECTED"},
                    {"id": "cam2bbbbbbbbbbbbbbbbbbbbb", "name": "Back Door", "state": "CONNECTED"},
                ]
            },
        )
    match = re.fullmatch(
        r"/proxy/protect/api/cameras/([^/]+)/(snapshot|recording-snapshot)", path
    )
    if match:
        camera_id, endpoint = match.groups()
        if camera_id not in ("cam1aaaaaaaaaaaaaaaaaaaaa", "cam2bbbbbbbbbbbbbbbbbbbbb"):
            return httpx.Response(404)
        ts = request.url.params.get("ts", "")
        if endpoint == "recording-snapshot" and not ts:
            # Mirrors Protect 7.1.87: the recording endpoint requires ts.
            return httpx.Response(
                404,
                json={"error": "Recording not found"},
            )
        return httpx.Response(
            200,
            content=FAKE_JPEG + ts.encode(),
            headers={"content-type": "image/jpeg"},
        )
    return httpx.Response(404)


@pytest.fixture(autouse=True)
def reset_protect_integration_mock():
    PROTECT_META_KEYS.clear()
    PROTECT_ALARM_CALLS.clear()
    PROTECT_ALARM_RESPONSES.clear()
    yield
    PROTECT_META_KEYS.clear()
    PROTECT_ALARM_CALLS.clear()
    PROTECT_ALARM_RESPONSES.clear()


def square_handler(request: httpx.Request) -> httpx.Response:
    if request.headers.get("authorization") != f"Bearer {SQUARE_TOKEN}":
        return httpx.Response(401, json={"errors": [{"code": "UNAUTHORIZED"}]})
    path = request.url.path
    if path == "/v2/locations":
        return httpx.Response(
            200,
            json={"locations": [{"id": "LOC1", "name": "Main Store", "status": "ACTIVE"}]},
        )
    if path == "/v2/merchants/me":
        return httpx.Response(200, json={"merchant": {"id": SQUARE_MERCHANT_ID}})
    if path == "/v2/payments":
        return httpx.Response(200, json={"payments": SQUARE_PAYMENTS})
    return httpx.Response(404)


@pytest.fixture()
def client(tmp_path):
    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(protect_handler),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    with TestClient(app) as test_client:
        yield test_client
    app.state.store.close()


@pytest.fixture()
def authed(client):
    """Client with setup complete and an active session."""
    assert client.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
    assert client.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
    return client


@pytest.fixture()
def configured(authed):
    """Authed client with Protect + Square connected and the POS camera chosen."""
    resp = authed.put(
        "/api/settings/protect",
        json={"host": "192.168.1.1", "username": PROTECT_USER, "password": PROTECT_PASS},
    )
    assert resp.status_code == 200, resp.text
    resp = authed.put(
        "/api/settings/square",
        json={
            "access_token": SQUARE_TOKEN,
            "environment": "production",
            "webhook_signature_key": WEBHOOK_KEY,
            "webhook_url": WEBHOOK_URL,
        },
    )
    assert resp.status_code == 200, resp.text
    authed.headers["X-Square-Account-Revision"] = resp.json()["account_revision"]
    resp = authed.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "camera_id": "cam1aaaaaaaaaaaaaaaaaaaaa",
                    "camera_name": "Front Counter",
                }
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    return authed
