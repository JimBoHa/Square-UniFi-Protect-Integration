"""Automatic Square webhook subscription registration."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app

from .conftest import (
    ADMIN_PASSWORD,
    PROTECT_PASS,
    PROTECT_USER,
    SQUARE_TOKEN,
    protect_handler,
    square_handler,
)

SIGNATURE_KEY = "whsec_auto_registered_123"


def make_registration_square(state):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != f"Bearer {SQUARE_TOKEN}":
            return httpx.Response(401, json={"errors": [{"code": "UNAUTHORIZED"}]})
        path = request.url.path
        if path == "/v2/webhooks/subscriptions" and request.method == "GET":
            return httpx.Response(200, json={"subscriptions": state["existing"]})
        if path == "/v2/webhooks/subscriptions" and request.method == "POST":
            body = json.loads(request.content)
            state["created"] = body
            return httpx.Response(
                200,
                json={
                    "subscription": {
                        "id": "SUB_NEW",
                        "name": body["subscription"]["name"],
                        "notification_url": body["subscription"]["notification_url"],
                        "signature_key": SIGNATURE_KEY,
                    }
                },
            )
        if path.startswith("/v2/webhooks/subscriptions/") and request.method == "PUT":
            body = json.loads(request.content)
            state["updated"] = (path.rsplit("/", 1)[-1], body)
            return httpx.Response(
                200,
                json={
                    "subscription": {
                        "id": path.rsplit("/", 1)[-1],
                        "notification_url": body["subscription"]["notification_url"],
                        "signature_key": SIGNATURE_KEY,
                    }
                },
            )
        return square_handler(request)

    return handler


@pytest.fixture()
def registration_app(tmp_path):
    state = {"existing": [], "created": None, "updated": None}
    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(protect_handler),
        square_transport=httpx.MockTransport(make_registration_square(state)),
        enable_poller=False,
    )
    with TestClient(app) as client:
        assert client.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
        assert client.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
        assert client.put(
            "/api/settings/square",
            json={"access_token": SQUARE_TOKEN, "environment": "production"},
        ).status_code == 200
        yield client, state, app.state.store
    app.state.store.close()


def test_register_creates_subscription_and_stores_key(registration_app):
    client, state, store = registration_app
    resp = client.post(
        "/api/settings/square/webhook/register",
        json={"notification_url": "https://shop.example.com/webhooks/square"},
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] is False
    assert state["created"]["subscription"]["event_types"] == [
        "payment.created",
        "payment.updated",
    ]
    assert store.get_setting("square.webhook_signature_key") == SIGNATURE_KEY
    assert store.get_setting("square.webhook_url") == (
        "https://shop.example.com/webhooks/square"
    )


def test_register_updates_existing_subscription(registration_app):
    client, state, store = registration_app
    state["existing"] = [{"id": "SUB_OLD", "name": "square-unifi-protect"}]
    resp = client.post(
        "/api/settings/square/webhook/register",
        json={"notification_url": "https://new.example.com/webhooks/square"},
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] is True
    assert state["updated"][0] == "SUB_OLD"
    assert store.get_setting("square.webhook_signature_key") == SIGNATURE_KEY


def test_register_rejects_non_https_url(registration_app):
    client, _state, store = registration_app
    resp = client.post(
        "/api/settings/square/webhook/register",
        json={"notification_url": "http://insecure.example.com/hook"},
    )
    assert resp.status_code == 422
    assert store.get_setting("square.webhook_signature_key") is None


def test_register_requires_square_configuration(authed):
    resp = authed.post(
        "/api/settings/square/webhook/register",
        json={"notification_url": "https://shop.example.com/webhooks/square"},
    )
    assert resp.status_code == 409


def test_register_requires_auth(client):
    resp = client.post(
        "/api/settings/square/webhook/register",
        json={"notification_url": "https://shop.example.com/webhooks/square"},
    )
    assert resp.status_code == 401


def test_register_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert 'id="square-register-webhook"' in html
    assert "/api/settings/square/webhook/register" in js
