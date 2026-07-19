"""Automatic Square webhook subscription registration."""

import concurrent.futures
import inspect
import json
import threading

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.store import SquareAccountChanged, SquareAccountSwitchRequired, Store

from . import conftest as test_fixtures
from .conftest import (
    ADMIN_PASSWORD,
    PROTECT_PASS,
    PROTECT_USER,
    SQUARE_TOKEN,
    protect_handler,
    square_handler,
)

SIGNATURE_KEY = "whsec_auto_registered_123"
ACCOUNT_A_TOKEN = "registration-token-account-a"
ACCOUNT_B_TOKEN = "registration-token-account-b"
ACCOUNT_A_MERCHANT = "REGISTRATION_MERCHANT_A"
ACCOUNT_B_MERCHANT = "REGISTRATION_MERCHANT_B"


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


def test_blocked_registration_cannot_cross_confirmed_account_switch(tmp_path):
    registration_started = threading.Event()
    release_registration = threading.Event()
    state = {"created": False}

    def blocked_square(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == f"Bearer {ACCOUNT_A_TOKEN}"
        if (
            request.url.path == "/v2/webhooks/subscriptions"
            and request.method == "GET"
        ):
            registration_started.set()
            assert release_registration.wait(timeout=5)
            return httpx.Response(200, json={"subscriptions": []})
        if (
            request.url.path == "/v2/webhooks/subscriptions"
            and request.method == "POST"
        ):
            state["created"] = True
            return httpx.Response(
                200,
                json={
                    "subscription": {
                        "id": "SUB_ACCOUNT_A",
                        "signature_key": SIGNATURE_KEY,
                    }
                },
            )
        return httpx.Response(404)

    data_dir = tmp_path / "data"
    create_options = dict(
        data_dir=data_dir,
        square_transport=httpx.MockTransport(blocked_square),
        enable_poller=False,
    )
    if "tls_enabled" in inspect.signature(create_app).parameters:
        create_options["tls_enabled"] = True
    app = create_app(**create_options)
    app_store = app.state.store
    second_store = Store(data_dir)
    app_store.configure_square_account(
        merchant_id=ACCOUNT_A_MERCHANT,
        access_token=ACCOUNT_A_TOKEN,
        environment="production",
    )
    account_a_revision = app_store.square_account_revision()
    assert account_a_revision
    with pytest.raises(SquareAccountSwitchRequired) as challenge:
        second_store.configure_square_account(
            merchant_id=ACCOUNT_B_MERCHANT,
            access_token=ACCOUNT_B_TOKEN,
            environment="sandbox",
        )

    try:
        with TestClient(app) as client:
            setup_body = {"password": ADMIN_PASSWORD}
            bootstrap_secret = getattr(test_fixtures, "BOOTSTRAP_SECRET", None)
            if bootstrap_secret:
                setup_body["bootstrap_secret"] = bootstrap_secret
            assert client.post(
                "/api/setup", json=setup_body
            ).status_code == 200
            assert client.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                registration = executor.submit(
                    client.post,
                    "/api/settings/square/webhook/register",
                    json={
                        "notification_url": (
                            "https://account-a.example/webhooks/square"
                        )
                    },
                )
                assert registration_started.wait(timeout=5)
                switch = executor.submit(
                    second_store.configure_square_account,
                    merchant_id=ACCOUNT_B_MERCHANT,
                    access_token=ACCOUNT_B_TOKEN,
                    environment="sandbox",
                    confirm_account_switch=True,
                    account_switch_confirmation_token=(
                        challenge.value.confirmation_token
                    ),
                )
                switched = switch.result(timeout=2)
                assert switched.switched
                release_registration.set()
                response = registration.result(timeout=5)

        assert state["created"]
        assert response.status_code == 409
        assert second_store.get_setting("square.merchant_id") == ACCOUNT_B_MERCHANT
        assert second_store.get_setting("square.access_token") == ACCOUNT_B_TOKEN
        assert second_store.get_setting("square.environment") == "sandbox"
        assert second_store.square_account_revision() != account_a_revision
        assert second_store.get_setting("square.webhook_signature_key") is None
        assert second_store.get_setting("square.webhook_url") is None
    finally:
        release_registration.set()
        second_store.close()
        app_store.close()


@pytest.mark.parametrize(
    ("changed_key", "changed_value", "secret"),
    (
        ("square.merchant_id", ACCOUNT_B_MERCHANT, False),
        ("square.environment", "sandbox", False),
        ("square.account_revision", "replacement-revision", False),
        ("square.access_token", ACCOUNT_B_TOKEN, True),
    ),
)
def test_webhook_commit_rejects_each_changed_square_identity_field(
    tmp_path, changed_key, changed_value, secret
):
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    second = Store(data_dir)
    try:
        first.configure_square_account(
            merchant_id=ACCOUNT_A_MERCHANT,
            access_token=ACCOUNT_A_TOKEN,
            environment="production",
        )
        snapshot = first.get_settings(
            (
                "square.merchant_id",
                "square.environment",
                "square.account_revision",
                "square.access_token",
            )
        )
        second.set_setting(changed_key, changed_value, secret=secret)

        with pytest.raises(SquareAccountChanged):
            first.update_square_webhook_settings(
                SIGNATURE_KEY,
                "https://account-a.example/webhooks/square",
                expected_merchant_id=snapshot["square.merchant_id"],
                expected_environment=snapshot["square.environment"] or "production",
                expected_account_revision=snapshot["square.account_revision"],
                expected_access_token=snapshot["square.access_token"] or "",
            )

        assert second.get_setting("square.webhook_signature_key") is None
        assert second.get_setting("square.webhook_url") is None
    finally:
        first.close()
        second.close()


def test_register_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert 'id="square-register-webhook"' in html
    assert "/api/settings/square/webhook/register" in js
