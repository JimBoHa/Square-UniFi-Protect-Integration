"""Connect-with-Square OAuth flow tests (token endpoint mocked)."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.square_client import oauth_authorize_url

from .conftest import (
    ADMIN_PASSWORD,
    PROTECT_PASS,
    PROTECT_USER,
    protect_handler,
    square_handler,
)

CLIENT_ID = "sq0idp-test-app-id"
CLIENT_SECRET = "sq0csp-test-app-secret"


def make_oauth_square(state):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            body = json.loads(request.content)
            state["token_requests"].append(body)
            if body.get("client_secret") != CLIENT_SECRET:
                return httpx.Response(401, json={"errors": [{"code": "UNAUTHORIZED"}]})
            suffix = "refreshed" if body.get("grant_type") == "refresh_token" else "initial"
            return httpx.Response(
                200,
                json={
                    "access_token": f"oauth-access-{suffix}",
                    "refresh_token": "oauth-refresh-token",
                    "expires_at": state["expires_at"],
                    "merchant_id": "MERCHANT_OAUTH",
                    "token_type": "bearer",
                },
            )
        auth = request.headers.get("authorization", "")
        if request.url.path == "/v2/locations" and auth.startswith("Bearer oauth-access-"):
            return httpx.Response(
                200,
                json={"locations": [{"id": "LOC1", "name": "OAuth Store", "status": "ACTIVE"}]},
            )
        return square_handler(request)

    return handler


@pytest.fixture()
def oauth_client(tmp_path):
    state = {"token_requests": [], "expires_at": "2027-01-01T00:00:00Z"}
    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(protect_handler),
        square_transport=httpx.MockTransport(make_oauth_square(state)),
        enable_poller=False,
    )
    with TestClient(app) as client:
        assert client.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
        assert client.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
        yield client, state, app.state.store
    app.state.store.close()


def _save_oauth_app(client):
    resp = client.put(
        "/api/settings/square/oauth-app",
        json={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "environment": "production",
        },
    )
    assert resp.status_code == 200


def test_authorize_url_contains_scopes_and_state():
    url = oauth_authorize_url("production", CLIENT_ID, "state123")
    assert url.startswith("https://connect.squareup.com/oauth2/authorize?")
    assert f"client_id={CLIENT_ID}" in url
    assert "MERCHANT_PROFILE_READ" in url and "PAYMENTS_READ" in url
    assert "state=state123" in url


def test_start_requires_saved_application(oauth_client):
    client, _state, _store = oauth_client
    resp = client.get("/oauth/square/start", follow_redirects=False)
    assert resp.status_code == 409


def test_full_oauth_flow_stores_tokens_and_merchant(oauth_client):
    client, state, store = oauth_client
    _save_oauth_app(client)

    start = client.get("/oauth/square/start", follow_redirects=False)
    assert start.status_code == 302
    location = start.headers["location"]
    assert location.startswith("https://connect.squareup.com/oauth2/authorize?")
    oauth_state = location.rsplit("state=", 1)[-1]

    callback = client.get(
        f"/oauth/square/callback?code=auth-code-1&state={oauth_state}",
        follow_redirects=False,
    )
    assert callback.status_code == 302
    assert callback.headers["location"] == "/?square_oauth=connected"

    assert store.get_setting("square.access_token") == "oauth-access-initial"
    assert store.get_setting("square.refresh_token") == "oauth-refresh-token"
    assert store.get_setting("square.merchant_id") == "MERCHANT_OAUTH"
    assert store.square_account_revision()
    assert state["token_requests"][0]["grant_type"] == "authorization_code"

    # Secrets stay encrypted at rest.
    db_bytes = (store.data_dir / "spi.db").read_bytes()
    assert b"oauth-access-initial" not in db_bytes
    assert b"oauth-refresh-token" not in db_bytes
    assert CLIENT_SECRET.encode() not in db_bytes


def test_fresh_oauth_account_can_save_revision_fenced_mapping(oauth_client):
    client, _state, _store = oauth_client
    assert client.put(
        "/api/settings/protect",
        json={
            "host": "10.0.0.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "verify_ssl": False,
        },
    ).status_code == 200
    _save_oauth_app(client)
    start = client.get("/oauth/square/start", follow_redirects=False)
    oauth_state = start.headers["location"].rsplit("state=", 1)[-1]
    assert client.get(
        f"/oauth/square/callback?code=auth-code-1&state={oauth_state}",
        follow_redirects=False,
    ).status_code == 302

    snapshot = client.get("/api/camera-mapping")
    assert snapshot.headers["x-square-account-revision"]
    assert snapshot.headers["x-protect-console-generation"]
    saved = client.put(
        "/api/camera-mapping",
        json={"mappings": []},
        headers={
            "X-Square-Account-Revision": snapshot.headers[
                "x-square-account-revision"
            ],
            "X-Protect-Console-Generation": snapshot.headers[
                "x-protect-console-generation"
            ],
        },
    )
    assert saved.status_code == 200


def test_oauth_different_merchant_requires_explicit_confirm_and_isolates_data(
    oauth_client,
):
    client, _state, store = oauth_client
    store.configure_square_account(
        merchant_id="MERCHANT_OLD",
        access_token="old-access-token",
        environment="production",
        webhook_signature_key="old-webhook-key",
        webhook_url="https://old.example/webhooks/square",
    )
    old_revision = store.square_account_revision()
    store.set_camera_mapping("LOC_OLD", "cam-old", "Old camera")
    store.upsert_transaction(
        {
            "id": "PAY_OLD",
            "created_at": "2026-07-18T12:00:00Z",
            "ts_ms": 1_752_840_000_000,
            "updated_at": "2026-07-18T12:00:00Z",
            "updated_ts_ms": 1_752_840_000_000,
            "amount": 1250,
            "currency": "USD",
            "status": "COMPLETED",
            "location_id": "LOC_OLD",
            "device_id": "",
            "device_name": "",
            "card_last4": "4242",
            "receipt_url": "",
            "camera_id": "cam-old",
            "thumbnail_path": None,
        }
    )
    _save_oauth_app(client)
    start = client.get("/oauth/square/start", follow_redirects=False)
    oauth_state = start.headers["location"].rsplit("state=", 1)[-1]

    callback = client.get(
        f"/oauth/square/callback?code=auth-code-1&state={oauth_state}",
        follow_redirects=False,
    )
    assert callback.status_code == 302
    assert callback.headers["location"] == "/?square_oauth=switch_required"
    assert store.get_setting("square.merchant_id") == "MERCHANT_OLD"
    assert store.get_setting("square.access_token") == "old-access-token"
    assert store.square_account_revision() == old_revision
    assert [txn["id"] for txn in store.list_transactions()] == ["PAY_OLD"]
    assert store.get_camera_mappings()
    assert store.get_setting("square.webhook_signature_key") == "old-webhook-key"

    confirmed = client.post("/api/settings/square/oauth-switch/confirm")
    assert confirmed.status_code == 200
    assert confirmed.json()["account_switched"] is True
    assert confirmed.json()["account_revision"] != old_revision
    assert store.get_setting("square.merchant_id") == "MERCHANT_OAUTH"
    assert store.get_setting("square.access_token") == "oauth-access-initial"
    assert store.get_setting("square.refresh_token") == "oauth-refresh-token"
    assert store.get_setting("square.webhook_signature_key") is None
    assert store.list_transactions() == []
    assert store.get_camera_mappings() == []
    assert store.get_setting("square.oauth_client_id") == CLIENT_ID
    assert store.get_setting("square.oauth_client_secret") == CLIENT_SECRET


def test_pending_oauth_switch_can_be_cancelled(oauth_client):
    client, _state, store = oauth_client
    store.configure_square_account(
        merchant_id="MERCHANT_OLD",
        access_token="old-access-token",
        environment="production",
    )
    _save_oauth_app(client)
    start = client.get("/oauth/square/start", follow_redirects=False)
    oauth_state = start.headers["location"].rsplit("state=", 1)[-1]
    client.get(
        f"/oauth/square/callback?code=auth-code-1&state={oauth_state}",
        follow_redirects=False,
    )

    cancelled = client.delete("/api/settings/square/oauth-switch")
    assert cancelled.status_code == 200
    assert store.get_setting("square.oauth_pending_access_token") is None
    assert store.get_setting("square.merchant_id") == "MERCHANT_OLD"
    assert client.post("/api/settings/square/oauth-switch/confirm").status_code == 409


def test_callback_rejects_bad_state(oauth_client):
    client, _state, store = oauth_client
    _save_oauth_app(client)
    client.get("/oauth/square/start", follow_redirects=False)
    resp = client.get(
        "/oauth/square/callback?code=auth-code-1&state=forged",
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert store.get_setting("square.access_token") is None


def test_expiring_token_is_refreshed_before_use(oauth_client):
    client, state, store = oauth_client
    _save_oauth_app(client)
    start = client.get("/oauth/square/start", follow_redirects=False)
    oauth_state = start.headers["location"].rsplit("state=", 1)[-1]
    client.get(
        f"/oauth/square/callback?code=auth-code-1&state={oauth_state}",
        follow_redirects=False,
    )
    # Make the stored token look nearly expired, then trigger any Square use.
    store.set_setting("square.token_expires_at", "2020-01-01T00:00:00Z")
    state["expires_at"] = "2030-01-01T00:00:00Z"
    assert client.get("/api/locations").status_code == 200
    assert store.get_setting("square.access_token") == "oauth-access-refreshed"
    refresh_calls = [
        r for r in state["token_requests"] if r.get("grant_type") == "refresh_token"
    ]
    assert refresh_calls and refresh_calls[0]["refresh_token"] == "oauth-refresh-token"


def test_oauth_endpoints_require_auth(client):
    assert client.put(
        "/api/settings/square/oauth-app",
        json={"client_id": "x" * 10, "client_secret": "y" * 10},
    ).status_code == 401
    assert client.get("/oauth/square/start", follow_redirects=False).status_code == 401


def test_oauth_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert 'id="square-oauth-connect"' in html
    assert "/oauth/square/start" in js
    assert "/api/settings/square/oauth-app" in js
    assert 'id="square-oauth-switch-warning"' in html
    assert "/api/settings/square/oauth-switch/confirm" in js
    assert "square_oauth=switch_required" not in js
    assert 'oauthOutcome === "switch_required"' in js
