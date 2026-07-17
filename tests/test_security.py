"""Security tests: authentication, secrets at rest, webhook forgery, traversal."""

import json

import pytest

from .conftest import ADMIN_PASSWORD, PROTECT_PASS, SQUARE_TOKEN, WEBHOOK_KEY
from .test_api import make_webhook_event

PROTECTED_ENDPOINTS = [
    ("GET", "/api/cameras"),
    ("GET", "/api/locations"),
    ("GET", "/api/pos-devices"),
    ("GET", "/api/camera-mapping"),
    ("PUT", "/api/camera-mapping"),
    ("GET", "/api/camera-preview/cam1aaaaaaaaaaaaaaaaaaaaa"),
    ("GET", "/api/transactions"),
    ("GET", "/api/thumbnails/PAY_001"),
    ("POST", "/api/sync"),
    ("PUT", "/api/settings/protect"),
    ("PUT", "/api/settings/square"),
    ("POST", "/api/logout"),
]


@pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
def test_endpoints_require_authentication(client, method, path):
    resp = client.request(method, path, json={})
    assert resp.status_code == 401, f"{method} {path} must require auth"

def test_forged_session_cookie_rejected(client):
    client.post("/api/setup", json={"password": ADMIN_PASSWORD})
    client.cookies.set("spi_session", "forged-token-attempt")
    assert client.get("/api/transactions").status_code == 401

def test_session_cookie_flags(client):
    client.post("/api/setup", json={"password": ADMIN_PASSWORD})
    resp = client.post("/api/login", json={"password": ADMIN_PASSWORD})
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie

def test_setup_cannot_be_rerun(authed):
    resp = authed.post("/api/setup", json={"password": "attacker-password"})
    assert resp.status_code == 409
    # Original password still works
    assert authed.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200

def test_login_throttled_after_repeated_failures(client):
    client.post("/api/setup", json={"password": ADMIN_PASSWORD})
    for _ in range(5):
        assert client.post("/api/login", json={"password": "wrong"}).status_code == 401
    resp = client.post("/api/login", json={"password": "wrong"})
    assert resp.status_code == 429
    # Even the correct password is throttled while locked out
    assert client.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 429


# -- secrets at rest ---------------------------------------------------------------

def test_credentials_encrypted_at_rest(configured, tmp_path):
    db_bytes = (tmp_path / "data" / "spi.db").read_bytes()
    assert SQUARE_TOKEN.encode() not in db_bytes, "Square token stored in plaintext"
    assert PROTECT_PASS.encode() not in db_bytes, "Protect password stored in plaintext"
    assert WEBHOOK_KEY.encode() not in db_bytes, "Webhook key stored in plaintext"

def test_admin_password_not_stored_in_plaintext(authed, tmp_path):
    db_bytes = (tmp_path / "data" / "spi.db").read_bytes()
    assert ADMIN_PASSWORD.encode() not in db_bytes

def test_api_never_returns_stored_secrets(configured):
    for path in ("/api/status", "/api/camera-mapping", "/api/transactions"):
        text = configured.get(path).text
        assert SQUARE_TOKEN not in text
        assert PROTECT_PASS not in text


# -- input validation / SSRF ---------------------------------------------------------

@pytest.mark.parametrize(
    "host",
    ["http://internal", "unifi.local/admin", "attacker@unifi.local", "unifi.local:443/../"],
)
def test_protect_host_rejects_url_injection(authed, host):
    resp = authed.put(
        "/api/settings/protect",
        json={"host": host, "username": "u", "password": "p"},
    )
    assert resp.status_code == 422

def test_protect_host_rejects_out_of_range_port(authed):
    resp = authed.put(
        "/api/settings/protect",
        json={"host": "unifi.local:99999", "username": "u", "password": "p"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "Protect host port must be between 1 and 65535"

def test_camera_preview_rejects_malformed_ids(configured):
    assert configured.get("/api/camera-preview/..%2F..%2Fetc").status_code in (404, 422)
    assert configured.get("/api/camera-preview/cam%20id").status_code == 422

def test_camera_mapping_rejects_malformed_camera_id(configured):
    resp = configured.put(
        "/api/camera-mapping",
        json={"mappings": [{"location_id": "LOC1", "camera_id": "../etc"}]},
    )
    assert resp.status_code == 422

def test_wildcard_camera_mapping_rejects_malformed_camera_id(configured):
    resp = configured.put(
        "/api/camera-mapping",
        json={"mappings": [{"location_id": "*", "camera_id": "../etc"}]},
    )
    assert resp.status_code == 422


# -- thumbnail path traversal ----------------------------------------------------------

def test_thumbnail_path_traversal_blocked(configured):
    store = configured.app.state.store
    store.upsert_transaction(
        {
            "id": "EVIL",
            "created_at": "2026-07-16T00:00:00Z",
            "ts_ms": 0,
            "amount": 1,
            "currency": "USD",
            "status": "COMPLETED",
            "thumbnail_path": "../secret.key",
        }
    )
    resp = configured.get("/api/thumbnails/EVIL")
    assert resp.status_code == 404
    assert b"BEGIN" not in resp.content and b"=" != resp.content[:1]


# -- webhook forgery ---------------------------------------------------------------------

def test_webhook_rejected_without_configuration(authed):
    resp = authed.post("/webhooks/square", content=make_webhook_event())
    assert resp.status_code == 403

def test_webhook_rejects_missing_signature(configured):
    resp = configured.post("/webhooks/square", content=make_webhook_event())
    assert resp.status_code == 401

def test_webhook_rejects_forged_signature(configured):
    resp = configured.post(
        "/webhooks/square",
        content=make_webhook_event(),
        headers={"x-square-hmacsha256-signature": "Zm9yZ2VkLXNpZ25hdHVyZQ=="},
    )
    assert resp.status_code == 401
    assert all(t["id"] != "PAY_HOOK" for t in configured.get("/api/transactions").json())

def test_webhook_rejects_tampered_body(configured):
    from .test_api import _webhook_signature

    body = make_webhook_event()
    tampered = body.replace(b'"amount": 500', b'"amount": 1')
    resp = configured.post(
        "/webhooks/square",
        content=tampered,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 401


# -- stored XSS surface -----------------------------------------------------------------

def test_malicious_payment_fields_returned_as_json_not_html(configured):
    """API responses are JSON; script payloads must come back JSON-escaped, and
    the frontend renders exclusively via textContent."""
    from .test_api import _webhook_signature

    payload = json.dumps(
        {
            "type": "payment.updated",
            "data": {
                "object": {
                    "payment": {
                        "id": "XSS1",
                        "created_at": "2026-07-16T17:00:00Z",
                        "amount_money": {"amount": 100, "currency": "USD"},
                        "status": "<script>alert(1)</script>",
                        "location_id": "LOC1",
                        "receipt_url": "javascript:alert(1)",
                    }
                }
            },
        }
    ).encode()
    resp = configured.post(
        "/webhooks/square",
        content=payload,
        headers={"x-square-hmacsha256-signature": _webhook_signature(payload)},
    )
    assert resp.status_code == 200
    listing = configured.get("/api/transactions")
    assert listing.headers["content-type"].startswith("application/json")
    txn = next(t for t in listing.json() if t["id"] == "XSS1")
    assert txn["status"] == "<script>alert(1)</script>"  # stored raw, escaped by JSON

def test_frontend_never_uses_innerhtml():
    from pathlib import Path

    js = (Path(__file__).parent.parent / "app" / "static" / "app.js").read_text()
    assert "innerHTML" not in js
    assert "document.write" not in js

def test_transaction_feed_refresh_is_visibility_aware_and_non_overlapping():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert "TRANSACTION_REFRESH_MS" in js
    assert 'document.visibilityState === "visible"' in js
    assert "transactionLoadInFlight" in js
    assert "payload !== lastTransactionPayload" in js
    assert 'id="txn-last-updated"' in html


def test_transaction_feed_pagination_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert "TRANSACTION_PAGE_SIZE + 1" in js
    assert "&offset=${requestedOffset}" in js
    assert "page.slice(0, TRANSACTION_PAGE_SIZE)" in js
    assert "transactionPendingOffset" in js
    assert "transactionOffset === 0" in js
    assert 'id="txn-prev"' in html
    assert 'id="txn-next"' in html
    assert 'id="txn-page-status"' in html
    assert 'aria-live="polite"' in html

def test_pos_device_mapping_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert 'api("/api/pos-devices")' in js
    assert "select.dataset.deviceId" in js
    assert "select.dataset.deviceName" in js
    assert "Other devices (fallback)" in js
    assert "observed Square POS device" in html
