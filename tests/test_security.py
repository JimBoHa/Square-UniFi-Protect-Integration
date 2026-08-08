"""Security tests: authentication, secrets at rest, webhook forgery, traversal."""

import json
import os
import stat
import time

import pytest

from app.main import (
    SQUARE_WEBHOOK_MAX_BODY_BYTES,
    TRANSACTION_QUERY_MAX_BODY_BYTES,
)
from app.store import Store
from app.sync import ingest_payment

from .conftest import (
    ADMIN_PASSWORD,
    PROTECT_PASS,
    SQUARE_MERCHANT_ID,
    SQUARE_TOKEN,
    WEBHOOK_KEY,
    bootstrap_setup_body,
)
from .test_api import make_webhook_event

PROTECTED_ENDPOINTS = [
    ("GET", "/api/session"),
    ("GET", "/api/users"),
    ("POST", "/api/users"),
    ("PUT", "/api/users/1/password"),
    ("GET", "/api/login-audit"),
    ("GET", "/api/motion-alerts"),
    ("PUT", "/api/transactions/PAY_001/note"),
    ("GET", "/api/cameras"),
    ("GET", "/api/locations"),
    ("GET", "/api/pos-devices"),
    ("GET", "/api/camera-mapping"),
    ("PUT", "/api/camera-mapping"),
    ("GET", "/api/camera-preview/cam1aaaaaaaaaaaaaaaaaaaaa"),
    ("GET", "/api/transactions"),
    ("POST", "/api/transactions"),
    ("GET", "/api/thumbnails/PAY_001"),
    ("POST", "/api/sync"),
    ("PUT", "/api/settings/protect"),
    ("GET", "/api/settings/deep-link"),
    ("PUT", "/api/settings/deep-link"),
    ("GET", "/api/settings/protect/motion-webhook"),
    ("PUT", "/api/settings/protect/motion-webhook"),
    ("DELETE", "/api/settings/protect/motion-webhook"),
    ("POST", "/api/settings/protect/console-switch-token"),
    ("PUT", "/api/settings/square"),
    ("POST", "/api/logout"),
]


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_transaction_data_and_camera_evidence_are_private_with_open_umask(tmp_path):
    old_umask = os.umask(0)
    store = None
    try:
        store = Store(tmp_path / "data")
        store.set_camera_mapping("LOC1", "CAM1", "Register")

        class Protect:
            def get_snapshot(self, camera_id, ts_ms=None):
                return b"private camera evidence"

        ingest_payment(
            store,
            {
                "id": "PRIVATE",
                "created_at": "2026-07-16T15:30:00.000Z",
                "amount_money": {"amount": 100, "currency": "USD"},
                "status": "COMPLETED",
                "location_id": "LOC1",
            },
            Protect(),
        )
    finally:
        os.umask(old_umask)

    assert store is not None
    try:
        txn = store.get_transaction("PRIVATE")
        thumbnail_path = store.thumbnail_dir / txn["thumbnail_path"]
        assert (store.data_dir / "spi.db").is_file()
        assert (store.data_dir / "secret.key").is_file()
        assert thumbnail_path.read_bytes() == b"private camera evidence"
        if os.name == "posix":
            assert _mode(store.data_dir) == 0o700
            assert _mode(store.thumbnail_dir) == 0o700
            assert _mode(store.data_dir / "spi.db") == 0o600
            assert _mode(store.data_dir / "secret.key") == 0o600
            assert _mode(thumbnail_path) == 0o600
    finally:
        store.close()


def test_store_hardens_existing_data_permissions(tmp_path):
    data_dir = tmp_path / "existing"
    thumbnail_dir = data_dir / "thumbnails"
    thumbnail_dir.mkdir(parents=True, mode=0o777)
    image_path = thumbnail_dir / "old.jpg"
    image_path.write_bytes(b"old evidence")
    os.chmod(data_dir, 0o777)
    os.chmod(thumbnail_dir, 0o777)
    os.chmod(image_path, 0o666)

    store = Store(data_dir)
    try:
        assert image_path.read_bytes() == b"old evidence"
        assert (data_dir / "spi.db").is_file()
        if os.name == "posix":
            assert _mode(data_dir) == 0o700
            assert _mode(thumbnail_dir) == 0o700
            assert _mode(image_path) == 0o600
            assert _mode(data_dir / "spi.db") == 0o600
    finally:
        store.close()


@pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
def test_endpoints_require_authentication(client, method, path):
    resp = client.request(method, path, json={})
    assert resp.status_code == 401, f"{method} {path} must require auth"

def test_forged_session_cookie_rejected(client):
    client.post("/api/setup", json=bootstrap_setup_body())
    client.cookies.set("spi_session", "forged-token-attempt")
    assert client.get("/api/transactions").status_code == 401

def test_session_cookie_flags(client):
    client.post("/api/setup", json=bootstrap_setup_body())
    resp = client.post("/api/login", json={"password": ADMIN_PASSWORD})
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie


def test_transaction_search_stays_out_of_request_target_even_when_unauthorized(client):
    search_term = "private-card-4242"
    response = client.post("/api/transactions", json={"q": search_term})

    assert response.status_code == 401
    assert search_term not in str(response.request.url)
    assert not response.request.url.query


def test_transaction_query_auth_precedes_json_parsing_and_declared_size(client):
    malformed = client.post(
        "/api/transactions",
        content=b"{",
        headers={"content-type": "application/json"},
    )
    oversized = client.post(
        "/api/transactions",
        content=b"{}",
        headers={
            "content-type": "application/json",
            "content-length": str(TRANSACTION_QUERY_MAX_BODY_BYTES + 1),
        },
    )

    assert malformed.status_code == 401
    assert oversized.status_code == 401


def test_unauthorized_transaction_query_does_not_consume_chunked_body(client):
    chunks_read = 0

    def query_chunks():
        nonlocal chunks_read
        chunks_read += 1
        yield b'{"q":"'
        chunks_read += 1
        yield b"x" * TRANSACTION_QUERY_MAX_BODY_BYTES
        chunks_read += 1
        yield b'"}'

    response = client.post(
        "/api/transactions",
        content=query_chunks(),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 401
    assert chunks_read == 0


def test_transaction_query_rejects_oversized_declared_body(authed):
    response = authed.post(
        "/api/transactions",
        content=b"{}",
        headers={
            "content-type": "application/json",
            "content-length": str(TRANSACTION_QUERY_MAX_BODY_BYTES + 1),
        },
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Transaction query payload too large"


@pytest.mark.parametrize("headers", [{}, {"content-length": "2"}])
def test_transaction_query_rejects_oversized_chunked_or_underdeclared_body(
    authed, headers
):
    chunks = iter(
        [
            b'{"q":"',
            b"x" * TRANSACTION_QUERY_MAX_BODY_BYTES,
            b'"}',
        ]
    )
    response = authed.post(
        "/api/transactions",
        content=chunks,
        headers={"content-type": "application/json", **headers},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Transaction query payload too large"


def test_transaction_query_validation_does_not_echo_private_input(authed):
    private_query = "private-card-4242-" + "x" * 64

    response = authed.post("/api/transactions", json={"q": private_query})

    assert response.status_code == 422
    assert private_query not in response.text


def test_transaction_query_rejects_url_parameters_and_csrf_form_posts(authed):
    ambiguous = authed.post(
        "/api/transactions?offset=1",
        json={"offset": 0, "q": "private-card-4242"},
    )
    legacy_query = authed.get(
        "/api/transactions", params={"q": "private-card-4242"}
    )
    form_post = authed.post(
        "/api/transactions", data={"q": "private-card-4242"}
    )

    assert ambiguous.status_code == 422
    assert ambiguous.json()["detail"] == (
        "Transaction read parameters must be sent in the JSON body"
    )
    assert legacy_query.status_code == 422
    assert legacy_query.json()["detail"] == (
        "Transaction read parameters must be sent in a POST JSON body"
    )
    assert form_post.status_code == 415
    assert form_post.json()["detail"] == (
        "Transaction reads require an application/json body"
    )


def test_legacy_unfiltered_transaction_read_remains_compatible(authed):
    legacy = authed.get("/api/transactions")
    body_read = authed.post("/api/transactions", json={})

    assert legacy.status_code == 200
    assert legacy.json() == body_read.json()

def test_setup_cannot_be_rerun(authed):
    resp = authed.post("/api/setup", json=bootstrap_setup_body("attacker-password"))
    assert resp.status_code == 409
    # Original password still works
    assert authed.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200

def test_login_throttled_after_repeated_failures(client):
    client.post("/api/setup", json=bootstrap_setup_body())
    for _ in range(5):
        assert client.post("/api/login", json={"password": "wrong"}).status_code == 401
    resp = client.post("/api/login", json={"password": "wrong"})
    assert resp.status_code == 429
    # Even the correct password is throttled while locked out
    assert client.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 429


def test_successful_login_resets_prior_failures(client):
    client.post("/api/setup", json=bootstrap_setup_body())
    for _ in range(4):
        assert client.post("/api/login", json={"password": "wrong"}).status_code == 401

    assert client.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
    assert client.app.state.login_failures == {}
    assert client.post("/api/login", json={"password": "one-more-typo"}).status_code == 401
    assert client.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200


def test_login_failure_map_prunes_expired_keys_and_throttles_at_capacity(
    client, monkeypatch
):
    client.post("/api/setup", json=bootstrap_setup_body())
    now = time.time()
    client.app.state.login_failures.update(
        {
            "active-a": [now],
            "active-b": [now],
            "expired": [now - 61],
        }
    )
    monkeypatch.setattr("app.main.LOGIN_FAILURE_KEY_LIMIT", 2)

    # At capacity, fail before running an expensive password hash for an
    # untracked source. The normal throttle check still removes expired keys.
    assert client.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 429
    assert set(client.app.state.login_failures) == {"active-a", "active-b"}

    # A failing new source is throttled rather than left untracked or allowed
    # to evict an active brute-force counter.
    assert client.post("/api/login", json={"password": "wrong"}).status_code == 429
    assert set(client.app.state.login_failures) == {"active-a", "active-b"}


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


def test_transaction_data_and_camera_media_are_not_cached(configured):
    preview = configured.get("/api/camera-preview/cam1aaaaaaaaaaaaaaaaaaaaa")
    assert configured.post("/api/sync").status_code == 200
    transactions = configured.post("/api/transactions", json={})
    thumbnail = configured.get(transactions.json()[0]["thumbnail_url"])

    for response in (preview, transactions, thumbnail):
        assert response.status_code == 200
        assert response.headers["cache-control"] == "private, no-store"


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


def test_webhook_rejects_oversized_content_length(configured):
    resp = configured.post(
        "/webhooks/square",
        content=b"{}",
        headers={"content-length": str(SQUARE_WEBHOOK_MAX_BODY_BYTES + 1)},
    )

    assert resp.status_code == 413
    assert resp.json()["detail"] == "Webhook payload too large"
    assert resp.headers["cache-control"] == "private, no-store"


@pytest.mark.parametrize("headers", [{}, {"content-length": "1"}])
def test_webhook_rejects_oversized_streamed_or_underdeclared_body(
    configured, headers
):
    chunks = iter(
        [
            b"x" * (SQUARE_WEBHOOK_MAX_BODY_BYTES // 2),
            b"y" * (SQUARE_WEBHOOK_MAX_BODY_BYTES // 2 + 1),
        ]
    )
    resp = configured.post("/webhooks/square", content=chunks, headers=headers)

    assert resp.status_code == 413
    assert resp.json()["detail"] == "Webhook payload too large"
    assert resp.headers["cache-control"] == "private, no-store"


@pytest.mark.parametrize(
    "event",
    [
        {"type": "payment.updated", "data": []},
        {"type": "payment.updated", "data": {"object": []}},
        {"type": "payment.updated", "data": {"object": {"payment": []}}},
        {"type": "payment.updated", "data": {"object": {"payment": "bad"}}},
    ],
)
def test_webhook_ignores_non_object_payment_envelopes(configured, event):
    from .test_api import _webhook_signature

    event = {"merchant_id": SQUARE_MERCHANT_ID, **event}
    body = json.dumps(event).encode()
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "ignored": True}


def test_webhook_rejects_malformed_nested_payment(configured):
    from .test_api import _webhook_signature

    event = json.loads(make_webhook_event())
    event["data"]["object"]["payment"]["device_details"] = []
    body = json.dumps(event).encode()
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )

    assert resp.status_code == 422
    assert resp.json()["detail"] == "Payment device_details must be an object"


# -- stored XSS surface -----------------------------------------------------------------

def test_malicious_payment_fields_returned_as_json_not_html(configured):
    """API responses are JSON; script payloads must come back JSON-escaped, and
    the frontend renders exclusively via textContent."""
    from .test_api import _webhook_signature

    payload = json.dumps(
        {
            "merchant_id": SQUARE_MERCHANT_ID,
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
    listing = configured.post("/api/transactions", json={})
    assert listing.headers["content-type"].startswith("application/json")
    txn = next(t for t in listing.json() if t["id"] == "XSS1")
    assert txn["status"] == "<script>alert(1)</script>"  # normalized, escaped by JSON

def test_frontend_never_uses_innerhtml():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js_files = sorted(static_dir.glob("*.js"))
    assert js_files, "expected frontend scripts in app/static"
    for js_file in js_files:
        js = js_file.read_text(encoding="utf-8")
        assert "innerHTML" not in js, js_file.name
        assert "document.write" not in js, js_file.name

def test_transaction_feed_refresh_is_visibility_aware_and_non_overlapping():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text(encoding="utf-8")
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    assert "TRANSACTION_REFRESH_MS" in js
    assert 'document.visibilityState === "visible"' in js
    # The 15-second refresh must keep running while the Settings section is
    # open; only browser-tab visibility, login state, and history paging gate
    # it — never the active app section.
    assert "transactionRefreshAllowed" in js
    assert '!$("#view-transactions").hidden' not in js
    assert "transactionLoadInFlight" in js
    assert "payload !== lastTransactionPayload" in js
    assert 'id="txn-last-updated"' in html


def test_transaction_amount_formatter_uses_currency_minor_units():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    formatter = (static_dir / "format.js").read_text(encoding="utf-8")
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    assert "resolvedOptions().maximumFractionDigits" in formatter
    assert "10 ** fractionDigits" in formatter
    assert html.index('/format.js') < html.index('/app.js')


def test_transaction_feed_pagination_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text(encoding="utf-8")
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    css = (static_dir / "style.css").read_text(encoding="utf-8")
    assert "TRANSACTION_PAGE_SIZE + 1" in js
    assert "transactionQueryBody(requestedFilters" in js
    assert 'api("/api/transactions", {' in js
    assert 'method: "POST"' in js
    assert "/api/transactions?" not in js
    assert "page.slice(0, TRANSACTION_PAGE_SIZE)" in js
    assert "transactionPendingOffset" in js
    assert "transactionSnapshot" in js
    assert 'headers.get("x-transaction-snapshot")' in js
    assert "transactionOffset === 0" in js
    assert "error.status = resp.status" in js
    assert "err.status === 409" in js
    assert "transactionPendingOffset = 0" in js
    assert 'id="txn-prev"' in html
    assert 'id="txn-next"' in html
    assert 'id="txn-page-status"' in html
    assert 'aria-live="polite"' in html
    assert "min-width: 0" in css
    assert "@media (max-width: 520px)" in css


def test_transaction_feed_describes_missing_thumbnail_state():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text(encoding="utf-8")
    assert 'unmapped: "camera not mapped"' in js
    assert 'queued: "footage queued"' in js
    assert 'retrying: "capture retrying"' in js


def test_transaction_thumbnails_use_accessible_timeline_links():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text(encoding="utf-8")
    css = (static_dir / "style.css").read_text(encoding="utf-8")
    assert 'const link = document.createElement("a")' in js
    assert "link.href = txn.deep_link" in js
    assert 'link.target = "_blank"' in js
    assert 'link.rel = "noopener noreferrer"' in js
    assert '"aria-label"' in js
    assert "window.open(txn.deep_link" not in js
    assert ".txn .thumbnail-link:focus-visible" in css


def test_pos_device_mapping_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text(encoding="utf-8")
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    assert 'api("/api/pos-devices")' in js
    assert "select.dataset.deviceId" in js
    assert "select.dataset.deviceName" in js
    assert "Other devices (fallback)" in js
    assert "observed Square POS device" in html


def test_all_api_responses_default_to_no_store(configured):
    for path in ("/api/status", "/api/camera-mapping", "/api/settings/deep-link"):
        resp = configured.get(path)
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "private, no-store"


def test_frontend_only_treats_session_401_as_logout():
    """Upstream-credential 401s from settings endpoints must not bounce the
    operator to the login view; only the app session's own 401 may."""
    from pathlib import Path

    js = (
        Path(__file__).parent.parent / "app" / "static" / "app.js"
    ).read_text(encoding="utf-8")
    assert 'data.detail === "Authentication required"' in js
    # The redirect decision must consider the parsed body, not status alone.
    assert 'resp.status === 401 && path !== "/api/login") {' not in js

def test_setup_wizard_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text(encoding="utf-8")
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    assert 'id="view-wizard"' in html
    for step in ("1", "2", "3", "4"):
        assert f'data-step="{step}"' in html
    assert "maybeStartWizard" in js
    assert "enterAppOrWizard" in js
    assert "buildMappingRows" in js  # shared with Settings, not duplicated
    assert js.count("function buildMappingRows") == 1
    assert 'id="wiz-skip"' in html
