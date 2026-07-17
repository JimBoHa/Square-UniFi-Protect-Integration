"""Unit tests for security helpers, deep links, clients, and sync logic."""

import base64
import hashlib
import hmac
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from app.deeplink import build_deep_link
from app.protect_client import (
    ProtectAuthError,
    ProtectClient,
    ProtectError,
    validate_alarm_trigger_id,
    validate_camera_id,
    validate_host,
)
from app.security import CredentialCipher, hash_password, verify_password
from app.square_client import SquareClient, verify_webhook_signature
from app.store import ALARM_ENABLED_AFTER_SETTING, Store
from app.sync import parse_ts_ms, safe_thumbnail_name, sync_payments

from .conftest import PROTECT_PASS, PROTECT_USER, protect_handler


# -- passwords & encryption --------------------------------------------------

def test_password_hash_roundtrip():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored)
    assert not verify_password("wrong password", stored)
    assert "correct horse" not in stored

def test_password_hash_salted():
    assert hash_password("same") != hash_password("same")

def test_verify_password_malformed_hash():
    assert not verify_password("x", "not-a-valid-hash")
    assert not verify_password("x", "md5$aa$bb")

def test_credential_cipher_roundtrip(tmp_path):
    cipher = CredentialCipher(tmp_path)
    token = cipher.encrypt("super-secret-token")
    assert "super-secret-token" not in token
    assert cipher.decrypt(token) == "super-secret-token"

def test_credential_cipher_key_file_permissions(tmp_path):
    CredentialCipher(tmp_path)
    mode = (tmp_path / "secret.key").stat().st_mode & 0o777
    assert mode == 0o600

def test_credential_cipher_rejects_tampered(tmp_path):
    cipher = CredentialCipher(tmp_path)
    with pytest.raises(ValueError):
        cipher.decrypt("bogus-ciphertext")


# -- host / camera id validation ---------------------------------------------

@pytest.mark.parametrize("host", ["192.168.1.1", "unifi.local", "console.example.com:8443"])
def test_validate_host_accepts(host):
    assert validate_host(host) == host

@pytest.mark.parametrize(
    "host",
    [
        "http://evil.com",
        "host/path",
        "user@host",
        "host?x=1",
        "host#frag",
        "",
        "host name",
        "evil.com:443/../..",
    ],
)
def test_validate_host_rejects(host):
    with pytest.raises(ValueError):
        validate_host(host)

@pytest.mark.parametrize("cam", ["abc123", "A1" * 10])
def test_validate_camera_id_accepts(cam):
    assert validate_camera_id(cam) == cam

@pytest.mark.parametrize("cam", ["", "../etc", "a b", "a/b", "x" * 65, "cam?ts=1"])
def test_validate_camera_id_rejects(cam):
    with pytest.raises(ValueError):
        validate_camera_id(cam)

@pytest.mark.parametrize(
    "trigger_id",
    [
        "sale",
        "Square_Sale-01",
        "square.completed",
        "sale/other",
        "sale?all=1",
        "sale space",
        "A" * 256,
    ],
)
def test_validate_alarm_trigger_id_accepts_user_defined_value(trigger_id):
    assert validate_alarm_trigger_id(trigger_id) == trigger_id

@pytest.mark.parametrize("trigger_id", ["", "sale\nother", "sale\x7fother", "A" * 257])
def test_validate_alarm_trigger_id_rejects_invalid_value(trigger_id):
    with pytest.raises(ValueError):
        validate_alarm_trigger_id(trigger_id)


# -- deep links -----------------------------------------------------------------

def test_deep_link_default_template():
    link = build_deep_link("192.168.1.1", "cam1", 1609459200000)
    assert link == "https://192.168.1.1/protect/timeline/cam1?ts=1609459200000"

def test_deep_link_custom_template():
    link = build_deep_link(
        "u.local", "cam1", 5, template="https://{host}/protect/timeline?cams={camera_id}&t={ts_ms}"
    )
    assert link == "https://u.local/protect/timeline?cams=cam1&t=5"

def test_deep_link_rejects_bad_values():
    with pytest.raises(ValueError):
        build_deep_link("evil.com/path", "cam1", 5)
    with pytest.raises(ValueError):
        build_deep_link("ok.local", "../cam", 5)


# -- sync helpers -------------------------------------------------------------------

def test_parse_ts_ms_known_value():
    assert parse_ts_ms("2021-01-01T00:00:00Z") == 1609459200000
    assert parse_ts_ms("2021-01-01T00:00:00.500Z") == 1609459200500

def test_safe_thumbnail_name_sanitizes():
    assert safe_thumbnail_name("PAY_001") == "PAY_001.jpg"
    assert safe_thumbnail_name("../../etc/passwd") == "etcpasswd.jpg"
    assert "/" not in safe_thumbnail_name("a/b\\c..d")

def test_safe_thumbnail_name_rejects_empty():
    with pytest.raises(ValueError):
        safe_thumbnail_name("../../..")


# -- Square webhook signature ------------------------------------------------------

def _sign(key: str, url: str, body: bytes) -> str:
    return base64.b64encode(
        hmac.new(key.encode(), url.encode() + body, hashlib.sha256).digest()
    ).decode()

def test_webhook_signature_valid():
    body = b'{"type":"payment.updated"}'
    sig = _sign("key1", "https://x.example/webhooks/square", body)
    assert verify_webhook_signature("key1", "https://x.example/webhooks/square", body, sig)

def test_webhook_signature_invalid():
    body = b'{"type":"payment.updated"}'
    sig = _sign("key1", "https://x.example/webhooks/square", body)
    assert not verify_webhook_signature("otherkey", "https://x.example/webhooks/square", body, sig)
    assert not verify_webhook_signature("key1", "https://x.example/webhooks/square", body + b" ", sig)
    assert not verify_webhook_signature("key1", "https://evil.example/hook", body, sig)
    assert not verify_webhook_signature("key1", "https://x.example/webhooks/square", body, "")
    assert not verify_webhook_signature("", "https://x.example/webhooks/square", body, sig)


# -- Protect client ------------------------------------------------------------------

def test_protect_login_and_cameras():
    client = ProtectClient(
        "unifi.local", PROTECT_USER, PROTECT_PASS,
        transport=httpx.MockTransport(protect_handler),
    )
    cameras = client.get_cameras()
    assert [c["name"] for c in cameras] == ["Front Counter", "Back Door"]
    client.close()

def test_protect_bad_credentials():
    client = ProtectClient(
        "unifi.local", PROTECT_USER, "wrong",
        transport=httpx.MockTransport(protect_handler),
    )
    with pytest.raises(ProtectAuthError):
        client.get_cameras()
    client.close()

def test_protect_snapshot_passes_timestamp():
    client = ProtectClient(
        "unifi.local", PROTECT_USER, PROTECT_PASS,
        transport=httpx.MockTransport(protect_handler),
    )
    image = client.get_snapshot("cam1aaaaaaaaaaaaaaaaaaaaa", ts_ms=1609459200000)
    assert image.startswith(b"\xff\xd8")
    assert image.endswith(b"1609459200000")
    client.close()

def test_protect_relogin_on_expired_session():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(401)
        return httpx.Response(200, json={"cameras": [{"id": "cam9", "name": "X"}]})

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    cameras = client.get_cameras()
    assert cameras[0]["id"] == "cam9"
    client.close()

def test_protect_official_api_uses_key_without_legacy_login():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(
            (
                request.method,
                request.url.raw_path.decode(),
                request.headers.get("x-api-key"),
            )
        )
        if request.url.path.endswith("/meta/info"):
            return httpx.Response(200, json={"applicationVersion": "7.1.87"})
        return httpx.Response(204)

    client = ProtectClient(
        "u.local",
        "legacy-user",
        "legacy-pass",
        api_key="api-key",
        transport=httpx.MockTransport(handler),
    )
    assert client.get_integration_info() == {"applicationVersion": "7.1.87"}
    client.trigger_alarm("square.completed/sale?all=1")
    client.close()

    assert requests == [
        (
            "GET",
            "/proxy/protect/integration/v1/meta/info",
            "api-key",
        ),
        (
            "POST",
            "/proxy/protect/integration/v1/alarm-manager/webhook/"
            "square.completed%2Fsale%3Fall%3D1",
            "api-key",
        ),
    ]

def test_protect_official_api_does_not_accept_redirect_as_success():
    client = ProtectClient(
        "u.local",
        "legacy-user",
        "legacy-pass",
        api_key="api-key",
        transport=httpx.MockTransport(lambda request: httpx.Response(302)),
    )
    with pytest.raises(ProtectError):
        client.trigger_alarm("square-sale")
    client.close()


# -- Store alarm state -------------------------------------------------------------

def _transaction(txn_id: str, status: str = "COMPLETED") -> dict:
    return {
        "id": txn_id,
        "created_at": "2026-07-16T15:30:00Z",
        "ts_ms": 1784215800000,
        "amount": 100,
        "currency": "USD",
        "status": status,
    }

def test_alarm_claim_is_atomic_and_terminal_after_success(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    second_store = Store(data_dir)
    try:
        store.upsert_transaction(_transaction("PAY1"))
        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(
                executor.map(
                    lambda candidate: candidate.claim_alarm_trigger("PAY1"),
                    (store, second_store),
                )
            )
        assert sum(bool(claim) for claim in claims) == 1
        claim_token = next(claim for claim in claims if claim)
        assert store.mark_alarm_sent("PAY1", claim_token) is True
        assert store.claim_alarm_trigger("PAY1") is None
        assert second_store.claim_alarm_trigger("PAY1") is None
    finally:
        second_store.close()
        store.close()

def test_store_startup_releases_abandoned_alarm_claim(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    store.upsert_transaction(_transaction("PAY1"))
    assert store.claim_alarm_trigger("PAY1") is not None
    store.close()

    monkeypatch.setattr("app.store.time.time", lambda: 10_000_000_000)
    reopened = Store(data_dir)
    try:
        assert reopened.get_transaction("PAY1")["alarm_state"] == "idle"
        assert reopened.claim_alarm_trigger("PAY1") is not None
    finally:
        reopened.close()

def test_store_startup_does_not_steal_live_alarm_claim(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    store.upsert_transaction(_transaction("PAY1"))
    claim_token = store.claim_alarm_trigger("PAY1")
    assert claim_token is not None

    second_store = Store(data_dir)
    try:
        assert second_store.get_transaction("PAY1")["alarm_state"] == "in_progress"
        assert second_store.claim_alarm_trigger("PAY1") is None
        assert store.mark_alarm_sent("PAY1", claim_token) is True
    finally:
        second_store.close()
        store.close()

def test_store_migrates_alarm_state_without_replaying_completed_rows(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db = sqlite3.connect(data_dir / "spi.db")
    db.execute(
        "CREATE TABLE transactions ("
        "id TEXT PRIMARY KEY, created_at TEXT NOT NULL, ts_ms INTEGER NOT NULL, "
        "amount INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, "
        "location_id TEXT NOT NULL DEFAULT '', card_last4 TEXT NOT NULL DEFAULT '', "
        "receipt_url TEXT NOT NULL DEFAULT '', camera_id TEXT, thumbnail_path TEXT, "
        "raw TEXT NOT NULL DEFAULT '{}')"
    )
    db.execute(
        "INSERT INTO transactions "
        "(id, created_at, ts_ms, amount, currency, status) VALUES (?, ?, ?, ?, ?, ?)",
        ("OLD", "2026-07-16T15:30:00Z", 1, 100, "USD", "COMPLETED"),
    )
    db.commit()
    db.close()

    store = Store(data_dir)
    try:
        assert store.get_transaction("OLD")["alarm_state"] == "sent"
        assert store.claim_alarm_trigger("OLD") is None
        store.upsert_transaction(_transaction("NEW"))
        assert store.claim_alarm_trigger("NEW") is not None
    finally:
        store.close()


def test_alarm_activation_suppresses_later_historical_imports(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.update_settings(
            {ALARM_ENABLED_AFTER_SETTING: ("1500", False)}
        )
        store.upsert_transaction(_transaction("HISTORICAL") | {"ts_ms": 1000})
        store.upsert_transaction(_transaction("LIVE") | {"ts_ms": 2000})
        assert store.get_transaction("HISTORICAL")["alarm_state"] == "sent"
        assert store.get_transaction("LIVE")["alarm_state"] == "idle"
    finally:
        store.close()


def test_alarm_retry_runs_when_square_listing_fails(tmp_path):
    class UnavailableSquare:
        def list_payments(self, **_kwargs):
            raise RuntimeError("Square unavailable")

    class RecordingProtect:
        def __init__(self):
            self.timeouts = []

        def trigger_alarm(self, _trigger_id, timeout=None):
            self.timeouts.append(timeout)

    store = Store(tmp_path / "data")
    protect = RecordingProtect()
    try:
        store.upsert_transaction(_transaction("PAY_RETRY_DURING_OUTAGE"))
        with pytest.raises(RuntimeError, match="Square unavailable"):
            sync_payments(
                store,
                UnavailableSquare(),
                protect,
                alarm_trigger_id="square.completed",
            )
        assert store.get_transaction("PAY_RETRY_DURING_OUTAGE")["alarm_state"] == "sent"
        assert len(protect.timeouts) == 1
        assert 0 < protect.timeouts[0] <= 5
    finally:
        store.close()


# -- Square client -------------------------------------------------------------------

def test_square_pagination_follows_cursor():
    pages = {
        None: {"payments": [{"id": "P1"}], "cursor": "next1"},
        "next1": {"payments": [{"id": "P2"}]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor")
        return httpx.Response(200, json=pages[cursor])

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    payments = client.list_payments()
    assert [p["id"] for p in payments] == ["P1", "P2"]
    client.close()

def test_square_rejects_bad_environment():
    with pytest.raises(ValueError):
        SquareClient("tok", environment="staging")
