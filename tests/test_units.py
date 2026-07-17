"""Unit tests for security helpers, deep links, clients, and sync logic."""

import base64
import hashlib
import hmac

import httpx
import pytest

from app.deeplink import build_deep_link
from app.protect_client import ProtectAuthError, ProtectClient, validate_camera_id, validate_host
from app.security import CredentialCipher, hash_password, verify_password
from app.square_client import SquareClient, payment_from_api, verify_webhook_signature
from app.store import Store
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


# -- Square client -------------------------------------------------------------------

def test_payment_from_api_uses_offline_client_timestamp():
    payment = {
        "id": "PAY_OFFLINE",
        "created_at": "2026-07-16T16:30:00Z",
        "is_offline_payment": True,
        "offline_payment_details": {"client_created_at": "2026-07-16T08:30:00Z"},
    }

    normalized = payment_from_api(payment)
    assert normalized["created_at"] == "2026-07-16T08:30:00Z"
    assert normalized["raw"]["created_at"] == "2026-07-16T16:30:00Z"

@pytest.mark.parametrize(
    "offline_details",
    [None, {}, {"client_created_at": ""}, {"client_created_at": "   "}],
)
def test_payment_from_api_falls_back_when_offline_timestamp_missing(offline_details):
    payment = {
        "created_at": "2026-07-16T16:30:00Z",
        "is_offline_payment": True,
        "offline_payment_details": offline_details,
    }

    assert payment_from_api(payment)["created_at"] == "2026-07-16T16:30:00Z"

def test_sync_uses_offline_client_timestamp_for_snapshot(tmp_path):
    client_created_at = "2026-07-16T08:30:00Z"
    payment = {
        "id": "PAY_OFFLINE",
        "created_at": "2026-07-16T16:30:00Z",
        "is_offline_payment": True,
        "offline_payment_details": {"client_created_at": client_created_at},
        "amount_money": {"amount": 1200, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
    }

    class Square:
        def list_payments(self, begin_time=None):
            return [payment]

    class RecordingProtect:
        def __init__(self):
            self.snapshot_calls = []

        def get_snapshot(self, camera_id, ts_ms):
            self.snapshot_calls.append((camera_id, ts_ms))
            return b"snapshot"

    store = Store(tmp_path / "data")
    protect = RecordingProtect()
    try:
        store.set_camera_mapping("LOC1", "CAM1", "Register")

        assert sync_payments(store, Square(), protect) == 1
        expected_ts = parse_ts_ms(client_created_at)
        assert protect.snapshot_calls == [("CAM1", expected_ts)]
        transaction = store.get_transaction("PAY_OFFLINE")
        assert transaction["created_at"] == client_created_at
        assert transaction["ts_ms"] == expected_ts
    finally:
        store.close()

def test_sync_skips_nonempty_malformed_offline_timestamp(tmp_path):
    payment = {
        "id": "PAY_BAD_TIME",
        "created_at": "2026-07-16T16:30:00Z",
        "is_offline_payment": True,
        "offline_payment_details": {"client_created_at": "not-a-timestamp"},
        "amount_money": {"amount": 1200, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
    }

    class Square:
        def list_payments(self, begin_time=None):
            return [payment]

    store = Store(tmp_path / "data")
    try:
        assert sync_payments(store, Square(), None) == 0
        assert store.get_transaction("PAY_BAD_TIME") is None
    finally:
        store.close()

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
