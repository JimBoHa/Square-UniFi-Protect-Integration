"""Unit tests for security helpers, deep links, clients, and sync logic."""

import base64
import hashlib
import hmac
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from cryptography.fernet import Fernet

from app.deeplink import build_deep_link
from app.protect_client import (
    ProtectAuthError,
    ProtectClient,
    ProtectError,
    validate_alarm_trigger_id,
    validate_camera_id,
    validate_host,
)
from app.security import CredentialCipher, KEY_FILENAME, hash_password, verify_password
from app.square_client import (
    SquareClient,
    SquareError,
    SquarePermissionError,
    payment_from_api,
    verify_webhook_signature,
)
from app.store import ALARM_ENABLED_AFTER_SETTING, Store
from app.sync import ingest_payment, parse_ts_ms, safe_thumbnail_name, sync_payments

from .conftest import FAKE_JPEG, PROTECT_PASS, PROTECT_USER, protect_handler


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


def test_credential_cipher_key_creation_is_atomic_under_concurrency(tmp_path, monkeypatch):
    worker_count = 32
    all_generating = threading.Barrier(worker_count)
    generate_key = Fernet.generate_key

    def synchronized_generate_key():
        all_generating.wait(timeout=10)
        return generate_key()

    monkeypatch.setattr(Fernet, "generate_key", staticmethod(synchronized_generate_key))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(CredentialCipher, tmp_path) for _ in range(worker_count)]
        ciphers = [future.result(timeout=20) for future in futures]

    token = ciphers[0].encrypt("shared-secret")
    assert all(cipher.decrypt(token) == "shared-secret" for cipher in ciphers)
    assert (tmp_path / KEY_FILENAME).stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.glob(f".{KEY_FILENAME}.*.tmp")) == []


def test_credential_cipher_rejects_tampered(tmp_path):
    cipher = CredentialCipher(tmp_path)
    with pytest.raises(ValueError):
        cipher.decrypt("bogus-ciphertext")


# -- host / camera id validation ---------------------------------------------

@pytest.mark.parametrize(
    "host",
    [
        "192.168.1.1",
        "unifi.local",
        "console.example.com:8443",
        "console.example.com:1",
        "console.example.com:65535",
    ],
)
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
        "unifi.local:0",
        "unifi.local:65536",
        "unifi.local:99999",
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
    assert link == "https://192.168.1.1/protect/timelapse/cam1?start=1609459200000"

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

def test_replace_camera_mappings_rolls_back_on_failure(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.set_camera_mapping("LOC_OLD", "camold", "Old camera")
        with pytest.raises(sqlite3.IntegrityError):
            store.replace_camera_mappings(
                [
                    ("LOC_NEW", "", "", "camnew", "New camera"),
                    ("LOC_BROKEN", "", "", None, "Broken camera"),
                ]
            )
        assert store.get_camera_mappings() == [
            {
                "location_id": "LOC_OLD",
                "device_id": "",
                "device_name": "",
                "camera_id": "camold",
                "camera_name": "Old camera",
            }
        ]
    finally:
        store.close()

def test_sync_queries_every_location_with_its_own_watermark(tmp_path):
    def payment(payment_id: str, created_at: str, location_id: str) -> dict:
        return {
            "id": payment_id,
            "created_at": created_at,
            "amount_money": {"amount": 100, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": location_id,
        }

    first_payment = payment("PAY_LOC1", "2026-07-16T15:30:00Z", "LOC1")
    second_payment = payment("PAY_LOC2", "2026-07-16T15:40:00Z", "LOC2")

    class RecordingSquare:
        def __init__(self):
            self.calls = []

        def list_locations(self):
            return [{"id": "LOC1"}, {"id": "LOC2"}]

        def list_payments(
            self,
            updated_at_begin_time=None,
            sort_field=None,
            sort_order=None,
            location_id=None,
        ):
            assert sort_field == "UPDATED_AT"
            assert sort_order == "ASC"
            self.calls.append((location_id, updated_at_begin_time))
            if location_id == "LOC1":
                return [first_payment]
            return [first_payment, second_payment]

    store = Store(tmp_path / "data")
    try:
        ingest_payment(
            store,
            payment("OLD_LOC1", "2026-07-15T12:00:00Z", "LOC1"),
            None,
        )
        ingest_payment(
            store,
            payment("OLD_LOC2", "2026-07-10T08:00:00Z", "LOC2"),
            None,
        )
        square = RecordingSquare()

        assert sync_payments(store, square, None) == 2
        assert square.calls == [
            ("LOC1", "2026-07-15T11:55:00Z"),
            ("LOC2", "2026-07-10T07:55:00Z"),
        ]
        assert store.get_transaction("PAY_LOC1") is not None
        assert store.get_transaction("PAY_LOC2") is not None
    finally:
        store.close()


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


def test_protect_login_transport_error_is_normalized():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive connection details", request=request)

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    with pytest.raises(ProtectError) as exc_info:
        client.get_cameras()
    assert str(exc_info.value) == "Network error while contacting UniFi Protect"
    assert "sensitive connection details" not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, httpx.RequestError)
    client.close()


def test_protect_request_transport_error_is_normalized():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        raise httpx.ReadTimeout("sensitive timeout details", request=request)

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    with pytest.raises(ProtectError) as exc_info:
        client.get_cameras()
    assert str(exc_info.value) == "Network error while contacting UniFi Protect"
    assert "sensitive timeout details" not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, httpx.RequestError)
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


def test_alarm_activation_watermark_is_set_once_across_settings_saves(tmp_path):
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    second = Store(data_dir)
    alarm_settings = {
        "protect.api_key": ("api-key", True),
        "protect.alarm_trigger_id": ("square.completed", False),
    }
    try:
        first.upsert_transaction(_transaction("BEFORE") | {"ts_ms": 1000})
        assert first.update_settings(
            alarm_settings, activate_alarm_at_ms=1500
        ) is True
        assert first.get_transaction("BEFORE")["alarm_state"] == "sent"

        first.upsert_transaction(_transaction("AFTER") | {"ts_ms": 2000})
        # This models a second request that began validation before the first
        # committed. Its stale decision cannot advance the activation boundary.
        assert second.update_settings(
            alarm_settings, activate_alarm_at_ms=2500
        ) is False
        assert second.get_setting(ALARM_ENABLED_AFTER_SETTING) == "1500"
        assert second.get_transaction("AFTER")["alarm_state"] == "idle"
    finally:
        second.close()
        first.close()


def test_alarm_disable_then_reenable_sets_a_new_watermark(tmp_path):
    store = Store(tmp_path / "data")
    alarm_settings = {
        "protect.api_key": ("api-key", True),
        "protect.alarm_trigger_id": ("square.completed", False),
    }
    try:
        assert store.update_settings(
            alarm_settings, activate_alarm_at_ms=1500
        ) is True
        store.update_settings(
            {},
            delete_keys=(
                "protect.api_key",
                "protect.alarm_trigger_id",
                ALARM_ENABLED_AFTER_SETTING,
            ),
            suppress_completed_alarms=True,
        )
        assert store.get_setting(ALARM_ENABLED_AFTER_SETTING) is None

        store.upsert_transaction(_transaction("WHILE_DISABLED") | {"ts_ms": 2500})
        assert store.update_settings(
            alarm_settings, activate_alarm_at_ms=3000
        ) is True
        assert store.get_setting(ALARM_ENABLED_AFTER_SETTING) == "3000"
        assert store.get_transaction("WHILE_DISABLED")["alarm_state"] == "sent"
        store.upsert_transaction(_transaction("AFTER_REENABLE") | {"ts_ms": 3500})
        assert store.get_transaction("AFTER_REENABLE")["alarm_state"] == "idle"
    finally:
        store.close()


def test_store_upgrades_configured_alarm_without_watermark(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    store.update_settings(
        {
            "protect.api_key": ("api-key", True),
            "protect.alarm_trigger_id": ("square.completed", False),
        }
    )
    store.upsert_transaction(_transaction("PRE_UPGRADE"))
    store.close()

    reopened = Store(data_dir)
    try:
        assert reopened.get_setting(ALARM_ENABLED_AFTER_SETTING) is not None
        assert reopened.get_transaction("PRE_UPGRADE")["alarm_state"] == "sent"
    finally:
        reopened.close()


def test_alarm_retry_runs_when_square_listing_fails(tmp_path):
    class UnavailableSquare:
        def list_locations(self):
            raise RuntimeError("Square unavailable")

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
        store.upsert_transaction(
            _transaction("PAY_RETRY_DURING_OUTAGE_1") | {"ts_ms": 1000}
        )
        store.upsert_transaction(
            _transaction("PAY_RETRY_DURING_OUTAGE_2") | {"ts_ms": 2000}
        )
        with pytest.raises(RuntimeError, match="Square unavailable"):
            sync_payments(
                store,
                UnavailableSquare(),
                protect,
                alarm_trigger_id="square.completed",
            )
        # The alarm batch drains oldest-first even though Square failed.
        assert store.get_transaction("PAY_RETRY_DURING_OUTAGE_1")["alarm_state"] == "sent"
        assert store.get_transaction("PAY_RETRY_DURING_OUTAGE_2")["alarm_state"] == "sent"
        assert len(protect.timeouts) == 2
        assert 0 < protect.timeouts[0] <= 5
    finally:
        store.close()


# -- Square client -------------------------------------------------------------------

def test_payment_from_api_prefers_tip_inclusive_total():
    payment = {
        "amount_money": {"amount": 1000, "currency": "USD"},
        "tip_money": {"amount": 200, "currency": "USD"},
        "total_money": {"amount": 1200, "currency": "USD"},
    }

    assert payment_from_api(payment)["amount"] == 1200

def test_payment_from_api_falls_back_to_amount_money():
    payment = {"amount_money": {"amount": 1000, "currency": "EUR"}}

    normalized = payment_from_api(payment)
    assert normalized["amount"] == 1000
    assert normalized["currency"] == "EUR"

def test_payment_from_api_uses_selected_currency_with_safe_fallback():
    selected_currency = payment_from_api(
        {
            "amount_money": {"amount": 1000, "currency": "USD"},
            "total_money": {"amount": 1200, "currency": "CAD"},
        }
    )
    base_currency = payment_from_api(
        {
            "amount_money": {"amount": 1000, "currency": "GBP"},
            "total_money": {"amount": 1200},
        }
    )

    assert selected_currency["currency"] == "CAD"
    assert base_currency["currency"] == "GBP"

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
    # Versioning stays anchored to the server clock, not the older client time.
    assert normalized["updated_at"] == "2026-07-16T16:30:00Z"

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
        def list_locations(self):
            return [{"id": "LOC1"}]

        def list_payments(self, **params):
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
        def list_locations(self):
            return [{"id": "LOC1"}]

        def list_payments(self, **params):
            return [payment]

    store = Store(tmp_path / "data")
    try:
        assert sync_payments(store, Square(), None) == 0
        assert store.get_transaction("PAY_BAD_TIME") is None
    finally:
        store.close()

def test_square_pagination_exhausts_cursor_pages_by_default():
    first_page = [{"id": f"P{i}"} for i in range(100)]
    pages = {
        None: {"payments": first_page, "cursor": "next1"},
        "next1": {"payments": [{"id": "P100"}, {"id": "P101"}]},
    }
    request_limits = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_limits.append(int(request.url.params["limit"]))
        cursor = request.url.params.get("cursor")
        return httpx.Response(200, json=pages[cursor])

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    payments = client.list_payments()
    assert [p["id"] for p in payments] == [f"P{i}" for i in range(102)]
    assert request_limits == [100, 100]
    client.close()

def test_square_pagination_rejects_repeated_cursor():
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            json={"payments": [{"id": f"P{requests}"}], "cursor": "loop"},
        )

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(SquareError, match="repeated pagination cursor"):
            client.list_payments()
    finally:
        client.close()

    assert requests == 2

def test_square_pagination_honors_explicit_total_limit():
    first_page = [{"id": f"P{i}"} for i in range(100)]
    pages = {
        None: {"payments": first_page, "cursor": "next1"},
        "next1": {
            "payments": [{"id": f"P{i}"} for i in range(100, 125)],
            "cursor": "next2",
        },
    }
    request_limits = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_limits.append(int(request.url.params["limit"]))
        cursor = request.url.params.get("cursor")
        return httpx.Response(200, json=pages[cursor])

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    payments = client.list_payments(limit=125)
    assert [p["id"] for p in payments] == [f"P{i}" for i in range(125)]
    assert request_limits == [100, 25]
    client.close()

def test_square_pagination_sends_location_filter_on_every_page():
    pages = {
        None: {"payments": [{"id": "P1"}], "cursor": "next1"},
        "next1": {"payments": [{"id": "P2"}]},
    }
    requested_locations = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_locations.append(request.url.params.get("location_id"))
        cursor = request.url.params.get("cursor")
        return httpx.Response(200, json=pages[cursor])

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    payments = client.list_payments(location_id="LOC1")
    assert [p["id"] for p in payments] == ["P1", "P2"]
    assert requested_locations == ["LOC1", "LOC1"]
    client.close()

def test_square_payment_update_filters_persist_across_pages():
    requests = []
    pages = {
        None: {"payments": [{"id": "P1"}], "cursor": "next1"},
        "next1": {"payments": [{"id": "P2"}]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(dict(request.url.params))
        cursor = request.url.params.get("cursor")
        return httpx.Response(200, json=pages[cursor])

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    payments = client.list_payments(
        updated_at_begin_time="2026-07-16T14:59:00Z",
        sort_field="UPDATED_AT",
        sort_order="ASC",
    )
    client.close()

    assert [p["id"] for p in payments] == ["P1", "P2"]
    assert requests == [
        {
            "sort_order": "ASC",
            "limit": "100",
            "updated_at_begin_time": "2026-07-16T14:59:00Z",
            "sort_field": "UPDATED_AT",
        },
        {
            "sort_order": "ASC",
            "limit": "100",
            "updated_at_begin_time": "2026-07-16T14:59:00Z",
            "sort_field": "UPDATED_AT",
            "cursor": "next1",
        },
    ]

def test_square_rejects_bad_sort_order():
    client = SquareClient("tok")
    try:
        with pytest.raises(ValueError, match="sort_order"):
            client.list_payments(sort_order="SIDEWAYS")
    finally:
        client.close()

def test_square_rejects_bad_environment():
    with pytest.raises(ValueError):
        SquareClient("tok", environment="staging")


def test_square_transport_error_is_normalized():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive Square connection details", request=request)

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    with pytest.raises(SquareError) as exc_info:
        client.list_locations()
    assert str(exc_info.value) == "Network error while contacting Square"
    assert "sensitive Square connection details" not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, httpx.RequestError)
    client.close()

def test_square_permission_error_is_distinct():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": [{"code": "FORBIDDEN"}]})

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    with pytest.raises(SquarePermissionError):
        client.list_payments(limit=1)
    client.close()


# -- historical snapshots against firmware variants (verified on 7.1.87) -------------

def test_snapshot_with_ts_uses_recording_endpoint():
    paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        paths.append(request.url.path + "?" + str(request.url.params))
        if request.url.path.endswith("/recording-snapshot"):
            return httpx.Response(
                200,
                content=(
                    FAKE_JPEG[:-2]
                    + b"rec:"
                    + request.url.params["ts"].encode()
                    + b"\xff\xd9"
                ),
                headers={"content-type": "image/jpeg"},
            )
        return httpx.Response(200, content=FAKE_JPEG)

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    image = client.get_snapshot("cam1", ts_ms=1609459200000)
    assert image == FAKE_JPEG[:-2] + b"rec:1609459200000\xff\xd9"
    assert len(paths) == 1 and "recording-snapshot" in paths[0]
    client.close()

def test_snapshot_no_recording_at_ts_raises_instead_of_wrong_frame():
    """Firmware supports recording-snapshot but has no frame at ts (too fresh
    or out of retention). Falling back to a live frame would attach wrong-time
    evidence; the retry queue must get a chance instead."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        if request.url.path.endswith("/recording-snapshot"):
            return httpx.Response(404, json={"error": "Recording not found"})
        return httpx.Response(200, content=b"\xff\xd8live")

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    with pytest.raises(ProtectError, match="No recording available"):
        client.get_snapshot("cam1", ts_ms=1609459200000)
    client.close()

def test_snapshot_falls_back_to_legacy_ts_on_old_firmware():
    """Old firmware without recording-snapshot returns an HTML 404 for the
    unknown path; the legacy snapshot endpoint (which honored ts on some of
    those versions) is used instead."""
    legacy_params = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        if request.url.path.endswith("/recording-snapshot"):
            return httpx.Response(
                404, content=b"<!DOCTYPE html>", headers={"content-type": "text/html"}
            )
        legacy_params.append(dict(request.url.params))
        return httpx.Response(200, content=FAKE_JPEG[:-2] + b"legacy\xff\xd9")

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    image = client.get_snapshot("cam1", ts_ms=1609459200000)
    assert image == FAKE_JPEG[:-2] + b"legacy\xff\xd9"
    assert legacy_params == [{"w": "640", "ts": "1609459200000"}]
    client.close()


@pytest.mark.parametrize(
    ("content_type", "content"),
    [
        ("application/json", b'{"error":"Recording not found"}'),
        ("text/html; charset=utf-8", b"<!DOCTYPE html><title>Error</title>"),
        ("image/jpeg", b"not actually a jpeg"),
        ("image/jpeg", b"\xff\xd8truncated"),
        ("image/jpeg", b"\xff\xd8\xff\xd9"),
    ],
)
def test_snapshot_rejects_successful_non_jpeg_response(content_type, content):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        return httpx.Response(
            200,
            content=content,
            headers={"content-type": content_type},
        )

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    with pytest.raises(ProtectError, match="JPEG"):
        client.get_snapshot("cam1", ts_ms=1609459200000)
    client.close()


@pytest.mark.parametrize(
    "content_type",
    ["image/jpeg", "image/jpg", "application/octet-stream", ""],
)
def test_snapshot_accepts_valid_jpeg_content_type_variants(content_type):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        headers = {"content-type": content_type} if content_type else {}
        return httpx.Response(200, content=FAKE_JPEG, headers=headers)

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    assert client.get_snapshot("cam1", ts_ms=1609459200000) == FAKE_JPEG
    client.close()


def test_integration_api_never_sends_legacy_session_cookie():
    """Verified on Protect 7.1.87: the console accepts the legacy session
    cookie on integration endpoints even when X-API-Key is wrong, so a shared
    cookie jar would make API-key verification silently pass."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(
                200,
                headers={"x-csrf-token": "c", "set-cookie": "TOKEN=session1; Path=/"},
                json={},
            )
        if "/integration/v1/" in request.url.path:
            assert "cookie" not in {k.lower() for k in request.headers}, (
                "integration request must not carry the legacy session cookie"
            )
            if request.headers.get("x-api-key") != "good-key":
                return httpx.Response(401, json={"error": "Unauthorized"})
            return httpx.Response(200, json={"applicationVersion": "7.1.87"})
        return httpx.Response(200, json={"cameras": []})

    good = ProtectClient("u.local", "u", "p", api_key="good-key",
                         transport=httpx.MockTransport(handler))
    good.login()
    assert good.get_integration_info() == {"applicationVersion": "7.1.87"}
    good.close()

    bad = ProtectClient("u.local", "u", "p", api_key="wrong-key",
                        transport=httpx.MockTransport(handler))
    bad.login()  # session cookie now present in the legacy client
    with pytest.raises(ProtectAuthError):
        bad.get_integration_info()
    bad.close()
