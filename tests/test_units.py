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

from app.deeplink import (
    DEFAULT_TEMPLATE,
    build_deep_link,
    validate_deep_link_template,
)
from app.main import _parse_poll_interval, create_app
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


def test_credential_cipher_key_creation_without_fchmod(tmp_path, monkeypatch):
    monkeypatch.setattr("app.security._fchmod", None)

    cipher = CredentialCipher(tmp_path)

    token = cipher.encrypt("windows-compatible-secret")
    assert cipher.decrypt(token) == "windows-compatible-secret"
    assert (tmp_path / KEY_FILENAME).is_file()


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

@pytest.mark.parametrize(
    "template",
    [
        DEFAULT_TEMPLATE,
        "https://{host}/protect/timeline/{camera_id}?at={ts_ms}",
        "  https://{host}/protect/{camera_id}#timestamp={ts_ms}  ",
    ],
)
def test_deep_link_template_validation_accepts_safe_urls(template):
    assert validate_deep_link_template(template) == template.strip()

def test_deep_link_template_validation_treats_blank_as_default_override():
    assert validate_deep_link_template("  ") == ""

@pytest.mark.parametrize(
    "template",
    [
        "http://{host}/protect/{camera_id}?at={ts_ms}",
        "javascript://{host}/{camera_id}?at={ts_ms}",
        "https://evil.example/{host}/{camera_id}?at={ts_ms}",
        "https://{host}@evil.example/{camera_id}?at={ts_ms}",
        "https://{host}:443/{camera_id}?at={ts_ms}",
        "https://{host}/protect/{camera_id}",
        "https://{host}/protect?at={ts_ms}",
        "https://{host}/protect/{camera_id}?at={ts_ms}&extra={unknown}",
        "https://{host}/protect/{{camera_id}}?at={ts_ms}",
        "https://{host}/protect/\n{camera_id}?at={ts_ms}",
        "https://{host}\\evil.example/{camera_id}?at={ts_ms}",
    ],
)
def test_deep_link_template_validation_rejects_unsafe_urls(template):
    with pytest.raises(ValueError):
        validate_deep_link_template(template)

def test_deep_link_build_rejects_unsafe_legacy_template():
    with pytest.raises(ValueError):
        build_deep_link(
            "u.local",
            "cam1",
            5,
            template="https://evil.example/{host}/{camera_id}?at={ts_ms}",
        )

def test_deep_link_rejects_bad_values():
    with pytest.raises(ValueError):
        build_deep_link("evil.com/path", "cam1", 5)
    with pytest.raises(ValueError):
        build_deep_link("ok.local", "../cam", 5)


# -- sync helpers -------------------------------------------------------------------

@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_app_rejects_unsafe_poll_interval_before_initialization(
    tmp_path, monkeypatch, value
):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("SPI_POLL_INTERVAL", value)
    with pytest.raises(
        ValueError,
        match="SPI_POLL_INTERVAL must be a finite number of at least 1 second",
    ):
        create_app(data_dir=data_dir, enable_poller=True)
    assert not data_dir.exists()


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", 1.0), ("1.5", 1.5), ("60", 60.0)],
)
def test_poll_interval_accepts_finite_values_at_least_one_second(value, expected):
    assert _parse_poll_interval(value) == expected


def test_parse_ts_ms_known_value():
    assert parse_ts_ms("2021-01-01T00:00:00Z") == 1609459200000
    assert parse_ts_ms("2021-01-01T00:00:00.500Z") == 1609459200500
    assert parse_ts_ms("2020-12-31T16:00:00-08:00") == 1609459200000


def test_parse_ts_ms_rejects_timezone_less_value():
    with pytest.raises(ValueError, match="timezone offset"):
        parse_ts_ms("2021-01-01T00:00:00")

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

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

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
        store.advance_square_poll_watermark(
            "LOC1", parse_ts_ms("2026-07-15T12:00:00Z")
        )
        store.advance_square_poll_watermark(
            "LOC2", parse_ts_ms("2026-07-10T08:00:00Z")
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


def test_webhook_before_first_poll_keeps_full_backfill(tmp_path, monkeypatch):
    poll_boundary = "2026-07-17T12:00:00Z"
    poll_boundary_ms = parse_ts_ms(poll_boundary)
    monkeypatch.setattr("app.sync._current_time_ms", lambda: poll_boundary_ms)

    def payment(payment_id: str, timestamp: str) -> dict:
        return {
            "id": payment_id,
            "created_at": timestamp,
            "updated_at": timestamp,
            "amount_money": {"amount": 100, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": "LOC1",
        }

    live_webhook_payment = payment("PAY_LIVE", poll_boundary)
    backfill_payment = payment("PAY_BACKFILL", "2026-07-16T13:00:00Z")

    class Square:
        def __init__(self):
            self.begin_times = []

        def list_locations(self):
            return [{"id": "LOC1"}]

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

        def list_payments(self, **params):
            self.begin_times.append(params["updated_at_begin_time"])
            return [backfill_payment]

    store = Store(tmp_path / "data")
    square = Square()
    try:
        # This is the webhook path: it stores a recent row without completing
        # any Square reconciliation window.
        ingest_payment(store, live_webhook_payment, None)
        assert store.latest_transaction_updated_ts("LOC1") == poll_boundary_ms
        assert store.get_square_poll_watermark("LOC1") is None

        assert sync_payments(store, square, None) == 1
        assert square.begin_times == ["2026-07-16T12:00:00Z"]
        assert store.get_transaction("PAY_BACKFILL") is not None
        assert store.get_square_poll_watermark("LOC1") == poll_boundary_ms
    finally:
        store.close()


def test_quiet_location_watermark_survives_restart(tmp_path, monkeypatch):
    first_boundary_ms = parse_ts_ms("2026-07-17T12:00:00Z")
    second_boundary_ms = parse_ts_ms("2026-07-17T12:10:00Z")
    poll_times = iter([first_boundary_ms, second_boundary_ms])
    monkeypatch.setattr("app.sync._current_time_ms", lambda: next(poll_times))

    class EmptySquare:
        def __init__(self):
            self.begin_times = []

        def list_locations(self):
            return [{"id": "LOC1"}]

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

        def list_payments(self, **params):
            self.begin_times.append(params["updated_at_begin_time"])
            return []

    data_dir = tmp_path / "data"
    square = EmptySquare()
    first_store = Store(data_dir)
    try:
        assert sync_payments(first_store, square, None) == 0
        assert first_store.get_square_poll_watermark("LOC1") == first_boundary_ms
    finally:
        first_store.close()

    restarted_store = Store(data_dir)
    try:
        assert sync_payments(restarted_store, square, None) == 0
        assert restarted_store.get_square_poll_watermark("LOC1") == second_boundary_ms
    finally:
        restarted_store.close()

    assert square.begin_times == [
        "2026-07-16T12:00:00Z",
        "2026-07-17T11:55:00Z",
    ]


def test_later_page_failure_does_not_advance_poll_watermark(
    tmp_path, monkeypatch
):
    original_watermark = parse_ts_ms("2026-07-17T10:00:00Z")
    failed_boundary = parse_ts_ms("2026-07-17T12:00:00Z")
    successful_boundary = parse_ts_ms("2026-07-17T12:10:00Z")
    poll_times = iter([failed_boundary, successful_boundary])
    monkeypatch.setattr("app.sync._current_time_ms", lambda: next(poll_times))

    def payment(payment_id: str, timestamp: str) -> dict:
        return {
            "id": payment_id,
            "created_at": timestamp,
            "updated_at": timestamp,
            "amount_money": {"amount": 100, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": "LOC1",
        }

    first_page_payment = payment("PAY_PAGE_1", "2026-07-17T10:30:00Z")
    second_page_payment = payment("PAY_PAGE_2", "2026-07-17T11:00:00Z")
    state = {"fail_second_page": True}
    begin_times = []
    payment_cursors = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/locations":
            return httpx.Response(200, json={"locations": [{"id": "LOC1"}]})
        cursor = request.url.params.get("cursor")
        payment_cursors.append(cursor)
        if cursor is None:
            begin_times.append(request.url.params["updated_at_begin_time"])
            return httpx.Response(
                200,
                json={"payments": [first_page_payment], "cursor": "next1"},
            )
        if state["fail_second_page"]:
            return httpx.Response(
                503,
                json={"errors": [{"code": "SERVICE_UNAVAILABLE"}]},
            )
        return httpx.Response(200, json={"payments": [second_page_payment]})

    store = Store(tmp_path / "data")
    store.advance_square_poll_watermark("LOC1", original_watermark)
    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(SquareError, match="HTTP 503"):
            sync_payments(store, client, None)
        assert store.get_square_poll_watermark("LOC1") == original_watermark

        state["fail_second_page"] = False
        sync_payments(store, client, None)
        assert store.get_transaction("PAY_PAGE_1") is not None
        assert store.get_transaction("PAY_PAGE_2") is not None
        assert store.get_square_poll_watermark("LOC1") == successful_boundary
    finally:
        client.close()
        store.close()

    assert begin_times == ["2026-07-17T09:55:00Z"] * 2
    assert payment_cursors == [None, "next1", None, "next1"]


def test_square_poll_watermark_never_moves_backward(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.advance_square_poll_watermark("LOC1", 2000)
        store.advance_square_poll_watermark("LOC1", 1000)
        assert store.get_square_poll_watermark("LOC1") == 2000
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


def test_protect_cameras_with_console_identity_uses_one_bootstrap_request():
    calls = {"bootstrap": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        calls["bootstrap"] += 1
        return httpx.Response(
            200,
            json={
                "cameras": [{"id": "cam1", "name": "Counter"}],
                "nvr": {"id": " nvr-console-1 ", "mac": "00:11:22:33:44:55"},
            },
        )

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    cameras, console_identity = client.get_cameras_with_console_identity()
    client.close()

    assert cameras == [{"id": "cam1", "name": "Counter", "state": ""}]
    assert console_identity == "nvr-console-1"
    assert calls["bootstrap"] == 1


@pytest.mark.parametrize(
    ("nvr", "expected_identity"),
    [
        ({"mac": "00:11:22:33:44:55"}, "00:11:22:33:44:55"),
        ({"id": "", "mac": "fallback-mac"}, "fallback-mac"),
        ({"id": 123, "mac": "fallback-mac"}, "fallback-mac"),
        ({"id": "x" * 257, "mac": "fallback-mac"}, "fallback-mac"),
        ({"id": "bad\nvalue", "mac": "fallback-mac"}, "fallback-mac"),
        (None, None),
        ([], None),
        ({"id": 123, "mac": {}}, None),
    ],
)
def test_protect_console_identity_is_optional_and_conservative(
    nvr, expected_identity
):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        return httpx.Response(200, json={"cameras": [], "nvr": nvr})

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    cameras, console_identity = client.get_cameras_with_console_identity()
    client.close()

    assert cameras == []
    assert console_identity == expected_identity

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


def test_protect_camera_html_response_is_normalized():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        return httpx.Response(200, content=b"<html>private console body</html>")

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    with pytest.raises(ProtectError) as exc_info:
        client.get_cameras()
    assert str(exc_info.value) == "UniFi Protect camera response was not JSON"
    assert "private console body" not in str(exc_info.value)
    client.close()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"cameras": {}},
        {"cameras": ["private camera item"]},
        {"cameras": [{"id": {"private": "camera id"}}]},
        {"cameras": [{"id": "../private-camera"}]},
        {"cameras": [{"id": "cam1", "name": ["private camera name"]}]},
        {"cameras": [{"id": "cam1", "marketName": {}}]},
        {"cameras": [{"id": "cam1", "state": []}]},
    ],
)
def test_protect_camera_response_shapes_are_normalized(payload):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        return httpx.Response(200, json=payload)

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    with pytest.raises(ProtectError) as exc_info:
        client.get_cameras()
    assert str(exc_info.value) == "UniFi Protect camera response was invalid"
    assert "private camera item" not in str(exc_info.value)
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


def test_pending_sale_completed_after_activation_remains_alarm_eligible(tmp_path):
    store = Store(tmp_path / "data")
    try:
        pending = _transaction("PAY_TRANSITION", "PENDING") | {
            "ts_ms": 1000,
            "updated_ts_ms": 1000,
        }
        store.upsert_transaction(pending)
        store.update_settings({ALARM_ENABLED_AFTER_SETTING: ("1500", False)})

        completed = _transaction("PAY_TRANSITION") | {
            "ts_ms": 1000,
            "updated_ts_ms": 2000,
        }
        store.upsert_transaction(completed)
        saved = store.get_transaction("PAY_TRANSITION")

        assert saved["status"] == "COMPLETED"
        assert saved["updated_ts_ms"] == 2000
        assert saved["alarm_state"] == "idle"
        assert store.claim_alarm_trigger("PAY_TRANSITION") is not None
    finally:
        store.close()


def test_first_seen_historical_completion_uses_sale_time_for_suppression(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.update_settings({ALARM_ENABLED_AFTER_SETTING: ("1500", False)})
        historical = _transaction("PAY_HISTORICAL") | {
            "ts_ms": 1000,
            # A recent Square version does not prove that an unseen sale
            # completed after alarms were enabled.
            "updated_ts_ms": 2000,
        }
        store.upsert_transaction(historical)

        saved = store.get_transaction("PAY_HISTORICAL")
        assert saved["alarm_state"] == "sent"
        assert store.claim_alarm_trigger("PAY_HISTORICAL") is None
    finally:
        store.close()


def test_stale_completion_version_cannot_suppress_live_alarm(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.update_settings({ALARM_ENABLED_AFTER_SETTING: ("1500", False)})
        live = _transaction("PAY_LIVE") | {
            "ts_ms": 2000,
            "updated_ts_ms": 2000,
        }
        stale = _transaction("PAY_LIVE") | {
            "ts_ms": 1000,
            "updated_ts_ms": 1000,
        }

        store.upsert_transaction(live)
        assert store.get_transaction("PAY_LIVE")["alarm_state"] == "idle"

        store.upsert_transaction(stale)
        saved = store.get_transaction("PAY_LIVE")
        assert saved["ts_ms"] == 2000
        assert saved["updated_ts_ms"] == 2000
        assert saved["alarm_state"] == "idle"
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

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("amount_money", []),
        ("total_money", "invalid"),
        ("card_details", []),
        ("card_details", {"card": []}),
        ("device_details", []),
        ("offline_payment_details", []),
        ("amount_money", {"amount": "500", "currency": "USD"}),
        ("amount_money", {"amount": 500, "currency": []}),
    ],
)
def test_payment_from_api_rejects_malformed_nested_fields(field, value):
    payment = {
        "id": "PAY_BAD_NESTED",
        "created_at": "2026-07-16T16:30:00Z",
        "amount_money": {"amount": 500, "currency": "USD"},
        field: value,
    }

    with pytest.raises(ValueError, match="Payment"):
        payment_from_api(payment)

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
    assert "raw" not in normalized
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

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

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

@pytest.mark.parametrize(
    "client_created_at",
    ["not-a-timestamp", "2026-07-16T08:30:00"],
)
def test_sync_skips_nonempty_malformed_offline_timestamp(
    tmp_path, client_created_at
):
    payment = {
        "id": "PAY_BAD_TIME",
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

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

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


def test_square_payment_page_iterator_honors_total_limit():
    pages = {
        None: {
            "payments": [{"id": "P0"}, {"id": "P1"}, {"id": "P2"}],
            "cursor": "next1",
        },
        "next1": {
            # Deliberately over-return to verify the client still enforces the
            # caller's total limit rather than trusting the provider page size.
            "payments": [{"id": "P3"}, {"id": "P4"}],
            "cursor": "unused",
        },
    }
    request_limits = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_limits.append(int(request.url.params["limit"]))
        return httpx.Response(200, json=pages[request.url.params.get("cursor")])

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    try:
        payment_pages = list(client.iter_payment_pages(limit=4))
    finally:
        client.close()

    assert [[payment["id"] for payment in page] for page in payment_pages] == [
        ["P0", "P1", "P2"],
        ["P3"],
    ]
    assert request_limits == [4, 1]


def test_square_payment_page_iterator_rejects_repeated_cursor():
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            json={"payments": [{"id": f"P{requests}"}], "cursor": "loop"},
        )

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    pages = client.iter_payment_pages()
    try:
        assert [payment["id"] for payment in next(pages)] == ["P1"]
        with pytest.raises(SquareError, match="repeated pagination cursor"):
            next(pages)
    finally:
        client.close()

    assert requests == 2


def test_sync_persists_page_before_later_square_failure(tmp_path):
    first_payment = {
        "id": "P_FIRST_PAGE",
        "created_at": "2026-07-17T20:00:00Z",
        "updated_at": "2026-07-17T20:00:00Z",
        "amount_money": {"amount": 100, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
    }
    payment_cursors = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/locations":
            return httpx.Response(200, json={"locations": [{"id": "LOC1"}]})
        cursor = request.url.params.get("cursor")
        payment_cursors.append(cursor)
        if cursor is None:
            return httpx.Response(
                200,
                json={"payments": [first_payment], "cursor": "next1"},
            )
        return httpx.Response(
            503,
            json={"errors": [{"code": "SERVICE_UNAVAILABLE"}]},
        )

    store = Store(tmp_path / "data")
    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(SquareError, match="HTTP 503"):
            sync_payments(store, client, None)
        assert store.get_transaction("P_FIRST_PAGE") is not None
        assert payment_cursors == [None, "next1"]
    finally:
        client.close()
        store.close()


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


def test_square_retries_rate_limit_until_success(monkeypatch):
    requests = 0
    delays = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests < 3:
            return httpx.Response(429, headers={"Retry-After": "0.25"})
        return httpx.Response(200, json={"locations": []})

    monkeypatch.setattr("app.square_client.time.sleep", delays.append)
    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    try:
        assert client.list_locations() == []
    finally:
        client.close()

    assert requests == 3
    assert delays == [0.25, 0.25]


def test_square_rate_limit_retries_are_bounded_and_jittered(monkeypatch):
    requests = 0
    delays = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(429)

    monkeypatch.setattr("app.square_client.time.sleep", delays.append)
    monkeypatch.setattr("app.square_client.random.uniform", lambda _low, high: high)
    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(SquareError, match=r"HTTP 429"):
            client.list_locations()
    finally:
        client.close()

    assert requests == 4
    assert delays == [0.625, 1.25, 2.5]


def test_square_rate_limit_caps_retry_after(monkeypatch):
    delays = []
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return httpx.Response(429, headers={"Retry-After": "3600"})
        return httpx.Response(200, json={"locations": []})

    monkeypatch.setattr("app.square_client.time.sleep", delays.append)
    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    try:
        assert client.list_locations() == []
    finally:
        client.close()

    assert delays == [10.0]


def test_square_html_response_is_normalized():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>private Square body</html>")

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    with pytest.raises(SquareError) as exc_info:
        client.list_locations()
    assert str(exc_info.value) == "Square returned a non-JSON response"
    assert "private Square body" not in str(exc_info.value)
    client.close()


@pytest.mark.parametrize(
    ("operation", "payload"),
    [
        ("locations", []),
        ("locations", {"locations": {}}),
        ("locations", {"locations": ["private location item"]}),
        ("locations", {"locations": [{"id": ["private location id"]}]}),
        ("locations", {"locations": [{"id": "LOC1", "name": {}}]}),
        ("locations", {"locations": [{"id": "LOC1", "status": []}]}),
        ("payments", {"payments": {}}),
        ("payments", {"payments": ["private payment item"]}),
        ("payments", {"payments": [], "cursor": []}),
    ],
)
def test_square_response_shapes_are_normalized(operation, payload):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    with pytest.raises(SquareError) as exc_info:
        if operation == "locations":
            client.list_locations()
        else:
            client.list_payments(limit=1)
    assert str(exc_info.value) == "Square returned an invalid response"
    assert "private location item" not in str(exc_info.value)
    assert "private payment item" not in str(exc_info.value)
    client.close()


@pytest.mark.parametrize("merchant_id", [{"private": "id"}, ["id"], 123, None])
def test_square_rejects_malformed_merchant_id(merchant_id):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"merchant": {"id": merchant_id}})

    client = SquareClient("tok", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(
            SquareError,
            match="Square did not return the access token's merchant id",
        ):
            client.merchant_id()
    finally:
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

def test_historical_snapshot_fails_closed_on_old_firmware():
    """Never attach a live frame when old firmware ignores snapshot?ts."""
    requested_paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        requested_paths.append(request.url.path)
        if request.url.path.endswith("/recording-snapshot"):
            return httpx.Response(
                404, content=b"<!DOCTYPE html>", headers={"content-type": "text/html"}
            )
        return httpx.Response(200, content=FAKE_JPEG)

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    with pytest.raises(ProtectError, match="recording-snapshot support"):
        client.get_snapshot("cam1", ts_ms=1609459200000)
    assert requested_paths == ["/proxy/protect/api/cameras/cam1/recording-snapshot"]
    client.close()


def test_live_snapshot_still_uses_snapshot_endpoint():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        requests.append((request.url.path, dict(request.url.params)))
        return httpx.Response(200, content=FAKE_JPEG)

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    assert client.get_snapshot("cam1") == FAKE_JPEG
    assert requests == [("/proxy/protect/api/cameras/cam1/snapshot", {"w": "640"})]
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


def test_snapshot_accepts_marker_bytes_inside_metadata_segment():
    metadata = b"Exif\x00\x00metadata with marker-like \xff\xd9 bytes"
    app_segment = b"\xff\xe1" + (len(metadata) + 2).to_bytes(2, "big") + metadata
    image = FAKE_JPEG[:2] + app_segment + FAKE_JPEG[2:]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        return httpx.Response(200, content=image, headers={"content-type": "image/jpeg"})

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    assert client.get_snapshot("cam1") == image
    client.close()


def test_snapshot_does_not_accept_markers_hidden_inside_metadata():
    metadata = b"not a frame \xff\xc0 fake header \xff\xda fake scan"
    app_segment = b"\xff\xe1" + (len(metadata) + 2).to_bytes(2, "big") + metadata
    image = b"\xff\xd8" + app_segment + b"\xff\xd9"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        return httpx.Response(200, content=image, headers={"content-type": "image/jpeg"})

    client = ProtectClient("u.local", "u", "p", transport=httpx.MockTransport(handler))
    with pytest.raises(ProtectError, match="invalid JPEG"):
        client.get_snapshot("cam1")
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
