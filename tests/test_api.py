"""End-to-end API tests against mocked Square and UniFi Protect backends."""

import base64
import concurrent.futures
from contextlib import contextmanager
import hashlib
import hmac
import json
import sqlite3
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.protect_client import ProtectClient
from app.square_client import SquareClient, SquarePermissionError
from app.store import Store
from app.sync import ingest_payment, retry_missing_thumbnails

from .conftest import (
    ADMIN_PASSWORD,
    PROTECT_ALARM_CALLS,
    PROTECT_ALARM_RESPONSES,
    PROTECT_ALARM_TRIGGER_ID,
    PROTECT_API_KEY,
    PROTECT_META_KEYS,
    PROTECT_PASS,
    PROTECT_USER,
    SQUARE_TOKEN,
    SQUARE_MERCHANT_ID,
    WEBHOOK_KEY,
    WEBHOOK_URL,
    protect_handler,
    square_handler,
)

CAM1 = "cam1aaaaaaaaaaaaaaaaaaaaa"
CAM2 = "cam2bbbbbbbbbbbbbbbbbbbbb"


def _refresh_camera_generation(client) -> None:
    response = client.get("/api/cameras")
    assert response.status_code == 200, response.text
    client.headers["X-Protect-Console-Generation"] = response.headers[
        "x-protect-console-generation"
    ]


def _protect_switch_token(client, host: str) -> str:
    response = client.post(
        "/api/settings/protect/console-switch-token",
        json={
            "host": host,
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
        },
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "private, no-store"
    token = response.json()["token"]
    assert token
    return token


def _mutable_identity_protect_handler(identity: dict[str, str | None]):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/proxy/protect/api/bootstrap":
            return protect_handler(request)
        payload = {
            "cameras": [
                {"id": CAM1, "name": "Front Counter", "state": "CONNECTED"},
                {"id": CAM2, "name": "Back Door", "state": "CONNECTED"},
            ]
        }
        if identity["value"] is not None:
            payload["nvr"] = {"id": identity["value"]}
        return httpx.Response(200, json=payload)

    return handler


# -- setup / login flow ------------------------------------------------------------

def test_status_reports_setup_state(client):
    status = client.get("/api/status").json()
    assert status == {
        "setup_complete": False,
        "protect_configured": False,
        "square_configured": False,
        "cameras_mapped": False,
    }

def test_setup_then_login(client):
    assert client.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
    assert client.get("/api/status").json()["setup_complete"] is True
    resp = client.post("/api/login", json={"password": ADMIN_PASSWORD})
    assert resp.status_code == 200
    assert client.get("/api/camera-mapping").status_code == 200

def test_setup_rejects_short_password(client):
    assert client.post("/api/setup", json={"password": "short"}).status_code == 422

def test_concurrent_setup_has_single_winner(client):
    passwords = ("first-admin-password", "second-admin-password")

    def setup(password: str):
        return password, client.post("/api/setup", json={"password": password})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(setup, passwords))

    assert sorted(response.status_code for _, response in results) == [200, 409]
    winner = next(password for password, response in results if response.status_code == 200)
    loser = next(password for password, response in results if response.status_code == 409)
    assert client.post("/api/login", json={"password": winner}).status_code == 200
    assert client.post("/api/login", json={"password": loser}).status_code == 401

def test_login_wrong_password(client):
    client.post("/api/setup", json={"password": ADMIN_PASSWORD})
    assert client.post("/api/login", json={"password": "wrong-password"}).status_code == 401

def test_logout_invalidates_session(authed):
    assert authed.get("/api/camera-mapping").status_code == 200
    assert authed.post("/api/logout").status_code == 200
    assert authed.get("/api/camera-mapping").status_code == 401


# -- settings ------------------------------------------------------------------------

def test_protect_settings_validates_credentials(authed):
    resp = authed.put(
        "/api/settings/protect",
        json={"host": "192.168.1.1", "username": PROTECT_USER, "password": "bad-pass"},
    )
    assert resp.status_code == 401
    assert authed.get("/api/status").json()["protect_configured"] is False

def test_protect_settings_success(authed):
    resp = authed.put(
        "/api/settings/protect",
        json={"host": "192.168.1.1", "username": PROTECT_USER, "password": PROTECT_PASS},
    )
    assert resp.status_code == 200
    assert resp.json()["cameras"] == 2
    assert resp.json()["console_switched"] is False
    assert authed.get("/api/status").json()["protect_configured"] is True
    cameras = authed.get("/api/cameras")
    assert cameras.headers["cache-control"] == "private, no-store"
    assert authed.app.state.store.get_setting("protect.console_id") == "nvr-console-1"

def test_protect_host_change_requires_confirmation_without_mutating_state(configured):
    _enable_alarm(configured)
    assert configured.post("/api/sync").status_code == 200
    store = configured.app.state.store
    before_mappings = store.get_camera_mappings()
    before_transactions = configured.get("/api/transactions").json()
    before_files = sorted(path.name for path in store.thumbnail_dir.iterdir())

    resp = configured.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.2",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
        },
    )

    assert resp.status_code == 409
    assert "Confirm the console switch" in resp.json()["detail"]
    assert store.get_setting("protect.host") == "192.168.1.1"
    assert store.get_setting("protect.api_key") == PROTECT_API_KEY
    assert store.get_camera_mappings() == before_mappings
    assert configured.get("/api/transactions").json() == before_transactions
    assert sorted(path.name for path in store.thumbnail_dir.iterdir()) == before_files

def test_same_protect_host_credential_refresh_retains_evidence(configured):
    assert configured.post("/api/sync").status_code == 200
    store = configured.app.state.store
    before_mappings = store.get_camera_mappings()
    before_transactions = configured.get("/api/transactions").json()
    before_files = sorted(path.name for path in store.thumbnail_dir.iterdir())
    before_generation = store.get_setting("protect.console_generation")

    resp = configured.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
        },
    )

    assert resp.status_code == 200
    assert resp.json()["console_switched"] is False
    assert store.get_camera_mappings() == before_mappings
    assert store.get_setting("protect.console_generation") == before_generation
    assert configured.get("/api/transactions").json() == before_transactions
    assert sorted(path.name for path in store.thumbnail_dir.iterdir()) == before_files


def test_stale_console_switch_token_cannot_confirm_a_later_switch(configured):
    stale_token = _protect_switch_token(configured, "192.168.1.2")
    fresh_token = _protect_switch_token(configured, "192.168.1.3")

    switched = configured.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.3",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "console_switch_token": fresh_token,
        },
    )
    assert switched.status_code == 200, switched.text

    stale_retry = configured.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.2",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "console_switch_token": stale_token,
        },
    )

    assert stale_retry.status_code == 409
    assert configured.app.state.store.get_setting("protect.host") == "192.168.1.3"


def test_console_switch_token_rejects_source_change_during_target_probe(tmp_path):
    target_probe_started = threading.Event()
    release_target_probe = threading.Event()

    def blocking_target_probe(request: httpx.Request) -> httpx.Response:
        if (
            request.url.host == "target.local"
            and request.url.path == "/proxy/protect/api/bootstrap"
        ):
            target_probe_started.set()
            if not release_target_probe.wait(timeout=10):
                raise httpx.ReadTimeout("target probe timed out", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_target_probe),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as client:
            assert client.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert client.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert client.put(
                "/api/settings/protect",
                json={
                    "host": "source.local",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            ).status_code == 200
            middle_token = _protect_switch_token(client, "middle.local")

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                target_future = executor.submit(
                    client.post,
                    "/api/settings/protect/console-switch-token",
                    json={
                        "host": "target.local",
                        "username": PROTECT_USER,
                        "password": PROTECT_PASS,
                    },
                )
                assert target_probe_started.wait(timeout=3)
                switched = client.put(
                    "/api/settings/protect",
                    json={
                        "host": "middle.local",
                        "username": PROTECT_USER,
                        "password": PROTECT_PASS,
                        "console_switch_token": middle_token,
                    },
                )
                assert switched.status_code == 200, switched.text
                release_target_probe.set()
                stale_confirmation = target_future.result(timeout=5)

            assert stale_confirmation.status_code == 409
            assert stale_confirmation.headers["cache-control"] == "private, no-store"
            assert app.state.store.get_setting("protect.host") == "middle.local"
    finally:
        release_target_probe.set()
        app.state.store.close()


def test_same_host_console_identity_change_requires_target_bound_consent(tmp_path):
    identity = {"value": "nvr-a"}
    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(
            _mutable_identity_protect_handler(identity)
        ),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as client:
            assert client.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert client.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            settings = {
                "host": "protect.local",
                "username": PROTECT_USER,
                "password": PROTECT_PASS,
            }
            assert client.put("/api/settings/protect", json=settings).status_code == 200
            assert client.put(
                "/api/settings/square",
                json={"access_token": SQUARE_TOKEN, "environment": "production"},
            ).status_code == 200
            app.state.store.set_camera_mapping("LOC1", CAM1, "Old camera")

            identity["value"] = "nvr-b"
            assert client.get("/api/cameras").status_code == 409
            assert client.post("/api/sync").status_code == 502
            assert app.state.store.list_transactions() == []
            refused = client.put("/api/settings/protect", json=settings)
            assert refused.status_code == 409
            assert "identity changed" in refused.json()["detail"]
            assert app.state.store.get_camera_mappings()

            token_for_b = _protect_switch_token(client, "protect.local")
            identity["value"] = "nvr-c"
            stale_target = client.put(
                "/api/settings/protect",
                json={**settings, "console_switch_token": token_for_b},
            )
            assert stale_target.status_code == 409
            assert app.state.store.get_setting("protect.console_id") == "nvr-a"

            token_for_c = _protect_switch_token(client, "protect.local")
            switched = client.put(
                "/api/settings/protect",
                json={**settings, "console_switch_token": token_for_c},
            )
            assert switched.status_code == 200, switched.text
            assert switched.json()["console_switched"] is True
            assert app.state.store.get_setting("protect.console_id") == "nvr-c"
            assert app.state.store.get_camera_mappings() == []
    finally:
        app.state.store.close()


def test_missing_previously_bound_console_identity_requires_confirmed_reset(tmp_path):
    identity = {"value": "nvr-a"}
    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(
            _mutable_identity_protect_handler(identity)
        ),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as client:
            assert client.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert client.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            settings = {
                "host": "protect.local",
                "username": PROTECT_USER,
                "password": PROTECT_PASS,
            }
            assert client.put("/api/settings/protect", json=settings).status_code == 200
            app.state.store.set_camera_mapping("LOC1", CAM1, "Old camera")

            identity["value"] = None
            refused = client.put("/api/settings/protect", json=settings)
            assert refused.status_code == 409
            assert app.state.store.get_setting("protect.console_id") == "nvr-a"
            assert app.state.store.get_camera_mappings()

            token = _protect_switch_token(client, "protect.local")
            switched = client.put(
                "/api/settings/protect",
                json={**settings, "console_switch_token": token},
            )
            assert switched.status_code == 200, switched.text
            assert switched.json()["console_switched"] is True
            assert app.state.store.get_setting("protect.console_id") is None
            assert app.state.store.get_camera_mappings() == []
    finally:
        app.state.store.close()

def test_confirmed_protect_console_switch_clears_only_console_scoped_state(configured):
    _enable_alarm(configured)
    assert configured.post("/api/sync").status_code == 200
    store = configured.app.state.store
    custom_deep_link = (
        "https://{host}/protect/timeline?camera={camera_id}&at={ts_ms}"
    )
    store.set_setting("deep_link_template", custom_deep_link)
    retained_before = store.get_transaction("PAY_001")
    old_generation = store.get_setting("protect.console_generation")
    store.upsert_transaction(
        {
            "id": "PAY_PENDING_EVIDENCE",
            "created_at": "2026-07-16T16:00:00.000Z",
            "ts_ms": 1784217600000,
            "amount": 321,
            "currency": "USD",
            "status": "COMPLETED",
            "location_id": "LOC1",
            "camera_id": CAM1,
        }
    )
    assert store.claim_thumbnail_retries(1, 60, now=0)
    assert any(store.thumbnail_dir.iterdir())

    resp = configured.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.2",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "console_switch_token": _protect_switch_token(
                configured, "192.168.1.2"
            ),
        },
    )

    assert resp.status_code == 200
    assert resp.json()["console_switched"] is True
    assert resp.json()["alarm_configured"] is False
    assert store.get_setting("protect.host") == "192.168.1.2"
    assert store.get_setting("protect.console_generation") != old_generation
    assert store.get_setting("protect.api_key") is None
    assert store.get_setting("protect.alarm_trigger_id") is None
    assert store.get_setting("protect.alarm_enabled_after_ms") is None
    assert store.get_setting("deep_link_template") == custom_deep_link
    assert store.get_camera_mappings() == []
    assert store._db.execute(
        "SELECT COUNT(*) FROM protect_evidence_retired"
    ).fetchone()[0] == 3
    assert store._db.execute("SELECT COUNT(*) FROM thumbnail_retries").fetchone()[0] == 0
    assert list(store.thumbnail_dir.iterdir()) == []

    retained_after = store.get_transaction("PAY_001")
    for field in (
        "id",
        "created_at",
        "ts_ms",
        "amount",
        "currency",
        "status",
        "location_id",
        "card_last4",
        "receipt_url",
    ):
        assert retained_after[field] == retained_before[field]
    for txn in configured.get("/api/transactions").json():
        assert txn["camera_id"] is None
        assert txn["thumbnail_url"] is None
        assert txn["deep_link"] is None

    stale_save = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "camera_id": CAM1,
                    "camera_name": "Old Console Camera",
                }
            ]
        },
    )
    assert stale_save.status_code == 409
    assert store.get_camera_mappings() == []

    # Re-selecting cameras must not reinterpret retained transactions as
    # evidence from the new console.
    _refresh_camera_generation(configured)
    assert configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "camera_id": CAM2,
                    "camera_name": "New Console Camera",
                }
            ]
        },
    ).status_code == 200
    assert store._db.execute("SELECT COUNT(*) FROM thumbnail_retries").fetchone()[0] == 0
    assert all(
        txn["camera_id"] is None
        for txn in configured.get("/api/transactions").json()
    )

    ingest_payment(
        store,
        {
            "id": "PAY_NEW_CONSOLE",
            "created_at": "2026-07-16T17:00:00.000Z",
            "amount_money": {"amount": 777, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": "LOC1",
        },
        protect=None,
    )
    new_txn = next(
        txn
        for txn in configured.get("/api/transactions").json()
        if txn["id"] == "PAY_NEW_CONSOLE"
    )
    assert new_txn["camera_id"] == CAM2
    assert new_txn["deep_link"] == (
        f"https://192.168.1.2/protect/timeline?camera={CAM2}&at={new_txn['ts_ms']}"
    )


def test_transaction_listing_cannot_mix_old_evidence_with_new_console_host(
    configured,
    monkeypatch,
):
    assert configured.post("/api/sync").status_code == 200
    store = configured.app.state.store
    token = _protect_switch_token(configured, "192.168.1.2")
    serialization_started = threading.Event()
    release_serialization = threading.Event()
    blocked_once = threading.Event()
    original_get_setting = store.get_setting

    def blocking_get_setting(key: str):
        value = original_get_setting(key)
        if key == "protect.host" and not blocked_once.is_set():
            blocked_once.set()
            serialization_started.set()
            assert release_serialization.wait(timeout=10)
        return value

    monkeypatch.setattr(store, "get_setting", blocking_get_setting)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        listing_future = executor.submit(configured.get, "/api/transactions")
        assert serialization_started.wait(timeout=3)
        switch_future = executor.submit(
            configured.put,
            "/api/settings/protect",
            json={
                "host": "192.168.1.2",
                "username": PROTECT_USER,
                "password": PROTECT_PASS,
                "console_switch_token": token,
            },
        )
        try:
            with pytest.raises(concurrent.futures.TimeoutError):
                switch_future.result(timeout=0.05)
            assert store.get_setting("protect.host") == "192.168.1.1"
        finally:
            release_serialization.set()
        old_listing = listing_future.result(timeout=5)
        switched = switch_future.result(timeout=5)

    assert old_listing.status_code == 200
    assert all(
        not txn["deep_link"] or "192.168.1.1" in txn["deep_link"]
        for txn in old_listing.json()
    )
    assert switched.status_code == 200, switched.text
    assert all(
        txn["camera_id"] is None
        and txn["thumbnail_url"] is None
        and txn["deep_link"] is None
        for txn in configured.get("/api/transactions").json()
    )


def test_camera_mapping_read_completes_before_console_switch(
    configured,
    monkeypatch,
):
    store = configured.app.state.store
    token = _protect_switch_token(configured, "192.168.1.2")
    mapping_read_started = threading.Event()
    release_mapping_read = threading.Event()
    original_get_mappings = store.get_camera_mappings

    def blocking_get_mappings():
        mappings = original_get_mappings()
        mapping_read_started.set()
        assert release_mapping_read.wait(timeout=10)
        return mappings

    monkeypatch.setattr(store, "get_camera_mappings", blocking_get_mappings)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        mapping_future = executor.submit(configured.get, "/api/camera-mapping")
        assert mapping_read_started.wait(timeout=3)
        switch_future = executor.submit(
            configured.put,
            "/api/settings/protect",
            json={
                "host": "192.168.1.2",
                "username": PROTECT_USER,
                "password": PROTECT_PASS,
                "console_switch_token": token,
            },
        )
        try:
            with pytest.raises(concurrent.futures.TimeoutError):
                switch_future.result(timeout=0.05)
        finally:
            release_mapping_read.set()
        old_mapping = mapping_future.result(timeout=5)
        switched = switch_future.result(timeout=5)

    assert old_mapping.status_code == 200
    assert old_mapping.json()[0]["camera_id"] == CAM1
    assert switched.status_code == 200, switched.text
    monkeypatch.setattr(store, "get_camera_mappings", original_get_mappings)
    assert configured.get("/api/camera-mapping").json() == []

def test_deep_link_settings_default_response_does_not_expose_secrets(configured):
    resp = configured.get("/api/settings/deep-link")
    assert resp.status_code == 200
    assert resp.json() == {
        "template": "",
        "default_template": (
            "https://{host}/protect/timelapse/{camera_id}?start={ts_ms}"
        ),
    }
    for secret in (SQUARE_TOKEN, PROTECT_PASS, PROTECT_API_KEY, WEBHOOK_KEY):
        assert secret not in resp.text

def test_deep_link_settings_custom_template_and_blank_restore(configured):
    template = "https://{host}/protect/timeline/{camera_id}?at={ts_ms}"
    saved = configured.put(
        "/api/settings/deep-link",
        json={"template": f"  {template}  "},
    )
    assert saved.status_code == 200
    assert saved.json()["template"] == template
    assert configured.app.state.store.get_setting("deep_link_template") == template

    configured.post("/api/sync")
    txn = configured.get("/api/transactions").json()[0]
    assert txn["deep_link"] == (
        f"https://192.168.1.1/protect/timeline/{CAM1}?at={txn['ts_ms']}"
    )

    restored = configured.put("/api/settings/deep-link", json={"template": ""})
    assert restored.status_code == 200
    assert restored.json()["template"] == ""
    assert configured.app.state.store.get_setting("deep_link_template") is None
    txn = configured.get("/api/transactions").json()[0]
    assert txn["deep_link"] == (
        f"https://192.168.1.1/protect/timelapse/{CAM1}?start={txn['ts_ms']}"
    )

def test_deep_link_settings_reject_invalid_without_replacing_saved_value(configured):
    template = "https://{host}/protect/timeline/{camera_id}?at={ts_ms}"
    assert configured.put(
        "/api/settings/deep-link", json={"template": template}
    ).status_code == 200

    resp = configured.put(
        "/api/settings/deep-link",
        json={
            "template": "https://evil.example/{host}/{camera_id}?at={ts_ms}",
        },
    )
    assert resp.status_code == 422
    assert configured.app.state.store.get_setting("deep_link_template") == template

def test_protect_alarm_settings_verify_and_encrypt_api_key(authed, tmp_path):
    bad = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": "wrong-api-key",
            "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
        },
    )
    assert bad.status_code == 401
    assert authed.app.state.store.get_setting("protect.api_key") is None

    good = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": PROTECT_API_KEY,
            "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
        },
    )
    assert good.status_code == 200
    assert good.json()["alarm_configured"] is True
    assert PROTECT_META_KEYS == ["wrong-api-key", PROTECT_API_KEY]
    assert authed.app.state.store.get_setting("protect.api_key") == PROTECT_API_KEY
    assert (
        authed.app.state.store.get_setting("protect.alarm_trigger_id")
        == PROTECT_ALARM_TRIGGER_ID
    )
    assert PROTECT_API_KEY.encode() not in (tmp_path / "data" / "spi.db").read_bytes()

    PROTECT_META_KEYS.clear()
    preserved = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
        },
    )
    assert preserved.status_code == 200
    assert preserved.json()["alarm_configured"] is True
    assert PROTECT_META_KEYS == [PROTECT_API_KEY]

def test_protect_alarm_settings_can_be_disabled(authed):
    _enable_alarm(authed)

    resp = authed.delete("/api/settings/protect/alarm")
    assert resp.status_code == 200
    assert resp.json()["alarm_configured"] is False
    assert authed.app.state.store.get_setting("protect.api_key") is None
    assert authed.app.state.store.get_setting("protect.alarm_trigger_id") is None

def test_protect_settings_reject_control_characters_in_alarm_trigger(authed):
    resp = authed.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": PROTECT_API_KEY,
            "alarm_trigger_id": "trigger\nall",
        },
    )
    assert resp.status_code == 422
    assert PROTECT_META_KEYS == []

def test_square_settings_validates_token(authed):
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": "bad-token", "environment": "production"},
    )
    assert resp.status_code == 401
    assert authed.get("/api/status").json()["square_configured"] is False

def test_square_settings_requires_payments_read_permission(authed, monkeypatch):
    def reject_payment_read(_self, begin_time=None, limit=100):
        raise SquarePermissionError("scope missing")

    monkeypatch.setattr(SquareClient, "list_payments", reject_payment_read)
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == (
        "Square access token must grant PAYMENTS_READ permission"
    )
    assert authed.get("/api/status").json()["square_configured"] is False

def test_square_settings_reports_profile_permission_separately(authed, monkeypatch):
    def reject_profile_read(_self):
        raise SquarePermissionError("scope missing")

    monkeypatch.setattr(SquareClient, "list_locations", reject_profile_read)
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == (
        "Square access token must grant MERCHANT_PROFILE_READ permission"
    )
    assert authed.get("/api/status").json()["square_configured"] is False

def test_square_settings_success(authed):
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert resp.status_code == 200
    assert resp.json()["locations"] == [
        {"id": "LOC1", "name": "Main Store", "status": "ACTIVE"}
    ]


def test_square_client_build_uses_one_settings_snapshot(authed, monkeypatch):
    resp = authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "sandbox"},
    )
    assert resp.status_code == 200
    store = authed.app.state.store
    original_get_setting = store.get_setting

    def switch_account_after_token_read(key):
        value = original_get_setting(key)
        if key == "square.access_token":
            store.update_settings(
                {
                    "square.access_token": ("replacement-token", True),
                    "square.environment": ("production", False),
                }
            )
        return value

    constructed = {}

    def capture_client(_self, access_token, environment="production", **_kwargs):
        constructed.update(token=access_token, environment=environment)

    monkeypatch.setattr(store, "get_setting", switch_account_after_token_read)
    monkeypatch.setattr(SquareClient, "__init__", capture_client)
    monkeypatch.setattr(SquareClient, "list_locations", lambda _self: [])
    monkeypatch.setattr(SquareClient, "close", lambda _self: None)

    assert authed.get("/api/locations").status_code == 200
    assert constructed == {"token": SQUARE_TOKEN, "environment": "sandbox"}


def test_square_settings_require_complete_webhook_pair(authed):
    resp = authed.put(
        "/api/settings/square",
        json={
            "access_token": SQUARE_TOKEN,
            "environment": "production",
            "webhook_signature_key": WEBHOOK_KEY,
        },
    )
    assert resp.status_code == 422
    assert authed.get("/api/status").json()["square_configured"] is False


def test_protect_settings_transport_error_returns_502(tmp_path):
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive upstream details", request=request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(unavailable),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
            resp = isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            )
        assert resp.status_code == 502
        assert resp.json()["detail"] == (
            "Could not reach UniFi Protect: Network error while contacting UniFi Protect"
        )
        assert "sensitive upstream details" not in resp.text
    finally:
        app.state.store.close()


def test_square_settings_transport_error_returns_502(tmp_path):
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive upstream details", request=request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(protect_handler),
        square_transport=httpx.MockTransport(unavailable),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
            resp = isolated.put(
                "/api/settings/square",
                json={"access_token": SQUARE_TOKEN, "environment": "production"},
            )
        assert resp.status_code == 502
        assert resp.json()["detail"] == (
            "Could not reach Square: Network error while contacting Square"
        )
        assert "sensitive upstream details" not in resp.text
    finally:
        app.state.store.close()


@pytest.mark.parametrize("malformed", ["html", "shape", "camera-id", "camera-name"])
def test_protect_settings_malformed_camera_response_returns_502(tmp_path, malformed):
    def malformed_protect(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        if malformed == "html":
            return httpx.Response(200, content=b"<html>private console body</html>")
        if malformed == "camera-id":
            return httpx.Response(
                200, json={"cameras": [{"id": {"private": "camera id"}}]}
            )
        if malformed == "camera-name":
            return httpx.Response(
                200, json={"cameras": [{"id": "cam1", "name": ["private name"]}]}
            )
        return httpx.Response(200, json={"cameras": ["private camera item"]})

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(malformed_protect),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            response = isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            )

        assert response.status_code == 502
        assert response.json()["detail"].startswith(
            "Could not reach UniFi Protect: UniFi Protect camera response"
        )
        assert "private console body" not in response.text
        assert "private camera item" not in response.text
        assert "private name" not in response.text
        assert "camera id" not in response.text
        assert app.state.store.get_setting("protect.host") is None
    finally:
        app.state.store.close()


@pytest.mark.parametrize(
    "malformed",
    ["html", "location-shape", "location-id", "merchant-id", "payment-shape"],
)
def test_square_settings_malformed_response_returns_502(tmp_path, malformed):
    def malformed_square(request: httpx.Request) -> httpx.Response:
        if malformed == "html":
            return httpx.Response(200, content=b"<html>private Square body</html>")
        if malformed == "location-shape":
            return httpx.Response(
                200, json={"locations": ["private location item"]}
            )
        if request.url.path == "/v2/locations":
            if malformed == "location-id":
                return httpx.Response(
                    200, json={"locations": [{"id": ["private location id"]}]}
                )
            return httpx.Response(200, json={"locations": [{"id": "LOC1"}]})
        if request.url.path == "/v2/merchants/me":
            if malformed == "merchant-id":
                return httpx.Response(
                    200, json={"merchant": {"id": {"private": "merchant id"}}}
                )
            return httpx.Response(200, json={"merchant": {"id": "MERCHANT_TEST"}})
        return httpx.Response(200, json={"payments": ["private payment item"]})

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(protect_handler),
        square_transport=httpx.MockTransport(malformed_square),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            response = isolated.put(
                "/api/settings/square",
                json={"access_token": SQUARE_TOKEN, "environment": "production"},
            )

        assert response.status_code == 502
        assert response.json()["detail"].startswith(
            "Could not reach Square: Square "
        )
        assert "private Square body" not in response.text
        assert "private location item" not in response.text
        assert "private payment item" not in response.text
        assert app.state.store.get_setting("square.access_token") is None
    finally:
        app.state.store.close()


def test_square_settings_malformed_nested_payment_returns_502(tmp_path):
    def malformed_payment(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/payments":
            return httpx.Response(
                200,
                json={
                    "payments": [
                        {
                            "id": "PAY_BAD_NESTED",
                            "created_at": "2026-07-16T16:30:00Z",
                            "amount_money": [],
                        }
                    ]
                },
            )
        return square_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(protect_handler),
        square_transport=httpx.MockTransport(malformed_payment),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            resp = isolated.put(
                "/api/settings/square",
                json={"access_token": SQUARE_TOKEN, "environment": "production"},
            )

        assert resp.status_code == 502
        assert resp.json()["detail"] == (
            "Could not reach Square: Square returned invalid payment data"
        )
    finally:
        app.state.store.close()


# -- cameras, locations, POS camera selection ------------------------------------------

def test_cameras_requires_protect_config(authed):
    assert authed.get("/api/cameras").status_code == 409

def test_camera_and_location_listing(configured):
    cameras = configured.get("/api/cameras").json()
    assert {c["name"] for c in cameras} == {"Front Counter", "Back Door"}
    locations = configured.get("/api/locations").json()
    assert locations[0]["id"] == "LOC1"

def test_camera_mapping_roundtrip(configured):
    mapping = configured.get("/api/camera-mapping").json()
    assert mapping == [
        {
            "location_id": "LOC1",
            "device_id": "",
            "device_name": "",
            "camera_id": CAM1,
            "camera_name": "Front Counter",
        }
    ]


def test_camera_mapping_headers_identify_both_provider_snapshots(configured):
    cameras = configured.get("/api/cameras")
    locations = configured.get("/api/locations")
    mapping = configured.get("/api/camera-mapping")

    assert mapping.status_code == 200
    assert mapping.headers["cache-control"] == "private, no-store"
    assert mapping.headers["x-protect-console-generation"] == (
        cameras.headers["x-protect-console-generation"]
    )
    assert mapping.headers["x-square-account-revision"] == (
        locations.headers["x-square-account-revision"]
    )


def test_camera_mapping_accepts_255_character_device_name(configured):
    device_name = "R" * 255
    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "device_id": "TERM_LONG_NAME",
                    "device_name": device_name,
                    "camera_id": CAM1,
                    "camera_name": "Front Counter",
                }
            ]
        },
    )
    assert resp.status_code == 200
    assert configured.get("/api/camera-mapping").json()[0]["device_name"] == device_name


def test_camera_mapping_rejects_duplicate_target_without_mutation(configured):
    existing = configured.get("/api/camera-mapping").json()
    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC_DUPLICATE",
                    "device_id": "TERM_A",
                    "camera_id": CAM1,
                },
                {
                    "location_id": "LOC_DUPLICATE",
                    "device_id": "TERM_A",
                    "camera_id": CAM2,
                },
            ]
        },
    )

    assert resp.status_code == 422
    assert "Duplicate camera mapping" in resp.text
    assert configured.get("/api/camera-mapping").json() == existing


def test_camera_mapping_rejects_more_than_500_entries_without_mutation(configured):
    existing = configured.get("/api/camera-mapping").json()
    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {"location_id": f"LOC{index}", "camera_id": CAM1}
                for index in range(501)
            ]
        },
    )

    assert resp.status_code == 422
    assert resp.json()["detail"] == "Camera mappings cannot exceed 500 entries"
    assert configured.get("/api/camera-mapping").json() == existing


def test_camera_mapping_save_drains_previously_unmapped_evidence(configured):
    _wait_for_protect_jobs(configured)
    configured.app.state.store.upsert_transaction(
        {
            "id": "PAY_PENDING_MAPPING",
            "created_at": "2026-07-16T15:30:00.000Z",
            "ts_ms": 1784215800000,
            "amount": 500,
            "currency": "USD",
            "status": "COMPLETED",
            "location_id": "LOC1",
            "camera_id": None,
        }
    )

    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "camera_id": CAM2,
                    "camera_name": "Back Door",
                }
            ]
        },
    )

    assert resp.status_code == 200
    txn = _wait_for_thumbnail(configured, "PAY_PENDING_MAPPING")
    assert txn["camera_id"] == CAM2
    assert configured.get(txn["thumbnail_url"]).status_code == 200


def test_camera_preview_returns_jpeg(configured):
    resp = configured.get(f"/api/camera-preview/{CAM1}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/jpeg"
    assert resp.content.startswith(b"\xff\xd8")


# -- transactions: sync, thumbnails, deep links ------------------------------------------

def test_sync_ingests_square_payments(configured):
    resp = configured.post("/api/sync")
    assert resp.status_code == 200
    assert resp.json()["ingested"] == 2

    txns = configured.get("/api/transactions").json()
    assert len(txns) == 2
    # Newest first
    assert txns[0]["id"] == "PAY_002"
    assert txns[1]["id"] == "PAY_001"

    first = txns[1]
    assert first["amount"] == 1250
    assert first["currency"] == "USD"
    assert first["card_last4"] == "4242"
    assert first["created_at"] == "2026-07-16T15:30:00.000Z"
    assert first["camera_id"] == CAM1

def test_transaction_deep_link_points_at_protect_timeline(configured):
    configured.post("/api/sync")
    txn = configured.get("/api/transactions").json()[-1]
    assert txn["deep_link"] == (
        f"https://192.168.1.1/protect/timelapse/{CAM1}?start={txn['ts_ms']}"
    )

def test_transaction_thumbnail_served(configured):
    configured.post("/api/sync")
    txn = configured.get("/api/transactions").json()[0]
    assert txn["thumbnail_url"] == f"/api/thumbnails/{txn['id']}"
    resp = configured.get(txn["thumbnail_url"])
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/jpeg"
    assert txn["thumbnail_status"] == "ready"
    assert txn["thumbnail_retry_attempts"] == 0
    # The mock embeds the requested ts in the image; the snapshot must have been
    # taken at the transaction's timestamp, not "now".
    assert resp.content.endswith(str(txn["ts_ms"]).encode())


def test_transaction_feed_reports_thumbnail_retry_status(configured):
    assert configured.post("/api/sync").status_code == 200
    store = configured.app.state.store
    txn = store.list_transactions(limit=1)[0]
    with store._lock:
        store._db.execute(
            "UPDATE transactions SET thumbnail_path = NULL WHERE id = ?",
            (txn["id"],),
        )
        store._db.execute(
            "INSERT INTO thumbnail_retries (transaction_id, attempts, last_error) "
            "VALUES (?, 2, 'console unavailable') "
            "ON CONFLICT(transaction_id) DO UPDATE SET attempts = 2, "
            "last_error = 'console unavailable'",
            (txn["id"],),
        )
        store._db.commit()

    listed = next(
        item for item in configured.get("/api/transactions").json()
        if item["id"] == txn["id"]
    )
    assert listed["thumbnail_url"] is None
    assert listed["thumbnail_status"] == "retrying"
    assert listed["thumbnail_retry_attempts"] == 2

def test_sync_is_idempotent(configured):
    first = configured.post("/api/sync")
    second = configured.post("/api/sync")
    assert first.json()["ingested"] == 2
    assert second.json()["ingested"] == 0
    assert len(configured.get("/api/transactions").json()) == 2


def test_transactions_api_supports_page_lookahead_and_offset(authed):
    store = authed.app.state.store
    for index in range(102):
        store.upsert_transaction(
            {
                "id": f"PAY_PAGE_{index:03d}",
                "created_at": "2026-07-16T15:30:00.000Z",
                # Equal timestamps verify the secondary id ordering keeps
                # offset pages deterministic and non-overlapping.
                "ts_ms": 1784215800000,
                "amount": index,
                "currency": "USD",
                "status": "COMPLETED",
                "location_id": "LOC1",
            }
        )

    first_response = authed.get("/api/transactions?limit=101&offset=0")
    snapshot = first_response.headers["x-transaction-snapshot"]
    second_response = authed.get(
        f"/api/transactions?limit=101&offset=100&snapshot={snapshot}"
    )
    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert second_response.headers["x-transaction-snapshot"] == snapshot
    first_with_lookahead = first_response.json()
    second_page = second_response.json()

    assert len(first_with_lookahead) == 101
    assert len(second_page) == 2
    first_page = first_with_lookahead[:100]
    assert first_with_lookahead[100]["id"] == second_page[0]["id"]
    assert {txn["id"] for txn in first_page}.isdisjoint(
        txn["id"] for txn in second_page
    )
    assert second_page[-1]["id"] == "PAY_PAGE_000"


def test_transaction_snapshot_keeps_offset_pages_stable_during_inserts(authed):
    store = authed.app.state.store
    created_at = "2026-07-16T15:30:00.000Z"
    for index in range(300):
        store.upsert_transaction(
            {
                "id": f"PAY_STABLE_{index:03d}",
                "created_at": created_at,
                "ts_ms": 1784215800000 - index,
                "amount": index,
                "currency": "USD",
                "status": "COMPLETED",
                "location_id": "LOC1",
            }
        )

    first_response = authed.get("/api/transactions?limit=101&offset=0")
    snapshot = first_response.headers["x-transaction-snapshot"]
    middle_page = authed.get(
        f"/api/transactions?limit=101&offset=100&snapshot={snapshot}"
    ).json()[:100]

    # These rows sort ahead of every row in the snapshot. Without the rowid
    # boundary they shift offset 200 and repeat five rows from the middle page.
    for index in range(5):
        store.upsert_transaction(
            {
                "id": f"PAY_NEW_{index}",
                "created_at": created_at,
                "ts_ms": 1784216800000 + index,
                "amount": index,
                "currency": "USD",
                "status": "COMPLETED",
                "location_id": "LOC1",
            }
        )

    refreshed = authed.get("/api/transactions?limit=101&offset=0")
    assert int(refreshed.headers["x-transaction-snapshot"]) > int(snapshot)
    assert {txn["id"] for txn in refreshed.json()[:5]} == {
        f"PAY_NEW_{index}" for index in range(5)
    }

    next_response = authed.get(
        f"/api/transactions?limit=101&offset=200&snapshot={snapshot}"
    )
    next_page = next_response.json()[:100]
    assert next_response.headers["x-transaction-snapshot"] == snapshot
    assert {txn["id"] for txn in middle_page}.isdisjoint(
        txn["id"] for txn in next_page
    )
    assert all(not txn["id"].startswith("PAY_NEW_") for txn in next_page)


def test_transaction_snapshot_keeps_timestamp_corrections_in_original_order(authed):
    store = authed.app.state.store

    def transaction(txn_id: str, ts_ms: int, updated_ts_ms: int) -> dict:
        return {
            "id": txn_id,
            "created_at": "2026-07-16T15:30:00.000Z",
            "ts_ms": ts_ms,
            "updated_at": "2026-07-16T15:30:00.000Z",
            "updated_ts_ms": updated_ts_ms,
            "amount": 100,
            "currency": "USD",
            "status": "COMPLETED",
            "location_id": "LOC1",
        }

    store.upsert_transaction(transaction("A", 300, 1))
    store.upsert_transaction(transaction("B", 200, 1))
    store.upsert_transaction(transaction("C", 100, 1))

    first_response = authed.get("/api/transactions?limit=2&offset=0")
    snapshot = first_response.headers["x-transaction-snapshot"]
    assert [txn["id"] for txn in first_response.json()] == ["A", "B"]

    # C moves ahead of both visible rows after page one was issued. Its old
    # ordering key remains part of that durable snapshot, so OFFSET 2 neither
    # repeats B nor loses C.
    store.upsert_transaction(transaction("C", 400, 2))
    second_response = authed.get(
        f"/api/transactions?limit=2&offset=2&snapshot={snapshot}"
    )
    assert second_response.headers["x-transaction-snapshot"] == snapshot
    assert [txn["id"] for txn in second_response.json()] == ["C"]
    assert [txn["id"] for txn in first_response.json() + second_response.json()] == [
        "A",
        "B",
        "C",
    ]

    refreshed = authed.get("/api/transactions?limit=2&offset=0")
    assert int(refreshed.headers["x-transaction-snapshot"]) > int(snapshot)
    assert [txn["id"] for txn in refreshed.json()] == ["C", "A"]


def test_expired_transaction_snapshot_returns_conflict(authed):
    store = authed.app.state.store
    store.upsert_transaction(
        {
            "id": "PAY_EXPIRED_PAGE",
            "created_at": "2026-07-16T15:30:00.000Z",
            "ts_ms": 100,
            "amount": 100,
            "currency": "USD",
            "status": "COMPLETED",
            "location_id": "LOC1",
        }
    )
    first_response = authed.get("/api/transactions?limit=1&offset=0")
    snapshot = int(first_response.headers["x-transaction-snapshot"])
    with store._lock:
        store._db.execute(
            "UPDATE transaction_feed_snapshots SET last_accessed_at = 0 "
            "WHERE id = ?",
            (snapshot,),
        )
        store._db.commit()

    expired = authed.get(
        f"/api/transactions?limit=1&offset=1&snapshot={snapshot}"
    )
    assert expired.status_code == 409
    assert "return to the newest page" in expired.json()["detail"]

    refreshed = authed.get("/api/transactions?limit=1&offset=0")
    assert refreshed.status_code == 200
    assert int(refreshed.headers["x-transaction-snapshot"]) > snapshot


def test_transactions_without_camera_mapping_still_listed(authed):
    authed.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert authed.post("/api/sync").json()["ingested"] == 2
    txns = authed.get("/api/transactions").json()
    assert all(t["thumbnail_url"] is None for t in txns)
    assert all(t["deep_link"] is None for t in txns)
    assert all(t["thumbnail_status"] == "unmapped" for t in txns)


def test_snapshot_transport_error_stores_transaction_without_thumbnail(tmp_path):
    def snapshot_unavailable(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("snapshot"):
            raise httpx.ReadTimeout("sensitive snapshot details", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(snapshot_unavailable),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            ).status_code == 200
            square_response = isolated.put(
                "/api/settings/square",
                json={"access_token": SQUARE_TOKEN, "environment": "production"},
            )
            assert square_response.status_code == 200
            isolated.headers["X-Square-Account-Revision"] = square_response.json()[
                "account_revision"
            ]
            _refresh_camera_generation(isolated)
            assert isolated.put(
                "/api/camera-mapping",
                json={
                    "mappings": [
                        {
                            "location_id": "LOC1",
                            "camera_id": CAM1,
                            "camera_name": "Front Counter",
                        }
                    ]
                },
            ).status_code == 200

            sync_resp = isolated.post("/api/sync")
            txns = isolated.get("/api/transactions").json()

        assert sync_resp.status_code == 200
        assert sync_resp.json()["ingested"] == 2
        assert len(txns) == 2
        assert all(txn["camera_id"] == CAM1 for txn in txns)
        assert all(txn["thumbnail_url"] is None for txn in txns)
        assert all(txn["deep_link"] is not None for txn in txns)
    finally:
        app.state.store.close()

def test_sync_persists_transactions_when_thumbnail_write_fails(configured, tmp_path):
    configured.app.state.store.thumbnail_dir = tmp_path / "missing" / "thumbnails"

    resp = configured.post("/api/sync")

    assert resp.status_code == 200
    assert resp.json()["ingested"] == 2
    txns = configured.get("/api/transactions").json()
    assert len(txns) == 2
    assert all(txn["thumbnail_url"] is None for txn in txns)
    assert all(txn["deep_link"] is not None for txn in txns)

def test_thumbnail_missing_returns_404(configured):
    assert configured.get("/api/thumbnails/NOPE").status_code == 404


def test_thumbnail_disappearance_after_validation_returns_404_and_requeues(
    configured, monkeypatch
):
    assert configured.post("/api/sync").status_code == 200
    txn = configured.get("/api/transactions").json()[0]
    store = configured.app.state.store
    stored_txn = store.get_transaction(txn["id"])
    original_thumbnail_path = stored_txn["thumbnail_path"]
    thumbnail_path = (store.thumbnail_dir / original_thumbnail_path).resolve()
    original_is_file = Path.is_file
    disappeared = False

    def unlink_after_validation(path):
        nonlocal disappeared
        exists = original_is_file(path)
        if path == thumbnail_path and exists and not disappeared:
            path.unlink()
            disappeared = True
        return exists

    requeue_calls = []
    original_requeue = store.requeue_missing_thumbnail

    def requeue_without_starting_worker(txn_id, expected_path):
        requeued = original_requeue(txn_id, expected_path)
        requeue_calls.append((txn_id, expected_path, requeued))
        # Keep the durable state deterministic for this assertion instead of
        # letting the background worker immediately recapture the image.
        return False

    monkeypatch.setattr(Path, "is_file", unlink_after_validation)
    monkeypatch.setattr(store, "requeue_missing_thumbnail", requeue_without_starting_worker)

    response = configured.get(txn["thumbnail_url"])

    assert disappeared is True
    assert response.status_code == 404
    assert response.json()["detail"] == "Thumbnail not found"
    assert requeue_calls == [(txn["id"], original_thumbnail_path, True)]
    assert store.get_transaction(txn["id"])["thumbnail_path"] is None


# -- Square webhook ---------------------------------------------------------------------

def _webhook_signature(body: bytes) -> str:
    return base64.b64encode(
        hmac.new(WEBHOOK_KEY.encode(), WEBHOOK_URL.encode() + body, hashlib.sha256).digest()
    ).decode()

def make_webhook_event(
    payment_id: str = "PAY_HOOK",
    device_id: str = "",
    device_name: str = "",
    status: str = "COMPLETED",
    created_at: str = "2026-07-16T16:00:00.000Z",
    updated_at: str | None = None,
    merchant_id: str = SQUARE_MERCHANT_ID,
    event_type: str = "payment.updated",
) -> bytes:
    payment = {
        "id": payment_id,
        "created_at": created_at,
        "amount_money": {"amount": 500, "currency": "USD"},
        "status": status,
        "location_id": "LOC1",
        "card_details": {"card": {"last_4": "9999"}},
    }
    if updated_at is not None:
        payment["updated_at"] = updated_at
    if device_id or device_name:
        payment["device_details"] = {
            "device_id": device_id,
            "device_name": device_name,
        }
    return json.dumps(
        {
            "merchant_id": merchant_id,
            "type": event_type,
            "data": {"object": {"payment": payment}},
        }
    ).encode()


def test_webhook_ignores_payment_for_another_merchant(configured):
    body = make_webhook_event("PAY_FOREIGN", merchant_id="MERCHANT_FOREIGN")
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "ignored": True}
    assert configured.app.state.store.get_transaction("PAY_FOREIGN") is None


def test_slow_webhook_rejects_signature_after_same_account_key_rotation(configured):
    body = make_webhook_event("PAY_OLD_WEBHOOK_KEY")
    body_requested = threading.Event()
    release_body = threading.Event()
    store = configured.app.state.store
    original_revision = store.square_account_revision()

    def delayed_body():
        body_requested.set()
        assert release_body.wait(timeout=5)
        yield body

    def send_webhook():
        return configured.post(
            "/webhooks/square",
            content=delayed_body(),
            headers={
                "x-square-hmacsha256-signature": _webhook_signature(body)
            },
        )

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(send_webhook)
    try:
        assert body_requested.wait(timeout=5)
        rotated = store.configure_square_account(
            merchant_id=SQUARE_MERCHANT_ID,
            access_token=SQUARE_TOKEN,
            environment="production",
            webhook_signature_key="rotated-webhook-key",
            webhook_url="https://rotated.example/webhooks/square",
        )
        assert not rotated.switched
        assert rotated.account_revision == original_revision
        release_body.set()
        response = future.result(timeout=5)
    finally:
        release_body.set()
        executor.shutdown(wait=True, cancel_futures=True)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid webhook signature"
    assert store.get_transaction("PAY_OLD_WEBHOOK_KEY") is None


def _wait_for_thumbnail(client, payment_id: str, timeout: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        txns = client.get("/api/transactions?limit=500").json()
        txn = next((item for item in txns if item["id"] == payment_id), None)
        if txn and txn["thumbnail_url"]:
            return txn
        time.sleep(0.01)
    raise AssertionError(f"thumbnail enrichment did not finish for {payment_id}")


def _wait_for_alarm_state(
    client, payment_id: str, state: str, timeout: float = 3.0
) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        txn = client.app.state.store.get_transaction(payment_id)
        if txn and txn["alarm_state"] == state:
            return txn
        time.sleep(0.01)
    raise AssertionError(
        f"alarm state for {payment_id} did not become {state}"
    )


def _wait_for_protect_jobs(client, timeout: float = 3.0) -> None:
    """Wait until every scheduled Protect work drain has finished."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not client.app.state.thumbnail_drain_queued:
            # The single-worker executor serializes drains; once this no-op
            # barrier runs, all previously scheduled drains have completed.
            client.app.state.thumbnail_executor.submit(lambda: None).result(
                timeout=timeout
            )
            if not client.app.state.thumbnail_drain_queued:
                return
        time.sleep(0.01)
    raise AssertionError("webhook Protect work did not finish")


def _observe_exclusive_integration_attempt(store: Store) -> threading.Event:
    """Signal immediately before this Store instance tries the provider writer."""
    attempted = threading.Event()
    original_guard = store.integration_guard

    @contextmanager
    def observed_guard(*, exclusive: bool = False):
        if exclusive:
            attempted.set()
        with original_guard(exclusive=exclusive):
            yield

    store.integration_guard = observed_guard
    return attempted


def _observe_protect_settings_attempt(store: Store) -> threading.Event:
    """Signal immediately before this Store instance tries the settings mutex."""
    attempted = threading.Event()
    original_guard = store.protect_settings_guard

    @contextmanager
    def observed_guard():
        attempted.set()
        with original_guard():
            yield

    store.protect_settings_guard = observed_guard
    return attempted


@pytest.mark.parametrize("event_type", ["payment.created", "payment.updated"])
def test_webhook_stores_payment_then_enriches_thumbnail(configured, event_type):
    body = make_webhook_event(event_type=event_type)
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    txns = configured.get("/api/transactions").json()
    assert txns[0]["id"] == "PAY_HOOK"
    assert txns[0]["deep_link"] is not None
    txn = _wait_for_thumbnail(configured, "PAY_HOOK")
    assert configured.get(txn["thumbnail_url"]).status_code == 200


def test_webhook_ack_and_transaction_listing_do_not_wait_for_snapshot(tmp_path):
    snapshot_started = threading.Event()
    release_snapshot = threading.Event()

    def blocking_snapshot(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("snapshot"):
            snapshot_started.set()
            if not release_snapshot.wait(timeout=10):
                raise httpx.ReadTimeout("snapshot test timed out", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_snapshot),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            ).status_code == 200
            square_response = isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            )
            assert square_response.status_code == 200
            isolated.headers["X-Square-Account-Revision"] = square_response.json()[
                "account_revision"
            ]
            _refresh_camera_generation(isolated)
            assert isolated.put(
                "/api/camera-mapping",
                json={
                    "mappings": [
                        {
                            "location_id": "LOC1",
                            "camera_id": CAM1,
                            "camera_name": "Front Counter",
                        }
                    ]
                },
            ).status_code == 200

            body = make_webhook_event("PAY_BLOCKED")
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as requester:
                response_future = requester.submit(
                    isolated.post,
                    "/webhooks/square",
                    content=body,
                    headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
                )
                try:
                    assert snapshot_started.wait(timeout=3)
                    response = response_future.result(timeout=2)
                    assert response.status_code == 200
                    assert not release_snapshot.is_set()

                    listing = isolated.get("/api/transactions")
                    assert listing.status_code == 200
                    txn = next(
                        item for item in listing.json() if item["id"] == "PAY_BLOCKED"
                    )
                    assert txn["thumbnail_url"] is None
                    assert txn["deep_link"] is not None
                finally:
                    release_snapshot.set()

            txn = _wait_for_thumbnail(isolated, "PAY_BLOCKED")
            assert isolated.get(txn["thumbnail_url"]).status_code == 200
    finally:
        release_snapshot.set()
        app.state.store.close()


def test_webhook_ack_does_not_wait_for_alarm_delivery(tmp_path):
    alarm_started = threading.Event()
    release_alarm = threading.Event()

    def blocking_alarm(request: httpx.Request) -> httpx.Response:
        if "/alarm-manager/webhook/" in request.url.path:
            alarm_started.set()
            if not release_alarm.wait(timeout=10):
                raise httpx.ReadTimeout("alarm test timed out", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_alarm),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                    "api_key": PROTECT_API_KEY,
                    "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            ).status_code == 200

            body = make_webhook_event(
                "PAY_ALARM_BLOCKED", created_at="2099-07-16T16:00:00.000Z"
            )
            response = isolated.post(
                "/webhooks/square",
                content=body,
                headers={
                    "x-square-hmacsha256-signature": _webhook_signature(body)
                },
            )
            assert response.status_code == 200
            assert alarm_started.wait(timeout=3)
            assert not release_alarm.is_set()
            assert (
                isolated.app.state.store.get_transaction("PAY_ALARM_BLOCKED")
                is not None
            )
            exclusive_attempted = _observe_exclusive_integration_attempt(
                app.state.store
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                disable_future = executor.submit(
                    isolated.delete, "/api/settings/protect/alarm"
                )
                assert exclusive_attempted.wait(timeout=3)
                with pytest.raises(concurrent.futures.TimeoutError):
                    disable_future.result(timeout=0.05)
                assert app.state.store.get_setting("protect.api_key") == PROTECT_API_KEY
                release_alarm.set()
                disabled = disable_future.result(timeout=5)
            assert disabled.status_code == 200
            assert app.state.store.get_setting("protect.api_key") is None
            assert app.state.store.get_setting("protect.alarm_trigger_id") is None
            _wait_for_alarm_state(isolated, "PAY_ALARM_BLOCKED", "sent")
    finally:
        release_alarm.set()
        app.state.store.close()


def test_same_host_alarm_rotation_waits_for_inflight_delivery(tmp_path):
    alarm_started = threading.Event()
    release_alarm = threading.Event()
    rotated_api_key = "rotated-protect-api-key"
    rotated_trigger_id = "rotated-square-sale"
    alarm_requests: list[tuple[str, str | None]] = []

    def blocking_alarm(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/proxy/protect/integration/v1/meta/info":
            if request.headers.get("x-api-key") not in {
                PROTECT_API_KEY,
                rotated_api_key,
            }:
                return httpx.Response(401, json={"error": "Invalid API key"})
            return httpx.Response(200, json={"applicationVersion": "7.1.87"})
        if "/alarm-manager/webhook/" in request.url.path:
            alarm_requests.append(
                (request.url.path.rsplit("/", 1)[-1], request.headers.get("x-api-key"))
            )
            alarm_started.set()
            if not release_alarm.wait(timeout=10):
                raise httpx.ReadTimeout("alarm test timed out", request=request)
            return httpx.Response(204)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_alarm),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                    "api_key": PROTECT_API_KEY,
                    "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            ).status_code == 200

            body = make_webhook_event(
                "PAY_ALARM_ROTATION", created_at="2099-07-16T16:00:00.000Z"
            )
            assert isolated.post(
                "/webhooks/square",
                content=body,
                headers={
                    "x-square-hmacsha256-signature": _webhook_signature(body)
                },
            ).status_code == 200
            assert alarm_started.wait(timeout=3)

            exclusive_attempted = _observe_exclusive_integration_attempt(
                app.state.store
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                rotation_future = executor.submit(
                    isolated.put,
                    "/api/settings/protect",
                    json={
                        "host": "192.168.1.1",
                        "username": PROTECT_USER,
                        "password": PROTECT_PASS,
                        "api_key": rotated_api_key,
                        "alarm_trigger_id": rotated_trigger_id,
                    },
                )
                assert exclusive_attempted.wait(timeout=3)
                with pytest.raises(concurrent.futures.TimeoutError):
                    rotation_future.result(timeout=0.05)
                assert app.state.store.get_setting("protect.api_key") == PROTECT_API_KEY
                assert (
                    app.state.store.get_setting("protect.alarm_trigger_id")
                    == PROTECT_ALARM_TRIGGER_ID
                )
                release_alarm.set()
                rotated = rotation_future.result(timeout=5)

            assert rotated.status_code == 200, rotated.text
            assert rotated.json()["alarm_configured"] is True
            assert app.state.store.get_setting("protect.api_key") == rotated_api_key
            assert (
                app.state.store.get_setting("protect.alarm_trigger_id")
                == rotated_trigger_id
            )
            assert alarm_requests == [(PROTECT_ALARM_TRIGGER_ID, PROTECT_API_KEY)]
            _wait_for_alarm_state(isolated, "PAY_ALARM_ROTATION", "sent")
    finally:
        release_alarm.set()
        app.state.store.close()


def test_alarm_disable_waits_for_same_host_settings_probe(tmp_path):
    block_meta_probe = threading.Event()
    meta_probe_started = threading.Event()
    release_meta_probe = threading.Event()
    replacement_trigger_id = "replacement-square-sale"

    def blocking_meta_probe(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/proxy/protect/integration/v1/meta/info":
            if request.headers.get("x-api-key") != PROTECT_API_KEY:
                return httpx.Response(401, json={"error": "Invalid API key"})
            if block_meta_probe.is_set():
                meta_probe_started.set()
                if not release_meta_probe.wait(timeout=10):
                    raise httpx.ReadTimeout("meta probe timed out", request=request)
            return httpx.Response(200, json={"applicationVersion": "7.1.87"})
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_meta_probe),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                    "api_key": PROTECT_API_KEY,
                    "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            ).status_code == 200

            block_meta_probe.set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                refresh_future = executor.submit(
                    isolated.put,
                    "/api/settings/protect",
                    json={
                        "host": "192.168.1.1",
                        "username": PROTECT_USER,
                        "password": PROTECT_PASS,
                        "alarm_trigger_id": replacement_trigger_id,
                    },
                )
                assert meta_probe_started.wait(timeout=3)
                body = make_webhook_event(
                    "PAY_DURING_SETTINGS_PROBE",
                    created_at="2099-07-16T16:00:00.000Z",
                )
                webhook_future = executor.submit(
                    isolated.post,
                    "/webhooks/square",
                    content=body,
                    headers={
                        "x-square-hmacsha256-signature": _webhook_signature(body)
                    },
                )
                webhook_response = webhook_future.result(timeout=2)
                assert webhook_response.status_code == 200
                assert isolated.get("/api/transactions").status_code == 200
                settings_attempted = _observe_protect_settings_attempt(
                    app.state.store
                )
                disable_future = executor.submit(
                    isolated.delete, "/api/settings/protect/alarm"
                )
                assert settings_attempted.wait(timeout=3)
                with pytest.raises(concurrent.futures.TimeoutError):
                    disable_future.result(timeout=0.05)
                assert app.state.store.get_setting("protect.api_key") == PROTECT_API_KEY
                assert (
                    app.state.store.get_setting("protect.alarm_trigger_id")
                    == PROTECT_ALARM_TRIGGER_ID
                )
                release_meta_probe.set()
                refreshed = refresh_future.result(timeout=5)
                disabled = disable_future.result(timeout=5)

            assert refreshed.status_code == 200, refreshed.text
            assert refreshed.json()["alarm_configured"] is True
            assert disabled.status_code == 200, disabled.text
            assert app.state.store.get_setting("protect.api_key") is None
            assert app.state.store.get_setting("protect.alarm_trigger_id") is None
    finally:
        release_meta_probe.set()
        app.state.store.close()


def test_console_switch_waits_for_inflight_old_console_alarm(tmp_path):
    alarm_started = threading.Event()
    release_alarm = threading.Event()

    def blocking_alarm(request: httpx.Request) -> httpx.Response:
        if "/alarm-manager/webhook/" in request.url.path:
            alarm_started.set()
            if not release_alarm.wait(timeout=10):
                raise httpx.ReadTimeout("alarm test timed out", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_alarm),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                    "api_key": PROTECT_API_KEY,
                    "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            ).status_code == 200
            switch_token = _protect_switch_token(isolated, "192.168.1.2")

            body = make_webhook_event(
                "PAY_ALARM_SWITCH", created_at="2099-07-16T16:00:00.000Z"
            )
            assert isolated.post(
                "/webhooks/square",
                content=body,
                headers={
                    "x-square-hmacsha256-signature": _webhook_signature(body)
                },
            ).status_code == 200
            assert alarm_started.wait(timeout=3)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                switch_future = executor.submit(
                    isolated.put,
                    "/api/settings/protect",
                    json={
                        "host": "192.168.1.2",
                        "username": PROTECT_USER,
                        "password": PROTECT_PASS,
                        "console_switch_token": switch_token,
                    },
                )
                with pytest.raises(concurrent.futures.TimeoutError):
                    switch_future.result(timeout=0.05)
                assert app.state.store.get_setting("protect.host") == "192.168.1.1"
                release_alarm.set()
                switched = switch_future.result(timeout=5)

            assert switched.status_code == 200, switched.text
            assert switched.json()["console_switched"] is True
            assert app.state.store.get_setting("protect.host") == "192.168.1.2"
    finally:
        release_alarm.set()
        app.state.store.close()


def test_thumbnail_retry_recaptures_after_camera_changes_in_flight(tmp_path):
    snapshot_started = threading.Event()
    release_snapshot = threading.Event()

    class BlockingProtect:
        def __init__(self):
            self.calls = []

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls.append((camera_id, ts_ms))
            if len(self.calls) == 1:
                snapshot_started.set()
                assert release_snapshot.wait(timeout=5)
            return b"snapshot:" + camera_id.encode()

    payment = {
        "id": "PAY_CAMERA_RACE",
        "created_at": "2026-07-16T16:00:00.000Z",
        "amount_money": {"amount": 500, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
    }
    store = Store(tmp_path / "data")
    protect = BlockingProtect()
    try:
        store.set_camera_mapping("LOC1", CAM1, "Front Counter")
        ingest_payment(store, payment, None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(retry_missing_thumbnails, store, protect)
            assert snapshot_started.wait(timeout=3)
            # Remap while the first capture is in flight; the reset queue row
            # invalidates the old lease, so the CAM1 frame cannot attach.
            store.set_camera_mapping("LOC1", CAM2, "Back Door")
            ingest_payment(store, payment, None)
            release_snapshot.set()
            assert future.result(timeout=5) == 1

        txn = store.get_transaction(payment["id"])
        assert txn["camera_id"] == CAM2
        assert protect.calls == [(CAM1, txn["ts_ms"]), (CAM2, txn["ts_ms"])]
        assert (store.thumbnail_dir / txn["thumbnail_path"]).read_bytes() == (
            b"snapshot:" + CAM2.encode()
        )
    finally:
        release_snapshot.set()
        store.close()


def test_webhook_burst_acks_immediately_and_queue_drains_all(tmp_path):
    release_snapshots = threading.Event()

    def blocking_snapshot(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("snapshot"):
            assert release_snapshots.wait(timeout=10)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(blocking_snapshot),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            ).status_code == 200
            square_response = isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            )
            assert square_response.status_code == 200
            isolated.headers["X-Square-Account-Revision"] = square_response.json()[
                "account_revision"
            ]
            _refresh_camera_generation(isolated)
            assert isolated.put(
                "/api/camera-mapping",
                json={
                    "mappings": [
                        {
                            "location_id": "LOC1",
                            "camera_id": CAM1,
                            "camera_name": "Front Counter",
                        }
                    ]
                },
            ).status_code == 200

            # A burst of webhooks all ack while Protect is still blocked.
            for index in range(7):
                body = make_webhook_event(f"PAY_QUEUE_{index}")
                response = isolated.post(
                    "/webhooks/square",
                    content=body,
                    headers={
                        "x-square-hmacsha256-signature": _webhook_signature(body)
                    },
                )
                assert response.status_code == 200

            listed = isolated.get("/api/transactions?limit=500").json()
            assert len(listed) == 7

            release_snapshots.set()
            for index in range(7):
                txn = _wait_for_thumbnail(isolated, f"PAY_QUEUE_{index}")
                assert isolated.get(txn["thumbnail_url"]).status_code == 200
    finally:
        release_snapshots.set()
        app.state.store.close()


def test_single_coalesced_webhook_drain_exhausts_due_batches(tmp_path):
    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(protect_handler),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    release_executor = threading.Event()
    executor_blocked = threading.Event()

    def block_executor() -> None:
        executor_blocked.set()
        assert release_executor.wait(timeout=10)

    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                    "api_key": PROTECT_API_KEY,
                    "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
                },
            ).status_code == 200
            square_response = isolated.put(
                "/api/settings/square",
                json={
                    "access_token": SQUARE_TOKEN,
                    "environment": "production",
                    "webhook_signature_key": WEBHOOK_KEY,
                    "webhook_url": WEBHOOK_URL,
                },
            )
            assert square_response.status_code == 200
            isolated.headers["X-Square-Account-Revision"] = square_response.json()[
                "account_revision"
            ]
            _refresh_camera_generation(isolated)
            assert isolated.put(
                "/api/camera-mapping",
                json={
                    "mappings": [
                        {
                            "location_id": "LOC1",
                            "camera_id": CAM1,
                            "camera_name": "Front Counter",
                        }
                    ]
                },
            ).status_code == 200

            blocker = isolated.app.state.thumbnail_executor.submit(block_executor)
            assert executor_blocked.wait(timeout=3)

            payment_ids = [f"PAY_BATCH_{index:02d}" for index in range(11)]
            for payment_id in payment_ids:
                body = make_webhook_event(
                    payment_id, created_at="2099-07-16T16:00:00.000Z"
                )
                response = isolated.post(
                    "/webhooks/square",
                    content=body,
                    headers={
                        "x-square-hmacsha256-signature": _webhook_signature(body)
                    },
                )
                assert response.status_code == 200

            assert isolated.app.state.thumbnail_drain_queued is True
            release_executor.set()
            blocker.result(timeout=3)

            for payment_id in payment_ids:
                _wait_for_thumbnail(isolated, payment_id)
                _wait_for_alarm_state(isolated, payment_id, "sent")
            _wait_for_protect_jobs(isolated)
            assert PROTECT_ALARM_CALLS == [PROTECT_ALARM_TRIGGER_ID] * 11
    finally:
        release_executor.set()
        app.state.store.close()

def test_square_settings_resave_leaves_webhook_config_untouched(configured):
    store = configured.app.state.store
    resp = configured.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production"},
    )
    assert resp.status_code == 200
    assert store.get_setting("square.webhook_signature_key") == WEBHOOK_KEY
    assert store.get_setting("square.webhook_url") == WEBHOOK_URL

def test_square_settings_rejects_clear_webhook_with_new_credentials(configured):
    resp = configured.put(
        "/api/settings/square",
        json={
            "access_token": SQUARE_TOKEN,
            "environment": "production",
            "webhook_signature_key": WEBHOOK_KEY,
            "webhook_url": WEBHOOK_URL,
            "clear_webhook": True,
        },
    )
    assert resp.status_code == 422

def test_square_settings_can_disable_existing_webhook(configured):
    store = configured.app.state.store
    assert store.get_setting("square.webhook_signature_key") == WEBHOOK_KEY
    assert store.get_setting("square.webhook_url") == WEBHOOK_URL

    resp = configured.put(
        "/api/settings/square",
        json={"access_token": SQUARE_TOKEN, "environment": "production", "clear_webhook": True},
    )
    assert resp.status_code == 200
    assert store.get_setting("square.webhook_signature_key") is None
    assert store.get_setting("square.webhook_url") is None

    body = make_webhook_event("PAY_DISABLED_HOOK")
    webhook_resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert webhook_resp.status_code == 403


def test_square_settings_failure_rolls_back_entire_bundle(configured):
    store = configured.app.state.store
    keys = (
        "square.access_token",
        "square.environment",
        "square.webhook_signature_key",
        "square.webhook_url",
    )
    before = store.get_settings(keys)
    store._db.execute(
        "CREATE TRIGGER reject_webhook_url BEFORE UPDATE ON settings "
        "WHEN NEW.key = 'square.webhook_url' BEGIN "
        "SELECT RAISE(ABORT, 'simulated settings failure'); END"
    )
    store._db.commit()

    with pytest.raises(sqlite3.IntegrityError, match="simulated settings failure"):
        configured.put(
            "/api/settings/square",
            json={
                "access_token": SQUARE_TOKEN,
                "environment": "production",
                "webhook_signature_key": "replacement-signature-key",
                "webhook_url": "https://replacement.example/webhooks/square",
            },
        )

    assert store.get_settings(keys) == before

def test_two_pos_devices_map_to_distinct_camera_evidence(configured, monkeypatch):
    snapshot_requests = []

    def record_snapshot(_self, camera_id, ts_ms=None, width=640):
        snapshot_requests.append((camera_id, ts_ms))
        return b"snapshot:" + camera_id.encode()

    monkeypatch.setattr(ProtectClient, "get_snapshot", record_snapshot)
    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "device_id": "TERM_A",
                    "device_name": "Register A",
                    "camera_id": CAM1,
                    "camera_name": "Front Counter",
                },
                {
                    "location_id": "LOC1",
                    "device_id": "TERM_B",
                    "device_name": "Register B",
                    "camera_id": CAM2,
                    "camera_name": "Back Door",
                },
            ]
        },
    )
    assert resp.status_code == 200
    assert configured.get("/api/camera-mapping").json() == [
        {
            "location_id": "LOC1",
            "device_id": "TERM_A",
            "device_name": "Register A",
            "camera_id": CAM1,
            "camera_name": "Front Counter",
        },
        {
            "location_id": "LOC1",
            "device_id": "TERM_B",
            "device_name": "Register B",
            "camera_id": CAM2,
            "camera_name": "Back Door",
        },
    ]

    for payment_id, device_id, device_name in (
        ("PAY_TERM_A", "TERM_A", "Register A"),
        ("PAY_TERM_B", "TERM_B", "Register B"),
    ):
        body = make_webhook_event(payment_id, device_id, device_name)
        resp = configured.post(
            "/webhooks/square",
            content=body,
            headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
        )
        assert resp.status_code == 200

    for payment_id, device_id, camera_id in (
        ("PAY_TERM_A", "TERM_A", CAM1),
        ("PAY_TERM_B", "TERM_B", CAM2),
    ):
        # Thumbnails attach asynchronously after the webhook ack.
        txn = _wait_for_thumbnail(configured, payment_id)
        assert txn["device_id"] == device_id
        assert txn["camera_id"] == camera_id
        assert txn["deep_link"] == (
            f"https://192.168.1.1/protect/timelapse/{camera_id}?start={txn['ts_ms']}"
        )
        thumbnail = configured.get(txn["thumbnail_url"])
        assert thumbnail.status_code == 200
        assert camera_id.encode() in thumbnail.content

    assert sorted(camera_id for camera_id, _ in snapshot_requests) == [CAM1, CAM2]
    assert configured.get("/api/pos-devices").json() == [
        {"location_id": "LOC1", "device_id": "TERM_A", "device_name": "Register A"},
        {"location_id": "LOC1", "device_id": "TERM_B", "device_name": "Register B"},
    ]

def test_payment_without_device_uses_location_fallback(configured, monkeypatch):
    snapshot_requests = []

    def record_snapshot(_self, camera_id, ts_ms=None, width=640):
        snapshot_requests.append(camera_id)
        return b"snapshot:" + camera_id.encode()

    monkeypatch.setattr(ProtectClient, "get_snapshot", record_snapshot)
    resp = configured.put(
        "/api/camera-mapping",
        json={
            "mappings": [
                {
                    "location_id": "LOC1",
                    "camera_id": CAM1,
                    "camera_name": "Front Counter",
                },
                {
                    "location_id": "LOC1",
                    "device_id": "TERM_A",
                    "device_name": "Register A",
                    "camera_id": CAM2,
                    "camera_name": "Back Door",
                },
            ]
        },
    )
    assert resp.status_code == 200

    body = make_webhook_event("PAY_NO_DEVICE")
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    # Thumbnails attach asynchronously after the webhook ack.
    txn = _wait_for_thumbnail(configured, "PAY_NO_DEVICE")
    assert txn["device_id"] == ""
    assert txn["camera_id"] == CAM1
    assert f"/timelapse/{CAM1}?start=" in txn["deep_link"]
    assert snapshot_requests == [CAM1]

def test_sparse_payment_update_preserves_device_camera_evidence(configured, monkeypatch):
    snapshot_requests = []

    def record_snapshot(_self, camera_id, ts_ms=None, width=640):
        snapshot_requests.append(camera_id)
        return b"snapshot:" + camera_id.encode()

    monkeypatch.setattr(ProtectClient, "get_snapshot", record_snapshot)
    mapping = {
        "mappings": [
            {
                "location_id": "LOC1",
                "camera_id": CAM2,
                "camera_name": "Back Door",
            },
            {
                "location_id": "LOC1",
                "device_id": "TERM_A",
                "device_name": "Register A",
                "camera_id": CAM1,
                "camera_name": "Front Counter",
            },
        ]
    }
    assert configured.put("/api/camera-mapping", json=mapping).status_code == 200

    initial_body = make_webhook_event("PAY_SPARSE", "TERM_A", "Register A")
    initial_payment = json.loads(initial_body)["data"]["object"]["payment"]
    ingest_payment(configured.app.state.store, initial_payment, protect=None)

    sparse_body = make_webhook_event(
        "PAY_SPARSE", updated_at="2026-07-16T16:01:00.000Z"
    )
    resp = configured.post(
        "/webhooks/square",
        content=sparse_body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(sparse_body)},
    )
    assert resp.status_code == 200
    # The thumbnail attaches asynchronously after the webhook ack.
    txn = _wait_for_thumbnail(configured, "PAY_SPARSE")
    original_image = configured.get(txn["thumbnail_url"]).content
    assert txn["device_id"] == "TERM_A"
    assert txn["camera_id"] == CAM1
    assert CAM1.encode() in original_image
    assert snapshot_requests == [CAM1]

    mapping["mappings"][1]["camera_id"] = CAM2
    mapping["mappings"][1]["camera_name"] = "Back Door"
    assert configured.put("/api/camera-mapping", json=mapping).status_code == 200
    snapshot_requests.clear()
    resp = configured.post(
        "/webhooks/square",
        content=sparse_body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(sparse_body)},
    )
    assert resp.status_code == 200

    txn = next(
        item
        for item in configured.get("/api/transactions").json()
        if item["id"] == "PAY_SPARSE"
    )
    assert txn["device_id"] == "TERM_A"
    assert txn["camera_id"] == CAM1
    assert f"/timelapse/{CAM1}?start=" in txn["deep_link"]
    assert configured.get(txn["thumbnail_url"]).content == original_image
    assert snapshot_requests == []

def _enable_alarm(client):
    resp = client.put(
        "/api/settings/protect",
        json={
            "host": "192.168.1.1",
            "username": PROTECT_USER,
            "password": PROTECT_PASS,
            "api_key": PROTECT_API_KEY,
            "alarm_trigger_id": PROTECT_ALARM_TRIGGER_ID,
        },
    )
    assert resp.status_code == 200, resp.text

def test_enable_before_first_sync_suppresses_backfill_then_triggers_live_sale(configured):
    _enable_alarm(configured)

    assert configured.post("/api/sync").status_code == 200
    assert PROTECT_ALARM_CALLS == []
    assert configured.post("/api/sync").status_code == 200

    body = make_webhook_event(
        "PAY_LIVE", created_at="2099-07-16T16:00:00.000Z"
    )
    assert configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    ).status_code == 200
    _wait_for_alarm_state(configured, "PAY_LIVE", "sent")
    assert PROTECT_ALARM_CALLS == [PROTECT_ALARM_TRIGGER_ID]

    assert configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    ).status_code == 200
    _wait_for_protect_jobs(configured)
    assert PROTECT_ALARM_CALLS == [PROTECT_ALARM_TRIGGER_ID]

def test_enabling_alarm_does_not_replay_existing_completed_sales(configured):
    assert configured.post("/api/sync").status_code == 200
    _enable_alarm(configured)

    assert configured.post("/api/sync").status_code == 200
    assert PROTECT_ALARM_CALLS == []

def test_pending_payment_triggers_when_it_becomes_completed(configured):
    _enable_alarm(configured)

    pending = make_webhook_event(
        "PAY_TRANSITION",
        status="PENDING",
        created_at="2099-07-16T16:00:00.000Z",
    )
    assert configured.post(
        "/webhooks/square",
        content=pending,
        headers={"x-square-hmacsha256-signature": _webhook_signature(pending)},
    ).status_code == 200
    assert PROTECT_ALARM_CALLS == []

    completed = make_webhook_event(
        "PAY_TRANSITION",
        status="COMPLETED",
        created_at="2099-07-16T16:00:00.000Z",
    )
    assert configured.post(
        "/webhooks/square",
        content=completed,
        headers={"x-square-hmacsha256-signature": _webhook_signature(completed)},
    ).status_code == 200
    _wait_for_alarm_state(configured, "PAY_TRANSITION", "sent")
    assert PROTECT_ALARM_CALLS == [PROTECT_ALARM_TRIGGER_ID]

def test_alarm_failure_persists_transaction_and_retries(configured):
    _enable_alarm(configured)
    PROTECT_ALARM_RESPONSES.extend([500, 204])
    body = make_webhook_event(
        "PAY_RETRY", created_at="2099-07-16T16:00:00.000Z"
    )
    headers = {"x-square-hmacsha256-signature": _webhook_signature(body)}

    assert configured.post("/webhooks/square", content=body, headers=headers).status_code == 200
    transaction = _wait_for_alarm_state(configured, "PAY_RETRY", "idle")
    deadline = time.monotonic() + 3
    while not PROTECT_ALARM_CALLS and time.monotonic() < deadline:
        time.sleep(0.01)
    assert transaction is not None
    assert transaction["alarm_state"] == "idle"
    assert PROTECT_ALARM_CALLS

    assert configured.post("/api/sync").status_code == 200
    assert configured.app.state.store.get_transaction("PAY_RETRY")["alarm_state"] == "sent"
    assert len(PROTECT_ALARM_CALLS) == 2

    assert configured.post("/webhooks/square", content=body, headers=headers).status_code == 200
    _wait_for_protect_jobs(configured)
    assert len(PROTECT_ALARM_CALLS) == 2

def test_webhook_ignores_non_payment_events(configured):
    body = json.dumps({"type": "inventory.count.updated", "data": {}}).encode()
    resp = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )
    assert resp.status_code == 200
    assert resp.json().get("ignored") is True


# -- Square connection health indicator ----------------------------------------------

def test_square_health_unconfigured(authed):
    health = authed.get("/api/health/square").json()
    assert health == {"configured": False, "ok": False, "detail": "Not configured"}

def test_square_health_connected(configured):
    health = configured.get("/api/health/square").json()
    assert health["configured"] is True
    assert health["ok"] is True
    assert health["locations"] == 1
    assert "Connected" in health["detail"]

def test_square_health_reports_revoked_token(configured, monkeypatch):
    from app.square_client import SquareAuthError, SquareClient

    def rejected(_self):
        raise SquareAuthError("Square rejected the access token")

    monkeypatch.setattr(SquareClient, "list_locations", rejected)
    health = configured.get("/api/health/square").json()
    assert health["configured"] is True
    assert health["ok"] is False
    assert "rejected" in health["detail"]

def test_square_health_requires_auth(client):
    assert client.get("/api/health/square").status_code == 401

def test_square_status_indicator_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert 'api("/api/health/square")' in js
    assert "refreshSquareStatus" in js
    assert 'id="square-status"' in html


# -- Protect connection health indicator ---------------------------------------------

def test_protect_health_unconfigured(authed):
    health = authed.get("/api/health/protect").json()
    assert health == {"configured": False, "ok": False, "detail": "Not configured"}

def test_protect_health_connected(configured):
    health = configured.get("/api/health/protect").json()
    assert health["configured"] is True
    assert health["ok"] is True
    assert health["cameras"] == 2
    assert "Connected" in health["detail"]

def test_protect_health_reports_outage(tmp_path):
    calls = {"n": 0}

    def flaky_protect(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] > 2:  # healthy during settings save, down afterwards
            raise httpx.ConnectError("console offline", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(flaky_protect),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/api/setup", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.post("/api/login", json={"password": ADMIN_PASSWORD}).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={"host": "192.168.1.1", "username": PROTECT_USER, "password": PROTECT_PASS},
            ).status_code == 200
            health = isolated.get("/api/health/protect").json()
        assert health["configured"] is True
        assert health["ok"] is False
        assert "console offline" not in health["detail"]  # no raw upstream detail
    finally:
        app.state.store.close()

def test_protect_health_requires_auth(client):
    assert client.get("/api/health/protect").status_code == 401

def test_protect_status_indicator_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert 'api("/api/health/protect")' in js
    assert "refreshProtectStatus" in js
    assert 'id="protect-status"' in html


# -- status dashboard ---------------------------------------------------------------

def test_dashboard_requires_auth(client):
    assert client.get("/api/dashboard").status_code == 401

def test_dashboard_unconfigured(authed):
    data = authed.get("/api/dashboard").json()
    assert data["protect"]["configured"] is False
    assert data["square"]["configured"] is False
    assert data["webhook"] == {"configured": False, "last_event_ms": None}
    assert data["queues"] == {"thumbnails_pending": 0, "alarms_pending": 0}

def test_dashboard_connected_with_webhook_freshness(configured):
    body = make_webhook_event("PAY_DASH")
    assert configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    ).status_code == 200
    _wait_for_protect_jobs(configured)

    data = configured.get("/api/dashboard").json()
    assert data["protect"]["ok"] is True
    assert "cameras" in data["protect"]["detail"]
    assert data["square"]["ok"] is True
    assert data["webhook"]["configured"] is True
    assert isinstance(data["webhook"]["last_event_ms"], int)
    assert data["queues"]["thumbnails_pending"] == 0

def test_dashboard_counts_pending_queue_work(configured):
    store = configured.app.state.store
    store.upsert_transaction(
        {
            "id": "PAY_QUEUED_TILE",
            "created_at": "2026-07-16T15:30:00.000Z",
            "ts_ms": 1784215800000,
            "amount": 100,
            "currency": "USD",
            "status": "COMPLETED",
            "location_id": "LOC1",
            "camera_id": CAM1,
            "thumbnail_path": None,
        }
    )
    data = configured.get("/api/dashboard").json()
    assert data["queues"]["thumbnails_pending"] == 1

def test_dashboard_tiles_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text()
    html = (static_dir / "index.html").read_text()
    assert 'api("/api/dashboard")' in js
    assert "startDashboardRefresh" in js
    for tile in ("protect", "square", "webhook", "queues"):
        assert f'data-tile="{tile}"' in html


def test_sync_ingests_square_facts_when_protect_console_unreachable(tmp_path):
    """A Protect outage defers camera evidence but must not block ingestion."""
    protect_down = {"value": False}

    def flaky_protect(request: httpx.Request) -> httpx.Response:
        if protect_down["value"]:
            raise httpx.ConnectError("console offline", request=request)
        return protect_handler(request)

    app = create_app(
        data_dir=tmp_path / "data",
        protect_transport=httpx.MockTransport(flaky_protect),
        square_transport=httpx.MockTransport(square_handler),
        enable_poller=False,
    )
    try:
        with TestClient(app) as isolated:
            assert isolated.post(
                "/api/setup", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.post(
                "/api/login", json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            assert isolated.put(
                "/api/settings/protect",
                json={
                    "host": "192.168.1.1",
                    "username": PROTECT_USER,
                    "password": PROTECT_PASS,
                },
            ).status_code == 200
            assert isolated.put(
                "/api/settings/square",
                json={"access_token": SQUARE_TOKEN, "environment": "sandbox"},
            ).status_code == 200

            protect_down["value"] = True
            resp = isolated.post("/api/sync")
            assert resp.status_code == 200
            assert resp.json()["ingested"] > 0
            txns = isolated.get("/api/transactions").json()
            assert txns
            assert all(txn["thumbnail_url"] is None for txn in txns)
    finally:
        app.state.store.close()
