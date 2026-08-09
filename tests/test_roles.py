"""Role migration, authentication, and authorization regression tests."""

from __future__ import annotations

import sqlite3
import time

import pytest
from fastapi.routing import APIRoute

import app.main as main_module
from app.security import hash_password, hash_session_token
from app.store import ROLE_ADMIN, ROLE_VIEWER, Store, normalize_username

from .conftest import ADMIN_PASSWORD, bootstrap_setup_body


VIEWER_USERNAME = "barn.viewer"
VIEWER_PASSWORD = "view-only-password"

ADMIN_ENDPOINTS = frozenset(
    {
        ("DELETE", "/api/settings/protect/alarm"),
        ("POST", "/api/discover/protect"),
        ("POST", "/api/settings/protect/console-switch-token"),
        ("PUT", "/api/settings/protect"),
        ("PUT", "/api/settings/square"),
        ("GET", "/api/settings/deep-link"),
        ("PUT", "/api/settings/deep-link"),
        ("POST", "/api/settings/square/webhook/register"),
        ("PUT", "/api/settings/square/oauth-app"),
        ("GET", "/oauth/square/start"),
        ("GET", "/oauth/square/callback"),
        ("POST", "/api/settings/square/oauth-switch/confirm"),
        ("DELETE", "/api/settings/square/oauth-switch"),
        ("GET", "/api/health/protect"),
        ("GET", "/api/cameras"),
        ("GET", "/api/health/square"),
        ("GET", "/api/locations"),
        ("GET", "/api/pos-devices"),
        ("GET", "/api/camera-preview/{camera_id}"),
        ("GET", "/api/camera-mapping"),
        ("PUT", "/api/camera-mapping"),
        ("POST", "/api/sync"),
    }
)

VIEWER_ENDPOINTS = frozenset(
    {
        ("GET", "/api/session"),
        ("POST", "/api/logout"),
        ("GET", "/api/dashboard"),
        ("GET", "/api/transactions/export.csv"),
        ("GET", "/api/transactions"),
        ("POST", "/api/transactions"),
        ("GET", "/api/thumbnails/{txn_id}"),
        ("GET", "/api/settings/thumbnail-storage"),
        ("PUT", "/api/settings/thumbnail-storage"),
        ("POST", "/api/settings/thumbnail-storage/maintenance"),
    }
)

PUBLIC_ENDPOINTS = frozenset(
    {
        ("GET", "/api/status"),
        ("POST", "/api/setup"),
        ("POST", "/api/login"),
        ("POST", "/webhooks/square"),
    }
)


def _create_viewer(client) -> None:
    client.app.state.store.create_user(
        VIEWER_USERNAME,
        hash_password(VIEWER_PASSWORD),
        ROLE_VIEWER,
    )


def _login_viewer(client) -> dict:
    response = client.post(
        "/api/login",
        json={"username": VIEWER_USERNAME, "password": VIEWER_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_setup_creates_named_administrator_and_legacy_login_still_works(client):
    setup = client.post("/api/setup", json=bootstrap_setup_body())
    assert setup.status_code == 200
    assert setup.json() == {"ok": True, "username": "admin"}
    assert client.app.state.store.get_setting("admin.password_hash") is None

    login = client.post("/api/login", json={"password": ADMIN_PASSWORD})
    assert login.status_code == 200
    assert login.json() == {
        "ok": True,
        "user": {"username": "admin", "role": ROLE_ADMIN},
    }
    assert client.get("/api/session").json() == {
        "user": {"username": "admin", "role": ROLE_ADMIN}
    }


def test_named_login_is_case_insensitive_and_returns_viewer_identity(client):
    assert client.post("/api/setup", json=bootstrap_setup_body()).status_code == 200
    _create_viewer(client)

    response = client.post(
        "/api/login",
        json={"username": "BARN.VIEWER", "password": VIEWER_PASSWORD},
    )
    assert response.status_code == 200
    assert response.json()["user"] == {
        "username": VIEWER_USERNAME,
        "role": ROLE_VIEWER,
    }
    assert client.get("/api/session").json()["user"]["role"] == ROLE_VIEWER


def test_unknown_username_uses_bounded_dummy_password_verification(client, monkeypatch):
    assert client.post("/api/setup", json=bootstrap_setup_body()).status_code == 200
    observed_hashes = []

    def reject_password(_password, stored_hash):
        observed_hashes.append(stored_hash)
        return False

    monkeypatch.setattr(main_module, "verify_password", reject_password)
    response = client.post(
        "/api/login",
        json={"username": "does-not-exist", "password": "irrelevant"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"
    assert observed_hashes == [main_module.DUMMY_PASSWORD_HASH]


def test_viewer_can_read_transaction_evidence_but_cannot_force_sync(configured):
    assert configured.post("/api/sync").status_code == 200
    _create_viewer(configured)
    assert configured.post("/api/logout").status_code == 200
    assert _login_viewer(configured)["user"]["role"] == ROLE_VIEWER

    responses = (
        configured.get("/api/dashboard"),
        configured.get("/api/transactions"),
        configured.post("/api/transactions", json={}),
        configured.get("/api/transactions/export.csv"),
        configured.get("/api/thumbnails/PAY_001"),
    )
    assert [response.status_code for response in responses] == [200] * len(responses)
    assert configured.post("/api/sync").status_code == 403


def _dependency_names(dependant) -> set[str]:
    names = set()
    for dependency in dependant.dependencies:
        if dependency.call is not None:
            names.add(dependency.call.__name__)
        names.update(_dependency_names(dependency))
    return names


def test_every_application_route_has_an_explicit_authorization_class(client):
    routes = {}
    for route in client.app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            routes[(method, route.path)] = _dependency_names(route.dependant)

    expected = PUBLIC_ENDPOINTS | VIEWER_ENDPOINTS | ADMIN_ENDPOINTS
    assert set(routes) == expected
    for endpoint in PUBLIC_ENDPOINTS:
        assert "require_session" not in routes[endpoint]
        assert "require_admin" not in routes[endpoint]
    for endpoint in VIEWER_ENDPOINTS:
        assert "require_session" in routes[endpoint]
        assert "require_admin" not in routes[endpoint]
    for endpoint in ADMIN_ENDPOINTS:
        assert "require_session" in routes[endpoint]
        assert "require_admin" in routes[endpoint]


@pytest.mark.parametrize(
    ("method", "path", "body"),
    (
        ("DELETE", "/api/settings/protect/alarm", None),
        ("POST", "/api/discover/protect", {}),
        (
            "POST",
            "/api/settings/protect/console-switch-token",
            {"host": "192.168.1.1", "username": "user", "password": "password"},
        ),
        (
            "PUT",
            "/api/settings/protect",
            {"host": "192.168.1.1", "username": "user", "password": "password"},
        ),
        (
            "PUT",
            "/api/settings/square",
            {"access_token": "sandbox-token", "environment": "sandbox"},
        ),
        ("GET", "/api/settings/deep-link", None),
        ("PUT", "/api/settings/deep-link", {"template": ""}),
        (
            "POST",
            "/api/settings/square/webhook/register",
            {"notification_url": "https://shop.example/webhooks/square"},
        ),
        (
            "PUT",
            "/api/settings/square/oauth-app",
            {
                "client_id": "sandbox-app-id",
                "client_secret": "sandbox-app-secret",
                "environment": "sandbox",
            },
        ),
        ("GET", "/oauth/square/start", None),
        ("GET", "/oauth/square/callback", None),
        ("POST", "/api/settings/square/oauth-switch/confirm", None),
        ("DELETE", "/api/settings/square/oauth-switch", None),
        ("GET", "/api/health/protect", None),
        ("GET", "/api/cameras", None),
        ("GET", "/api/health/square", None),
        ("GET", "/api/locations", None),
        ("GET", "/api/pos-devices", None),
        ("GET", "/api/camera-preview/cam1aaaaaaaaaaaaaaaaaaaaa", None),
        ("GET", "/api/camera-mapping", None),
        ("PUT", "/api/camera-mapping", {"mappings": []}),
        ("POST", "/api/sync", None),
    ),
)
def test_every_administration_endpoint_rejects_viewer(client, method, path, body):
    assert client.post("/api/setup", json=bootstrap_setup_body()).status_code == 200
    _create_viewer(client)
    _login_viewer(client)

    options = {"json": body} if body is not None else {}
    response = client.request(method, path, **options)

    assert response.status_code == 403, (path, response.text)
    assert response.json()["detail"] == "Administrator access required"


def test_disabled_account_invalidates_its_existing_session(client):
    assert client.post("/api/setup", json=bootstrap_setup_body()).status_code == 200
    _create_viewer(client)
    _login_viewer(client)
    token = client.cookies.get("spi_session")
    store = client.app.state.store

    with store._lock:
        store._db.execute(
            "UPDATE users SET enabled = 0 WHERE username = ? COLLATE NOCASE",
            (VIEWER_USERNAME,),
        )
        store._db.commit()

    assert client.get("/api/session").status_code == 401
    with store._lock:
        session = store._db.execute(
            "SELECT 1 FROM sessions WHERE token_hash = ?",
            (hash_session_token(token),),
        ).fetchone()
    assert session is None


def test_legacy_admin_and_sessions_migrate_atomically(tmp_path):
    data_dir = tmp_path / "legacy"
    data_dir.mkdir()
    legacy_hash = hash_password(ADMIN_PASSWORD)
    legacy_token = "legacy-session-token"
    with sqlite3.connect(data_dir / "spi.db") as connection:
        connection.execute(
            "CREATE TABLE settings ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL, "
            "encrypted INTEGER NOT NULL DEFAULT 0)"
        )
        connection.execute(
            "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, 0)",
            ("admin.password_hash", legacy_hash),
        )
        connection.execute(
            "CREATE TABLE sessions ("
            "token_hash TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)",
            (hash_session_token(legacy_token), time.time() + 3600),
        )

    store = Store(data_dir)
    try:
        account = store.user_for_login("ADMIN")
        assert account is not None
        assert account["password_hash"] == legacy_hash
        assert account["role"] == ROLE_ADMIN
        assert store.get_setting("admin.password_hash") is None
        assert store.session_user(legacy_token) == {
            "id": account["id"],
            "username": "admin",
            "role": ROLE_ADMIN,
        }
        with store._lock:
            session_columns = {
                row["name"]
                for row in store._db.execute("PRAGMA table_info(sessions)")
            }
        assert session_columns == {"token_hash", "user_id", "expires_at"}
    finally:
        store.close()

    reopened = Store(data_dir)
    try:
        assert reopened.user_for_login("admin")["password_hash"] == legacy_hash
        assert reopened.session_user(legacy_token)["role"] == ROLE_ADMIN
    finally:
        reopened.close()


def test_legacy_sessions_without_an_admin_are_not_reassigned(tmp_path):
    data_dir = tmp_path / "legacy-no-admin"
    data_dir.mkdir()
    legacy_token = "orphaned-session-token"
    with sqlite3.connect(data_dir / "spi.db") as connection:
        connection.execute(
            "CREATE TABLE settings ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL, "
            "encrypted INTEGER NOT NULL DEFAULT 0)"
        )
        connection.execute(
            "CREATE TABLE sessions ("
            "token_hash TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)",
            (hash_session_token(legacy_token), time.time() + 3600),
        )

    store = Store(data_dir)
    try:
        assert store.setup_complete() is False
        assert store.session_user(legacy_token) is None
    finally:
        store.close()


@pytest.mark.parametrize(
    "username",
    ("", "name with space", ".leading-dot", "café", "a" * 65),
)
def test_username_validation_rejects_ambiguous_or_unbounded_values(username):
    with pytest.raises(ValueError):
        normalize_username(username)


def test_username_normalization_trims_accidental_outer_whitespace():
    assert normalize_username("  barn.viewer  ") == "barn.viewer"


def test_store_enforces_case_insensitive_unique_usernames(tmp_path):
    store = Store(tmp_path / "accounts")
    try:
        account = store.create_user(
            "Desk.Viewer",
            hash_password(VIEWER_PASSWORD),
            ROLE_VIEWER,
        )
        assert account["username"] == "Desk.Viewer"
        assert store.user_for_login("desk.viewer")["id"] == account["id"]
        with pytest.raises(sqlite3.IntegrityError):
            store.create_user(
                "DESK.VIEWER",
                hash_password("another-password"),
                ROLE_VIEWER,
            )
    finally:
        store.close()
