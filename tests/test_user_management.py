"""Administrator-managed local account API tests."""

from __future__ import annotations

import json
import sqlite3
import time

import pytest

from app.security import hash_password
from app.store import ROLE_ADMIN, ROLE_VIEWER, Store

from .conftest import ADMIN_PASSWORD


VIEWER_PASSWORD = "initial-viewer-password"
NEW_VIEWER_PASSWORD = "replacement-viewer-password"


def _create_user(client, username="auditor", role=ROLE_VIEWER, password=VIEWER_PASSWORD):
    response = client.post(
        "/api/users",
        json={"username": username, "role": role, "password": password},
    )
    assert response.status_code == 201, response.text
    return response.json()["user"]


def test_administrator_can_list_and_create_safe_user_records(authed):
    initial = authed.get("/api/users")
    assert initial.status_code == 200
    assert initial.headers["cache-control"] == "private, no-store"
    assert initial.json()["users"] == [
        {
            "id": 1,
            "username": "admin",
            "role": ROLE_ADMIN,
            "enabled": True,
            "created_at": initial.json()["users"][0]["created_at"],
            "current": True,
        }
    ]

    viewer = _create_user(authed, username="Barn.Viewer")
    administrator = _create_user(
        authed,
        username="shift-admin",
        role=ROLE_ADMIN,
        password="another-admin-password",
    )

    assert viewer["username"] == "Barn.Viewer"
    assert viewer["role"] == ROLE_VIEWER
    assert viewer["enabled"] is True
    assert viewer["current"] is False
    assert isinstance(viewer["created_at"], float)
    assert administrator["role"] == ROLE_ADMIN
    listing = authed.get("/api/users").json()["users"]
    assert [user["username"] for user in listing] == [
        "admin",
        "Barn.Viewer",
        "shift-admin",
    ]
    assert sum(user["current"] for user in listing) == 1
    assert "password" not in json.dumps(listing).lower()


def test_duplicate_username_is_case_insensitive_and_conflict_safe(authed):
    _create_user(authed, username="floor.viewer")
    duplicate = authed.post(
        "/api/users",
        json={
            "username": "FLOOR.VIEWER",
            "role": ROLE_VIEWER,
            "password": "different-viewer-password",
        },
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "Username already exists"


@pytest.mark.parametrize(
    ("payload", "expected_status"),
    (
        ({"username": ".hidden", "role": "viewer", "password": "valid-password"}, 422),
        ({"username": "bad name", "role": "viewer", "password": "valid-password"}, 422),
        ({"username": "valid", "role": "owner", "password": "valid-password"}, 422),
        ({"username": "valid", "role": "viewer", "password": "short"}, 422),
        ({"username": "a" * 65, "role": "viewer", "password": "valid-password"}, 422),
    ),
)
def test_user_creation_validates_username_role_and_password(authed, payload, expected_status):
    assert authed.post("/api/users", json=payload).status_code == expected_status


def test_viewer_cannot_list_create_or_reset_accounts(authed):
    viewer = _create_user(authed)
    assert authed.post("/api/logout").status_code == 200
    assert authed.post(
        "/api/login",
        json={"username": "auditor", "password": VIEWER_PASSWORD},
    ).status_code == 200

    responses = (
        authed.get("/api/users"),
        authed.post(
            "/api/users",
            json={
                "username": "forbidden",
                "role": ROLE_VIEWER,
                "password": "forbidden-password",
            },
        ),
        authed.put(
            f"/api/users/{viewer['id']}/password",
            json={"password": NEW_VIEWER_PASSWORD},
        ),
    )
    assert [response.status_code for response in responses] == [403, 403, 403]


def test_password_reset_revokes_all_target_sessions_and_changes_login(authed):
    viewer = _create_user(authed)
    store = authed.app.state.store
    account = store.user_for_login("auditor")
    store.create_session(
        "secondary-viewer-session",
        account["id"],
        account["auth_revision"],
    )

    assert authed.post(
        "/api/login",
        json={"username": "auditor", "password": VIEWER_PASSWORD},
    ).status_code == 200
    browser_viewer_token = authed.cookies.get("spi_session")
    assert authed.post(
        "/api/login",
        json={"username": "admin", "password": ADMIN_PASSWORD},
    ).status_code == 200

    reset = authed.put(
        f"/api/users/{viewer['id']}/password",
        json={"password": NEW_VIEWER_PASSWORD},
    )
    assert reset.status_code == 200
    assert reset.json()["current_session_revoked"] is False
    assert reset.json()["sessions_revoked"] == 2
    assert store.session_user(browser_viewer_token) is None
    assert store.session_user("secondary-viewer-session") is None
    assert authed.post(
        "/api/login",
        json={"username": "auditor", "password": VIEWER_PASSWORD},
    ).status_code == 401
    assert authed.post(
        "/api/login",
        json={"username": "auditor", "password": NEW_VIEWER_PASSWORD},
    ).status_code == 200


def test_password_reset_fences_old_password_login_race(authed):
    viewer = _create_user(authed)
    store = authed.app.state.store
    stale_login = store.user_for_login("auditor")

    reset = authed.put(
        f"/api/users/{viewer['id']}/password",
        json={"password": NEW_VIEWER_PASSWORD},
    )
    assert reset.status_code == 200
    with pytest.raises(ValueError, match="not available"):
        store.create_session(
            "stale-password-race",
            stale_login["id"],
            stale_login["auth_revision"],
        )
    assert store.session_user("stale-password-race") is None


def test_administrator_can_reset_own_password_and_is_signed_out(authed):
    admin = authed.get("/api/users").json()["users"][0]
    new_password = "rotated-administrator-password"

    reset = authed.put(
        f"/api/users/{admin['id']}/password",
        json={"password": new_password},
    )
    assert reset.status_code == 200
    assert reset.json()["current_session_revoked"] is True
    assert reset.json()["sessions_revoked"] == 1
    assert authed.get("/api/session").status_code == 401
    assert authed.post(
        "/api/login", json={"username": "admin", "password": ADMIN_PASSWORD}
    ).status_code == 401
    assert authed.post(
        "/api/login", json={"username": "admin", "password": new_password}
    ).status_code == 200


def test_password_reset_rejects_missing_account_and_weak_password(authed):
    assert authed.put(
        "/api/users/999999/password",
        json={"password": "valid-new-password"},
    ).status_code == 404
    assert authed.put(
        "/api/users/1/password",
        json={"password": "short"},
    ).status_code == 422


def test_new_user_password_is_never_stored_or_returned_in_plaintext(authed, tmp_path):
    unique_password = "plaintext-must-not-survive-92841"
    response = authed.post(
        "/api/users",
        json={
            "username": "safe-user",
            "role": ROLE_VIEWER,
            "password": unique_password,
        },
    )
    assert response.status_code == 201
    assert unique_password not in response.text
    assert unique_password.encode() not in (tmp_path / "data" / "spi.db").read_bytes()


def test_roles_database_migrates_auth_revision_for_reset_race_fence(tmp_path):
    data_dir = tmp_path / "roles-release"
    data_dir.mkdir()
    password_hash = hash_password(ADMIN_PASSWORD)
    with sqlite3.connect(data_dir / "spi.db") as connection:
        connection.execute(
            "CREATE TABLE settings ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL, "
            "encrypted INTEGER NOT NULL DEFAULT 0)"
        )
        connection.execute(
            "CREATE TABLE users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT NOT NULL COLLATE NOCASE UNIQUE, "
            "password_hash TEXT NOT NULL, role TEXT NOT NULL, "
            "enabled INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO users "
            "(username, password_hash, role, enabled, created_at) "
            "VALUES ('admin', ?, 'admin', 1, ?)",
            (password_hash, time.time()),
        )
        connection.execute(
            "CREATE TABLE sessions ("
            "token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, "
            "expires_at REAL NOT NULL)"
        )

    store = Store(data_dir)
    try:
        account = store.user_for_login("admin")
        assert account["auth_revision"] == 0
        with store._lock:
            columns = {
                row["name"]
                for row in store._db.execute("PRAGMA table_info(users)")
            }
        assert "auth_revision" in columns
    finally:
        store.close()
