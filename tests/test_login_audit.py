"""Append-only administrator login-history tests."""

from __future__ import annotations

import sqlite3

import pytest

from app.store import ROLE_ADMIN, ROLE_VIEWER

from .conftest import ADMIN_PASSWORD, bootstrap_setup_body


VIEWER_PASSWORD = "login-history-viewer-password"


def test_successful_login_is_recorded_with_identity_role_ip_and_time(authed):
    response = authed.get("/api/login-audit")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    payload = response.json()
    assert payload["next_before_id"] is None
    assert len(payload["events"]) == 1
    event = payload["events"][0]
    assert event["id"] == 1
    assert event["user_id"] == 1
    assert event["username"] == "admin"
    assert event["role"] == ROLE_ADMIN
    assert event["client_ip"] == "127.0.0.1"
    assert isinstance(event["logged_in_at"], float)
    assert ADMIN_PASSWORD not in response.text


def test_failed_credentials_do_not_create_successful_login_record(client):
    assert client.post("/api/setup", json=bootstrap_setup_body()).status_code == 200
    failed = client.post(
        "/api/login",
        json={"username": "admin", "password": "incorrect-password"},
    )
    assert failed.status_code == 401
    assert client.app.state.store.list_login_audit() == ([], None)

    assert client.post(
        "/api/login",
        json={"username": "admin", "password": ADMIN_PASSWORD},
    ).status_code == 200
    events, cursor = client.app.state.store.list_login_audit()
    assert cursor is None
    assert [event["username"] for event in events] == ["admin"]


def test_viewer_login_is_recorded_but_history_is_administrator_only(authed):
    created = authed.post(
        "/api/users",
        json={
            "username": "auditor",
            "role": ROLE_VIEWER,
            "password": VIEWER_PASSWORD,
        },
    ).json()["user"]
    assert authed.post(
        "/api/login",
        json={"username": "auditor", "password": VIEWER_PASSWORD},
    ).status_code == 200
    assert authed.get("/api/login-audit").status_code == 403

    assert authed.post(
        "/api/login",
        json={"username": "admin", "password": ADMIN_PASSWORD},
    ).status_code == 200
    events = authed.get("/api/login-audit").json()["events"]
    viewer_event = next(event for event in events if event["user_id"] == created["id"])
    assert viewer_event["username"] == "auditor"
    assert viewer_event["role"] == ROLE_VIEWER


def test_login_history_uses_stable_cursor_pagination_without_duplicates(authed):
    store = authed.app.state.store
    account = store.user_for_login("admin")
    for index in range(4):
        store.create_session(
            f"audit-session-{index}",
            account["id"],
            account["auth_revision"],
            f"192.0.2.{index + 1}",
        )

    first = authed.get("/api/login-audit?limit=2").json()
    second = authed.get(
        f"/api/login-audit?limit=2&before_id={first['next_before_id']}"
    ).json()
    third = authed.get(
        f"/api/login-audit?limit=2&before_id={second['next_before_id']}"
    ).json()

    ids = [
        event["id"]
        for page in (first, second, third)
        for event in page["events"]
    ]
    assert ids == [5, 4, 3, 2, 1]
    assert len(ids) == len(set(ids))
    assert first["next_before_id"] == 4
    assert second["next_before_id"] == 2
    assert third["next_before_id"] is None


@pytest.mark.parametrize(
    "query",
    ("limit=0", "limit=251", "before_id=0", "limit=not-a-number"),
)
def test_login_history_rejects_invalid_pagination(authed, query):
    assert authed.get(f"/api/login-audit?{query}").status_code == 422


def test_login_history_is_append_only_at_the_storage_boundary(authed):
    store = authed.app.state.store
    with store._lock:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._db.execute(
                "UPDATE login_audit SET username = 'changed' WHERE id = 1"
            )
        store._db.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._db.execute("DELETE FROM login_audit WHERE id = 1")
        store._db.rollback()
    events, _ = store.list_login_audit()
    assert [(event["id"], event["username"]) for event in events] == [(1, "admin")]


def test_session_and_audit_insert_roll_back_together_on_audit_failure(authed):
    store = authed.app.state.store
    account = store.user_for_login("admin")
    with store._lock:
        store._db.execute(
            "CREATE TRIGGER fail_login_audit_insert "
            "BEFORE INSERT ON login_audit BEGIN "
            "SELECT RAISE(ABORT, 'simulated audit failure'); END"
        )
        store._db.commit()

    with pytest.raises(sqlite3.IntegrityError, match="simulated audit failure"):
        store.create_session(
            "must-roll-back",
            account["id"],
            account["auth_revision"],
            "192.0.2.10",
        )
    assert store.session_user("must-roll-back") is None
    events, _ = store.list_login_audit()
    assert len(events) == 1
