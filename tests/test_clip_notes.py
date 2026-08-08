"""Searchable per-transaction camera-clip note coverage."""

from __future__ import annotations

from app.store import ROLE_VIEWER


VIEWER_PASSWORD = "clip-note-viewer-password"


def _sync(configured):
    response = configured.post("/api/sync")
    assert response.status_code == 200, response.text


def _transaction(configured, transaction_id):
    rows = configured.post("/api/transactions", json={}).json()
    return next(row for row in rows if row["id"] == transaction_id)


def _set_note(configured, transaction_id, note, revision):
    return configured.put(
        f"/api/transactions/{transaction_id}/note",
        json={"note": note, "revision": revision},
    )


def test_admin_note_is_returned_searchable_and_preserved_by_square_sync(configured):
    _sync(configured)
    initial = _transaction(configured, "PAY_001")
    assert initial["note"] == ""
    assert initial["note_revision"] == 0

    saved = _set_note(
        configured,
        "PAY_001",
        "Investigate cash drawer variance",
        initial["note_revision"],
    )
    assert saved.status_code == 200
    assert saved.json()["note_revision"] == 1
    assert _transaction(configured, "PAY_001")["note"] == (
        "Investigate cash drawer variance"
    )

    search = configured.post(
        "/api/transactions",
        json={"q": "CASH DRAWER"},
    )
    assert search.status_code == 200
    assert [row["id"] for row in search.json()] == ["PAY_001"]

    _sync(configured)
    preserved = _transaction(configured, "PAY_001")
    assert preserved["note"] == "Investigate cash drawer variance"
    assert preserved["note_revision"] == 1


def test_note_search_escapes_sql_wildcards_as_literal_text(configured):
    _sync(configured)
    assert _set_note(configured, "PAY_001", "variance %_ exact", 0).status_code == 200

    response = configured.post("/api/transactions", json={"q": "%_"})

    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == ["PAY_001"]


def test_viewer_can_read_and_search_notes_but_cannot_edit_them(configured):
    _sync(configured)
    assert _set_note(configured, "PAY_001", "Review red jacket", 0).status_code == 200
    created = configured.post(
        "/api/users",
        json={
            "username": "note.viewer",
            "role": ROLE_VIEWER,
            "password": VIEWER_PASSWORD,
        },
    )
    assert created.status_code == 201
    assert configured.post("/api/logout").status_code == 200
    assert configured.post(
        "/api/login",
        json={"username": "note.viewer", "password": VIEWER_PASSWORD},
    ).status_code == 200

    search = configured.post("/api/transactions", json={"q": "red jacket"})
    assert search.status_code == 200
    assert search.json()[0]["note"] == "Review red jacket"
    denied = _set_note(configured, "PAY_001", "viewer overwrite", 1)
    assert denied.status_code == 403


def test_note_updates_are_idempotent_and_reject_stale_editors(configured):
    _sync(configured)
    first = _set_note(configured, "PAY_001", "First review", 0)
    assert first.status_code == 200
    assert first.json()["note_revision"] == 1

    unchanged = _set_note(configured, "PAY_001", "First review", 1)
    assert unchanged.status_code == 200
    assert unchanged.json()["note_revision"] == 1

    stale = _set_note(configured, "PAY_001", "Stale overwrite", 0)
    assert stale.status_code == 409
    assert stale.json()["detail"] == (
        "Note changed in another session; reload and try again"
    )
    assert _transaction(configured, "PAY_001")["note"] == "First review"

    cleared = _set_note(configured, "PAY_001", "", 1)
    assert cleared.status_code == 200
    assert cleared.json()["note_revision"] == 2
    assert _transaction(configured, "PAY_001")["note"] == ""


def test_note_changes_expire_filtered_but_not_unfiltered_page_snapshots(configured):
    _sync(configured)
    assert _set_note(configured, "PAY_001", "flagged review", 0).status_code == 200
    assert _set_note(configured, "PAY_002", "flagged review", 0).status_code == 200

    filtered = configured.post(
        "/api/transactions",
        json={"limit": 1, "q": "flagged"},
    )
    filtered_snapshot = int(filtered.headers["x-transaction-snapshot"])
    assert _set_note(configured, "PAY_001", "resolved", 1).status_code == 200
    continuation = configured.post(
        "/api/transactions",
        json={
            "limit": 1,
            "offset": 1,
            "snapshot": filtered_snapshot,
            "q": "flagged",
        },
    )
    assert continuation.status_code == 409

    unfiltered = configured.post("/api/transactions", json={"limit": 1})
    unfiltered_snapshot = int(unfiltered.headers["x-transaction-snapshot"])
    assert _set_note(configured, "PAY_002", "still flagged", 1).status_code == 200
    unfiltered_continuation = configured.post(
        "/api/transactions",
        json={
            "limit": 1,
            "offset": 1,
            "snapshot": unfiltered_snapshot,
        },
    )
    assert unfiltered_continuation.status_code == 200
    assert len(unfiltered_continuation.json()) == 1


def test_note_endpoint_validates_target_body_and_revision(configured):
    _sync(configured)
    assert _set_note(configured, "MISSING", "note", 0).status_code == 404
    assert _set_note(configured, "PAY_001", "x" * 2001, 0).status_code == 422
    assert _set_note(configured, "PAY_001", "note", -1).status_code == 422
    assert _set_note(configured, "PAY_001", "bad\x00note", 0).status_code == 422
    assert _set_note(configured, "PAY_001", "line one\nline two", 0).status_code == 200
    too_long_id = "T" * 256
    assert _set_note(configured, too_long_id, "note", 0).status_code == 422
