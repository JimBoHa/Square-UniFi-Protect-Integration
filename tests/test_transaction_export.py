"""Transaction CSV export API coverage."""

from __future__ import annotations

import concurrent.futures
import csv
import io
import threading

import pytest

from .conftest import FAKE_JPEG, SQUARE_TOKEN


EXPORT_HEADERS = [
    "transaction_id",
    "timestamp",
    "amount_minor_units",
    "currency",
    "status",
    "location_id",
    "device_id",
    "device_name",
    "card_last4",
    "receipt_url",
    "protect_timeline_url",
    "note",
]


def _export_rows(response) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(response.text, newline="")))


def test_transaction_export_requires_authentication(client):
    response = client.get("/api/transactions/export.csv")

    assert response.status_code == 401
    assert response.headers["cache-control"] == "private, no-store"


def test_transaction_export_returns_allowlisted_facts_and_timeline_links(configured):
    sync_response = configured.post("/api/sync")
    assert sync_response.status_code == 200, sync_response.text
    listed = configured.get("/api/transactions").json()
    expected_links = {
        str(transaction["amount"]): transaction["deep_link"]
        for transaction in listed
    }

    response = configured.get("/api/transactions/export.csv")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["content-disposition"] == (
        'attachment; filename="square-protect-transactions.csv"'
    )
    assert response.content.endswith(b"\r\n")
    rows = _export_rows(response)
    assert list(rows[0]) == EXPORT_HEADERS
    assert [row["transaction_id"] for row in rows] == ["PAY_002", "PAY_001"]
    assert [row["amount_minor_units"] for row in rows] == ["999", "1250"]
    assert all(row["currency"] == "USD" for row in rows)
    assert all(row["status"] == "COMPLETED" for row in rows)
    assert all(row["location_id"] == "LOC1" for row in rows)
    assert all(
        row["protect_timeline_url"] == expected_links[row["amount_minor_units"]]
        for row in rows
    )
    assert all(row["note"] == "" for row in rows)
    assert SQUARE_TOKEN.encode() not in response.content
    assert FAKE_JPEG not in response.content
    assert b"thumbnail_path" not in response.content
    assert b"raw" not in response.content


def test_transaction_export_quotes_rfc4180_fields_and_neutralizes_formulas(
    configured,
):
    assert configured.post("/api/sync").status_code == 200
    store = configured.app.state.store
    with store._lock:
        store._db.execute(
            "UPDATE transactions SET created_at = ?, currency = ?, status = ?, "
            "location_id = ?, device_id = ?, device_name = ?, card_last4 = ?, "
            "receipt_url = ?, note = ?, raw = ?, thumbnail_path = ? WHERE id = ?",
            (
                "=1+1",
                "=USD",
                "+SUM(1,1)",
                "  @location",
                "-DEVICE",
                'Register, "A"\nNorth',
                "\t=4242",
                '=HYPERLINK("https://attacker.invalid")',
                '=HYPERLINK("https://note.invalid")\nfollow up',
                '{"access_token":"raw-provider-secret"}',
                "thumbnail-secret.jpg",
                "PAY_001",
            ),
        )
        store._db.commit()

    response = configured.get("/api/transactions/export.csv")

    assert response.status_code == 200
    row = next(
        item for item in _export_rows(response)
        if item["amount_minor_units"] == "1250"
    )
    assert row["timestamp"] == "'=1+1"
    assert row["currency"] == "'=USD"
    assert row["status"] == "'+SUM(1,1)"
    assert row["location_id"] == "'  @location"
    assert row["device_id"] == "'-DEVICE"
    assert row["device_name"] == 'Register, "A"\r\nNorth'
    assert row["card_last4"] == "'\t=4242"
    assert row["receipt_url"] == (
        "'=HYPERLINK(\"https://attacker.invalid\")"
    )
    assert row["protect_timeline_url"].startswith("https://192.168.1.1/")
    assert row["note"] == (
        "'=HYPERLINK(\"https://note.invalid\")\r\nfollow up"
    )
    assert b'"Register, ""A""\r\nNorth"' in response.content
    assert b"raw-provider-secret" not in response.content
    assert b"thumbnail-secret.jpg" not in response.content


def test_transaction_export_finishes_before_protect_switch_can_commit(
    configured,
    monkeypatch,
):
    assert configured.post("/api/sync").status_code == 200
    store = configured.app.state.store
    facts_read = threading.Event()
    release_export = threading.Event()
    switch_started = threading.Event()
    original_read = store.list_transaction_export_facts

    def blocked_read():
        facts = original_read()
        facts_read.set()
        assert release_export.wait(timeout=10)
        return facts

    def switch_host():
        switch_started.set()
        with store.integration_guard(exclusive=True):
            store.set_setting("protect.host", "192.168.1.2")

    monkeypatch.setattr(store, "list_transaction_export_facts", blocked_read)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        export_future = executor.submit(
            configured.get, "/api/transactions/export.csv"
        )
        assert facts_read.wait(timeout=3)
        switch_future = executor.submit(switch_host)
        assert switch_started.wait(timeout=3)
        try:
            with pytest.raises(concurrent.futures.TimeoutError):
                switch_future.result(timeout=0.05)
            assert store.get_setting("protect.host") == "192.168.1.1"
        finally:
            release_export.set()
        response = export_future.result(timeout=5)
        switch_future.result(timeout=5)

    assert response.status_code == 200
    assert all(
        row["protect_timeline_url"].startswith("https://192.168.1.1/")
        for row in _export_rows(response)
    )
    assert store.get_setting("protect.host") == "192.168.1.2"
