"""Square account changes cannot mix merchant-owned data or work."""

from __future__ import annotations

import concurrent.futures
import errno
import os
import sqlite3
import threading
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import app.store as store_module
from app.main import create_app
from app.store import (
    SquareAccountChanged,
    SquareAccountSwitchRequired,
    Store,
)
from app.sync import deliver_completed_alarm, ingest_payment

from .conftest import ADMIN_PASSWORD


TOKEN_A = "square-token-merchant-a"
TOKEN_A_REFRESH = "square-token-merchant-a-refreshed"
TOKEN_B = "square-token-merchant-b"
TOKEN_C = "square-token-merchant-c"
MERCHANT_A = "MERCHANT_ACCOUNT_A"
MERCHANT_B = "MERCHANT_ACCOUNT_B"
MERCHANT_C = "MERCHANT_ACCOUNT_C"
WEBHOOK_A_KEY = "webhook-key-account-a"
WEBHOOK_A_URL = "https://merchant-a.example/webhooks/square"
WEBHOOK_B_KEY = "webhook-key-account-b"
WEBHOOK_B_URL = "https://merchant-b.example/webhooks/square"
CAMERA_ID = "cam1aaaaaaaaaaaaaaaaaaaaa"


def _square_accounts(request: httpx.Request) -> httpx.Response:
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    accounts = {
        TOKEN_A: (MERCHANT_A, "LOC_A", "Merchant A"),
        TOKEN_A_REFRESH: (MERCHANT_A, "LOC_A", "Merchant A"),
        TOKEN_B: (MERCHANT_B, "LOC_B", "Merchant B"),
        TOKEN_C: (MERCHANT_C, "LOC_C", "Merchant C"),
    }
    account = accounts.get(token)
    if account is None:
        return httpx.Response(401, json={"errors": [{"code": "UNAUTHORIZED"}]})
    merchant_id, location_id, name = account
    if request.url.path == "/v2/locations":
        return httpx.Response(
            200,
            json={
                "locations": [
                    {"id": location_id, "name": name, "status": "ACTIVE"}
                ]
            },
        )
    if request.url.path == "/v2/merchants/me":
        return httpx.Response(200, json={"merchant": {"id": merchant_id}})
    if request.url.path == "/v2/payments":
        return httpx.Response(200, json={"payments": []})
    return httpx.Response(404)


def _transaction(
    txn_id: str = "PAY_ACCOUNT_A",
    *,
    thumbnail_path: str | None = "account-a.jpg",
) -> dict:
    return {
        "id": txn_id,
        "created_at": "2026-07-17T12:00:00Z",
        "ts_ms": 1_752_753_600_000,
        "updated_at": "2026-07-17T12:00:00Z",
        "updated_ts_ms": 1_752_753_600_000,
        "amount": 1250,
        "currency": "USD",
        "status": "COMPLETED",
        "location_id": "LOC_A",
        "device_id": "DEVICE_A",
        "device_name": "Register A",
        "card_last4": "4242",
        "receipt_url": "https://square.example/account-a-receipt",
        "camera_id": CAMERA_ID,
        "thumbnail_path": thumbnail_path,
    }


def _payment(txn_id: str = "PAY_STALE_ACCOUNT_A") -> dict:
    return {
        "id": txn_id,
        "created_at": "2026-07-17T12:05:00Z",
        "updated_at": "2026-07-17T12:05:00Z",
        "amount_money": {"amount": 500, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC_A",
    }


def _configure(
    store: Store,
    merchant_id: str,
    token: str,
    *,
    confirm: bool = False,
    webhook_key: str | None = None,
    webhook_url: str | None = None,
    confirmation_token: str = "",
) -> bool:
    kwargs = {
        "merchant_id": merchant_id,
        "access_token": token,
        "environment": "production",
        "webhook_signature_key": webhook_key,
        "webhook_url": webhook_url,
        "confirm_account_switch": confirm,
        "account_switch_confirmation_token": confirmation_token,
    }
    if not confirm or confirmation_token:
        return store.configure_square_account(**kwargs).switched
    try:
        return store.configure_square_account(**kwargs).switched
    except SquareAccountSwitchRequired as exc:
        kwargs["account_switch_confirmation_token"] = exc.confirmation_token
        return store.configure_square_account(**kwargs).switched


def _seed_account_data(store: Store) -> None:
    store.set_camera_mapping(
        "LOC_A",
        CAMERA_ID,
        "Account A camera",
        device_id="DEVICE_A",
        device_name="Register A",
    )
    store.upsert_transaction(_transaction())
    store.upsert_transaction(
        _transaction("PAY_ACCOUNT_A_RETRY", thumbnail_path=None)
    )
    (store.thumbnail_dir / "account-a.jpg").write_bytes(b"account A evidence")
    (store.thumbnail_dir / "orphan-account-a.jpg").write_bytes(b"orphan evidence")
    store._db.execute(
        "CREATE TABLE IF NOT EXISTS square_poll_watermarks ("
        "location_id TEXT PRIMARY KEY, polled_through_ms INTEGER NOT NULL)"
    )
    store._db.execute(
        "INSERT OR REPLACE INTO square_poll_watermarks "
        "(location_id, polled_through_ms) VALUES ('LOC_A', 123456)"
    )
    # This table is introduced by the independent Protect-console isolation
    # PR. Account switching must compose correctly before and after that PR is
    # merged, even when SQLite foreign-key enforcement is disabled.
    store._db.execute(
        "CREATE TABLE IF NOT EXISTS protect_evidence_retired ("
        "transaction_id TEXT PRIMARY KEY, "
        "FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE)"
    )
    store._db.execute(
        "INSERT OR REPLACE INTO protect_evidence_retired (transaction_id) "
        "VALUES ('PAY_ACCOUNT_A')"
    )
    store._db.commit()
    store.set_setting("square.poll.legacy", "old-account-cursor")


def _authed_account_app(tmp_path: Path) -> tuple[object, TestClient]:
    app = create_app(
        data_dir=tmp_path / "data",
        square_transport=httpx.MockTransport(_square_accounts),
        enable_poller=False,
    )
    client = TestClient(app)
    assert client.post(
        "/api/setup", json={"password": ADMIN_PASSWORD}
    ).status_code == 200
    assert client.post(
        "/api/login", json={"password": ADMIN_PASSWORD}
    ).status_code == 200
    return app, client


def test_api_refuses_then_atomically_purges_confirmed_account_switch(tmp_path):
    app, client = _authed_account_app(tmp_path)
    store = app.state.store
    try:
        connected = client.put(
            "/api/settings/square",
            json={
                "access_token": TOKEN_A,
                "environment": "production",
                "webhook_signature_key": WEBHOOK_A_KEY,
                "webhook_url": WEBHOOK_A_URL,
            },
        )
        assert connected.status_code == 200
        account_a_revision = connected.json()["account_revision"]
        locations = client.get("/api/locations")
        assert locations.status_code == 200
        assert locations.headers["cache-control"] == "private, no-store"
        assert (
            locations.headers["x-square-account-revision"]
            == account_a_revision
        )
        _seed_account_data(store)
        store.set_setting("protect.host", "protect-console.local")

        before = client.get("/api/transactions").json()
        assert {row["id"] for row in before} == {
            "PAY_ACCOUNT_A",
            "PAY_ACCOUNT_A_RETRY",
        }
        assert client.get("/api/pos-devices").json() == [
            {
                "location_id": "LOC_A",
                "device_id": "DEVICE_A",
                "device_name": "Register A",
            }
        ]

        refused = client.put(
            "/api/settings/square",
            json={"access_token": TOKEN_B, "environment": "production"},
        )
        assert refused.status_code == 409
        assert refused.json()["detail"]["code"] == (
            "square_account_switch_confirmation_required"
        )
        confirmation_token = refused.json()["detail"]["confirmation_token"]
        assert store.get_setting("square.merchant_id") == MERCHANT_A
        assert len(store.list_transactions()) == 2
        assert len(store.get_camera_mappings()) == 1
        assert store.get_setting("square.webhook_signature_key") == WEBHOOK_A_KEY
        assert store._db.execute(
            "SELECT COUNT(*) FROM square_poll_watermarks"
        ).fetchone()[0] == 1
        assert store._db.execute(
            "SELECT COUNT(*) FROM protect_evidence_retired"
        ).fetchone()[0] == 1
        assert (store.thumbnail_dir / "account-a.jpg").exists()
        assert (store.thumbnail_dir / "orphan-account-a.jpg").exists()

        unbound_confirmation = client.put(
            "/api/settings/square",
            json={
                "access_token": TOKEN_B,
                "environment": "production",
                "confirm_account_switch": True,
            },
        )
        assert unbound_confirmation.status_code == 409
        assert store.get_setting("square.merchant_id") == MERCHANT_A
        assert len(store.list_transactions()) == 2

        switched = client.put(
            "/api/settings/square",
            json={
                "access_token": TOKEN_B,
                "environment": "production",
                "confirm_account_switch": True,
                "account_switch_confirmation_token": confirmation_token,
            },
        )
        assert switched.status_code == 200
        switched_data = switched.json()
        assert switched_data.pop("account_revision")
        assert switched_data == {
            "ok": True,
            "locations": [
                {"id": "LOC_B", "name": "Merchant B", "status": "ACTIVE"}
            ],
            "account_switched": True,
            "webhook_configured": False,
            "evidence_cleanup_pending": False,
        }

        assert store.get_setting("square.merchant_id") == MERCHANT_B
        assert store.get_setting("square.access_token") == TOKEN_B
        assert store.get_setting("square.webhook_signature_key") is None
        assert store.get_setting("square.webhook_url") is None
        assert store.get_setting("square.poll.legacy") is None
        assert store.get_setting("protect.host") == "protect-console.local"
        stale_mapping = client.put(
            "/api/camera-mapping",
            headers={"X-Square-Account-Revision": account_a_revision},
            json={
                "mappings": [
                    {"location_id": "LOC_A", "camera_id": CAMERA_ID}
                ]
            },
        )
        assert stale_mapping.status_code == 409
        assert client.get("/api/transactions").json() == []
        assert client.get("/api/pos-devices").json() == []
        assert client.get("/api/camera-mapping").json() == []
        assert store._db.execute(
            "SELECT COUNT(*) FROM thumbnail_retries"
        ).fetchone()[0] == 0
        assert store._db.execute(
            "SELECT COUNT(*) FROM square_poll_watermarks"
        ).fetchone()[0] == 0
        assert store._db.execute(
            "SELECT COUNT(*) FROM protect_evidence_retired"
        ).fetchone()[0] == 0
        assert list(store.thumbnail_dir.iterdir()) == []
        assert client.post("/webhooks/square", content=b"{}").status_code == 403
    finally:
        client.close()
        store.close()


@pytest.mark.parametrize(
    ("endpoint", "store_method"),
    (
        ("/api/transactions", "list_transactions_page"),
        ("/api/pos-devices", "get_observed_devices"),
        ("/api/camera-mapping", "get_camera_mappings"),
    ),
)
def test_account_scoped_read_finishes_before_switch_can_commit(
    tmp_path, monkeypatch, endpoint, store_method
):
    app, client = _authed_account_app(tmp_path)
    store = app.state.store
    read_started = threading.Event()
    release_read = threading.Event()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    try:
        connected = client.put(
            "/api/settings/square",
            json={"access_token": TOKEN_A, "environment": "production"},
        )
        assert connected.status_code == 200
        _seed_account_data(store)
        with pytest.raises(SquareAccountSwitchRequired) as challenge:
            store.configure_square_account(
                merchant_id=MERCHANT_B,
                access_token=TOKEN_B,
                environment="production",
            )

        original_read = getattr(store, store_method)

        def blocked_read(*args, **kwargs):
            result = original_read(*args, **kwargs)
            read_started.set()
            assert release_read.wait(timeout=5)
            return result

        monkeypatch.setattr(store, store_method, blocked_read)
        read_future = executor.submit(client.get, endpoint)
        assert read_started.wait(timeout=5)
        switch_future = executor.submit(
            store.configure_square_account,
            merchant_id=MERCHANT_B,
            access_token=TOKEN_B,
            environment="production",
            confirm_account_switch=True,
            account_switch_confirmation_token=(
                challenge.value.confirmation_token
            ),
        )
        with pytest.raises(concurrent.futures.TimeoutError):
            switch_future.result(timeout=0.05)

        release_read.set()
        response = read_future.result(timeout=5)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "private, no-store"
        assert {row["location_id"] for row in response.json()} == {"LOC_A"}
        assert switch_future.result(timeout=5).switched
        assert client.get(endpoint).json() == []
    finally:
        release_read.set()
        executor.shutdown(wait=True, cancel_futures=True)
        client.close()
        store.close()


def test_same_merchant_refresh_retains_data_even_when_confirmation_is_set(tmp_path):
    app, client = _authed_account_app(tmp_path)
    store = app.state.store
    try:
        connected = client.put(
            "/api/settings/square",
            json={
                "access_token": TOKEN_A,
                "environment": "production",
                "webhook_signature_key": WEBHOOK_A_KEY,
                "webhook_url": WEBHOOK_A_URL,
            },
        )
        assert connected.status_code == 200
        account_revision = connected.json()["account_revision"]
        _seed_account_data(store)

        refreshed = client.put(
            "/api/settings/square",
            json={
                "access_token": TOKEN_A_REFRESH,
                "environment": "production",
                "confirm_account_switch": True,
            },
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["account_switched"] is False
        assert refreshed.json()["webhook_configured"] is True
        assert refreshed.json()["account_revision"] == account_revision
        assert store.get_setting("square.access_token") == TOKEN_A_REFRESH
        assert store.get_setting("square.webhook_signature_key") == WEBHOOK_A_KEY
        assert store.get_setting("square.webhook_url") == WEBHOOK_A_URL
        assert len(store.list_transactions()) == 2
        assert len(store.get_camera_mappings()) == 1
        assert store.get_observed_devices()[0]["device_id"] == "DEVICE_A"
        assert store._db.execute(
            "SELECT polled_through_ms FROM square_poll_watermarks WHERE location_id = 'LOC_A'"
        ).fetchone()[0] == 123456
        assert store._db.execute(
            "SELECT COUNT(*) FROM thumbnail_retries"
        ).fetchone()[0] == 1
        assert store._db.execute(
            "SELECT COUNT(*) FROM protect_evidence_retired"
        ).fetchone()[0] == 1
        assert (store.thumbnail_dir / "account-a.jpg").exists()
    finally:
        client.close()
        store.close()


def test_store_switch_uses_only_new_accounts_webhook_credentials(tmp_path):
    store = Store(tmp_path / "data")
    try:
        _configure(
            store,
            MERCHANT_A,
            TOKEN_A,
            webhook_key=WEBHOOK_A_KEY,
            webhook_url=WEBHOOK_A_URL,
        )
        assert _configure(
            store,
            MERCHANT_B,
            TOKEN_B,
            confirm=True,
            webhook_key=WEBHOOK_B_KEY,
            webhook_url=WEBHOOK_B_URL,
        )
        assert store.get_setting("square.webhook_signature_key") == WEBHOOK_B_KEY
        assert store.get_setting("square.webhook_url") == WEBHOOK_B_URL
    finally:
        store.close()


def test_store_switch_rollback_preserves_settings_data_and_files(tmp_path):
    store = Store(tmp_path / "data")
    try:
        _configure(
            store,
            MERCHANT_A,
            TOKEN_A,
            webhook_key=WEBHOOK_A_KEY,
            webhook_url=WEBHOOK_A_URL,
        )
        _seed_account_data(store)
        before_settings = store.get_settings(
            (
                "square.access_token",
                "square.environment",
                "square.merchant_id",
                "square.webhook_signature_key",
                "square.webhook_url",
                "square.poll.legacy",
            )
        )
        store._db.execute(
            "CREATE TRIGGER reject_account_purge BEFORE DELETE ON transactions "
            "BEGIN SELECT RAISE(ABORT, 'simulated purge failure'); END"
        )
        store._db.commit()

        with pytest.raises(sqlite3.IntegrityError, match="simulated purge failure"):
            _configure(store, MERCHANT_B, TOKEN_B, confirm=True)

        assert store.get_settings(tuple(before_settings)) == before_settings
        assert len(store.list_transactions()) == 2
        assert len(store.get_camera_mappings()) == 1
        assert store._db.execute(
            "SELECT polled_through_ms FROM square_poll_watermarks WHERE location_id = 'LOC_A'"
        ).fetchone()[0] == 123456
        assert store._db.execute(
            "SELECT COUNT(*) FROM thumbnail_retries"
        ).fetchone()[0] == 1
        assert store._db.execute(
            "SELECT COUNT(*) FROM protect_evidence_retired"
        ).fetchone()[0] == 1
        assert (store.thumbnail_dir / "account-a.jpg").exists()
        assert (store.thumbnail_dir / "orphan-account-a.jpg").exists()
    finally:
        store.close()


def test_failed_thumbnail_cleanup_is_durable_and_retried_on_startup(
    tmp_path, monkeypatch
):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    _configure(store, MERCHANT_A, TOKEN_A)
    _seed_account_data(store)
    unlink = store._unlink_thumbnail_if_unreferenced

    def fail_one_file(thumbnail_path: str) -> bool:
        if thumbnail_path == "account-a.jpg":
            raise OSError("simulated cleanup interruption")
        return unlink(thumbnail_path)

    monkeypatch.setattr(store, "_unlink_thumbnail_if_unreferenced", fail_one_file)
    try:
        with pytest.raises(SquareAccountSwitchRequired) as challenge:
            _configure(store, MERCHANT_B, TOKEN_B)
        configuration = store.configure_square_account(
            merchant_id=MERCHANT_B,
            access_token=TOKEN_B,
            environment="production",
            confirm_account_switch=True,
            account_switch_confirmation_token=(
                challenge.value.confirmation_token
            ),
        )
        assert configuration.switched
        assert configuration.evidence_cleanup_pending
        assert store.list_transactions() == []
        assert store.orphan_thumbnail_cleanup_pending()
        assert (store.thumbnail_dir / "account-a.jpg").exists()
    finally:
        store.close()

    reopened = Store(data_dir)
    try:
        assert not reopened.orphan_thumbnail_cleanup_pending()
        assert list(reopened.thumbnail_dir.iterdir()) == []
    finally:
        reopened.close()


def test_same_account_save_retries_pending_thumbnail_cleanup(tmp_path, monkeypatch):
    store = Store(tmp_path / "data")
    _configure(store, MERCHANT_A, TOKEN_A)
    _seed_account_data(store)
    unlink = store._unlink_thumbnail_if_unreferenced

    def fail_account_thumbnail(thumbnail_path: str) -> bool:
        if thumbnail_path == "account-a.jpg":
            raise OSError("simulated cleanup interruption")
        return unlink(thumbnail_path)

    monkeypatch.setattr(
        store, "_unlink_thumbnail_if_unreferenced", fail_account_thumbnail
    )
    try:
        assert _configure(store, MERCHANT_B, TOKEN_B, confirm=True)
        assert store.orphan_thumbnail_cleanup_pending()
        assert (store.thumbnail_dir / "account-a.jpg").exists()

        monkeypatch.setattr(store, "_unlink_thumbnail_if_unreferenced", unlink)
        refreshed = store.configure_square_account(
            merchant_id=MERCHANT_B,
            access_token=TOKEN_B,
            environment="production",
        )
        assert not refreshed.switched
        assert not refreshed.evidence_cleanup_pending
        assert list(store.thumbnail_dir.iterdir()) == []
    finally:
        store.close()


def test_stale_confirmation_cannot_erase_a_concurrently_selected_account(tmp_path):
    store = Store(tmp_path / "data")
    try:
        _configure(store, MERCHANT_A, TOKEN_A)
        with pytest.raises(SquareAccountSwitchRequired) as challenge:
            _configure(store, MERCHANT_B, TOKEN_B)
        stale_confirmation = challenge.value.confirmation_token

        assert _configure(store, MERCHANT_C, TOKEN_C, confirm=True)
        store.upsert_transaction(_transaction("PAY_ACCOUNT_C"))

        with pytest.raises(SquareAccountSwitchRequired):
            _configure(
                store,
                MERCHANT_B,
                TOKEN_B,
                confirm=True,
                confirmation_token=stale_confirmation,
            )

        assert store.get_setting("square.merchant_id") == MERCHANT_C
        assert store.get_setting("square.access_token") == TOKEN_C
        assert store.get_transaction("PAY_ACCOUNT_C") is not None
    finally:
        store.close()


def test_environment_change_is_an_account_switch_and_confirmation_is_bound_to_it(
    tmp_path,
):
    store = Store(tmp_path / "data")
    try:
        _configure(store, MERCHANT_A, TOKEN_A)
        production_revision = store.square_account_revision()
        assert production_revision
        _seed_account_data(store)
        with pytest.raises(SquareAccountSwitchRequired) as challenge:
            store.configure_square_account(
                merchant_id=MERCHANT_A,
                access_token=TOKEN_A,
                environment="sandbox",
            )

        changed = store.configure_square_account(
            merchant_id=MERCHANT_A,
            access_token=TOKEN_A,
            environment="sandbox",
            confirm_account_switch=True,
            account_switch_confirmation_token=(
                challenge.value.confirmation_token
            ),
        )
        assert changed.switched
        assert store.get_setting("square.environment") == "sandbox"
        assert store.list_transactions() == []
        assert store.get_camera_mappings() == []
        with pytest.raises(SquareAccountChanged):
            ingest_payment(
                store,
                _payment(),
                None,
                expected_merchant_id=MERCHANT_A,
                expected_environment="production",
                expected_account_revision=production_revision,
            )
        assert store.list_transactions() == []
    finally:
        store.close()


def test_store_assigns_account_revision_when_upgrading_legacy_settings(tmp_path):
    data_dir = tmp_path / "data"
    legacy = Store(data_dir)
    legacy.set_setting("square.access_token", TOKEN_A, secret=True)
    legacy.set_setting("square.environment", "production")
    legacy.set_setting("square.merchant_id", MERCHANT_A)
    assert legacy.square_account_revision() is None
    legacy.close()

    upgraded = Store(data_dir)
    try:
        assert upgraded.square_account_revision()
    finally:
        upgraded.close()


def test_concurrent_refresh_cannot_restore_old_account_after_switch(tmp_path):
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    second = Store(data_dir)
    try:
        _configure(first, MERCHANT_A, TOKEN_A)
        _seed_account_data(first)
        barrier = threading.Barrier(2)

        def refresh_old_account() -> str:
            barrier.wait()
            try:
                _configure(first, MERCHANT_A, TOKEN_A_REFRESH)
            except SquareAccountSwitchRequired:
                return "refused"
            return "refreshed-before-switch"

        def switch_account() -> str:
            barrier.wait()
            _configure(second, MERCHANT_B, TOKEN_B, confirm=True)
            return "switched"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = {
                future.result()
                for future in (
                    executor.submit(refresh_old_account),
                    executor.submit(switch_account),
                )
            }

        assert "switched" in results
        assert second.get_setting("square.merchant_id") == MERCHANT_B
        assert second.get_setting("square.access_token") == TOKEN_B
        assert second.list_transactions() == []
        assert second.get_camera_mappings() == []

        with pytest.raises(SquareAccountChanged):
            ingest_payment(
                first,
                _payment(),
                None,
                expected_merchant_id=MERCHANT_A,
            )
        assert second.list_transactions() == []
    finally:
        first.close()
        second.close()


def test_account_switch_waits_for_old_alarm_work_across_store_instances(tmp_path):
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    second = Store(data_dir)
    release_alarm = threading.Event()
    alarm_started = threading.Event()

    class BlockingProtect:
        def trigger_alarm(self, _trigger_id, timeout=None):
            alarm_started.set()
            assert release_alarm.wait(timeout=5)

    try:
        _configure(first, MERCHANT_A, TOKEN_A)
        first.upsert_transaction(_transaction())
        with pytest.raises(SquareAccountSwitchRequired) as challenge:
            _configure(second, MERCHANT_B, TOKEN_B)

        def deliver_old_alarm() -> bool:
            with first.integration_guard():
                return deliver_completed_alarm(
                    first,
                    "PAY_ACCOUNT_A",
                    BlockingProtect(),
                    "square-sale",
                )

        def switch_account():
            return second.configure_square_account(
                merchant_id=MERCHANT_B,
                access_token=TOKEN_B,
                environment="production",
                confirm_account_switch=True,
                account_switch_confirmation_token=(
                    challenge.value.confirmation_token
                ),
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            alarm_future = executor.submit(deliver_old_alarm)
            assert alarm_started.wait(timeout=5)
            switch_future = executor.submit(switch_account)
            with pytest.raises(concurrent.futures.TimeoutError):
                switch_future.result(timeout=0.05)
            release_alarm.set()
            assert alarm_future.result(timeout=5)
            assert switch_future.result(timeout=5).switched

        assert second.get_setting("square.merchant_id") == MERCHANT_B
        assert second.get_transaction("PAY_ACCOUNT_A") is None
    finally:
        release_alarm.set()
        first.close()
        second.close()


def test_windows_integration_guard_allows_readers_and_makes_writer_wait(
    tmp_path, monkeypatch
):
    class FakeMsvcrt:
        LK_NBLCK = 1
        LK_UNLCK = 2

        def __init__(self):
            self._condition = threading.Condition()
            self._owners: dict[int, int] = {}

        def locking(self, fd: int, operation: int, length: int) -> None:
            offset = os.lseek(fd, 0, os.SEEK_CUR)
            byte_range = range(offset, offset + length)
            with self._condition:
                if operation == self.LK_NBLCK:
                    if any(
                        owner != fd
                        for byte in byte_range
                        if (owner := self._owners.get(byte)) is not None
                    ):
                        raise OSError(errno.EACCES, "simulated sharing violation")
                    for byte in byte_range:
                        self._owners[byte] = fd
                    return
                if operation == self.LK_UNLCK:
                    assert all(self._owners.get(byte) == fd for byte in byte_range)
                    for byte in byte_range:
                        del self._owners[byte]
                    self._condition.notify_all()
                    return
                raise AssertionError(f"unexpected operation {operation}")

    fake_msvcrt = FakeMsvcrt()
    monkeypatch.setattr(store_module, "_fcntl", None)
    monkeypatch.setattr(store_module, "_msvcrt", fake_msvcrt)
    data_dir = tmp_path / "data"
    first = Store(data_dir)
    second = Store(data_dir)
    release_readers = threading.Event()
    first_reader_started = threading.Event()
    second_reader_started = threading.Event()
    writer_started = threading.Event()

    def hold_reader(store: Store, started: threading.Event) -> None:
        with store.integration_guard():
            started.set()
            assert release_readers.wait(timeout=5)

    def take_writer() -> None:
        with second.integration_guard(exclusive=True):
            writer_started.set()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            first_reader = executor.submit(
                hold_reader, first, first_reader_started
            )
            assert first_reader_started.wait(timeout=5)
            second_reader = executor.submit(
                hold_reader, second, second_reader_started
            )
            assert second_reader_started.wait(timeout=5)
            writer = executor.submit(take_writer)
            assert not writer_started.wait(timeout=0.05)
            release_readers.set()
            first_reader.result(timeout=5)
            second_reader.result(timeout=5)
            writer.result(timeout=5)
            assert writer_started.is_set()

        # All byte-range locks were released, so a subsequent reader can enter.
        with first.integration_guard():
            pass
        assert fake_msvcrt._owners == {}
    finally:
        release_readers.set()
        first.close()
        second.close()


def test_unidentified_legacy_data_also_requires_switch_confirmation(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.upsert_transaction(_transaction())
        with pytest.raises(SquareAccountSwitchRequired):
            _configure(store, MERCHANT_B, TOKEN_B)
        assert store.get_transaction("PAY_ACCOUNT_A") is not None
        assert _configure(store, MERCHANT_B, TOKEN_B, confirm=True)
        assert store.get_transaction("PAY_ACCOUNT_A") is None
    finally:
        store.close()


def test_unidentified_legacy_thumbnail_requires_confirmation_and_cleanup(tmp_path):
    store = Store(tmp_path / "data")
    legacy_thumbnail = store.thumbnail_dir / "unidentified-account.jpg"
    legacy_thumbnail.write_bytes(b"legacy evidence")
    try:
        with pytest.raises(SquareAccountSwitchRequired):
            _configure(store, MERCHANT_B, TOKEN_B)
        assert legacy_thumbnail.exists()

        assert _configure(store, MERCHANT_B, TOKEN_B, confirm=True)
        assert not legacy_thumbnail.exists()
        assert not store.orphan_thumbnail_cleanup_pending()
    finally:
        store.close()


def test_account_switch_ui_reveals_destructive_confirmation_after_409():
    static_dir = Path(__file__).parents[1] / "app" / "static"
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    js = (static_dir / "app.js").read_text(encoding="utf-8")

    assert 'id="square-account-switch-warning"' in html
    assert 'role="alert" hidden' in html
    assert 'id="square-confirm-account-switch"' in html
    assert "permanently erases" in html
    assert "confirm_account_switch" in js
    assert "account_switch_confirmation_token" in js
    assert 'err.code === "square_account_switch_confirmation_required"' in js
    assert '$("#square-account-switch-warning").hidden = false' in js
    assert "renderTransactions([])" in js
    assert "loadTransactions({ reset: true })" in js
    # Stale-load protection lives in the shared settings loader: only the
    # latest load's render publishes the account revision.
    assert "createLatestSettingsLoader" in js
    assert "settings.mappingRevision" in js
    assert "X-Square-Account-Revision" in js
    assert "evidence_cleanup_pending" in js
