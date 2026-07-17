"""Durable retry coverage for historical Protect thumbnails."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from app.protect_client import ProtectError
from app.store import Store
from app.sync import retry_missing_thumbnails, retry_thumbnail_name, sync_payments


CAM_A = "cameraA"
CAM_B = "cameraB"


def _stored_txn(
    txn_id: str,
    ts_ms: int,
    *,
    camera_id: str = CAM_A,
    thumbnail_path: str | None = None,
) -> dict:
    return {
        "id": txn_id,
        "created_at": "2026-07-16T15:30:00.000Z",
        "ts_ms": ts_ms,
        "amount": 100,
        "currency": "USD",
        "status": "COMPLETED",
        "location_id": "LOC1",
        "card_last4": "4242",
        "receipt_url": "",
        "camera_id": camera_id,
        "thumbnail_path": thumbnail_path,
        "raw": {},
    }


def _payment(txn_id: str, created_at: str) -> dict:
    return {
        "id": txn_id,
        "created_at": created_at,
        "amount_money": {"amount": 100, "currency": "USD"},
        "status": "COMPLETED",
        "location_id": "LOC1",
    }


def _fail(store: Store, job: dict, now: float, base: float = 10, cap: float = 25) -> bool:
    return store.fail_thumbnail_retry(
        job["transaction_id"],
        job["lease_token"],
        job["camera_id"],
        job["ts_ms"],
        "offline",
        now=now,
        base_delay_seconds=base,
        max_delay_seconds=cap,
    )


def test_old_failure_retries_after_square_window_advances(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAM_A, "Register")
    old = _payment("OLD", "2026-07-16T15:30:00.000Z")
    new = _payment("NEW", "2026-07-16T15:45:00.000Z")

    class Square:
        calls = 0
        returned: list[list[str]] = []

        def list_payments(self, begin_time=None):
            self.calls += 1
            result = [old, new] if self.calls == 1 else [new]
            self.returned.append([payment["id"] for payment in result])
            return result

    class Protect:
        failed_old = False
        calls: list[int] = []

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls.append(ts_ms)
            if ts_ms == 1784215800000 and not self.failed_old:
                self.failed_old = True
                raise ProtectError("recording temporarily unavailable")
            return b"jpeg-" + str(ts_ms).encode()

    square = Square()
    protect = Protect()
    try:
        assert sync_payments(store, square, protect) == 2
        assert store.get_transaction("OLD")["thumbnail_path"] is None
        assert store.get_transaction("NEW")["thumbnail_path"] is not None
        assert store.latest_transaction_ts() == 1784216700000

        # Square no longer returns OLD, but the independent durable queue does.
        assert sync_payments(store, square, protect) == 1
        assert square.returned[1] == ["NEW"]
        old_row = store.get_transaction("OLD")
        assert old_row["thumbnail_path"] is not None
        assert old_row["thumbnail_path"] != "OLD.jpg"
        assert (store.thumbnail_dir / old_row["thumbnail_path"]).read_bytes().endswith(
            b"1784215800000"
        )
    finally:
        store.close()


def test_retry_backoff_is_exponential_and_capped(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.upsert_transaction(_stored_txn("P", 1000))

        first = store.claim_thumbnail_retries(1, 5, now=100)[0]
        assert _fail(store, first, 100)
        assert store.claim_thumbnail_retries(1, 5, now=109) == []

        second = store.claim_thumbnail_retries(1, 5, now=110)[0]
        assert _fail(store, second, 110)
        assert store.claim_thumbnail_retries(1, 5, now=129) == []

        third = store.claim_thumbnail_retries(1, 5, now=130)[0]
        assert _fail(store, third, 130)
        assert store.claim_thumbnail_retries(1, 5, now=154) == []

        # Third delay is capped at 25 seconds instead of growing to 40.
        fourth = store.claim_thumbnail_retries(1, 5, now=155)[0]
        assert fourth["attempts"] == 3
    finally:
        store.close()


def test_retry_lease_is_exclusive_across_store_connections(tmp_path):
    data_dir = tmp_path / "data"
    first_store = Store(data_dir)
    first_store.upsert_transaction(_stored_txn("P", 1000))
    second_store = Store(data_dir)
    try:
        first = first_store.claim_thumbnail_retries(1, 10, now=100)[0]
        assert second_store.claim_thumbnail_retries(1, 10, now=109) == []
        reclaimed = second_store.claim_thumbnail_retries(1, 10, now=111)[0]
        assert reclaimed["lease_token"] != first["lease_token"]
    finally:
        first_store.close()
        second_store.close()


def test_expired_token_cannot_complete_or_fail_new_claim(tmp_path):
    data_dir = tmp_path / "data"
    first_store = Store(data_dir)
    first_store.upsert_transaction(_stored_txn("P", 1000))
    second_store = Store(data_dir)
    try:
        stale = first_store.claim_thumbnail_retries(1, 10, now=100)[0]
        current = second_store.claim_thumbnail_retries(1, 10, now=111)[0]

        assert not first_store.complete_thumbnail_retry(
            "P", stale["lease_token"], CAM_A, 1000, "stale.jpg"
        )
        assert not first_store.fail_thumbnail_retry(
            "P", stale["lease_token"], CAM_A, 1000, "late", now=111
        )
        assert first_store.get_transaction("P")["thumbnail_path"] is None

        assert second_store.complete_thumbnail_retry(
            "P", current["lease_token"], CAM_A, 1000, "current.jpg"
        )
        assert first_store.get_transaction("P")["thumbnail_path"] == "current.jpg"
    finally:
        first_store.close()
        second_store.close()


def test_camera_change_during_fetch_cannot_misattach(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.upsert_transaction(_stored_txn("P", 1000, camera_id=CAM_A))
        old = store.claim_thumbnail_retries(1, 10, now=100)[0]

        store.upsert_transaction(_stored_txn("P", 1000, camera_id=CAM_B))
        assert not store.complete_thumbnail_retry(
            "P", old["lease_token"], CAM_A, 1000, "wrong-camera.jpg"
        )
        assert store.get_transaction("P")["thumbnail_path"] is None

        replacement = store.claim_thumbnail_retries(1, 10, now=100)[0]
        assert replacement["camera_id"] == CAM_B
    finally:
        store.close()


def test_retry_batch_bounds_protect_calls(tmp_path):
    store = Store(tmp_path / "data")
    for index in range(5):
        store.upsert_transaction(_stored_txn(f"P{index}", 1000 + index))

    class Protect:
        calls = 0

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls += 1
            return b"jpeg"

    protect = Protect()
    try:
        assert retry_missing_thumbnails(store, protect, batch_size=2, now=100) == 2
        assert protect.calls == 2
        assert sum(
            bool(store.get_transaction(f"P{index}")["thumbnail_path"])
            for index in range(5)
        ) == 2
    finally:
        store.close()


@pytest.mark.parametrize(
    "error",
    [ProtectError("protect down"), ValueError("bad evidence"), OSError("disk down")],
)
def test_retry_failures_are_caught_and_requeued(tmp_path, error):
    store = Store(tmp_path / type(error).__name__)
    store.upsert_transaction(_stored_txn("P", 1000))

    class Protect:
        def get_snapshot(self, camera_id, ts_ms=None):
            raise error

    try:
        assert retry_missing_thumbnails(store, Protect(), batch_size=1, now=100) == 0
        assert store.get_transaction("P")["thumbnail_path"] is None
        assert store.claim_thumbnail_retries(1, 5, now=129) == []
        assert store.claim_thumbnail_retries(1, 5, now=130)[0]["attempts"] == 1
    finally:
        store.close()


def test_retry_file_write_failure_is_caught(tmp_path, monkeypatch):
    store = Store(tmp_path / "data")
    store.upsert_transaction(_stored_txn("P", 1000))

    class Protect:
        def get_snapshot(self, camera_id, ts_ms=None):
            return b"jpeg"

    def fail_write(_path: Path, _image: bytes):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_bytes", fail_write)
    try:
        assert retry_missing_thumbnails(store, Protect(), batch_size=1, now=100) == 0
        assert store.get_transaction("P")["thumbnail_path"] is None
        assert store.claim_thumbnail_retries(1, 5, now=129) == []
        assert store.claim_thumbnail_retries(1, 5, now=130)[0]["attempts"] == 1
    finally:
        store.close()


def test_retry_io_does_not_hold_database_claim_lock(tmp_path):
    data_dir = tmp_path / "data"
    worker_store = Store(data_dir)
    worker_store.upsert_transaction(_stored_txn("P", 1000))
    other_store = Store(data_dir)
    entered = threading.Event()
    release = threading.Event()

    class Protect:
        def get_snapshot(self, camera_id, ts_ms=None):
            entered.set()
            assert release.wait(2)
            return b"jpeg"

    thread = threading.Thread(
        target=retry_missing_thumbnails,
        args=(worker_store, Protect()),
        kwargs={"batch_size": 1, "now": 100},
    )
    try:
        thread.start()
        assert entered.wait(1)
        # This write needs BEGIN/COMMIT access while snapshot I/O is blocked.
        other_store.set_setting("concurrent", "ok")
        assert other_store.get_setting("concurrent") == "ok"
    finally:
        release.set()
        thread.join(2)
        worker_store.close()
        other_store.close()


def test_existing_missing_thumbnail_is_backfilled_on_migration(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    store.upsert_transaction(_stored_txn("P", 1000))
    with store._lock:
        store._db.execute("DROP TABLE thumbnail_retries")
        store._db.commit()
    store.close()

    reopened = Store(data_dir)
    try:
        claimed = reopened.claim_thumbnail_retries(1, 5, now=100)
        assert [job["transaction_id"] for job in claimed] == ["P"]
    finally:
        reopened.close()


def test_retry_filename_is_bound_to_evidence_and_claim():
    base = retry_thumbnail_name("P/1", CAM_A, 1000, "token-a")
    assert "/" not in base
    assert base != retry_thumbnail_name("P/1", CAM_B, 1000, "token-a")
    assert base != retry_thumbnail_name("P/1", CAM_A, 1001, "token-a")
    assert base != retry_thumbnail_name("P/1", CAM_A, 1000, "token-b")
