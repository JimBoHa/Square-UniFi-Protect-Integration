"""Durable retry coverage for historical Protect thumbnails."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import logging
import threading
from pathlib import Path

import httpx
import pytest

from app.protect_client import ProtectClient, ProtectError
from app.square_client import SquareError
from app.store import Store
from app.sync import (
    ingest_payment,
    retry_missing_thumbnails,
    retry_thumbnail_name,
    sync_payments,
)


CAM_A = "cameraA"
CAM_B = "cameraB"


def _stored_txn(
    txn_id: str,
    ts_ms: int,
    *,
    camera_id: str | None = CAM_A,
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

    class UnavailableProtect:
        def get_snapshot(self, camera_id, ts_ms=None):
            raise ProtectError("recording temporarily unavailable")

    class Square:
        returned: list[list[str]] = []

        def list_locations(self):
            return [{"id": "LOC1"}]

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

        def list_payments(self, **params):
            self.returned.append([new["id"]])
            return [new]

    class Protect:
        calls: list[int] = []

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls.append(ts_ms)
            return b"jpeg-" + str(ts_ms).encode()

    square = Square()
    protect = Protect()
    try:
        # OLD persists after both its initial capture and first queue attempt fail.
        ingest_payment(store, old, UnavailableProtect())
        assert retry_missing_thumbnails(
            store, UnavailableProtect(), batch_size=1, now=0
        ) == 0
        assert store.get_transaction("OLD")["thumbnail_path"] is None

        # Square returns only newer NEW. Fresh ingestion runs before OLD's queue.
        assert sync_payments(store, square, protect) == 1
        assert square.returned == [["NEW"]]
        assert protect.calls == [1784216700000, 1784215800000]
        assert store.get_transaction("NEW")["thumbnail_path"] is not None
        assert store.latest_transaction_ts() == 1784216700000
        old_row = store.get_transaction("OLD")
        assert old_row["thumbnail_path"] is not None
        assert old_row["thumbnail_path"] != "OLD.jpg"
        assert (store.thumbnail_dir / old_row["thumbnail_path"]).read_bytes().endswith(
            b"1784215800000"
        )
    finally:
        store.close()


def test_missing_thumbnail_file_is_requeued_on_reingest(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAM_A, "Register")
    payment = _payment("LOST", "2026-07-16T15:30:00.000Z")

    class Protect:
        calls = 0

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls += 1
            return f"jpeg-{self.calls}".encode()

    protect = Protect()
    try:
        ingest_payment(store, payment, protect)
        original = store.get_transaction("LOST")
        (store.thumbnail_dir / original["thumbnail_path"]).unlink()

        ingest_payment(store, payment, protect)
        missing = store.get_transaction("LOST")
        assert missing["thumbnail_path"] is None
        assert protect.calls == 1

        assert retry_missing_thumbnails(store, protect) == 1
        repaired = store.get_transaction("LOST")
        assert repaired["thumbnail_path"] is not None
        assert (store.thumbnail_dir / repaired["thumbnail_path"]).read_bytes() == (
            b"jpeg-2"
        )
    finally:
        store.close()


def test_reingest_reloads_evidence_after_missing_file_race(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    peer = Store(data_dir)
    store.set_camera_mapping("LOC1", CAM_A, "Register")
    payment = _payment("LOST", "2026-07-16T15:30:00.000Z")

    class Protect:
        def get_snapshot(self, camera_id, ts_ms=None):
            return b"original"

    try:
        ingest_payment(store, payment, Protect())
        original = store.get_transaction("LOST")
        (store.thumbnail_dir / original["thumbnail_path"]).unlink()
        requeue = store.requeue_missing_thumbnail

        def lose_requeue_race(txn_id: str, expected_path: str) -> bool:
            assert peer.requeue_missing_thumbnail(txn_id, expected_path)
            job = peer.claim_thumbnail_retries(1, 10, now=0)[0]
            current_path = "current.jpg"
            (peer.thumbnail_dir / current_path).write_bytes(b"current")
            assert peer.complete_thumbnail_retry(
                txn_id,
                job["lease_token"],
                job["camera_id"],
                job["ts_ms"],
                current_path,
            )
            assert not requeue(txn_id, expected_path)
            return False

        monkeypatch.setattr(store, "requeue_missing_thumbnail", lose_requeue_race)
        ingest_payment(store, payment, protect=None)

        stored = store.get_transaction("LOST")
        assert stored["thumbnail_path"] == "current.jpg"
        assert (store.thumbnail_dir / stored["thumbnail_path"]).read_bytes() == b"current"
        assert store.claim_thumbnail_retries(1, 10, now=0) == []
    finally:
        store.close()
        peer.close()


@pytest.mark.parametrize(
    ("mappings", "expected_camera"),
    [
        (
            [
                ("LOC1", "TERM1", "Register", CAM_B, "Exact"),
                ("LOC1", "", "", CAM_A, "Location"),
                ("*", "", "", CAM_A, "Wildcard"),
            ],
            CAM_B,
        ),
        (
            [
                ("LOC1", "", "", CAM_B, "Location"),
                ("*", "", "", CAM_A, "Wildcard"),
            ],
            CAM_B,
        ),
        ([("*", "", "", CAM_B, "Wildcard")], CAM_B),
        ([], None),
    ],
    ids=("exact", "location", "wildcard", "unmapped"),
)
def test_missing_file_requeue_uses_current_mapping(
    tmp_path, mappings, expected_camera
):
    store = Store(tmp_path / "data")
    txn = _stored_txn("LOST", 1000, camera_id=CAM_A, thumbnail_path="lost.jpg")
    txn["device_id"] = "TERM1"

    try:
        store.upsert_transaction(txn)
        store.replace_camera_mappings(mappings)

        assert store.requeue_missing_thumbnail("LOST", "lost.jpg")
        stored = store.get_transaction("LOST")
        jobs = store.claim_thumbnail_retries(1, 10, now=0)
    finally:
        store.close()

    assert stored["thumbnail_path"] is None
    assert stored["camera_id"] == expected_camera
    assert [job["camera_id"] for job in jobs] == (
        [expected_camera] if expected_camera else []
    )


def test_store_startup_requeues_missing_thumbnail_file(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    store.set_camera_mapping("LOC1", CAM_A, "Register")
    store.upsert_transaction(
        _stored_txn("LOST", 1000, thumbnail_path="vanished.jpg")
    )
    store.close()

    reopened = Store(data_dir)
    try:
        assert reopened.get_transaction("LOST")["thumbnail_path"] is None
        jobs = reopened.claim_thumbnail_retries(1, 10, now=0)
        assert [job["transaction_id"] for job in jobs] == ["LOST"]
    finally:
        reopened.close()


@pytest.mark.parametrize(
    ("mappings", "expected_camera"),
    [
        ([("LOC1", "TERM1", "Terminal", CAM_B, "Exact")], CAM_B),
        ([("LOC1", "", "", CAM_B, "Location")], CAM_B),
        ([("*", "", "", CAM_B, "Wildcard")], CAM_B),
        ([], None),
    ],
    ids=("exact", "location", "wildcard", "unmapped"),
)
def test_store_startup_missing_thumbnail_uses_current_mapping(
    tmp_path, mappings, expected_camera
):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    evidence = store.thumbnail_dir / "vanished.jpg"
    evidence.write_bytes(b"old evidence")
    txn = _stored_txn("LOST", 1000, thumbnail_path=evidence.name)
    txn["device_id"] = "TERM1"
    store.upsert_transaction(txn)

    # Captured evidence keeps its historical camera when mappings change.
    store.replace_camera_mappings(mappings)
    assert store.get_transaction("LOST")["camera_id"] == CAM_A
    store.close()
    evidence.unlink()

    reopened = Store(data_dir)
    try:
        stored = reopened.get_transaction("LOST")
        jobs = reopened.claim_thumbnail_retries(1, 10, now=0)
    finally:
        reopened.close()

    assert stored["thumbnail_path"] is None
    assert stored["camera_id"] == expected_camera
    assert [job["camera_id"] for job in jobs] == (
        [expected_camera] if expected_camera else []
    )


def test_square_failure_still_processes_retry_queue(tmp_path):
    store = Store(tmp_path / "data")
    store.upsert_transaction(_stored_txn("OLD", 1000))

    class Square:
        def list_locations(self):
            return [{"id": "LOC1"}]

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

        def list_payments(self, **params):
            raise SquareError("Square unavailable")

    class Protect:
        def get_snapshot(self, camera_id, ts_ms=None):
            return b"jpeg"

    try:
        with pytest.raises(SquareError, match="Square unavailable"):
            sync_payments(store, Square(), Protect())
        assert store.get_transaction("OLD")["thumbnail_path"] is not None
    finally:
        store.close()


def test_retry_error_does_not_mask_square_failure(tmp_path, monkeypatch, caplog):
    store = Store(tmp_path / "data")

    class Square:
        def list_locations(self):
            return [{"id": "LOC1"}]

        def iter_payment_pages(self, **params):
            yield self.list_payments(**params)

        def list_payments(self, **params):
            raise SquareError("original Square failure")

    def fail_retry(*_args, **_kwargs):
        raise RuntimeError("retry drain failed")

    monkeypatch.setattr("app.sync.retry_missing_thumbnails", fail_retry)
    caplog.set_level(logging.WARNING, logger="spi.sync")
    try:
        with pytest.raises(SquareError, match="original Square failure"):
            sync_payments(store, Square(), object())
        assert "Thumbnail retry batch failed: retry drain failed" in caplog.text
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


def test_camera_change_resets_retry_backoff(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.upsert_transaction(_stored_txn("P", 1000, camera_id=CAM_A))
        failed = store.claim_thumbnail_retries(1, 10, now=100)[0]
        assert _fail(store, failed, 100)
        assert store.claim_thumbnail_retries(1, 10, now=109) == []

        store.upsert_transaction(_stored_txn("P", 1000, camera_id=CAM_B))
        replacement = store.claim_thumbnail_retries(1, 10, now=100)[0]
        assert replacement["camera_id"] == CAM_B
        assert replacement["ts_ms"] == 1000
        assert replacement["attempts"] == 0
    finally:
        store.close()


def test_mapping_save_retargets_pending_evidence_and_cancels_old_lease(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.set_camera_mapping("LOC1", CAM_A, "Original camera")
        pending_txn = _stored_txn("PENDING", 1000, camera_id=CAM_A)
        pending_txn["device_id"] = "TERM_A"
        store.upsert_transaction(pending_txn)
        store.upsert_transaction(
            _stored_txn(
                "CAPTURED",
                2000,
                camera_id=CAM_A,
                thumbnail_path="captured.jpg",
            )
        )

        first = store.claim_thumbnail_retries(1, 10, now=100)[0]
        assert _fail(store, first, 100)
        leased = store.claim_thumbnail_retries(1, 10, now=110)[0]
        assert leased["attempts"] == 1

        store.replace_camera_mappings(
            [("LOC1", "TERM_A", "Register A", CAM_B, "New camera")]
        )

        pending = store.get_transaction("PENDING")
        captured = store.get_transaction("CAPTURED")
        assert pending["camera_id"] == CAM_B
        assert captured["camera_id"] == CAM_A
        assert captured["thumbnail_path"] == "captured.jpg"
        replacement = store.claim_thumbnail_retries(1, 10, now=110)[0]
        assert replacement["camera_id"] == CAM_B
        assert replacement["attempts"] == 0
        assert replacement["lease_token"] != leased["lease_token"]
    finally:
        store.close()


def test_mapping_save_assigns_previously_unmapped_evidence(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.upsert_transaction(_stored_txn("P", 1000, camera_id=None))
        assert store.claim_thumbnail_retries(1, 10, now=100) == []

        store.replace_camera_mappings([("LOC1", "", "", CAM_B, "Selected camera")])

        assert store.get_transaction("P")["camera_id"] == CAM_B
        job = store.claim_thumbnail_retries(1, 10, now=100)[0]
        assert job["camera_id"] == CAM_B
        assert job["attempts"] == 0
    finally:
        store.close()


def test_mapping_removal_clears_pending_camera_and_retry(tmp_path):
    store = Store(tmp_path / "data")
    try:
        store.set_camera_mapping("LOC1", CAM_A, "Original camera")
        store.upsert_transaction(_stored_txn("P", 1000, camera_id=CAM_A))
        leased = store.claim_thumbnail_retries(1, 10, now=100)[0]

        store.replace_camera_mappings([])

        assert store.get_transaction("P")["camera_id"] is None
        assert store.claim_thumbnail_retries(1, 10, now=100) == []
        assert not store.complete_thumbnail_retry(
            "P", leased["lease_token"], CAM_A, 1000, "old-camera.jpg"
        )
    finally:
        store.close()


def test_stale_reingest_cannot_move_transaction_timestamp(tmp_path):
    store = Store(tmp_path / "data")
    original = _stored_txn("P", 1000)
    original["created_at"] = "2026-07-16T15:30:00.000Z"
    original["updated_at"] = "2026-07-16T17:00:00.000Z"
    original["updated_ts_ms"] = 1784224800000
    stale = _stored_txn("P", 2000)
    stale["created_at"] = "2026-07-16T16:30:00.000Z"
    stale["updated_at"] = "2026-07-16T16:30:00.000Z"
    stale["updated_ts_ms"] = 1784219400000
    try:
        store.upsert_transaction(original)
        store.upsert_transaction(stale)
        saved = store.get_transaction("P")
        assert saved["created_at"] == original["created_at"]
        assert saved["ts_ms"] == original["ts_ms"]
    finally:
        store.close()


def test_reingest_preserves_captured_camera_across_remap(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAM_A, "Original camera")
    payment = _payment("P", "2026-07-16T15:30:00.000Z")

    class Protect:
        calls = 0

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls += 1
            return f"jpeg-{camera_id}-{ts_ms}".encode()

    protect = Protect()
    try:
        ingest_payment(store, payment, protect)
        original = store.get_transaction("P")
        original_image = (store.thumbnail_dir / original["thumbnail_path"]).read_bytes()

        store.set_camera_mapping("LOC1", CAM_B, "New camera")
        ingest_payment(store, payment, protect)
        saved = store.get_transaction("P")

        assert protect.calls == 1
        assert saved["camera_id"] == CAM_A
        assert saved["thumbnail_path"] == original["thumbnail_path"]
        assert (
            store.thumbnail_dir / saved["thumbnail_path"]
        ).read_bytes() == original_image
    finally:
        store.close()


def test_reingest_missing_evidence_adopts_remapped_camera(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAM_A, "Original camera")
    payment = _payment("P", "2026-07-16T15:30:00.000Z")
    ingest_payment(store, payment, None)
    failed = store.claim_thumbnail_retries(1, 10, now=100)[0]
    assert _fail(store, failed, 100)

    class Protect:
        calls = 0

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls += 1
            return b"jpeg"

    protect = Protect()
    try:
        store.set_camera_mapping("LOC1", CAM_B, "New camera")
        ingest_payment(store, payment, protect)
        saved = store.get_transaction("P")
        assert protect.calls == 0
        assert saved["camera_id"] == CAM_B
        assert saved["thumbnail_path"] is None

        replacement = store.claim_thumbnail_retries(1, 10, now=100)[0]
        assert replacement["camera_id"] == CAM_B
        assert replacement["attempts"] == 0
    finally:
        store.close()


def test_mapping_save_wins_over_blocked_initial_snapshot(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAM_A, "Original camera")
    payment = _payment("P", "2026-07-16T15:30:00.000Z")
    snapshot_started = threading.Event()
    release_snapshot = threading.Event()
    errors: list[Exception] = []

    class BlockingProtect:
        def get_snapshot(self, camera_id, ts_ms=None):
            assert camera_id == CAM_A
            snapshot_started.set()
            assert release_snapshot.wait(timeout=5)
            return b"old-camera-frame"

    def ingest() -> None:
        try:
            ingest_payment(store, payment, BlockingProtect())
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=ingest)
    worker.start()
    try:
        assert snapshot_started.wait(timeout=5)
        store.replace_camera_mappings(
            [("LOC1", "", "", CAM_B, "New camera")]
        )
        release_snapshot.set()
        worker.join(timeout=5)

        saved = store.get_transaction("P")
        jobs = store.claim_thumbnail_retries(1, 10, now=0)
        assert not worker.is_alive()
        assert errors == []
        assert saved["camera_id"] == CAM_B
        assert saved["thumbnail_path"] is None
        assert [job["camera_id"] for job in jobs] == [CAM_B]
        assert list(store.thumbnail_dir.iterdir()) == []
    finally:
        release_snapshot.set()
        worker.join(timeout=5)
        store.close()


def test_late_duplicate_webhook_ingest_cannot_undo_pending_evidence_remap(
    tmp_path, monkeypatch
):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAM_A, "Original camera")
    payment = _payment("P", "2026-07-16T15:30:00.000Z")
    ingest_payment(store, payment, None)
    upsert_started = threading.Event()
    release_upsert = threading.Event()
    errors: list[Exception] = []
    original_upsert = store.upsert_transaction

    def blocked_upsert(txn, **kwargs):
        upsert_started.set()
        assert release_upsert.wait(timeout=5)
        return original_upsert(txn, **kwargs)

    def ingest_duplicate() -> None:
        try:
            ingest_payment(store, payment, None)
        except Exception as exc:
            errors.append(exc)

    monkeypatch.setattr(store, "upsert_transaction", blocked_upsert)
    worker = threading.Thread(target=ingest_duplicate)
    worker.start()
    try:
        assert upsert_started.wait(timeout=5)
        store.replace_camera_mappings(
            [("LOC1", "", "", CAM_B, "New camera")]
        )
        assert store.get_transaction("P")["camera_id"] == CAM_B
        release_upsert.set()
        worker.join(timeout=5)

        saved = store.get_transaction("P")
        jobs = store.claim_thumbnail_retries(1, 10, now=0)
        assert not worker.is_alive()
        assert errors == []
        assert saved["camera_id"] == CAM_B
        assert saved["thumbnail_path"] is None
        assert [job["camera_id"] for job in jobs] == [CAM_B]
    finally:
        release_upsert.set()
        worker.join(timeout=5)
        store.close()


def test_reingest_does_not_bypass_retry_backoff(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAM_A, "Register")
    payment = _payment("P", "2026-07-16T15:30:00.000Z")
    ingest_payment(store, payment, None)
    failed = store.claim_thumbnail_retries(1, 10, now=100)[0]
    assert _fail(store, failed, 100)

    class Protect:
        calls = 0

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls += 1
            return b"jpeg"

    protect = Protect()
    try:
        ingest_payment(store, payment, protect)
        assert protect.calls == 0
        assert store.get_transaction("P")["thumbnail_path"] is None
        assert store.claim_thumbnail_retries(1, 10, now=109) == []
        assert store.claim_thumbnail_retries(1, 10, now=110)[0]["attempts"] == 1
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


def test_request_error_releases_job_and_continues_batch(tmp_path):
    store = Store(tmp_path / "data")
    store.upsert_transaction(_stored_txn("P1", 1000))
    store.upsert_transaction(_stored_txn("P2", 1001))

    class Protect:
        calls = 0

        def get_snapshot(self, camera_id, ts_ms=None):
            self.calls += 1
            if ts_ms == 1000:
                request = httpx.Request("GET", "https://protect.local/snapshot")
                raise httpx.ConnectError("Protect offline", request=request)
            return b"jpeg"

    protect = Protect()
    try:
        assert retry_missing_thumbnails(store, protect, batch_size=2, now=100) == 1
        assert protect.calls == 2
        assert store.get_transaction("P1")["thumbnail_path"] is None
        assert store.get_transaction("P2")["thumbnail_path"] is not None
        assert store.has_due_thumbnail_retries(now=129) is False
        assert store.has_due_thumbnail_retries(now=130) is True
        assert store.claim_thumbnail_retries(1, 10, now=129) == []
        assert store.claim_thumbnail_retries(1, 10, now=130)[0]["attempts"] == 1
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


def test_successful_json_snapshot_response_keeps_durable_retry(tmp_path):
    store = Store(tmp_path / "data")
    store.upsert_transaction(_stored_txn("P", 1000))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, headers={"x-csrf-token": "c"}, json={})
        return httpx.Response(200, json={"error": "Recording not found"})

    protect = ProtectClient(
        "protect.local",
        "user",
        "password",
        transport=httpx.MockTransport(handler),
    )
    try:
        assert retry_missing_thumbnails(store, protect, batch_size=1, now=100) == 0
        assert store.get_transaction("P")["thumbnail_path"] is None
        assert store.claim_thumbnail_retries(1, 5, now=129) == []
        retry = store.claim_thumbnail_retries(1, 5, now=130)[0]
        assert retry["transaction_id"] == "P"
        assert retry["attempts"] == 1
    finally:
        protect.close()
        store.close()


def test_retry_file_write_failure_is_caught(tmp_path, monkeypatch):
    store = Store(tmp_path / "data")
    store.upsert_transaction(_stored_txn("P", 1000))

    class Protect:
        def get_snapshot(self, camera_id, ts_ms=None):
            return b"jpeg"

    def fail_write(_path: Path, _image: bytes):
        raise OSError("disk full")

    monkeypatch.setattr("app.sync.write_thumbnail", fail_write)
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
    worker_store.upsert_transaction(_stored_txn("P1", 1000))
    worker_store.upsert_transaction(_stored_txn("P2", 1001))
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
        # Only P1 is leased while its I/O runs; P2 remains claimable.
        other_job = other_store.claim_thumbnail_retries(1, 10, now=100)[0]
        assert other_job["transaction_id"] == "P2"
        # This write needs BEGIN/COMMIT access while snapshot I/O is blocked.
        other_store.set_setting("concurrent", "ok")
        assert other_store.get_setting("concurrent") == "ok"
    finally:
        release.set()
        thread.join(2)
        worker_store.close()
        other_store.close()


def test_console_switch_invalidates_thumbnail_retry_in_flight(tmp_path):
    snapshot_started = threading.Event()
    release_snapshot = threading.Event()

    class OldProtect:
        host = "old-console.local"

        def get_snapshot(self, camera_id, ts_ms=None):
            snapshot_started.set()
            assert release_snapshot.wait(timeout=5)
            return b"old console retry evidence"

    store = Store(tmp_path / "data")
    initial_settings = {
        "protect.host": ("old-console.local", False),
        "protect.username": ("user", False),
        "protect.password": ("password", True),
        "protect.verify_ssl": ("0", False),
    }
    assert store.update_protect_settings(
        initial_settings,
        expected_host=None,
        expected_generation=None,
    ) is False
    store.set_camera_mapping("LOC1", CAM_A, "Register")
    ingest_payment(
        store,
        _payment("P_SWITCH", "2026-07-16T15:30:00.000Z"),
        protect=None,
    )
    generation = store.get_setting("protect.console_generation")
    switch_token = store.protect_console_switch_token(
        "new-console.local",
        None,
        expected_host="old-console.local",
        expected_generation=generation,
        expected_console_id=None,
    )
    assert switch_token

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                retry_missing_thumbnails,
                store,
                OldProtect(),
                batch_size=1,
                now=100,
            )
            assert snapshot_started.wait(timeout=3)
            assert store.update_protect_settings(
                {
                    **initial_settings,
                    "protect.host": ("new-console.local", False),
                },
                expected_host="old-console.local",
                expected_generation=generation,
                console_switch_token=switch_token,
            )
            release_snapshot.set()
            assert future.result(timeout=5) == 0

        saved = store.get_transaction("P_SWITCH")
        assert saved["camera_id"] is None
        assert saved["thumbnail_path"] is None
        assert store.claim_thumbnail_retries(1, 5, now=100) == []
        assert list(store.thumbnail_dir.iterdir()) == []
    finally:
        release_snapshot.set()
        store.close()


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
