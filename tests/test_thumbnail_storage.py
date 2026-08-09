"""Compression, retention, and storage-control integration tests."""

from __future__ import annotations

import io
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

from app import sync
from app.store import Store
from app.thumbnail_storage import (
    ThumbnailPolicy,
    policy_values,
    prepare_thumbnail,
    run_thumbnail_maintenance,
)
from .conftest import ADMIN_PASSWORD


NOW_MS = 1_800_000_000_000
DAY_MS = 24 * 60 * 60 * 1000
CAMERA_ID = "cam1aaaaaaaaaaaaaaaaaaaaa"


def _jpeg(width: int = 1600, height: int = 900, quality: int = 95) -> bytes:
    image = Image.effect_noise((width, height), 100).convert("RGB")
    output = io.BytesIO()
    image.save(output, format="JPEG", quality=quality)
    return output.getvalue()


def _policy(
    *,
    enabled: bool = False,
    quality: int = 72,
    dimension: int = 960,
    retention_days: int = 0,
    max_storage_mib: int = 0,
    revision: int = 1,
) -> ThumbnailPolicy:
    return ThumbnailPolicy(
        compression_enabled=enabled,
        jpeg_quality=quality,
        max_dimension=dimension,
        retention_days=retention_days,
        max_storage_mib=max_storage_mib,
        revision=revision,
    )


def _transaction(
    transaction_id: str,
    ts_ms: int,
    path: str,
    size: int,
    *,
    revision: int = 0,
) -> dict:
    created_at = (
        datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    return {
        "id": transaction_id,
        "created_at": created_at,
        "updated_at": created_at,
        "ts_ms": ts_ms,
        "updated_ts_ms": ts_ms,
        "amount": 99,
        "currency": "USD",
        "status": "COMPLETED",
        "location_id": "LOC1",
        "camera_id": CAMERA_ID,
        "thumbnail_path": path,
        "thumbnail_bytes": size,
        "thumbnail_policy_revision": revision,
        "raw": {},
    }


def _add_asset(
    store: Store,
    transaction_id: str,
    ts_ms: int,
    data: bytes,
    *,
    revision: int = 0,
) -> Path:
    path = store.thumbnail_dir / f"{transaction_id}.jpg"
    sync.write_thumbnail(path, data)
    store.upsert_transaction(
        _transaction(
            transaction_id,
            ts_ms,
            path.name,
            len(data),
            revision=revision,
        )
    )
    return path


def _save_policy(store: Store, policy: ThumbnailPolicy) -> int:
    return store.update_thumbnail_storage_settings(policy_values(policy))


def test_compression_resizes_and_reduces_large_jpeg():
    original = _jpeg()
    prepared = prepare_thumbnail(
        original,
        _policy(enabled=True, quality=40, dimension=320, revision=7),
    )

    assert prepared.error is None
    assert prepared.changed is True
    assert prepared.policy_revision == 7
    assert len(prepared.data) < len(original)
    with Image.open(io.BytesIO(prepared.data)) as image:
        assert max(image.size) <= 320
        assert image.mode == "RGB"
        assert image.format == "JPEG"


def test_compression_failure_preserves_original_bytes():
    original = b"not-a-camera-jpeg"

    prepared = prepare_thumbnail(
        original,
        _policy(enabled=True, revision=4),
    )

    assert prepared.data == original
    assert prepared.changed is False
    assert prepared.policy_revision == 4
    assert "UnidentifiedImageError" in prepared.error


def test_disabled_compression_never_decodes_or_changes_bytes():
    original = b"opaque-provider-bytes"

    prepared = prepare_thumbnail(original, _policy(enabled=False, revision=9))

    assert prepared.data == original
    assert prepared.policy_revision == 0
    assert prepared.error is None


def test_age_retention_preserves_transactions_and_prevents_recapture(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAMERA_ID, "Counter")
    old_path = _add_asset(store, "OLD", NOW_MS - 3 * DAY_MS, b"old-image")
    recent_path = _add_asset(store, "RECENT", NOW_MS, b"recent-image")
    _save_policy(store, _policy(retention_days=1))

    try:
        result = run_thumbnail_maintenance(
            store,
            sync.write_thumbnail,
            now_ms=NOW_MS,
        )
        old = store.get_transaction("OLD")
        recent = store.get_transaction("RECENT")

        class Protect:
            calls = 0

            def get_snapshot(self, camera_id, ts_ms=None):
                self.calls += 1
                return b"should-not-be-recaptured"

        protect = Protect()
        sync.ingest_payment(
            store,
            {
                "id": "OLD",
                "created_at": old["created_at"],
                "updated_at": old["updated_at"],
                "amount_money": {"amount": 99, "currency": "USD"},
                "status": "COMPLETED",
                "location_id": "LOC1",
            },
            protect,
        )
    finally:
        store.close()

    assert result["retired_age_count"] == 1
    assert old["camera_id"] == CAMERA_ID
    assert old["thumbnail_path"] is None
    assert old["thumbnail_retired_at"] == NOW_MS
    assert old["thumbnail_retired_reason"] == "age"
    assert not old_path.exists()
    assert recent["thumbnail_path"] == recent_path.name
    assert recent_path.exists()
    assert protect.calls == 0


def test_storage_quota_retires_oldest_until_below_limit(tmp_path):
    store = Store(tmp_path / "data")
    paths = [
        _add_asset(
            store,
            f"TXN-{index}",
            NOW_MS - (3 - index) * DAY_MS,
            bytes([index]) * (600 * 1024),
        )
        for index in range(3)
    ]
    _save_policy(store, _policy(max_storage_mib=1))

    try:
        result = run_thumbnail_maintenance(
            store,
            sync.write_thumbnail,
            now_ms=NOW_MS,
        )
        rows = [store.get_transaction(f"TXN-{index}") for index in range(3)]
        summary = store.thumbnail_storage_summary()
    finally:
        store.close()

    assert result["retired_quota_count"] == 2
    assert [row["thumbnail_retired_reason"] for row in rows] == [
        "quota",
        "quota",
        "",
    ]
    assert [path.exists() for path in paths] == [False, False, True]
    assert summary["active_bytes"] == 600 * 1024
    assert summary["active_count"] == 1
    assert summary["retired_count"] == 2


def test_quota_scale_preserves_1000_transaction_rows_across_restart(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    for index in range(1000):
        _add_asset(
            store,
            f"SCALE-{index:04d}",
            NOW_MS + index,
            bytes([index % 251]) * 2048,
        )
    _save_policy(store, _policy(max_storage_mib=1))

    result = run_thumbnail_maintenance(
        store,
        sync.write_thumbnail,
        now_ms=NOW_MS + 1000,
    )
    count = store._db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    store.close()

    reopened = Store(data_dir)
    try:
        reopened_count = reopened._db.execute(
            "SELECT COUNT(*) FROM transactions"
        ).fetchone()[0]
        queued = reopened.claim_thumbnail_retries(100, 60, now=0)
        summary = reopened.thumbnail_storage_summary()
    finally:
        reopened.close()

    assert result["retired_quota_count"] == 488
    assert summary == {
        "active_count": 512,
        "active_bytes": 1024 * 1024,
        "retired_count": 488,
    }
    assert count == reopened_count == 1000
    assert queued == []


def test_existing_optimization_is_one_time_per_policy_revision(tmp_path):
    store = Store(tmp_path / "data")
    original = _jpeg()
    path = _add_asset(store, "OPTIMIZE", NOW_MS, original)
    revision = _save_policy(
        store,
        _policy(enabled=True, quality=40, dimension=320),
    )

    try:
        first = run_thumbnail_maintenance(
            store,
            sync.write_thumbnail,
            optimize_existing=True,
            now_ms=NOW_MS,
        )
        first_bytes = path.read_bytes()
        stored = store.get_transaction("OPTIMIZE")
        second = run_thumbnail_maintenance(
            store,
            sync.write_thumbnail,
            optimize_existing=True,
            now_ms=NOW_MS,
        )
    finally:
        store.close()

    assert revision > 0
    assert first["optimized_count"] == 1
    assert len(first_bytes) < len(original)
    assert stored["thumbnail_bytes"] == len(first_bytes)
    assert stored["thumbnail_policy_revision"] == revision
    assert second["optimized_count"] == 0
    assert path.read_bytes() == first_bytes


def test_retention_only_change_does_not_force_recompression(tmp_path):
    store = Store(tmp_path / "data")
    try:
        first_revision = _save_policy(store, _policy(enabled=True))
        second_revision = _save_policy(
            store,
            _policy(enabled=True, retention_days=30),
        )
        third_revision = _save_policy(
            store,
            _policy(enabled=True, quality=60, retention_days=30),
        )
    finally:
        store.close()

    assert second_revision == first_revision
    assert third_revision == first_revision + 1


def test_relaxed_policy_stops_stale_inflight_retention(tmp_path, monkeypatch):
    store = Store(tmp_path / "data")
    path = _add_asset(store, "KEEP", NOW_MS - 5 * DAY_MS, b"keep-me")
    _save_policy(store, _policy(retention_days=1))
    policy_loaded = threading.Event()
    release_listing = threading.Event()
    original_listing = store.list_thumbnail_assets
    listing_calls = 0

    def blocked_listing():
        nonlocal listing_calls
        listing_calls += 1
        rows = original_listing()
        if listing_calls == 1:
            policy_loaded.set()
            assert release_listing.wait(timeout=5)
        return rows

    monkeypatch.setattr(store, "list_thumbnail_assets", blocked_listing)
    outcome: list[dict] = []
    worker = threading.Thread(
        target=lambda: outcome.append(
            run_thumbnail_maintenance(
                store,
                sync.write_thumbnail,
                now_ms=NOW_MS,
            )
        )
    )
    worker.start()
    try:
        assert policy_loaded.wait(timeout=5)
        _save_policy(store, _policy(retention_days=0))
    finally:
        release_listing.set()
        worker.join(timeout=5)
        store.close()

    assert not worker.is_alive()
    assert outcome[0]["policy_changed_during_run"] == 1
    assert outcome[0]["retired_age_count"] == 0
    assert path.read_bytes() == b"keep-me"


def test_storage_settings_api_requires_auth_and_validates_bounds(client, authed):
    # The fixture pair refers to the same TestClient; log out to prove the
    # endpoint is protected, then authenticate again for mutation coverage.
    assert authed.post("/api/logout").status_code == 200
    assert client.get("/api/settings/thumbnail-storage").status_code == 401
    assert client.post(
        "/api/login", json={"password": ADMIN_PASSWORD}
    ).status_code == 200
    invalid = client.put(
        "/api/settings/thumbnail-storage",
        json={
            "compression_enabled": True,
            "jpeg_quality": 1,
            "max_dimension": 960,
            "retention_days": 0,
            "max_storage_mib": 0,
        },
    )
    assert invalid.status_code == 422

    saved = client.put(
        "/api/settings/thumbnail-storage",
        json={
            "compression_enabled": True,
            "jpeg_quality": 68,
            "max_dimension": 800,
            "retention_days": 14,
            "max_storage_mib": 2048,
        },
    )

    assert saved.status_code == 200, saved.text
    payload = saved.json()
    assert payload["compression_enabled"] is True
    assert payload["jpeg_quality"] == 68
    assert payload["max_dimension"] == 800
    assert payload["retention_days"] == 14
    assert payload["max_storage_mib"] == 2048
    assert payload["usage"] == {
        "active_count": 0,
        "active_bytes": 0,
        "retired_count": 0,
    }


def test_storage_settings_compress_before_enforcing_new_quota(authed):
    store = authed.app.state.store
    originals = [_jpeg(), _jpeg()]
    for index, original in enumerate(originals):
        _add_asset(store, f"QUOTA-{index}", NOW_MS + index, original)
    assert sum(map(len, originals)) > 1024 * 1024

    saved = authed.put(
        "/api/settings/thumbnail-storage",
        json={
            "compression_enabled": True,
            "jpeg_quality": 40,
            "max_dimension": 320,
            "retention_days": 0,
            "max_storage_mib": 1,
        },
    )
    assert saved.status_code == 200, saved.text

    deadline = time.monotonic() + 10
    while True:
        settings = authed.get("/api/settings/thumbnail-storage").json()
        if settings["maintenance"]["state"] not in {"queued", "running"}:
            break
        assert time.monotonic() < deadline
        time.sleep(0.01)

    assert settings["maintenance"]["state"] == "complete"
    assert settings["maintenance"]["optimize_existing"] is True
    assert settings["maintenance"]["result"]["optimized_count"] == 2
    assert settings["maintenance"]["result"]["retired_quota_count"] == 0
    assert settings["usage"]["active_count"] == 2
    assert settings["usage"]["retired_count"] == 0
    assert settings["usage"]["active_bytes"] < 1024 * 1024


def test_retired_thumbnail_api_is_gone_but_timeline_link_remains(authed):
    store = authed.app.state.store
    store.set_setting("protect.host", "192.0.2.10")
    path = _add_asset(store, "EXPIRED", NOW_MS - 2 * DAY_MS, b"jpeg")
    _save_policy(store, _policy(retention_days=1))
    run_thumbnail_maintenance(
        store,
        sync.write_thumbnail,
        now_ms=NOW_MS,
    )

    feed = authed.get("/api/transactions")
    thumbnail = authed.get("/api/thumbnails/EXPIRED")

    assert feed.status_code == 200
    row = feed.json()[0]
    assert row["thumbnail_status"] == "expired"
    assert row["thumbnail_url"] is None
    assert row["deep_link"]
    assert thumbnail.status_code == 410
    assert not path.exists()
