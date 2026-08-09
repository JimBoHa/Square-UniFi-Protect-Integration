"""Thumbnail compression, accounting, and retention maintenance."""

from __future__ import annotations

import io
import logging
import os
import stat
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from PIL import Image, ImageOps, UnidentifiedImageError

from .store import (
    THUMBNAIL_COMPRESSION_ENABLED_SETTING,
    THUMBNAIL_JPEG_QUALITY_SETTING,
    THUMBNAIL_MAX_DIMENSION_SETTING,
    THUMBNAIL_MAX_STORAGE_MIB_SETTING,
    THUMBNAIL_POLICY_REVISION_SETTING,
    THUMBNAIL_RETENTION_DAYS_SETTING,
    THUMBNAIL_STORAGE_SETTING_KEYS,
)

if TYPE_CHECKING:
    from .store import Store

logger = logging.getLogger("spi.thumbnail_storage")

DEFAULT_JPEG_QUALITY = 72
DEFAULT_MAX_DIMENSION = 960
DEFAULT_RETENTION_DAYS = 0
DEFAULT_MAX_STORAGE_MIB = 0
MAX_THUMBNAIL_FILE_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class ThumbnailPolicy:
    compression_enabled: bool
    jpeg_quality: int
    max_dimension: int
    retention_days: int
    max_storage_mib: int
    revision: int


@dataclass(frozen=True)
class PreparedThumbnail:
    data: bytes
    policy_revision: int
    changed: bool
    error: str | None = None


def _bounded_int(
    value: str | None,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value) if value is not None else default
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def policy_from_settings(settings: dict[str, str | None]) -> ThumbnailPolicy:
    """Normalize persisted values, including databases edited by hand."""
    return ThumbnailPolicy(
        compression_enabled=(
            settings.get(THUMBNAIL_COMPRESSION_ENABLED_SETTING) == "1"
        ),
        jpeg_quality=_bounded_int(
            settings.get(THUMBNAIL_JPEG_QUALITY_SETTING),
            DEFAULT_JPEG_QUALITY,
            30,
            95,
        ),
        max_dimension=_bounded_int(
            settings.get(THUMBNAIL_MAX_DIMENSION_SETTING),
            DEFAULT_MAX_DIMENSION,
            320,
            3840,
        ),
        retention_days=_bounded_int(
            settings.get(THUMBNAIL_RETENTION_DAYS_SETTING),
            DEFAULT_RETENTION_DAYS,
            0,
            3650,
        ),
        max_storage_mib=_bounded_int(
            settings.get(THUMBNAIL_MAX_STORAGE_MIB_SETTING),
            DEFAULT_MAX_STORAGE_MIB,
            0,
            1_048_576,
        ),
        revision=_bounded_int(
            settings.get(THUMBNAIL_POLICY_REVISION_SETTING),
            0,
            0,
            (1 << 63) - 1,
        ),
    )


def load_policy(store: Store) -> ThumbnailPolicy:
    return policy_from_settings(store.get_settings(THUMBNAIL_STORAGE_SETTING_KEYS))


def policy_values(policy: ThumbnailPolicy) -> dict[str, str]:
    """Serialize the editable portion of a validated policy."""
    return {
        THUMBNAIL_COMPRESSION_ENABLED_SETTING: (
            "1" if policy.compression_enabled else "0"
        ),
        THUMBNAIL_JPEG_QUALITY_SETTING: str(policy.jpeg_quality),
        THUMBNAIL_MAX_DIMENSION_SETTING: str(policy.max_dimension),
        THUMBNAIL_RETENTION_DAYS_SETTING: str(policy.retention_days),
        THUMBNAIL_MAX_STORAGE_MIB_SETTING: str(policy.max_storage_mib),
    }


def prepare_thumbnail(image: bytes, policy: ThumbnailPolicy) -> PreparedThumbnail:
    """Compress one camera JPEG, preserving original bytes on any failure."""
    original = bytes(image)
    if not policy.compression_enabled:
        return PreparedThumbnail(original, 0, False)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(original)) as source:
                source.load()
                prepared = ImageOps.exif_transpose(source)
                prepared.thumbnail(
                    (policy.max_dimension, policy.max_dimension),
                    Image.Resampling.LANCZOS,
                )
                if prepared.mode not in {"RGB", "L"}:
                    if "A" in prepared.getbands():
                        rgba = prepared.convert("RGBA")
                        background = Image.new("RGBA", rgba.size, "white")
                        background.alpha_composite(rgba)
                        prepared = background.convert("RGB")
                    else:
                        prepared = prepared.convert("RGB")
                output = io.BytesIO()
                prepared.save(
                    output,
                    format="JPEG",
                    quality=policy.jpeg_quality,
                    optimize=True,
                    progressive=True,
                )
        compressed = output.getvalue()
        # Re-encoding an already-small JPEG can increase disk use. Mark it as
        # processed but keep the smaller original.
        if len(compressed) >= len(original):
            return PreparedThumbnail(original, policy.revision, False)
        return PreparedThumbnail(compressed, policy.revision, True)
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        ValueError,
    ) as exc:
        return PreparedThumbnail(
            original,
            policy.revision,
            False,
            f"{type(exc).__name__}: {exc}",
        )


def prepare_thumbnail_for_store(store: Store, image: bytes) -> PreparedThumbnail:
    return prepare_thumbnail(image, load_policy(store))


def read_thumbnail_file(directory: Path, name: str) -> bytes:
    """Read one bounded, regular local file without following a final symlink."""
    relative = Path(name)
    if relative.name != name:
        raise ValueError("Thumbnail path is not local")
    path = Path(directory) / relative
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    chunks: list[bytes] = []
    size = 0
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("Thumbnail is not a regular file")
        if metadata.st_size > MAX_THUMBNAIL_FILE_BYTES:
            raise OSError("Thumbnail exceeds the maintenance size limit")
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > MAX_THUMBNAIL_FILE_BYTES:
                raise OSError("Thumbnail exceeds the maintenance size limit")
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def thumbnail_file_size(directory: Path, name: str) -> int:
    """Return a regular-file size without reading image content."""
    relative = Path(name)
    if relative.name != name:
        raise ValueError("Thumbnail path is not local")
    path = Path(directory) / relative
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("Thumbnail is not a regular file")
        return int(metadata.st_size)
    finally:
        os.close(fd)


def _current_asset(store: Store, asset: dict) -> dict | None:
    current = store.get_transaction(asset["id"])
    if (
        current is None
        or current.get("thumbnail_path") != asset["thumbnail_path"]
        or current.get("thumbnail_retired_at") is not None
    ):
        return None
    return current


def run_thumbnail_maintenance(
    store: Store,
    write_file: Callable[[Path, bytes], None],
    *,
    optimize_existing: bool = False,
    now_ms: int | None = None,
) -> dict[str, int]:
    """Reconcile usage, optionally optimize old files, then enforce retention."""
    policy = load_policy(store)
    started_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
    before = store.thumbnail_storage_summary()
    optimized = 0
    optimization_errors = 0
    policy_stale = False

    for asset in store.list_thumbnail_assets():
        if policy_stale:
            break
        expected_revision = int(asset.get("thumbnail_policy_revision") or 0)
        should_optimize = bool(
            optimize_existing
            and policy.compression_enabled
            and expected_revision < policy.revision
        )
        if not should_optimize:
            if asset.get("thumbnail_bytes") is not None:
                continue
            try:
                with store.integration_guard():
                    if _current_asset(store, asset) is None:
                        continue
                    size = thumbnail_file_size(
                        store.thumbnail_dir, asset["thumbnail_path"]
                    )
                    store.update_thumbnail_metadata(
                        asset["id"],
                        asset["thumbnail_path"],
                        size,
                        expected_revision,
                        expected_policy_revision=expected_revision,
                    )
            except (OSError, ValueError) as exc:
                logger.warning(
                    "Could not inspect thumbnail %s: %s", asset["id"], exc
                )
            continue

        try:
            with store.integration_guard():
                if _current_asset(store, asset) is None:
                    continue
                original = read_thumbnail_file(
                    store.thumbnail_dir, asset["thumbnail_path"]
                )
        except (OSError, ValueError) as exc:
            optimization_errors += 1
            logger.warning(
                "Could not inspect thumbnail %s: %s", asset["id"], exc
            )
            continue

        prepared = prepare_thumbnail(original, policy)
        if prepared.error:
            optimization_errors += 1
            logger.warning(
                "Could not compress thumbnail %s: %s",
                asset["id"],
                prepared.error,
            )
        try:
            with store.integration_guard(exclusive=True):
                if load_policy(store) != policy:
                    policy_stale = True
                    continue
                current = _current_asset(store, asset)
                if current is None or int(
                    current.get("thumbnail_policy_revision") or 0
                ) != expected_revision:
                    continue
                if prepared.changed:
                    write_file(
                        store.thumbnail_dir / asset["thumbnail_path"],
                        prepared.data,
                    )
                if store.update_thumbnail_metadata(
                    asset["id"],
                    asset["thumbnail_path"],
                    len(prepared.data),
                    prepared.policy_revision,
                    expected_policy_revision=expected_revision,
                ):
                    optimized += int(prepared.changed)
        except OSError as exc:
            optimization_errors += 1
            logger.warning(
                "Could not publish compressed thumbnail %s: %s",
                asset["id"],
                exc,
            )

    assets = store.list_thumbnail_assets()
    total_bytes = sum(int(asset.get("thumbnail_bytes") or 0) for asset in assets)
    retired_ids: set[str] = set()
    retired_age = 0
    retired_quota = 0

    def retire(asset: dict, reason: str) -> bool:
        nonlocal policy_stale, total_bytes
        retirement_committed = False
        try:
            with store.integration_guard(exclusive=True):
                if load_policy(store) != policy:
                    policy_stale = True
                    return False
                if _current_asset(store, asset) is None:
                    return False
                if not store.retire_thumbnail(
                    asset["id"],
                    asset["thumbnail_path"],
                    reason,
                    retired_at_ms=started_ms,
                ):
                    return False
                retirement_committed = True
                store.delete_unreferenced_thumbnail(asset["thumbnail_path"])
        except OSError as exc:
            if not retirement_committed:
                logger.warning(
                    "Could not retire thumbnail %s: %s", asset["id"], exc
                )
                return False
            # The database retirement already prevents recapture; its durable
            # orphan-cleanup marker retries the unlink after a transient error.
            logger.warning(
                "Could not remove retired thumbnail %s: %s", asset["id"], exc
            )
        retired_ids.add(asset["id"])
        total_bytes = max(0, total_bytes - int(asset.get("thumbnail_bytes") or 0))
        return True

    if policy.retention_days:
        cutoff = started_ms - policy.retention_days * 24 * 60 * 60 * 1000
        for asset in assets:
            if policy_stale:
                break
            if int(asset["ts_ms"]) < cutoff and retire(asset, "age"):
                retired_age += 1

    if policy.max_storage_mib and not policy_stale:
        quota_bytes = policy.max_storage_mib * 1024 * 1024
        for asset in assets:
            if total_bytes <= quota_bytes:
                break
            if asset["id"] in retired_ids:
                continue
            if retire(asset, "quota"):
                retired_quota += 1

    if store.orphan_thumbnail_cleanup_pending():
        try:
            with store.integration_guard(exclusive=True):
                store.remove_orphan_thumbnails()
        except OSError as exc:
            logger.warning("Could not complete thumbnail orphan cleanup: %s", exc)

    after = store.thumbnail_storage_summary()
    return {
        "before_bytes": int(before["active_bytes"]),
        "after_bytes": int(after["active_bytes"]),
        "bytes_saved": max(
            0, int(before["active_bytes"]) - int(after["active_bytes"])
        ),
        "optimized_count": optimized,
        "optimization_error_count": optimization_errors,
        "policy_changed_during_run": int(policy_stale),
        "retired_age_count": retired_age,
        "retired_quota_count": retired_quota,
        "active_count": int(after["active_count"]),
        "retired_count": int(after["retired_count"]),
    }
