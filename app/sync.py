"""Transaction ingestion: match Square payments to camera footage."""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from datetime import datetime, timedelta, timezone

from .protect_client import ProtectClient, ProtectError
from .square_client import SquareClient, payment_from_api
from .store import Store

logger = logging.getLogger("spi.sync")

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_\-]")
BACKFILL_HOURS = 24
THUMBNAIL_RETRY_BATCH_SIZE = 10
THUMBNAIL_RETRY_LEASE_SECONDS = 5 * 60
THUMBNAIL_RETRY_BASE_DELAY_SECONDS = 30
THUMBNAIL_RETRY_MAX_DELAY_SECONDS = 60 * 60


def parse_ts_ms(created_at: str) -> int:
    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def safe_thumbnail_name(payment_id: str) -> str:
    cleaned = _SAFE_ID_RE.sub("", payment_id)[:80]
    if not cleaned:
        raise ValueError("Payment id yields no safe filename")
    return f"{cleaned}.jpg"


def retry_thumbnail_name(
    payment_id: str,
    camera_id: str,
    ts_ms: int,
    lease_token: str,
) -> str:
    """Unique filename bound to claimed camera/time evidence."""
    cleaned = _SAFE_ID_RE.sub("", payment_id)[:48]
    if not cleaned:
        raise ValueError("Payment id yields no safe filename")
    evidence = f"{payment_id}\0{camera_id}\0{int(ts_ms)}\0{lease_token}".encode()
    digest = hashlib.sha256(evidence).hexdigest()[:24]
    return f"{cleaned}-{int(ts_ms)}-{digest}.jpg"


def ingest_payment(
    store: Store, payment: dict, protect: ProtectClient | None
) -> dict:
    """Store one Square payment; capture a Protect thumbnail if possible."""
    txn = payment_from_api(payment)
    if not txn["id"] or not txn["created_at"]:
        raise ValueError("Payment missing id or created_at")
    txn["ts_ms"] = parse_ts_ms(txn["created_at"])

    mapping = store.camera_for_location(txn["location_id"])
    txn["camera_id"] = mapping["camera_id"] if mapping else None
    txn["thumbnail_path"] = None

    existing = store.get_transaction(txn["id"])
    already_has_thumb = bool(existing and existing.get("thumbnail_path"))

    if protect is not None and txn["camera_id"] and not already_has_thumb:
        try:
            image = protect.get_snapshot(txn["camera_id"], ts_ms=txn["ts_ms"])
            name = safe_thumbnail_name(txn["id"])
            (store.thumbnail_dir / name).write_bytes(image)
            txn["thumbnail_path"] = name
        except (ProtectError, ValueError, OSError) as exc:
            logger.warning("Thumbnail capture failed for %s: %s", txn["id"], exc)

    store.upsert_transaction(txn)
    return txn


def retry_missing_thumbnails(
    store: Store,
    protect: ProtectClient,
    *,
    batch_size: int = THUMBNAIL_RETRY_BATCH_SIZE,
    now: float | None = None,
) -> int:
    """Retry a bounded batch independently of Square's current payment window."""
    jobs = store.claim_thumbnail_retries(
        batch_size,
        THUMBNAIL_RETRY_LEASE_SECONDS,
        now=now,
    )
    completed = 0
    for job in jobs:
        path = None
        try:
            image = protect.get_snapshot(job["camera_id"], ts_ms=job["ts_ms"])
            name = retry_thumbnail_name(
                job["transaction_id"],
                job["camera_id"],
                job["ts_ms"],
                job["lease_token"],
            )
            path = store.thumbnail_dir / name
            path.write_bytes(image)
            attached = store.complete_thumbnail_retry(
                job["transaction_id"],
                job["lease_token"],
                job["camera_id"],
                job["ts_ms"],
                name,
            )
            if attached:
                completed += 1
            else:
                path.unlink(missing_ok=True)
        except (ProtectError, ValueError, OSError) as exc:
            if path is not None:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            store.fail_thumbnail_retry(
                job["transaction_id"],
                job["lease_token"],
                job["camera_id"],
                job["ts_ms"],
                str(exc),
                now=now,
                base_delay_seconds=THUMBNAIL_RETRY_BASE_DELAY_SECONDS,
                max_delay_seconds=THUMBNAIL_RETRY_MAX_DELAY_SECONDS,
            )
            logger.warning(
                "Thumbnail retry failed for %s: %s", job["transaction_id"], exc
            )
    return completed


def sync_payments(
    store: Store, square: SquareClient, protect: ProtectClient | None
) -> int:
    """Pull recent Square payments and ingest them. Returns count ingested."""
    if protect is not None:
        retry_missing_thumbnails(store, protect)
    latest = store.latest_transaction_ts()
    if latest:
        begin = datetime.fromtimestamp(latest / 1000, tz=timezone.utc) - timedelta(minutes=5)
    else:
        begin = datetime.now(tz=timezone.utc) - timedelta(hours=BACKFILL_HOURS)
    payments = square.list_payments(
        begin_time=begin.isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    count = 0
    for payment in payments:
        try:
            ingest_payment(store, payment, protect)
            count += 1
        except ValueError as exc:
            logger.warning("Skipping malformed payment: %s", exc)
    return count


class Poller:
    """Background thread that periodically syncs Square payments."""

    def __init__(self, sync_fn, interval_seconds: float = 60.0):
        self._sync_fn = sync_fn
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="spi-poller")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._sync_fn()
            except Exception as exc:  # keep polling through transient failures
                logger.warning("Background sync failed: %s", exc)
