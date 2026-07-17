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


def parse_ts_ms(created_at: str) -> int:
    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def safe_thumbnail_name(payment_id: str) -> str:
    cleaned = _SAFE_ID_RE.sub("", payment_id)[:80]
    if not cleaned:
        raise ValueError("Payment id yields no safe filename")
    return f"{cleaned}.jpg"


def evidence_thumbnail_name(txn_id: str, camera_id: str, ts_ms: int) -> str:
    """Name asynchronous evidence uniquely by its camera and timestamp."""
    cleaned = _SAFE_ID_RE.sub("", txn_id)[:48]
    if not cleaned:
        raise ValueError("Payment id yields no safe filename")
    evidence_hash = hashlib.sha256(
        f"{camera_id}\0{int(ts_ms)}".encode()
    ).hexdigest()[:16]
    return f"{cleaned}-{evidence_hash}.jpg"


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
        except (ProtectError, ValueError) as exc:
            logger.warning("Thumbnail capture failed for %s: %s", txn["id"], exc)

    store.upsert_transaction(txn)
    return txn


def enrich_transaction_thumbnail(
    store: Store, txn_id: str, protect: ProtectClient
) -> bool:
    """Capture evidence, retrying once if its camera changes in flight."""
    for _attempt in range(2):
        txn = store.get_transaction(txn_id)
        if not txn or not txn.get("camera_id") or txn.get("thumbnail_path"):
            return False
        camera_id = txn["camera_id"]
        ts_ms = txn["ts_ms"]
        try:
            image = protect.get_snapshot(camera_id, ts_ms=ts_ms)
            name = evidence_thumbnail_name(txn_id, camera_id, ts_ms)
            (store.thumbnail_dir / name).write_bytes(image)
            if store.set_transaction_thumbnail(
                txn_id,
                name,
                expected_camera_id=camera_id,
                expected_ts_ms=ts_ms,
            ):
                return True
        except (ProtectError, ValueError) as exc:
            logger.warning("Thumbnail capture failed for %s: %s", txn_id, exc)
            return False

        current = store.get_transaction(txn_id)
        if (
            not current
            or current.get("thumbnail_path")
            or (
                current.get("camera_id") == camera_id
                and current.get("ts_ms") == ts_ms
            )
        ):
            return False
        logger.info("Camera evidence changed while enriching %s; retrying", txn_id)
    return False


def sync_payments(
    store: Store, square: SquareClient, protect: ProtectClient | None
) -> int:
    """Pull recent Square payments and ingest them. Returns count ingested."""
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
