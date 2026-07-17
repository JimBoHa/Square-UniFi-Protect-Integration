"""Transaction ingestion: match Square payments to camera footage."""

from __future__ import annotations

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


def _ingest_payment_with_status(
    store: Store, payment: dict, protect: ProtectClient | None
) -> tuple[dict, bool]:
    """Store one Square payment and return it with insertion status."""
    txn = payment_from_api(payment)
    if not txn["id"] or not txn["created_at"]:
        raise ValueError("Payment missing id or created_at")
    txn["ts_ms"] = parse_ts_ms(txn["created_at"])
    txn["updated_ts_ms"] = parse_ts_ms(txn["updated_at"])

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

    return txn, store.upsert_transaction(txn)


def ingest_payment(
    store: Store, payment: dict, protect: ProtectClient | None
) -> dict:
    """Store one Square payment and return its normalized transaction."""
    txn, _is_new = _ingest_payment_with_status(store, payment, protect)
    return txn


def sync_payments(
    store: Store, square: SquareClient, protect: ProtectClient | None
) -> int:
    """Pull recent Square payments and ingest them. Returns count ingested."""
    count = 0
    seen_payment_ids: set[str] = set()
    for location in square.list_locations():
        location_id = location.get("id", "")
        if not location_id:
            logger.warning("Skipping Square location without an id")
            continue

        # Watermark on Square's updated_at so delayed completions, refunds, and
        # other state changes to older payments are still reconciled.
        latest = store.latest_transaction_updated_ts(location_id=location_id)
        if latest:
            begin = datetime.fromtimestamp(latest / 1000, tz=timezone.utc) - timedelta(
                minutes=5
            )
        else:
            begin = datetime.now(tz=timezone.utc) - timedelta(hours=BACKFILL_HOURS)
        payments = square.list_payments(
            updated_at_begin_time=begin.isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
            sort_field="UPDATED_AT",
            location_id=location_id,
        )

        for payment in payments:
            payment_id = payment.get("id", "")
            if payment_id and payment_id in seen_payment_ids:
                continue
            try:
                _txn, is_new = _ingest_payment_with_status(store, payment, protect)
                if is_new:
                    count += 1
                if payment_id:
                    seen_payment_ids.add(payment_id)
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
