"""Transaction ingestion: match Square payments to camera footage."""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from datetime import datetime, timedelta, timezone

import httpx

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
_THUMBNAIL_ERRORS = (ProtectError, httpx.RequestError, ValueError, OSError)
ALARM_RETRY_BATCH_SIZE = 10
ALARM_RETRY_NETWORK_TIMEOUT_SECONDS = 5


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


def _ingest_payment_with_status(
    store: Store, payment: dict, protect: ProtectClient | None
) -> tuple[dict, bool]:
    """Store one Square payment and return it with insertion status."""
    txn = payment_from_api(payment)
    if not txn["id"] or not txn["created_at"]:
        raise ValueError("Payment missing id or created_at")
    txn["ts_ms"] = parse_ts_ms(txn["created_at"])
    txn["updated_ts_ms"] = parse_ts_ms(txn["updated_at"])

    existing = store.get_transaction(txn["id"])
    if existing and not txn["device_id"]:
        txn["device_id"] = existing.get("device_id", "")
        if not txn["device_name"]:
            txn["device_name"] = existing.get("device_name", "")

    mapping = store.camera_for_location(txn["location_id"], txn["device_id"])
    txn["camera_id"] = mapping["camera_id"] if mapping else None
    txn["thumbnail_path"] = None

    # A stale out-of-order event is ignored by the versioned upsert, so it must
    # not overwrite the on-disk thumbnail with a wrong-time frame either.
    stale_event = bool(existing and txn["updated_ts_ms"] < existing["updated_ts_ms"])
    ts_unchanged = bool(existing and existing["ts_ms"] == txn["ts_ms"])

    if (
        existing
        and existing.get("camera_id")
        and existing.get("thumbnail_path")
        and (ts_unchanged or stale_event)
    ):
        # Camera and thumbnail form one historical evidence record. A later
        # location remap applies to new/missing evidence, never to this pair.
        txn["camera_id"] = existing["camera_id"]
        txn["thumbnail_path"] = existing["thumbnail_path"]
    elif (
        protect is not None
        and txn["camera_id"]
        and not stale_event
        and (existing is None or not ts_unchanged)
    ):
        # Capture inline only for brand-new transactions or corrected sale
        # times. Existing misses belong to the durable retry queue; fetching
        # them here would bypass its next_attempt_at backoff on every Square
        # overlap page.
        try:
            image = protect.get_snapshot(txn["camera_id"], ts_ms=txn["ts_ms"])
            name = safe_thumbnail_name(txn["id"])
            (store.thumbnail_dir / name).write_bytes(image)
            txn["thumbnail_path"] = name
        except _THUMBNAIL_ERRORS as exc:
            logger.warning("Thumbnail capture failed for %s: %s", txn["id"], exc)

    return txn, store.upsert_transaction(txn)


def ingest_payment(
    store: Store, payment: dict, protect: ProtectClient | None
) -> dict:
    """Store one Square payment and return its normalized transaction."""
    txn, _is_new = _ingest_payment_with_status(store, payment, protect)
    return txn


def retry_missing_thumbnails(
    store: Store,
    protect: ProtectClient,
    *,
    batch_size: int = THUMBNAIL_RETRY_BATCH_SIZE,
    now: float | None = None,
) -> int:
    """Retry a bounded batch independently of Square's current payment window."""
    batch_size = max(0, min(int(batch_size), 100))
    completed = 0
    for _ in range(batch_size):
        jobs = store.claim_thumbnail_retries(
            1,
            THUMBNAIL_RETRY_LEASE_SECONDS,
            now=now,
        )
        if not jobs:
            break
        job = jobs[0]
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
        except _THUMBNAIL_ERRORS as exc:
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


def deliver_completed_alarm(
    store: Store,
    txn_id: str,
    protect: ProtectClient | None,
    alarm_trigger_id: str | None,
    *,
    timeout: float | None = None,
) -> bool:
    """Best-effort Alarm Manager delivery after the transaction is durable."""
    if protect is None or not alarm_trigger_id:
        return True
    try:
        claim_token = store.claim_alarm_trigger(txn_id)
    except Exception as exc:
        logger.warning("Could not claim alarm trigger for %s: %s", txn_id, exc)
        return False
    if not claim_token:
        return True

    try:
        protect.trigger_alarm(alarm_trigger_id, timeout=timeout)
    except Exception as exc:
        try:
            store.release_alarm_claim(txn_id, claim_token)
        except Exception as release_exc:
            logger.warning(
                "Could not release alarm trigger claim for %s: %s",
                txn_id,
                release_exc,
            )
        logger.warning("Alarm trigger failed for %s: %s", txn_id, exc)
        return False

    try:
        marked_sent = store.mark_alarm_sent(txn_id, claim_token)
    except Exception as exc:
        # Leave the claim in progress. Startup resets it for an at-least-once
        # retry rather than risking an immediate duplicate delivery.
        logger.warning("Alarm sent but state update failed for %s: %s", txn_id, exc)
        return False
    else:
        if not marked_sent:
            logger.warning("Alarm sent but claim ownership changed for %s", txn_id)
            return False
    return True


def _load_pending_alarm_ids(
    store: Store,
    protect: ProtectClient | None,
    alarm_trigger_id: str | None,
) -> list[str]:
    if protect is None or not alarm_trigger_id:
        return []
    try:
        return store.pending_alarm_transaction_ids()
    except Exception as exc:
        logger.warning("Could not load pending alarm triggers: %s", exc)
        return []


def retry_pending_alarms(
    store: Store,
    protect: ProtectClient | None,
    alarm_trigger_id: str | None,
    *,
    batch_size: int = ALARM_RETRY_BATCH_SIZE,
) -> int:
    """Deliver a bounded batch of pending sale alarms, oldest first.

    Stops at the first hard failure so an unreachable console cannot burn the
    whole batch; the durable alarm state retries on the next nudge or sync.
    """
    delivered = 0
    for txn_id in _load_pending_alarm_ids(store, protect, alarm_trigger_id)[
        : max(0, int(batch_size))
    ]:
        if not deliver_completed_alarm(
            store,
            txn_id,
            protect,
            alarm_trigger_id,
            timeout=ALARM_RETRY_NETWORK_TIMEOUT_SECONDS,
        ):
            break
        delivered += 1
    return delivered


def sync_payments(
    store: Store,
    square: SquareClient,
    protect: ProtectClient | None,
    alarm_trigger_id: str | None = None,
) -> int:
    """Pull recent Square payments and ingest them. Returns count ingested."""
    count = 0
    seen_payment_ids: set[str] = set()
    try:
        for location in square.list_locations():
            location_id = location.get("id", "")
            if not location_id:
                logger.warning("Skipping Square location without an id")
                continue

            # Watermark on Square's updated_at so delayed completions, refunds,
            # and other state changes to older payments are still reconciled.
            latest = store.latest_transaction_updated_ts(location_id=location_id)
            if latest:
                begin = datetime.fromtimestamp(
                    latest / 1000, tz=timezone.utc
                ) - timedelta(minutes=5)
            else:
                begin = datetime.now(tz=timezone.utc) - timedelta(hours=BACKFILL_HOURS)
            payments = square.list_payments(
                updated_at_begin_time=begin.isoformat(timespec="seconds").replace(
                    "+00:00", "Z"
                ),
                sort_field="UPDATED_AT",
                # Keep the durable watermark behind any unprocessed result if
                # ingestion is interrupted partway through the response.
                sort_order="ASC",
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
    finally:
        # Durable Protect work runs even when Square listing fails, and never
        # contributes to the ingested count: first any pending sale alarms,
        # then persisted thumbnail misses.
        retry_pending_alarms(store, protect, alarm_trigger_id)
        if protect is not None:
            try:
                retry_missing_thumbnails(store, protect)
            except Exception as exc:
                logger.warning("Thumbnail retry batch failed: %s", exc)
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
