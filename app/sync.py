"""Transaction ingestion: match Square payments to camera footage."""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from .protect_client import ProtectClient, ProtectError
from .square_client import SquareClient, payment_from_api
from .store import Store

logger = logging.getLogger("spi.sync")

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_\-]")
BACKFILL_HOURS = 24
ALARM_RETRY_BUDGET_SECONDS = 5


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


def _retry_pending_alarms(
    store: Store,
    protect: ProtectClient | None,
    alarm_trigger_id: str | None,
    txn_ids: list[str],
) -> None:
    """Drain durable work after Square ingestion, stopping on first failure."""
    deadline = time.monotonic() + ALARM_RETRY_BUDGET_SECONDS
    for txn_id in txn_ids:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if not deliver_completed_alarm(
            store,
            txn_id,
            protect,
            alarm_trigger_id,
            timeout=remaining,
        ):
            break


def sync_payments(
    store: Store,
    square: SquareClient,
    protect: ProtectClient | None,
    alarm_trigger_id: str | None = None,
) -> int:
    """Pull recent Square payments and ingest them. Returns count ingested."""
    previously_pending = _load_pending_alarm_ids(store, protect, alarm_trigger_id)
    count = 0
    try:
        latest = store.latest_transaction_ts()
        if latest:
            begin = datetime.fromtimestamp(latest / 1000, tz=timezone.utc) - timedelta(
                minutes=5
            )
        else:
            begin = datetime.now(tz=timezone.utc) - timedelta(hours=BACKFILL_HOURS)
        payments = square.list_payments(
            begin_time=begin.isoformat(timespec="seconds").replace("+00:00", "Z")
        )
        for payment in payments:
            try:
                ingest_payment(store, payment, protect)
                count += 1
            except ValueError as exc:
                logger.warning("Skipping malformed payment: %s", exc)
    finally:
        # Alarm delivery is durable work, independent of Square availability
        # and the current payment-list window.
        pending_after_ingest = _load_pending_alarm_ids(
            store, protect, alarm_trigger_id
        )
        prior_ids = set(previously_pending)
        retry_ids = previously_pending + [
            txn_id for txn_id in pending_after_ingest if txn_id not in prior_ids
        ]
        _retry_pending_alarms(
            store,
            protect,
            alarm_trigger_id,
            retry_ids[:100],
        )
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
