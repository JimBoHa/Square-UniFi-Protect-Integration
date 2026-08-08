"""Validation helpers for inbound UniFi Protect motion alarm webhooks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json


PROTECT_MOTION_WEBHOOK_MAX_BODY_BYTES = 32 * 1024
MAX_ALARM_NAME_LENGTH = 256
MAX_DEVICE_IDENTIFIER_LENGTH = 128
MAX_ALARM_ENTRIES = 64
MAX_FUTURE_SKEW_MS = 5 * 60 * 1000


class ProtectMotionPayloadError(ValueError):
    """A Protect Alarm Manager payload is malformed or is not motion."""


@dataclass(frozen=True)
class ProtectMotionDelivery:
    event_ts_ms: int
    alarm_name: str
    device_identifiers: tuple[str, ...]
    event_key: str


def _bounded_text(value: object, *, maximum: int, field: str) -> str:
    if not isinstance(value, str):
        raise ProtectMotionPayloadError(f"Protect motion {field} must be text")
    value = value.strip()
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ProtectMotionPayloadError(f"Protect motion {field} is invalid")
    return value


def _bounded_entries(value: object, *, field: str) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ALARM_ENTRIES:
        raise ProtectMotionPayloadError(f"Protect motion {field} is invalid")
    if any(not isinstance(entry, dict) for entry in value):
        raise ProtectMotionPayloadError(f"Protect motion {field} is invalid")
    return value


def parse_protect_motion_payload(
    body: bytes,
    *,
    received_at_ms: int,
    oldest_allowed_ms: int,
) -> ProtectMotionDelivery:
    """Parse the documented Alarm Manager POST shape without retaining raw JSON."""
    if not body or len(body) > PROTECT_MOTION_WEBHOOK_MAX_BODY_BYTES:
        raise ProtectMotionPayloadError("Protect motion payload size is invalid")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProtectMotionPayloadError("Protect motion payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ProtectMotionPayloadError("Protect motion payload must be an object")

    timestamp = payload.get("timestamp")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ProtectMotionPayloadError(
            "Protect motion timestamp must be Unix milliseconds"
        )
    event_ts_ms = int(timestamp)
    if event_ts_ms < int(oldest_allowed_ms):
        raise ProtectMotionPayloadError("Protect motion timestamp is too old")
    if event_ts_ms > int(received_at_ms) + MAX_FUTURE_SKEW_MS:
        raise ProtectMotionPayloadError("Protect motion timestamp is in the future")

    alarm = payload.get("alarm")
    if not isinstance(alarm, dict):
        raise ProtectMotionPayloadError("Protect motion alarm is invalid")
    alarm_name = _bounded_text(
        alarm.get("name", ""),
        maximum=MAX_ALARM_NAME_LENGTH,
        field="alarm name",
    )
    conditions = _bounded_entries(alarm.get("conditions"), field="conditions")
    triggers = _bounded_entries(alarm.get("triggers"), field="triggers")

    motion_source_found = False
    canonical_triggers: list[tuple[str, str]] = []
    device_identifiers: list[str] = []
    for wrapper in conditions:
        condition = wrapper.get("condition", wrapper)
        if not isinstance(condition, dict):
            raise ProtectMotionPayloadError("Protect motion condition is invalid")
        source = condition.get("source", "")
        if source:
            source = _bounded_text(source, maximum=64, field="condition source")
            motion_source_found |= source.casefold() == "motion"

    for trigger in triggers:
        key = _bounded_text(
            trigger.get("key", ""), maximum=64, field="trigger key"
        )
        device = _bounded_text(
            trigger.get("device", ""),
            maximum=MAX_DEVICE_IDENTIFIER_LENGTH,
            field="device identifier",
        )
        motion_source_found |= key.casefold() == "motion"
        canonical_triggers.append((key, device))
        if device and device not in device_identifiers:
            device_identifiers.append(device)

    if not motion_source_found:
        raise ProtectMotionPayloadError("Protect alarm did not report motion")

    canonical = json.dumps(
        {
            "timestamp": event_ts_ms,
            "alarm_name": alarm_name,
            "triggers": sorted(canonical_triggers),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return ProtectMotionDelivery(
        event_ts_ms=event_ts_ms,
        alarm_name=alarm_name,
        device_identifiers=tuple(device_identifiers),
        event_key="post:" + hashlib.sha256(canonical).hexdigest(),
    )


def get_delivery_event_key(camera_id: str, received_at_ms: int) -> str:
    """Coalesce header-authenticated GET retries into five-second buckets."""
    bucket = int(received_at_ms) // 5000
    material = f"{camera_id}\0{bucket}".encode("utf-8")
    return "get:" + hashlib.sha256(material).hexdigest()
