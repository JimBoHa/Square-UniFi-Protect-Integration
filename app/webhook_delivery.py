"""Privacy-minimized Square webhook receipt and timing helpers."""

from __future__ import annotations

import hashlib
from datetime import datetime

SUPPORTED_PAYMENT_EVENT_TYPES = frozenset(
    ("payment.created", "payment.updated")
)
MAX_EVENT_ID_LENGTH = 256


def receipt_key(event_id: object, body: bytes) -> str:
    """Return a stable digest without retaining Square's event id or payload."""
    if (
        isinstance(event_id, str)
        and 0 < len(event_id) <= MAX_EVENT_ID_LENGTH
        and not any(
            ord(character) < 32 or ord(character) == 127
            for character in event_id
        )
    ):
        material = b"event-id\0" + event_id.encode("utf-8")
    else:
        # Official deliveries include event_id. Hash exact signed bytes as a
        # compatibility fallback for malformed or older fixtures.
        material = b"signed-body\0" + body
    return hashlib.sha256(material).hexdigest()


def event_created_at_ms(event: dict) -> int | None:
    """Parse Square's event timestamp for delivery-lag observability."""
    value = event.get("created_at")
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    try:
        milliseconds = int(parsed.timestamp() * 1000)
    except (OverflowError, OSError, ValueError):
        return None
    return milliseconds if milliseconds >= 0 else None
