"""Build UniFi Protect timeline deep links for a camera at a timestamp."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .protect_client import validate_camera_id, validate_host

# Verified against Protect 7.1.87: the web app's own event links use
# /protect/timelapse/{camera}?start={ms} and the player seeks to `start`.
DEFAULT_TEMPLATE = "https://{host}/protect/timelapse/{camera_id}?start={ts_ms}"
REQUIRED_PLACEHOLDERS = frozenset({"host", "camera_id", "ts_ms"})
_PLACEHOLDER = re.compile(r"{([^{}]+)}")


def validate_deep_link_template(template: str) -> str:
    """Return a normalized, safe Protect deep-link template.

    A blank value means "use the built-in default". The console host must be
    the complete URL authority so an override cannot redirect transaction
    links to a different server while merely mentioning ``{host}`` elsewhere.
    """
    normalized = template.strip()
    if not normalized:
        return ""
    if any(
        character == "\\"
        or character.isspace()
        or ord(character) < 32
        or ord(character) == 127
        for character in normalized
    ):
        raise ValueError(
            "Deep-link template cannot contain whitespace, control characters, "
            "or backslashes"
        )

    placeholders = set(_PLACEHOLDER.findall(normalized))
    remainder = _PLACEHOLDER.sub("", normalized)
    if "{" in remainder or "}" in remainder:
        raise ValueError("Deep-link template contains malformed placeholders")
    unknown = placeholders - REQUIRED_PLACEHOLDERS
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ValueError(f"Deep-link template contains unknown placeholders: {names}")
    missing = REQUIRED_PLACEHOLDERS - placeholders
    if missing:
        names = ", ".join(sorted(missing))
        raise ValueError(f"Deep-link template is missing required placeholders: {names}")

    try:
        parsed = urlsplit(normalized)
    except ValueError as exc:
        raise ValueError("Deep-link template is not a valid URL") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("Deep-link template must use HTTPS")
    if parsed.netloc != "{host}":
        raise ValueError(
            "Deep-link template URL authority must be exactly {host}"
        )
    return normalized


def build_deep_link(
    host: str, camera_id: str, ts_ms: int, template: str | None = None
) -> str:
    """Fill the deep-link template with validated values.

    Placeholders are replaced literally (no str.format) so a custom template
    cannot reach attribute access on the substituted values.
    """
    host = validate_host(host)
    camera_id = validate_camera_id(camera_id)
    link = validate_deep_link_template(template or DEFAULT_TEMPLATE) or DEFAULT_TEMPLATE
    link = link.replace("{host}", host)
    link = link.replace("{camera_id}", camera_id)
    link = link.replace("{ts_ms}", str(int(ts_ms)))
    return link
