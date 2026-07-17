"""Build UniFi Protect timeline deep links for a camera at a timestamp."""

from __future__ import annotations

from .protect_client import validate_camera_id, validate_host

# Verified against Protect 7.1.87: the web app's own event links use
# /protect/timelapse/{camera}?start={ms} and the player seeks to `start`.
DEFAULT_TEMPLATE = "https://{host}/protect/timelapse/{camera_id}?start={ts_ms}"


def build_deep_link(
    host: str, camera_id: str, ts_ms: int, template: str | None = None
) -> str:
    """Fill the deep-link template with validated values.

    Placeholders are replaced literally (no str.format) so a custom template
    cannot reach attribute access on the substituted values.
    """
    host = validate_host(host)
    camera_id = validate_camera_id(camera_id)
    link = template or DEFAULT_TEMPLATE
    link = link.replace("{host}", host)
    link = link.replace("{camera_id}", camera_id)
    link = link.replace("{ts_ms}", str(int(ts_ms)))
    return link
