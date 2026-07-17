"""Minimal UniFi Protect (UniFi OS) API client.

Talks to a local UniFi Protect console over HTTPS: local-account login,
camera enumeration via the bootstrap payload, JPEG snapshots (optionally at a
historical timestamp), and official API-key Alarm Manager triggers.
"""

from __future__ import annotations

import re
from urllib.parse import quote

import httpx

HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?(?::\d{1,5})?$")
CAMERA_ID_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")
_SNAPSHOT_CONTENT_TYPES = frozenset(
    {
        "image/jpeg",
        "image/jpg",
        "image/pjpeg",
        "application/octet-stream",
        "binary/octet-stream",
    }
)
_JPEG_START_OF_FRAME_MARKERS = tuple(
    bytes((0xFF, marker))
    for marker in (
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    )
)


class ProtectError(Exception):
    pass


class ProtectAuthError(ProtectError):
    pass


def _validated_snapshot_bytes(resp: httpx.Response) -> bytes:
    """Return a complete JPEG response or reject an upstream error document."""
    content_type = (
        resp.headers.get("content-type", "").partition(";")[0].strip().lower()
    )
    if content_type and content_type not in _SNAPSHOT_CONTENT_TYPES:
        raise ProtectError("UniFi Protect snapshot response was not a JPEG")

    content = resp.content
    # Protect may omit Content-Type or use application/octet-stream. Require a
    # frame header and scan in addition to SOI/EOI so marker-only or wrapped
    # error payloads are not persisted as camera evidence. Trailing bytes are
    # allowed because JPEG decoders permit data after the EOI marker.
    eoi_position = content.find(b"\xff\xd9", 2)
    scan_position = content.find(b"\xff\xda", 2, eoi_position)
    has_frame = scan_position != -1 and any(
        content.find(marker, 2, scan_position) != -1
        for marker in _JPEG_START_OF_FRAME_MARKERS
    )
    if not content.startswith(b"\xff\xd8") or eoi_position == -1 or not has_frame:
        raise ProtectError("UniFi Protect snapshot response contained invalid JPEG data")
    return content


def validate_host(host: str) -> str:
    """Allow only a bare hostname/IP with optional port — no scheme or path."""
    host = (host or "").strip()
    if not HOST_RE.match(host):
        raise ValueError(
            "Protect host must be a hostname or IP address (optionally with :port), "
            "without scheme or path"
        )
    _, separator, port = host.rpartition(":")
    if separator and not 1 <= int(port) <= 65535:
        raise ValueError("Protect host port must be between 1 and 65535")
    return host


def validate_camera_id(camera_id: str) -> str:
    if not CAMERA_ID_RE.match(camera_id or ""):
        raise ValueError("Invalid camera id")
    return camera_id


def validate_alarm_trigger_id(trigger_id: str) -> str:
    """Validate a user-defined Alarm Manager webhook path segment."""
    trigger_id = (trigger_id or "").strip()
    if not trigger_id or len(trigger_id) > 256 or any(
        ord(char) < 32 or ord(char) == 127 for char in trigger_id
    ):
        raise ValueError(
            "Alarm trigger id must be 1-256 characters without control characters"
        )
    return trigger_id


class ProtectClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 15.0,
        api_key: str | None = None,
    ):
        self.host = validate_host(host)
        self._username = username
        self._password = password
        self._api_key = api_key.strip() if api_key else None
        self._csrf_token: str | None = None
        self._logged_in = False
        self._client = httpx.Client(
            base_url=f"https://{self.host}",
            verify=verify_ssl,
            transport=transport,
            timeout=timeout,
        )
        # The integration API must authenticate with the API key alone. A
        # shared client would send the legacy login's session cookie, which
        # the console accepts even when the API key is wrong — verified on
        # Protect 7.1.87 — so key verification would silently pass and alarm
        # delivery would break only once the session expired.
        self._integration_client = httpx.Client(
            base_url=f"https://{self.host}",
            verify=verify_ssl,
            transport=transport,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()
        self._integration_client.close()

    # -- auth ----------------------------------------------------------------

    def login(self) -> None:
        try:
            resp = self._client.post(
                "/api/auth/login",
                json={
                    "username": self._username,
                    "password": self._password,
                    "rememberMe": True,
                },
            )
        except httpx.RequestError as exc:
            raise ProtectError("Network error while contacting UniFi Protect") from exc
        if resp.status_code in (401, 403):
            raise ProtectAuthError("UniFi Protect rejected the credentials")
        if resp.status_code >= 400:
            raise ProtectError(f"UniFi Protect login failed (HTTP {resp.status_code})")
        self._csrf_token = resp.headers.get("x-csrf-token") or resp.headers.get(
            "x-updated-csrf-token"
        )
        self._logged_in = True

    def _request(
        self, method: str, path: str, raise_for_status: bool = True, **kwargs
    ) -> httpx.Response:
        if not self._logged_in:
            self.login()
        headers = kwargs.pop("headers", {})
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token
        try:
            resp = self._client.request(method, path, headers=headers, **kwargs)
        except httpx.RequestError as exc:
            raise ProtectError("Network error while contacting UniFi Protect") from exc
        if resp.status_code == 401:
            # Session expired — log in once more and retry.
            self.login()
            if self._csrf_token:
                headers["X-CSRF-Token"] = self._csrf_token
            try:
                resp = self._client.request(method, path, headers=headers, **kwargs)
            except httpx.RequestError as exc:
                raise ProtectError("Network error while contacting UniFi Protect") from exc
        if raise_for_status and not 200 <= resp.status_code < 300:
            raise ProtectError(
                f"UniFi Protect request {method} {path} failed (HTTP {resp.status_code})"
            )
        return resp

    def _integration_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Request the official Protect integration API with an API key."""
        if not self._api_key:
            raise ProtectAuthError("UniFi Protect API key is not configured")
        headers = dict(kwargs.pop("headers", {}))
        headers.setdefault("Accept", "application/json")
        headers["X-API-Key"] = self._api_key
        try:
            resp = self._integration_client.request(method, path, headers=headers, **kwargs)
        except httpx.RequestError as exc:
            raise ProtectError("Network error while contacting UniFi Protect") from exc
        if resp.status_code in (401, 403):
            raise ProtectAuthError("UniFi Protect rejected the API key")
        if not 200 <= resp.status_code < 300:
            raise ProtectError(
                f"UniFi Protect integration request {method} {path} failed "
                f"(HTTP {resp.status_code})"
            )
        return resp

    # -- API -------------------------------------------------------------------

    def get_cameras(self) -> list[dict]:
        resp = self._request("GET", "/proxy/protect/api/bootstrap")
        try:
            data = resp.json()
        except ValueError as exc:
            raise ProtectError("UniFi Protect camera response was not JSON") from exc
        if not isinstance(data, dict):
            raise ProtectError("UniFi Protect camera response was invalid")
        cameras = data.get("cameras", [])
        if not isinstance(cameras, list) or any(
            not isinstance(camera, dict) for camera in cameras
        ):
            raise ProtectError("UniFi Protect camera response was invalid")
        return [
            {
                "id": cam.get("id", ""),
                "name": cam.get("name") or cam.get("marketName") or cam.get("id", ""),
                "state": cam.get("state", ""),
            }
            for cam in cameras
        ]

    def get_snapshot(
        self, camera_id: str, ts_ms: int | None = None, width: int = 640
    ) -> bytes:
        """JPEG snapshot for a camera; historical if ts_ms is given.

        Modern Protect firmware (verified on 7.1.87) serves recorded frames
        from ``recording-snapshot?ts=`` and silently ignores ``ts`` on the
        live ``snapshot`` endpoint, so historical requests never fall back to
        that endpoint. Frames become available roughly ten seconds behind live;
        "no recording yet/anymore" raises ProtectError so the durable retry
        queue can back off and try again.
        """
        camera_id = validate_camera_id(camera_id)
        if ts_ms is not None:
            resp = self._request(
                "GET",
                f"/proxy/protect/api/cameras/{camera_id}/recording-snapshot",
                params={"ts": int(ts_ms)},
                raise_for_status=False,
            )
            if 200 <= resp.status_code < 300:
                return _validated_snapshot_bytes(resp)
            content_type = resp.headers.get("content-type", "")
            if resp.status_code == 404 and "json" in content_type:
                # Firmware supports the endpoint but has no recorded frame at
                # this timestamp (not flushed yet, or outside retention).
                raise ProtectError(
                    f"No recording available for camera {camera_id} at ts {int(ts_ms)}"
                )
            if resp.status_code != 404:
                raise ProtectError(
                    "UniFi Protect recording-snapshot failed "
                    f"(HTTP {resp.status_code})"
                )
            # Plain 404 (HTML): older firmware without recording-snapshot.
            # snapshot?ts is not a safe fallback because some Protect versions
            # ignore ts and return a live frame with a successful response.
            raise ProtectError(
                "Historical snapshots require Protect recording-snapshot support"
            )
        params: dict = {"w": width}
        resp = self._request(
            "GET", f"/proxy/protect/api/cameras/{camera_id}/snapshot", params=params
        )
        return _validated_snapshot_bytes(resp)

    def get_integration_info(self) -> dict:
        """Verify API-key access and return official Protect application metadata."""
        resp = self._integration_request(
            "GET", "/proxy/protect/integration/v1/meta/info"
        )
        try:
            data = resp.json()
        except ValueError as exc:
            raise ProtectError("UniFi Protect integration metadata was not JSON") from exc
        version = data.get("applicationVersion") if isinstance(data, dict) else None
        if not isinstance(version, str) or not version.strip():
            raise ProtectError("UniFi Protect integration metadata was invalid")
        return data

    def trigger_alarm(self, trigger_id: str, timeout: float | None = None) -> None:
        """Send a user-defined webhook trigger to Protect Alarm Manager."""
        trigger_id = validate_alarm_trigger_id(trigger_id)
        request_options = {"timeout": timeout} if timeout is not None else {}
        self._integration_request(
            "POST",
            "/proxy/protect/integration/v1/alarm-manager/webhook/"
            f"{quote(trigger_id, safe='')}",
            **request_options,
        )
