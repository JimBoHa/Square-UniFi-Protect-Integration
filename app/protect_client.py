"""Minimal UniFi Protect (UniFi OS) API client.

Talks to a local UniFi Protect console over HTTPS: local-account login,
camera enumeration via the bootstrap payload, JPEG snapshots (optionally at a
historical timestamp), and official API-key Alarm Manager triggers.
"""

from __future__ import annotations

import logging
import math
import random
import re
import time
from urllib.parse import quote

import httpx


logger = logging.getLogger("spi.protect")

HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?(?::\d{1,5})?$")
CAMERA_ID_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")
_CONSOLE_ID_MAX_LENGTH = 256
LOGIN_RATE_LIMIT_MAX_RETRIES = 3
LOGIN_RATE_LIMIT_BASE_DELAY_SECONDS = 1.0
LOGIN_RATE_LIMIT_MAX_DELAY_SECONDS = 10.0
_SNAPSHOT_CONTENT_TYPES = frozenset(
    {
        "image/jpeg",
        "image/jpg",
        "image/pjpeg",
        "application/octet-stream",
        "binary/octet-stream",
    }
)
_JPEG_START_OF_FRAME_CODES = frozenset(
    (
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


def _is_complete_jpeg(content: bytes) -> bool:
    """Validate JPEG structure without treating marker-like metadata as syntax."""
    if not content.startswith(b"\xff\xd8"):
        return False

    position = 2
    in_scan = False
    saw_frame = False
    saw_scan = False
    saw_scan_data = False
    while position < len(content):
        if in_scan:
            marker_start = content.find(b"\xff", position)
            if marker_start == -1 or marker_start + 1 >= len(content):
                return False
            if marker_start > position:
                saw_scan_data = True
            marker = content[marker_start + 1]
            if marker == 0x00:  # Entropy-coded 0xff byte.
                saw_scan_data = True
                position = marker_start + 2
                continue
            if marker == 0xFF:  # Fill byte before a marker.
                position = marker_start + 1
                continue
            if 0xD0 <= marker <= 0xD7:  # Restart marker within scan data.
                position = marker_start + 2
                continue
            position = marker_start
            in_scan = False
            continue

        if content[position] != 0xFF:
            return False
        while position < len(content) and content[position] == 0xFF:
            position += 1
        if position >= len(content):
            return False
        marker = content[position]
        position += 1

        if marker == 0xD9:  # End of image; trailing bytes are permitted.
            return saw_frame and saw_scan and saw_scan_data
        if marker == 0xD8 or marker == 0x00:
            return False
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if position + 2 > len(content):
            return False
        segment_length = int.from_bytes(content[position : position + 2], "big")
        if segment_length < 2:
            return False
        segment_end = position + segment_length
        if segment_end > len(content):
            return False

        if marker in _JPEG_START_OF_FRAME_CODES:
            saw_frame = True
        if marker == 0xDA:  # Start of scan.
            if not saw_frame:
                return False
            saw_scan = True
            in_scan = True
        position = segment_end
    return False


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
    if not _is_complete_jpeg(content):
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
        login_rate_limit_max_retries: int = LOGIN_RATE_LIMIT_MAX_RETRIES,
        login_rate_limit_max_delay: float = LOGIN_RATE_LIMIT_MAX_DELAY_SECONDS,
    ):
        self.host = validate_host(host)
        self._username = username
        self._password = password
        self._api_key = api_key.strip() if api_key else None
        self._csrf_token: str | None = None
        self._logged_in = False
        self.login_rate_limit_max_retries = login_rate_limit_max_retries
        self.login_rate_limit_max_delay = login_rate_limit_max_delay
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
        attempt = 0
        while True:
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
                raise ProtectError(
                    "Network error while contacting UniFi Protect"
                ) from exc
            if (
                resp.status_code != 429
                or attempt >= self.login_rate_limit_max_retries
            ):
                break
            delay = self._login_retry_delay(attempt, resp)
            logger.warning(
                "UniFi Protect rate limited login; retrying in %.2f seconds",
                delay,
            )
            time.sleep(delay)
            attempt += 1
        if resp.status_code in (401, 403):
            raise ProtectAuthError("UniFi Protect rejected the credentials")
        if resp.status_code >= 400:
            raise ProtectError(f"UniFi Protect login failed (HTTP {resp.status_code})")
        self._csrf_token = resp.headers.get("x-csrf-token") or resp.headers.get(
            "x-updated-csrf-token"
        )
        self._logged_in = True

    def _login_retry_delay(self, attempt: int, resp: httpx.Response) -> float:
        max_delay = self.login_rate_limit_max_delay
        retry_after = resp.headers.get("retry-after")
        if retry_after is not None:
            try:
                requested_delay = float(retry_after)
            except ValueError:
                requested_delay = -1.0
            if math.isfinite(requested_delay) and requested_delay >= 0:
                return min(requested_delay, max_delay)
        backoff = min(
            LOGIN_RATE_LIMIT_BASE_DELAY_SECONDS * (2 ** max(0, attempt)),
            max_delay,
        )
        jitter = random.uniform(0, backoff * 0.25)
        return min(backoff + jitter, max_delay)

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

    def get_cameras_with_console_identity(self) -> tuple[list[dict], str | None]:
        """Return cameras and Protect's optional durable console identity.

        Protect bootstrap payloads do not always include an NVR identity, so
        malformed or absent identity fields must not prevent camera discovery.
        """
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
        normalized = []
        for camera in cameras:
            camera_id = camera.get("id")
            name = camera.get("name")
            market_name = camera.get("marketName")
            state = camera.get("state")
            try:
                validate_camera_id(camera_id)
            except (TypeError, ValueError) as exc:
                raise ProtectError(
                    "UniFi Protect camera response was invalid"
                ) from exc
            if any(
                value is not None and not isinstance(value, str)
                for value in (name, market_name, state)
            ):
                raise ProtectError("UniFi Protect camera response was invalid")
            normalized.append(
                {
                    "id": camera_id,
                    "name": name or market_name or camera_id,
                    "state": state or "",
                }
            )
        console_identity = None
        nvr = data.get("nvr")
        if isinstance(nvr, dict):
            for field in ("id", "mac"):
                candidate = nvr.get(field)
                if not isinstance(candidate, str):
                    continue
                candidate = candidate.strip()
                if (
                    candidate
                    and len(candidate) <= _CONSOLE_ID_MAX_LENGTH
                    and not any(ord(char) < 32 or ord(char) == 127 for char in candidate)
                ):
                    console_identity = candidate
                    break
        return normalized, console_identity

    def get_cameras(self) -> list[dict]:
        cameras, _console_identity = self.get_cameras_with_console_identity()
        return cameras

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
