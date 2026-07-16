"""Minimal UniFi Protect (UniFi OS) API client.

Talks to a local UniFi Protect console over HTTPS: local-account login,
camera enumeration via the bootstrap payload, and JPEG snapshots
(optionally at a historical timestamp for consoles that support it).
"""

from __future__ import annotations

import re

import httpx

HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?(?::\d{1,5})?$")
CAMERA_ID_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")


class ProtectError(Exception):
    pass


class ProtectAuthError(ProtectError):
    pass


def validate_host(host: str) -> str:
    """Allow only a bare hostname/IP with optional port — no scheme or path."""
    host = (host or "").strip()
    if not HOST_RE.match(host):
        raise ValueError(
            "Protect host must be a hostname or IP address (optionally with :port), "
            "without scheme or path"
        )
    return host


def validate_camera_id(camera_id: str) -> str:
    if not CAMERA_ID_RE.match(camera_id or ""):
        raise ValueError("Invalid camera id")
    return camera_id


class ProtectClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 15.0,
    ):
        self.host = validate_host(host)
        self._username = username
        self._password = password
        self._csrf_token: str | None = None
        self._logged_in = False
        self._client = httpx.Client(
            base_url=f"https://{self.host}",
            verify=verify_ssl,
            transport=transport,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    # -- auth ----------------------------------------------------------------

    def login(self) -> None:
        resp = self._client.post(
            "/api/auth/login",
            json={
                "username": self._username,
                "password": self._password,
                "rememberMe": True,
            },
        )
        if resp.status_code in (401, 403):
            raise ProtectAuthError("UniFi Protect rejected the credentials")
        if resp.status_code >= 400:
            raise ProtectError(f"UniFi Protect login failed (HTTP {resp.status_code})")
        self._csrf_token = resp.headers.get("x-csrf-token") or resp.headers.get(
            "x-updated-csrf-token"
        )
        self._logged_in = True

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        if not self._logged_in:
            self.login()
        headers = kwargs.pop("headers", {})
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token
        resp = self._client.request(method, path, headers=headers, **kwargs)
        if resp.status_code == 401:
            # Session expired — log in once more and retry.
            self.login()
            if self._csrf_token:
                headers["X-CSRF-Token"] = self._csrf_token
            resp = self._client.request(method, path, headers=headers, **kwargs)
        if resp.status_code >= 400:
            raise ProtectError(
                f"UniFi Protect request {method} {path} failed (HTTP {resp.status_code})"
            )
        return resp

    # -- API -------------------------------------------------------------------

    def get_cameras(self) -> list[dict]:
        data = self._request("GET", "/proxy/protect/api/bootstrap").json()
        return [
            {
                "id": cam.get("id", ""),
                "name": cam.get("name") or cam.get("marketName") or cam.get("id", ""),
                "state": cam.get("state", ""),
            }
            for cam in data.get("cameras", [])
        ]

    def get_snapshot(
        self, camera_id: str, ts_ms: int | None = None, width: int = 640
    ) -> bytes:
        """JPEG snapshot for a camera; historical if ts_ms is given.

        Recent Protect versions serve historical frames from the recording
        when `ts` is passed; older ones ignore it and return a live frame.
        """
        camera_id = validate_camera_id(camera_id)
        params: dict = {"w": width}
        if ts_ms is not None:
            params["ts"] = int(ts_ms)
        resp = self._request(
            "GET", f"/proxy/protect/api/cameras/{camera_id}/snapshot", params=params
        )
        return resp.content
