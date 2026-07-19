"""Bound HTTP request bodies before application parsing or authentication."""

from __future__ import annotations

import json
from collections.abc import Iterable

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class InvalidContentLength(ValueError):
    """Raised when Content-Length cannot be interpreted unambiguously."""


class RequestBodyLimitMiddleware:
    """Reject oversized HTTP bodies before invoking downstream application code.

    The middleware buffers at most ``max_body_bytes`` and then replays the exact
    body bytes. Pre-reading keeps rejection independent of route/auth ordering
    and ensures a downstream response cannot start before an oversized streamed
    body is detected.
    """

    def __init__(
        self,
        app: ASGIApp,
        max_body_bytes: int,
        excluded_routes: Iterable[tuple[str, str]] = (),
    ) -> None:
        if max_body_bytes < 0:
            raise ValueError("max_body_bytes cannot be negative")
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.excluded_routes = frozenset(
            (method.upper(), path) for method, path in excluded_routes
        )

    def _content_length(self, headers: Iterable[tuple[bytes, bytes]]) -> int | None:
        values: list[str] = []
        for name, raw_value in headers:
            if name.lower() != b"content-length":
                continue
            try:
                text = raw_value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise InvalidContentLength from exc
            for item in text.split(","):
                item = item.strip()
                if not item or not item.isascii() or not item.isdecimal():
                    raise InvalidContentLength
                values.append(item.lstrip("0") or "0")

        if not values:
            return None
        if any(value != values[0] for value in values[1:]):
            raise InvalidContentLength

        normalized = values[0]
        limit_text = str(self.max_body_bytes)
        if len(normalized) > len(limit_text):
            return self.max_body_bytes + 1
        return int(normalized)

    @staticmethod
    async def _send_json_error(send: Send, status: int, detail: str) -> None:
        body = json.dumps(
            {"detail": detail}, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"private, no-store"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        route = (scope.get("method", "").upper(), scope.get("path", ""))
        if route in self.excluded_routes:
            await self.app(scope, receive, send)
            return

        try:
            declared_length = self._content_length(scope.get("headers", ()))
        except InvalidContentLength:
            await self._send_json_error(send, 400, "Invalid Content-Length")
            return

        if (
            declared_length is not None
            and declared_length > self.max_body_bytes
        ):
            await self._send_json_error(send, 413, "Request body too large")
            return

        body = bytearray()
        received = 0
        saw_request = False
        terminal_message: Message | None = None
        while True:
            message = await receive()
            if message["type"] == "http.request":
                saw_request = True
                chunk = message.get("body", b"")
                if len(chunk) > self.max_body_bytes - received:
                    await self._send_json_error(send, 413, "Request body too large")
                    return
                body.extend(chunk)
                received += len(chunk)
                if not message.get("more_body", False):
                    break
                continue

            # Preserve disconnects or extension messages for downstream code.
            terminal_message = message
            break

        replayed_body = False
        replayed_terminal = False

        async def replay() -> Message:
            nonlocal replayed_body, replayed_terminal
            if saw_request and not replayed_body:
                replayed_body = True
                return {
                    "type": "http.request",
                    "body": bytes(body),
                    "more_body": terminal_message is not None,
                }
            if terminal_message is not None and not replayed_terminal:
                replayed_terminal = True
                return terminal_message
            return await receive()

        await self.app(scope, replay, send)
