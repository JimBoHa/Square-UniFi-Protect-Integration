"""Global ASGI request-body bound and replay behavior."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence

import pytest

from app.body_limit import RequestBodyLimitMiddleware
from app.main import REQUEST_MAX_BODY_BYTES

from .conftest import ADMIN_PASSWORD


def _asgi_exchange(
    frames: Sequence[dict],
    *,
    headers: Sequence[tuple[bytes, bytes]] = (),
    limit: int = 8,
) -> tuple[list[dict], list[bytes]]:
    pending = list(frames)
    sent: list[dict] = []
    downstream_bodies: list[bytes] = []

    async def downstream(scope, receive, send):
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            body.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break
        downstream_bodies.append(bytes(body))
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        if pending:
            return pending.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/login",
        "raw_path": b"/api/login",
        "query_string": b"",
        "headers": list(headers),
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
    }
    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=limit)
    asyncio.run(middleware(scope, receive, send))
    return sent, downstream_bodies


def _assert_direct_error(sent: list[dict], status: int, detail: str) -> None:
    assert [message["type"] for message in sent] == [
        "http.response.start",
        "http.response.body",
    ]
    assert sent[0]["status"] == status
    assert dict(sent[0]["headers"])[b"cache-control"] == b"private, no-store"
    assert json.loads(sent[1]["body"]) == {"detail": detail}


def test_multiframe_body_at_boundary_is_replayed_exactly():
    sent, downstream_bodies = _asgi_exchange(
        [
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"45678", "more_body": False},
        ]
    )

    assert sent[0]["status"] == 204
    assert downstream_bodies == [b"12345678"]


@pytest.mark.parametrize("headers", [(), ((b"content-length", b"1"),)])
def test_multiframe_body_over_limit_is_rejected_before_downstream(headers):
    sent, downstream_bodies = _asgi_exchange(
        [
            {"type": "http.request", "body": b"12345", "more_body": True},
            {"type": "http.request", "body": b"6789", "more_body": False},
        ],
        headers=headers,
    )

    _assert_direct_error(sent, 413, "Request body too large")
    assert downstream_bodies == []


@pytest.mark.parametrize(
    "headers",
    [
        ((b"content-length", b""),),
        ((b"content-length", b"-1"),),
        ((b"content-length", b"not-a-number"),),
        ((b"content-length", b"2"), (b"content-length", b"3")),
        ((b"content-length", b"2, 3"),),
        ((b"content-length", b"\xff"),),
    ],
)
def test_malformed_content_length_is_rejected_before_downstream(headers):
    sent, downstream_bodies = _asgi_exchange(
        [{"type": "http.request", "body": b"", "more_body": False}],
        headers=headers,
    )

    _assert_direct_error(sent, 400, "Invalid Content-Length")
    assert downstream_bodies == []


def test_identical_content_length_values_are_unambiguous():
    sent, downstream_bodies = _asgi_exchange(
        [{"type": "http.request", "body": b"12", "more_body": False}],
        headers=((b"content-length", b"02, 2"),),
    )

    assert sent[0]["status"] == 204
    assert downstream_bodies == [b"12"]


def test_transaction_query_exemption_does_not_pre_read_before_auth():
    sent: list[dict] = []

    async def downstream(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"cache-control", b"private, no-store")],
            }
        )
        await send({"type": "http.response.body", "body": b"unauthorized"})

    async def receive():
        raise AssertionError("auth-first exempt route body was pre-read")

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/transactions",
        "headers": [(b"content-length", b"999999999")],
    }
    middleware = RequestBodyLimitMiddleware(
        downstream,
        max_body_bytes=8,
        excluded_routes=(("POST", "/api/transactions"),),
    )

    asyncio.run(middleware(scope, receive, send))

    assert sent[0]["status"] == 401


def test_unauthenticated_declared_body_over_global_limit_is_no_store(client):
    response = client.put(
        "/api/settings/deep-link",
        content=b"x" * (REQUEST_MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert response.headers["cache-control"] == "private, no-store"


def test_authenticated_chunked_body_over_global_limit_is_no_store(authed):
    chunks = iter(
        [
            b"x" * (REQUEST_MAX_BODY_BYTES // 2),
            b"y" * (REQUEST_MAX_BODY_BYTES // 2 + 1),
        ]
    )
    response = authed.put(
        "/api/settings/deep-link",
        content=chunks,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert response.headers["cache-control"] == "private, no-store"


def test_body_exactly_at_global_limit_reaches_login(authed):
    body = json.dumps({"password": ADMIN_PASSWORD}).encode()
    body += b" " * (REQUEST_MAX_BODY_BYTES - len(body))

    response = authed.post(
        "/api/login",
        content=body,
        headers={"content-type": "application/json"},
    )

    assert len(body) == REQUEST_MAX_BODY_BYTES
    assert response.status_code == 200


def test_signed_webhook_body_exactly_at_existing_limit_is_accepted(configured):
    from .test_api import _webhook_signature, make_webhook_event

    body = make_webhook_event("PAY_BODY_LIMIT_BOUNDARY")
    body += b" " * (REQUEST_MAX_BODY_BYTES - len(body))

    response = configured.post(
        "/webhooks/square",
        content=body,
        headers={"x-square-hmacsha256-signature": _webhook_signature(body)},
    )

    assert len(body) == REQUEST_MAX_BODY_BYTES
    assert response.status_code == 200
