"""Minimal Square Connect API client: locations, payments, webhook signatures."""

from __future__ import annotations

import base64
import hashlib
import hmac

import httpx

SQUARE_VERSION = "2025-01-23"

BASE_URLS = {
    "production": "https://connect.squareup.com",
    "sandbox": "https://connect.squareupsandbox.com",
}


class SquareError(Exception):
    pass


class SquareAuthError(SquareError):
    pass


class SquareClient:
    def __init__(
        self,
        access_token: str,
        environment: str = "production",
        transport: httpx.BaseTransport | None = None,
        timeout: float = 15.0,
    ):
        if environment not in BASE_URLS:
            raise ValueError("environment must be 'production' or 'sandbox'")
        self.environment = environment
        self._client = httpx.Client(
            base_url=BASE_URLS[environment],
            headers={
                "Authorization": f"Bearer {access_token}",
                "Square-Version": SQUARE_VERSION,
                "Content-Type": "application/json",
            },
            transport=transport,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = self._client.get(path, params=params)
        if resp.status_code == 401:
            raise SquareAuthError("Square rejected the access token")
        if resp.status_code >= 400:
            raise SquareError(f"Square request {path} failed (HTTP {resp.status_code})")
        return resp.json()

    def list_locations(self) -> list[dict]:
        data = self._get("/v2/locations")
        return [
            {
                "id": loc.get("id", ""),
                "name": loc.get("name", ""),
                "status": loc.get("status", ""),
            }
            for loc in data.get("locations", [])
        ]

    def list_payments(
        self,
        begin_time: str | None = None,
        limit: int = 100,
        updated_at_begin_time: str | None = None,
        sort_field: str | None = None,
    ) -> list[dict]:
        """Completed and pending payments, newest first, following pagination."""
        payments: list[dict] = []
        cursor: str | None = None
        while True:
            params: dict = {"sort_order": "DESC", "limit": min(limit, 100)}
            if begin_time:
                params["begin_time"] = begin_time
            if updated_at_begin_time:
                params["updated_at_begin_time"] = updated_at_begin_time
            if sort_field:
                params["sort_field"] = sort_field
            if cursor:
                params["cursor"] = cursor
            data = self._get("/v2/payments", params=params)
            payments.extend(data.get("payments", []))
            cursor = data.get("cursor")
            if not cursor or len(payments) >= limit:
                break
        return payments[:limit]


def verify_webhook_signature(
    signature_key: str, notification_url: str, body: bytes, signature_header: str
) -> bool:
    """Validate Square's x-square-hmacsha256-signature header.

    Square signs base64(HMAC-SHA256(key, notification_url + body)).
    """
    if not signature_key or not signature_header:
        return False
    digest = hmac.new(
        signature_key.encode(), notification_url.encode() + body, hashlib.sha256
    ).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, signature_header)


def payment_from_api(payment: dict) -> dict:
    """Normalize a Square Payment object into our transaction shape."""
    amount = payment.get("amount_money", {})
    card = payment.get("card_details", {}).get("card", {})
    created_at = payment.get("created_at", "")
    return {
        "id": payment.get("id", ""),
        "created_at": created_at,
        "updated_at": payment.get("updated_at") or created_at,
        "amount": int(amount.get("amount", 0)),
        "currency": amount.get("currency", "USD"),
        "status": payment.get("status", ""),
        "location_id": payment.get("location_id", ""),
        "card_last4": card.get("last_4", ""),
        "receipt_url": payment.get("receipt_url", ""),
        "raw": payment,
    }
