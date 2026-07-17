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


class SquarePermissionError(SquareError):
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

    def _request_json(
        self, method: str, path: str, json_body: dict | None = None
    ) -> dict:
        try:
            resp = self._client.request(method, path, json=json_body)
        except httpx.RequestError as exc:
            raise SquareError("Network error while contacting Square") from exc
        if resp.status_code == 401:
            raise SquareAuthError("Square rejected the access token")
        if resp.status_code == 403:
            raise SquarePermissionError("Square rejected the token's permissions")
        if resp.status_code >= 400:
            raise SquareError(f"Square request {path} failed (HTTP {resp.status_code})")
        try:
            data = resp.json()
        except ValueError as exc:
            raise SquareError("Square returned a non-JSON response") from exc
        if not isinstance(data, dict):
            raise SquareError("Square returned an invalid response")
        return data

    def _get(self, path: str, params: dict | None = None) -> dict:
        try:
            resp = self._client.get(path, params=params)
        except httpx.RequestError as exc:
            raise SquareError("Network error while contacting Square") from exc
        if resp.status_code == 401:
            raise SquareAuthError("Square rejected the access token")
        if resp.status_code == 403:
            raise SquarePermissionError("Square rejected the token's permissions")
        if resp.status_code >= 400:
            raise SquareError(f"Square request {path} failed (HTTP {resp.status_code})")
        try:
            data = resp.json()
        except ValueError as exc:
            raise SquareError("Square returned a non-JSON response") from exc
        if not isinstance(data, dict):
            raise SquareError("Square returned an invalid response")
        return data

    @staticmethod
    def _object_list(data: dict, key: str) -> list[dict]:
        items = data.get(key, [])
        if not isinstance(items, list) or any(
            not isinstance(item, dict) for item in items
        ):
            raise SquareError("Square returned an invalid response")
        return items

    def list_locations(self) -> list[dict]:
        data = self._get("/v2/locations")
        locations = self._object_list(data, "locations")
        return [
            {
                "id": loc.get("id", ""),
                "name": loc.get("name", ""),
                "status": loc.get("status", ""),
            }
            for loc in locations
        ]

    def merchant_id(self) -> str:
        """Return the merchant bound to this access token."""
        data = self._get("/v2/merchants/me")
        merchant = data.get("merchant") if isinstance(data, dict) else None
        merchant_id = merchant.get("id", "") if isinstance(merchant, dict) else ""
        if not merchant_id:
            raise SquareError("Square did not return the access token's merchant id")
        return merchant_id

    def list_webhook_subscriptions(self) -> list[dict]:
        data = self._get("/v2/webhooks/subscriptions")
        subscriptions = data.get("subscriptions", [])
        if not isinstance(subscriptions, list) or any(
            not isinstance(item, dict) for item in subscriptions
        ):
            raise SquareError("Square returned an invalid response")
        return subscriptions

    def create_webhook_subscription(
        self, name: str, notification_url: str, idempotency_key: str
    ) -> dict:
        data = self._request_json(
            "POST",
            "/v2/webhooks/subscriptions",
            {
                "idempotency_key": idempotency_key,
                "subscription": {
                    "name": name,
                    "notification_url": notification_url,
                    "event_types": ["payment.updated"],
                    "api_version": SQUARE_VERSION,
                },
            },
        )
        subscription = data.get("subscription")
        if not isinstance(subscription, dict):
            raise SquareError("Square returned an invalid response")
        return subscription

    def update_webhook_subscription(
        self, subscription_id: str, notification_url: str
    ) -> dict:
        data = self._request_json(
            "PUT",
            f"/v2/webhooks/subscriptions/{subscription_id}",
            {"subscription": {"notification_url": notification_url}},
        )
        subscription = data.get("subscription")
        if not isinstance(subscription, dict):
            raise SquareError("Square returned an invalid response")
        return subscription

    def get_webhook_signature_key(self, subscription_id: str) -> str:
        data = self._get(f"/v2/webhooks/subscriptions/{subscription_id}")
        subscription = data.get("subscription")
        key = (
            subscription.get("signature_key", "")
            if isinstance(subscription, dict)
            else ""
        )
        if not key:
            raise SquareError("Square did not return the webhook signature key")
        return key

    def list_payments(
        self,
        begin_time: str | None = None,
        limit: int | None = None,
        location_id: str | None = None,
        updated_at_begin_time: str | None = None,
        sort_field: str | None = None,
        sort_order: str = "DESC",
    ) -> list[dict]:
        """Completed and pending payments in the requested order, following pagination.

        By default, exhaust all cursor pages.  A positive limit caps the total
        number of returned payments.
        """
        if limit is not None and limit <= 0:
            raise ValueError("limit must be positive or None")
        if sort_order not in {"ASC", "DESC"}:
            raise ValueError("sort_order must be 'ASC' or 'DESC'")

        payments: list[dict] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            remaining = limit - len(payments) if limit is not None else 100
            params: dict = {"sort_order": sort_order, "limit": min(remaining, 100)}
            if begin_time:
                params["begin_time"] = begin_time
            if location_id:
                params["location_id"] = location_id
            if updated_at_begin_time:
                params["updated_at_begin_time"] = updated_at_begin_time
            if sort_field:
                params["sort_field"] = sort_field
            if cursor:
                params["cursor"] = cursor
            data = self._get("/v2/payments", params=params)
            page = self._object_list(data, "payments")
            try:
                for payment in page:
                    payment_from_api(payment)
            except (TypeError, ValueError) as exc:
                raise SquareError("Square returned invalid payment data") from exc
            payments.extend(page)
            next_cursor = data.get("cursor")
            if next_cursor is not None and not isinstance(next_cursor, str):
                raise SquareError("Square returned an invalid response")
            if not next_cursor or (limit is not None and len(payments) >= limit):
                break
            if next_cursor in seen_cursors:
                raise SquareError("Square returned a repeated pagination cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        return payments if limit is None else payments[:limit]


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
    if not isinstance(payment, dict):
        raise ValueError("Payment must be an object")

    def object_field(parent: dict, key: str, label: str | None = None) -> dict:
        value = parent.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError(f"Payment {label or key} must be an object")
        return value

    def text_field(parent: dict, key: str, label: str | None = None) -> str:
        value = parent.get(key)
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValueError(f"Payment {label or key} must be a string")
        return value

    amount_money = object_field(payment, "amount_money")
    total_money = object_field(payment, "total_money")
    display_money = total_money or amount_money
    display_amount = display_money.get("amount")
    if display_amount is None:
        display_amount = amount_money.get("amount")
    if display_amount is None:
        display_amount = 0
    if isinstance(display_amount, bool) or not isinstance(display_amount, int):
        raise ValueError("Payment amount must be an integer")
    display_currency = display_money.get("currency")
    if display_currency is None or display_currency == "":
        display_currency = amount_money.get("currency")
    if display_currency is None or display_currency == "":
        display_currency = "USD"
    if not isinstance(display_currency, str):
        raise ValueError("Payment currency must be a string")
    card_details = object_field(payment, "card_details")
    card = object_field(card_details, "card", "card_details.card")
    device = object_field(payment, "device_details")
    offline_details = object_field(payment, "offline_payment_details")
    created_at = text_field(payment, "created_at")
    server_created_at = created_at
    if payment.get("is_offline_payment") is True:
        client_created_at = offline_details.get("client_created_at")
        if client_created_at is not None and not isinstance(client_created_at, str):
            raise ValueError(
                "Payment offline_payment_details.client_created_at must be a string"
            )
        if client_created_at and client_created_at.strip():
            created_at = client_created_at.strip()
    updated_at = text_field(payment, "updated_at") or server_created_at
    return {
        "id": text_field(payment, "id"),
        "created_at": created_at,
        "updated_at": updated_at,
        "amount": display_amount,
        "currency": display_currency,
        "status": text_field(payment, "status"),
        "location_id": text_field(payment, "location_id"),
        "device_id": text_field(device, "device_id", "device_details.device_id"),
        "device_name": text_field(device, "device_name", "device_details.device_name"),
        "card_last4": text_field(card, "last_4", "card_details.card.last_4"),
        "receipt_url": text_field(payment, "receipt_url"),
    }
