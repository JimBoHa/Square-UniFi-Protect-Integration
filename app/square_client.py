"""Minimal Square Connect API client: locations, payments, webhook signatures."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import math
import random
import time
from collections.abc import Iterator

import httpx

logger = logging.getLogger("spi.square")

SQUARE_VERSION = "2025-01-23"
WEBHOOK_SUBSCRIPTION_PAGE_SIZE = 100
MAX_WEBHOOK_SUBSCRIPTION_PAGES = 100

BASE_URLS = {
    "production": "https://connect.squareup.com",
    "sandbox": "https://connect.squareupsandbox.com",
}
RATE_LIMIT_MAX_RETRIES = 3
RATE_LIMIT_BASE_DELAY_SECONDS = 0.5
RATE_LIMIT_MAX_DELAY_SECONDS = 10.0
SQLITE_INTEGER_MAX = (1 << 63) - 1
IDEMPOTENT_RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


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
        rate_limit_max_retries: int = RATE_LIMIT_MAX_RETRIES,
        rate_limit_max_delay: float = RATE_LIMIT_MAX_DELAY_SECONDS,
    ):
        if environment not in BASE_URLS:
            raise ValueError("environment must be 'production' or 'sandbox'")
        self.environment = environment
        self.rate_limit_max_retries = rate_limit_max_retries
        self.rate_limit_max_delay = rate_limit_max_delay
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
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        *,
        retry_idempotent: bool = False,
    ) -> dict:
        attempt = 0
        while True:
            try:
                resp = self._client.request(method, path, json=json_body)
            except httpx.RequestError as exc:
                if not retry_idempotent or attempt >= self.rate_limit_max_retries:
                    raise SquareError("Network error while contacting Square") from exc
                delay = self._retry_delay(attempt)
                logger.warning(
                    "Square %s %s had a network error; retrying in %.2f seconds",
                    method,
                    path,
                    delay,
                )
                time.sleep(delay)
                attempt += 1
                continue
            if (
                not retry_idempotent
                or resp.status_code not in IDEMPOTENT_RETRY_STATUS_CODES
                or attempt >= self.rate_limit_max_retries
            ):
                break
            delay = self._retry_delay(attempt, resp)
            logger.warning(
                "Square %s %s returned HTTP %d; retrying in %.2f seconds",
                method,
                path,
                resp.status_code,
                delay,
            )
            time.sleep(delay)
            attempt += 1
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
        attempt = 0
        while True:
            try:
                resp = self._client.get(path, params=params)
            except httpx.RequestError as exc:
                raise SquareError("Network error while contacting Square") from exc
            if resp.status_code != 429 or attempt >= self.rate_limit_max_retries:
                break
            delay = self._retry_delay(attempt, resp)
            logger.warning(
                "Square rate limited %s; retrying in %.2f seconds",
                path,
                delay,
            )
            time.sleep(delay)
            attempt += 1
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

    def _retry_delay(
        self, attempt: int, resp: httpx.Response | None = None
    ) -> float:
        # Retry-After may also arrive as an HTTP-date; that form falls back to
        # exponential backoff below.
        max_delay = self.rate_limit_max_delay
        retry_after = resp.headers.get("retry-after") if resp is not None else None
        if retry_after is not None:
            try:
                requested_delay = float(retry_after)
            except ValueError:
                requested_delay = -1.0
            if math.isfinite(requested_delay) and requested_delay >= 0:
                return min(requested_delay, max_delay)
        backoff = min(
            RATE_LIMIT_BASE_DELAY_SECONDS * (2 ** max(0, attempt)),
            max_delay,
        )
        jitter = random.uniform(0, backoff * 0.25)
        return min(backoff + jitter, max_delay)

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
        normalized = []
        for location in self._object_list(data, "locations"):
            location_id = location.get("id")
            name = location.get("name")
            status = location.get("status")
            if not isinstance(location_id, str) or not location_id:
                raise SquareError("Square returned an invalid response")
            if name is not None and not isinstance(name, str):
                raise SquareError("Square returned an invalid response")
            if status is not None and not isinstance(status, str):
                raise SquareError("Square returned an invalid response")
            normalized.append(
                {
                    "id": location_id,
                    "name": name or "",
                    "status": status or "",
                }
            )
        return normalized

    def merchant_id(self) -> str:
        """Return the merchant bound to this access token."""
        data = self._get("/v2/merchants/me")
        merchant = data.get("merchant") if isinstance(data, dict) else None
        merchant_id = merchant.get("id", "") if isinstance(merchant, dict) else ""
        if not isinstance(merchant_id, str) or not merchant_id:
            raise SquareError("Square did not return the access token's merchant id")
        return merchant_id

    def list_webhook_subscriptions(self) -> list[dict]:
        """Return all subscription pages within a defensive request bound."""
        subscriptions: list[dict] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for page_number in range(MAX_WEBHOOK_SUBSCRIPTION_PAGES):
            params: dict = {"limit": WEBHOOK_SUBSCRIPTION_PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor
            data = self._get("/v2/webhooks/subscriptions", params=params)
            subscriptions.extend(self._object_list(data, "subscriptions"))
            next_cursor = data.get("cursor")
            if next_cursor is not None and not isinstance(next_cursor, str):
                raise SquareError("Square returned an invalid response")
            if not next_cursor:
                return subscriptions
            if next_cursor in seen_cursors:
                raise SquareError("Square returned a repeated pagination cursor")
            seen_cursors.add(next_cursor)
            if page_number + 1 >= MAX_WEBHOOK_SUBSCRIPTION_PAGES:
                raise SquareError(
                    "Square webhook subscription pagination exceeded safety limit"
                )
            cursor = next_cursor
        raise SquareError(
            "Square webhook subscription pagination exceeded safety limit"
        )

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
                    "event_types": ["payment.created", "payment.updated"],
                    "api_version": SQUARE_VERSION,
                },
            },
            retry_idempotent=True,
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
            {
                # Re-assert the event types and enabled flag so a manually
                # edited or disabled subscription becomes functional again.
                "subscription": {
                    "notification_url": notification_url,
                    "event_types": ["payment.created", "payment.updated"],
                    "enabled": True,
                }
            },
            retry_idempotent=True,
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

    def iter_payment_pages(
        self,
        begin_time: str | None = None,
        limit: int | None = None,
        location_id: str | None = None,
        updated_at_begin_time: str | None = None,
        sort_field: str | None = None,
        sort_order: str = "DESC",
    ) -> Iterator[list[dict]]:
        """Yield validated payment pages in the requested order.

        A positive limit caps the total number of yielded payments across all
        pages. Each page is yielded before the next Square request is made.
        """
        if limit is not None and limit <= 0:
            raise ValueError("limit must be positive or None")
        if sort_order not in {"ASC", "DESC"}:
            raise ValueError("sort_order must be 'ASC' or 'DESC'")

        yielded = 0
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            remaining = limit - yielded if limit is not None else 100
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
            next_cursor = data.get("cursor")
            if next_cursor is not None and not isinstance(next_cursor, str):
                raise SquareError("Square returned an invalid response")

            yielded_page = page if limit is None else page[:remaining]
            yielded += len(yielded_page)
            has_more = bool(next_cursor) and (
                limit is None or yielded < limit
            )
            if has_more:
                if next_cursor in seen_cursors:
                    raise SquareError("Square returned a repeated pagination cursor")
                seen_cursors.add(next_cursor)

            yield yielded_page
            if not has_more:
                return
            cursor = next_cursor

    def list_payments(
        self,
        begin_time: str | None = None,
        limit: int | None = None,
        location_id: str | None = None,
        updated_at_begin_time: str | None = None,
        sort_field: str | None = None,
        sort_order: str = "DESC",
    ) -> list[dict]:
        """Return validated payments after exhausting all requested pages."""
        return [
            payment
            for page in self.iter_payment_pages(
                begin_time=begin_time,
                limit=limit,
                location_id=location_id,
                updated_at_begin_time=updated_at_begin_time,
                sort_field=sort_field,
                sort_order=sort_order,
            )
            for payment in page
        ]


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
    refunded_amount = 0
    if payment.get("refunded_money") is not None:
        refunded_money = object_field(payment, "refunded_money")
        if "amount" not in refunded_money:
            raise ValueError("Payment refunded_money.amount is required")
        if "currency" not in refunded_money:
            raise ValueError("Payment refunded_money.currency is required")
        refunded_amount = refunded_money["amount"]
        refund_currency = refunded_money["currency"]
        if (
            isinstance(refunded_amount, bool)
            or not isinstance(refunded_amount, int)
            or not 0 <= refunded_amount <= SQLITE_INTEGER_MAX
        ):
            raise ValueError(
                "Payment refunded_money.amount must be a non-negative integer"
            )
        if (
            not isinstance(refund_currency, str)
            or len(refund_currency) != 3
            or not refund_currency.isascii()
            or not refund_currency.isalpha()
            or refund_currency != refund_currency.upper()
        ):
            raise ValueError(
                "Payment refunded_money.currency must be an uppercase ISO currency code"
            )
        if refund_currency != display_currency:
            # Never label a refund against a sale amount denominated in a
            # different currency. Reject the update so an accepted version is
            # not replaced by facts that cannot be compared safely.
            raise ValueError("Payment refunded_money currency does not match payment")
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
        "refunded_amount": refunded_amount,
        "status": text_field(payment, "status"),
        "location_id": text_field(payment, "location_id"),
        "device_id": text_field(device, "device_id", "device_details.device_id"),
        "device_name": text_field(device, "device_name", "device_details.device_name"),
        "card_last4": text_field(card, "last_4", "card_details.card.last_4"),
        "receipt_url": text_field(payment, "receipt_url"),
    }


OAUTH_SCOPES = ("MERCHANT_PROFILE_READ", "PAYMENTS_READ")


def oauth_authorize_url(environment: str, client_id: str, state: str) -> str:
    """Square OAuth consent URL for the configured environment."""
    if environment not in BASE_URLS:
        raise ValueError("environment must be 'production' or 'sandbox'")
    base = BASE_URLS[environment]
    scope = "+".join(OAUTH_SCOPES)
    return (
        f"{base}/oauth2/authorize?client_id={client_id}"
        f"&scope={scope}&session=false&state={state}"
    )


def oauth_exchange(
    environment: str,
    client_id: str,
    client_secret: str,
    *,
    code: str | None = None,
    refresh_token: str | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 15.0,
) -> dict:
    """Exchange an authorization code (or refresh token) for tokens.

    Returns the token payload: access_token, refresh_token, expires_at,
    merchant_id.
    """
    if environment not in BASE_URLS:
        raise ValueError("environment must be 'production' or 'sandbox'")
    body: dict = {
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if code is not None:
        body.update({"grant_type": "authorization_code", "code": code})
    elif refresh_token is not None:
        body.update({"grant_type": "refresh_token", "refresh_token": refresh_token})
    else:
        raise ValueError("code or refresh_token is required")
    client = httpx.Client(
        base_url=BASE_URLS[environment], transport=transport, timeout=timeout
    )
    try:
        try:
            resp = client.post("/oauth2/token", json=body)
        except httpx.RequestError as exc:
            raise SquareError("Network error while contacting Square") from exc
    finally:
        client.close()
    if resp.status_code in (400, 401, 403):
        raise SquareAuthError("Square rejected the OAuth request")
    if resp.status_code >= 400:
        raise SquareError(f"Square OAuth failed (HTTP {resp.status_code})")
    try:
        data = resp.json()
    except ValueError as exc:
        raise SquareError("Square returned a non-JSON response") from exc
    if not isinstance(data, dict) or not data.get("access_token"):
        raise SquareError("Square returned an invalid OAuth response")
    return data
