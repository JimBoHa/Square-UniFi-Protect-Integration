"""FastAPI application wiring the Square and UniFi Protect integrations together."""

from __future__ import annotations

import csv
import datetime
import hashlib
import io
import ipaddress
import json
import logging
import math
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from . import deeplink, discovery, sync
from .body_limit import RequestBodyLimitMiddleware
from .protect_client import (
    ProtectAuthError,
    ProtectClient,
    ProtectError,
    validate_alarm_trigger_id,
    validate_camera_id,
    validate_host,
)
from .security import hash_password, new_session_token, verify_password
from .square_client import (
    SquareAuthError,
    oauth_authorize_url,
    oauth_exchange,
    SquareClient,
    SquareError,
    SquarePermissionError,
    verify_webhook_signature,
)
from .store import (
    ALARM_ENABLED_AFTER_SETTING,
    PROTECT_CONSOLE_ID_SETTING,
    PROTECT_CONSOLE_GENERATION_SETTING,
    SQUARE_OAUTH_AUTHORIZATION_REVISION_SETTING,
    ProtectConsoleSwitchConfirmationRequired,
    ProtectSettingsConflict,
    SquareAccountChanged,
    SquareAccountSwitchRequired,
    SQUARE_OAUTH_PENDING_SETTING_KEYS,
    Store,
    TransactionSnapshotExpired,
    TransactionSnapshotFilterMismatch,
)

logger = logging.getLogger("spi")

SESSION_COOKIE = "spi_session"
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60
# One bounded request can hold the maximum 500-entry camera mapping plus ample
# JSON overhead. Square webhooks retain their existing 1 MiB contract.
REQUEST_MAX_BODY_BYTES = 1024 * 1024
SQUARE_WEBHOOK_MAX_BODY_BYTES = REQUEST_MAX_BODY_BYTES
TRANSACTION_QUERY_MAX_BODY_BYTES = 2 * 1024
REQUEST_BODY_LIMIT_EXEMPT_ROUTES = (
    # Dedicated reader keeps webhook bytes unchanged for HMAC verification.
    ("POST", "/webhooks/square"),
    # Transaction search owns a tighter auth-first streaming bound.
    ("POST", "/api/transactions"),
)
LOGIN_FAILURE_KEY_LIMIT = 10_000
DRAIN_MAX_BATCHES = 100
PROTECT_SETTING_KEYS = (
    "protect.host",
    "protect.username",
    "protect.password",
    "protect.verify_ssl",
    "protect.api_key",
    "protect.alarm_trigger_id",
    PROTECT_CONSOLE_ID_SETTING,
    PROTECT_CONSOLE_GENERATION_SETTING,
)
SQUARE_CLIENT_SETTING_KEYS = (
    "square.access_token",
    "square.environment",
    "square.merchant_id",
    "square.account_revision",
)
SQUARE_ACCOUNT_SWITCH_CODE = "square_account_switch_confirmation_required"
MAX_CAMERA_MAPPINGS = 500
PRIVATE_NO_STORE = "private, no-store"
MIN_POLL_INTERVAL_SECONDS = 1.0
BOOTSTRAP_SECRET_MIN_LENGTH = 32
BOOTSTRAP_SECRET_MAX_LENGTH = 4096
FORWARDED_CLIENT_HEADERS = frozenset(
    {
        "cf-connecting-ip",
        "fastly-client-ip",
        "fly-client-ip",
        "forwarded",
        "true-client-ip",
        "via",
        "x-client-ip",
        "x-cluster-client-ip",
        "x-envoy-external-address",
        "x-real-ip",
    }
)


def _normalized_ip_address(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def _is_loopback_host(host: str | None) -> bool:
    """Accept only localhost or a literal loopback address."""
    if not isinstance(host, str):
        return False
    normalized = host.strip().lower().rstrip(".")
    if normalized == "localhost":
        return True
    address = _normalized_ip_address(normalized)
    return address is not None and address.is_loopback


def _authority_host(authority: str | None) -> str | None:
    """Return a strictly parsed HTTP Host hostname, without its optional port."""
    if not isinstance(authority, str):
        return None
    authority = authority.strip()
    if (
        not authority
        or any(character.isspace() for character in authority)
        or any(character in authority for character in "/\\@?#,")
    ):
        return None
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return None
        host = authority[1:close]
        suffix = authority[close + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            return None
        port = suffix[1:] if suffix else ""
    else:
        if authority.count(":") > 1:
            return None
        host, separator, port = authority.partition(":")
        if separator and not port.isdigit():
            return None
    if port:
        # Bound work before int(): Python rejects conversions above its digit
        # limit, and Host is attacker-controlled during first-run setup.
        if len(port) > 5 or not port.isascii() or not 0 < int(port) <= 65535:
            return None
    return host


def _is_loopback_origin(origin: str | None) -> bool:
    if origin is None:
        return True
    if (
        not origin
        or any(character.isspace() for character in origin)
        or "\\" in origin
    ):
        return False
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or (port is not None and not 0 < port <= 65535)
    ):
        return False
    return _is_loopback_host(parsed.hostname)


def _has_forwarding_headers(request: Request) -> bool:
    for name in request.headers.keys():
        normalized = name.lower()
        if normalized in FORWARDED_CLIENT_HEADERS or normalized.startswith(
            "x-forwarded-"
        ):
            return True
    return False


def _is_explicit_local_setup_request(request: Request, bind_host: str | None) -> bool:
    """Require every independently visible signal to describe local-only use."""
    if not _is_loopback_host(bind_host) or _has_forwarding_headers(request):
        return False
    peer = request.scope.get("client")
    if (
        not isinstance(peer, (tuple, list))
        or not peer
        or not isinstance(peer[0], str)
    ):
        return False
    peer_address = _normalized_ip_address(peer[0].split("%", 1)[0])
    return bool(
        peer_address is not None
        and peer_address.is_loopback
        and _is_loopback_host(_authority_host(request.headers.get("host")))
        and _is_loopback_origin(request.headers.get("origin"))
    )


class _BootstrapSecretVerifier:
    """Keep only a wipeable digest of the one-time bootstrap secret."""

    def __init__(self, secret: str | None):
        self._lock = threading.Lock()
        self._digest: bytearray | None = None
        if secret is None or not (
            BOOTSTRAP_SECRET_MIN_LENGTH
            <= len(secret)
            <= BOOTSTRAP_SECRET_MAX_LENGTH
        ):
            return
        secret_bytes = bytearray(secret.encode("utf-8"))
        try:
            self._digest = bytearray(hashlib.sha256(secret_bytes).digest())
        finally:
            secret_bytes[:] = b"\0" * len(secret_bytes)

    @classmethod
    def from_environment(
        cls, *, generate_if_missing: bool = True
    ) -> "_BootstrapSecretVerifier":
        plaintext = os.environ.get("SPI_BOOTSTRAP_SECRET")
        invalid = plaintext is None or not (
            BOOTSTRAP_SECRET_MIN_LENGTH
            <= len(plaintext)
            <= BOOTSTRAP_SECRET_MAX_LENGTH
        )
        generated = invalid and generate_if_missing
        if generated:
            plaintext = secrets.token_urlsafe(32)
        elif invalid:
            plaintext = None
        try:
            verifier = cls(plaintext)
            if generated:
                logger.warning(
                    "Generated one-time first-run bootstrap secret: %s\n"
                    "Enter it in the setup form. It will not be shown over HTTP.",
                    plaintext,
                )
            return verifier
        finally:
            # Do not leave plaintext available to libraries or child processes.
            os.environ.pop("SPI_BOOTSTRAP_SECRET", None)
            plaintext = None

    @property
    def configured(self) -> bool:
        with self._lock:
            return self._digest is not None

    def verify(self, candidate: str) -> bool:
        candidate_digest = bytearray(
            hashlib.sha256(candidate.encode("utf-8")).digest()
        )
        try:
            with self._lock:
                return self._digest is not None and secrets.compare_digest(
                    candidate_digest, self._digest
                )
        finally:
            candidate_digest[:] = b"\0" * len(candidate_digest)

    def clear(self) -> None:
        with self._lock:
            if self._digest is not None:
                self._digest[:] = b"\0" * len(self._digest)
                self._digest = None


TRANSACTION_EXPORT_HEADERS = (
    "transaction_id",
    "timestamp",
    "amount_minor_units",
    "currency",
    "status",
    "location_id",
    "device_id",
    "device_name",
    "card_last4",
    "receipt_url",
    "protect_timeline_url",
)
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _safe_csv_cell(value: object) -> str:
    """Return spreadsheet-safe text while preserving RFC 4180 line endings."""
    text = "" if value is None else str(value)
    text = (
        text.replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", "\r\n")
    )
    formula_candidate = text.lstrip()
    if formula_candidate.startswith("\ufeff"):
        formula_candidate = formula_candidate[1:].lstrip()
    if text.startswith(("\t", "\r", "\n")) or formula_candidate.startswith(
        CSV_FORMULA_PREFIXES
    ):
        return f"'{text}"
    return text


def _parse_poll_interval(value: str) -> float:
    """Return a safe poll interval or fail before starting background work."""
    try:
        interval = float(value)
    except ValueError as exc:
        raise ValueError(
            "SPI_POLL_INTERVAL must be a finite number of at least 1 second"
        ) from exc
    if not math.isfinite(interval) or interval < MIN_POLL_INTERVAL_SECONDS:
        raise ValueError(
            "SPI_POLL_INTERVAL must be a finite number of at least 1 second"
        )
    return interval


def _read_thumbnail_bytes(path: Path) -> bytes:
    """Read an already-resolved evidence file without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    chunks: list[bytes] = []
    try:
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SetupBody(BaseModel):
    password: str = Field(min_length=8, max_length=256)
    bootstrap_secret: str = Field(
        default="", max_length=BOOTSTRAP_SECRET_MAX_LENGTH
    )

class LoginBody(BaseModel):
    password: str = Field(max_length=256)

class ProtectSettingsBody(BaseModel):
    host: str
    username: str
    password: str
    verify_ssl: bool = False
    api_key: str = Field(default="", max_length=512)
    alarm_trigger_id: str = Field(default="", max_length=256)
    disable_alarm: bool = False
    console_switch_token: str = Field(default="", max_length=2048)

class ProtectConsoleSwitchTokenBody(BaseModel):
    host: str
    username: str
    password: str
    verify_ssl: bool = False

class SquareSettingsBody(BaseModel):
    access_token: str
    environment: str = "production"
    webhook_signature_key: str = ""
    webhook_url: str = ""
    clear_webhook: bool = False
    confirm_account_switch: bool = False
    account_switch_confirmation_token: str = Field(default="", max_length=4096)

class CameraMappingEntry(BaseModel):
    location_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(default="", max_length=255)
    device_name: str = Field(default="", max_length=255)
    camera_id: str = Field(min_length=1, max_length=64)
    camera_name: str = Field(default="", max_length=128)

class WebhookRegisterBody(BaseModel):
    notification_url: str = Field(min_length=12, max_length=512)

class DiscoverProtectBody(BaseModel):
    host: str = Field(default="", max_length=255)

class SquareOAuthAppBody(BaseModel):
    client_id: str = Field(min_length=8, max_length=128)
    client_secret: str = Field(min_length=8, max_length=256)
    environment: str = "production"

class CameraMappingBody(BaseModel):
    mappings: list[CameraMappingEntry]

class DeepLinkSettingsBody(BaseModel):
    template: str = Field(default="", max_length=2048)


TransactionStatusFilter = Literal[
    "APPROVED",
    "PENDING",
    "COMPLETED",
    "CANCELED",
    "FAILED",
]


class TransactionQueryBody(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=1_000_000)
    snapshot: int | None = Field(default=None, ge=1, le=(1 << 63) - 1)
    q: str = Field(default="", max_length=64)
    status: TransactionStatusFilter | None = None


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    data_dir: str | Path | None = None,
    protect_transport=None,
    square_transport=None,
    enable_poller: bool | None = None,
    bind_host: str | None = None,
    tls_enabled: bool = False,
) -> FastAPI:
    if enable_poller is None:
        enable_poller = os.environ.get("SPI_DISABLE_POLLER", "0") != "1"
    poll_interval = (
        _parse_poll_interval(os.environ.get("SPI_POLL_INTERVAL", "60"))
        if enable_poller
        else None
    )
    data_dir = Path(data_dir or os.environ.get("SPI_DATA_DIR", "./data"))
    store = Store(data_dir)
    app = FastAPI(title="Square UniFi Protect Integration", docs_url=None, redoc_url=None)
    app.state.store = store
    app.state.login_failures: dict[str, list[float]] = {}
    app.state.login_lock = threading.Lock()
    square_account_lock = threading.RLock()
    # Single worker draining the durable thumbnail-retry queue: webhooks ack
    # before any Protect I/O and just nudge this drain, which the queue's
    # leases and backoff keep bounded and evidence-safe.
    thumbnail_executor = ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="spi-thumbnail-drain"
    )
    drain_state_lock = threading.Lock()
    app.state.thumbnail_executor = thumbnail_executor
    app.state.thumbnail_drain_queued = False

    cookie_secure = os.environ.get("SPI_COOKIE_SECURE", "0") == "1"
    configured_bind_host = (
        bind_host if bind_host is not None else os.environ.get("SPI_HOST")
    )
    # Only the bundled runner may assert this after installing its TLS kwargs.
    # Never infer transport security from environment or request headers here.
    configured_tls = tls_enabled
    setup_pending = store.get_setting("admin.password_hash") is None
    bootstrap_secret_verifier = _BootstrapSecretVerifier.from_environment(
        generate_if_missing=setup_pending
    )
    if not setup_pending:
        bootstrap_secret_verifier.clear()

    @app.middleware("http")
    async def apply_api_cache_policy(request: Request, call_next):
        # Every API response can carry account or evidence data; keep all of it
        # out of browser and intermediary caches. Routes may still set their
        # own policy, which wins.
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", PRIVATE_NO_STORE)
        return response

    # Register after the cache policy so this pure ASGI gate runs first. It
    # bounds body buffering before FastAPI parses models or evaluates auth.
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=REQUEST_MAX_BODY_BYTES,
        excluded_routes=REQUEST_BODY_LIMIT_EXEMPT_ROUTES,
    )

    # -- client construction from stored settings ---------------------------

    def build_protect(settings: dict[str, str | None] | None = None) -> ProtectClient | None:
        settings = settings or store.get_settings(PROTECT_SETTING_KEYS)
        host = settings["protect.host"]
        username = settings["protect.username"]
        password = settings["protect.password"]
        if not (host and username and password):
            return None
        return ProtectClient(
            host,
            username,
            password,
            verify_ssl=settings["protect.verify_ssl"] == "1",
            transport=protect_transport,
            api_key=settings["protect.api_key"],
        )

    def _maybe_refresh_oauth_token() -> None:
        # Serialize exchanges without taking the provider-state writer. A
        # confirmed account switch may complete while Square is slow; the exact
        # snapshot fence in update_square_oauth_tokens then discards this result.
        with store.square_oauth_refresh_guard():
            oauth = store.get_settings(
                (
                    "square.access_token",
                    "square.oauth_client_id",
                    "square.oauth_client_secret",
                    "square.refresh_token",
                    "square.token_expires_at",
                    "square.environment",
                    "square.merchant_id",
                    "square.account_revision",
                )
            )
            if not (
                oauth["square.oauth_client_id"]
                and oauth["square.oauth_client_secret"]
                and oauth["square.refresh_token"]
                and oauth["square.token_expires_at"]
            ):
                return
            try:
                expires = datetime.datetime.fromisoformat(
                    oauth["square.token_expires_at"].replace("Z", "+00:00")
                )
            except ValueError:
                return
            now = datetime.datetime.now(datetime.timezone.utc)
            if expires - now > datetime.timedelta(days=3):
                return
            try:
                tokens = oauth_exchange(
                    oauth["square.environment"] or "production",
                    oauth["square.oauth_client_id"],
                    oauth["square.oauth_client_secret"],
                    refresh_token=oauth["square.refresh_token"],
                    transport=square_transport,
                )
            except SquareError as exc:
                logger.warning("Square OAuth token refresh failed: %s", exc)
                return
            try:
                store.update_square_oauth_tokens(
                    access_token=tokens["access_token"],
                    refresh_token=(
                        tokens.get("refresh_token")
                        or oauth["square.refresh_token"]
                    ),
                    token_expires_at=tokens.get("expires_at", ""),
                    expected_access_token=oauth["square.access_token"],
                    expected_refresh_token=oauth["square.refresh_token"],
                    expected_merchant_id=oauth["square.merchant_id"],
                    expected_environment=oauth["square.environment"],
                    expected_account_revision=oauth["square.account_revision"],
                    expected_oauth_client_id=oauth["square.oauth_client_id"],
                    expected_oauth_client_secret=(
                        oauth["square.oauth_client_secret"]
                    ),
                )
            except SquareAccountChanged:
                logger.info(
                    "Discarded Square OAuth refresh after account settings changed"
                )

    def build_square(
        settings: dict[str, str | None] | None = None,
    ) -> SquareClient | None:
        if settings is None:
            _maybe_refresh_oauth_token()
            settings = store.get_settings(SQUARE_CLIENT_SETTING_KEYS)
        token = settings["square.access_token"]
        if not token:
            return None
        return SquareClient(
            token,
            environment=settings["square.environment"] or "production",
            transport=square_transport,
        )

    class ProtectConsoleIdentityMismatch(ProtectError):
        """A different NVR answered on the configured Protect host."""

    def verify_protect_console_identity(
        protect: ProtectClient,
        settings: dict[str, str | None],
    ) -> None:
        """Reject provider work when a previously bound NVR identity changed."""
        expected_console_id = settings[PROTECT_CONSOLE_ID_SETTING]
        if expected_console_id is None:
            return
        _, observed_console_id = protect.get_cameras_with_console_identity()
        if observed_console_id != expected_console_id:
            raise ProtectConsoleIdentityMismatch(
                "UniFi Protect console identity changed or disappeared; "
                "reconnect Protect before processing camera evidence or alarms"
            )

    def _drain_protect_work_queue() -> None:
        with drain_state_lock:
            app.state.thumbnail_drain_queued = False
        protect_settings = store.get_settings(PROTECT_SETTING_KEYS)
        protect = build_protect(protect_settings)
        if protect is None:
            return
        try:
            verify_protect_console_identity(protect, protect_settings)
            # Sale alarms first: a slow snapshot request must not delay the
            # Alarm Manager automation for a completed sale. The iteration
            # caps are a backstop: no realistic queue needs more than
            # cap * batch-size items per drain, and the next nudge or poll
            # picks up anything a pathological interaction leaves behind.
            for _ in range(DRAIN_MAX_BATCHES):
                if (
                    sync.retry_pending_alarms(
                        store,
                        protect,
                        protect_settings["protect.alarm_trigger_id"],
                    )
                    != sync.ALARM_RETRY_BATCH_SIZE
                ):
                    # A partial batch includes failures or an empty queue, so
                    # stop and wait for the next nudge instead of retrying a
                    # dead console here.
                    break

            for _ in range(DRAIN_MAX_BATCHES):
                sync.retry_missing_thumbnails(store, protect)
                # Failed captures move into backoff and are intentionally not
                # considered due. Continue only for runnable jobs beyond the
                # bounded retry batch.
                if not store.has_due_thumbnail_retries():
                    break
        except Exception:
            logger.exception("Protect work drain failed")
        finally:
            try:
                protect.close()
            except Exception:
                logger.exception("Could not close Protect client after queue drain")

    def drain_protect_work_queue() -> None:
        # A completed account switch cannot be followed by an old merchant's
        # already-claimed alarm or thumbnail work in this process.
        with square_account_lock, store.integration_guard():
            _drain_protect_work_queue()

    def nudge_protect_work_queue() -> None:
        """Schedule a queue drain; nudges coalesce to at most one queued drain."""
        with drain_state_lock:
            if app.state.thumbnail_drain_queued:
                return
            app.state.thumbnail_drain_queued = True
        try:
            thumbnail_executor.submit(drain_protect_work_queue)
        except RuntimeError:
            # Shutting down — the durable queues retry on the next sync.
            with drain_state_lock:
                app.state.thumbnail_drain_queued = False

    def require_square() -> SquareClient:
        client = build_square()
        if client is None:
            raise HTTPException(status_code=409, detail="Square is not configured")
        return client

    # -- auth ----------------------------------------------------------------

    def require_session(request: Request) -> None:
        token = request.cookies.get(SESSION_COOKIE)
        if not token or not store.session_valid(token):
            raise HTTPException(status_code=401, detail="Authentication required")

    authed = Depends(require_session)

    def client_key(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def prune_login_failures_locked(now: float) -> None:
        """Discard expired attempts and empty client keys while holding the lock."""
        for key, attempts in list(app.state.login_failures.items()):
            active = [
                attempted_at
                for attempted_at in attempts
                if now - attempted_at < LOGIN_LOCKOUT_SECONDS
            ]
            if active:
                app.state.login_failures[key] = active
            else:
                app.state.login_failures.pop(key, None)

    def check_login_throttle(request: Request) -> None:
        key = client_key(request)
        now = time.time()
        with app.state.login_lock:
            prune_login_failures_locked(now)
            attempts = app.state.login_failures.get(key)
            if attempts is None and len(app.state.login_failures) >= LOGIN_FAILURE_KEY_LIMIT:
                # Fail before the expensive password hash when a distributed
                # attack has filled the bounded source map. Expired entries
                # were pruned above, so legitimate new clients can retry once
                # the short lockout window rolls forward.
                raise HTTPException(
                    status_code=429,
                    detail="Too many failed login attempts; try again shortly",
                )
            if len(attempts or ()) >= LOGIN_MAX_FAILURES:
                raise HTTPException(
                    status_code=429,
                    detail="Too many failed login attempts; try again shortly",
                )

    def record_login_failure(request: Request) -> None:
        key = client_key(request)
        now = time.time()
        with app.state.login_lock:
            prune_login_failures_locked(now)
            attempts = app.state.login_failures.get(key)
            if attempts is None:
                # Never evict an active source: doing so would let a distributed
                # attacker reset another source's brute-force counter. When the
                # bounded map is full, throttle new failing sources instead.
                if len(app.state.login_failures) >= LOGIN_FAILURE_KEY_LIMIT:
                    raise HTTPException(
                        status_code=429,
                        detail="Too many failed login attempts; try again shortly",
                    )
                attempts = []
                app.state.login_failures[key] = attempts
            if len(attempts) >= LOGIN_MAX_FAILURES:
                raise HTTPException(
                    status_code=429,
                    detail="Too many failed login attempts; try again shortly",
                )
            attempts.append(now)

    def clear_login_failures(request: Request) -> None:
        with app.state.login_lock:
            app.state.login_failures.pop(client_key(request), None)

    # -- setup & login -------------------------------------------------------

    @app.get("/api/status")
    def status() -> dict:
        return {
            "setup_complete": store.get_setting("admin.password_hash") is not None,
            "protect_configured": store.get_setting("protect.host") is not None,
            "square_configured": store.get_setting("square.access_token") is not None,
            "cameras_mapped": len(store.get_camera_mappings()) > 0,
        }

    @app.post("/api/setup")
    def setup(body: SetupBody, request: Request) -> dict:
        if store.get_setting("admin.password_hash") is not None:
            bootstrap_secret_verifier.clear()
            raise HTTPException(status_code=409, detail="Setup already completed")
        direct_request = _is_explicit_local_setup_request(
            request, configured_bind_host
        )
        if not direct_request and not configured_tls:
            body.bootstrap_secret = ""
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "bootstrap_tls_not_configured",
                    "message": (
                        "Non-local first-run setup requires the app's built-in "
                        "TLS. Set SPI_TLS=1 and restart before opening the remote "
                        "setup page. Forwarded request headers cannot satisfy "
                        "this requirement."
                    ),
                },
            )
        secret_valid = bootstrap_secret_verifier.verify(body.bootstrap_secret)
        body.bootstrap_secret = ""
        if not secret_valid:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "invalid_bootstrap_secret",
                    "message": (
                        "First-run setup requires the one-time bootstrap secret "
                        "configured in SPI_BOOTSTRAP_SECRET or printed in the "
                        "server console at startup."
                    ),
                },
            )
        password_hash = hash_password(body.password)
        if not store.set_setting_if_absent("admin.password_hash", password_hash):
            bootstrap_secret_verifier.clear()
            raise HTTPException(status_code=409, detail="Setup already completed")
        bootstrap_secret_verifier.clear()
        return {"ok": True}

    @app.post("/api/login")
    def login(body: LoginBody, request: Request, response: Response) -> dict:
        check_login_throttle(request)
        stored = store.get_setting("admin.password_hash")
        if stored is None:
            raise HTTPException(status_code=409, detail="Run setup first")
        if not verify_password(body.password, stored):
            record_login_failure(request)
            raise HTTPException(status_code=401, detail="Invalid password")
        token = new_session_token()
        store.create_session(token)
        clear_login_failures(request)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            secure=cookie_secure,
            max_age=12 * 3600,
        )
        return {"ok": True}

    @app.post("/api/logout")
    def logout(request: Request, response: Response, _=authed) -> dict:
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            store.delete_session(token)
        response.delete_cookie(SESSION_COOKIE)
        return {"ok": True}

    # -- settings --------------------------------------------------------------

    def clear_protect_alarm_settings() -> dict:
        with store.protect_settings_guard():
            # Wait for any claimed delivery to finish before reporting the
            # trigger disabled. New drains take the shared side of the
            # provider-state guard.
            with store.integration_guard(exclusive=True):
                store.update_settings(
                    {},
                    delete_keys=(
                        "protect.api_key",
                        "protect.alarm_trigger_id",
                        ALARM_ENABLED_AFTER_SETTING,
                    ),
                    suppress_completed_alarms=True,
                )
        return {"ok": True, "alarm_configured": False}

    @app.delete("/api/settings/protect/alarm")
    def delete_protect_alarm(_=authed) -> dict:
        """Disable alarms locally even when the Protect console is offline."""
        return clear_protect_alarm_settings()

    discovery_scan_lock = threading.Lock()

    @app.post("/api/discover/protect")
    def discover_protect(body: DiscoverProtectBody, _=authed) -> list[dict]:
        """Scan the LAN for UniFi consoles; optionally probe one address.

        Broadcast/subnet discovery finds consoles on this network; consoles
        on routed VLANs only answer a direct probe, so the UI passes the
        typed host here to identify it before connecting. POST because the
        scan emits network traffic; one scan runs at a time.
        """
        extra: tuple[str, ...] = ()
        if body.host:
            try:
                extra = (validate_host(body.host).partition(":")[0],)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        if not discovery_scan_lock.acquire(blocking=False):
            raise HTTPException(
                status_code=409, detail="A network scan is already running"
            )
        try:
            return discovery.discover_consoles(extra_hosts=extra)
        finally:
            discovery_scan_lock.release()

    @app.post("/api/settings/protect/console-switch-token")
    def protect_console_switch_token(
        body: ProtectConsoleSwitchTokenBody,
        response: Response,
        _=authed,
    ) -> dict:
        """Verify the target console, then issue short-lived destructive consent."""
        try:
            host = validate_host(body.host)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        current_identity = store.get_settings(
            (
                "protect.host",
                PROTECT_CONSOLE_ID_SETTING,
                PROTECT_CONSOLE_GENERATION_SETTING,
            )
        )
        client = ProtectClient(
            host,
            body.username,
            body.password,
            verify_ssl=body.verify_ssl,
            transport=protect_transport,
        )
        try:
            client.login()
            _, console_id = client.get_cameras_with_console_identity()
        except ProtectAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except (ProtectError, OSError) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not reach UniFi Protect: {exc}",
            )
        finally:
            client.close()
        try:
            token = store.protect_console_switch_token(
                host,
                console_id,
                expected_host=current_identity["protect.host"],
                expected_generation=current_identity[
                    PROTECT_CONSOLE_GENERATION_SETTING
                ],
                expected_console_id=current_identity[PROTECT_CONSOLE_ID_SETTING],
            )
        except ProtectSettingsConflict as exc:
            raise HTTPException(
                status_code=409,
                detail=f"{exc}; review the Protect host and try again",
                headers={"Cache-Control": "private, no-store"},
            )
        response.headers["Cache-Control"] = "private, no-store"
        return {"token": token or ""}

    @app.put("/api/settings/protect")
    def set_protect(body: ProtectSettingsBody, _=authed) -> dict:
        if body.disable_alarm:
            return {
                **clear_protect_alarm_settings(),
                "cameras": None,
            }
        with store.protect_settings_guard():
            return set_protect_locked(body)

    def set_protect_locked(body: ProtectSettingsBody) -> dict:
        """Validate and commit one serialized Protect settings mutation."""
        try:
            host = validate_host(body.host)
            submitted_trigger_id = (
                validate_alarm_trigger_id(body.alarm_trigger_id)
                if body.alarm_trigger_id
                else ""
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        submitted_api_key = body.api_key.strip()
        stored_protect_settings = store.get_settings(PROTECT_SETTING_KEYS)
        stored_host = stored_protect_settings["protect.host"]
        stored_generation = stored_protect_settings[PROTECT_CONSOLE_GENERATION_SETTING]
        stored_console_id = stored_protect_settings[PROTECT_CONSOLE_ID_SETTING]
        host_changed = bool(stored_host and stored_host != host)
        if host_changed and not body.console_switch_token:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Protect host changed. Confirm the console switch to clear "
                    "old camera mappings and Protect evidence, then save again."
                ),
            )
        candidate_api_key = submitted_api_key or (
            stored_protect_settings["protect.api_key"] if not host_changed else None
        )
        client = ProtectClient(
            host,
            body.username,
            body.password,
            verify_ssl=body.verify_ssl,
            transport=protect_transport,
            api_key=candidate_api_key,
        )
        try:
            client.login()
            cameras, observed_console_id = client.get_cameras_with_console_identity()
        except ProtectAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except (ProtectError, OSError) as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach UniFi Protect: {exc}")
        finally:
            client.close()
        identity_changed = bool(
            stored_host
            and stored_console_id is not None
            and stored_console_id != observed_console_id
        )
        console_switch_requested = host_changed or identity_changed
        if console_switch_requested and not store.protect_console_switch_token_valid(
            body.console_switch_token,
            host,
            observed_console_id,
        ):
            identity_reason = (
                "Protect console identity changed or disappeared. "
                if identity_changed
                else "Protect host changed. "
            )
            raise HTTPException(
                status_code=409,
                detail=(
                    identity_reason
                    + "Confirm the console switch to clear old camera mappings "
                    "and Protect evidence, then save again."
                ),
            )
        # API keys and alarm triggers are console-specific. Blank values retain
        # them only after the same console identity has been verified.
        stored_api_key = (
            None if console_switch_requested else stored_protect_settings["protect.api_key"]
        )
        stored_trigger_id = (
            None
            if console_switch_requested
            else stored_protect_settings["protect.alarm_trigger_id"]
        )
        effective_api_key = submitted_api_key or stored_api_key
        effective_trigger_id = submitted_trigger_id or stored_trigger_id
        if effective_trigger_id and not effective_api_key:
            raise HTTPException(
                status_code=422,
                detail="Protect API key is required when an alarm trigger id is set",
            )
        if effective_api_key:
            integration_client = ProtectClient(
                host,
                body.username,
                body.password,
                verify_ssl=body.verify_ssl,
                transport=protect_transport,
                api_key=effective_api_key,
            )
            try:
                integration_client.get_integration_info()
            except ProtectAuthError as exc:
                raise HTTPException(status_code=401, detail=str(exc))
            except (ProtectError, OSError) as exc:
                raise HTTPException(
                    status_code=502,
                    detail=f"Could not reach UniFi Protect: {exc}",
                )
            finally:
                integration_client.close()
        settings_updates = {
            "protect.host": (host, False),
            "protect.username": (body.username, False),
            "protect.password": (body.password, True),
            "protect.verify_ssl": ("1" if body.verify_ssl else "0", False),
        }
        if submitted_api_key:
            settings_updates["protect.api_key"] = (submitted_api_key, True)
        if submitted_trigger_id:
            settings_updates["protect.alarm_trigger_id"] = (
                submitted_trigger_id,
                False,
            )
        alarm_is_configured = bool(effective_api_key and effective_trigger_id)
        delete_keys = (
            (
                "protect.api_key",
                "protect.alarm_trigger_id",
                ALARM_ENABLED_AFTER_SETTING,
            )
            if console_switch_requested
            else ()
        )

        def commit_protect_settings() -> bool:
            return store.update_protect_settings(
                settings_updates,
                expected_host=stored_host,
                expected_generation=stored_generation,
                expected_console_id=stored_console_id,
                observed_console_id=observed_console_id,
                console_switch_token=body.console_switch_token,
                delete_keys=delete_keys,
                activate_alarm_at_ms=(
                    int(time.time() * 1000) if alarm_is_configured else None
                ),
            )

        try:
            # Keep slow credential probes outside the provider writer so
            # webhook persistence and reads remain available. The mutation
            # guard still prevents another PUT/DELETE from changing the
            # retained settings snapshot before this atomic commit.
            with store.integration_guard(exclusive=True):
                console_switched = commit_protect_settings()
        except ProtectConsoleSwitchConfirmationRequired as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ProtectSettingsConflict as exc:
            raise HTTPException(
                status_code=409,
                detail=f"{exc}; review the Protect host and try again",
            )
        return {
            "ok": True,
            "cameras": len(cameras),
            "alarm_configured": alarm_is_configured,
            "console_switched": console_switched,
        }

    @app.put("/api/settings/square")
    def set_square(body: SquareSettingsBody, _=authed) -> dict:
        if body.environment not in ("production", "sandbox"):
            raise HTTPException(status_code=422, detail="Invalid environment")
        if bool(body.webhook_signature_key) != bool(body.webhook_url):
            raise HTTPException(
                status_code=422,
                detail="Webhook signature key and notification URL must be provided together",
            )
        if body.clear_webhook and body.webhook_signature_key:
            raise HTTPException(
                status_code=422,
                detail="clear_webhook cannot be combined with new webhook credentials",
            )
        # Interactive save: keep rate-limit retries short so the browser isn't
        # left waiting behind the poller's more patient defaults.
        client = SquareClient(
            body.access_token,
            environment=body.environment,
            transport=square_transport,
            rate_limit_max_retries=1,
            rate_limit_max_delay=2.0,
        )
        try:
            try:
                locations = client.list_locations()
                merchant_id = client.merchant_id()
            except SquarePermissionError as exc:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Square access token must grant MERCHANT_PROFILE_READ permission"
                    ),
                ) from exc
            try:
                client.list_payments(limit=1)
            except SquarePermissionError as exc:
                raise HTTPException(
                    status_code=403,
                    detail="Square access token must grant PAYMENTS_READ permission",
                ) from exc
        except SquareAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except (SquareError, OSError) as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach Square: {exc}")
        finally:
            client.close()
        try:
            with square_account_lock:
                account_configuration = store.configure_square_account(
                    merchant_id=merchant_id,
                    access_token=body.access_token,
                    environment=body.environment,
                    webhook_signature_key=(
                        body.webhook_signature_key
                        if body.webhook_signature_key
                        else None
                    ),
                    webhook_url=body.webhook_url if body.webhook_url else None,
                    clear_webhook=body.clear_webhook,
                    confirm_account_switch=body.confirm_account_switch,
                    account_switch_confirmation_token=(
                        body.account_switch_confirmation_token
                    ),
                    # A pasted access token explicitly replaces any prior
                    # OAuth grant and pending callbacks. Keep the reusable
                    # OAuth application credentials.
                    clear_oauth_token_metadata=True,
                )
                saved_webhook = store.get_settings(
                    ("square.webhook_signature_key", "square.webhook_url")
                )
        except SquareAccountSwitchRequired as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": SQUARE_ACCOUNT_SWITCH_CODE,
                    "message": (
                        "These credentials belong to a different Square account. "
                        "Confirm the account switch to erase the previous account's "
                        "local transactions, thumbnails, POS devices, camera mappings, "
                        "sync history, and saved Square webhook credentials."
                    ),
                    "confirmation_token": exc.confirmation_token,
                },
            ) from exc

        webhook_configured = bool(
            saved_webhook["square.webhook_signature_key"]
            and saved_webhook["square.webhook_url"]
        )
        # Blank webhook fields retain saved credentials only for the same
        # merchant. A switch clears them unless a new pair was submitted.
        return {
            "ok": True,
            "locations": locations,
            "account_switched": account_configuration.switched,
            "webhook_configured": webhook_configured,
            "account_revision": account_configuration.account_revision,
            "evidence_cleanup_pending": (
                account_configuration.evidence_cleanup_pending
            ),
        }

    def deep_link_settings_response() -> dict[str, str]:
        return {
            "template": store.get_setting("deep_link_template") or "",
            "default_template": deeplink.DEFAULT_TEMPLATE,
        }

    @app.get("/api/settings/deep-link")
    def get_deep_link_settings(_=authed) -> dict[str, str]:
        """Return only the non-secret Protect timeline-link configuration."""
        return deep_link_settings_response()

    @app.put("/api/settings/deep-link")
    def set_deep_link_settings(body: DeepLinkSettingsBody, _=authed) -> dict:
        try:
            template = deeplink.validate_deep_link_template(body.template)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if not template or template == deeplink.DEFAULT_TEMPLATE:
            store.delete_setting("deep_link_template")
        else:
            store.set_setting("deep_link_template", template)
        return {"ok": True, **deep_link_settings_response()}

    WEBHOOK_SUBSCRIPTION_NAME = "square-unifi-protect"

    @app.post("/api/settings/square/webhook/register")
    def register_webhook(body: WebhookRegisterBody, _=authed) -> dict:
        """Create (or retarget) our Square webhook subscription automatically.

        Uses Square's Webhook Subscriptions API so the operator never has to
        open the developer dashboard: the subscription is created for
        payment.updated, its signature key is fetched, and both are stored.
        """
        url = body.notification_url.strip()
        if not url.lower().startswith("https://"):
            raise HTTPException(
                status_code=422,
                detail="Notification URL must be https:// and publicly reachable",
            )
        _maybe_refresh_oauth_token()
        # Bind every provider call below to one coherent credential snapshot.
        # The slow Square requests remain outside the cross-process writer;
        # the final store operation compares this snapshot before committing.
        with store.integration_guard():
            square_settings = store.get_settings(SQUARE_CLIENT_SETTING_KEYS)
        client = build_square(square_settings)
        if client is None:
            raise HTTPException(status_code=409, detail="Square is not configured")
        try:
            existing = next(
                (
                    sub
                    for sub in client.list_webhook_subscriptions()
                    if sub.get("name") == WEBHOOK_SUBSCRIPTION_NAME
                ),
                None,
            )
            if existing:
                subscription = client.update_webhook_subscription(
                    str(existing.get("id", "")), url
                )
                signature_key = subscription.get("signature_key") or (
                    client.get_webhook_signature_key(str(existing.get("id", "")))
                )
            else:
                subscription = client.create_webhook_subscription(
                    WEBHOOK_SUBSCRIPTION_NAME, url, secrets.token_hex(16)
                )
                signature_key = subscription.get("signature_key", "")
            if not signature_key:
                raise HTTPException(
                    status_code=502,
                    detail="Square did not return the webhook signature key",
                )
        except SquareAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except SquarePermissionError:
            raise HTTPException(
                status_code=403,
                detail="Square access token cannot manage webhook subscriptions",
            )
        except SquareError as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach Square: {exc}")
        finally:
            client.close()
        try:
            store.update_square_webhook_settings(
                signature_key,
                url,
                expected_merchant_id=square_settings["square.merchant_id"],
                expected_environment=(
                    square_settings["square.environment"] or "production"
                ),
                expected_account_revision=(
                    square_settings["square.account_revision"]
                ),
                expected_access_token=square_settings["square.access_token"] or "",
            )
        except SquareAccountChanged as exc:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Square account or credentials changed while the webhook "
                    "was being registered; try again"
                ),
            ) from exc
        return {"ok": True, "notification_url": url, "updated": existing is not None}

    @app.put("/api/settings/square/oauth-app")
    def set_square_oauth_app(body: SquareOAuthAppBody, _=authed) -> dict:
        """Store the Square application's OAuth client credentials."""
        if body.environment not in ("production", "sandbox"):
            raise HTTPException(status_code=422, detail="Invalid environment")
        store.update_settings(
            {
                "square.oauth_client_id": (body.client_id.strip(), False),
                "square.oauth_client_secret": (body.client_secret.strip(), True),
                # OAuth application setup must not mutate the environment bound
                # to an already-connected merchant and its account revision.
                "square.oauth_environment": (body.environment, False),
            }
        )
        return {"ok": True}

    @app.get("/oauth/square/start")
    def square_oauth_start(_=authed) -> RedirectResponse:
        oauth = store.get_settings(
            (
                "square.oauth_client_id",
                "square.oauth_environment",
                "square.environment",
            )
        )
        if not oauth["square.oauth_client_id"]:
            raise HTTPException(
                status_code=409,
                detail="Save the Square application client id/secret first",
            )
        # Starting over explicitly abandons any older, unconfirmed grant.
        store.delete_settings(*SQUARE_OAUTH_PENDING_SETTING_KEYS)
        state = secrets.token_urlsafe(24)
        store.create_square_oauth_state(state)
        return RedirectResponse(
            oauth_authorize_url(
                oauth["square.oauth_environment"]
                or oauth["square.environment"]
                or "production",
                oauth["square.oauth_client_id"],
                state,
            ),
            status_code=302,
        )

    @app.get("/oauth/square/callback")
    def square_oauth_callback(
        code: str = "", state: str = "", error: str = "", _=authed
    ) -> RedirectResponse:
        # Read the manual-authorization fence before consuming the one-time
        # state. A manual save racing either step will delete the state or
        # rotate the fence before this callback can persist exchanged tokens.
        authorization_revision = store.get_setting(
            SQUARE_OAUTH_AUTHORIZATION_REVISION_SETTING
        )
        if not store.consume_square_oauth_state(state):
            raise HTTPException(status_code=400, detail="Invalid OAuth state")
        if error:
            # The operator declined consent (or Square reported a problem);
            # land back in the app instead of on a bare JSON error.
            return RedirectResponse("/?square_oauth=denied", status_code=302)
        if not code:
            raise HTTPException(status_code=400, detail="Invalid OAuth state")
        oauth = store.get_settings(
            (
                "square.oauth_client_id",
                "square.oauth_client_secret",
                "square.oauth_environment",
                "square.environment",
            )
        )
        oauth_environment = (
            oauth["square.oauth_environment"]
            or oauth["square.environment"]
            or "production"
        )
        try:
            tokens = oauth_exchange(
                oauth_environment,
                oauth["square.oauth_client_id"] or "",
                oauth["square.oauth_client_secret"] or "",
                code=code,
                transport=square_transport,
            )
        except SquareAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except SquareError as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach Square: {exc}")
        access_token = tokens.get("access_token")
        merchant_id = tokens.get("merchant_id")
        refresh_token = tokens.get("refresh_token")
        expires_at = tokens.get("expires_at", "")
        if not isinstance(access_token, str) or not access_token:
            raise HTTPException(status_code=502, detail="Square returned an invalid OAuth token")
        if not isinstance(merchant_id, str) or not merchant_id:
            raise HTTPException(status_code=502, detail="Square did not identify the OAuth merchant")
        if refresh_token is not None and not isinstance(refresh_token, str):
            raise HTTPException(status_code=502, detail="Square returned an invalid refresh token")
        if not isinstance(expires_at, str):
            raise HTTPException(status_code=502, detail="Square returned an invalid token expiry")
        environment = oauth_environment
        try:
            with square_account_lock:
                store.configure_square_account(
                    merchant_id=merchant_id,
                    access_token=access_token,
                    environment=environment,
                    oauth_refresh_token=refresh_token,
                    oauth_token_expires_at=expires_at,
                    clear_oauth_pending=True,
                    expected_oauth_authorization_revision=(
                        authorization_revision
                    ),
                )
        except SquareAccountSwitchRequired as exc:
            # Keep the active merchant untouched until the operator explicitly
            # confirms the same destructive switch shown by manual-token setup.
            if not store.update_square_oauth_grant(
                authorization_revision,
                {
                    "square.oauth_pending_access_token": (access_token, True),
                    "square.oauth_pending_refresh_token": (refresh_token or "", True),
                    "square.oauth_pending_expires_at": (expires_at, False),
                    "square.oauth_pending_merchant_id": (merchant_id, False),
                    "square.oauth_pending_environment": (environment, False),
                    "square.oauth_pending_confirmation_token": (
                        exc.confirmation_token,
                        True,
                    ),
                    "square.oauth_pending_created_at": (str(time.time()), False),
                    "square.oauth_pending_authorization_revision": (
                        authorization_revision or "",
                        False,
                    ),
                },
            ):
                raise HTTPException(status_code=400, detail="Invalid OAuth state")
            return RedirectResponse("/?square_oauth=switch_required", status_code=302)
        except SquareAccountChanged:
            raise HTTPException(status_code=400, detail="Invalid OAuth state")
        return RedirectResponse("/?square_oauth=connected", status_code=302)

    @app.post("/api/settings/square/oauth-switch/confirm")
    def confirm_square_oauth_switch(_=authed) -> dict:
        """Activate a pending OAuth grant after explicit destructive consent."""
        with square_account_lock:
            pending = store.get_settings(SQUARE_OAUTH_PENDING_SETTING_KEYS)
            try:
                created_at = float(pending["square.oauth_pending_created_at"] or "")
            except ValueError:
                created_at = 0.0
            now = time.time()
            required = (
                pending["square.oauth_pending_access_token"],
                pending["square.oauth_pending_merchant_id"],
                pending["square.oauth_pending_environment"],
                pending["square.oauth_pending_confirmation_token"],
            )
            if (
                not all(required)
                or created_at > now + 30
                or now - created_at > 10 * 60
            ):
                store.delete_settings(*SQUARE_OAUTH_PENDING_SETTING_KEYS)
                raise HTTPException(
                    status_code=409,
                    detail="The pending Square authorization expired; connect again",
                )
            try:
                configuration = store.configure_square_account(
                    merchant_id=pending["square.oauth_pending_merchant_id"] or "",
                    access_token=pending["square.oauth_pending_access_token"] or "",
                    environment=pending["square.oauth_pending_environment"] or "production",
                    confirm_account_switch=True,
                    account_switch_confirmation_token=(
                        pending["square.oauth_pending_confirmation_token"] or ""
                    ),
                    oauth_refresh_token=(
                        pending["square.oauth_pending_refresh_token"] or None
                    ),
                    oauth_token_expires_at=(
                        pending["square.oauth_pending_expires_at"] or ""
                    ),
                    clear_oauth_pending=True,
                    expected_oauth_authorization_revision=(
                        pending[
                            "square.oauth_pending_authorization_revision"
                        ]
                        or None
                    ),
                )
            except SquareAccountSwitchRequired as exc:
                store.delete_settings(*SQUARE_OAUTH_PENDING_SETTING_KEYS)
                raise HTTPException(
                    status_code=409,
                    detail="The Square account changed; connect again before confirming",
                ) from exc
            except SquareAccountChanged as exc:
                store.delete_settings(*SQUARE_OAUTH_PENDING_SETTING_KEYS)
                raise HTTPException(
                    status_code=409,
                    detail="The Square authorization changed; connect again",
                ) from exc
        return {
            "ok": True,
            "account_switched": configuration.switched,
            "account_revision": configuration.account_revision,
            "evidence_cleanup_pending": configuration.evidence_cleanup_pending,
        }

    @app.delete("/api/settings/square/oauth-switch")
    def cancel_square_oauth_switch(_=authed) -> dict:
        store.delete_settings(*SQUARE_OAUTH_PENDING_SETTING_KEYS)
        return {"ok": True}

    # -- cameras & mapping ------------------------------------------------------

    @app.get("/api/health/protect")
    def protect_health(_=authed) -> dict:
        """Live connectivity check so the UI can show a trustworthy indicator."""
        client = build_protect()
        if client is None:
            return {"configured": False, "ok": False, "detail": "Not configured"}
        try:
            cameras = client.get_cameras()
        except ProtectAuthError as exc:
            return {"configured": True, "ok": False, "detail": str(exc)}
        except ProtectError as exc:
            return {"configured": True, "ok": False, "detail": str(exc)}
        finally:
            client.close()
        return {
            "configured": True,
            "ok": True,
            "cameras": len(cameras),
            "detail": f"Connected — {len(cameras)} cameras",
        }

    @app.get("/api/cameras")
    def cameras(response: Response, _=authed) -> list[dict]:
        with store.integration_guard():
            return _cameras_locked(response)

    def _cameras_locked(response: Response) -> list[dict]:
        settings = store.get_settings(PROTECT_SETTING_KEYS)
        client = build_protect(settings)
        if client is None:
            raise HTTPException(status_code=409, detail="UniFi Protect is not configured")
        try:
            camera_rows, observed_console_id = client.get_cameras_with_console_identity()
        except ProtectError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        finally:
            client.close()
        current_identity = store.get_settings(
            (
                "protect.host",
                PROTECT_CONSOLE_ID_SETTING,
                PROTECT_CONSOLE_GENERATION_SETTING,
            )
        )
        if (
            current_identity["protect.host"] != settings["protect.host"]
            or current_identity[PROTECT_CONSOLE_GENERATION_SETTING]
            != settings[PROTECT_CONSOLE_GENERATION_SETTING]
            or current_identity[PROTECT_CONSOLE_ID_SETTING]
            != settings[PROTECT_CONSOLE_ID_SETTING]
        ):
            raise HTTPException(
                status_code=409,
                detail="Protect console changed while cameras were loading; reload settings",
            )
        if (
            settings[PROTECT_CONSOLE_ID_SETTING] is not None
            and observed_console_id != settings[PROTECT_CONSOLE_ID_SETTING]
        ):
            raise HTTPException(
                status_code=409,
                detail="Protect console identity changed; reconnect Protect before loading cameras",
            )
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["X-Protect-Console-Generation"] = (
            settings[PROTECT_CONSOLE_GENERATION_SETTING] or ""
        )
        return camera_rows

    @app.get("/api/health/square")
    def square_health(_=authed) -> dict:
        """Live connectivity check so the UI can show a trustworthy indicator."""
        client = build_square()
        if client is None:
            return {"configured": False, "ok": False, "detail": "Not configured"}
        try:
            locations = client.list_locations()
        except SquareAuthError as exc:
            return {"configured": True, "ok": False, "detail": str(exc)}
        except SquareError as exc:
            return {"configured": True, "ok": False, "detail": str(exc)}
        finally:
            client.close()
        return {
            "configured": True,
            "ok": True,
            "locations": len(locations),
            "detail": f"Connected — {len(locations)} location(s)",
        }

    @app.get("/api/locations")
    def locations(response: Response, _=authed) -> list[dict]:
        with square_account_lock, store.integration_guard():
            client = require_square()
            try:
                result = client.list_locations()
                # Location IDs and the account revision form one account-bound
                # mapping snapshot and must never be replayed from a cache.
                response.headers["Cache-Control"] = "private, no-store"
                account_revision = store.square_account_revision()
                if account_revision:
                    response.headers["X-Square-Account-Revision"] = account_revision
                return result
            except SquareError as exc:
                raise HTTPException(status_code=502, detail=str(exc))
            finally:
                client.close()

    @app.get("/api/pos-devices")
    def pos_devices(_=authed) -> JSONResponse:
        with store.integration_guard():
            return JSONResponse(
                store.get_observed_devices(),
                headers={"Cache-Control": "private, no-store"},
            )

    @app.get("/api/camera-preview/{camera_id}")
    def camera_preview(camera_id: str, _=authed) -> Response:
        try:
            camera_id = validate_camera_id(camera_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        with store.integration_guard():
            return _camera_preview_locked(camera_id)

    def _camera_preview_locked(camera_id: str) -> Response:
        protect_settings = store.get_settings(PROTECT_SETTING_KEYS)
        client = build_protect(protect_settings)
        if client is None:
            raise HTTPException(status_code=409, detail="UniFi Protect is not configured")
        try:
            verify_protect_console_identity(client, protect_settings)
            image = client.get_snapshot(camera_id)
        except ProtectError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        finally:
            client.close()
        return Response(
            content=image,
            media_type="image/jpeg",
            headers={"Cache-Control": PRIVATE_NO_STORE},
        )

    @app.get("/api/camera-mapping")
    def get_mapping(_=authed) -> JSONResponse:
        with store.integration_guard():
            protect_generation = store.get_setting(
                PROTECT_CONSOLE_GENERATION_SETTING
            )
            square_account_revision = store.square_account_revision()
            return JSONResponse(
                store.get_camera_mappings(),
                headers={
                    "Cache-Control": "private, no-store",
                    "X-Protect-Console-Generation": protect_generation or "",
                    "X-Square-Account-Revision": square_account_revision or "",
                },
            )

    @app.put("/api/camera-mapping")
    def set_mapping(request: Request, body: CameraMappingBody, _=authed) -> dict:
        account_revision = request.headers.get("x-square-account-revision")
        if not account_revision:
            raise HTTPException(
                status_code=409,
                detail="Reload settings before saving camera mappings",
            )
        expected_generation = request.headers.get("x-protect-console-generation")
        if not expected_generation:
            if account_revision != store.square_account_revision():
                raise HTTPException(
                    status_code=409,
                    detail="Square account changed; reload settings",
                )
            raise HTTPException(
                status_code=428,
                detail="Reload cameras before saving camera mappings",
            )
        if len(body.mappings) > MAX_CAMERA_MAPPINGS:
            raise HTTPException(
                status_code=422,
                detail=f"Camera mappings cannot exceed {MAX_CAMERA_MAPPINGS} entries",
            )
        targets: set[tuple[str, str]] = set()
        for entry in body.mappings:
            target = (entry.location_id, entry.device_id)
            if target in targets:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "Duplicate camera mapping for the same location_id and "
                        "device_id"
                    ),
                )
            targets.add(target)
            try:
                validate_camera_id(entry.camera_id)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        try:
            store.replace_camera_mappings(
                [
                    (
                        entry.location_id,
                        entry.device_id,
                        entry.device_name,
                        entry.camera_id,
                        entry.camera_name,
                    )
                    for entry in body.mappings
                ],
                expected_account_revision=account_revision,
                expected_protect_generation=expected_generation,
            )
        except SquareAccountChanged as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ProtectSettingsConflict as exc:
            raise HTTPException(status_code=409, detail=f"{exc}; reload settings")
        nudge_protect_work_queue()
        return {"ok": True, "count": len(body.mappings)}

    # -- transactions -------------------------------------------------------------

    def txn_response(txn: dict) -> dict:
        host = store.get_setting("protect.host")
        link = None
        if host and txn.get("camera_id"):
            try:
                link = deeplink.build_deep_link(
                    host,
                    txn["camera_id"],
                    txn["ts_ms"],
                    template=store.get_setting("deep_link_template"),
                )
            except ValueError:
                link = None
        if txn.get("thumbnail_path"):
            thumbnail_status = "ready"
        elif not txn.get("camera_id"):
            thumbnail_status = "unmapped"
        elif int(txn.get("thumbnail_retry_attempts", 0)) > 0:
            thumbnail_status = "retrying"
        else:
            thumbnail_status = "queued"
        return {
            "id": txn["id"],
            "created_at": txn["created_at"],
            "ts_ms": txn["ts_ms"],
            "amount": txn["amount"],
            "currency": txn["currency"],
            "refunded_amount": txn["refunded_amount"],
            "status": txn["status"],
            "location_id": txn["location_id"],
            "device_id": txn.get("device_id", ""),
            "device_name": txn.get("device_name", ""),
            "card_last4": txn["card_last4"],
            "receipt_url": txn["receipt_url"],
            "camera_id": txn.get("camera_id"),
            "deep_link": link,
            "thumbnail_url": (
                f"/api/thumbnails/{txn['id']}" if txn.get("thumbnail_path") else None
            ),
            "thumbnail_status": thumbnail_status,
            "thumbnail_retry_attempts": int(
                txn.get("thumbnail_retry_attempts", 0)
            ),
        }

    @app.get("/api/dashboard")
    def dashboard(_=authed) -> dict:
        """Live status tiles: connections, webhook freshness, queue depths."""
        protect: dict = {"configured": False, "ok": False, "detail": "Not configured"}
        client = build_protect()
        if client is not None:
            try:
                cameras = client.get_cameras()
                protect = {
                    "configured": True,
                    "ok": True,
                    "detail": f"Connected — {len(cameras)} cameras",
                }
            except ProtectAuthError as exc:
                protect = {"configured": True, "ok": False, "detail": str(exc)}
            except ProtectError as exc:
                protect = {"configured": True, "ok": False, "detail": str(exc)}
            finally:
                client.close()

        square: dict = {"configured": False, "ok": False, "detail": "Not configured"}
        square_client = build_square()
        if square_client is not None:
            try:
                locations = square_client.list_locations()
                square = {
                    "configured": True,
                    "ok": True,
                    "detail": f"Connected — {len(locations)} location(s)",
                }
            except SquareAuthError as exc:
                square = {"configured": True, "ok": False, "detail": str(exc)}
            except SquareError as exc:
                square = {"configured": True, "ok": False, "detail": str(exc)}
            finally:
                square_client.close()

        webhook_settings = store.get_settings(
            ("square.webhook_signature_key", "webhook.last_event_ms")
        )
        last_event_ms = None
        raw_last = webhook_settings["webhook.last_event_ms"]
        if raw_last:
            try:
                last_event_ms = int(raw_last)
            except ValueError:
                last_event_ms = None
        webhook = {
            "configured": bool(webhook_settings["square.webhook_signature_key"]),
            "last_event_ms": last_event_ms,
        }

        queues = store.queue_depths()
        if not store.get_setting("protect.alarm_trigger_id"):
            # Idle alarm states are meaningless while the feature is off.
            queues["alarms_pending"] = 0
        return {
            "protect": protect,
            "square": square,
            "webhook": webhook,
            "queues": queues,
        }

    @app.get("/api/transactions/export.csv")
    def export_transactions(_=authed) -> Response:
        with store.integration_guard():
            transactions = store.list_transaction_export_facts()
            protect_settings = store.get_settings(
                ("protect.host", "deep_link_template")
            )
            host = protect_settings["protect.host"]
            template = protect_settings["deep_link_template"]
            output = io.StringIO(newline="")
            writer = csv.writer(output, lineterminator="\r\n")
            writer.writerow(TRANSACTION_EXPORT_HEADERS)
            for transaction in transactions:
                timeline_url = ""
                if host and transaction.get("camera_id"):
                    try:
                        timeline_url = deeplink.build_deep_link(
                            host,
                            transaction["camera_id"],
                            transaction["ts_ms"],
                            template=template,
                        )
                    except ValueError:
                        timeline_url = ""
                writer.writerow(
                    (
                        _safe_csv_cell(transaction["id"]),
                        _safe_csv_cell(transaction["created_at"]),
                        transaction["amount"],
                        _safe_csv_cell(transaction["currency"]),
                        _safe_csv_cell(transaction["status"]),
                        _safe_csv_cell(transaction["location_id"]),
                        _safe_csv_cell(transaction["device_id"]),
                        _safe_csv_cell(transaction["device_name"]),
                        _safe_csv_cell(transaction["card_last4"]),
                        _safe_csv_cell(transaction["receipt_url"]),
                        _safe_csv_cell(timeline_url),
                    )
                )
            # Build the complete body before releasing the provider-state guard;
            # streaming it later could mix old evidence with a new console URL.
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={
                    "Cache-Control": PRIVATE_NO_STORE,
                    "Content-Disposition": (
                        'attachment; filename="square-protect-transactions.csv"'
                    ),
                },
            )

    def transaction_listing(body: TransactionQueryBody) -> JSONResponse:
        query = body.q
        if any(
            ord(character) < 32 or ord(character) == 127 for character in query
        ):
            raise HTTPException(
                status_code=422,
                detail="Search query cannot contain control characters",
            )
        query = query.strip()
        with store.integration_guard():
            try:
                rows, transaction_snapshot = store.list_transactions_page(
                    body.limit,
                    body.offset,
                    body.snapshot,
                    query=query,
                    status=body.status or "",
                )
            except TransactionSnapshotFilterMismatch as exc:
                raise HTTPException(
                    status_code=409,
                    detail="Transaction filters changed; return to the newest page",
                ) from exc
            except TransactionSnapshotExpired as exc:
                raise HTTPException(
                    status_code=409,
                    detail="Transaction page expired; return to the newest page",
                ) from exc
            # Render the account-bound payload while the shared guard is held,
            # so an acknowledged switch cannot bisect the read and encoding.
            return JSONResponse(
                [txn_response(t) for t in rows],
                headers={
                    "X-Transaction-Snapshot": str(transaction_snapshot),
                    "Cache-Control": PRIVATE_NO_STORE,
                },
            )

    def require_transaction_query_transport(request: Request) -> None:
        if request.query_params:
            raise HTTPException(
                status_code=422,
                detail="Transaction read parameters must be sent in the JSON body",
            )
        media_type = request.headers.get("content-type", "").split(";", 1)[0]
        media_type = media_type.strip().lower()
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise HTTPException(
                status_code=415,
                detail="Transaction reads require an application/json body",
            )

    async def read_transaction_query_body(request: Request) -> TransactionQueryBody:
        """Read and validate the small query payload after route dependencies run."""
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid transaction query Content-Length",
                ) from exc
            if declared_length < 0:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid transaction query Content-Length",
                )
            if declared_length > TRANSACTION_QUERY_MAX_BODY_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Transaction query payload too large",
                )

        payload = bytearray()
        async for chunk in request.stream():
            if len(payload) + len(chunk) > TRANSACTION_QUERY_MAX_BODY_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Transaction query payload too large",
                )
            payload.extend(chunk)

        try:
            return TransactionQueryBody.model_validate_json(bytes(payload))
        except ValidationError as exc:
            errors = []
            for error in exc.errors(include_url=False):
                body_error = dict(error)
                body_error["loc"] = ("body", *error.get("loc", ()))
                body_error.pop("input", None)
                errors.append(body_error)
            raise RequestValidationError(errors) from None

    @app.get("/api/transactions")
    def legacy_transactions(request: Request, _=authed) -> JSONResponse:
        """Compatibility read without filters or paging parameters."""
        if request.query_params:
            raise HTTPException(
                status_code=422,
                detail="Transaction read parameters must be sent in a POST JSON body",
            )
        return transaction_listing(TransactionQueryBody())

    @app.post("/api/transactions")
    async def transactions(
        request: Request,
        _=authed,
        __=Depends(require_transaction_query_transport),
    ) -> JSONResponse:
        body = await read_transaction_query_body(request)
        return await run_in_threadpool(transaction_listing, body)

    @app.get("/api/thumbnails/{txn_id}")
    def thumbnail(txn_id: str, _=authed) -> Response:
        with store.integration_guard():
            txn = store.get_transaction(txn_id)
            if not txn or not txn.get("thumbnail_path"):
                raise HTTPException(
                    status_code=404, detail="No thumbnail for this transaction"
                )
            path = (store.thumbnail_dir / txn["thumbnail_path"]).resolve()

            def missing_thumbnail() -> None:
                if store.requeue_missing_thumbnail(txn_id, txn["thumbnail_path"]):
                    nudge_protect_work_queue()
                raise HTTPException(status_code=404, detail="Thumbnail not found")

            if (
                store.thumbnail_dir.resolve() not in path.parents
                or not path.is_file()
            ):
                missing_thumbnail()
            try:
                image = _read_thumbnail_bytes(path)
            except OSError:
                # The file can disappear or be atomically replaced after
                # is_file(). Reconcile the durable reference instead of letting
                # a lazy response fail after headers have been sent.
                missing_thumbnail()
            return Response(
                content=image,
                media_type="image/jpeg",
                headers={"Cache-Control": PRIVATE_NO_STORE},
            )

    def run_sync() -> int:
        with square_account_lock:
            # Sync passes an account-fenced settings snapshot to build_square,
            # so refresh the OAuth grant before taking that snapshot. Otherwise
            # unattended/manual sync is the one Square path that never renews
            # an expiring token.
            _maybe_refresh_oauth_token()
            try:
                store.retry_orphan_thumbnail_cleanup()
            except Exception as exc:
                logger.warning("Could not retry orphan thumbnail cleanup: %s", exc)
            with store.integration_guard():
                square_settings = store.get_settings(SQUARE_CLIENT_SETTING_KEYS)
                square = build_square(square_settings)
                if square is None:
                    return 0
                protect_settings = store.get_settings(PROTECT_SETTING_KEYS)
                protect = build_protect(protect_settings)
                try:
                    if protect:
                        try:
                            verify_protect_console_identity(
                                protect, protect_settings
                            )
                        except ProtectConsoleIdentityMismatch:
                            raise
                        except (ProtectError, OSError) as exc:
                            # A Protect outage must not block Square ingestion:
                            # ingest payment facts now and let the durable
                            # retry queue capture camera evidence later. Only a
                            # positively observed identity mismatch hard-fails.
                            logger.warning(
                                "Protect unreachable during sync; "
                                "deferring camera evidence: %s",
                                exc,
                            )
                            protect.close()
                            protect = None
                    return sync.sync_payments(
                        store,
                        square,
                        protect,
                        alarm_trigger_id=protect_settings["protect.alarm_trigger_id"],
                        expected_merchant_id=square_settings["square.merchant_id"],
                        expected_environment=square_settings["square.environment"],
                        expected_account_revision=(
                            square_settings["square.account_revision"]
                        ),
                    )
                finally:
                    square.close()
                    if protect:
                        protect.close()

    @app.post("/api/sync")
    def manual_sync(_=authed) -> dict:
        try:
            return {"ok": True, "ingested": run_sync()}
        except (SquareError, ProtectError) as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        except SquareAccountChanged as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    # -- Square webhook (unauthenticated; HMAC-verified) ---------------------------

    async def read_square_webhook_body(request: Request) -> bytes:
        """Read exact HMAC input while enforcing the 1 MiB webhook limit."""
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid Content-Length",
                    headers={"Cache-Control": PRIVATE_NO_STORE},
                )
            if declared_length < 0:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid Content-Length",
                    headers={"Cache-Control": PRIVATE_NO_STORE},
                )
            if declared_length > SQUARE_WEBHOOK_MAX_BODY_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Webhook payload too large",
                    headers={"Cache-Control": PRIVATE_NO_STORE},
                )

        body = bytearray()
        received = 0
        async for chunk in request.stream():
            if len(chunk) > SQUARE_WEBHOOK_MAX_BODY_BYTES - received:
                raise HTTPException(
                    status_code=413,
                    detail="Webhook payload too large",
                    headers={"Cache-Control": PRIVATE_NO_STORE},
                )
            body.extend(chunk)
            received += len(chunk)
        return bytes(body)

    def process_square_webhook(body: bytes, signature: str) -> dict | None:
        """Verify and ingest against one current account/settings snapshot."""
        with store.integration_guard():
            square_settings = store.get_settings(
                (
                    "square.webhook_signature_key",
                    "square.webhook_url",
                    "square.merchant_id",
                    "square.environment",
                    "square.account_revision",
                )
            )
            signature_key = square_settings["square.webhook_signature_key"]
            webhook_url = square_settings["square.webhook_url"]
            if not signature_key or not webhook_url:
                raise HTTPException(status_code=403, detail="Webhook not configured")
            if not verify_webhook_signature(
                signature_key, webhook_url, body, signature
            ):
                raise HTTPException(status_code=401, detail="Invalid webhook signature")
            # Every validly signed delivery counts as webhook liveness for the
            # dashboard tile, including events ignored below.
            store.set_setting("webhook.last_event_ms", str(int(time.time() * 1000)))
            try:
                event = json.loads(body)
            except ValueError as exc:
                raise HTTPException(
                    status_code=422, detail="Invalid JSON payload"
                ) from exc
            if (
                not isinstance(event, dict)
                or not square_settings["square.merchant_id"]
                or event.get("merchant_id")
                != square_settings["square.merchant_id"]
            ):
                return None
            event_data = event.get("data")
            event_object = (
                event_data.get("object")
                if isinstance(event_data, dict)
                else None
            )
            payment = (
                event_object.get("payment")
                if isinstance(event_object, dict)
                else None
            )
            if not isinstance(payment, dict) or not payment:
                return None
            return sync.ingest_payment(
                store,
                payment,
                None,
                expected_merchant_id=square_settings["square.merchant_id"],
                expected_environment=(
                    square_settings["square.environment"] or "production"
                ),
                expected_account_revision=(
                    square_settings["square.account_revision"]
                ),
            )

    @app.post("/webhooks/square")
    async def square_webhook(request: Request) -> JSONResponse:
        body = await read_square_webhook_body(request)
        signature = request.headers.get("x-square-hmacsha256-signature", "")
        try:
            txn = await run_in_threadpool(
                process_square_webhook, body, signature
            )
        except SquareAccountChanged:
            # A verified event can race an explicitly confirmed account
            # switch. Treat the stale merchant's event as acknowledged but
            # never let it repopulate the new account.
            return JSONResponse({"ok": True, "ignored": True})
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if txn is None:
            return JSONResponse({"ok": True, "ignored": True})
        # Both alarm delivery and thumbnail capture are durable queue work;
        # the drain no-ops cheaply when neither has anything pending.
        nudge_protect_work_queue()
        return JSONResponse({"ok": True})

    # -- static frontend ---------------------------------------------------------

    static_dir = Path(__file__).parent / "static"
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    # -- background poller ---------------------------------------------------------

    poller: sync.Poller | None = None
    if poll_interval is not None:
        poller = sync.Poller(run_sync, interval_seconds=poll_interval)
        app.state.poller = poller

        @app.on_event("startup")
        def _start_poller() -> None:
            poller.start()

    @app.on_event("shutdown")
    def _shutdown_background_work() -> None:
        # FastAPI runs shutdown handlers in registration order. Keep this as
        # one ordered lifecycle so no worker can touch a closed dependency.
        if poller is not None:
            poller.stop()
        thumbnail_executor.shutdown(wait=True, cancel_futures=True)
        store.close()

    return app


def app() -> FastAPI:  # uvicorn factory entry point: `uvicorn app.main:app --factory`
    return create_app(
        bind_host=os.environ.get("SPI_HOST"),
        # A raw Uvicorn factory invocation does not install app.tls settings.
        tls_enabled=False,
    )
