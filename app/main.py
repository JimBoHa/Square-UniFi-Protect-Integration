"""FastAPI application wiring the Square and UniFi Protect integrations together."""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import deeplink, sync
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
    SquareClient,
    SquareError,
    SquarePermissionError,
    verify_webhook_signature,
)
from .store import ALARM_ENABLED_AFTER_SETTING, Store, TransactionSnapshotExpired

logger = logging.getLogger("spi")

SESSION_COOKIE = "spi_session"
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60
SQUARE_WEBHOOK_MAX_BODY_BYTES = 1024 * 1024
LOGIN_FAILURE_KEY_LIMIT = 10_000
DRAIN_MAX_BATCHES = 100
PROTECT_SETTING_KEYS = (
    "protect.host",
    "protect.username",
    "protect.password",
    "protect.verify_ssl",
    "protect.api_key",
    "protect.alarm_trigger_id",
)
MAX_CAMERA_MAPPINGS = 500
PRIVATE_NO_STORE = "private, no-store"
MIN_POLL_INTERVAL_SECONDS = 1.0


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

class SquareSettingsBody(BaseModel):
    access_token: str
    environment: str = "production"
    webhook_signature_key: str = ""
    webhook_url: str = ""
    clear_webhook: bool = False

class CameraMappingEntry(BaseModel):
    location_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(default="", max_length=255)
    device_name: str = Field(default="", max_length=255)
    camera_id: str = Field(min_length=1, max_length=64)
    camera_name: str = Field(default="", max_length=128)

class CameraMappingBody(BaseModel):
    mappings: list[CameraMappingEntry]

class DeepLinkSettingsBody(BaseModel):
    template: str = Field(default="", max_length=2048)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    data_dir: str | Path | None = None,
    protect_transport=None,
    square_transport=None,
    enable_poller: bool | None = None,
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

    @app.middleware("http")
    async def apply_api_cache_policy(request: Request, call_next):
        # Every API response can carry account or evidence data; keep all of it
        # out of browser and intermediary caches. Routes may still set their
        # own policy, which wins.
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", PRIVATE_NO_STORE)
        return response

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

    def build_square() -> SquareClient | None:
        settings = store.get_settings(
            ("square.access_token", "square.environment")
        )
        token = settings["square.access_token"]
        if not token:
            return None
        return SquareClient(
            token,
            environment=settings["square.environment"] or "production",
            transport=square_transport,
        )

    def drain_protect_work_queue() -> None:
        with drain_state_lock:
            app.state.thumbnail_drain_queued = False
        protect_settings = store.get_settings(PROTECT_SETTING_KEYS)
        protect = build_protect(protect_settings)
        if protect is None:
            return
        try:
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

    @app.on_event("shutdown")
    def _shutdown_thumbnail_executor() -> None:
        thumbnail_executor.shutdown(wait=True, cancel_futures=True)

    def require_protect() -> ProtectClient:
        client = build_protect()
        if client is None:
            raise HTTPException(status_code=409, detail="UniFi Protect is not configured")
        return client

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
    def setup(body: SetupBody) -> dict:
        if store.get_setting("admin.password_hash") is not None:
            raise HTTPException(status_code=409, detail="Setup already completed")
        password_hash = hash_password(body.password)
        if not store.set_setting_if_absent("admin.password_hash", password_hash):
            raise HTTPException(status_code=409, detail="Setup already completed")
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

    @app.put("/api/settings/protect")
    def set_protect(body: ProtectSettingsBody, _=authed) -> dict:
        if body.disable_alarm:
            return {
                **clear_protect_alarm_settings(),
                "cameras": None,
            }
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
        stored_alarm_settings = store.get_settings(
            ("protect.api_key", "protect.alarm_trigger_id")
        )
        stored_api_key = stored_alarm_settings["protect.api_key"]
        stored_trigger_id = stored_alarm_settings["protect.alarm_trigger_id"]
        effective_api_key = submitted_api_key or stored_api_key
        effective_trigger_id = submitted_trigger_id or stored_trigger_id
        if effective_trigger_id and not effective_api_key:
            raise HTTPException(
                status_code=422,
                detail="Protect API key is required when an alarm trigger id is set",
            )
        client = ProtectClient(
            host,
            body.username,
            body.password,
            verify_ssl=body.verify_ssl,
            transport=protect_transport,
            api_key=effective_api_key,
        )
        try:
            client.login()
            cameras = client.get_cameras()
            if effective_api_key:
                client.get_integration_info()
        except ProtectAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except (ProtectError, OSError) as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach UniFi Protect: {exc}")
        finally:
            client.close()
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
        store.update_settings(
            settings_updates,
            activate_alarm_at_ms=(
                int(time.time() * 1000) if alarm_is_configured else None
            ),
        )
        return {
            "ok": True,
            "cameras": len(cameras),
            "alarm_configured": alarm_is_configured,
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
        settings_updates = {
            "square.access_token": (body.access_token, True),
            "square.environment": (body.environment, False),
            "square.merchant_id": (merchant_id, False),
        }
        delete_keys = ()
        if body.webhook_signature_key and body.webhook_url:
            settings_updates.update(
                {
                    "square.webhook_signature_key": (
                        body.webhook_signature_key,
                        True,
                    ),
                    "square.webhook_url": (body.webhook_url, False),
                }
            )
        elif body.clear_webhook:
            delete_keys = (
                "square.webhook_signature_key", "square.webhook_url"
            )
        store.update_settings(settings_updates, delete_keys=delete_keys)
        # Blank webhook fields without clear_webhook leave any stored webhook
        # configuration untouched, so re-saving the access token is safe.
        return {"ok": True, "locations": locations}

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
    def cameras(_=authed) -> list[dict]:
        client = require_protect()
        try:
            return client.get_cameras()
        except ProtectError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        finally:
            client.close()

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
    def locations(_=authed) -> list[dict]:
        client = require_square()
        try:
            return client.list_locations()
        except SquareError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        finally:
            client.close()

    @app.get("/api/pos-devices")
    def pos_devices(_=authed) -> list[dict]:
        return store.get_observed_devices()

    @app.get("/api/camera-preview/{camera_id}")
    def camera_preview(camera_id: str, _=authed) -> Response:
        try:
            camera_id = validate_camera_id(camera_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        client = require_protect()
        try:
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
    def get_mapping(_=authed) -> list[dict]:
        return store.get_camera_mappings()

    @app.put("/api/camera-mapping")
    def set_mapping(body: CameraMappingBody, _=authed) -> dict:
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
            ]
        )
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

    @app.get("/api/transactions")
    def transactions(
        response: Response,
        limit: int = 50,
        offset: int = 0,
        snapshot: int | None = None,
        _=authed,
    ) -> list[dict]:
        try:
            rows, transaction_snapshot = store.list_transactions_page(
                limit, offset, snapshot
            )
        except TransactionSnapshotExpired as exc:
            raise HTTPException(
                status_code=409,
                detail="Transaction page expired; return to the newest page",
            ) from exc
        response.headers["Cache-Control"] = PRIVATE_NO_STORE
        # Preserve the existing list response while issuing an optional
        # durable ordering token for clients that paginate across live writes.
        response.headers["X-Transaction-Snapshot"] = str(transaction_snapshot)
        return [txn_response(t) for t in rows]

    @app.get("/api/thumbnails/{txn_id}")
    def thumbnail(txn_id: str, _=authed) -> Response:
        txn = store.get_transaction(txn_id)
        if not txn or not txn.get("thumbnail_path"):
            raise HTTPException(status_code=404, detail="No thumbnail for this transaction")
        path = (store.thumbnail_dir / txn["thumbnail_path"]).resolve()

        def missing_thumbnail() -> None:
            if store.requeue_missing_thumbnail(txn_id, txn["thumbnail_path"]):
                nudge_protect_work_queue()
            raise HTTPException(status_code=404, detail="Thumbnail not found")

        if store.thumbnail_dir.resolve() not in path.parents or not path.is_file():
            missing_thumbnail()
        try:
            image = _read_thumbnail_bytes(path)
        except OSError:
            # The file can disappear or be atomically replaced after is_file().
            # Reconcile the durable reference instead of letting a lazy response
            # fail after headers have already been sent.
            missing_thumbnail()
        return Response(
            content=image,
            media_type="image/jpeg",
            headers={"Cache-Control": PRIVATE_NO_STORE},
        )

    def run_sync() -> int:
        square = build_square()
        if square is None:
            return 0
        protect_settings = store.get_settings(PROTECT_SETTING_KEYS)
        protect = build_protect(protect_settings)
        try:
            return sync.sync_payments(
                store,
                square,
                protect,
                alarm_trigger_id=protect_settings["protect.alarm_trigger_id"],
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

    # -- Square webhook (unauthenticated; HMAC-verified) ---------------------------

    async def read_square_webhook_body(request: Request) -> bytes:
        """Read exact HMAC input while enforcing the 1 MiB webhook limit."""
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid Content-Length")
            if declared_length < 0:
                raise HTTPException(status_code=400, detail="Invalid Content-Length")
            if declared_length > SQUARE_WEBHOOK_MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Webhook payload too large")

        chunks: list[bytes] = []
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > SQUARE_WEBHOOK_MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Webhook payload too large")
            chunks.append(chunk)
        return b"".join(chunks)

    @app.post("/webhooks/square")
    async def square_webhook(request: Request) -> JSONResponse:
        square_settings = store.get_settings(
            (
                "square.webhook_signature_key",
                "square.webhook_url",
                "square.merchant_id",
            )
        )
        signature_key = square_settings["square.webhook_signature_key"]
        webhook_url = square_settings["square.webhook_url"]
        if not signature_key or not webhook_url:
            raise HTTPException(status_code=403, detail="Webhook not configured")
        body = await read_square_webhook_body(request)
        signature = request.headers.get("x-square-hmacsha256-signature", "")
        if not verify_webhook_signature(signature_key, webhook_url, body, signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
        store.set_setting("webhook.last_event_ms", str(int(time.time() * 1000)))
        import json as _json

        try:
            event = _json.loads(body)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid JSON payload")
        if (
            not isinstance(event, dict)
            or not square_settings["square.merchant_id"]
            or event.get("merchant_id") != square_settings["square.merchant_id"]
        ):
            return JSONResponse({"ok": True, "ignored": True})
        event_data = event.get("data")
        event_object = (
            event_data.get("object") if isinstance(event_data, dict) else None
        )
        payment = (
            event_object.get("payment")
            if isinstance(event_object, dict)
            else None
        )
        if not isinstance(payment, dict) or not payment:
            return JSONResponse({"ok": True, "ignored": True})
        try:
            txn = await run_in_threadpool(sync.ingest_payment, store, payment, None)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        # Both alarm delivery and thumbnail capture are durable queue work;
        # the drain no-ops cheaply when neither has anything pending.
        nudge_protect_work_queue()
        return JSONResponse({"ok": True})

    # -- static frontend ---------------------------------------------------------

    static_dir = Path(__file__).parent / "static"
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    # -- background poller ---------------------------------------------------------

    if poll_interval is not None:
        poller = sync.Poller(run_sync, interval_seconds=poll_interval)
        app.state.poller = poller

        @app.on_event("startup")
        def _start_poller() -> None:
            poller.start()

        @app.on_event("shutdown")
        def _stop_poller() -> None:
            poller.stop()

    return app


def app() -> FastAPI:  # uvicorn factory entry point: `uvicorn app.main:app --factory`
    return create_app()
