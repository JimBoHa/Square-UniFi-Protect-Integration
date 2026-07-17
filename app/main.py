"""FastAPI application wiring the Square and UniFi Protect integrations together."""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
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
from .store import (
    ALARM_ENABLED_AFTER_SETTING,
    PROTECT_CONSOLE_ID_SETTING,
    PROTECT_CONSOLE_GENERATION_SETTING,
    ProtectConsoleSwitchConfirmationRequired,
    ProtectSettingsConflict,
    SquareAccountChanged,
    SquareAccountSwitchRequired,
    Store,
)

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

class CameraMappingBody(BaseModel):
    mappings: list[CameraMappingEntry]


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    data_dir: str | Path | None = None,
    protect_transport=None,
    square_transport=None,
    enable_poller: bool | None = None,
) -> FastAPI:
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
    if enable_poller is None:
        enable_poller = os.environ.get("SPI_DISABLE_POLLER", "0") != "1"

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

    def build_square(
        settings: dict[str, str | None] | None = None,
    ) -> SquareClient | None:
        settings = settings or store.get_settings(SQUARE_CLIENT_SETTING_KEYS)
        token = settings["square.access_token"]
        if not token:
            return None
        return SquareClient(
            token,
            environment=settings["square.environment"] or "production",
            transport=square_transport,
        )

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
            raise ProtectError(
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

    @app.on_event("shutdown")
    def _shutdown_thumbnail_executor() -> None:
        thumbnail_executor.shutdown(wait=True, cancel_futures=True)

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
            if console_switch_requested:
                with store.integration_guard(exclusive=True):
                    console_switched = commit_protect_settings()
            else:
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
        client = SquareClient(
            body.access_token, environment=body.environment, transport=square_transport
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

    # -- cameras & mapping ------------------------------------------------------

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
        return Response(content=image, media_type="image/jpeg")

    @app.get("/api/camera-mapping")
    def get_mapping(_=authed) -> JSONResponse:
        with store.integration_guard():
            return JSONResponse(
                store.get_camera_mappings(),
                headers={"Cache-Control": "private, no-store"},
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
        }

    @app.get("/api/transactions")
    def transactions(
        limit: int = 50,
        offset: int = 0,
        snapshot: int | None = None,
        _=authed,
    ) -> JSONResponse:
        with store.integration_guard():
            rows, snapshot_rowid = store.list_transactions_page(
                limit, offset, snapshot
            )
            # Render the account-bound payload while the shared guard is held,
            # so an acknowledged switch cannot bisect the read and encoding.
            return JSONResponse(
                [txn_response(t) for t in rows],
                headers={
                    "X-Transaction-Snapshot": str(snapshot_rowid),
                    "Cache-Control": "private, no-store",
                },
            )

    @app.get("/api/thumbnails/{txn_id}")
    def thumbnail(txn_id: str, _=authed) -> FileResponse:
        with store.integration_guard():
            txn = store.get_transaction(txn_id)
            if not txn or not txn.get("thumbnail_path"):
                raise HTTPException(
                    status_code=404, detail="No thumbnail for this transaction"
                )
            path = (store.thumbnail_dir / txn["thumbnail_path"]).resolve()
            if (
                store.thumbnail_dir.resolve() not in path.parents
                or not path.is_file()
            ):
                if store.requeue_missing_thumbnail(
                    txn_id, txn["thumbnail_path"]
                ):
                    nudge_protect_work_queue()
                raise HTTPException(status_code=404, detail="Thumbnail not found")
            return FileResponse(
                path,
                media_type="image/jpeg",
                headers={"Cache-Control": "private, no-store"},
            )

    def run_sync() -> int:
        with square_account_lock:
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
                        verify_protect_console_identity(protect, protect_settings)
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

    def ingest_square_webhook_payment(
        payment: dict,
        expected_merchant_id: str,
        expected_environment: str,
        expected_account_revision: str | None,
    ) -> dict:
        with store.integration_guard():
            return sync.ingest_payment(
                store,
                payment,
                None,
                expected_merchant_id=expected_merchant_id,
                expected_environment=expected_environment,
                expected_account_revision=expected_account_revision,
            )

    @app.post("/webhooks/square")
    async def square_webhook(request: Request) -> JSONResponse:
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
        body = await read_square_webhook_body(request)
        signature = request.headers.get("x-square-hmacsha256-signature", "")
        if not verify_webhook_signature(signature_key, webhook_url, body, signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
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
            txn = await run_in_threadpool(
                ingest_square_webhook_payment,
                payment,
                square_settings["square.merchant_id"],
                square_settings["square.environment"] or "production",
                square_settings["square.account_revision"],
            )
        except SquareAccountChanged:
            # A verified event can race an explicitly confirmed account
            # switch. Treat the stale merchant's event as acknowledged but
            # never let it repopulate the new account.
            return JSONResponse({"ok": True, "ignored": True})
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

    if enable_poller:
        interval = float(os.environ.get("SPI_POLL_INTERVAL", "60"))
        poller = sync.Poller(run_sync, interval_seconds=interval)
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
