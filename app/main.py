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
    verify_webhook_signature,
)
from .store import Store

logger = logging.getLogger("spi")

SESSION_COOKIE = "spi_session"
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60
WEBHOOK_THUMBNAIL_WORKERS = 2
WEBHOOK_THUMBNAIL_MAX_PENDING = 32
PROTECT_SETTING_KEYS = (
    "protect.host",
    "protect.username",
    "protect.password",
    "protect.verify_ssl",
    "protect.api_key",
    "protect.alarm_trigger_id",
)


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
    alarm_trigger_id: str = Field(default="", max_length=64)
    disable_alarm: bool = False

class SquareSettingsBody(BaseModel):
    access_token: str
    environment: str = "production"
    webhook_signature_key: str = ""
    webhook_url: str = ""

class CameraMappingEntry(BaseModel):
    location_id: str = Field(min_length=1, max_length=64)
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
    thumbnail_executor = ThreadPoolExecutor(
        max_workers=WEBHOOK_THUMBNAIL_WORKERS,
        thread_name_prefix="spi-webhook-thumbnail",
    )
    thumbnail_jobs: set[str] = set()
    thumbnail_jobs_lock = threading.Lock()
    app.state.thumbnail_executor = thumbnail_executor
    app.state.thumbnail_jobs = thumbnail_jobs

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

    def build_square() -> SquareClient | None:
        token = store.get_setting("square.access_token")
        if not token:
            return None
        return SquareClient(
            token,
            environment=store.get_setting("square.environment") or "production",
            transport=square_transport,
        )

    def enrich_webhook_thumbnail(txn_id: str) -> None:
        protect = None
        try:
            txn = store.get_transaction(txn_id)
            if not txn or txn.get("thumbnail_path") or not txn.get("camera_id"):
                return
            protect = build_protect()
            if protect is not None:
                sync.enrich_transaction_thumbnail(store, txn_id, protect)
        except Exception:
            logger.exception("Webhook thumbnail enrichment failed for payment %s", txn_id)
        finally:
            if protect is not None:
                try:
                    protect.close()
                except Exception:
                    logger.exception("Could not close Protect client for payment %s", txn_id)

    def submit_thumbnail_enrichment(txn_id: str) -> None:
        with thumbnail_jobs_lock:
            if txn_id in thumbnail_jobs:
                return
            if len(thumbnail_jobs) >= WEBHOOK_THUMBNAIL_MAX_PENDING:
                logger.warning(
                    "Thumbnail queue full; deferring payment %s to later sync",
                    txn_id,
                )
                return
            thumbnail_jobs.add(txn_id)
        try:
            future = thumbnail_executor.submit(enrich_webhook_thumbnail, txn_id)
        except RuntimeError:
            with thumbnail_jobs_lock:
                thumbnail_jobs.discard(txn_id)
            logger.warning("Thumbnail executor unavailable for payment %s", txn_id)
            return

        def job_done(_future) -> None:
            with thumbnail_jobs_lock:
                thumbnail_jobs.discard(txn_id)

        future.add_done_callback(job_done)

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

    def check_login_throttle(request: Request) -> None:
        key = client_key(request)
        now = time.time()
        with app.state.login_lock:
            attempts = [
                t for t in app.state.login_failures.get(key, [])
                if now - t < LOGIN_LOCKOUT_SECONDS
            ]
            app.state.login_failures[key] = attempts
            if len(attempts) >= LOGIN_MAX_FAILURES:
                raise HTTPException(
                    status_code=429,
                    detail="Too many failed login attempts; try again shortly",
                )

    def record_login_failure(request: Request) -> None:
        with app.state.login_lock:
            app.state.login_failures.setdefault(client_key(request), []).append(time.time())

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
        store.set_setting("admin.password_hash", hash_password(body.password))
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

    @app.put("/api/settings/protect")
    def set_protect(body: ProtectSettingsBody, _=authed) -> dict:
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
        alarm_was_configured = bool(stored_api_key and stored_trigger_id)
        if body.disable_alarm:
            effective_api_key = None
            effective_trigger_id = None
        else:
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
        delete_keys: tuple[str, ...] = ()
        if body.disable_alarm:
            delete_keys = ("protect.api_key", "protect.alarm_trigger_id")
        else:
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
            delete_keys=delete_keys,
            suppress_completed_alarms=(
                alarm_is_configured and not alarm_was_configured
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
        client = SquareClient(
            body.access_token, environment=body.environment, transport=square_transport
        )
        try:
            locations = client.list_locations()
        except SquareAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except (SquareError, OSError) as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach Square: {exc}")
        finally:
            client.close()
        store.set_setting("square.access_token", body.access_token, secret=True)
        store.set_setting("square.environment", body.environment)
        if body.webhook_signature_key:
            store.set_setting(
                "square.webhook_signature_key", body.webhook_signature_key, secret=True
            )
        if body.webhook_url:
            store.set_setting("square.webhook_url", body.webhook_url)
        return {"ok": True, "locations": locations}

    # -- cameras & mapping ------------------------------------------------------

    @app.get("/api/cameras")
    def cameras(_=authed) -> list[dict]:
        client = require_protect()
        try:
            return client.get_cameras()
        except ProtectError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        finally:
            client.close()

    @app.get("/api/locations")
    def locations(_=authed) -> list[dict]:
        client = require_square()
        try:
            return client.list_locations()
        except SquareError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        finally:
            client.close()

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
        return Response(content=image, media_type="image/jpeg")

    @app.get("/api/camera-mapping")
    def get_mapping(_=authed) -> list[dict]:
        return store.get_camera_mappings()

    @app.put("/api/camera-mapping")
    def set_mapping(body: CameraMappingBody, _=authed) -> dict:
        for entry in body.mappings:
            if entry.location_id != "*":
                try:
                    validate_camera_id(entry.camera_id)
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail=str(exc))
        store.clear_camera_mappings()
        for entry in body.mappings:
            store.set_camera_mapping(entry.location_id, entry.camera_id, entry.camera_name)
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
            "card_last4": txn["card_last4"],
            "receipt_url": txn["receipt_url"],
            "camera_id": txn.get("camera_id"),
            "deep_link": link,
            "thumbnail_url": (
                f"/api/thumbnails/{txn['id']}" if txn.get("thumbnail_path") else None
            ),
        }

    @app.get("/api/transactions")
    def transactions(limit: int = 50, offset: int = 0, _=authed) -> list[dict]:
        return [txn_response(t) for t in store.list_transactions(limit, offset)]

    @app.get("/api/thumbnails/{txn_id}")
    def thumbnail(txn_id: str, _=authed) -> FileResponse:
        txn = store.get_transaction(txn_id)
        if not txn or not txn.get("thumbnail_path"):
            raise HTTPException(status_code=404, detail="No thumbnail for this transaction")
        path = (store.thumbnail_dir / txn["thumbnail_path"]).resolve()
        if store.thumbnail_dir.resolve() not in path.parents or not path.is_file():
            raise HTTPException(status_code=404, detail="Thumbnail not found")
        return FileResponse(path, media_type="image/jpeg")

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

    @app.post("/webhooks/square")
    async def square_webhook(request: Request) -> JSONResponse:
        signature_key = store.get_setting("square.webhook_signature_key")
        webhook_url = store.get_setting("square.webhook_url")
        if not signature_key or not webhook_url:
            raise HTTPException(status_code=403, detail="Webhook not configured")
        body = await request.body()
        signature = request.headers.get("x-square-hmacsha256-signature", "")
        if not verify_webhook_signature(signature_key, webhook_url, body, signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
        import json as _json

        try:
            event = _json.loads(body)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid JSON payload")
        payment = (
            event.get("data", {}).get("object", {}).get("payment")
            if isinstance(event, dict)
            else None
        )
        if not payment:
            return JSONResponse({"ok": True, "ignored": True})
        try:
            txn = await run_in_threadpool(sync.ingest_payment, store, payment, None)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if txn.get("camera_id"):
            submit_thumbnail_enrichment(txn["id"])
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
