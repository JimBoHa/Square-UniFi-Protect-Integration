#!/usr/bin/env python3
"""Continuously audit the Square Protect load test and print compact metrics."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

import httpx


DATA_DIR = Path(__file__).resolve().parent
STATE_PATH = DATA_DIR / "sandbox-load-state.json"
EVENTS_PATH = DATA_DIR / "sandbox-load-events.jsonl"
DB_PATH = DATA_DIR / "spi.db"
SERVICE_LOG_PATH = DATA_DIR / "service.log"
INTERVAL_SECONDS = 30
MAX_SETTLE_SECONDS = 20 * 60
MIN_FREE_BYTES = 10 * 1024**3


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"{path.name} must contain a JSON object")
    return value


def payment_ledger() -> dict[str, dict]:
    payments: dict[str, dict] = {}
    if not EVENTS_PATH.exists():
        return payments
    with EVENTS_PATH.open(encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            if event.get("type") == "payment":
                payments[event["payment_id"]] = event
    return payments


def db_snapshot(ledger: dict[str, dict], expected_camera_id: str) -> dict:
    connection = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        total = connection.execute("SELECT count(*) FROM transactions").fetchone()[0]
        ready = connection.execute(
            "SELECT count(*) FROM transactions WHERE thumbnail_path IS NOT NULL"
        ).fetchone()[0]
        retries = connection.execute(
            "SELECT count(*) FROM thumbnail_retries"
        ).fetchone()[0]
        mismatches: list[dict] = []
        transient_approved = 0
        ingested = 0
        payment_ids = list(ledger)
        for start in range(0, len(payment_ids), 400):
            chunk = payment_ids[start : start + 400]
            placeholders = ",".join("?" for _ in chunk)
            rows = connection.execute(
                f"SELECT id, amount, currency, status, camera_id, thumbnail_path "
                f"FROM transactions WHERE id IN ({placeholders})",
                chunk,
            ).fetchall()
            ingested += len(rows)
            for row in rows:
                expected = ledger[row["id"]]
                if row["status"] == "APPROVED":
                    transient_approved += 1
                if (
                    row["amount"] != expected["amount"]
                    or row["currency"] != "USD"
                    or row["status"] not in {"APPROVED", "COMPLETED"}
                    or row["camera_id"] != expected_camera_id
                ):
                    mismatches.append(
                        {
                            "id": row["id"],
                            "expected_amount": expected["amount"],
                            "actual_amount": row["amount"],
                            "currency": row["currency"],
                            "status": row["status"],
                            "camera_matches": row["camera_id"] == expected_camera_id,
                        }
                    )
        return {
            "total": total,
            "ready": ready,
            "retries": retries,
            "load_ingested": ingested,
            "transient_approved": transient_approved,
            "mismatches": mismatches,
        }
    finally:
        connection.close()


def db_integrity() -> str:
    connection = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10)
    try:
        return str(connection.execute("PRAGMA quick_check").fetchone()[0])
    finally:
        connection.close()


def login_client() -> httpx.Client:
    admin = subprocess.check_output(
        [
            "security",
            "find-generic-password",
            "-a",
            "admin",
            "-s",
            "com.squareprotect.app",
            "-w",
        ],
        text=True,
    ).strip()
    client = httpx.Client(
        base_url="https://10.0.7.215:8000",
        timeout=180.0,
        trust_env=False,
        verify=False,
    )
    response = client.post("/api/login", json={"password": admin})
    admin = ""
    response.raise_for_status()
    return client


def api_json(client: httpx.Client, method: str, path: str, **kwargs) -> dict | list:
    response = client.request(method, path, **kwargs)
    if response.status_code == 401:
        client.close()
        raise RuntimeError("App session unexpectedly expired")
    response.raise_for_status()
    return response.json()


def new_log_alerts(offset: int) -> tuple[int, list[str]]:
    if not SERVICE_LOG_PATH.exists():
        return offset, []
    size = SERVICE_LOG_PATH.stat().st_size
    if size < offset:
        offset = 0
    with SERVICE_LOG_PATH.open(encoding="utf-8", errors="replace") as stream:
        stream.seek(offset)
        new_text = stream.read()
        new_offset = stream.tell()
    alerts = []
    for line in new_text.splitlines():
        upper = line.upper()
        if any(marker in upper for marker in ("TRACEBACK", "ERROR", "CRITICAL")):
            alerts.append(line[:500])
    return new_offset, alerts


def main() -> None:
    client = login_client()
    mappings = api_json(client, "GET", "/api/camera-mapping")
    barn_mappings = [
        mapping
        for mapping in mappings
        if isinstance(mapping, dict) and mapping.get("camera_name") == "Barn East"
    ]
    if len(barn_mappings) != 1:
        raise RuntimeError("Expected one Barn East fallback mapping")
    expected_camera_id = barn_mappings[0]["camera_id"]
    log_offset = SERVICE_LOG_PATH.stat().st_size if SERVICE_LOG_PATH.exists() else 0
    loop = 0
    completed_seen_at: float | None = None
    previous_created = -1
    previous_ingested = -1
    last_dashboard: dict = {}

    try:
        while True:
            loop_started = time.monotonic()
            loop += 1
            alerts: list[str] = []
            try:
                state = read_json(STATE_PATH)
                ledger = payment_ledger()
                created = int(state.get("created", 0))
                if created < previous_created or abs(created - len(ledger)) > 1:
                    alerts.append(
                        f"generator ledger mismatch: state={created}, ledger={len(ledger)}"
                    )
                previous_created = created

                snapshot = db_snapshot(ledger, expected_camera_id)
                sync_result = {"ingested": 0}
                sync_seconds = 0.0
                status = api_json(client, "GET", "/api/status")
                if loop == 1 or loop % 4 == 0:
                    last_dashboard = api_json(client, "GET", "/api/dashboard")
                square = last_dashboard.get("square", {})
                protect = last_dashboard.get("protect", {})
                if not all(status.values()):
                    alerts.append(f"configuration status degraded: {status}")
                if not square.get("ok"):
                    alerts.append(f"Square unhealthy: {square.get('detail')}")
                if not protect.get("ok"):
                    alerts.append(f"Protect unhealthy: {protect.get('detail')}")

                if snapshot["mismatches"]:
                    alerts.append(
                        f"transaction invariant mismatches: {snapshot['mismatches'][:5]}"
                    )
                if snapshot["load_ingested"] < previous_ingested:
                    alerts.append("ingested load count moved backwards")
                previous_ingested = snapshot["load_ingested"]
                lag = created - snapshot["load_ingested"]
                if lag > 30:
                    alerts.append(f"ingestion lag high: {lag}")
                if snapshot["retries"] > 200:
                    alerts.append(f"thumbnail retry backlog high: {snapshot['retries']}")

                integrity = db_integrity() if loop == 1 or loop % 10 == 0 else "not-due"
                if integrity not in ("ok", "not-due"):
                    alerts.append(f"database integrity failed: {integrity}")
                free_bytes = os.statvfs(DATA_DIR).f_bavail * os.statvfs(DATA_DIR).f_frsize
                if free_bytes < MIN_FREE_BYTES:
                    alerts.append(f"disk guard threshold crossed: {free_bytes}")
                log_offset, log_alerts = new_log_alerts(log_offset)
                alerts.extend(f"service log: {line}" for line in log_alerts)

                metrics = {
                    "event": "watchdog",
                    "loop": loop,
                    "generator": state.get("status"),
                    "created": created,
                    "ingested": snapshot["load_ingested"],
                    "ingestion_lag": lag,
                    "thumbnails_ready_total": snapshot["ready"],
                    "thumbnail_retries": snapshot["retries"],
                    "transient_approved": snapshot["transient_approved"],
                    "sync_ingested": sync_result.get("ingested"),
                    "sync_seconds": round(sync_seconds, 2),
                    "db_integrity": integrity,
                    "free_gib": round(free_bytes / 1024**3, 2),
                    "alerts": alerts,
                }
                print(json.dumps(metrics), flush=True)

                if state.get("status") == "failed":
                    raise RuntimeError(f"Generator failed: {state.get('last_error')}")
                if state.get("status") == "complete":
                    if completed_seen_at is None:
                        completed_seen_at = time.monotonic()
                    if (
                        created == int(state.get("target", 0))
                        and snapshot["load_ingested"] == created
                        and snapshot["retries"] == 0
                        and not alerts
                    ):
                        print(json.dumps({**metrics, "event": "settled"}), flush=True)
                        return
                    if time.monotonic() - completed_seen_at > MAX_SETTLE_SECONDS:
                        raise RuntimeError("Load test did not settle within 20 minutes")
            except (httpx.HTTPError, OSError, RuntimeError, sqlite3.Error) as exc:
                print(
                    json.dumps(
                        {
                            "event": "watchdog-error",
                            "loop": loop,
                            "detail": f"{type(exc).__name__}: {exc}",
                        }
                    ),
                    flush=True,
                )
                try:
                    client.close()
                finally:
                    client = login_client()

            remaining = INTERVAL_SECONDS - (time.monotonic() - loop_started)
            if remaining > 0:
                time.sleep(remaining)
    finally:
        client.close()


if __name__ == "__main__":
    main()
