#!/usr/bin/env python3
"""Create evenly spaced, low-value Square Sandbox payments for load testing."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

import httpx


TARGET = 1_000
DURATION_SECONDS = 2 * 60 * 60
MAX_AMOUNT_CENTS = 99
MIN_FREE_BYTES = 10 * 1024**3
SQUARE_VERSION = "2026-07-15"
BASE_URL = "https://connect.squareupsandbox.com"
DATA_DIR = Path(__file__).resolve().parent
PLAN_PATH = DATA_DIR / "sandbox-load-plan.json"
STATE_PATH = DATA_DIR / "sandbox-load-state.json"
EVENTS_PATH = DATA_DIR / "sandbox-load-events.jsonl"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, payload: dict) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(payload, stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def append_event(payload: dict) -> None:
    descriptor = os.open(
        EVENTS_PATH,
        os.O_APPEND | os.O_CREAT | os.O_WRONLY,
        0o600,
    )
    try:
        encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def keychain_token() -> str:
    token = subprocess.check_output(
        [
            "security",
            "find-generic-password",
            "-a",
            "sandbox",
            "-s",
            "com.squareprotect.square-sandbox",
            "-w",
        ],
        text=True,
    ).strip()
    if not token:
        raise RuntimeError("Square Sandbox token missing from Keychain")
    return token


def request_json(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    attempts: int = 12,
) -> dict:
    delay = 0.5
    for attempt in range(1, attempts + 1):
        try:
            response = client.request(method, path, json=body)
        except httpx.RequestError as exc:
            retryable = True
            detail = type(exc).__name__
        else:
            retryable = response.status_code == 429 or response.status_code >= 500
            detail = f"HTTP {response.status_code}"
            if 200 <= response.status_code < 300:
                payload = response.json()
                if not isinstance(payload, dict):
                    raise RuntimeError(f"Square {path} returned invalid JSON")
                return payload
            if not retryable:
                safe_body = response.text[:1_000]
                raise RuntimeError(
                    f"Square {path} failed ({detail}): {safe_body}"
                )
        if attempt == attempts:
            raise RuntimeError(
                f"Square {path} failed after {attempts} attempts ({detail})"
            )
        append_event(
            {
                "type": "retry",
                "at": utc_now(),
                "path": path,
                "attempt": attempt,
                "detail": detail,
            }
        )
        time.sleep(delay)
        delay = min(delay * 2, 30.0)
    raise AssertionError("unreachable")


def build_plan() -> dict:
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    interval = DURATION_SECONDS / (TARGET - 1)
    payments = []
    for index in range(TARGET):
        payments.append(
            {
                "index": index + 1,
                "offset_seconds": index * interval,
                "amount": ((index * 37) % MAX_AMOUNT_CENTS) + 1,
                "idempotency_key": f"spi-{uuid.uuid4().hex}",
            }
        )
    return {
        "run_id": run_id,
        "created_at": utc_now(),
        "target": TARGET,
        "duration_seconds": DURATION_SECONDS,
        "max_amount_cents": MAX_AMOUNT_CENTS,
        "payments": payments,
    }


def main() -> None:
    if PLAN_PATH.exists() or STATE_PATH.exists() or EVENTS_PATH.exists():
        raise RuntimeError("Load-test state already exists; refusing duplicate run")

    plan = build_plan()
    atomic_json(PLAN_PATH, plan)
    started_monotonic = time.monotonic()
    started_at = utc_now()
    state = {
        "run_id": plan["run_id"],
        "status": "starting",
        "started_at": started_at,
        "target": TARGET,
        "created": 0,
        "failed": 0,
        "last_payment_id": None,
        "last_error": None,
    }
    atomic_json(STATE_PATH, state)

    token = keychain_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Square-Version": SQUARE_VERSION,
        "Content-Type": "application/json",
    }
    token = ""
    with httpx.Client(
        base_url=BASE_URL,
        headers=headers,
        timeout=30.0,
        trust_env=False,
    ) as client:
        locations_payload = request_json(client, "GET", "/v2/locations")
        locations = [
            location
            for location in locations_payload.get("locations", [])
            if isinstance(location, dict) and location.get("status") == "ACTIVE"
        ]
        if len(locations) != 1:
            raise RuntimeError(
                f"Expected exactly one active Sandbox location, found {len(locations)}"
            )
        location = locations[0]
        if location.get("currency") != "USD":
            raise RuntimeError(
                f"Expected USD Sandbox location, found {location.get('currency')!r}"
            )
        location_id = location.get("id")
        if not isinstance(location_id, str) or not location_id:
            raise RuntimeError("Square Sandbox location id missing")

        state.update(
            {
                "status": "running",
                "location_name": location.get("name", ""),
                "interval_seconds": DURATION_SECONDS / (TARGET - 1),
            }
        )
        atomic_json(STATE_PATH, state)
        print(
            json.dumps(
                {
                    "event": "start",
                    "run_id": plan["run_id"],
                    "target": TARGET,
                    "duration_seconds": DURATION_SECONDS,
                    "location": location.get("name", ""),
                }
            ),
            flush=True,
        )

        try:
            for payment_plan in plan["payments"]:
                due_at = started_monotonic + payment_plan["offset_seconds"]
                remaining = due_at - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
                free_bytes = shutil.disk_usage(DATA_DIR).free
                if free_bytes < MIN_FREE_BYTES:
                    raise RuntimeError(
                        f"Disk safety guard tripped with {free_bytes} bytes free"
                    )

                index = payment_plan["index"]
                amount = payment_plan["amount"]
                payload = request_json(
                    client,
                    "POST",
                    "/v2/payments",
                    body={
                        "source_id": "cnon:card-nonce-ok",
                        "idempotency_key": payment_plan["idempotency_key"],
                        "amount_money": {"amount": amount, "currency": "USD"},
                        "autocomplete": True,
                        "location_id": location_id,
                        "reference_id": f"spi-load-{plan['run_id']}-{index:04d}",
                        "note": "Square Protect two-hour Sandbox load test",
                    },
                )
                payment = payload.get("payment")
                if not isinstance(payment, dict):
                    raise RuntimeError("Square CreatePayment response missing payment")
                payment_id = payment.get("id")
                actual_money = payment.get("amount_money")
                if (
                    not isinstance(payment_id, str)
                    or not payment_id
                    or payment.get("status") != "COMPLETED"
                    or not isinstance(actual_money, dict)
                    or actual_money.get("amount") != amount
                    or actual_money.get("currency") != "USD"
                    or amount < 1
                    or amount > MAX_AMOUNT_CENTS
                ):
                    raise RuntimeError(
                        f"Square payment invariant failed at index {index}"
                    )

                append_event(
                    {
                        "type": "payment",
                        "at": utc_now(),
                        "index": index,
                        "payment_id": payment_id,
                        "amount": amount,
                        "currency": "USD",
                        "status": payment.get("status"),
                    }
                )
                state.update(
                    {
                        "created": index,
                        "last_payment_id": payment_id,
                        "last_payment_at": utc_now(),
                        "free_bytes": free_bytes,
                    }
                )
                atomic_json(STATE_PATH, state)
                if index == 1 or index % 10 == 0 or index == TARGET:
                    elapsed = time.monotonic() - started_monotonic
                    print(
                        json.dumps(
                            {
                                "event": "progress",
                                "created": index,
                                "target": TARGET,
                                "elapsed_seconds": round(elapsed, 1),
                                "last_amount_cents": amount,
                                "free_gib": round(free_bytes / 1024**3, 2),
                            }
                        ),
                        flush=True,
                    )
        except BaseException as exc:
            state.update(
                {
                    "status": "failed",
                    "failed": 1,
                    "last_error": f"{type(exc).__name__}: {exc}",
                    "finished_at": utc_now(),
                }
            )
            atomic_json(STATE_PATH, state)
            append_event(
                {
                    "type": "fatal",
                    "at": utc_now(),
                    "detail": state["last_error"],
                }
            )
            print(json.dumps({"event": "fatal", "detail": state["last_error"]}), flush=True)
            raise

    state.update(
        {
            "status": "complete",
            "finished_at": utc_now(),
            "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
        }
    )
    atomic_json(STATE_PATH, state)
    print(json.dumps({"event": "complete", **state}), flush=True)


if __name__ == "__main__":
    main()
