"""SQLite-backed storage for settings, camera mappings, transactions, sessions."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from .security import CredentialCipher, hash_session_token

SESSION_TTL_SECONDS = 12 * 3600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    encrypted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS camera_map (
    location_id TEXT PRIMARY KEY,
    camera_id TEXT NOT NULL,
    camera_name TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    ts_ms INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    currency TEXT NOT NULL,
    status TEXT NOT NULL,
    location_id TEXT NOT NULL DEFAULT '',
    card_last4 TEXT NOT NULL DEFAULT '',
    receipt_url TEXT NOT NULL DEFAULT '',
    camera_id TEXT,
    thumbnail_path TEXT,
    raw TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_transactions_ts ON transactions (ts_ms DESC);
CREATE TABLE IF NOT EXISTS thumbnail_retries (
    transaction_id TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL DEFAULT 0,
    lease_token TEXT,
    lease_expires_at REAL,
    last_error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_thumbnail_retries_due
    ON thumbnail_retries (next_attempt_at, lease_expires_at);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""


class Store:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.thumbnail_dir = self.data_dir / "thumbnails"
        self.thumbnail_dir.mkdir(exist_ok=True)
        self.cipher = CredentialCipher(self.data_dir)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.data_dir / "spi.db", check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(_SCHEMA)
            # Upgrade existing databases: any transaction that already missed
            # its thumbnail must enter the durable retry queue.
            self._db.execute(
                "INSERT OR IGNORE INTO thumbnail_retries (transaction_id) "
                "SELECT id FROM transactions "
                "WHERE camera_id IS NOT NULL AND thumbnail_path IS NULL"
            )
            self._db.execute(
                "DELETE FROM thumbnail_retries WHERE NOT EXISTS ("
                "SELECT 1 FROM transactions t "
                "WHERE t.id = thumbnail_retries.transaction_id "
                "AND t.camera_id IS NOT NULL AND t.thumbnail_path IS NULL)"
            )
            self._db.commit()

    def close(self) -> None:
        self._db.close()

    # -- settings ----------------------------------------------------------

    def set_setting(self, key: str, value: str, secret: bool = False) -> None:
        stored = self.cipher.encrypt(value) if secret else value
        with self._lock:
            self._db.execute(
                "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, encrypted=excluded.encrypted",
                (key, stored, int(secret)),
            )
            self._db.commit()

    def get_setting(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT value, encrypted FROM settings WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        return self.cipher.decrypt(row["value"]) if row["encrypted"] else row["value"]

    def delete_setting(self, key: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM settings WHERE key = ?", (key,))
            self._db.commit()

    # -- camera mapping ----------------------------------------------------

    def set_camera_mapping(self, location_id: str, camera_id: str, camera_name: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO camera_map (location_id, camera_id, camera_name) VALUES (?, ?, ?) "
                "ON CONFLICT(location_id) DO UPDATE SET camera_id=excluded.camera_id, "
                "camera_name=excluded.camera_name",
                (location_id, camera_id, camera_name),
            )
            self._db.commit()

    def get_camera_mappings(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM camera_map ORDER BY location_id").fetchall()
        return [dict(r) for r in rows]

    def camera_for_location(self, location_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM camera_map WHERE location_id = ?", (location_id,)
            ).fetchone()
            if row is None:
                row = self._db.execute(
                    "SELECT * FROM camera_map WHERE location_id = '*'"
                ).fetchone()
        return dict(row) if row else None

    def clear_camera_mappings(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM camera_map")
            self._db.commit()

    # -- transactions ------------------------------------------------------

    def upsert_transaction(self, txn: dict) -> bool:
        """Insert or update a transaction. Returns True if it was new."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT id, camera_id, ts_ms FROM transactions WHERE id = ?",
                    (txn["id"],),
                ).fetchone()
                self._db.execute(
                    "INSERT INTO transactions (id, created_at, ts_ms, amount, currency, status, "
                    "location_id, card_last4, receipt_url, camera_id, thumbnail_path, raw) "
                    "VALUES (:id, :created_at, :ts_ms, :amount, :currency, :status, "
                    ":location_id, :card_last4, :receipt_url, :camera_id, :thumbnail_path, "
                    ":raw) ON CONFLICT(id) DO UPDATE SET status=excluded.status, "
                    "created_at=excluded.created_at, ts_ms=excluded.ts_ms, "
                    "thumbnail_path=CASE WHEN "
                    "transactions.camera_id IS NOT COALESCE(excluded.camera_id, "
                    "transactions.camera_id) OR transactions.ts_ms != excluded.ts_ms "
                    "THEN excluded.thumbnail_path ELSE COALESCE(excluded.thumbnail_path, "
                    "transactions.thumbnail_path) END, "
                    "camera_id=COALESCE(excluded.camera_id, transactions.camera_id)",
                    {
                        "camera_id": None,
                        "thumbnail_path": None,
                        "location_id": "",
                        "card_last4": "",
                        "receipt_url": "",
                        "raw": json.dumps(txn.get("raw", {})),
                        **{k: v for k, v in txn.items() if k != "raw"},
                    },
                )
                current = self._db.execute(
                    "SELECT camera_id, ts_ms, thumbnail_path FROM transactions WHERE id = ?",
                    (txn["id"],),
                ).fetchone()
                evidence_changed = bool(
                    existing
                    and current
                    and (
                        existing["camera_id"] != current["camera_id"]
                        or existing["ts_ms"] != current["ts_ms"]
                    )
                )
                if current and current["camera_id"] and not current["thumbnail_path"]:
                    if evidence_changed:
                        self._db.execute(
                            "INSERT INTO thumbnail_retries (transaction_id) VALUES (?) "
                            "ON CONFLICT(transaction_id) DO UPDATE SET attempts = 0, "
                            "next_attempt_at = 0, lease_token = NULL, "
                            "lease_expires_at = NULL, last_error = ''",
                            (txn["id"],),
                        )
                    else:
                        self._db.execute(
                            "INSERT OR IGNORE INTO thumbnail_retries (transaction_id) "
                            "VALUES (?)",
                            (txn["id"],),
                        )
                else:
                    self._db.execute(
                        "DELETE FROM thumbnail_retries WHERE transaction_id = ?",
                        (txn["id"],),
                    )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return existing is None

    def claim_thumbnail_retries(
        self,
        limit: int,
        lease_seconds: float,
        *,
        now: float | None = None,
    ) -> list[dict]:
        """Lease a bounded batch of due thumbnail jobs.

        ``BEGIN IMMEDIATE`` serializes claimers across Store instances and
        processes. Each row gets a unique token so an expired worker cannot
        commit over a newer claim.
        """
        limit = max(1, min(int(limit), 100))
        lease_seconds = max(1.0, float(lease_seconds))
        claimed_at = time.time() if now is None else float(now)
        claimed: list[dict] = []
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                rows = self._db.execute(
                    "SELECT r.transaction_id, r.attempts, t.camera_id, t.ts_ms "
                    "FROM thumbnail_retries r "
                    "JOIN transactions t ON t.id = r.transaction_id "
                    "WHERE t.camera_id IS NOT NULL AND t.thumbnail_path IS NULL "
                    "AND r.next_attempt_at <= ? "
                    "AND (r.lease_token IS NULL OR r.lease_expires_at <= ?) "
                    "ORDER BY r.next_attempt_at, t.ts_ms, r.transaction_id LIMIT ?",
                    (claimed_at, claimed_at, limit),
                ).fetchall()
                for row in rows:
                    token = secrets.token_hex(16)
                    updated = self._db.execute(
                        "UPDATE thumbnail_retries "
                        "SET lease_token = ?, lease_expires_at = ? "
                        "WHERE transaction_id = ? "
                        "AND next_attempt_at <= ? "
                        "AND (lease_token IS NULL OR lease_expires_at <= ?)",
                        (
                            token,
                            claimed_at + lease_seconds,
                            row["transaction_id"],
                            claimed_at,
                            claimed_at,
                        ),
                    )
                    if updated.rowcount == 1:
                        claimed.append(
                            {
                                "transaction_id": row["transaction_id"],
                                "camera_id": row["camera_id"],
                                "ts_ms": row["ts_ms"],
                                "attempts": row["attempts"],
                                "lease_token": token,
                            }
                        )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return claimed

    def complete_thumbnail_retry(
        self,
        transaction_id: str,
        lease_token: str,
        camera_id: str,
        ts_ms: int,
        thumbnail_path: str,
    ) -> bool:
        """Attach retry evidence only when token, camera, and time still match."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                retry = self._db.execute(
                    "SELECT 1 FROM thumbnail_retries "
                    "WHERE transaction_id = ? AND lease_token = ?",
                    (transaction_id, lease_token),
                ).fetchone()
                if retry is None:
                    self._db.commit()
                    return False

                updated = self._db.execute(
                    "UPDATE transactions SET thumbnail_path = ? "
                    "WHERE id = ? AND camera_id = ? AND ts_ms = ? "
                    "AND thumbnail_path IS NULL",
                    (thumbnail_path, transaction_id, camera_id, int(ts_ms)),
                )
                if updated.rowcount == 1:
                    self._db.execute(
                        "DELETE FROM thumbnail_retries "
                        "WHERE transaction_id = ? AND lease_token = ?",
                        (transaction_id, lease_token),
                    )
                    self._db.commit()
                    return True

                self._requeue_changed_thumbnail_locked(transaction_id, lease_token)
                self._db.commit()
                return False
            except Exception:
                self._db.rollback()
                raise

    def fail_thumbnail_retry(
        self,
        transaction_id: str,
        lease_token: str,
        camera_id: str,
        ts_ms: int,
        error: str,
        *,
        now: float | None = None,
        base_delay_seconds: float = 30.0,
        max_delay_seconds: float = 3600.0,
    ) -> bool:
        """Release a claimed job with exponential, capped retry backoff."""
        failed_at = time.time() if now is None else float(now)
        base_delay_seconds = max(1.0, float(base_delay_seconds))
        max_delay_seconds = max(base_delay_seconds, float(max_delay_seconds))
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                retry = self._db.execute(
                    "SELECT attempts FROM thumbnail_retries "
                    "WHERE transaction_id = ? AND lease_token = ?",
                    (transaction_id, lease_token),
                ).fetchone()
                if retry is None:
                    self._db.commit()
                    return False

                txn = self._db.execute(
                    "SELECT camera_id, ts_ms, thumbnail_path FROM transactions WHERE id = ?",
                    (transaction_id,),
                ).fetchone()
                same_evidence = bool(
                    txn
                    and txn["camera_id"] == camera_id
                    and txn["ts_ms"] == int(ts_ms)
                    and not txn["thumbnail_path"]
                )
                if not same_evidence:
                    self._requeue_changed_thumbnail_locked(transaction_id, lease_token)
                    self._db.commit()
                    return True

                attempts = int(retry["attempts"]) + 1
                delay = min(
                    base_delay_seconds * (2 ** min(attempts - 1, 30)),
                    max_delay_seconds,
                )
                updated = self._db.execute(
                    "UPDATE thumbnail_retries SET attempts = ?, next_attempt_at = ?, "
                    "lease_token = NULL, lease_expires_at = NULL, last_error = ? "
                    "WHERE transaction_id = ? AND lease_token = ?",
                    (
                        attempts,
                        failed_at + delay,
                        str(error)[:1000],
                        transaction_id,
                        lease_token,
                    ),
                )
                self._db.commit()
                return updated.rowcount == 1
            except Exception:
                self._db.rollback()
                raise

    def _requeue_changed_thumbnail_locked(
        self, transaction_id: str, lease_token: str
    ) -> None:
        """Reset changed evidence immediately, or discard a finished/stale job."""
        txn = self._db.execute(
            "SELECT camera_id, thumbnail_path FROM transactions WHERE id = ?",
            (transaction_id,),
        ).fetchone()
        if txn and txn["camera_id"] and not txn["thumbnail_path"]:
            self._db.execute(
                "UPDATE thumbnail_retries SET attempts = 0, next_attempt_at = 0, "
                "lease_token = NULL, lease_expires_at = NULL, last_error = '' "
                "WHERE transaction_id = ? AND lease_token = ?",
                (transaction_id, lease_token),
            )
        else:
            self._db.execute(
                "DELETE FROM thumbnail_retries "
                "WHERE transaction_id = ? AND lease_token = ?",
                (transaction_id, lease_token),
            )

    def get_transaction(self, txn_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM transactions WHERE id = ?", (txn_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_transactions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM transactions ORDER BY ts_ms DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def latest_transaction_ts(self) -> int | None:
        with self._lock:
            row = self._db.execute("SELECT MAX(ts_ms) AS ts FROM transactions").fetchone()
        return row["ts"] if row and row["ts"] is not None else None

    # -- sessions ----------------------------------------------------------

    def create_session(self, token: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)",
                (hash_session_token(token), time.time() + SESSION_TTL_SECONDS),
            )
            self._db.commit()

    def session_valid(self, token: str) -> bool:
        now = time.time()
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            row = self._db.execute(
                "SELECT 1 FROM sessions WHERE token_hash = ? AND expires_at >= ?",
                (hash_session_token(token), now),
            ).fetchone()
            self._db.commit()
        return row is not None

    def delete_session(self, token: str) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (hash_session_token(token),)
            )
            self._db.commit()
