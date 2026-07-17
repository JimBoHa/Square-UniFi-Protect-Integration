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
ALARM_IDLE = "idle"
ALARM_IN_PROGRESS = "in_progress"
ALARM_SENT = "sent"
ALARM_CLAIM_LEASE_SECONDS = 60

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
    raw TEXT NOT NULL DEFAULT '{}',
    alarm_state TEXT NOT NULL DEFAULT 'idle',
    alarm_claim_token TEXT,
    alarm_claimed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_transactions_ts ON transactions (ts_ms DESC);
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
            # Serialize schema inspection and ALTER statements across workers.
            self._db.execute("BEGIN IMMEDIATE")
            columns = {
                row["name"]
                for row in self._db.execute("PRAGMA table_info(transactions)").fetchall()
            }
            if "alarm_state" not in columns:
                self._db.execute(
                    "ALTER TABLE transactions ADD COLUMN alarm_state TEXT "
                    "NOT NULL DEFAULT 'idle'"
                )
                # Existing completed rows predate alarm delivery. Treat them as
                # handled so enabling the feature cannot replay historical sales.
                self._db.execute(
                    "UPDATE transactions SET alarm_state = ? "
                    "WHERE UPPER(status) = 'COMPLETED'",
                    (ALARM_SENT,),
                )
            if "alarm_claim_token" not in columns:
                self._db.execute(
                    "ALTER TABLE transactions ADD COLUMN alarm_claim_token TEXT"
                )
            if "alarm_claimed_at" not in columns:
                self._db.execute(
                    "ALTER TABLE transactions ADD COLUMN alarm_claimed_at REAL"
                )
            self._release_expired_alarm_claims_locked()
            self._db.commit()

    def close(self) -> None:
        self._db.close()

    # -- settings ----------------------------------------------------------

    def set_setting(self, key: str, value: str, secret: bool = False) -> None:
        self.update_settings({key: (value, secret)})

    def update_settings(
        self,
        updates: dict[str, tuple[str, bool]],
        delete_keys: tuple[str, ...] = (),
        suppress_completed_alarms: bool = False,
    ) -> None:
        """Apply related settings changes in one database transaction."""
        stored_updates = [
            (key, self.cipher.encrypt(value) if secret else value, int(secret))
            for key, (value, secret) in updates.items()
        ]
        with self._lock:
            try:
                for key in delete_keys:
                    self._db.execute("DELETE FROM settings WHERE key = ?", (key,))
                self._db.executemany(
                    "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "encrypted=excluded.encrypted",
                    stored_updates,
                )
                if suppress_completed_alarms:
                    self._db.execute(
                        "UPDATE transactions SET alarm_state = ?, "
                        "alarm_claim_token = NULL, alarm_claimed_at = NULL "
                        "WHERE UPPER(status) = 'COMPLETED' AND alarm_state != ?",
                        (ALARM_SENT, ALARM_SENT),
                    )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    def get_setting(self, key: str) -> str | None:
        return self.get_settings((key,))[key]

    def get_settings(self, keys: tuple[str, ...]) -> dict[str, str | None]:
        """Read related settings from one locked database snapshot."""
        if not keys:
            return {}
        placeholders = ", ".join("?" for _ in keys)
        with self._lock:
            rows = self._db.execute(
                f"SELECT key, value, encrypted FROM settings "
                f"WHERE key IN ({placeholders})",
                keys,
            ).fetchall()
        values = {key: None for key in keys}
        for row in rows:
            values[row["key"]] = (
                self.cipher.decrypt(row["value"])
                if row["encrypted"]
                else row["value"]
            )
        return values

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
            existing = self._db.execute(
                "SELECT id FROM transactions WHERE id = ?", (txn["id"],)
            ).fetchone()
            self._db.execute(
                "INSERT INTO transactions (id, created_at, ts_ms, amount, currency, status, "
                "location_id, card_last4, receipt_url, camera_id, thumbnail_path, raw) "
                "VALUES (:id, :created_at, :ts_ms, :amount, :currency, :status, :location_id, "
                ":card_last4, :receipt_url, :camera_id, :thumbnail_path, :raw) "
                "ON CONFLICT(id) DO UPDATE SET status=excluded.status, "
                "camera_id=COALESCE(excluded.camera_id, camera_id), "
                "thumbnail_path=COALESCE(excluded.thumbnail_path, thumbnail_path)",
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
            self._db.commit()
        return existing is None

    def get_transaction(self, txn_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM transactions WHERE id = ?", (txn_id,)
            ).fetchone()
        return dict(row) if row else None

    def set_transaction_thumbnail(
        self,
        txn_id: str,
        thumbnail_path: str,
        expected_camera_id: str,
        expected_ts_ms: int,
    ) -> bool:
        """Attach a thumbnail only while its camera evidence still matches."""
        with self._lock:
            cursor = self._db.execute(
                "UPDATE transactions SET thumbnail_path = ? "
                "WHERE id = ? AND thumbnail_path IS NULL "
                "AND camera_id = ? AND ts_ms = ?",
                (thumbnail_path, txn_id, expected_camera_id, expected_ts_ms),
            )
            self._db.commit()
        return cursor.rowcount > 0

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

    def _release_expired_alarm_claims_locked(self) -> None:
        """Release abandoned claims without stealing work from a live process."""
        cutoff = time.time() - ALARM_CLAIM_LEASE_SECONDS
        self._db.execute(
            "UPDATE transactions SET alarm_state = ?, alarm_claim_token = NULL, "
            "alarm_claimed_at = NULL WHERE alarm_state = ? "
            "AND (alarm_claimed_at IS NULL OR alarm_claimed_at <= ?)",
            (ALARM_IDLE, ALARM_IN_PROGRESS, cutoff),
        )

    def pending_alarm_transaction_ids(self, limit: int = 100) -> list[str]:
        """Completed alarm deliveries awaiting an attempt, oldest first."""
        limit = max(1, min(int(limit), 500))
        with self._lock:
            self._release_expired_alarm_claims_locked()
            rows = self._db.execute(
                "SELECT id FROM transactions WHERE UPPER(status) = 'COMPLETED' "
                "AND alarm_state = ? ORDER BY ts_ms ASC LIMIT ?",
                (ALARM_IDLE, limit),
            ).fetchall()
            self._db.commit()
        return [row["id"] for row in rows]

    def claim_alarm_trigger(self, txn_id: str) -> str | None:
        """Atomically claim an unhandled completed transaction for delivery."""
        claim_token = secrets.token_urlsafe(18)
        with self._lock:
            self._release_expired_alarm_claims_locked()
            cursor = self._db.execute(
                "UPDATE transactions SET alarm_state = ?, alarm_claim_token = ?, "
                "alarm_claimed_at = ? "
                "WHERE id = ? AND UPPER(status) = 'COMPLETED' AND alarm_state = ?",
                (ALARM_IN_PROGRESS, claim_token, time.time(), txn_id, ALARM_IDLE),
            )
            self._db.commit()
        return claim_token if cursor.rowcount == 1 else None

    def mark_alarm_sent(self, txn_id: str, claim_token: str) -> bool:
        with self._lock:
            cursor = self._db.execute(
                "UPDATE transactions SET alarm_state = ?, alarm_claim_token = NULL, "
                "alarm_claimed_at = NULL WHERE id = ? AND alarm_state = ? "
                "AND alarm_claim_token = ?",
                (ALARM_SENT, txn_id, ALARM_IN_PROGRESS, claim_token),
            )
            self._db.commit()
        return cursor.rowcount == 1

    def release_alarm_claim(self, txn_id: str, claim_token: str) -> bool:
        with self._lock:
            cursor = self._db.execute(
                "UPDATE transactions SET alarm_state = ?, alarm_claim_token = NULL, "
                "alarm_claimed_at = NULL WHERE id = ? AND alarm_state = ? "
                "AND alarm_claim_token = ?",
                (ALARM_IDLE, txn_id, ALARM_IN_PROGRESS, claim_token),
            )
            self._db.commit()
        return cursor.rowcount == 1

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
