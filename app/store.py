"""SQLite-backed storage for settings, camera mappings, transactions, sessions."""

from __future__ import annotations

import json
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
    updated_at TEXT NOT NULL,
    updated_ts_ms INTEGER NOT NULL,
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
            self._migrate_transactions()
            self._db.commit()

    def _migrate_transactions(self) -> None:
        """Add transaction version columns without replacing existing tables."""
        columns = {
            row["name"]
            for row in self._db.execute("PRAGMA table_info(transactions)").fetchall()
        }
        if "updated_at" not in columns:
            self._db.execute(
                "ALTER TABLE transactions ADD COLUMN updated_at "
                "TEXT NOT NULL DEFAULT ''"
            )
            self._db.execute("UPDATE transactions SET updated_at = created_at")
        if "updated_ts_ms" not in columns:
            self._db.execute(
                "ALTER TABLE transactions ADD COLUMN updated_ts_ms "
                "INTEGER NOT NULL DEFAULT 0"
            )
            self._db.execute("UPDATE transactions SET updated_ts_ms = ts_ms")

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
        values = {
            "camera_id": None,
            "thumbnail_path": None,
            "location_id": "",
            "card_last4": "",
            "receipt_url": "",
            "raw": json.dumps(txn.get("raw", {})),
            **{k: v for k, v in txn.items() if k != "raw"},
        }
        values["updated_at"] = txn.get("updated_at") or txn["created_at"]
        values["updated_ts_ms"] = txn.get("updated_ts_ms", txn["ts_ms"])

        with self._lock:
            existing = self._db.execute(
                "SELECT id FROM transactions WHERE id = ?", (txn["id"],)
            ).fetchone()
            self._db.execute(
                "INSERT INTO transactions (id, created_at, ts_ms, updated_at, updated_ts_ms, "
                "amount, currency, status, location_id, card_last4, receipt_url, camera_id, "
                "thumbnail_path, raw) VALUES (:id, :created_at, :ts_ms, :updated_at, "
                ":updated_ts_ms, :amount, :currency, :status, :location_id, :card_last4, "
                ":receipt_url, :camera_id, :thumbnail_path, :raw) "
                "ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at, "
                "updated_ts_ms=excluded.updated_ts_ms, amount=excluded.amount, "
                "currency=excluded.currency, status=excluded.status, "
                "location_id=excluded.location_id, card_last4=excluded.card_last4, "
                "receipt_url=excluded.receipt_url, raw=excluded.raw, "
                "camera_id=COALESCE(excluded.camera_id, transactions.camera_id), "
                "thumbnail_path=COALESCE(excluded.thumbnail_path, transactions.thumbnail_path) "
                "WHERE excluded.updated_ts_ms >= transactions.updated_ts_ms",
                values,
            )
            self._db.commit()
        return existing is None

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
