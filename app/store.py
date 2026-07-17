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

    def set_setting_if_absent(self, key: str, value: str, secret: bool = False) -> bool:
        """Store a setting only if no caller has created the key."""
        stored = self.cipher.encrypt(value) if secret else value
        with self._lock:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO settings (key, value, encrypted) VALUES (?, ?, ?)",
                (key, stored, int(secret)),
            )
            self._db.commit()
        return cursor.rowcount == 1

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

    def delete_settings(self, *keys: str) -> None:
        if not keys:
            return
        placeholders = ", ".join("?" for _ in keys)
        with self._lock:
            self._db.execute(
                f"DELETE FROM settings WHERE key IN ({placeholders})", keys
            )
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

    def replace_camera_mappings(
        self, mappings: list[tuple[str, str, str]]
    ) -> None:
        """Replace every camera mapping in one SQLite transaction."""
        with self._lock, self._db:
            self._db.execute("DELETE FROM camera_map")
            self._db.executemany(
                "INSERT INTO camera_map (location_id, camera_id, camera_name) "
                "VALUES (?, ?, ?)",
                mappings,
            )

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

    def list_transactions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM transactions ORDER BY ts_ms DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def latest_transaction_ts(self, location_id: str | None = None) -> int | None:
        with self._lock:
            if location_id is None:
                row = self._db.execute(
                    "SELECT MAX(ts_ms) AS ts FROM transactions"
                ).fetchone()
            else:
                row = self._db.execute(
                    "SELECT MAX(ts_ms) AS ts FROM transactions WHERE location_id = ?",
                    (location_id,),
                ).fetchone()
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
