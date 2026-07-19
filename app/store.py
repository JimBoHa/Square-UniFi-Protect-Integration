"""SQLite-backed storage for settings, camera mappings, transactions, sessions."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from .security import CredentialCipher, hash_session_token

try:  # POSIX advisory locks.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised by the Windows-backend test
    _fcntl = None

try:  # Windows byte-range locks.
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - unavailable on POSIX
    _msvcrt = None

logger = logging.getLogger("spi.store")

SESSION_TTL_SECONDS = 12 * 3600
TRANSACTION_SNAPSHOT_TTL_SECONDS = SESSION_TTL_SECONDS
MAX_TRANSACTION_SNAPSHOTS = 8
MAX_TRANSACTION_ORDER_HISTORY = 10_000
MAX_TRANSACTION_SEARCH_LENGTH = 64
TRANSACTION_FILTER_STATUSES = frozenset(
    {"APPROVED", "PENDING", "COMPLETED", "CANCELED", "FAILED"}
)
ALARM_IDLE = "idle"
ALARM_IN_PROGRESS = "in_progress"
ALARM_SENT = "sent"
ALARM_CLAIM_LEASE_SECONDS = 60
ALARM_ENABLED_AFTER_SETTING = "protect.alarm_enabled_after_ms"
SQUARE_POLL_WATERMARK_TABLE = "square_poll_watermarks"
PROTECT_EVIDENCE_RETIRED_TABLE = "protect_evidence_retired"
SQUARE_ACCOUNT_REVISION_SETTING = "square.account_revision"
PROTECT_CONSOLE_GENERATION_SETTING = "protect.console_generation"
PROTECT_CONSOLE_ID_SETTING = "protect.console_id"
PROTECT_SWITCH_TOKEN_TTL_SECONDS = 5 * 60
ORPHAN_THUMBNAIL_CLEANUP_SETTING = "maintenance.orphan_thumbnail_cleanup_pending"
_NO_EXPECTED_PROTECT_HOST = object()

# Windows' msvcrt backend offers only exclusive byte-range locks. A short-lived
# gate plus independent reader slots provides shared-reader/exclusive-writer
# semantics without a platform-specific dependency. The writer keeps the gate
# while draining every reader slot, so new readers cannot starve it.
_WINDOWS_LOCK_GATE_BYTE = 0
_WINDOWS_LOCK_READER_START = 1
_WINDOWS_LOCK_READER_SLOTS = 128
_WINDOWS_LOCK_FILE_BYTES = _WINDOWS_LOCK_READER_START + _WINDOWS_LOCK_READER_SLOTS
_WINDOWS_LOCK_RETRY_SECONDS = 0.01
_WINDOWS_LOCK_BUSY_ERRNOS = {
    errno.EACCES,
    errno.EAGAIN,
    getattr(errno, "EDEADLK", errno.EACCES),
}


class SquareAccountSwitchRequired(Exception):
    """A different or unknown prior Square account needs explicit consent."""

    def __init__(self, confirmation_token: str):
        super().__init__("Confirm the Square account switch before replacing local data")
        self.confirmation_token = confirmation_token


class SquareAccountChanged(Exception):
    """Reject work that started with credentials for an older Square account."""


@dataclass(frozen=True)
class SquareAccountConfiguration:
    switched: bool
    account_revision: str
    evidence_cleanup_pending: bool


class ProtectConsoleSwitchConfirmationRequired(RuntimeError):
    """A host change attempted to discard console-scoped state without consent."""


class ProtectSettingsConflict(RuntimeError):
    """Protect settings changed after a caller took its validation snapshot."""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    encrypted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS camera_map (
    location_id TEXT NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    camera_id TEXT NOT NULL,
    camera_name TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (location_id, device_id)
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
    device_id TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
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
CREATE INDEX IF NOT EXISTS idx_transactions_status_ts
    ON transactions (status, ts_ms DESC, id DESC);
CREATE TABLE IF NOT EXISTS square_poll_watermarks (
    location_id TEXT PRIMARY KEY,
    polled_through_ms INTEGER NOT NULL CHECK (polled_through_ms >= 0)
);
CREATE TABLE IF NOT EXISTS transaction_feed_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    order_revision INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO transaction_feed_state (singleton, order_revision)
VALUES (1, 0);
CREATE TABLE IF NOT EXISTS transaction_feed_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_revision INTEGER NOT NULL,
    rowid_boundary INTEGER NOT NULL,
    filter_signature TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    last_accessed_at REAL NOT NULL,
    UNIQUE (order_revision, rowid_boundary, filter_signature)
);
CREATE INDEX IF NOT EXISTS idx_transaction_feed_snapshots_access
    ON transaction_feed_snapshots (last_accessed_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS transaction_feed_order_history (
    transaction_id TEXT NOT NULL,
    order_revision INTEGER NOT NULL,
    ts_ms INTEGER NOT NULL,
    PRIMARY KEY (transaction_id, order_revision)
);
CREATE INDEX IF NOT EXISTS idx_transaction_feed_history_revision
    ON transaction_feed_order_history (order_revision);
CREATE TRIGGER IF NOT EXISTS invalidate_transaction_feed_after_delete
AFTER DELETE ON transactions
BEGIN
    DELETE FROM transaction_feed_snapshots;
    DELETE FROM transaction_feed_order_history;
    UPDATE transaction_feed_state
    SET order_revision = order_revision + 1
    WHERE singleton = 1;
END;
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
CREATE TABLE IF NOT EXISTS protect_evidence_retired (
    transaction_id TEXT PRIMARY KEY,
    FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""


class TransactionSnapshotExpired(Exception):
    """Requested transaction-feed ordering snapshot is no longer retained."""


class TransactionSnapshotFilterMismatch(Exception):
    """Requested transaction-feed snapshot belongs to different filters."""


def _transaction_filter(
    query: str,
    status: str,
) -> tuple[str, str, tuple[str, ...]]:
    """Return filter signature, fixed SQL, and bound parameters."""
    query = str(query)
    status = str(status).strip().upper()
    if len(query) > MAX_TRANSACTION_SEARCH_LENGTH or any(
        ord(character) < 32 or ord(character) == 127 for character in query
    ):
        raise ValueError("Invalid transaction search query")
    query = query.strip()
    if status and status not in TRANSACTION_FILTER_STATUSES:
        raise ValueError("Invalid transaction status filter")

    if not query and not status:
        return "", "", ()
    signature = hashlib.sha256(
        json.dumps([query, status], ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    clauses: list[str] = []
    parameters: list[str] = []
    if query:
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        fields = (
            "t.id",
            "t.card_last4",
            "t.device_id",
            "t.device_name",
            "t.location_id",
            "t.status",
        )
        clauses.append(
            "(" + " OR ".join(
                f"{field} LIKE ? ESCAPE '\\' COLLATE NOCASE" for field in fields
            ) + ")"
        )
        parameters.extend(pattern for _field in fields)
    if status:
        clauses.append("t.status = ?")
        parameters.append(status)
    return signature, " AND " + " AND ".join(clauses), tuple(parameters)


def _windows_try_lock_byte(fd: int, offset: int) -> bool:
    """Attempt one Windows byte-range lock without waiting."""
    if _msvcrt is None:  # pragma: no cover - guarded by integration_guard
        raise RuntimeError("Windows file locking is unavailable")
    os.lseek(fd, offset, os.SEEK_SET)
    try:
        _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
    except OSError as exc:
        # CPython reports a sharing violation as EACCES; the extra errno and
        # winerror values cover alternative Windows runtimes.
        if exc.errno in _WINDOWS_LOCK_BUSY_ERRNOS or getattr(
            exc, "winerror", None
        ) in (33, 36, 158):
            return False
        raise
    return True


def _windows_lock_byte(fd: int, offset: int) -> None:
    while not _windows_try_lock_byte(fd, offset):
        time.sleep(_WINDOWS_LOCK_RETRY_SECONDS)


def _windows_unlock_byte(fd: int, offset: int) -> None:
    if _msvcrt is None:  # pragma: no cover - guarded by integration_guard
        raise RuntimeError("Windows file locking is unavailable")
    os.lseek(fd, offset, os.SEEK_SET)
    _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)


def _acquire_windows_integration_lock(
    fd: int, *, exclusive: bool
) -> tuple[tuple[int, ...], bool]:
    """Return (reader slots, gate-held) for the acquired Windows lock."""
    slots: list[int] = []
    gate_held = False
    try:
        _windows_lock_byte(fd, _WINDOWS_LOCK_GATE_BYTE)
        gate_held = True
        if exclusive:
            for slot in range(
                _WINDOWS_LOCK_READER_START, _WINDOWS_LOCK_FILE_BYTES
            ):
                _windows_lock_byte(fd, slot)
                slots.append(slot)
        else:
            while not slots:
                for slot in range(
                    _WINDOWS_LOCK_READER_START, _WINDOWS_LOCK_FILE_BYTES
                ):
                    if _windows_try_lock_byte(fd, slot):
                        slots.append(slot)
                        break
                if not slots:
                    # Do not monopolize the gate if every reader slot is busy.
                    _windows_unlock_byte(fd, _WINDOWS_LOCK_GATE_BYTE)
                    gate_held = False
                    time.sleep(_WINDOWS_LOCK_RETRY_SECONDS)
                    _windows_lock_byte(fd, _WINDOWS_LOCK_GATE_BYTE)
                    gate_held = True
            _windows_unlock_byte(fd, _WINDOWS_LOCK_GATE_BYTE)
            gate_held = False
        return tuple(slots), gate_held
    except Exception:
        for slot in reversed(slots):
            _windows_unlock_byte(fd, slot)
        if gate_held:
            _windows_unlock_byte(fd, _WINDOWS_LOCK_GATE_BYTE)
        raise


def _release_windows_integration_lock(
    fd: int, slots: tuple[int, ...], gate_held: bool
) -> None:
    for slot in reversed(slots):
        _windows_unlock_byte(fd, slot)
    if gate_held:
        _windows_unlock_byte(fd, _WINDOWS_LOCK_GATE_BYTE)


class Store:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.data_dir, 0o700)
        self.thumbnail_dir = self.data_dir / "thumbnails"
        self.thumbnail_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.thumbnail_dir, 0o700)
        for path in self.thumbnail_dir.iterdir():
            if path.is_file() and not path.is_symlink():
                # Temp files from writes interrupted by a hard crash are never
                # referenced by the database; sweep them instead of keeping them.
                if path.name.startswith(".") and path.name.endswith(".tmp"):
                    path.unlink(missing_ok=True)
                    continue
                path.chmod(0o600)
        self.cipher = CredentialCipher(self.data_dir)
        # Square and Protect work share one reader/writer lock. Provider
        # switches therefore cannot overlap in-flight evidence work or acquire
        # provider-specific locks in opposing orders across processes.
        self._integration_lock_path = self.data_dir / ".provider-state.lock"
        self._protect_settings_lock_path = self.data_dir / ".protect-settings.lock"
        key_path = self.data_dir / "secret.key"
        if key_path.is_file() and not key_path.is_symlink():
            key_path.chmod(0o600)
        self._lock = threading.Lock()
        db_path = self.data_dir / "spi.db"
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        os.chmod(db_path, 0o600)
        self._db.row_factory = sqlite3.Row
        # Ensure migration updates overwrite discarded Payment JSON in SQLite
        # pages instead of leaving recoverable buyer metadata in free space.
        self._db.execute("PRAGMA secure_delete = ON")
        with self._lock:
            self._db.executescript(_SCHEMA)
            # Serialize schema inspection and ALTER statements across workers.
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._migrate_transactions()
                self._migrate_transaction_feed_snapshots()
                self._migrate_schema()
                # Legacy releases kept the complete Square Payment JSON so
                # device metadata could be backfilled later. The schema
                # migration above has consumed that one needed field; discard
                # the remaining buyer and payment metadata before committing.
                self._scrub_transaction_raw()
                self._migrate_alarms()
                self._ensure_protect_console_generation_locked()
                self._clear_missing_thumbnail_references_locked()
                # Upgrade existing databases: any transaction that already
                # missed its thumbnail must enter the durable retry queue.
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
                self._release_expired_alarm_claims_locked()
                if self._db.execute(
                    "SELECT 1 FROM settings WHERE key LIKE 'square.%' LIMIT 1"
                ).fetchone() and not self._db.execute(
                    "SELECT 1 FROM settings WHERE key = ?",
                    (SQUARE_ACCOUNT_REVISION_SETTING,),
                ).fetchone():
                    # Give upgraded installations an account generation before
                    # any webhook or sync can snapshot the legacy settings.
                    self._db.execute(
                        "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, 0)",
                        (
                            SQUARE_ACCOUNT_REVISION_SETTING,
                            secrets.token_urlsafe(24),
                        ),
                    )
            except Exception:
                self._db.rollback()
                raise
            else:
                self._db.commit()
        if self.get_setting(ORPHAN_THUMBNAIL_CLEANUP_SETTING) is not None:
            try:
                with self.integration_guard(exclusive=True):
                    self.remove_orphan_thumbnails()
            except Exception as exc:
                logger.warning("Could not resume orphan thumbnail cleanup: %s", exc)

    @contextmanager
    def _cross_process_guard(self, lock_path: Path, *, exclusive: bool):
        """Acquire one shared/exclusive file lock on every supported platform."""
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(lock_path, flags, 0o600)
        windows_lock: tuple[tuple[int, ...], bool] | None = None
        posix_locked = False
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            if _fcntl is not None:
                operation = _fcntl.LOCK_EX if exclusive else _fcntl.LOCK_SH
                _fcntl.flock(fd, operation)
                posix_locked = True
            elif _msvcrt is not None:
                windows_lock = _acquire_windows_integration_lock(
                    fd, exclusive=exclusive
                )
            else:  # Fail closed instead of silently losing provider isolation.
                raise RuntimeError("No supported cross-process file-lock backend")
            yield
        finally:
            try:
                if posix_locked and _fcntl is not None:
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
                if windows_lock is not None:
                    _release_windows_integration_lock(fd, *windows_lock)
            finally:
                # Closing is the fail-safe release for every OS lock still
                # associated with this descriptor if explicit unlock failed.
                os.close(fd)

    @contextmanager
    def integration_guard(self, *, exclusive: bool = False):
        """Coordinate provider work across threads, Store objects, and processes."""
        with self._cross_process_guard(
            self._integration_lock_path,
            exclusive=exclusive,
        ):
            yield

    @contextmanager
    def protect_settings_guard(self):
        """Serialize Protect settings mutations without blocking provider reads.

        Code needing both locks must acquire this mutation guard first and the
        integration writer second. Provider work never takes this lock, which
        keeps the lock order acyclic while network validation is in progress.
        """
        with self._cross_process_guard(
            self._protect_settings_lock_path,
            exclusive=True,
        ):
            yield

    def _thumbnail_file_exists(self, name: str) -> bool:
        path = (self.thumbnail_dir / name).resolve()
        return self.thumbnail_dir.resolve() in path.parents and path.is_file()

    def _clear_missing_thumbnail_references_locked(self) -> None:
        rows = self._db.execute(
            "SELECT id, location_id, device_id, thumbnail_path FROM transactions "
            "WHERE thumbnail_path IS NOT NULL"
        ).fetchall()
        for row in rows:
            if self._thumbnail_file_exists(row["thumbnail_path"]):
                continue
            # Once historical evidence is gone, retry against the mapping that
            # currently owns this POS. This matches the runtime missing-file
            # repair path and avoids recreating evidence from a stale camera.
            mapping = self._camera_for_location_locked(
                row["location_id"], row["device_id"]
            )
            camera_id = mapping["camera_id"] if mapping else None
            self._db.execute(
                "UPDATE transactions SET camera_id = ?, thumbnail_path = NULL "
                "WHERE id = ?",
                (camera_id, row["id"]),
            )

    def _migrate_alarms(self) -> None:
        """Add alarm delivery columns; never replay pre-existing completed sales."""
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
        configured_alarm_keys = {
            row["key"]
            for row in self._db.execute(
                "SELECT key FROM settings WHERE key IN (?, ?, ?)",
                (
                    "protect.api_key",
                    "protect.alarm_trigger_id",
                    ALARM_ENABLED_AFTER_SETTING,
                ),
            ).fetchall()
        }
        if {
            "protect.api_key",
            "protect.alarm_trigger_id",
        }.issubset(configured_alarm_keys) and (
            ALARM_ENABLED_AFTER_SETTING not in configured_alarm_keys
        ):
            # Upgrade early alarm-feature databases without replaying
            # imports that happened before this process started.
            self._db.execute(
                "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, 0)",
                (ALARM_ENABLED_AFTER_SETTING, str(int(time.time() * 1000))),
            )
            self._db.execute(
                "UPDATE transactions SET alarm_state = ?, "
                "alarm_claim_token = NULL, alarm_claimed_at = NULL "
                "WHERE UPPER(status) = 'COMPLETED' AND alarm_state != ?",
                (ALARM_SENT, ALARM_SENT),
            )

    def _ensure_protect_console_generation_locked(self) -> None:
        """Bind upgraded Protect settings to a stable console generation."""
        configured = self._db.execute(
            "SELECT 1 FROM settings WHERE key = ?", ("protect.host",)
        ).fetchone()
        generation = self._db.execute(
            "SELECT 1 FROM settings WHERE key = ?",
            (PROTECT_CONSOLE_GENERATION_SETTING,),
        ).fetchone()
        if configured and not generation:
            self._db.execute(
                "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, 0)",
                (PROTECT_CONSOLE_GENERATION_SETTING, secrets.token_hex(16)),
            )

    def _migrate_schema(self) -> None:
        mapping_columns = {
            row["name"]
            for row in self._db.execute("PRAGMA table_info(camera_map)").fetchall()
        }
        if "device_id" not in mapping_columns:
            self._db.execute("ALTER TABLE camera_map RENAME TO camera_map_legacy")
            self._db.execute(
                """
                CREATE TABLE camera_map (
                    location_id TEXT NOT NULL,
                    device_id TEXT NOT NULL DEFAULT '',
                    device_name TEXT NOT NULL DEFAULT '',
                    camera_id TEXT NOT NULL,
                    camera_name TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (location_id, device_id)
                )
                """
            )
            self._db.execute(
                """
                INSERT INTO camera_map (
                    location_id, device_id, device_name, camera_id, camera_name
                )
                SELECT location_id, '', '', camera_id, camera_name
                FROM camera_map_legacy
                """
            )
            self._db.execute("DROP TABLE camera_map_legacy")

        transaction_columns = {
            row["name"]
            for row in self._db.execute("PRAGMA table_info(transactions)").fetchall()
        }
        if "device_id" not in transaction_columns:
            self._db.execute(
                "ALTER TABLE transactions ADD COLUMN device_id "
                "TEXT NOT NULL DEFAULT ''"
            )
        if "device_name" not in transaction_columns:
            self._db.execute(
                "ALTER TABLE transactions ADD COLUMN device_name "
                "TEXT NOT NULL DEFAULT ''"
            )
        self._backfill_transaction_devices()

    def _migrate_transaction_feed_snapshots(self) -> None:
        """Bind upgraded paging snapshots to one canonical filter set."""
        columns = {
            row["name"]
            for row in self._db.execute(
                "PRAGMA table_info(transaction_feed_snapshots)"
            ).fetchall()
        }
        if "filter_signature" in columns:
            return

        # SQLite cannot extend the existing UNIQUE constraint in place. Keep
        # unfiltered snapshot ids valid while rebuilding the small bounded
        # table with filter_signature included in its identity.
        sequence = self._db.execute(
            "SELECT seq FROM sqlite_sequence "
            "WHERE name = 'transaction_feed_snapshots'"
        ).fetchone()
        sequence_high_watermark = int(sequence["seq"]) if sequence else 0
        self._db.execute("DROP TRIGGER IF EXISTS invalidate_transaction_feed_after_delete")
        self._db.execute("DROP INDEX IF EXISTS idx_transaction_feed_snapshots_access")
        self._db.execute(
            "ALTER TABLE transaction_feed_snapshots "
            "RENAME TO transaction_feed_snapshots_legacy"
        )
        self._db.execute(
            """
            CREATE TABLE transaction_feed_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_revision INTEGER NOT NULL,
                rowid_boundary INTEGER NOT NULL,
                filter_signature TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                last_accessed_at REAL NOT NULL,
                UNIQUE (order_revision, rowid_boundary, filter_signature)
            )
            """
        )
        self._db.execute(
            """
            INSERT INTO transaction_feed_snapshots (
                id, order_revision, rowid_boundary, filter_signature,
                created_at, last_accessed_at
            )
            SELECT id, order_revision, rowid_boundary, '', created_at, last_accessed_at
            FROM transaction_feed_snapshots_legacy
            """
        )
        updated_sequence = self._db.execute(
            "UPDATE sqlite_sequence SET seq = MAX(COALESCE(seq, 0), ?) "
            "WHERE name = 'transaction_feed_snapshots'",
            (sequence_high_watermark,),
        )
        if updated_sequence.rowcount == 0:
            self._db.execute(
                "INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)",
                ("transaction_feed_snapshots", sequence_high_watermark),
            )
        self._db.execute("DROP TABLE transaction_feed_snapshots_legacy")
        self._db.execute(
            "CREATE INDEX idx_transaction_feed_snapshots_access "
            "ON transaction_feed_snapshots (last_accessed_at DESC, id DESC)"
        )
        self._db.execute(
            """
            CREATE TRIGGER invalidate_transaction_feed_after_delete
            AFTER DELETE ON transactions
            BEGIN
                DELETE FROM transaction_feed_snapshots;
                DELETE FROM transaction_feed_order_history;
                UPDATE transaction_feed_state
                SET order_revision = order_revision + 1
                WHERE singleton = 1;
            END
            """
        )

    def _backfill_transaction_devices(self) -> None:
        rows = self._db.execute(
            "SELECT id, device_id, device_name, raw FROM transactions "
            "WHERE device_id = '' OR device_name = ''"
        ).fetchall()
        for row in rows:
            try:
                payment = json.loads(row["raw"])
            except (TypeError, ValueError):
                continue
            if not isinstance(payment, dict):
                continue
            details = payment.get("device_details")
            if not isinstance(details, dict):
                continue
            parsed_id = details.get("device_id")
            parsed_name = details.get("device_name")
            parsed_id = parsed_id if isinstance(parsed_id, str) else ""
            parsed_name = parsed_name if isinstance(parsed_name, str) else ""
            device_id = row["device_id"] or parsed_id
            device_name = row["device_name"] or parsed_name
            if device_id != row["device_id"] or device_name != row["device_name"]:
                self._db.execute(
                    "UPDATE transactions SET device_id = ?, device_name = ? WHERE id = ?",
                    (device_id, device_name, row["id"]),
                )

    def _scrub_transaction_raw(self) -> None:
        """Remove legacy Square Payment payloads after device backfill."""
        self._db.execute("UPDATE transactions SET raw = '{}' WHERE raw != '{}'")

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

    def _setting_value_locked(self, key: str) -> str | None:
        row = self._db.execute(
            "SELECT value, encrypted FROM settings WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        return self.cipher.decrypt(row["value"]) if row["encrypted"] else row["value"]

    def set_setting(self, key: str, value: str, secret: bool = False) -> None:
        self.update_settings({key: (value, secret)})

    def update_settings(
        self,
        updates: dict[str, tuple[str, bool]],
        delete_keys: tuple[str, ...] = (),
        suppress_completed_alarms: bool = False,
        activate_alarm_at_ms: int | None = None,
    ) -> bool:
        """Apply settings atomically; return whether alarm activation occurred."""
        stored_updates = [
            (key, self.cipher.encrypt(value) if secret else value, int(secret))
            for key, (value, secret) in updates.items()
        ]
        alarm_activated = False
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                for key in delete_keys:
                    self._db.execute("DELETE FROM settings WHERE key = ?", (key,))
                self._db.executemany(
                    "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "encrypted=excluded.encrypted",
                    stored_updates,
                )
                if activate_alarm_at_ms is not None:
                    configured_keys = {
                        row["key"]
                        for row in self._db.execute(
                            "SELECT key FROM settings WHERE key IN (?, ?, ?)",
                            (
                                "protect.api_key",
                                "protect.alarm_trigger_id",
                                ALARM_ENABLED_AFTER_SETTING,
                            ),
                        ).fetchall()
                    }
                    if {
                        "protect.api_key",
                        "protect.alarm_trigger_id",
                    }.issubset(configured_keys) and (
                        ALARM_ENABLED_AFTER_SETTING not in configured_keys
                    ):
                        self._db.execute(
                            "INSERT INTO settings (key, value, encrypted) "
                            "VALUES (?, ?, 0)",
                            (
                                ALARM_ENABLED_AFTER_SETTING,
                                str(int(activate_alarm_at_ms)),
                            ),
                        )
                        alarm_activated = True
                if suppress_completed_alarms or alarm_activated:
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
        return alarm_activated

    def update_protect_settings(
        self,
        updates: dict[str, tuple[str, bool]],
        *,
        expected_host: str | None,
        expected_generation: str | None,
        expected_console_id: str | None = None,
        observed_console_id: str | None = None,
        console_switch_token: str = "",
        delete_keys: tuple[str, ...] = (),
        activate_alarm_at_ms: int | None = None,
    ) -> bool:
        """Atomically save Protect settings and isolate a confirmed console switch.

        Returns whether the stored host or durable console identity changed.
        Database references are cleared in the same transaction as the settings
        update; files are removed afterward only if no transaction references them.
        """
        if "protect.host" not in updates:
            raise ValueError("Protect settings update requires protect.host")
        new_host = updates["protect.host"][0]
        if observed_console_id is not None:
            updates = {
                **updates,
                PROTECT_CONSOLE_ID_SETTING: (observed_console_id, False),
            }
        elif PROTECT_CONSOLE_ID_SETTING in updates:
            raise ValueError("Protect console id must be passed as observed_console_id")
        stored_updates = [
            (key, self.cipher.encrypt(value) if secret else value, int(secret))
            for key, (value, secret) in updates.items()
        ]
        console_switched = False
        alarm_activated = False

        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                current_host = self._setting_value_locked("protect.host")
                current_generation = self._setting_value_locked(
                    PROTECT_CONSOLE_GENERATION_SETTING
                )
                current_console_id = self._setting_value_locked(
                    PROTECT_CONSOLE_ID_SETTING
                )
                if (
                    current_host != expected_host
                    or current_generation != expected_generation
                    or current_console_id != expected_console_id
                ):
                    raise ProtectSettingsConflict(
                        "Protect settings changed while credentials were being verified"
                    )
                console_switched = bool(
                    current_host
                    and (
                        current_host != new_host
                        or (
                            current_console_id is not None
                            and current_console_id != observed_console_id
                        )
                    )
                )
                if console_switched and not self._protect_switch_confirmation_matches(
                    console_switch_token,
                    current_generation,
                    new_host,
                    observed_console_id,
                ):
                    raise ProtectConsoleSwitchConfirmationRequired(
                        "Protect console switch requires explicit confirmation"
                    )

                if console_switched:
                    # Retained Square facts must not be silently remapped to
                    # cameras on the new console when mappings are re-created.
                    self._db.execute(
                        "INSERT OR IGNORE INTO protect_evidence_retired "
                        "(transaction_id) SELECT id FROM transactions"
                    )
                    self._db.execute("DELETE FROM camera_map")
                    self._db.execute("DELETE FROM thumbnail_retries")
                    self._db.execute(
                        "UPDATE transactions SET camera_id = NULL, "
                        "thumbnail_path = NULL "
                        "WHERE camera_id IS NOT NULL OR thumbnail_path IS NOT NULL"
                    )
                    self._db.execute(
                        "INSERT INTO settings (key, value, encrypted) VALUES (?, '1', 0) "
                        "ON CONFLICT(key) DO UPDATE SET value='1', encrypted=0",
                        (ORPHAN_THUMBNAIL_CLEANUP_SETTING,),
                    )

                for key in delete_keys:
                    self._db.execute("DELETE FROM settings WHERE key = ?", (key,))
                if console_switched and observed_console_id is None:
                    self._db.execute(
                        "DELETE FROM settings WHERE key = ?",
                        (PROTECT_CONSOLE_ID_SETTING,),
                    )
                self._db.executemany(
                    "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "encrypted=excluded.encrypted",
                    stored_updates,
                )
                if not current_generation or console_switched:
                    self._db.execute(
                        "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, 0) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, encrypted=0",
                        (
                            PROTECT_CONSOLE_GENERATION_SETTING,
                            secrets.token_hex(16),
                        ),
                    )
                if activate_alarm_at_ms is not None:
                    configured_keys = {
                        row["key"]
                        for row in self._db.execute(
                            "SELECT key FROM settings WHERE key IN (?, ?, ?)",
                            (
                                "protect.api_key",
                                "protect.alarm_trigger_id",
                                ALARM_ENABLED_AFTER_SETTING,
                            ),
                        ).fetchall()
                    }
                    if {
                        "protect.api_key",
                        "protect.alarm_trigger_id",
                    }.issubset(configured_keys) and (
                        ALARM_ENABLED_AFTER_SETTING not in configured_keys
                    ):
                        self._db.execute(
                            "INSERT INTO settings (key, value, encrypted) "
                            "VALUES (?, ?, 0)",
                            (
                                ALARM_ENABLED_AFTER_SETTING,
                                str(int(activate_alarm_at_ms)),
                            ),
                        )
                        alarm_activated = True
                if console_switched or alarm_activated:
                    # Pending alarm claims and deliveries belong to the old
                    # console too. Never replay completed sales on the new one.
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

        if console_switched:
            try:
                self.remove_orphan_thumbnails()
            except Exception as exc:
                # The durable marker retries the scan at startup. The database
                # no longer exposes old-console evidence, so this must not make
                # the committed settings switch look rolled back.
                logger.warning(
                    "Could not scan orphan thumbnails after console switch: %s",
                    exc,
                )
        return console_switched

    def protect_console_switch_token(
        self,
        target_host: str,
        target_console_id: str | None,
        *,
        expected_host: str | None,
        expected_generation: str | None,
        expected_console_id: str | None,
        now: float | None = None,
    ) -> str | None:
        """Issue short-lived consent bound to the current console generation."""
        with self._lock:
            current_host = self._setting_value_locked("protect.host")
            current_generation = self._setting_value_locked(
                PROTECT_CONSOLE_GENERATION_SETTING
            )
            current_console_id = self._setting_value_locked(
                PROTECT_CONSOLE_ID_SETTING
            )
            if (
                current_host != expected_host
                or current_generation != expected_generation
                or current_console_id != expected_console_id
            ):
                raise ProtectSettingsConflict(
                    "Protect settings changed while switch confirmation was being verified"
                )
        if not current_host or not current_generation:
            return None
        payload = json.dumps(
            {
                "generation": current_generation,
                "target_host": target_host,
                "target_console_id": target_console_id,
                "issued_at": int(time.time() if now is None else now),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return self.cipher.encrypt(payload)

    def _protect_switch_confirmation_matches(
        self,
        token: str,
        current_generation: str | None,
        target_host: str,
        target_console_id: str | None,
        *,
        now: float | None = None,
    ) -> bool:
        if not token or not current_generation:
            return False
        try:
            payload = json.loads(self.cipher.decrypt(token))
            issued_at = payload["issued_at"]
            generation = payload["generation"]
            confirmed_target = payload["target_host"]
            confirmed_console_id = payload["target_console_id"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return False
        current_time = int(time.time() if now is None else now)
        return (
            isinstance(issued_at, int)
            and current_time - PROTECT_SWITCH_TOKEN_TTL_SECONDS <= issued_at
            <= current_time + 30
            and generation == current_generation
            and confirmed_target == target_host
            and confirmed_console_id == target_console_id
        )

    def protect_console_switch_token_valid(
        self,
        token: str,
        target_host: str,
        target_console_id: str | None,
    ) -> bool:
        """Validate a switch token against the latest stored generation."""
        with self._lock:
            current_generation = self._setting_value_locked(
                PROTECT_CONSOLE_GENERATION_SETTING
            )
        return self._protect_switch_confirmation_matches(
            token,
            current_generation,
            target_host,
            target_console_id,
        )

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

    def delete_settings(self, *keys: str) -> None:
        if not keys:
            return
        placeholders = ", ".join("?" for _ in keys)
        with self._lock:
            self._db.execute(
                f"DELETE FROM settings WHERE key IN ({placeholders})", keys
            )
            self._db.commit()

    def _setting_value_locked(self, key: str) -> str | None:
        row = self._db.execute(
            "SELECT value, encrypted FROM settings WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        return self.cipher.decrypt(row["value"]) if row["encrypted"] else row["value"]

    def _table_exists_locked(self, table_name: str) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        return row is not None

    def _has_square_account_data_locked(self) -> bool:
        """Detect legacy account data that has no merchant identity setting."""
        if self._db.execute(
            "SELECT 1 FROM settings WHERE key LIKE 'square.%' LIMIT 1"
        ).fetchone():
            return True
        for table_name in ("transactions", "camera_map"):
            if self._db.execute(f"SELECT 1 FROM {table_name} LIMIT 1").fetchone():
                return True
        for table_name in (
            SQUARE_POLL_WATERMARK_TABLE,
            PROTECT_EVIDENCE_RETIRED_TABLE,
        ):
            if self._table_exists_locked(table_name) and self._db.execute(
                f"SELECT 1 FROM {table_name} LIMIT 1"
            ).fetchone():
                return True
        # Legacy or interrupted installations can leave evidence files after
        # losing their database references. Treat managed regular files as
        # unidentified account data so first-time credentials cannot silently
        # inherit them.
        for path in self.thumbnail_dir.iterdir():
            if path.is_file() and not path.is_symlink():
                return True
        return False

    def _assert_square_merchant_locked(self, expected_merchant_id: str | None) -> None:
        if expected_merchant_id is None:
            return
        if self._setting_value_locked("square.merchant_id") != expected_merchant_id:
            raise SquareAccountChanged("Square account changed while work was in progress")

    def _assert_square_environment_locked(
        self, expected_environment: str | None
    ) -> None:
        if expected_environment is None:
            return
        current_environment = self._setting_value_locked("square.environment")
        if current_environment is None:
            current_environment = "production"
        if current_environment != expected_environment:
            raise SquareAccountChanged("Square account changed while work was in progress")

    def _assert_square_account_revision_locked(
        self, expected_account_revision: str | None
    ) -> None:
        if expected_account_revision is None:
            return
        if (
            self._setting_value_locked(SQUARE_ACCOUNT_REVISION_SETTING)
            != expected_account_revision
        ):
            raise SquareAccountChanged(
                "Square account changed; reload settings before saving camera mappings"
            )

    def _square_switch_confirmation_token(
        self,
        current_revision: str,
        new_environment: str,
        new_merchant_id: str,
    ) -> str:
        payload = json.dumps(
            {
                "version": 1,
                "current_revision": current_revision,
                "new_environment": new_environment,
                "new_merchant_id": new_merchant_id,
                "issued_at": int(time.time()),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return self.cipher.encrypt(payload)

    def _square_switch_confirmation_matches(
        self,
        token: str,
        current_revision: str,
        new_environment: str,
        new_merchant_id: str,
    ) -> bool:
        if not token:
            return False
        try:
            payload = json.loads(self.cipher.decrypt(token))
            issued_at = int(payload["issued_at"])
        except (KeyError, TypeError, ValueError):
            return False
        return bool(
            payload.get("version") == 1
            and payload.get("current_revision") == current_revision
            and payload.get("new_environment") == new_environment
            and payload.get("new_merchant_id") == new_merchant_id
            and 0 <= time.time() - issued_at <= 10 * 60
        )

    def configure_square_account(
        self,
        *,
        merchant_id: str,
        access_token: str,
        environment: str,
        webhook_signature_key: str | None = None,
        webhook_url: str | None = None,
        clear_webhook: bool = False,
        confirm_account_switch: bool = False,
        account_switch_confirmation_token: str = "",
    ) -> SquareAccountConfiguration:
        """Configure one merchant while excluding cross-process account work."""
        with self.integration_guard(exclusive=True):
            switched = self._configure_square_account(
                merchant_id=merchant_id,
                access_token=access_token,
                environment=environment,
                webhook_signature_key=webhook_signature_key,
                webhook_url=webhook_url,
                clear_webhook=clear_webhook,
                confirm_account_switch=confirm_account_switch,
                account_switch_confirmation_token=(
                    account_switch_confirmation_token
                ),
            )
            revision = self.square_account_revision()
            if revision is None:
                raise RuntimeError("Square account revision was not persisted")
            return SquareAccountConfiguration(
                switched=switched,
                account_revision=revision,
                evidence_cleanup_pending=(
                    self.orphan_thumbnail_cleanup_pending()
                ),
            )

    def _configure_square_account(
        self,
        *,
        merchant_id: str,
        access_token: str,
        environment: str,
        webhook_signature_key: str | None = None,
        webhook_url: str | None = None,
        clear_webhook: bool = False,
        confirm_account_switch: bool = False,
        account_switch_confirmation_token: str = "",
    ) -> bool:
        """Save Square credentials and atomically isolate a changed account.

        Returns whether this replaced a different (or unidentified legacy)
        account. Database evidence is removed in the same transaction as the
        credential change. Files cannot participate in SQLite transactions,
        so unreferenced thumbnails are removed only after a successful commit.
        """
        if bool(webhook_signature_key) != bool(webhook_url):
            raise ValueError(
                "Webhook signature key and notification URL must be provided together"
            )
        if clear_webhook and webhook_signature_key:
            raise ValueError(
                "clear_webhook cannot be combined with new webhook credentials"
            )
        updates = [
            ("square.access_token", self.cipher.encrypt(access_token), 1),
            ("square.environment", environment, 0),
            ("square.merchant_id", merchant_id, 0),
        ]
        if webhook_signature_key is not None and webhook_url is not None:
            updates.extend(
                (
                    (
                        "square.webhook_signature_key",
                        self.cipher.encrypt(webhook_signature_key),
                        1,
                    ),
                    ("square.webhook_url", webhook_url, 0),
                )
            )

        switched = False
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                current_merchant_id = self._setting_value_locked(
                    "square.merchant_id"
                )
                current_environment = self._setting_value_locked(
                    "square.environment"
                )
                if current_environment is None and current_merchant_id is not None:
                    # Pre-environment releases implicitly used production.
                    current_environment = "production"
                current_revision = self._setting_value_locked(
                    SQUARE_ACCOUNT_REVISION_SETTING
                ) or f"legacy:{current_environment or ''}:{current_merchant_id or ''}"
                switched = (
                    current_merchant_id != merchant_id
                    or bool(
                        current_environment
                        and current_environment != environment
                    )
                    if current_merchant_id is not None
                    else self._has_square_account_data_locked()
                )
                confirmed_switch = bool(
                    switched
                    and confirm_account_switch
                    and self._square_switch_confirmation_matches(
                        account_switch_confirmation_token,
                        current_revision,
                        environment,
                        merchant_id,
                    )
                )
                if switched and not confirmed_switch:
                    raise SquareAccountSwitchRequired(
                        self._square_switch_confirmation_token(
                            current_revision, environment, merchant_id
                        )
                    )

                if switched:
                    # Delete children explicitly because older databases did
                    # not enable SQLite foreign-key enforcement.
                    self._db.execute("DELETE FROM thumbnail_retries")
                    if self._table_exists_locked(PROTECT_EVIDENCE_RETIRED_TABLE):
                        # Protect console isolation tracks transaction IDs
                        # whose old-console evidence must stay retired. A new
                        # merchant may legitimately reuse a payment ID, so the
                        # retirement state is Square-account-owned too.
                        self._db.execute(
                            f"DELETE FROM {PROTECT_EVIDENCE_RETIRED_TABLE}"
                        )
                    self._db.execute("DELETE FROM transactions")
                    self._db.execute("DELETE FROM camera_map")
                    if self._table_exists_locked(SQUARE_POLL_WATERMARK_TABLE):
                        self._db.execute(
                            f"DELETE FROM {SQUARE_POLL_WATERMARK_TABLE}"
                        )
                    # Webhook signatures and any future Square-owned state
                    # must never cross merchant boundaries. Submitted webhook
                    # credentials below are inserted for the new account.
                    self._db.execute(
                        "DELETE FROM settings WHERE key LIKE 'square.%'"
                    )
                    self._db.execute(
                        "INSERT INTO settings (key, value, encrypted) VALUES (?, '1', 0) "
                        "ON CONFLICT(key) DO UPDATE SET value='1', encrypted=0",
                        (ORPHAN_THUMBNAIL_CLEANUP_SETTING,),
                    )
                elif clear_webhook:
                    self._db.execute(
                        "DELETE FROM settings WHERE key IN (?, ?)",
                        ("square.webhook_signature_key", "square.webhook_url"),
                    )

                if switched or self._setting_value_locked(
                    SQUARE_ACCOUNT_REVISION_SETTING
                ) is None:
                    updates.append(
                        (
                            SQUARE_ACCOUNT_REVISION_SETTING,
                            secrets.token_urlsafe(24),
                            0,
                        )
                    )

                self._db.executemany(
                    "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "encrypted=excluded.encrypted",
                    updates,
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

        if switched or self.orphan_thumbnail_cleanup_pending():
            try:
                self.remove_orphan_thumbnails()
            except Exception as exc:
                # Account isolation is already durable in SQLite. A cleanup
                # failure must not imply that the credential switch rolled back.
                logger.warning("Could not scan orphan thumbnails after account switch: %s", exc)
        return switched

    def remove_orphan_thumbnails(self) -> int:
        """Remove regular local files only when no transaction references them."""
        removed = 0
        failed = False
        for path in self.thumbnail_dir.iterdir():
            if path.is_symlink() or not path.is_file():
                continue
            try:
                removed += int(self._unlink_thumbnail_if_unreferenced(path.name))
            except OSError as exc:
                failed = True
                logger.warning("Could not delete orphan thumbnail %r: %s", path.name, exc)
        if not failed:
            self.delete_setting(ORPHAN_THUMBNAIL_CLEANUP_SETTING)
        return removed

    def orphan_thumbnail_cleanup_pending(self) -> bool:
        return self.get_setting(ORPHAN_THUMBNAIL_CLEANUP_SETTING) is not None

    def retry_orphan_thumbnail_cleanup(self) -> bool:
        """Retry a durable provider cleanup and return whether it remains pending."""
        if not self.orphan_thumbnail_cleanup_pending():
            return False
        with self.integration_guard(exclusive=True):
            # Another process may have completed the scan while this process
            # waited for the provider-state writer lock.
            if self.orphan_thumbnail_cleanup_pending():
                self.remove_orphan_thumbnails()
        return self.orphan_thumbnail_cleanup_pending()

    def square_account_revision(self) -> str | None:
        return self.get_setting(SQUARE_ACCOUNT_REVISION_SETTING)

    # -- camera mapping ----------------------------------------------------

    def set_camera_mapping(
        self,
        location_id: str,
        camera_id: str,
        camera_name: str = "",
        device_id: str = "",
        device_name: str = "",
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO camera_map (location_id, device_id, device_name, camera_id, "
                "camera_name) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(location_id, device_id) DO UPDATE SET "
                "device_name=excluded.device_name, camera_id=excluded.camera_id, "
                "camera_name=excluded.camera_name",
                (location_id, device_id, device_name, camera_id, camera_name),
            )
            self._db.commit()

    def get_camera_mappings(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM camera_map ORDER BY location_id, device_id"
            ).fetchall()
        return [dict(r) for r in rows]

    def _camera_for_location_locked(
        self, location_id: str, device_id: str = ""
    ) -> sqlite3.Row | None:
        row = None
        if device_id:
            row = self._db.execute(
                "SELECT * FROM camera_map WHERE location_id = ? AND device_id = ?",
                (location_id, device_id),
            ).fetchone()
        if row is None:
            row = self._db.execute(
                "SELECT * FROM camera_map WHERE location_id = ? AND device_id = ''",
                (location_id,),
            ).fetchone()
        if row is None:
            row = self._db.execute(
                "SELECT * FROM camera_map WHERE location_id = '*' AND device_id = ''"
            ).fetchone()
        return row

    def camera_for_location(self, location_id: str, device_id: str = "") -> dict | None:
        with self._lock:
            row = self._camera_for_location_locked(location_id, device_id)
        return dict(row) if row else None

    def camera_context_for_location(
        self, location_id: str, device_id: str = ""
    ) -> tuple[dict | None, str | None, str | None]:
        """Read a camera mapping and console identity from one DB snapshot."""
        with self._lock:
            try:
                self._db.execute("BEGIN")
                host = self._setting_value_locked("protect.host")
                generation = self._setting_value_locked(
                    PROTECT_CONSOLE_GENERATION_SETTING
                )
                mapping_row = self._camera_for_location_locked(location_id, device_id)
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return (dict(mapping_row) if mapping_row else None, host, generation)

    def clear_camera_mappings(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM camera_map")
            self._db.commit()

    def replace_camera_mappings(
        self,
        mappings: list[tuple[str, str, str, str, str]],
        *,
        expected_account_revision: str | None = None,
        expected_protect_generation: str | object = _NO_EXPECTED_PROTECT_HOST,
    ) -> None:
        with self.integration_guard():
            self._replace_camera_mappings(
                mappings,
                expected_account_revision=expected_account_revision,
                expected_protect_generation=expected_protect_generation,
            )

    def _replace_camera_mappings(
        self,
        mappings: list[tuple[str, str, str, str, str]],
        *,
        expected_account_revision: str | None = None,
        expected_protect_generation: str | object = _NO_EXPECTED_PROTECT_HOST,
    ) -> None:
        """Replace mappings and retarget pending evidence in one transaction.

        Each entry is (location_id, device_id, device_name, camera_id,
        camera_name); device_id '' is the location-level fallback row. Camera
        assignments with captured thumbnails remain immutable historical
        evidence.
        """
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._assert_square_account_revision_locked(
                    expected_account_revision
                )
                if expected_protect_generation is not _NO_EXPECTED_PROTECT_HOST:
                    current_generation = self._setting_value_locked(
                        PROTECT_CONSOLE_GENERATION_SETTING
                    )
                    if current_generation != expected_protect_generation:
                        raise ProtectSettingsConflict(
                            "Protect console changed while cameras were being selected"
                        )
                self._db.execute("DELETE FROM camera_map")
                self._db.executemany(
                    "INSERT INTO camera_map (location_id, device_id, device_name, "
                    "camera_id, camera_name) VALUES (?, ?, ?, ?, ?)",
                    mappings,
                )
                mapping_rows = self._db.execute(
                    "SELECT location_id, device_id, camera_id FROM camera_map"
                ).fetchall()
                cameras = {
                    (row["location_id"], row["device_id"]): row["camera_id"]
                    for row in mapping_rows
                }
                pending = self._db.execute(
                    "SELECT id, location_id, device_id, camera_id FROM transactions "
                    "WHERE thumbnail_path IS NULL AND NOT EXISTS ("
                    "SELECT 1 FROM protect_evidence_retired r "
                    "WHERE r.transaction_id = transactions.id)"
                ).fetchall()
                for txn in pending:
                    exact_key = (txn["location_id"], txn["device_id"])
                    location_key = (txn["location_id"], "")
                    wildcard_key = ("*", "")
                    if txn["device_id"] and exact_key in cameras:
                        camera_id = cameras[exact_key]
                    elif location_key in cameras:
                        camera_id = cameras[location_key]
                    else:
                        camera_id = cameras.get(wildcard_key)

                    if txn["camera_id"] == camera_id:
                        continue
                    self._db.execute(
                        "UPDATE transactions SET camera_id = ? WHERE id = ?",
                        (camera_id, txn["id"]),
                    )
                    if camera_id is None:
                        self._db.execute(
                            "DELETE FROM thumbnail_retries WHERE transaction_id = ?",
                            (txn["id"],),
                        )
                    else:
                        self._db.execute(
                            "INSERT INTO thumbnail_retries (transaction_id) VALUES (?) "
                            "ON CONFLICT(transaction_id) DO UPDATE SET attempts = 0, "
                            "next_attempt_at = 0, lease_token = NULL, "
                            "lease_expires_at = NULL, last_error = ''",
                            (txn["id"],),
                        )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    # -- transactions ------------------------------------------------------

    def upsert_transaction(
        self,
        txn: dict,
        *,
        replace_evidence: bool = False,
        enforce_current_mapping: bool = False,
        expected_merchant_id: str | None = None,
        expected_environment: str | None = None,
        expected_account_revision: str | None = None,
        expected_protect_host: str | None | object = _NO_EXPECTED_PROTECT_HOST,
        expected_protect_generation: str | None | object = _NO_EXPECTED_PROTECT_HOST,
    ) -> bool:
        """Insert or update a transaction. Returns True if it was new.

        ``replace_evidence`` lets an authoritative source correction clear
        nullable camera evidence instead of coalescing the prior values.
        ``enforce_current_mapping`` resolves mutable evidence against the
        camera map inside this write transaction, so a mapping save cannot be
        lost to an ingestion that read the old map before doing Protect I/O.
        """
        values = {
            "camera_id": None,
            "thumbnail_path": None,
            "location_id": "",
            "device_id": "",
            "device_name": "",
            "card_last4": "",
            "receipt_url": "",
            # Normalized columns contain everything used at runtime. Never
            # persist the original Square Payment, which can include buyer
            # contact, address, note, wallet, and risk metadata.
            "raw": "{}",
            **{k: v for k, v in txn.items() if k != "raw"},
        }
        values["updated_at"] = txn.get("updated_at") or txn["created_at"]
        values["updated_ts_ms"] = txn.get("updated_ts_ms", txn["ts_ms"])
        values["replace_evidence"] = int(bool(replace_evidence))
        superseded_thumbnail: str | None = None
        protect_identity_mismatch = False

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._assert_square_merchant_locked(expected_merchant_id)
                self._assert_square_environment_locked(expected_environment)
                self._assert_square_account_revision_locked(
                    expected_account_revision
                )
                if expected_protect_host is not _NO_EXPECTED_PROTECT_HOST:
                    current_host = self._setting_value_locked("protect.host")
                    current_generation = self._setting_value_locked(
                        PROTECT_CONSOLE_GENERATION_SETTING
                    )
                    if (
                        current_host != expected_protect_host
                        or current_generation != expected_protect_generation
                    ):
                        protect_identity_mismatch = True
                        # Square facts remain valid, but camera IDs and bytes
                        # selected under another console must not reattach.
                        values["camera_id"] = None
                        values["thumbnail_path"] = None
                        values["replace_evidence"] = 0
                retired = self._db.execute(
                    "SELECT 1 FROM protect_evidence_retired "
                    "WHERE transaction_id = ?",
                    (txn["id"],),
                ).fetchone()
                if retired:
                    values["camera_id"] = None
                    values["thumbnail_path"] = None
                    values["replace_evidence"] = 0
                existing = self._db.execute(
                    "SELECT id, camera_id, ts_ms, updated_ts_ms, status, "
                    "location_id, device_id, device_name, card_last4, thumbnail_path "
                    "FROM transactions WHERE id = ?",
                    (txn["id"],),
                ).fetchone()
                if enforce_current_mapping:
                    accepted_version = bool(
                        existing is None
                        or int(values["updated_ts_ms"])
                        >= int(existing["updated_ts_ms"])
                    )
                    evidence_is_mutable = bool(
                        existing is None
                        or not existing["thumbnail_path"]
                        or int(values["ts_ms"]) != int(existing["ts_ms"])
                        or replace_evidence
                    )
                    if accepted_version and evidence_is_mutable:
                        # Match the upsert's sparse-device semantics when choosing
                        # the row that owns this evidence. BEGIN IMMEDIATE keeps
                        # this mapping stable until the transaction commits.
                        mapped_device_id = values["device_id"]
                        if not mapped_device_id and existing is not None:
                            mapped_device_id = existing["device_id"]
                        mapping = self._camera_for_location_locked(
                            values["location_id"], mapped_device_id
                        )
                        mapped_camera_id = mapping["camera_id"] if mapping else None
                        if values["camera_id"] != mapped_camera_id:
                            # The captured path belongs to the mapping observed
                            # before this transaction began. Leave it unattached;
                            # the caller removes it after seeing the winning row.
                            values["thumbnail_path"] = None
                        values["camera_id"] = mapped_camera_id
                applied = self._db.execute(
                    "INSERT INTO transactions (id, created_at, ts_ms, updated_at, updated_ts_ms, "
                    "amount, currency, status, location_id, device_id, device_name, card_last4, "
                    "receipt_url, camera_id, thumbnail_path, raw) "
                    "VALUES (:id, :created_at, :ts_ms, :updated_at, "
                    ":updated_ts_ms, :amount, :currency, :status, :location_id, :device_id, "
                    ":device_name, :card_last4, :receipt_url, :camera_id, :thumbnail_path, :raw) "
                    "ON CONFLICT(id) DO UPDATE SET created_at=excluded.created_at, "
                    "ts_ms=excluded.ts_ms, updated_at=excluded.updated_at, "
                    "updated_ts_ms=excluded.updated_ts_ms, amount=excluded.amount, "
                    "currency=excluded.currency, status=excluded.status, "
                    "location_id=excluded.location_id, "
                    "device_id=COALESCE(NULLIF(excluded.device_id, ''), transactions.device_id), "
                    "device_name=CASE WHEN NULLIF(excluded.device_id, '') IS NOT NULL "
                    "AND excluded.device_id != transactions.device_id "
                    "THEN excluded.device_name ELSE COALESCE(NULLIF(excluded.device_name, ''), "
                    "transactions.device_name) END, "
                    "card_last4=excluded.card_last4, "
                    "receipt_url=excluded.receipt_url, raw=excluded.raw, "
                    "camera_id=CASE WHEN excluded.ts_ms != transactions.ts_ms "
                    "OR :replace_evidence = 1 "
                    "THEN excluded.camera_id ELSE COALESCE(excluded.camera_id, "
                    "transactions.camera_id) END, "
                    "thumbnail_path=CASE WHEN excluded.ts_ms != transactions.ts_ms "
                    "OR :replace_evidence = 1 "
                    "THEN excluded.thumbnail_path ELSE COALESCE(excluded.thumbnail_path, "
                    "transactions.thumbnail_path) END "
                    "WHERE excluded.updated_ts_ms >= transactions.updated_ts_ms",
                    values,
                )
                if protect_identity_mismatch and existing is None:
                    # A transaction first persisted by work from a superseded
                    # console was not present when the switch took its reset
                    # snapshot. Retire it now so later remapping stays isolated.
                    self._db.execute(
                        "INSERT OR IGNORE INTO protect_evidence_retired "
                        "(transaction_id) VALUES (?)",
                        (txn["id"],),
                    )
                current = self._db.execute(
                    "SELECT camera_id, ts_ms, status, location_id, device_id, "
                    "device_name, card_last4, thumbnail_path "
                    "FROM transactions WHERE id = ?",
                    (txn["id"],),
                ).fetchone()
                filter_membership_changed = bool(
                    existing
                    and current
                    and applied.rowcount == 1
                    and any(
                        existing[field] != current[field]
                        for field in (
                            "status",
                            "location_id",
                            "device_id",
                            "device_name",
                            "card_last4",
                        )
                    )
                )
                if filter_membership_changed:
                    # Search membership changed inside an existing rowid
                    # boundary. Expire filtered tokens instead of letting an
                    # OFFSET page repeat or skip a row; unfiltered tokens are
                    # unaffected because every retained row still belongs.
                    self._db.execute(
                        "DELETE FROM transaction_feed_snapshots "
                        "WHERE filter_signature != ''"
                    )
                timestamp_changed = bool(
                    existing
                    and current
                    and applied.rowcount == 1
                    and int(existing["ts_ms"]) != int(current["ts_ms"])
                )
                order_changed = bool(
                    applied.rowcount == 1
                    and current
                    and (existing is None or timestamp_changed)
                )
                if order_changed:
                    self._db.execute(
                        "UPDATE transaction_feed_state "
                        "SET order_revision = order_revision + 1 "
                        "WHERE singleton = 1"
                    )
                    if timestamp_changed:
                        revision = self._db.execute(
                            "SELECT order_revision FROM transaction_feed_state "
                            "WHERE singleton = 1"
                        ).fetchone()["order_revision"]
                        self._db.execute(
                            "INSERT INTO transaction_feed_order_history "
                            "(transaction_id, order_revision, ts_ms) VALUES (?, ?, ?)",
                            (txn["id"], revision, int(existing["ts_ms"])),
                        )
                        self._prune_transaction_snapshots_locked(time.time())
                if (
                    existing
                    and existing["thumbnail_path"]
                    and current
                    and current["thumbnail_path"] != existing["thumbnail_path"]
                ):
                    superseded_thumbnail = existing["thumbnail_path"]
                # Evidence changed when the camera or the sale time moved; a
                # changed job must retry immediately instead of waiting out a
                # backoff earned by different evidence.
                evidence_changed = bool(
                    existing
                    and current
                    and applied.rowcount == 1
                    and (
                        replace_evidence
                        or existing["camera_id"] != current["camera_id"]
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
                # Backfilled sales completed before alarm activation must
                # never fire an alarm.
                activation = self._db.execute(
                    "SELECT value, encrypted FROM settings WHERE key = ?",
                    (ALARM_ENABLED_AFTER_SETTING,),
                ).fetchone()
                try:
                    enabled_after_ms = (
                        int(activation["value"])
                        if activation is not None and not activation["encrypted"]
                        else None
                    )
                except (TypeError, ValueError):
                    enabled_after_ms = None

                # A first-seen completed payment is historical according to
                # its sale time. Once a pending payment is already known, its
                # accepted Square update version is the completion boundary.
                # Rejected stale versions never get a suppression boundary.
                completion_reference_ms = None
                if (
                    applied.rowcount == 1
                    and str(txn.get("status", "")).upper() == "COMPLETED"
                ):
                    if existing is None:
                        completion_reference_ms = int(txn["ts_ms"])
                    elif str(existing["status"]).upper() != "COMPLETED":
                        completion_reference_ms = int(values["updated_ts_ms"])
                if (
                    enabled_after_ms is not None
                    and completion_reference_ms is not None
                    and completion_reference_ms < enabled_after_ms
                ):
                    self._db.execute(
                        "UPDATE transactions SET alarm_state = ?, "
                        "alarm_claim_token = NULL, alarm_claimed_at = NULL "
                        "WHERE id = ? AND alarm_state != ?",
                        (ALARM_SENT, txn["id"], ALARM_SENT),
                    )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        if superseded_thumbnail:
            try:
                self._unlink_thumbnail_if_unreferenced(superseded_thumbnail)
            except Exception as exc:
                # Evidence replacement already committed. Cleanup failure must
                # not turn a durable Square update into an API/sync failure.
                logger.warning(
                    "Could not delete superseded thumbnail %r: %s",
                    superseded_thumbnail,
                    exc,
                )
        return existing is None

    def _unlink_thumbnail_if_unreferenced(self, thumbnail_path: str) -> bool:
        """Delete a local thumbnail only while no transaction references it."""
        relative_path = Path(thumbnail_path)
        if relative_path.name != thumbnail_path:
            logger.warning(
                "Refusing to delete non-local thumbnail path %r", thumbnail_path
            )
            return False
        path = self.thumbnail_dir / relative_path
        if path.is_symlink():
            logger.warning("Refusing to delete symlink thumbnail %r", thumbnail_path)
            return False

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                referenced = self._db.execute(
                    "SELECT 1 FROM transactions WHERE thumbnail_path = ? LIMIT 1",
                    (thumbnail_path,),
                ).fetchone()
                if referenced:
                    self._db.commit()
                    return False
                path.unlink(missing_ok=True)
                self._db.commit()
                return True
            except Exception:
                self._db.rollback()
                raise

    def requeue_missing_thumbnail(
        self,
        txn_id: str,
        expected_path: str,
        *,
        expected_merchant_id: str | None = None,
        expected_environment: str | None = None,
        expected_account_revision: str | None = None,
    ) -> bool:
        """Clear a vanished file reference and schedule immediate recapture."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._assert_square_merchant_locked(expected_merchant_id)
                self._assert_square_environment_locked(expected_environment)
                self._assert_square_account_revision_locked(
                    expected_account_revision
                )
                if self._thumbnail_file_exists(expected_path):
                    self._db.commit()
                    return False
                cursor = self._db.execute(
                    "UPDATE transactions SET thumbnail_path = NULL "
                    "WHERE id = ? AND thumbnail_path = ?",
                    (txn_id, expected_path),
                )
                if cursor.rowcount != 1:
                    self._db.commit()
                    return False
                txn = self._db.execute(
                    "SELECT location_id, device_id FROM transactions WHERE id = ?",
                    (txn_id,),
                ).fetchone()
                mapping = (
                    self._camera_for_location_locked(
                        txn["location_id"], txn["device_id"]
                    )
                    if txn
                    else None
                )
                camera_id = mapping["camera_id"] if mapping else None
                self._db.execute(
                    "UPDATE transactions SET camera_id = ? WHERE id = ?",
                    (camera_id, txn_id),
                )
                if camera_id:
                    self._db.execute(
                        "INSERT INTO thumbnail_retries (transaction_id) VALUES (?) "
                        "ON CONFLICT(transaction_id) DO UPDATE SET attempts = 0, "
                        "next_attempt_at = 0, lease_token = NULL, "
                        "lease_expires_at = NULL, last_error = ''",
                        (txn_id,),
                    )
                else:
                    self._db.execute(
                        "DELETE FROM thumbnail_retries WHERE transaction_id = ?",
                        (txn_id,),
                    )
                self._db.commit()
                return True
            except Exception:
                self._db.rollback()
                raise

    def queue_depths(self) -> dict:
        """Pending work counts for the status dashboard."""
        with self._lock:
            thumbs = self._db.execute(
                "SELECT COUNT(*) AS n FROM thumbnail_retries"
            ).fetchone()["n"]
            alarms = self._db.execute(
                "SELECT COUNT(*) AS n FROM transactions "
                "WHERE UPPER(status) = 'COMPLETED' AND alarm_state = ?",
                (ALARM_IDLE,),
            ).fetchone()["n"]
        return {"thumbnails_pending": thumbs, "alarms_pending": alarms}

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

    def has_due_thumbnail_retries(self, *, now: float | None = None) -> bool:
        """Return whether an unleased thumbnail job is immediately runnable."""
        due_at = time.time() if now is None else float(now)
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM thumbnail_retries r "
                "JOIN transactions t ON t.id = r.transaction_id "
                "WHERE t.camera_id IS NOT NULL AND t.thumbnail_path IS NULL "
                "AND r.next_attempt_at <= ? "
                "AND (r.lease_token IS NULL OR r.lease_expires_at <= ?) "
                "LIMIT 1",
                (due_at, due_at),
            ).fetchone()
        return row is not None

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

    def _delete_transaction_snapshots_locked(self, snapshot_ids: list[int]) -> None:
        if not snapshot_ids:
            return
        self._db.executemany(
            "DELETE FROM transaction_feed_snapshots WHERE id = ?",
            ((snapshot_id,) for snapshot_id in snapshot_ids),
        )

    def _trim_transaction_order_history_locked(
        self, keep_snapshot_id: int | None = None
    ) -> bool:
        """Retain only history needed by bounded, active feed snapshots."""
        keep_retained = True
        while True:
            oldest = self._db.execute(
                "SELECT id, order_revision FROM transaction_feed_snapshots "
                "ORDER BY order_revision, last_accessed_at, id LIMIT 1"
            ).fetchone()
            if oldest is None:
                self._db.execute("DELETE FROM transaction_feed_order_history")
                return keep_retained

            self._db.execute(
                "DELETE FROM transaction_feed_order_history "
                "WHERE order_revision <= ?",
                (oldest["order_revision"],),
            )
            history_count = self._db.execute(
                "SELECT COUNT(*) AS count FROM transaction_feed_order_history"
            ).fetchone()["count"]
            if history_count <= MAX_TRANSACTION_ORDER_HISTORY:
                return keep_retained

            # Too many timestamp corrections are still needed by the oldest
            # snapshot. Expire it, then reclaim versions no remaining token
            # can observe. This keeps the history table hard bounded.
            self._delete_transaction_snapshots_locked([oldest["id"]])
            if oldest["id"] == keep_snapshot_id:
                keep_retained = False

    def _prune_transaction_snapshots_locked(
        self,
        now: float,
        keep_snapshot_id: int | None = None,
    ) -> bool:
        """Expire idle/LRU snapshots and bound retained timestamp history."""
        rows = self._db.execute(
            "SELECT id, last_accessed_at FROM transaction_feed_snapshots "
            "ORDER BY last_accessed_at DESC, id DESC"
        ).fetchall()
        cutoff = now - TRANSACTION_SNAPSHOT_TTL_SECONDS
        eligible = [row for row in rows if row["last_accessed_at"] >= cutoff]
        retained_ids: list[int] = []
        if keep_snapshot_id is not None and any(
            row["id"] == keep_snapshot_id for row in eligible
        ):
            retained_ids.append(keep_snapshot_id)
        for row in eligible:
            if row["id"] in retained_ids:
                continue
            if len(retained_ids) >= MAX_TRANSACTION_SNAPSHOTS:
                break
            retained_ids.append(row["id"])
        retained = set(retained_ids)
        self._delete_transaction_snapshots_locked(
            [row["id"] for row in rows if row["id"] not in retained]
        )
        keep_retained = (
            keep_snapshot_id is None or keep_snapshot_id in retained
        )
        history_kept = self._trim_transaction_order_history_locked(
            keep_snapshot_id=keep_snapshot_id
        )
        return keep_retained and history_kept

    def list_transactions_page(
        self,
        limit: int = 50,
        offset: int = 0,
        snapshot_id: int | None = None,
        *,
        query: str = "",
        status: str = "",
    ) -> tuple[list[dict], int]:
        """List one filter-bound page in a durable chronological snapshot."""
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        filter_signature, filter_sql, filter_parameters = _transaction_filter(
            query, status
        )
        expired = False
        filter_mismatch = False
        rows: list[sqlite3.Row] = []
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                snapshot = None
                if snapshot_id is None:
                    self._prune_transaction_snapshots_locked(now)
                    state = self._db.execute(
                        "SELECT order_revision FROM transaction_feed_state "
                        "WHERE singleton = 1"
                    ).fetchone()
                    boundary = self._db.execute(
                        "SELECT COALESCE(MAX(rowid), 0) AS rowid FROM transactions"
                    ).fetchone()
                    revision = int(state["order_revision"])
                    rowid_boundary = int(boundary["rowid"])
                    snapshot = self._db.execute(
                        "SELECT * FROM transaction_feed_snapshots "
                        "WHERE order_revision = ? AND rowid_boundary = ? "
                        "AND filter_signature = ?",
                        (revision, rowid_boundary, filter_signature),
                    ).fetchone()
                    if snapshot is None:
                        cursor = self._db.execute(
                            "INSERT INTO transaction_feed_snapshots "
                            "(order_revision, rowid_boundary, filter_signature, "
                            "created_at, last_accessed_at) VALUES (?, ?, ?, ?, ?)",
                            (revision, rowid_boundary, filter_signature, now, now),
                        )
                        snapshot_id = int(cursor.lastrowid)
                        snapshot = self._db.execute(
                            "SELECT * FROM transaction_feed_snapshots WHERE id = ?",
                            (snapshot_id,),
                        ).fetchone()
                    else:
                        snapshot_id = int(snapshot["id"])
                else:
                    snapshot_id = max(
                        0,
                        min(int(snapshot_id), (1 << 63) - 1),
                    )
                    snapshot = self._db.execute(
                        "SELECT * FROM transaction_feed_snapshots WHERE id = ?",
                        (snapshot_id,),
                    ).fetchone()
                    if (
                        snapshot is None
                        or snapshot["last_accessed_at"]
                        < now - TRANSACTION_SNAPSHOT_TTL_SECONDS
                    ):
                        if snapshot is not None:
                            self._delete_transaction_snapshots_locked([snapshot_id])
                        self._prune_transaction_snapshots_locked(now)
                        expired = True
                    elif snapshot["filter_signature"] != filter_signature:
                        filter_mismatch = True

                if not expired and not filter_mismatch:
                    self._db.execute(
                        "UPDATE transaction_feed_snapshots "
                        "SET last_accessed_at = ? WHERE id = ?",
                        (now, snapshot_id),
                    )
                    if not self._prune_transaction_snapshots_locked(
                        now, keep_snapshot_id=snapshot_id
                    ):
                        expired = True

                if not expired and not filter_mismatch:
                    has_later_timestamp_change = self._db.execute(
                        "SELECT 1 FROM transaction_feed_order_history "
                        "WHERE order_revision > ? LIMIT 1",
                        (snapshot["order_revision"],),
                    ).fetchone()
                    if has_later_timestamp_change:
                        rows = self._db.execute(
                            "SELECT t.*, COALESCE(r.attempts, 0) AS thumbnail_retry_attempts "
                            "FROM transactions t LEFT JOIN thumbnail_retries r "
                            "ON r.transaction_id = t.id "
                            "WHERE t.rowid <= ? " + filter_sql + " "
                            "ORDER BY COALESCE((SELECT h.ts_ms "
                            "FROM transaction_feed_order_history h "
                            "WHERE h.transaction_id = t.id "
                            "AND h.order_revision > ? "
                            "ORDER BY h.order_revision LIMIT 1), t.ts_ms) DESC, "
                            "t.id DESC LIMIT ? OFFSET ?",
                            (
                                snapshot["rowid_boundary"],
                                *filter_parameters,
                                snapshot["order_revision"],
                                limit,
                                offset,
                            ),
                        ).fetchall()
                    else:
                        rows = self._db.execute(
                            "SELECT t.*, COALESCE(r.attempts, 0) AS thumbnail_retry_attempts "
                            "FROM transactions t LEFT JOIN thumbnail_retries r "
                            "ON r.transaction_id = t.id WHERE t.rowid <= ? "
                            + filter_sql + " "
                            "ORDER BY t.ts_ms DESC, t.id DESC LIMIT ? OFFSET ?",
                            (
                                snapshot["rowid_boundary"],
                                *filter_parameters,
                                limit,
                                offset,
                            ),
                        ).fetchall()
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        if expired:
            raise TransactionSnapshotExpired("Transaction page snapshot expired")
        if filter_mismatch:
            raise TransactionSnapshotFilterMismatch(
                "Transaction page snapshot belongs to different filters"
            )
        return [dict(r) for r in rows], int(snapshot_id)

    def list_transactions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        rows, _snapshot_id = self.list_transactions_page(limit, offset)
        return rows

    def get_observed_devices(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT devices.location_id, devices.device_id, "
                "COALESCE((SELECT named.device_name FROM transactions AS named "
                "WHERE named.location_id = devices.location_id "
                "AND named.device_id = devices.device_id AND named.device_name != '' "
                "ORDER BY named.ts_ms DESC, named.id DESC LIMIT 1), '') AS device_name "
                "FROM (SELECT DISTINCT location_id, device_id FROM transactions "
                "WHERE device_id != '') AS devices "
                "ORDER BY devices.location_id, device_name, devices.device_id"
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

    def latest_transaction_updated_ts(self, location_id: str | None = None) -> int | None:
        with self._lock:
            if location_id is None:
                row = self._db.execute(
                    "SELECT MAX(updated_ts_ms) AS ts FROM transactions"
                ).fetchone()
            else:
                row = self._db.execute(
                    "SELECT MAX(updated_ts_ms) AS ts FROM transactions "
                    "WHERE location_id = ?",
                    (location_id,),
                ).fetchone()
        return row["ts"] if row and row["ts"] is not None else None

    # -- Square polling -----------------------------------------------------

    def get_square_poll_watermark(self, location_id: str) -> int | None:
        """Return the last successfully completed poll boundary for a location."""
        with self._lock:
            row = self._db.execute(
                "SELECT polled_through_ms FROM square_poll_watermarks "
                "WHERE location_id = ?",
                (location_id,),
            ).fetchone()
        return int(row["polled_through_ms"]) if row else None

    def advance_square_poll_watermark(
        self, location_id: str, polled_through_ms: int
    ) -> None:
        """Monotonically advance a location after its poll completes."""
        polled_through_ms = int(polled_through_ms)
        if polled_through_ms < 0:
            raise ValueError("Square poll watermark cannot be negative")
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO square_poll_watermarks "
                "(location_id, polled_through_ms) VALUES (?, ?) "
                "ON CONFLICT(location_id) DO UPDATE SET polled_through_ms = "
                "MAX(square_poll_watermarks.polled_through_ms, "
                "excluded.polled_through_ms)",
                (location_id, polled_through_ms),
            )

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
