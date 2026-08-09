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
    refunded_amount INTEGER NOT NULL DEFAULT 0 CHECK (refunded_amount >= 0),
    status TEXT NOT NULL,
    location_id TEXT NOT NULL DEFAULT '',
    device_id TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    card_last4 TEXT NOT NULL DEFAULT '',
    receipt_url TEXT NOT NULL DEFAULT '',
    camera_id TEXT,
    thumbnail_path TEXT,
    note TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
    note_revision INTEGER NOT NULL DEFAULT 0 CHECK (note_revision >= 0),
    thumbnail_bytes INTEGER CHECK (thumbnail_bytes IS NULL OR thumbnail_bytes >= 0),
    thumbnail_policy_revision INTEGER NOT NULL DEFAULT 0,
    thumbnail_retired_at INTEGER,
    thumbnail_retired_reason TEXT NOT NULL DEFAULT '',
    raw TEXT NOT NULL DEFAULT '{}',
    alarm_state TEXT NOT NULL DEFAULT 'idle',
    alarm_claim_token TEXT,
    alarm_claimed_at REAL,
    alarm_delivered_at_ms INTEGER CHECK (
        alarm_delivered_at_ms IS NULL OR alarm_delivered_at_ms >= 0
    )
);
CREATE INDEX IF NOT EXISTS idx_transactions_ts ON transactions (ts_ms DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_status_ts
    ON transactions (status, ts_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_camera_ts
    ON transactions (camera_id, ts_ms DESC, id DESC);
CREATE TABLE IF NOT EXISTS square_poll_watermarks (
    location_id TEXT PRIMARY KEY,
    polled_through_ms INTEGER NOT NULL CHECK (polled_through_ms >= 0)
);
CREATE TABLE IF NOT EXISTS square_webhook_receipts (
    event_key TEXT PRIMARY KEY CHECK (length(event_key) = 64),
    event_type TEXT NOT NULL CHECK (
        event_type IN ('payment.created', 'payment.updated')
    ),
    received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0),
    event_created_at_ms INTEGER CHECK (
        event_created_at_ms IS NULL OR event_created_at_ms >= 0
    )
);
CREATE INDEX IF NOT EXISTS idx_square_webhook_receipts_received
    ON square_webhook_receipts (received_at_ms DESC);
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
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (
        length(username) BETWEEN 1 AND 64 AND username = trim(username)
    ),
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    auth_revision INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at REAL NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS login_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL CHECK (length(username) BETWEEN 1 AND 64),
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    client_ip TEXT NOT NULL CHECK (length(client_ip) BETWEEN 1 AND 128),
    logged_in_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_audit_user
    ON login_audit (user_id, id DESC);
CREATE TRIGGER IF NOT EXISTS login_audit_prevent_update
BEFORE UPDATE ON login_audit
BEGIN
    SELECT RAISE(ABORT, 'login audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS login_audit_prevent_delete
BEFORE DELETE ON login_audit
BEGIN
    SELECT RAISE(ABORT, 'login audit is append-only');
END;
CREATE TABLE IF NOT EXISTS protect_motion_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL CHECK (length(event_key) BETWEEN 1 AND 80),
    camera_id TEXT NOT NULL CHECK (length(camera_id) BETWEEN 1 AND 64),
    camera_name TEXT NOT NULL CHECK (length(camera_name) <= 128),
    event_ts_ms INTEGER NOT NULL CHECK (event_ts_ms >= 0),
    received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0),
    evaluate_after_ms INTEGER NOT NULL CHECK (evaluate_after_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    match_window_ms INTEGER NOT NULL CHECK (
        match_window_ms BETWEEN 1000 AND 300000
    ),
    delivery_method TEXT NOT NULL CHECK (delivery_method IN ('get', 'post')),
    alarm_name TEXT NOT NULL DEFAULT '' CHECK (length(alarm_name) <= 256),
    device_identifiers TEXT NOT NULL DEFAULT '[]' CHECK (
        length(device_identifiers) <= 4096
    ),
    UNIQUE (camera_id, event_key)
);
CREATE INDEX IF NOT EXISTS idx_protect_motion_events_time
    ON protect_motion_events (event_ts_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_protect_motion_events_expiry
    ON protect_motion_events (expires_at_ms);
CREATE TABLE IF NOT EXISTS square_oauth_states (
    state_hash TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_square_oauth_states_expiry
    ON square_oauth_states (expires_at);
