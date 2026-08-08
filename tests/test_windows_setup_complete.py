"""Tests for the transport-independent Windows setup completion probe."""

import sqlite3

from scripts.windows import setup_complete as setup_probe


def _settings_database(tmp_path, value=None):
    database = tmp_path / "spi.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        if value is not None:
            connection.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                ("admin.password_hash", value),
            )
    return tmp_path


def _users_database(tmp_path, users=()):
    database = tmp_path / "spi.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE users ("
            "role TEXT NOT NULL, enabled INTEGER NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO users (role, enabled) VALUES (?, ?)", users
        )
    return tmp_path


def test_setup_probe_is_false_before_database_exists(tmp_path):
    assert setup_probe.setup_complete(tmp_path) is False


def test_setup_probe_is_false_before_admin_transaction(tmp_path):
    assert setup_probe.setup_complete(_settings_database(tmp_path)) is False


def test_setup_probe_reads_committed_admin_state_without_http(tmp_path):
    assert setup_probe.setup_complete(_settings_database(tmp_path, "hash")) is True


def test_setup_probe_reads_enabled_administrator_account(tmp_path):
    data_dir = _users_database(
        tmp_path,
        (("viewer", 1), ("admin", 0), ("admin", 1)),
    )
    assert setup_probe.setup_complete(data_dir) is True


def test_setup_probe_rejects_viewers_and_disabled_administrators(tmp_path):
    data_dir = _users_database(tmp_path, (("viewer", 1), ("admin", 0)))
    assert setup_probe.setup_complete(data_dir) is False
