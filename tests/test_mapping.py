"""POS-device camera mapping and schema migration tests."""

import sqlite3

from app.store import Store

CAM1 = "cam1aaaaaaaaaaaaaaaaaaaaa"
CAM2 = "cam2bbbbbbbbbbbbbbbbbbbbb"
CAM_WILDCARD = "cam9ccccccccccccccccccccc"


def test_legacy_location_mapping_migrates_to_device_aware_schema(tmp_path):
    data_dir = tmp_path / "legacy"
    data_dir.mkdir()
    db = sqlite3.connect(data_dir / "spi.db")
    db.executescript(
        """
        CREATE TABLE camera_map (
            location_id TEXT PRIMARY KEY,
            camera_id TEXT NOT NULL,
            camera_name TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE transactions (
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
        """
    )
    db.execute(
        "INSERT INTO camera_map (location_id, camera_id, camera_name) VALUES (?, ?, ?)",
        ("LOC1", CAM1, "Front Counter"),
    )
    db.execute(
        """
        INSERT INTO transactions (
            id, created_at, ts_ms, amount, currency, status, location_id,
            card_last4, receipt_url, camera_id, thumbnail_path, raw
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "PAY_LEGACY",
            "2026-07-16T15:00:00.000Z",
            1784239200000,
            500,
            "USD",
            "COMPLETED",
            "LOC1",
            "4242",
            "https://square.example/legacy",
            CAM1,
            "PAY_LEGACY.jpg",
            '{"device_details":{"device_id":"TERM_LEGACY",'
            '"device_name":"Legacy Register"}}',
        ),
    )
    db.execute(
        """
        INSERT INTO transactions (
            id, created_at, ts_ms, amount, currency, status, location_id,
            card_last4, receipt_url, camera_id, thumbnail_path, raw
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "PAY_MALFORMED",
            "2026-07-16T15:01:00.000Z",
            1784239260000,
            600,
            "USD",
            "COMPLETED",
            "LOC1",
            "1111",
            "https://square.example/malformed",
            CAM1,
            "PAY_MALFORMED.jpg",
            "not valid json",
        ),
    )
    db.commit()
    db.close()
    thumbnail_dir = data_dir / "thumbnails"
    thumbnail_dir.mkdir()
    (thumbnail_dir / "PAY_LEGACY.jpg").write_bytes(b"legacy image")
    (thumbnail_dir / "PAY_MALFORMED.jpg").write_bytes(b"malformed image")

    store = Store(data_dir)
    try:
        assert store.get_camera_mappings() == [
            {
                "location_id": "LOC1",
                "device_id": "",
                "device_name": "",
                "camera_id": CAM1,
                "camera_name": "Front Counter",
            }
        ]
        legacy_txn = store.get_transaction("PAY_LEGACY")
        assert legacy_txn["device_id"] == "TERM_LEGACY"
        assert legacy_txn["device_name"] == "Legacy Register"
        assert legacy_txn["thumbnail_path"] == "PAY_LEGACY.jpg"
        malformed_txn = store.get_transaction("PAY_MALFORMED")
        assert malformed_txn["device_id"] == ""
        assert malformed_txn["device_name"] == ""
        assert malformed_txn["thumbnail_path"] == "PAY_MALFORMED.jpg"

        store.set_camera_mapping(
            "LOC1",
            CAM2,
            "Back Door",
            device_id="TERM_A",
            device_name="Register A",
        )
        store.set_camera_mapping("*", CAM_WILDCARD, "Default Camera")
        assert store.camera_for_location("LOC1", "TERM_A")["camera_id"] == CAM2
        assert store.camera_for_location("LOC1", "UNKNOWN")["camera_id"] == CAM1
        assert store.camera_for_location("LOC2", "UNKNOWN")["camera_id"] == CAM_WILDCARD
    finally:
        store.close()


def test_observed_device_name_uses_newest_nonempty_transaction(tmp_path):
    store = Store(tmp_path / "data")

    def add_transaction(txn_id: str, ts_ms: int, device_name: str) -> None:
        store.upsert_transaction(
            {
                "id": txn_id,
                "created_at": "2026-07-16T15:00:00.000Z",
                "ts_ms": ts_ms,
                "amount": 500,
                "currency": "USD",
                "status": "COMPLETED",
                "location_id": "LOC1",
                "device_id": "TERM_A",
                "device_name": device_name,
            }
        )

    try:
        add_transaction("PAY_OLD", 100, "Zebra Register")
        add_transaction("PAY_NEW", 200, "Alpha Register")
        add_transaction("PAY_EMPTY", 300, "")
        assert store.get_observed_devices() == [
            {
                "location_id": "LOC1",
                "device_id": "TERM_A",
                "device_name": "Alpha Register",
            }
        ]

        add_transaction("PAY_TIE_A", 400, "Register A")
        add_transaction("PAY_TIE_B", 400, "Register B")
        assert store.get_observed_devices()[0]["device_name"] == "Register B"
    finally:
        store.close()
