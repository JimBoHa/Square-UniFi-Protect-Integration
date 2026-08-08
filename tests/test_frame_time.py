"""UniFi burned-in frame timestamp measurement tests."""

from __future__ import annotations

import io
from datetime import datetime, timedelta

import pytest
from PIL import Image, ImageDraw, ImageFont

from app import frame_time, sync
from app.store import (
    FRAME_OFFSET_MEASURED,
    FRAME_OFFSET_PENDING,
    FRAME_OFFSET_UNAVAILABLE,
    Store,
)
from app.thumbnail_storage import ThumbnailPolicy, policy_values


CAMERA_ID = "cam1aaaaaaaaaaaaaaaaaaaaa"


def _local_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _overlay_frame(displayed: datetime) -> bytes:
    image = Image.new("RGB", (1280, 720), (65, 85, 95))
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=48)
    text = f"{displayed.strftime('%Y-%m-%d %I:%M:%S %p')} | Test Camera"
    bounds = draw.textbbox((20, 10), text, font=font)
    draw.rectangle(
        (8, 4, bounds[2] + 12, bounds[3] + 7),
        fill=(20, 20, 20),
    )
    draw.text((20, 10), text, font=font, fill="white")
    output = io.BytesIO()
    image.save(output, format="JPEG", quality=95)
    return output.getvalue()


def _txn(transaction_id: str, ts_ms: int, thumbnail_path: str | None) -> dict:
    created_at = datetime.fromtimestamp(ts_ms / 1000).astimezone().isoformat()
    return {
        "id": transaction_id,
        "created_at": created_at,
        "updated_at": created_at,
        "ts_ms": ts_ms,
        "updated_ts_ms": ts_ms,
        "amount": 99,
        "currency": "USD",
        "status": "COMPLETED",
        "location_id": "LOC1",
        "camera_id": CAMERA_ID,
        "thumbnail_path": thumbnail_path,
        "raw": {},
    }


def test_reads_burned_in_seconds_and_preserves_transaction_milliseconds():
    transaction = datetime(2026, 8, 8, 13, 25, 5, 434000)
    displayed = transaction.replace(second=1, microsecond=0)

    analysis = frame_time.analyze_frame_time(
        _overlay_frame(displayed),
        _local_ms(transaction),
    )

    assert analysis.error == ""
    assert analysis.measurement is not None
    assert analysis.measurement.frame_ts_ms == _local_ms(displayed)
    assert analysis.measurement.offset_ms == -4434
    assert analysis.measurement.confidence > 0


def test_learned_templates_classify_digits_absent_from_current_prefix():
    training_time = datetime(2026, 8, 8, 13, 47, 30)
    training = frame_time.extract_frame_glyphs(
        _overlay_frame(training_time),
        _local_ms(training_time),
    )
    transaction = datetime(2026, 1, 1, 1, 20, 50, 250000)
    displayed = transaction.replace(second=47, microsecond=0)

    without_templates = frame_time.analyze_frame_time(
        _overlay_frame(displayed),
        _local_ms(transaction),
    )
    with_templates = frame_time.analyze_frame_time(
        _overlay_frame(displayed),
        _local_ms(transaction),
        training.learned_templates,
    )

    assert without_templates.measurement is None
    assert with_templates.measurement is not None
    assert with_templates.measurement.offset_ms == -3250


def test_nearest_minute_handles_frame_before_transaction_boundary():
    training_time = datetime(2026, 8, 8, 13, 58, 30)
    templates = frame_time.extract_frame_glyphs(
        _overlay_frame(training_time),
        _local_ms(training_time),
    ).learned_templates
    transaction = datetime(2026, 8, 8, 14, 0, 1, 500000)
    displayed = transaction - timedelta(seconds=3, milliseconds=500)

    analysis = frame_time.analyze_frame_time(
        _overlay_frame(displayed),
        _local_ms(transaction),
        templates,
    )

    assert analysis.measurement is not None
    assert analysis.measurement.frame_ts_ms == _local_ms(displayed)
    assert analysis.measurement.offset_ms == -3500


def test_template_learning_skips_fields_that_can_change_within_offset_window():
    transaction = datetime(2026, 8, 8, 13, 0, 5)

    stable_prefix = frame_time._stable_timestamp_prefix_digits(
        _local_ms(transaction)
    )

    # A valid -8 second frame belongs to 12:59. Hour and minute positions
    # cannot safely teach labels from the requested Square wall time.
    assert stable_prefix[8:12] == (None, None, None, None)


def test_missing_overlay_fails_closed_without_inventing_offset():
    output = io.BytesIO()
    Image.new("RGB", (640, 360), "black").save(output, format="JPEG")

    analysis = frame_time.analyze_frame_time(
        output.getvalue(),
        _local_ms(datetime(2026, 8, 8, 13, 25, 5)),
    )

    assert analysis.measurement is None
    assert "overlay was not detected" in analysis.error


def test_new_capture_persists_measurement_before_thumbnail_compression(tmp_path):
    store = Store(tmp_path / "data")
    store.set_camera_mapping("LOC1", CAMERA_ID, "Counter")
    store.update_thumbnail_storage_settings(
        policy_values(
            ThumbnailPolicy(
                compression_enabled=True,
                jpeg_quality=60,
                max_dimension=320,
                retention_days=0,
                max_storage_mib=0,
                revision=0,
            )
        )
    )
    transaction = datetime(2026, 8, 8, 13, 25, 5, 434000)
    displayed = transaction.replace(second=1, microsecond=0)

    class Protect:
        def get_snapshot(self, camera_id, ts_ms=None):
            assert camera_id == CAMERA_ID
            assert ts_ms == _local_ms(transaction)
            return _overlay_frame(displayed)

    try:
        sync.ingest_payment(
            store,
            {
                "id": "NEW-MEASURED",
                "created_at": transaction.astimezone().isoformat(),
                "updated_at": transaction.astimezone().isoformat(),
                "amount_money": {"amount": 99, "currency": "USD"},
                "status": "COMPLETED",
                "location_id": "LOC1",
            },
            Protect(),
        )
        stored = store.get_transaction("NEW-MEASURED")
        templates = store.get_frame_digit_templates(CAMERA_ID)
        with Image.open(store.thumbnail_dir / stored["thumbnail_path"]) as thumbnail:
            stored_dimensions = thumbnail.size
    finally:
        store.close()

    assert stored["frame_offset_status"] == FRAME_OFFSET_MEASURED
    assert stored["frame_offset_ms"] == -4434
    assert stored["thumbnail_path"]
    assert max(stored_dimensions) <= 320
    assert templates


def test_backfill_learns_batch_before_measuring_and_survives_restart(tmp_path):
    data_dir = tmp_path / "data"
    store = Store(data_dir)
    transactions = (
        datetime(2026, 8, 8, 13, 47, 30, 400000),
        datetime(2026, 1, 1, 1, 20, 50, 250000),
    )
    displayed = (
        transactions[0].replace(second=28, microsecond=0),
        transactions[1].replace(second=47, microsecond=0),
    )
    for index, (transaction, frame) in enumerate(zip(transactions, displayed)):
        name = f"FRAME-{index}.jpg"
        sync.write_thumbnail(store.thumbnail_dir / name, _overlay_frame(frame))
        store.upsert_transaction(_txn(f"FRAME-{index}", _local_ms(transaction), name))

    try:
        result = frame_time.backfill_frame_offsets(
            store,
            frame_time_path_reader,
        )
        rows = [store.get_transaction(f"FRAME-{index}") for index in range(2)]
        template_digits = store.get_frame_digit_templates(CAMERA_ID)
    finally:
        store.close()

    reopened = Store(data_dir)
    try:
        durable = [
            reopened.get_transaction(f"FRAME-{index}") for index in range(2)
        ]
    finally:
        reopened.close()

    assert result["measured_count"] == 2
    assert [row["frame_offset_status"] for row in rows] == [
        FRAME_OFFSET_MEASURED,
        FRAME_OFFSET_MEASURED,
    ]
    assert [row["frame_offset_ms"] for row in rows] == [-2400, -3250]
    assert "4" in template_digits and "7" in template_digits
    assert [row["frame_offset_ms"] for row in durable] == [-2400, -3250]


def test_unreadable_overlay_stops_after_bounded_attempts(tmp_path):
    store = Store(tmp_path / "data")
    output = io.BytesIO()
    Image.new("RGB", (640, 360), "black").save(output, format="JPEG")
    sync.write_thumbnail(store.thumbnail_dir / "blank.jpg", output.getvalue())
    store.upsert_transaction(_txn("BLANK", 10_000, "blank.jpg"))
    try:
        statuses = []
        for _ in range(frame_time.FRAME_OFFSET_MAX_ATTEMPTS):
            frame_time.backfill_frame_offsets(store, frame_time_path_reader)
            statuses.append(store.get_transaction("BLANK")["frame_offset_status"])
        final_run = frame_time.backfill_frame_offsets(
            store,
            frame_time_path_reader,
        )
    finally:
        store.close()

    assert statuses == [
        FRAME_OFFSET_PENDING,
        FRAME_OFFSET_PENDING,
        FRAME_OFFSET_UNAVAILABLE,
    ]
    assert final_run["processed_count"] == 0


def test_thumbnail_retention_keeps_durable_measured_offset(tmp_path):
    store = Store(tmp_path / "data")
    row = _txn("RETIRED-MEASURED", 10_000, "retired.jpg")
    row.update(
        {
            "frame_ts_ms": 8_000,
            "frame_offset_ms": -2_000,
            "frame_offset_confidence": 9_000,
            "frame_offset_status": FRAME_OFFSET_MEASURED,
        }
    )
    sync.write_thumbnail(store.thumbnail_dir / "retired.jpg", b"jpeg")
    store.upsert_transaction(row)
    try:
        assert store.retire_thumbnail(
            "RETIRED-MEASURED",
            "retired.jpg",
            "age",
            retired_at_ms=20_000,
        )
        retired = store.get_transaction("RETIRED-MEASURED")
    finally:
        store.close()

    assert retired["thumbnail_path"] is None
    assert retired["frame_offset_status"] == FRAME_OFFSET_MEASURED
    assert retired["frame_ts_ms"] == 8_000
    assert retired["frame_offset_ms"] == -2_000


def frame_time_path_reader(directory, name):
    return (directory / name).read_bytes()


def test_template_store_rejects_malformed_glyphs_and_stays_bounded(tmp_path):
    store = Store(tmp_path / "data")
    try:
        with pytest.raises(ValueError, match="Invalid frame template glyph"):
            store.add_frame_digit_templates(
                CAMERA_ID,
                {"2": [b"x" * frame_time.NORMALIZED_GLYPH_BYTES]},
            )
        for index in range(25):
            glyph = bytearray(frame_time.NORMALIZED_GLYPH_BYTES)
            glyph[index] = 1
            store.add_frame_digit_templates(CAMERA_ID, {"2": [bytes(glyph)]})
        templates = store.get_frame_digit_templates(CAMERA_ID)
    finally:
        store.close()

    assert len(templates["2"]) == 16


def test_retry_rejects_inconsistent_measured_frame_time(tmp_path):
    store = Store(tmp_path / "data")
    store.upsert_transaction(_txn("RETRY-OFFSET", 10_000, None))
    job = store.claim_thumbnail_retries(1, 10, now=0)[0]
    try:
        with pytest.raises(ValueError, match="Frame timestamp and offset disagree"):
            store.complete_thumbnail_retry(
                "RETRY-OFFSET",
                job["lease_token"],
                CAMERA_ID,
                10_000,
                "retry.jpg",
                frame_ts_ms=9_000,
                frame_offset_ms=-999,
                frame_offset_status=FRAME_OFFSET_MEASURED,
            )
    finally:
        store.close()


def test_transaction_api_exposes_measurement_without_ocr_diagnostics(authed):
    store = authed.app.state.store
    transaction = datetime(2026, 8, 8, 13, 25, 5, 434000)
    ts_ms = _local_ms(transaction)
    row = _txn("VISIBLE-OFFSET", ts_ms, "visible.jpg")
    row.update(
        {
            "frame_ts_ms": ts_ms - 4434,
            "frame_offset_ms": -4434,
            "frame_offset_confidence": 9000,
            "frame_offset_status": FRAME_OFFSET_MEASURED,
            "frame_offset_error": "must stay private",
        }
    )
    sync.write_thumbnail(store.thumbnail_dir / "visible.jpg", b"jpeg")
    store.upsert_transaction(row)

    response = authed.get("/api/transactions")

    assert response.status_code == 200
    payload = response.json()[0]
    assert payload["frame_ts_ms"] == ts_ms - 4434
    assert payload["frame_offset_ms"] == -4434
    assert payload["frame_offset_status"] == FRAME_OFFSET_MEASURED
    assert "frame_offset_confidence" not in payload
    assert "frame_offset_error" not in payload
