"""Atomic camera-evidence file write tests."""

from __future__ import annotations

import os
import threading

import pytest

from app.sync import write_thumbnail


def test_concurrent_thumbnail_writes_never_publish_mixed_bytes(
    tmp_path, monkeypatch
):
    target = tmp_path / "evidence.jpg"
    first_half_written = threading.Event()
    release_first_writer = threading.Event()
    original_write = os.write
    writer_state = threading.local()
    errors: list[BaseException] = []

    def split_first_writer(fd, data):
        if (
            threading.current_thread().name == "first-thumbnail-writer"
            and not getattr(writer_state, "split", False)
        ):
            writer_state.split = True
            written = original_write(fd, data[: len(data) // 2])
            first_half_written.set()
            assert release_first_writer.wait(timeout=5)
            return written
        return original_write(fd, data)

    def write_in_thread(image: bytes) -> None:
        try:
            write_thumbnail(target, image)
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr("app.sync.os.write", split_first_writer)
    first_image = b"A" * 10_000
    second_image = b"B" * 10_000
    first = threading.Thread(
        target=write_in_thread,
        args=(first_image,),
        name="first-thumbnail-writer",
    )
    second = threading.Thread(
        target=write_in_thread,
        args=(second_image,),
        name="second-thumbnail-writer",
    )

    first.start()
    try:
        assert first_half_written.wait(timeout=5)
        second.start()
        second.join(timeout=5)
        assert not second.is_alive()
    finally:
        release_first_writer.set()
        first.join(timeout=5)
        if second.is_alive():
            second.join(timeout=5)

    assert not first.is_alive()
    assert errors == []
    assert target.read_bytes() == first_image
    assert target.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.glob(f".{target.name}.*.tmp")) == []


def test_failed_thumbnail_write_preserves_published_file(tmp_path, monkeypatch):
    target = tmp_path / "evidence.jpg"
    published = b"complete-camera-evidence"
    target.write_bytes(published)
    original_write = os.write
    calls = 0

    def fail_after_partial_write(fd, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(fd, data[: len(data) // 2])
        raise OSError("simulated disk failure")

    monkeypatch.setattr("app.sync.os.write", fail_after_partial_write)

    with pytest.raises(OSError, match="simulated disk failure"):
        write_thumbnail(target, b"replacement-camera-evidence")

    assert target.read_bytes() == published
    assert list(tmp_path.glob(f".{target.name}.*.tmp")) == []


def test_startup_sweeps_orphaned_temp_files(tmp_path):
    from app.store import Store

    data_dir = tmp_path / "data"
    thumb_dir = data_dir / "thumbnails"
    thumb_dir.mkdir(parents=True)
    orphan = thumb_dir / ".evidence.jpg.abc123.tmp"
    orphan.write_bytes(b"partial")
    keeper = thumb_dir / "evidence.jpg"
    keeper.write_bytes(b"published")

    store = Store(data_dir)
    store.close()

    assert not orphan.exists()
    assert keeper.read_bytes() == b"published"
