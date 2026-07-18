"""Tests for environment handling in the ``python -m app`` runner."""

from __future__ import annotations

import app.__main__ as runner
import app.main as main_module


def test_tls_forces_secure_session_cookies(tmp_path, monkeypatch):
    sentinel_app = object()
    captured = {}

    monkeypatch.setenv("SPI_TLS", "1")
    monkeypatch.setenv("SPI_COOKIE_SECURE", "0")
    monkeypatch.setenv("SPI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(main_module, "create_app", lambda data_dir: sentinel_app)
    monkeypatch.setattr(runner, "uvicorn_tls_kwargs", lambda *_: {"ssl_keyfile": "key"})
    monkeypatch.setattr(
        runner.uvicorn,
        "run",
        lambda app, **kwargs: captured.update(app=app, **kwargs),
    )

    runner.main()

    assert captured["app"] is sentinel_app
    assert captured["ssl_keyfile"] == "key"
    assert runner.os.environ["SPI_COOKIE_SECURE"] == "1"
