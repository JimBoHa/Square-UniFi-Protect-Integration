"""Command-line runner configuration and transport tests."""

from __future__ import annotations

import pytest

import app.__main__ as runner
import app.main as main_module
from app.__main__ import PORT_ERROR, _parse_listen_port


def test_tls_forces_secure_session_cookies(tmp_path, monkeypatch):
    sentinel_app = object()
    captured = {}

    monkeypatch.setenv("SPI_TLS", "1")
    monkeypatch.setenv("SPI_COOKIE_SECURE", "0")
    monkeypatch.setenv("SPI_DATA_DIR", str(tmp_path))

    def capture_create_app(*, data_dir, bind_host, tls_enabled):
        captured.update(
            create_data_dir=data_dir,
            create_bind_host=bind_host,
            create_tls_enabled=tls_enabled,
        )
        return sentinel_app

    monkeypatch.setattr(main_module, "create_app", capture_create_app)
    monkeypatch.setattr(runner, "uvicorn_tls_kwargs", lambda *_: {"ssl_keyfile": "key"})
    monkeypatch.setattr(
        runner.uvicorn,
        "run",
        lambda app, **kwargs: captured.update(app=app, **kwargs),
    )

    runner.main()

    assert captured["app"] is sentinel_app
    assert captured["ssl_keyfile"] == "key"
    assert captured["create_bind_host"] == "127.0.0.1"
    assert captured["create_tls_enabled"] is True
    assert runner.os.environ["SPI_COOKIE_SECURE"] == "1"


@pytest.mark.parametrize(
    ("value", "expected"),
    (("1", 1), ("8000", 8000), ("65535", 65535), ("00080", 80)),
)
def test_parse_listen_port_accepts_valid_decimal_values(value, expected):
    assert _parse_listen_port(value) == expected


@pytest.mark.parametrize(
    "value",
    ("", "0", "65536", "-1", "+8000", "8000.0", " 8000 ", "abc", "9" * 100),
)
def test_parse_listen_port_rejects_invalid_values(value):
    with pytest.raises(ValueError, match=PORT_ERROR):
        _parse_listen_port(value)


def test_runner_rejects_invalid_port_before_starting_uvicorn(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("SPI_PORT", "0")
    monkeypatch.setenv("SPI_DATA_DIR", str(data_dir))

    def unexpected_run(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("Uvicorn started with an invalid port")

    monkeypatch.setattr(runner.uvicorn, "run", unexpected_run)

    with pytest.raises(SystemExit, match=PORT_ERROR):
        runner.main()
    assert not data_dir.exists()


def test_runner_rejects_custom_tls_files_before_creating_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SPI_TLS", "0")
    monkeypatch.setenv("SPI_TLS_CERTFILE", "/tmp/cert.pem")
    monkeypatch.setenv("SPI_TLS_KEYFILE", "/tmp/key.pem")
    monkeypatch.setenv("SPI_DATA_DIR", str(tmp_path / "data"))

    def unexpected_create_app(**_kwargs):  # pragma: no cover - must not run
        raise AssertionError("Application created with invalid TLS configuration")

    monkeypatch.setattr(main_module, "create_app", unexpected_create_app)

    with pytest.raises(ValueError, match="SPI_TLS must be 1"):
        runner.main()
    assert not (tmp_path / "data").exists()


def test_runner_passes_normalized_port_to_uvicorn(tmp_path, monkeypatch):
    application = object()
    captured = {}
    monkeypatch.setenv("SPI_PORT", "00080")
    monkeypatch.setenv("SPI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SPI_TLS", "0")

    def capture_create_app(*, data_dir, bind_host, tls_enabled):
        captured.update(
            create_data_dir=data_dir,
            create_bind_host=bind_host,
            create_tls_enabled=tls_enabled,
        )
        return application

    monkeypatch.setattr(main_module, "create_app", capture_create_app)
    monkeypatch.setattr(runner, "uvicorn_tls_kwargs", lambda *args: {})
    monkeypatch.setattr(
        runner.uvicorn,
        "run",
        lambda app, **kwargs: captured.update(app=app, **kwargs),
    )

    runner.main()

    assert captured["app"] is application
    assert captured["port"] == 80
    assert captured["create_bind_host"] == "127.0.0.1"
    assert captured["create_tls_enabled"] is False
