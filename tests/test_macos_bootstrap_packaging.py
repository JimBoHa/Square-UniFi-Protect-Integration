"""Regression tests for first-run setup in the windowed macOS app."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
MENUBAR_APP = ROOT / "scripts" / "macos" / "menubar_app.py"


class _FakeApp:
    pass


class _FakeMenuItem:
    def __init__(self, title, callback=None):
        self.title = title
        self.callback = callback

    def set_callback(self, callback):
        self.callback = callback


class _FakeTimer:
    def __init__(self, callback, interval):
        self.callback = callback
        self.interval = interval
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class _FakeWindow:
    calls = []

    def __init__(self, **options):
        self.options = options

    def run(self):
        self.calls.append(self.options)


@pytest.fixture
def menubar_module(monkeypatch):
    _FakeWindow.calls = []
    fake_rumps = SimpleNamespace(
        App=_FakeApp,
        MenuItem=_FakeMenuItem,
        Timer=_FakeTimer,
        Window=_FakeWindow,
        quit_application=lambda: None,
    )
    fake_uvicorn = SimpleNamespace(Config=object, Server=object)
    monkeypatch.setitem(sys.modules, "rumps", fake_rumps)
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    spec = importlib.util.spec_from_file_location("packaging_menubar_app", MENUBAR_APP)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _fake_web_app(password_hash=None):
    store = SimpleNamespace(
        setup_complete=lambda: password_hash is not None,
    )
    return SimpleNamespace(state=SimpleNamespace(store=store))


def test_packaging_base_stays_dormant_without_secure_bootstrap_api(
    tmp_path, monkeypatch, menubar_module
):
    calls = []
    expected_app = _fake_web_app()

    class LegacyMain:
        @staticmethod
        def create_app(data_dir=None):
            calls.append({"data_dir": data_dir})
            return expected_app

    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", "leave-legacy-environment-alone")

    web_app, retained_secret = menubar_module._create_menu_web_app(LegacyMain, tmp_path)

    assert web_app is expected_app
    assert retained_secret is None
    assert calls == [{"data_dir": tmp_path}]
    assert (
        menubar_module.os.environ["SPI_BOOTSTRAP_SECRET"]
        == "leave-legacy-environment-alone"
    )


def test_secure_bootstrap_is_classified_as_explicit_loopback(
    tmp_path, monkeypatch, menubar_module, capsys
):
    generated_secret = "generated-menu-secret-01234567890123456789"
    calls = []
    expected_app = _fake_web_app()

    class SecureMain:
        BOOTSTRAP_SECRET_MIN_LENGTH = 32
        BOOTSTRAP_SECRET_MAX_LENGTH = 4096

        @staticmethod
        def create_app(data_dir=None, bind_host=None, tls_enabled=None):
            calls.append(
                {
                    "data_dir": data_dir,
                    "bind_host": bind_host,
                    "tls_enabled": tls_enabled,
                }
            )
            return expected_app

    monkeypatch.delenv("SPI_BOOTSTRAP_SECRET", raising=False)
    monkeypatch.setattr(
        menubar_module.secrets,
        "token_urlsafe",
        lambda _size: generated_secret,
    )

    web_app, retained_secret = menubar_module._create_menu_web_app(SecureMain, tmp_path)

    assert web_app is expected_app
    assert bytes(retained_secret).decode("utf-8") == generated_secret
    assert calls == [
        {
            "data_dir": tmp_path,
            "bind_host": "127.0.0.1",
            "tls_enabled": False,
        }
    ]
    assert "SPI_BOOTSTRAP_SECRET" not in menubar_module.os.environ
    captured = capsys.readouterr()
    assert generated_secret not in captured.out
    assert generated_secret not in captured.err


def test_secret_reveal_is_user_initiated_and_cleared_after_setup(
    menubar_module,
):
    secret_text = "visible-only-on-request-secret-0123456789"
    secret_buffer = bytearray(secret_text.encode("utf-8"))
    setup_state = {"complete": False}
    store = SimpleNamespace(setup_complete=lambda: setup_state["complete"])
    app = object.__new__(menubar_module.SquareProtectApp)
    app.web_app = SimpleNamespace(state=SimpleNamespace(store=store))
    app._bootstrap_secret = secret_buffer
    app._setup_secret_item = _FakeMenuItem(
        "Show One-Time Setup Secret", callback=app.show_setup_secret
    )
    app._setup_timer = _FakeTimer(app._refresh_setup_state, 1.0)

    assert _FakeWindow.calls == []

    app.show_setup_secret(None)

    assert len(_FakeWindow.calls) == 1
    assert _FakeWindow.calls[0]["default_text"] == secret_text

    setup_state["complete"] = True
    app._refresh_setup_state()

    assert app._bootstrap_secret is None
    assert secret_buffer == bytearray(len(secret_buffer))
    assert app._setup_secret_item.title == "First-Run Setup Complete"
    assert app._setup_secret_item.callback is None
    assert app._setup_timer is None

    app.show_setup_secret(None)
    assert len(_FakeWindow.calls) == 1
