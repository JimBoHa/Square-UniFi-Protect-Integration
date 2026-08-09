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
    monkeypatch.setitem(sys.modules, "rumps", fake_rumps)
    spec = importlib.util.spec_from_file_location("packaging_menubar_app", MENUBAR_APP)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_setup_probe_uses_the_rust_binary_without_inheriting_a_secret(
    tmp_path, monkeypatch, menubar_module
):
    calls = []
    binary = tmp_path / "square-unifi-protect"
    monkeypatch.setenv("SPI_BOOTSTRAP_SECRET", "never-forward-this-to-the-probe-0001")
    monkeypatch.setattr(
        menubar_module.subprocess,
        "run",
        lambda command, **options: calls.append((command, options))
        or SimpleNamespace(returncode=0),
    )

    assert menubar_module._setup_complete(binary, tmp_path) is True
    command, options = calls[0]
    assert command == [str(binary), "--setup-complete"]
    assert options["env"]["SPI_DATA_DIR"] == str(tmp_path)
    assert "SPI_BOOTSTRAP_SECRET" not in options["env"]


def test_incomplete_setup_generates_a_revealable_one_time_secret(
    tmp_path, monkeypatch, menubar_module, capsys
):
    generated_secret = "generated-menu-secret-01234567890123456789"
    monkeypatch.delenv("SPI_BOOTSTRAP_SECRET", raising=False)
    monkeypatch.setattr(menubar_module, "_setup_complete", lambda *_args: False)
    monkeypatch.setattr(
        menubar_module.secrets,
        "token_urlsafe",
        lambda _size: generated_secret,
    )

    retained_secret = menubar_module._prepare_bootstrap_secret(
        tmp_path / "square-unifi-protect", tmp_path
    )

    assert bytes(retained_secret).decode("utf-8") == generated_secret
    assert "SPI_BOOTSTRAP_SECRET" not in menubar_module.os.environ
    captured = capsys.readouterr()
    assert generated_secret not in captured.out
    assert generated_secret not in captured.err


def test_secret_reveal_is_user_initiated_and_cleared_after_setup(
    monkeypatch, menubar_module, tmp_path
):
    secret_text = "visible-only-on-request-secret-0123456789"
    secret_buffer = bytearray(secret_text.encode("utf-8"))
    setup_state = {"complete": False}
    monkeypatch.setattr(
        menubar_module,
        "_setup_complete",
        lambda *_args: setup_state["complete"],
    )
    app = object.__new__(menubar_module.SquareProtectApp)
    app.binary = tmp_path / "square-unifi-protect"
    app.data_dir = tmp_path
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
