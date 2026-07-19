"""macOS menu-bar app wrapping the Square x UniFi Protect server.

Bundled by scripts/macos/build_dmg.sh via PyInstaller. Runs the server in a
background thread, lives in the menu bar (no Dock icon), and offers Open
Dashboard / Data Folder / Quit.
"""

from __future__ import annotations

import inspect
import os
import secrets
import socket
import subprocess
import threading
import webbrowser
from pathlib import Path

import rumps
import uvicorn

APP_NAME = "Square Protect"
DATA_DIR = Path.home() / "Library" / "Application Support" / "SquareProtect"
LOOPBACK_HOST = "127.0.0.1"


def _supports_secure_bootstrap(app_module) -> bool:
    """Detect the bootstrap API without making packaging depend on its PR."""
    parameters = inspect.signature(app_module.create_app).parameters
    minimum = getattr(app_module, "BOOTSTRAP_SECRET_MIN_LENGTH", None)
    maximum = getattr(app_module, "BOOTSTRAP_SECRET_MAX_LENGTH", None)
    return bool(
        {"bind_host", "tls_enabled"}.issubset(parameters)
        and isinstance(minimum, int)
        and isinstance(maximum, int)
        and 1 <= minimum <= maximum
    )


def _wipe_secret(secret: bytearray | None) -> None:
    if secret is not None:
        secret[:] = b"\0" * len(secret)


def _create_menu_web_app(app_module, data_dir: Path):
    """Create the web app and retain a revealable secret only while setup is pending."""
    if not _supports_secure_bootstrap(app_module):
        return app_module.create_app(data_dir=data_dir), None

    minimum = app_module.BOOTSTRAP_SECRET_MIN_LENGTH
    maximum = app_module.BOOTSTRAP_SECRET_MAX_LENGTH
    plaintext = os.environ.get("SPI_BOOTSTRAP_SECRET")
    if plaintext is None or not minimum <= len(plaintext) <= maximum:
        plaintext = secrets.token_urlsafe(32)
    retained_secret = bytearray(plaintext.encode("utf-8"))
    os.environ["SPI_BOOTSTRAP_SECRET"] = plaintext
    plaintext = None
    try:
        web_app = app_module.create_app(
            data_dir=data_dir,
            bind_host=LOOPBACK_HOST,
            tls_enabled=False,
        )
    except BaseException:
        _wipe_secret(retained_secret)
        raise
    finally:
        # Secure bootstrap also removes this value, but keep the packaging
        # adapter fail-closed if app construction exits before that point.
        os.environ.pop("SPI_BOOTSTRAP_SECRET", None)

    if web_app.state.store.get_setting("admin.password_hash") is not None:
        _wipe_secret(retained_secret)
        return web_app, None
    return web_app, retained_secret


def pick_port(preferred: int = 8000) -> int:
    for port in range(preferred, preferred + 21):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred


class SquareProtectApp(rumps.App):
    def __init__(self) -> None:
        super().__init__(APP_NAME, title="◉", quit_button=None)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("SPI_DATA_DIR", str(DATA_DIR))
        self.port = int(os.environ.get("SPI_PORT", "0")) or pick_port()

        from app import main as app_main  # after SPI_DATA_DIR is set

        self.web_app, self._bootstrap_secret = _create_menu_web_app(app_main, DATA_DIR)

        config = uvicorn.Config(
            self.web_app,
            host=LOOPBACK_HOST,
            port=self.port,
            log_level="warning",
        )
        self.server = uvicorn.Server(config)
        threading.Thread(target=self.server.run, daemon=True).start()

        self._setup_secret_item = None
        self._setup_timer = None
        menu_items = [
            rumps.MenuItem("Open Dashboard", callback=self.open_dashboard),
            rumps.MenuItem("Open Data Folder", callback=self.open_data_folder),
            None,
            rumps.MenuItem(f"Running on port {self.port}", callback=None),
            None,
            rumps.MenuItem("Quit", callback=self.quit_app),
        ]
        if self._bootstrap_secret is not None:
            self._setup_secret_item = rumps.MenuItem(
                "Show One-Time Setup Secret", callback=self.show_setup_secret
            )
            menu_items[2:2] = [self._setup_secret_item]
        self.menu = menu_items

        if self._bootstrap_secret is not None:
            self._setup_timer = rumps.Timer(self._refresh_setup_state, 1.0)
            self._setup_timer.start()

    def open_dashboard(self, _sender) -> None:
        webbrowser.open(f"http://127.0.0.1:{self.port}")

    def open_data_folder(self, _sender) -> None:
        subprocess.run(["open", str(DATA_DIR)], check=False)

    def _clear_setup_secret(self) -> None:
        _wipe_secret(self._bootstrap_secret)
        self._bootstrap_secret = None
        if self._setup_secret_item is not None:
            self._setup_secret_item.title = "First-Run Setup Complete"
            self._setup_secret_item.set_callback(None)
        if self._setup_timer is not None:
            self._setup_timer.stop()
            self._setup_timer = None

    def _refresh_setup_state(self, _timer=None) -> None:
        if (
            self._bootstrap_secret is not None
            and self.web_app.state.store.get_setting("admin.password_hash") is not None
        ):
            self._clear_setup_secret()

    def show_setup_secret(self, _sender) -> None:
        self._refresh_setup_state()
        if self._bootstrap_secret is None:
            return
        plaintext = bytes(self._bootstrap_secret).decode("utf-8")
        try:
            rumps.Window(
                title="One-Time Setup Secret",
                message=(
                    "Copy this into the dashboard's first-run setup form. "
                    "It is removed from this menu after setup succeeds."
                ),
                default_text=plaintext,
                ok="Close",
                cancel=None,
                dimensions=(440, 24),
            ).run()
        finally:
            plaintext = None

    def quit_app(self, _sender) -> None:
        self._clear_setup_secret()
        self.server.should_exit = True
        rumps.quit_application()


if __name__ == "__main__":
    SquareProtectApp().run()
