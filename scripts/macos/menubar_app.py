"""macOS menu-bar wrapper around the native Rust Square Protect server."""

from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import webbrowser
from pathlib import Path

import rumps


APP_NAME = "Square Protect"
DATA_DIR = Path.home() / "Library" / "Application Support" / "SquareProtect"
LOOPBACK_HOST = "127.0.0.1"
BOOTSTRAP_SECRET_MIN_LENGTH = 32
BOOTSTRAP_SECRET_MAX_LENGTH = 4096


def _resource_dir() -> Path:
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        return Path(bundled)
    return Path(__file__).resolve().parents[2]


RESOURCE_DIR = _resource_dir()
STATIC_DIR = RESOURCE_DIR / "app" / "static"
_BINARY_NAME = "square-unifi-protect.exe" if os.name == "nt" else "square-unifi-protect"
BINARY = (
    RESOURCE_DIR / _BINARY_NAME
    if (RESOURCE_DIR / _BINARY_NAME).is_file()
    else RESOURCE_DIR / "target" / "release" / _BINARY_NAME
)


def _wipe_secret(secret: bytearray | None) -> None:
    if secret is not None:
        secret[:] = b"\0" * len(secret)


def _probe_environment(data_dir: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["SPI_DATA_DIR"] = str(data_dir)
    environment.pop("SPI_BOOTSTRAP_SECRET", None)
    return environment


def _setup_complete(binary: Path, data_dir: Path) -> bool:
    result = subprocess.run(
        [str(binary), "--setup-complete"],
        cwd=RESOURCE_DIR,
        env=_probe_environment(data_dir),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _prepare_bootstrap_secret(binary: Path, data_dir: Path) -> bytearray | None:
    if _setup_complete(binary, data_dir):
        os.environ.pop("SPI_BOOTSTRAP_SECRET", None)
        return None
    plaintext = os.environ.pop("SPI_BOOTSTRAP_SECRET", None)
    if plaintext is None or not (
        BOOTSTRAP_SECRET_MIN_LENGTH
        <= len(plaintext)
        <= BOOTSTRAP_SECRET_MAX_LENGTH
    ):
        plaintext = secrets.token_urlsafe(32)
    retained = bytearray(plaintext.encode("utf-8"))
    plaintext = None
    return retained


def pick_port(preferred: int = 8000) -> int:
    for port in range(preferred, preferred + 21):
        with socket.socket() as probe:
            try:
                probe.bind((LOOPBACK_HOST, port))
                return port
            except OSError:
                continue
    return preferred


class SquareProtectApp(rumps.App):
    def __init__(self) -> None:
        super().__init__(APP_NAME, title="◉", quit_button=None)
        if not BINARY.is_file() or not os.access(BINARY, os.X_OK):
            raise RuntimeError(f"Rust server binary is missing or not executable: {BINARY}")
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.binary = BINARY
        self.data_dir = DATA_DIR
        self.port = int(os.environ.get("SPI_PORT", "0")) or pick_port()
        self.tls_enabled = os.environ.get("SPI_TLS") == "1"
        self._bootstrap_secret = _prepare_bootstrap_secret(self.binary, self.data_dir)

        child_environment = os.environ.copy()
        child_environment.update(
            {
                "SPI_DATA_DIR": str(self.data_dir),
                "SPI_STATIC_DIR": str(STATIC_DIR),
                "SPI_HOST": LOOPBACK_HOST,
                "SPI_PORT": str(self.port),
                "SPI_TLS": "1" if self.tls_enabled else "0",
            }
        )
        if self._bootstrap_secret is not None:
            child_environment["SPI_BOOTSTRAP_SECRET"] = bytes(
                self._bootstrap_secret
            ).decode("utf-8")
        self._log = (self.data_dir / "service.log").open("ab", buffering=0)
        try:
            self.server = subprocess.Popen(
                [str(self.binary)],
                cwd=RESOURCE_DIR,
                env=child_environment,
                stdin=subprocess.DEVNULL,
                stdout=self._log,
                stderr=subprocess.STDOUT,
            )
        except BaseException:
            _wipe_secret(self._bootstrap_secret)
            self._log.close()
            raise
        finally:
            child_environment.pop("SPI_BOOTSTRAP_SECRET", None)

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
        scheme = "https" if self.tls_enabled else "http"
        webbrowser.open(f"{scheme}://{LOOPBACK_HOST}:{self.port}")

    def open_data_folder(self, _sender) -> None:
        subprocess.run(["open", str(self.data_dir)], check=False)

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
        if self._bootstrap_secret is not None and _setup_complete(
            self.binary, self.data_dir
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
        if self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)
        self._log.close()
        rumps.quit_application()


if __name__ == "__main__":
    SquareProtectApp().run()
