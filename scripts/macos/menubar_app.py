"""macOS menu-bar app wrapping the Square x UniFi Protect server.

Bundled by scripts/macos/build_dmg.sh via PyInstaller. Runs the server in a
background thread, lives in the menu bar (no Dock icon), and offers Open
Dashboard / Data Folder / Quit.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import webbrowser
from pathlib import Path

import rumps
import uvicorn

APP_NAME = "Square Protect"
DATA_DIR = Path.home() / "Library" / "Application Support" / "SquareProtect"


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

        from app.main import create_app  # after SPI_DATA_DIR is set

        config = uvicorn.Config(
            create_app(data_dir=DATA_DIR),
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
        )
        self.server = uvicorn.Server(config)
        threading.Thread(target=self.server.run, daemon=True).start()

        self.menu = [
            rumps.MenuItem("Open Dashboard", callback=self.open_dashboard),
            rumps.MenuItem("Open Data Folder", callback=self.open_data_folder),
            None,
            rumps.MenuItem(f"Running on port {self.port}", callback=None),
            None,
            rumps.MenuItem("Quit", callback=self.quit_app),
        ]

    def open_dashboard(self, _sender) -> None:
        webbrowser.open(f"http://127.0.0.1:{self.port}")

    def open_data_folder(self, _sender) -> None:
        subprocess.run(["open", str(DATA_DIR)], check=False)

    def quit_app(self, _sender) -> None:
        self.server.should_exit = True
        rumps.quit_application()


if __name__ == "__main__":
    SquareProtectApp().run()
