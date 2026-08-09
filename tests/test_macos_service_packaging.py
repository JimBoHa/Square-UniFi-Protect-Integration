"""Static regression tests for macOS service packaging."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_macos_log_directory_exists_before_launchd_load():
    installer = (REPO_ROOT / "scripts" / "install-service.sh").read_text(
        encoding="utf-8"
    )
    macos_start = installer.index("  Darwin)")
    macos_end = installer.index("  Linux)")
    macos_installer = installer[macos_start:macos_end]

    create_data_dir = macos_installer.index('mkdir -p "$REPO/data"')
    load_agent = macos_installer.index('launchctl load "$PLIST"')

    assert (
        "<key>StandardOutPath</key><string>$REPO/data/service.log</string>"
        in macos_installer
    )
    assert (
        "<key>StandardErrorPath</key><string>$REPO/data/service.log</string>"
        in macos_installer
    )
    assert create_data_dir < load_agent


def test_macos_service_uses_dynamic_lan_tls_binding():
    installer = (REPO_ROOT / "scripts" / "install-service.sh").read_text(
        encoding="utf-8"
    )
    macos_start = installer.index("  Darwin)")
    macos_end = installer.index("  Linux)")
    macos_installer = installer[macos_start:macos_end]

    assert "<key>SPI_HOST</key><string>0.0.0.0</string>" in macos_installer
    assert "<key>SPI_TLS</key><string>1</string>" in macos_installer
    assert "https://<this-host>:8000" in macos_installer
    assert "LAN IP changes" in macos_installer
    assert "http://<this-host>:8000" not in macos_installer
