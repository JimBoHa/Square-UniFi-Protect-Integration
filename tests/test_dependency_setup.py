"""Tests that service installers prepare the native Rust runtime."""

from pathlib import Path


def test_service_installers_prepare_their_runtime():
    root = Path(__file__).resolve().parents[1]
    unix_installer = (root / "scripts" / "install-service.sh").read_text(
        encoding="utf-8"
    )
    windows_installer = (
        root / "scripts" / "windows" / "install-service.ps1"
    ).read_text(encoding="utf-8")

    unix_guard = unix_installer.index('if [ "$UNINSTALL" != "--uninstall" ]; then')
    unix_check = unix_installer.index(
        'cargo build --manifest-path "$REPO/Cargo.toml" --locked --release'
    )
    unix_guard_end = unix_installer.index("\nfi\n", unix_check)
    windows_guard = windows_installer.index("if ($Uninstall)")
    windows_exit = windows_installer.index("exit 0", windows_guard)
    windows_check = windows_installer.index(
        '& cargo build --manifest-path "$Repo\\Cargo.toml" --locked --release'
    )

    assert unix_guard < unix_check < unix_guard_end
    assert windows_guard < windows_exit < windows_check


def test_obsolete_python_runtime_helpers_are_removed():
    root = Path(__file__).resolve().parents[1]

    assert not (root / "scripts" / "ensure_dependencies.py").exists()
    assert not (root / "scripts" / "windows" / "setup_complete.py").exists()
    assert not (root / "scripts" / "macos" / "menubar_app.py").exists()
