"""Regression tests for side-effect-free service uninstalls."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_unix_rust_build_is_guarded_from_uninstall():
    installer = (REPO_ROOT / "scripts" / "install-service.sh").read_text(
        encoding="utf-8"
    )
    setup_guard = installer.index('if [ "$UNINSTALL" != "--uninstall" ]; then')
    build_binary = installer.index("cargo build", setup_guard)
    setup_guard_end = installer.index("\nfi\n\nBINARY", build_binary)
    platform_dispatch = installer.index('case "$(uname -s)" in')

    assert setup_guard < build_binary < setup_guard_end < platform_dispatch


def test_windows_uninstall_exits_before_rust_build():
    installer = (
        REPO_ROOT / "scripts" / "windows" / "install-service.ps1"
    ).read_text(encoding="utf-8")

    uninstall = installer.index("if ($Uninstall)")
    uninstall_exit = installer.index("exit 0", uninstall)
    setup_environment = installer.index("& cargo build")

    assert uninstall < uninstall_exit < setup_environment
