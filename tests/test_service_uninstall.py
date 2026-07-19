"""Regression tests for side-effect-free service uninstalls."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_unix_dependency_setup_is_guarded_from_uninstall():
    installer = (REPO_ROOT / "scripts" / "install-service.sh").read_text(
        encoding="utf-8"
    )
    setup_guard = installer.index('if [ "$UNINSTALL" != "--uninstall" ]; then')
    create_environment = installer.index("python3 -m venv", setup_guard)
    setup_guard_end = installer.index("\nfi\n\ncase", create_environment)
    platform_dispatch = installer.index('case "$(uname -s)" in')

    assert setup_guard < create_environment < setup_guard_end < platform_dispatch


def test_windows_uninstall_exits_before_python_setup():
    installer = (
        REPO_ROOT / "scripts" / "windows" / "install-service.ps1"
    ).read_text(encoding="utf-8")

    uninstall = installer.index("if ($Uninstall)")
    uninstall_exit = installer.index("exit 0", uninstall)
    setup_environment = installer.index(
        'if (-not (Test-Path "$Repo\\.venv\\Scripts\\python.exe"))'
    )

    assert uninstall < uninstall_exit < setup_environment
