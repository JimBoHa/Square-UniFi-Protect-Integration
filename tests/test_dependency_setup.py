"""Tests for reusable launcher dependency freshness checks."""

from __future__ import annotations

from pathlib import Path

from scripts import ensure_dependencies as dependency_setup


def _project(tmp_path: Path) -> tuple[Path, Path]:
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pyproject.toml").write_text(
        '[project]\nname = "test-project"\ndependencies = ["example"]\n',
        encoding="utf-8",
    )
    venv_dir = project_root / ".venv"
    venv_dir.mkdir()
    return project_root, venv_dir


def test_stale_dependency_fingerprint_triggers_install(tmp_path, monkeypatch):
    project_root, venv_dir = _project(tmp_path)
    stamp = venv_dir / dependency_setup.STAMP_FILENAME
    stamp.write_text("old-fingerprint\n", encoding="utf-8")
    installs = []
    monkeypatch.setattr(dependency_setup, "_dependencies_available", lambda: True)
    monkeypatch.setattr(dependency_setup, "_install_dependencies", installs.append)

    changed = dependency_setup.ensure_dependencies(project_root, venv_dir)

    assert changed is True
    assert installs == [project_root]
    assert stamp.read_text(encoding="utf-8").strip() == (
        dependency_setup.dependency_fingerprint(project_root)
    )


def test_incomplete_current_environment_triggers_repair(tmp_path, monkeypatch):
    project_root, venv_dir = _project(tmp_path)
    stamp = venv_dir / dependency_setup.STAMP_FILENAME
    stamp.write_text(
        dependency_setup.dependency_fingerprint(project_root), encoding="utf-8"
    )
    installs = []
    monkeypatch.setattr(dependency_setup, "_dependencies_available", lambda: False)
    monkeypatch.setattr(dependency_setup, "_install_dependencies", installs.append)

    changed = dependency_setup.ensure_dependencies(project_root, venv_dir)

    assert changed is True
    assert installs == [project_root]


def test_current_healthy_environment_skips_install(tmp_path, monkeypatch):
    project_root, venv_dir = _project(tmp_path)
    stamp = venv_dir / dependency_setup.STAMP_FILENAME
    stamp.write_text(
        dependency_setup.dependency_fingerprint(project_root), encoding="utf-8"
    )
    installs = []
    monkeypatch.setattr(dependency_setup, "_dependencies_available", lambda: True)
    monkeypatch.setattr(dependency_setup, "_install_dependencies", installs.append)

    changed = dependency_setup.ensure_dependencies(project_root, venv_dir)

    assert changed is False
    assert installs == []


def test_missing_pip_is_bootstrapped_before_dependency_repair(
    tmp_path, monkeypatch
):
    project_root, _ = _project(tmp_path)
    commands = []
    monkeypatch.setattr(
        dependency_setup.importlib.util, "find_spec", lambda _module: None
    )
    monkeypatch.setattr(
        dependency_setup.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command),
    )

    dependency_setup._install_dependencies(project_root)

    assert commands[0][2:] == ["ensurepip", "--upgrade"]
    assert commands[1][-2:] == ["-e", str(project_root)]


def test_missing_project_install_is_incomplete(monkeypatch):
    def missing_distribution(_name):
        raise dependency_setup.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(
        dependency_setup.importlib.metadata, "version", missing_distribution
    )

    assert dependency_setup._dependencies_available() is False


def test_service_installers_prepare_their_runtime():
    unix_installer = (
        Path(__file__).resolve().parents[1] / "scripts" / "install-service.sh"
    ).read_text(encoding="utf-8")
    windows_installer = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "windows"
        / "install-service.ps1"
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
