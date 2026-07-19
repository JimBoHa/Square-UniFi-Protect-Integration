"""Regression tests for the double-clickable macOS launcher."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASH = Path("/bin/bash")
pytestmark = pytest.mark.skipif(
    not BASH.is_file() or not os.access(BASH, os.X_OK),
    reason="requires executable /bin/bash",
)


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o755)


def _ready_launcher_environment(tmp_path: Path, *, port_in_use: bool = False):
    launcher = tmp_path / "Start Square Protect.command"
    shutil.copy2(ROOT / launcher.name, launcher)
    port_marker = tmp_path / "server-port"
    open_marker = tmp_path / "browser-url"
    _write_executable(
        tmp_path / ".venv" / "bin" / "python",
        "#!/bin/sh\n"
        'if [ "$1" = "scripts/ensure_dependencies.py" ]; then exit 0; fi\n'
        'if [ "$1" = "-c" ]; then exit 0; fi\n'
        'if [ "$1" = "-m" ] && [ "$2" = "app" ]; then\n'
        '  printf "%s" "$SPI_PORT" > "$PORT_MARKER"\n'
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
    )
    fake_bin = tmp_path / "fake-bin"
    _write_executable(
        fake_bin / "lsof",
        f"#!/bin/sh\nexit {0 if port_in_use else 1}\n",
    )
    _write_executable(fake_bin / "sleep", "#!/bin/sh\nexit 0\n")
    _write_executable(
        fake_bin / "open",
        "#!/bin/sh\n"
        'printf "%s" "$1" > "$OPEN_MARKER"\n',
    )
    environment = {
        **os.environ,
        "OPEN_MARKER": str(open_marker),
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "PORT_MARKER": str(port_marker),
        "SPI_LAUNCHER_SETUP_ONLY": "0",
        "SPI_TLS": "0",
    }
    return launcher, environment, port_marker, open_marker


def test_launcher_checks_dependencies_in_existing_environment(tmp_path):
    launcher = tmp_path / "Start Square Protect.command"
    shutil.copy2(ROOT / launcher.name, launcher)
    python = tmp_path / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"scripts/ensure_dependencies.py\" ]; then\n"
        "  : > \"$DEPENDENCY_CHECK_MARKER\"\n"
        "  exit 0\n"
        "fi\n"
        "exit 1\n"
    )
    python.chmod(0o755)
    dependency_check_marker = tmp_path / "dependency-check-was-run"
    environment = {
        **os.environ,
        "DEPENDENCY_CHECK_MARKER": str(dependency_check_marker),
        "SPI_LAUNCHER_SETUP_ONLY": "1",
    }

    result = subprocess.run(
        [str(BASH), str(launcher)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert dependency_check_marker.is_file()


@pytest.mark.parametrize(
    "value",
    ("", "0", "65536", "-1", "+8000", "8000.0", " 8000 ", "abc", "9" * 100),
)
def test_launcher_rejects_invalid_port_before_setup(tmp_path, value):
    launcher = tmp_path / "Start Square Protect.command"
    shutil.copy2(ROOT / launcher.name, launcher)
    environment = {**os.environ, "SPI_PORT": value}

    result = subprocess.run(
        ["/bin/bash", str(launcher)],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 1
    assert "SPI_PORT must be a whole number from 1 to 65535" in result.stderr
    assert not (tmp_path / ".venv").exists()


def test_launcher_browser_and_runner_use_same_normalized_port(tmp_path):
    launcher, environment, port_marker, open_marker = _ready_launcher_environment(
        tmp_path
    )
    environment["SPI_PORT"] = "00080"

    result = subprocess.run(
        ["/bin/bash", str(launcher)],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    for _ in range(100):
        if open_marker.exists():
            break
        time.sleep(0.01)
    assert result.returncode == 0, result.stderr
    assert port_marker.read_text() == "80"
    assert open_marker.read_text() == "http://localhost:80"


def test_launcher_does_not_search_above_maximum_port(tmp_path):
    launcher, environment, port_marker, open_marker = _ready_launcher_environment(
        tmp_path, port_in_use=True
    )
    environment["SPI_PORT"] = "65535"

    result = subprocess.run(
        ["/bin/bash", str(launcher)],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 1
    assert "between 65535 and 65535" in result.stdout
    assert "trying 65536" not in result.stdout
    assert not port_marker.exists()
    assert not open_marker.exists()
