"""Regression tests for the double-clickable macOS launcher."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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
        ["/bin/bash", str(launcher)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert dependency_check_marker.is_file()
