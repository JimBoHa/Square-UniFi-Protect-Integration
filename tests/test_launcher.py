"""Regression tests for the double-clickable macOS launcher."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASH = Path("/bin/bash")
pytestmark = pytest.mark.skipif(
    not BASH.is_file() or not os.access(BASH, os.X_OK),
    reason="requires executable /bin/bash",
)


def test_launcher_repairs_incomplete_existing_environment(tmp_path):
    launcher = tmp_path / "Start Square Protect.command"
    shutil.copy2(ROOT / launcher.name, launcher)
    python = tmp_path / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"-c\" ]; then exit 1; fi\n"
        "if [ \"$1\" = \"-m\" ] && [ \"$2\" = \"pip\" ]; then\n"
        "  : > \"$INSTALL_MARKER\"\n"
        "  exit 0\n"
        "fi\n"
        "exit 1\n"
    )
    python.chmod(0o755)
    install_marker = tmp_path / "pip-was-run"
    environment = {
        **os.environ,
        "INSTALL_MARKER": str(install_marker),
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
    assert install_marker.is_file()
    assert "repairing Python dependencies" in result.stdout
