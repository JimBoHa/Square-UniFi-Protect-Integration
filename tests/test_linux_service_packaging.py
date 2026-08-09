"""Regression tests for network setup through the Linux service."""

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


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_linux_service_uses_builtin_tls_for_its_remote_dashboard(tmp_path):
    repo = tmp_path / "repo"
    installer = repo / "scripts" / "install-service.sh"
    installer.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "scripts" / "install-service.sh", installer)
    fake_bin = tmp_path / "fake-bin"
    _write_executable(fake_bin / "uname", "#!/bin/sh\necho Linux\n")
    _write_executable(fake_bin / "cargo", "#!/bin/sh\nexit 0\n")
    _write_executable(
        fake_bin / "sudo",
        "#!/bin/sh\n"
        'if [ "$1" = "tee" ]; then cat > "$UNIT_CAPTURE"; exit 0; fi\n'
        'if [ "$1" = "systemctl" ]; then '
        'printf "%s\\n" "$*" >> "$SYSTEMCTL_CAPTURE"; exit 0; fi\n'
        "exit 0\n",
    )
    unit_path = tmp_path / "square-protect.service"
    systemctl_path = tmp_path / "systemctl-calls"
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}/usr/bin:/bin",
        "SYSTEMCTL_CAPTURE": str(systemctl_path),
        "UNIT_CAPTURE": str(unit_path),
        "USER": "square-protect-test",
    }

    result = subprocess.run(
        [str(BASH), str(installer)],
        cwd=repo,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    unit = unit_path.read_text(encoding="utf-8")
    assert "Environment=SPI_HOST=0.0.0.0" in unit
    assert "Environment=SPI_TLS=1" in unit
    assert "target/release/square-unifi-protect" in unit
    assert ".venv/bin/python" not in unit
    assert "SPI_BOOTSTRAP_SECRET" not in unit
    assert "https://<this-host>:8000" in result.stdout
    assert "journalctl -u square-protect" in result.stdout
    assert "http://<this-host>:8000" not in result.stdout
    systemctl_calls = systemctl_path.read_text(encoding="utf-8").splitlines()
    assert "systemctl enable square-protect" in systemctl_calls
    assert "systemctl restart square-protect" in systemctl_calls
    assert "systemctl enable --now square-protect" not in systemctl_calls


def test_linux_service_instructions_match_the_secure_unit():
    instructions = (ROOT / "PACKAGING.md").read_text(encoding="utf-8")

    assert "https://<host>:8000" in instructions
    assert "journalctl -u square-protect" in instructions
    assert "No plaintext secret is stored in the unit" in instructions
