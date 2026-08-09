#!/usr/bin/env python3
"""Repair a reusable project virtualenv only when its dependencies need it."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import subprocess
import sys
from pathlib import Path


REQUIRED_MODULES = ("app", "PIL", "cryptography", "fastapi", "httpx", "uvicorn")
PROJECT_DISTRIBUTION = "square-unifi-protect-integration"
STAMP_FILENAME = ".square-protect-dependencies.sha256"


def dependency_fingerprint(project_root: Path) -> str:
    return hashlib.sha256((project_root / "pyproject.toml").read_bytes()).hexdigest()


def _dependencies_available() -> bool:
    try:
        importlib.metadata.version(PROJECT_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        return False
    import_probe = subprocess.run(
        [sys.executable, "-c", f"import {', '.join(REQUIRED_MODULES)}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if import_probe.returncode != 0:
        return False
    return (
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "--disable-pip-version-check",
                "check",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def _install_dependencies(project_root: Path) -> None:
    if importlib.util.find_spec("pip") is None:
        subprocess.run(
            [sys.executable, "-m", "ensurepip", "--upgrade"], check=True
        )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "--disable-pip-version-check",
            "install",
            "--quiet",
            "-e",
            str(project_root),
        ],
        check=True,
    )


def ensure_dependencies(project_root: Path, venv_dir: Path) -> bool:
    fingerprint = dependency_fingerprint(project_root)
    stamp_path = venv_dir / STAMP_FILENAME
    try:
        stamp_matches = stamp_path.read_text(encoding="utf-8").strip() == fingerprint
    except OSError:
        stamp_matches = False

    if stamp_matches and _dependencies_available():
        return False

    print("Installing or repairing Python dependencies (about a minute)...")
    _install_dependencies(project_root)
    stamp_path.write_text(f"{fingerprint}\n", encoding="utf-8")
    return True


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: ensure_dependencies.py PROJECT_ROOT VENV_DIR")
    ensure_dependencies(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
