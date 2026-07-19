"""Exit successfully only after the local admin setup transaction commits."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


def setup_complete(data_dir: Path) -> bool:
    database = data_dir / "spi.db"
    try:
        with sqlite3.connect(
            f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=0.2
        ) as connection:
            row = connection.execute(
                "SELECT value FROM settings WHERE key = 'admin.password_hash'"
            ).fetchone()
    except sqlite3.Error:
        return False
    return bool(row and row[0])


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: setup_complete.py DATA_DIR")
    raise SystemExit(0 if setup_complete(Path(sys.argv[1])) else 1)


if __name__ == "__main__":
    main()
