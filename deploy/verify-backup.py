"""Create and verify a SQLite backup without stopping the Helper service."""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import os
import pathlib
import sqlite3
import tempfile
import time


def check_database(path: pathlib.Path) -> tuple[str, int, int]:
    with closing(sqlite3.connect(path)) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        tables = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0]
        audit_events = connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]
    return integrity, tables, audit_events


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("backup_dir", type=pathlib.Path)
    args = parser.parse_args()

    args.backup_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chmod(args.backup_dir, 0o750)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_fd, backup_name = tempfile.mkstemp(
        prefix=f"vozen-helper-{stamp}-", suffix=".db", dir=args.backup_dir
    )
    os.close(backup_fd)
    backup = pathlib.Path(backup_name)

    with (
        closing(sqlite3.connect(args.source.resolve().as_uri() + "?mode=ro", uri=True)) as source,
        closing(sqlite3.connect(backup)) as target,
    ):
        source.backup(target)

    integrity, tables, audit_events = check_database(backup)
    if integrity != "ok":
        raise SystemExit(f"backup integrity failed: {integrity}")

    with tempfile.TemporaryDirectory(prefix="vozen-helper-restore-") as restore_dir:
        restore_fd, restore_name = tempfile.mkstemp(suffix=".db", dir=restore_dir)
        restore_copy = pathlib.Path(restore_name)
        with os.fdopen(restore_fd, "wb") as restore:
            restore.write(backup.read_bytes())
        restored_integrity, restored_tables, _ = check_database(restore_copy)
        if restored_integrity != "ok" or restored_tables != tables:
            raise SystemExit("restore verification failed")

    os.chmod(backup, 0o640)
    print(f"backup={backup}")
    print(f"sha256={hashlib.sha256(backup.read_bytes()).hexdigest()}")
    print(f"integrity={integrity}")
    print(f"tables={tables}")
    print(f"audit_events={audit_events}")
    print(f"restore_integrity={restored_integrity}")


if __name__ == "__main__":
    main()
