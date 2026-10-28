"""Isolated POSIX regressions for the release backup verifier."""

import contextlib
import hashlib
import importlib.util
import io
import os
import pathlib
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "verify-backup.py"
SPEC = importlib.util.spec_from_file_location("verify_backup", SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@unittest.skipUnless(os.name == "posix", "requires POSIX modes and symlinks")
class VerifyBackupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="helper-backup-test-")
        self.addCleanup(self.fixture.cleanup)
        self.root = pathlib.Path(self.fixture.name)
        self.source = self.root / "source.db"
        self.backups = self.root / "backups"
        with contextlib.closing(sqlite3.connect(self.source)) as connection:
            connection.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, event TEXT)")
            connection.execute("INSERT INTO audit_events (event) VALUES ('synthetic-event')")
            connection.commit()
        self.source_bytes = self.source.read_bytes()
        self.stamp = self.root.name

    def run_verifier(self, checker=None):
        with (
            mock.patch("sys.argv", [str(SCRIPT), str(self.source), str(self.backups)]),
            mock.patch.object(verifier.time, "strftime", return_value=self.stamp),
            contextlib.redirect_stdout(io.StringIO()) as output,
            mock.patch.object(verifier, "check_database", checker or verifier.check_database),
        ):
            verifier.main()
        return output.getvalue()

    def assert_source_unchanged(self):
        self.assertEqual(self.source.read_bytes(), self.source_bytes)

    def test_missing_source_is_not_created(self):
        self.source = self.root / "missing-source.db"
        with self.assertRaises(sqlite3.OperationalError):
            self.run_verifier()
        self.assertFalse(self.source.exists())

    def test_private_restore_and_retained_backup_with_permissive_umask(self):
        original_check = verifier.check_database
        observed = []

        def check(path):
            path = pathlib.Path(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            if path.parent != self.backups:
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                observed.append(path)
            return original_check(path)

        previous_umask = os.umask(0o022)
        try:
            output = self.run_verifier(check)
        finally:
            os.umask(previous_umask)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())
        self.assertFalse(observed[0].parent.exists())
        backups = list(self.backups.glob("vozen-helper-*.db"))
        self.assertEqual(len(backups), 1)
        backup = backups[0]
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o640)
        self.assertEqual(original_check(backup), ("ok", 1, 1))
        self.assertIn(f"backup={backup}", output)
        self.assertIn(f"sha256={hashlib.sha256(backup.read_bytes()).hexdigest()}", output)
        self.assertIn("restore_integrity=ok", output)
        self.assert_source_unchanged()

    def test_restore_cleanup_on_verification_failure(self):
        original_check = verifier.check_database
        observed = []

        def fail_restore(path):
            path = pathlib.Path(path)
            if path.parent != self.backups:
                observed.append(path)
                raise RuntimeError("synthetic restore verification failure")
            return original_check(path)

        with self.assertRaisesRegex(RuntimeError, "synthetic restore verification failure"):
            self.run_verifier(fail_restore)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())
        self.assertFalse(observed[0].parent.exists())
        backup = next(self.backups.glob("vozen-helper-*.db"))
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assert_source_unchanged()

    def test_old_predictable_restore_symlink_cannot_overwrite_target(self):
        sentinel = self.root / "unrelated.db"
        sentinel.write_bytes(b"synthetic unrelated file: preserve exactly")
        old_restore = pathlib.Path("/tmp") / f"vozen-helper-restore-{self.stamp}.db"
        old_restore.symlink_to(sentinel)
        try:
            self.run_verifier()
            self.assertEqual(sentinel.read_bytes(), b"synthetic unrelated file: preserve exactly")
            self.assertTrue(old_restore.is_symlink())
        finally:
            old_restore.unlink(missing_ok=True)
        self.assert_source_unchanged()

    def test_repeated_timestamp_preserves_existing_and_new_backups(self):
        self.backups.mkdir()
        old_backup = self.backups / f"vozen-helper-{self.stamp}.db"
        old_backup.write_bytes(b"synthetic preexisting backup")
        old_backup.chmod(0o640)
        self.run_verifier()
        after_first = {path.name: path.read_bytes() for path in self.backups.iterdir()}
        self.run_verifier()
        after_second = {path.name: path.read_bytes() for path in self.backups.iterdir()}
        self.assertEqual(len(after_first), 2)
        self.assertEqual(len(after_second), 3)
        for name, content in after_first.items():
            self.assertEqual(after_second[name], content)
        self.assertEqual(old_backup.read_bytes(), b"synthetic preexisting backup")
        self.assert_source_unchanged()


if __name__ == "__main__":
    unittest.main()
