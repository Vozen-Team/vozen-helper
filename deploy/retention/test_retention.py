import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import retention as r

A, B, C, D = (letter * 40 for letter in 'abcd')


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'helper'
        self.releases = self.root / 'releases'
        self.releases.mkdir(parents=True)
        self.state = Path(self.temp.name) / 'state'
        self.state.mkdir()
        for index, name in enumerate((A, B, C, D)):
            folder = self.releases / name
            (folder / 'bin').mkdir(parents=True)
            (folder / 'bin/vozen-helper').write_bytes(b'\x7fELFfixture')
            (folder / 'deploy').mkdir()
            for file in ('ROLLBACK.md', 'vozen-helper-rust.service'):
                (folder / 'deploy' / file).write_text('fixture')
            os.utime(folder, ns=(index + 1, index + 1))
        self.write_state(C, B)
        self.observe = lambda root: (C, {'pid': '123'})

    def write_state(self, current, rollback):
        (self.state / 'state.json').write_text(json.dumps(dict(current=current, rollback=rollback)))

    def run_cleanup(self, refs=None, health=lambda: None, observe=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return r.cleanup(self.root, self.state, observe or self.observe,
                             health, refs or (lambda root: set()))

    def test_keeps_current_rollback_and_newer_staging(self):
        result = self.run_cleanup()
        self.assertEqual(result['removed'], [A])
        self.assertEqual({p.name for p in self.releases.iterdir()}, {B, C, D})
        self.assertEqual(self.run_cleanup()['removed'], [])

    def test_new_healthy_release_rotates_rollback(self):
        result = self.run_cleanup(observe=lambda root: (D, {}))
        self.assertEqual(set(result['removed']), {A, B})
        self.assertEqual(json.loads((self.state / 'state.json').read_text()),
                         {'current': D, 'rollback': C})

    def test_rollback_rotates_without_deleting_former_current(self):
        result = self.run_cleanup(observe=lambda root: (B, {}))
        self.assertEqual(result['current'], B)
        self.assertEqual(result['rollback'], C)
        self.assertTrue((self.releases / C).exists())

    def test_live_reference_is_protected(self):
        self.assertEqual(self.run_cleanup(refs=lambda root: {A})['removed'], [])

    def test_reference_appearing_before_delete_is_protected(self):
        with patch.object(r, 'protected_releases'):
            calls = iter([set(), {A}])
            self.assertEqual(self.run_cleanup(refs=lambda root: next(calls))['removed'], [])

    def test_unknown_archive_inside_release_is_preserved(self):
        (self.releases / A / 'backup.tar.gz').write_bytes(b'archive')
        self.assertEqual(self.run_cleanup()['removed'], [])

    def test_malformed_names_and_archives_are_preserved(self):
        (self.releases / (A + '#!')).mkdir()
        (self.releases / (A + '.tar.gz')).write_bytes(b'archive')
        self.run_cleanup()
        self.assertTrue((self.releases / (A + '#!')).exists())
        self.assertTrue((self.releases / (A + '.tar.gz')).exists())

    def test_symlink_inside_release_is_preserved(self):
        binary = self.releases / A / 'bin/vozen-helper'
        binary.unlink()
        binary.symlink_to(self.releases / B / 'bin/vozen-helper')
        self.assertEqual(self.run_cleanup()['removed'], [])

    def test_symlink_release_is_preserved(self):
        r.shutil.rmtree(self.releases / A)
        (self.releases / A).symlink_to(self.releases / B, target_is_directory=True)
        self.assertEqual(self.run_cleanup()['removed'], [])

    def test_hardlinked_content_is_preserved(self):
        os.link(self.releases / A / 'bin/vozen-helper', self.root / 'external')
        self.assertEqual(self.run_cleanup()['removed'], [])

    def test_non_elf_is_preserved(self):
        (self.releases / A / 'bin/vozen-helper').write_bytes(b'database')
        self.assertEqual(self.run_cleanup()['removed'], [])

    def test_missing_rollback_aborts(self):
        self.write_state(C, 'e' * 40)
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.assertTrue((self.releases / A).exists())

    def test_path_traversal_state_aborts(self):
        self.write_state(C, '../../backups')
        with self.assertRaises(ValueError):
            self.run_cleanup()

    def test_failed_health_does_not_update_state_or_delete(self):
        before = (self.state / 'state.json').read_bytes()
        with self.assertRaises(ValueError):
            self.run_cleanup(health=lambda: (_ for _ in ()).throw(ValueError('unhealthy')))
        self.assertEqual((self.state / 'state.json').read_bytes(), before)
        self.assertTrue((self.releases / A).exists())

    def test_changed_current_aborts_before_deletion(self):
        observations = iter([(C, {}), (D, {})])
        with self.assertRaises(ValueError):
            self.run_cleanup(observe=lambda root: next(observations))
        self.assertTrue((self.releases / A).exists())

    def test_changed_current_at_removal_aborts(self):
        observations = iter([(C, {}), (C, {}), (D, {})])
        with self.assertRaises(ValueError):
            self.run_cleanup(observe=lambda root: next(observations))
        self.assertTrue((self.releases / A).exists())

    def test_failed_removal_can_be_retried(self):
        with patch.object(r.shutil, 'rmtree', side_effect=OSError('busy')) as remove:
            remove.avoids_symlink_attacks = True
            with self.assertRaises(OSError):
                self.run_cleanup()
        self.assertEqual(self.run_cleanup()['removed'], [A])

    def test_backups_and_shared_data_untouched(self):
        for folder in ('backups', 'shared/data', 'shared/release-cache'):
            path = self.root / folder
            path.mkdir(parents=True)
            (path / 'important').write_bytes(b'keep exactly')
        before = {str(p): p.read_bytes() for p in self.root.rglob('important')}
        self.run_cleanup()
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('important')})

    def test_systemd_write_scope_excludes_data_and_backups(self):
        unit = Path(__file__).with_name('vozen-helper-release-retention.service').read_text()
        writable = next(line for line in unit.splitlines() if line.startswith('ReadWritePaths='))
        self.assertEqual(writable, 'ReadWritePaths=/home/vozen/vozen-helper-rust/releases /var/lib/vozen-helper-release-retention')
        self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('ProtectHome=read-only', unit)


if __name__ == '__main__':
    unittest.main()
