import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
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
        self.assertEqual([line for line in unit.splitlines() if line.startswith('ReadWritePaths=')],
                         [writable, 'ReadWritePaths=/home/ubuntu'])


class PackageTests(unittest.TestCase):
    write_state = RetentionTests.write_state

    def setUp(self):
        RetentionTests.setUp(self)
        self.packages = Path(self.temp.name) / 'packages'
        self.packages.mkdir()
        self.stage = self.packages / 'helper-feature-20261018'
        self.stage.mkdir()

    def package(self, revision=A, folder=None, extra=None):
        path = (folder or self.stage) / ('vozen-helper-rust-' + revision + '.tar.gz')
        with tarfile.open(path, 'w:gz') as archive:
            for name in ('.', './bin', './deploy'):
                item = tarfile.TarInfo(name)
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
            files = {'./bin/vozen-helper': b'\x7fELFfixture',
                     './deploy/ROLLBACK.md': b'rollback instructions',
                     './deploy/vozen-helper-rust.service': b'service'}
            if extra:
                files.update(extra)
            for name, data in files.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        os.utime(path, ns=(1, 1))
        return path

    def clean(self, **kwargs):
        kwargs.setdefault('observe', self.observe)
        kwargs.setdefault('check_health', lambda: None)
        kwargs.setdefault('in_use', lambda paths: set())
        with contextlib.redirect_stdout(io.StringIO()):
            return r.cleanup_packages(self.root, self.state, self.packages, **kwargs)

    def test_only_old_package_deleted_current_and_rollback_preserved(self):
        old = self.package(A)
        current, rollback = self.package(C), self.package(B)
        self.assertEqual(self.clean()['removed'], [str(old)])
        self.assertTrue(current.exists() and rollback.exists())
        self.assertEqual(self.clean()['removed'], [])

    def test_duplicate_retained_packages_in_other_staging_directory_survive(self):
        other = self.packages / 'helper-another-20261018'
        other.mkdir()
        current = self.package(C, folder=other)
        self.clean()
        self.assertTrue(current.exists())

    def test_archive_with_database_is_preserved(self):
        path = self.package(extra={'./snapshot.db': b'important'})
        self.assertEqual(self.clean()['removed'], [])
        self.assertTrue(path.exists())

    def test_archive_with_environment_file_is_preserved(self):
        self.package(extra={'./.env': b'private'})
        self.assertEqual(self.clean()['removed'], [])

    def test_archive_path_traversal_is_preserved(self):
        self.package(extra={'../backups/database': b'private'})
        self.assertEqual(self.clean()['removed'], [])

    def test_unknown_and_backup_staging_directories_are_preserved(self):
        for name in ('helper-backup-20261018', 'helper-snapshot-20261018', 'other-project', 'helper-undated'):
            folder = self.packages / name
            folder.mkdir()
            path = self.package(folder=folder)
            self.clean()
            self.assertTrue(path.exists())

    def test_newer_staged_package_survives(self):
        path = self.package(D)
        os.utime(path, ns=(4, 4))
        self.assertEqual(self.clean()['removed'], [])

    def test_open_package_survives(self):
        path = self.package()
        self.assertEqual(self.clean(in_use=lambda paths: {path})['removed'], [])

    def test_reference_appearing_before_unlink_survives(self):
        path = self.package()
        references = iter([set(), {path}])
        self.assertEqual(self.clean(in_use=lambda paths: next(references))['removed'], [])

    def test_real_open_file_reference_is_detected(self):
        path = self.package()
        proc_root = Path(self.temp.name) / 'proc'
        proc_root.mkdir()
        (proc_root / str(os.getpid())).symlink_to('/proc/self', target_is_directory=True)
        with path.open('rb'):
            self.assertIn(path, r.packages_in_use([path], proc_root))

    def test_unreadable_process_reference_aborts(self):
        proc_root = Path(self.temp.name) / 'proc'
        proc_root.mkdir()
        (proc_root / '123').mkdir()
        with patch.object(r.os, 'readlink', side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):
                r.packages_in_use([self.package()], proc_root)

    def test_package_symlink_is_preserved(self):
        path = self.package()
        original = path.rename(self.packages / 'original.tar.gz')
        path.symlink_to(original)
        self.assertEqual(self.clean()['removed'], [])

    def test_staging_symlink_is_preserved(self):
        path = self.package()
        folder = self.stage.rename(self.packages / 'original')
        self.stage.symlink_to(folder, target_is_directory=True)
        self.assertEqual(self.clean()['removed'], [])
        self.assertTrue(path.exists())

    def test_hardlinked_package_is_preserved(self):
        path = self.package()
        os.link(path, self.packages / 'archive-copy')
        self.assertEqual(self.clean()['removed'], [])

    def test_corrupt_archive_is_preserved(self):
        path = self.package()
        path.write_bytes(b'not gzip')
        os.utime(path, ns=(1, 1))
        self.assertEqual(self.clean()['removed'], [])

    def test_failed_health_preserves_packages(self):
        path = self.package()
        with self.assertRaises(ValueError):
            self.clean(check_health=lambda: (_ for _ in ()).throw(ValueError('unhealthy')))
        self.assertTrue(path.exists())

    def test_changed_publication_cancels_removal(self):
        path = self.package()
        observations = iter([(C, {}), (D, {})])
        with self.assertRaises(ValueError):
            self.clean(observe=lambda root: next(observations))
        self.assertTrue(path.exists())

    def test_changed_state_cancels_removal(self):
        path = self.package()
        def busy(paths):
            self.write_state(D, C)
            return set()
        with self.assertRaises(ValueError):
            self.clean(in_use=busy)
        self.assertTrue(path.exists())

    def test_missing_retained_binary_cancels(self):
        path = self.package()
        (self.releases / B / 'bin/vozen-helper').unlink()
        with self.assertRaises(ValueError):
            self.clean()
        self.assertTrue(path.exists())

    def test_state_change_during_final_archive_inspection_cancels(self):
        path = self.package()
        validate = r.package_code_only
        calls = []
        def inspect(archive):
            result = validate(archive)
            calls.append(archive)
            if len(calls) == 2:
                self.write_state(D, C)
            return result
        with patch.object(r, 'package_code_only', side_effect=inspect):
            with self.assertRaises(ValueError):
                self.clean()
        self.assertTrue(path.exists())

    def test_scripts_backups_data_and_unknown_files_untouched(self):
        self.package()
        files = [self.stage / 'activate.sh', self.stage / 'backup.db',
                 self.stage / 'snapshot.tar.gz', self.packages / 'private-data']
        for file in files:
            file.write_bytes(b'keep exactly')
        self.clean()
        self.assertTrue(self.stage.exists())
        self.assertTrue(all(file.read_bytes() == b'keep exactly' for file in files))


if __name__ == '__main__':
    unittest.main()
