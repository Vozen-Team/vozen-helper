import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import cache_cleanup as c


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.apt = self.base / 'apt'
        self.apt.mkdir()
        self.npm = self.base / 'npm'
        self.npm.mkdir()
        self.locks = [self.base / ('lock' + str(i)) for i in range(4)]
        for lock in self.locks:
            lock.touch()

    def apt_files(self):
        for name in ('pkgcache.bin', 'srcpkgcache.bin'):
            (self.apt / name).write_bytes(b'rebuildable')

    def npm_files(self):
        for name in ('content-v2', 'index-v5', 'tmp'):
            folder = self.npm / name
            folder.mkdir()
            (folder / 'cached-entry').write_bytes(b'rebuildable')

    def clean_apt(self, **kwargs):
        return c.clean_apt(self.apt, self.locks, kwargs.get('busy', lambda paths: False))

    def clean_npm(self, **kwargs):
        return c.clean_npm(self.npm, kwargs.get('busy', lambda paths, **opts: False))

    def test_apt_only_two_indexes_removed(self):
        self.apt_files()
        other = self.apt / 'packages.deb'
        other.write_bytes(b'keep')
        self.assertEqual(self.clean_apt()['removed'], ['pkgcache.bin', 'srcpkgcache.bin'])
        self.assertEqual(other.read_bytes(), b'keep')
        self.assertEqual(self.clean_apt()['removed'], [])

    def test_apt_missing_lock_defers(self):
        self.apt_files()
        self.locks[0].unlink()
        self.assertIn('skipped', self.clean_apt())
        self.assertTrue((self.apt / 'pkgcache.bin').exists())

    def test_real_exclusive_apt_writer_defers(self):
        self.apt_files()
        process = subprocess.Popen([sys.executable, '-c',
            'import fcntl,sys; f=open(sys.argv[1],"r+b"); fcntl.lockf(f,fcntl.LOCK_EX); print("ready",flush=True); sys.stdin.read()',
            str(self.locks[0])], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'ready')
            self.assertIn('skipped', self.clean_apt())
            self.assertTrue((self.apt / 'pkgcache.bin').exists())
        finally:
            process.communicate('done', timeout=5)

    def test_apt_open_reference_defers(self):
        self.apt_files()
        self.assertIn('skipped', self.clean_apt(busy=lambda paths: True))

    def test_apt_becoming_busy_defers(self):
        self.apt_files()
        calls = iter([False, True])
        self.assertIn('skipped', self.clean_apt(busy=lambda paths: next(calls)))
        self.assertTrue((self.apt / 'pkgcache.bin').exists())

    def test_apt_symlink_is_not_followed(self):
        private = self.base / 'backup.db'
        private.write_bytes(b'keep')
        (self.apt / 'pkgcache.bin').symlink_to(private)
        with self.assertRaises(ValueError):
            self.clean_apt()
        self.assertEqual(private.read_bytes(), b'keep')

    def test_apt_hardlink_is_preserved(self):
        self.apt_files()
        os.link(self.apt / 'pkgcache.bin', self.base / 'private')
        with self.assertRaises(ValueError):
            self.clean_apt()

    def test_apt_redirected_root_aborts(self):
        real = self.apt.rename(self.base / 'real-apt')
        self.apt.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.clean_apt()

    def test_npm_only_recognized_children_removed_root_ownership_retained(self):
        self.npm_files()
        before = self.npm.stat()
        result = self.clean_npm()
        self.assertEqual(set(result['removed']), {'content-v2', 'index-v5', 'tmp'})
        after = self.npm.stat()
        self.assertEqual((before.st_ino, before.st_uid, before.st_gid),
                         (after.st_ino, after.st_uid, after.st_gid))
        self.assertEqual(self.clean_npm()['removed'], [])

    def test_npm_unknown_files_and_settings_preserved(self):
        self.npm_files()
        (self.npm / 'backup.db').write_bytes(b'keep')
        (self.npm.parent / '.npmrc').write_bytes(b'keep config')
        self.clean_npm()
        self.assertEqual((self.npm / 'backup.db').read_bytes(), b'keep')
        self.assertEqual((self.npm.parent / '.npmrc').read_bytes(), b'keep config')

    def test_npm_busy_defers(self):
        self.npm_files()
        self.assertIn('skipped', self.clean_npm(busy=lambda paths, **opts: True))
        self.assertTrue((self.npm / 'tmp/cached-entry').exists())

    def test_npm_becoming_busy_defers(self):
        self.npm_files()
        calls = iter([False, True])
        self.assertIn('skipped', self.clean_npm(busy=lambda paths, **opts: next(calls)))
        self.assertTrue((self.npm / 'content-v2').exists())

    def test_missing_npm_cache_is_not_created(self):
        self.npm.rmdir()
        self.assertIn('skipped', self.clean_npm())
        self.assertFalse(self.npm.exists())

    def test_npm_symlink_inside_cache_aborts(self):
        self.npm_files()
        (self.npm / 'content-v2/private').symlink_to(self.base / 'private')
        with self.assertRaises(ValueError):
            self.clean_npm()
        self.assertTrue((self.npm / 'content-v2/cached-entry').exists())

    def test_npm_hardlink_inside_cache_aborts(self):
        self.npm_files()
        os.link(self.npm / 'content-v2/cached-entry', self.base / 'private')
        with self.assertRaises(ValueError):
            self.clean_npm()

    def test_redirected_npm_root_aborts(self):
        real = self.npm.rename(self.base / 'real-npm')
        self.npm.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.clean_npm()

    def test_data_and_backups_outside_caches_untouched(self):
        self.npm_files()
        self.apt_files()
        for name in ('data', 'backups', 'releases'):
            folder = self.base / name
            folder.mkdir()
            (folder / 'important').write_bytes(b'keep')
        self.clean_apt()
        self.clean_npm()
        self.assertTrue(all((self.base / n / 'important').read_bytes() == b'keep'
                            for n in ('data', 'backups', 'releases')))

    def fake_proc(self, args=b'node\0npm-cli.js\0', name='node'):
        root = self.base / 'proc'
        proc = root / '123'
        (proc / 'fd').mkdir(parents=True)
        (proc / 'comm').write_text(name)
        (proc / 'cmdline').write_bytes(args)
        (proc / 'cwd').symlink_to(self.base)
        return root, proc

    def test_npm_node_cli_detected(self):
        root, _ = self.fake_proc()
        self.assertTrue(c.busy([self.npm], npm=True, proc_root=root))

    def test_npm_named_process_detected(self):
        root, _ = self.fake_proc(args=b'node\0', name='npm install')
        self.assertTrue(c.busy([self.npm], npm=True, proc_root=root))

    def test_open_cache_descriptor_detected(self):
        root, proc = self.fake_proc(args=b'other\0')
        (proc / 'fd/4').symlink_to(self.npm / 'content-v2/file')
        self.assertTrue(c.busy([self.npm], npm=True, proc_root=root))

    def test_unreadable_reference_aborts(self):
        root, _ = self.fake_proc(args=b'other\0')
        with patch.object(c.os, 'readlink', side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):
                c.busy([self.npm], proc_root=root)

    def test_maintenance_own_cache_directory_descriptor_is_ignored(self):
        proc_root = self.base / 'self-proc'
        proc_root.mkdir()
        (proc_root / str(os.getpid())).symlink_to('/proc/self', target_is_directory=True)
        descriptor = os.open(self.npm, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertFalse(c.busy([self.npm], npm=True, proc_root=proc_root))
        finally:
            os.close(descriptor)

    def test_systemd_write_scope_and_weekly_schedule(self):
        unit = Path(__file__).with_name('vozen-cache-cleanup.service').read_text()
        self.assertEqual([line for line in unit.splitlines() if line.startswith('ReadWritePaths=')],
                         ['ReadWritePaths=/var/cache/apt /var/lib/vozen-cache-cleanup',
                          'ReadWritePaths=-/home/ubuntu/.npm/_cacache'])
        self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('ProtectHome=read-only', unit)
        timer = Path(__file__).with_name('vozen-cache-cleanup.timer').read_text()
        self.assertIn('OnCalendar=Sun *-*-* 04:00:00 UTC', timer)
        self.assertIn('Persistent=true', timer)


if __name__ == '__main__':
    unittest.main()
