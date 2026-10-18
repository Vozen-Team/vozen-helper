#!/usr/bin/env python3
"""Weekly maintenance of two APT indexes and Ubuntu's npm download cache."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat

APT = Path('/var/cache/apt')
NPM = Path('/home/ubuntu/.npm/_cacache')
STATE = Path('/var/lib/vozen-cache-cleanup')
APT_LOCKS = [Path(p) for p in ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock',
                              '/var/cache/apt/archives/lock', '/var/lib/apt/lists/lock')]


def identity(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or os.path.ismount(path)):
        raise ValueError('unexpected cache file type: ' + str(path))
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def real_directory(path):
    return path.is_dir() and not path.is_symlink() and path.resolve() == path


def busy(paths, npm=False, proc_root=Path('/proc')):
    for proc in proc_root.iterdir():
        if not proc.name.isdecimal() or proc.name == str(os.getpid()):
            continue
        try:
            if npm:
                name = (proc / 'comm').read_text().strip()
                args = (proc / 'cmdline').read_bytes().split(b'\0')
                if name.startswith(('npm', 'npx')) or any(
                    arg.rsplit(b'/', 1)[-1] in (b'npm', b'npx', b'npm-cli.js', b'npx-cli.js')
                    for arg in args):
                    return True
            for link in [proc / 'cwd'] + list((proc / 'fd').glob('*')):
                try:
                    target = Path(os.readlink(link))
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if any(target == path or target.is_relative_to(path) for path in paths):
                    return True
        except (FileNotFoundError, ProcessLookupError):
            continue
        # Permission failures propagate: do not assume unreadable refs are idle.
    return False


def clean_apt(root=APT, locks=APT_LOCKS, is_busy=busy):
    if not real_directory(root):
        raise ValueError('APT cache root is missing or redirected')
    paths = [root / name for name in ('pkgcache.bin', 'srcpkgcache.bin')]
    with contextlib.ExitStack() as stack:
        try:
            for path in locks:
                lock = stack.enter_context(path.open('rb'))
                fcntl.lockf(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except (BlockingIOError, FileNotFoundError):
            return {'cache': 'apt', 'skipped': 'package manager lock busy or missing'}
        if is_busy(paths):
            return {'cache': 'apt', 'skipped': 'cache in use'}
        removed, allocated = [], 0
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        for path in paths:
            if not path.exists() and not path.is_symlink():
                continue
            before = identity(path)
            if is_busy(paths):
                return {'cache': 'apt', 'removed': removed, 'bytes': allocated,
                        'skipped': 'cache became busy'}
            opened = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            if identity(path) != before or (opened.st_dev, opened.st_ino) != before[:2]:
                raise ValueError('APT cache changed during inspection')
            allocated += opened.st_blocks * 512
            os.unlink(path.name, dir_fd=fd)
            removed.append(path.name)
        return {'cache': 'apt', 'removed': removed, 'bytes': allocated}


def cache_tree(path, device):
    allocated = 0
    for item in [path] + list(path.rglob('*')):
        info = item.lstat()
        if (info.st_dev != device or os.path.ismount(item) or item.is_symlink()
                or not (stat.S_ISDIR(info.st_mode)
                        or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1))):
            raise ValueError('unexpected npm cache layout: ' + str(item))
        allocated += info.st_blocks * 512
    return allocated


def clean_npm(root=NPM, is_busy=busy):
    if not root.exists() and not root.is_symlink():
        return {'cache': 'npm', 'skipped': 'cache absent'}
    if not real_directory(root):
        raise ValueError('npm cache root redirected')
    if is_busy([root], npm=True):
        return {'cache': 'npm', 'skipped': 'npm or cache in use'}
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError('fd-safe rmtree required')
    removed, skipped, allocated = [], [], 0
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for child in sorted(root.iterdir()):
            if not re.fullmatch(r'(?:content-v[0-9]+|index-v[0-9]+|tmp)', child.name):
                skipped.append(child.name)
                continue
            before = child.lstat()
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('npm cache child must be a directory')
            size = cache_tree(child, root.stat().st_dev)
            if is_busy([root], npm=True):
                return {'cache': 'npm', 'removed': removed, 'bytes': allocated,
                        'skipped': 'npm or cache became busy'}
            opened = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
            if ((opened.st_dev, opened.st_ino, opened.st_mtime_ns)
                    != (before.st_dev, before.st_ino, before.st_mtime_ns)):
                raise ValueError('npm cache changed during inspection')
            shutil.rmtree(child.name, dir_fd=fd)
            allocated += size
            removed.append(child.name)
    finally:
        os.close(fd)
    return {'cache': 'npm', 'removed': removed, 'bytes': allocated, 'unknown_preserved': skipped}


def main():
    with (STATE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        results = []
        for clean in (clean_apt, clean_npm):
            try:
                results.append(clean())
            except Exception as error:
                results.append({'warning': str(error), 'cleanup': 'stopped'})
        result = {'results': results}
        temporary = STATE / 'last-run.json.tmp'
        temporary.write_text(json.dumps(result, indent=2))
        os.chmod(temporary, 0o600)
        os.replace(temporary, STATE / 'last-run.json')
        print(json.dumps(result), flush=True)
        return int(any('warning' in item for item in results))


if __name__ == '__main__':
    raise SystemExit(main())
