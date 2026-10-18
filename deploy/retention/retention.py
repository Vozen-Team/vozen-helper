#!/usr/bin/env python3
"""Keep the healthy Helper release and its predecessor; never prune shared data."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path('/home/vozen/vozen-helper-rust')
STATE = Path('/var/lib/vozen-helper-release-retention')
PACKAGE_ROOT = Path('/home/ubuntu')
SHA = re.compile(r'[0-9a-f]{40}')
STAGE = re.compile(r'helper-[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]{8}')
PACKAGE = re.compile(r'vozen-helper-rust-([0-9a-f]{40})\.tar\.gz')


def release_name(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError('invalid release revision')
    return value


def snapshot(root):
    releases = root / 'releases'
    if releases.is_symlink() or releases.resolve() != releases:
        raise ValueError('releases root must be a real fixed directory')
    current = (root / 'current').resolve(strict=True)
    if current.parent != releases:
        raise ValueError('current is outside releases')
    revision = release_name(current.name)
    props = dict(line.split('=', 1) for line in subprocess.check_output(
        ['systemctl', 'show', 'vozen-helper.service', '-p', 'MainPID',
         '-p', 'ActiveState', '-p', 'ExecMainStartTimestampMonotonic'],
        text=True, timeout=10).splitlines())
    if props['ActiveState'] != 'active' or int(props['MainPID']) <= 0:
        raise ValueError('Helper is not active')
    if not os.path.samefile('/proc/' + props['MainPID'] + '/exe',
                            current / 'bin/vozen-helper'):
        raise ValueError('current symlink does not match running binary')
    return revision, props


def healthy():
    # No proxy or redirects: only the local Helper health endpoint may approve.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open('http://127.0.0.1:8788/health', timeout=5) as response:
        if response.status != 200 or json.loads(response.read(4096)).get('status') != 'ok':
            raise ValueError('Helper health failed')


def protected_releases(root):
    """Protect every process exe/cwd and additional deployment symlink."""
    protected = set()
    releases = root / 'releases'
    paths = [p for p in root.iterdir() if p.is_symlink()]
    for proc in Path('/proc').iterdir():
        if proc.name.isdecimal():
            paths.extend([proc / 'exe', proc / 'cwd'])
    for path in paths:
        try:
            target = Path(os.readlink(path))
            if not target.is_absolute():
                target = path.parent / target
            relative = target.relative_to(releases)
            if relative.parts and SHA.fullmatch(relative.parts[0]):
                protected.add(relative.parts[0])
        except (FileNotFoundError, ProcessLookupError):
            continue  # A process can exit during the scan.
        except ValueError:
            continue  # Reference belongs to another application.
        # Permission failures deliberately abort rather than ignore live refs.
    return protected


def code_only(path):
    """Recognize the exact deployed code layout; unknown content stays put."""
    allowed = {'bin', 'deploy'}
    if path.is_symlink() or not path.is_dir() or os.path.ismount(path):
        return False
    if {p.name for p in path.iterdir()} != allowed:
        return False
    expected = {'bin': {'vozen-helper'},
                'deploy': {'ROLLBACK.md', 'vozen-helper-rust.service'}}
    device = path.stat().st_dev
    for directory, names in expected.items():
        folder = path / directory
        if folder.is_symlink() or not folder.is_dir() or os.path.ismount(folder):
            return False
        if {p.name for p in folder.iterdir()} != names:
            return False
        for file in folder.iterdir():
            info = file.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_dev != device or info.st_nlink != 1:
                return False
    with (path / 'bin/vozen-helper').open('rb') as binary:
        return binary.read(4) == b'\x7fELF'


def advance(state, current, releases):
    previous = release_name(state['current'])
    rollback = release_name(state['rollback'])
    if previous == rollback:
        raise ValueError('current and rollback must be distinct')
    for name in (previous, rollback, current):
        path = releases / release_name(name)
        if path.is_symlink() or not (path / 'bin/vozen-helper').is_file():
            raise ValueError('protected release missing or unsafe')
    return {'current': current, 'rollback': previous if current != previous else rollback}


def save_state(directory, state):
    temp = directory / 'state.json.tmp'
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(state, output)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, directory / 'state.json')


def package_fingerprint(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or not 0 < info.st_size <= 100 * 1024 * 1024 or os.path.ismount(path)):
        raise ValueError('package is not a recognized regular archive')
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def package_code_only(path):
    """Read, never extract: accept only the exact binary/deploy archive layout."""
    expected = {'.', './bin', './deploy', './bin/vozen-helper',
                './deploy/ROLLBACK.md', './deploy/vozen-helper-rust.service'}
    try:
        package_fingerprint(path)
        with tarfile.open(path, 'r:gz') as archive:
            seen = set()
            for member in archive:
                if member.name not in expected or member.name in seen:
                    return False
                seen.add(member.name)
                directory = member.name in {'.', './bin', './deploy'}
                if directory:
                    if not member.isdir():
                        return False
                elif not member.isfile():
                    return False
                elif member.name == './bin/vozen-helper':
                    if not 4 <= member.size <= 200 * 1024 * 1024:
                        return False
                    with archive.extractfile(member) as binary:
                        if binary.read(4) != b'\x7fELF':
                            return False
                elif member.size > 64 * 1024:
                    return False
            return seen == expected
    except (OSError, ValueError, EOFError, tarfile.TarError):
        return False


def packages_in_use(paths, proc_root=Path('/proc')):
    protected = set()
    for proc in proc_root.iterdir():
        if not proc.name.isdecimal():
            continue
        links = [proc / 'exe', proc / 'cwd'] + list((proc / 'fd').glob('*'))
        for link in links:
            try:
                target = Path(os.readlink(link))
            except (FileNotFoundError, ProcessLookupError):
                continue
            for path in paths:
                if target == path or (link.name == 'cwd' and target.is_relative_to(path.parent)):
                    protected.add(path)
        # Permission failures abort rather than hide a possible publication.
    return protected


def cleanup_packages(root, state_dir, package_root, observe=snapshot,
                     check_health=healthy, in_use=packages_in_use):
    if package_root.resolve() != package_root or package_root.is_symlink():
        raise ValueError('package root must be a real fixed directory')
    first = observe(root)
    check_health()
    state_bytes = (state_dir / 'state.json').read_bytes()
    state = json.loads(state_bytes)
    keep = {release_name(state['current']), release_name(state['rollback'])}
    if state['current'] != first[0] or len(keep) != 2:
        raise ValueError('package retention state does not match healthy current')
    for revision in keep:
        if not (root / 'releases' / revision / 'bin/vozen-helper').is_file():
            raise ValueError('retained binary missing')
    cutoff = (root / 'releases' / first[0]).stat().st_mtime_ns
    candidates, skipped = [], []
    for folder in sorted(package_root.iterdir()):
        if not STAGE.fullmatch(folder.name):
            continue
        if {'backup', 'backups', 'snapshot', 'snapshots', 'restore', 'data'} & set(folder.name.split('-')):
            continue
        if folder.is_symlink() or not folder.is_dir() or os.path.ismount(folder):
            continue
        for path in sorted(folder.iterdir()):
            match = PACKAGE.fullmatch(path.name)
            if not match or match[1] in keep:
                continue
            try:
                fingerprint = package_fingerprint(path)
            except (OSError, ValueError):
                skipped.append(str(path))
                continue
            if fingerprint[3] >= cutoff or not package_code_only(path):
                skipped.append(str(path))
                continue
            candidates.append((path, fingerprint))
    busy = in_use([path for path, _ in candidates])
    removed = []
    for path, fingerprint in candidates:
        if (observe(root) != first or (state_dir / 'state.json').read_bytes() != state_bytes):
            raise ValueError('publication changed; remaining package cleanup cancelled')
        if path in busy or path in in_use([path]):
            skipped.append(str(path))
            continue
        # Open only the validated immediate staging directory; never recurse.
        if path.parent.resolve() != path.parent:
            raise ValueError('staging directory changed')
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if package_fingerprint(path) != fingerprint or not package_code_only(path):
                raise ValueError('package changed before removal')
            opened = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != fingerprint[:2]:
                raise ValueError('staging directory changed before removal')
            if (observe(root) != first or (state_dir / 'state.json').read_bytes() != state_bytes):
                raise ValueError('publication changed during package inspection')
            os.unlink(path.name, dir_fd=fd)
        finally:
            os.close(fd)
        removed.append(str(path))
        print(json.dumps({'removed_package': str(path)}), flush=True)
    result = {'package_retention': True, 'current': state['current'],
              'rollback': state['rollback'], 'removed': removed, 'skipped': skipped}
    print(json.dumps(result), flush=True)
    return result


def cleanup(root, state_dir, observe=snapshot, check_health=healthy,
            references=protected_releases):
    first = observe(root)
    check_health()
    releases = root / 'releases'
    state = advance(json.loads((state_dir / 'state.json').read_text()), first[0], releases)
    if observe(root) != first:
        raise ValueError('deployment changed during health check')
    save_state(state_dir, state)
    keep = set(state.values()) | references(root)
    # Newly staged directories must survive even if they are not running yet.
    cutoff = (releases / first[0]).stat().st_mtime_ns
    candidates, skipped = [], []
    for path in sorted(releases.iterdir()):
        if path.name in keep:
            continue
        if (not SHA.fullmatch(path.name) or not code_only(path)
                or path.stat().st_mtime_ns >= cutoff):
            skipped.append(path.name)
            continue
        candidates.append((path.name, path.stat().st_dev, path.stat().st_ino))
    removed = []
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError('fd-safe rmtree required')
    with contextlib.ExitStack() as stack:
        fd = os.open(releases, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        for name, device, inode in candidates:
            if observe(root) != first:
                raise ValueError('deployment changed; remaining cleanup cancelled')
            if name in references(root):
                continue
            path = releases / name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (device, inode) or not code_only(path):
                raise ValueError('release changed before removal')
            # The only deletion in this program is a validated immediate release.
            shutil.rmtree(name, dir_fd=fd)
            removed.append(name)
            print(json.dumps({'removed': name}), flush=True)
    result = {'current': state['current'], 'rollback': state['rollback'],
              'removed': removed, 'skipped': skipped, 'protected': sorted(keep)}
    print(json.dumps(result), flush=True)
    return result


def main():
    try:
        with (STATE / 'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # ExecStartPost queues this unit after Helper becomes active. Allow
            # the HTTP listener a short bounded startup window before skipping.
            for attempt in range(10):
                try:
                    snapshot(ROOT)
                    healthy()
                    break
                except (OSError, ValueError):
                    if attempt == 9:
                        raise
                    time.sleep(2)
            cleanup(ROOT, STATE)
            cleanup_packages(ROOT, STATE, PACKAGE_ROOT)
    except Exception as error:
        # A maintenance problem must not take a healthy bot offline.
        print(json.dumps({'warning': str(error), 'cleanup': 'stopped'}), flush=True)


if __name__ == '__main__':
    main()
