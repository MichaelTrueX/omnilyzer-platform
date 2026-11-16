#!/usr/bin/python3 -I
"""Root-owned, zero-argument, one-use D11 source-install capability only.

Issue281: permits the delivery agent to run the reviewed source-only operation
without a general root shell. No signed dispatch, replay reset or root daemon.
Installed by the separately owner-interactive exact-hash bootstrap.
"""
import hashlib
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile

SELF = Path('/usr/local/sbin/omnilyzer-m05-d11-delivery-once')
SOURCE = Path('/usr/local/lib/m05-analytics016-d11-delivery/operator.py')
SOURCE_SHA = 'e4ea1e0d6d1657672a4aeeafba4d444b72f89223742a7b7ddf339f67e3b6694a'
CONSUMED = Path('/var/lib/omnilyzer/deployment/.m05-d11-delivery-command-consumed')


def require(ok):
    if ok is not True:
        raise ValueError('fixed custody hold')


def regular(path, mode):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and
            (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) ==
            (0, 0, mode, 1))
    return s


def main():
    snapshot = None
    try:
        require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) ==
                (0, 0, 0, 0) and socket.gethostname() == 'omnilyzerdev'
                and sys.argv == [str(SELF)] and Path(__file__) == SELF)
        os.umask(0o077)
        regular(SELF, 0o750)
        for folder in (SELF.parent, SOURCE.parent, CONSUMED.parent, Path('/run')):
            s = folder.lstat()
            require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0
                    and stat.S_IMODE(s.st_mode) & 0o022 == 0)
        before = regular(SOURCE, 0o400)
        fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(fd)
            require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino))
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(65537)
            after = os.fstat(fd)
            require(0 < len(raw) <= 65536 and
                    hashlib.sha256(raw).hexdigest() == SOURCE_SHA and
                    (opened.st_dev, opened.st_ino, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns))
        finally:
            os.close(fd)
        # O_EXCL is deliberately before invoking any part of the operator.
        # Failure, interruption and success all permanently consume this grant.
        fd = os.open(CONSUMED, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, b'D11_DELIVERY_ONE_SOURCE_OPERATION_CONSUMED_NO_RETRY\n')
            os.fsync(fd)
        finally:
            os.close(fd)
        parent_fd = os.open(CONSUMED.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        snapshot = Path(tempfile.mkdtemp(prefix='m05-analytics016-d11-delivery-launch.',
                                        dir='/run'))
        file = snapshot / 'operator.py'
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        regular(file, 0o400)
        require(hashlib.sha256(file.read_bytes()).hexdigest() == SOURCE_SHA)
        print('M05_DELIVERY_ROOT_CAPABILITY_CONSUMED_SNAPSHOT_PASS', flush=True)
        return subprocess.run([
            '/usr/bin/python3', '-I', '-B', str(file),
            '--apply-approved-analytics016-d11-delivery-once',
        ], stdin=subprocess.DEVNULL, cwd='/opt/omnilyzer/deployment',
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                 'HOME': '/nonexistent', 'PYTHONDONTWRITEBYTECODE': '1'},
            check=False).returncode
    except Exception:
        print('M05_DELIVERY_ROOT_CAPABILITY_HOLD_NO_RETRY', flush=True)
        return 2
    finally:
        if snapshot is not None:
            (snapshot / 'operator.py').unlink(missing_ok=True)
            snapshot.rmdir()


if __name__ == '__main__':
    raise SystemExit(main())
