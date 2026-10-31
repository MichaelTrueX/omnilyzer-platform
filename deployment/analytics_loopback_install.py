#!/usr/bin/env python3
"""File: deployment/analytics_loopback_install.py

Purpose: One owner-approved, one-time installation of the reviewed DEV-only
         Analytics 0.15.0 loopback service, with fail-closed checks and a
         reversible activation. Never install onto production.
Related: deployment/analytics_loopback_guard.py,
         deployment/systemd/rootless/omnilyzer-analytics-loopback.service,
         docs/operations/task014-analytics-loopback-20261031.md,
         MichaelTrueX/omnilyzer Issue #27.

Security: Execute only an exact-hash root-owned copy, not this editable source.
         Read the two stage files by no-follow file descriptors and compare
         their exact hashes before creating any root-owned target. No Docker
         write, database, registry, replay or preexisting systemd unit change.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import time

# Section 1: Immutable release and exact allowlisted paths for this DEV host.
STAGE = Path('/home/omnigpt/repos/omnilyzer-platform/.m05-14-release-review')
APP_SRC = STAGE / 'analytics_loopback_guard.py'
UNIT_SRC = STAGE / 'omnilyzer-analytics-loopback.service'
APP_SHA = 'e87be219e93130a3f9103aac21d2d809b2b226c990ed56fa24e441540870196c'
UNIT_SHA = 'aa61b6d9a329136594c6e37dfd07a1ddfb417dd551462d0ba806b49e2df29c7f'
APP_DIR = Path('/opt/omnilyzer/deployment/analytics-loopback')
APP_DST = APP_DIR / 'analytics_loopback_guard.py'
UNIT_DST = Path('/etc/systemd/system/omnilyzer-analytics-loopback.service')
ENV_DST = Path('/etc/omnilyzer/deployment/analytics-loopback.env')
NAME = 'omnilyzer-analytics-loopback.service'
CONTAINER = 'omnilyzer-analytics-dev-analytics-blue-1'
IMAGE = ('oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:'
         '6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1')
PORT = 3141
HEX = re.compile(r'[0-9a-f]{64}\Z')


# Section 2: Bounded, no-follow review of unprivileged staging bytes.
def read_stage(path: Path, expected: str, max_size: int) -> bytes:
    """Accept one regular, single-linked owned source with its exact hash."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 1005
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o644
                or info.st_size < 1 or info.st_size > max_size):
            raise RuntimeError('staged file properties denied')
        raw = os.read(fd, max_size + 1)
        if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != expected:
            raise RuntimeError('staged file hash mismatch')
        return raw
    finally:
        os.close(fd)


def run(argv: list[str], *, timeout: int = 15) -> str:
    """Run only an explicit local command, without shell or credential logging."""
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          check=False, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    if proc.returncode != 0:
        raise RuntimeError('operator command failed: ' + argv[0])
    return proc.stdout.strip()


def preflight() -> tuple[str, bytes, bytes]:
    """Qualify DEV host, stopped port, absent target files and signed image."""
    if os.geteuid() != 0 or socket.gethostname().split('.')[0] != 'omnilyzerdev':
        raise RuntimeError('DEV root context required')
    u = pwd.getpwnam('omnilyzer-executor')
    if (u.pw_uid, u.pw_gid) != (991, 991):
        raise RuntimeError('rootless executor identity changed')
    if any(p.exists() or p.is_symlink() for p in (APP_DST, UNIT_DST, ENV_DST)):
        raise RuntimeError('reviewed target already exists; never overwrite')
    app = read_stage(APP_SRC, APP_SHA, 18000)
    unit = read_stage(UNIT_SRC, UNIT_SHA, 2000)
    check = run(['/usr/bin/sudo', '-n', '-u', 'omnilyzer-executor',
                 '/usr/bin/docker', '--host', 'unix:///run/user/991/docker.sock',
                 'inspect', '--format',
                 '{{.Id}} {{.Config.Image}} {{.State.Health.Status}}', CONTAINER])
    fields = check.split(' ')
    if (len(fields) != 3 or HEX.fullmatch(fields[0]) is None
            or fields[1] != IMAGE or fields[2] != 'healthy'):
        raise RuntimeError('signed running container identity changed')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        if s.connect_ex(('127.0.0.1', PORT)) == 0:
            raise RuntimeError('loopback port already allocated')
    return fields[0], app, unit


# Section 3: Create root-owned targets exclusively from validated in-memory bytes.
def write_new(path: Path, content: bytes, mode: int) -> None:
    """Create a fixed privileged file without replacement or symlink follows."""
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_WRONLY | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def check_http() -> None:
    """Confirm real loopback health before accepting service as installed."""
    import http.client
    for path in ('/readyz', '/livez'):
        conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=3)
        try:
            conn.request('GET', path, headers={'Cache-Control': 'no-store'})
            res = conn.getresponse()
            res.read(1024)
            if res.status != 200:
                raise RuntimeError('Analytics loopback health denied')
        finally:
            conn.close()


def wait_healthy() -> None:
    """Allow bounded systemd startup, never dispatching a new release."""
    for _ in range(18):
        try:
            if run(['/usr/bin/systemctl', 'is-active', NAME], timeout=3) == 'active':
                check_http()
                return
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            time.sleep(1)
    raise RuntimeError('no accepted DEV loopback readiness')


# Section 4: One authorized activation and fail-safe disable on failure.
def main() -> int:
    """Install, activate, verify restart and stop-cleanup, then leave active."""
    started = False
    try:
        cid, app, unit = preflight()
        print('PRECHECK_PASS exact_signed_container', flush=True)
        run(['/usr/bin/install', '-d', '-o', 'root', '-g', 'root', '-m', '0755',
             str(APP_DIR)])
        write_new(APP_DST, app, 0o644)
        write_new(UNIT_DST, unit, 0o644)
        write_new(ENV_DST, ('ANALYTICS_APPROVED_CONTAINER_ID=' + cid + '\n').encode(), 0o600)
        run(['/usr/bin/systemctl', 'daemon-reload'])
        started = True
        run(['/usr/bin/systemctl', 'enable', '--now', NAME])
        wait_healthy()
        print('LIVE_PASS localhost_3141 readyz=200 livez=200', flush=True)
        run(['/usr/bin/systemctl', 'stop', NAME])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            if s.connect_ex(('127.0.0.1', PORT)) == 0:
                raise RuntimeError('port not closed on stop')
        print('STOP_CLEANUP_PASS localhost_3141_closed', flush=True)
        run(['/usr/bin/systemctl', 'start', NAME])
        wait_healthy()
        print('DEV_LOOPBACK_INSTALLED_ACTIVE version=0.15.0 canary_preserved', flush=True)
        return 0
    except Exception as exc:
        print('DEV_LOOPBACK_INSTALL_HOLD ' + type(exc).__name__ + ': ' + str(exc),
              file=sys.stderr, flush=True)
        if started:
            subprocess.run(['/usr/bin/systemctl', 'disable', '--now', NAME],
                           capture_output=True, timeout=20, check=False)
        print('DEV_LOOPBACK_FAIL_CLOSED service_disabled_if_created; retain_files_for_review',
              file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
