#!/usr/bin/env python3
"""Read-only component matrix for Issue281's consumed D11 prewrite HOLD.

Uses AST statements from the exact M04-approved frozen operator, without
calling its installer, preflight, composite attestation or consumed main.
Only fixed labels and source line numbers leave FD-level output confinement.
Run only from the reviewed root0400 snapshot on private omnilyzerdev.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import traceback

FRESH = Path('/home/trust/m05-analytics016-d11-fresh-review/m05_pr296_d11_fresh_20261116_source_only.py')
FRESH_SHA = '3201abfe5636228714385fed95655bf55a3f6baffd96dd5488523741a842ce71'
PRIOR = '/home/trust/m05-766e-recovery-source-review/owner_rebind_766e_recovery.py'
# Half-open AST statement ranges in the SHA-pinned function, dependencies
# refer only to earlier groups. Independent groups continue after a failure.
GROUPS = (
    ('ROOT', 1, 2, ()),
    ('STAGE_ABSENT', 2, 3, ()),
    ('APPROVED_HELPERS', 3, 4, ()),
    ('MANIFEST', 4, 5, ()),
    ('ORIGINAL_HELPER', 5, 6, ('APPROVED_HELPERS',)),
    ('RECEIPT_CUSTODY', 6, 8, ()),
    ('RECEIPT_CONTRACT', 8, 13, ('RECEIPT_CUSTODY',)),
    ('CONFIG_PREIMAGES', 13, 15, ('RECEIPT_CUSTODY',)),
    ('CONFIG_EXPECTED', 15, 16, ('CONFIG_PREIMAGES',)),
    ('CONFIG_LIVE', 16, 17, ('CONFIG_EXPECTED', 'ORIGINAL_HELPER')),
    ('CURRENT_MARKER', 17, 18, ()),
    ('PRIOR_SEAL', 18, 19, ('APPROVED_HELPERS',)),
    ('PRIOR_MARKER', 19, 20, ('APPROVED_HELPERS',)),
    ('CURRENT_SOURCE', 20, 23, ('MANIFEST',)),
    ('BACKUP_SOURCE', 23, 24, ('MANIFEST',)),
    ('UID991_EXACT', 24, 25, ()),
    ('SERVICES', 25, 26, ('ORIGINAL_HELPER',)),
    ('BLUE_HEALTH', 26, 27, ('ORIGINAL_HELPER',)),
    ('ACTIVE_STABLE', 27, 28, ('APPROVED_HELPERS',)),
)


@contextmanager
def confined():
    """Suppress imported Python and child OS-level stdout/stderr alike."""
    sys.stdout.flush()
    sys.stderr.flush()
    saved = (os.dup(1), os.dup(2))
    null = os.open('/dev/null', os.O_WRONLY)
    try:
        os.dup2(null, 1)
        os.dup2(null, 2)
        yield
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for fd in (*saved, null):
            os.close(fd)


def require(ok):
    if ok is not True:
        raise ValueError('component hold')


def custody(path, uid, gid, mode, size=None):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and
            (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) ==
            (uid, gid, mode, 1) and (size is None or s.st_size == size))
    return s


def load_source():
    """Validate caller and exact frozen bytes before any imports."""
    require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == (0, 0, 0, 0)
            and socket.gethostname() == 'omnilyzerdev' and len(sys.argv) == 1)
    here = Path(__file__)
    require(str(here.parent).startswith('/run/m05-prior766-components.'))
    s = here.parent.lstat()
    require(stat.S_ISDIR(s.st_mode) and
            (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, 0, 0o700))
    custody(here, 0, 0, 0o400)
    parent = FRESH.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and
            (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode)) ==
            (1001, 1001, 0o700))
    before = custody(FRESH, 1001, 1001, 0o600, 30620)
    fd = os.open(FRESH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(30621)
        after = os.fstat(fd)
        require(len(raw) == 30620 and hashlib.sha256(raw).hexdigest() == FRESH_SHA
                and (opened.st_dev, opened.st_ino, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns))
    finally:
        os.close(fd)
    ns = {'__name__': 'm05_frozen_readonly_components', '__file__': str(FRESH)}
    exec(compile(raw, str(FRESH), 'exec'), ns)
    ns['prior'] = ns['original']()  # Hash-pinned loader only, not an operator.
    fn = next(n for n in ast.parse(raw).body
              if isinstance(n, ast.FunctionDef) and n.name == 'attest_prior_766_readonly')
    require(len(fn.body) == 29 and fn.body[24].lineno == 389
            and fn.body[28].lineno == 397)
    return ns, fn


def run_matrix(ns, fn):
    """Evaluate exact read-only statement groups once; never print exceptions."""
    passed = set()
    failed = False
    groups = list(GROUPS)
    # Split the original final AND into two independent original predicates.
    final = fn.body[28].value.args[0]
    require(isinstance(final, ast.BoolOp) and len(final.values) == 2)
    extra = (
        ('REPLAY_RECEIPT_EQUAL', final.values[0], ('APPROVED_HELPERS', 'RECEIPT_CONTRACT')),
        ('ROUTE_EMPTY', final.values[1], ()),
    )
    for label, begin, end, dependencies in groups:
        if not set(dependencies) <= passed:
            print('M05_COMPONENT_' + label + '=BLOCKED', flush=True)
            failed = True
            continue
        line = 0
        child = []
        original_run = subprocess.run

        def observed_run(*args, **kwargs):
            try:
                result = original_run(*args, **kwargs)
            except subprocess.TimeoutExpired:
                child.append('TIMEOUT')
                raise
            child.append('EXIT_ZERO' if result.returncode == 0 else 'EXIT_NONZERO')
            child.append('STDOUT_EXACT' if result.stdout ==
                         b'M05_766_UID991_SOURCE_BLUE_PASS\n' else 'STDOUT_DIFFERS')
            return result

        try:
            with confined():
                try:
                    if label == 'UID991_EXACT':
                        subprocess.run = observed_run
                    exec(compile(ast.Module(body=fn.body[begin:end], type_ignores=[]),
                                 str(FRESH), 'exec'), ns)
                finally:
                    subprocess.run = original_run
        except Exception as exc:
            for frame in traceback.extract_tb(exc.__traceback__):
                if frame.filename in (str(FRESH), PRIOR):
                    line = frame.lineno
            print('M05_COMPONENT_' + label + '=HOLD LINE=' + str(line), flush=True)
            failed = True
        else:
            passed.add(label)
            print('M05_COMPONENT_' + label + '=PASS', flush=True)
        for outcome in child:
            print('M05_COMPONENT_UID991_CHILD=' + outcome, flush=True)
    for label, expression, dependencies in extra:
        if not set(dependencies) <= passed:
            print('M05_COMPONENT_' + label + '=BLOCKED', flush=True)
            failed = True
            continue
        try:
            with confined():
                require(eval(compile(ast.Expression(expression), str(FRESH), 'eval'), ns))
        except Exception:
            print('M05_COMPONENT_' + label + '=HOLD', flush=True)
            failed = True
        else:
            print('M05_COMPONENT_' + label + '=PASS', flush=True)
    print('M05_COMPONENT_MATRIX_' + ('HOLD' if failed else 'PASS') + '_NO_INSTALL_NO_RETRY', flush=True)
    return 2 if failed else 0


def main():
    try:
        with confined():
            ns, fn = load_source()
        return run_matrix(ns, fn)
    except Exception:
        print('M05_COMPONENT_SETUP_HOLD_NO_INSTALL_NO_RETRY', flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
