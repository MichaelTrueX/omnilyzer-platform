#!/usr/bin/env python3
"""File: /usr/local/libexec/omnilyzer-m05-readonly-native-root-preflight-v2.py

Purpose: Read-only native-root verification of M05 PR318's split source graph:
         45 immutable runtime files plus 16 original approved importer-only files.
Related: GitHub PR318 HEAD 375a449bbc03d36f58cf404d9e364e11d2abf14a;
         deployment/operators/m05_source_stage_cfc.py; GitHub issue #281.
Sections: fixed source expectations, stable no-follow reads, source-only AST
          inspection, split-origin root source verification, consolidated report.

WARNING: This script does not grant release approval and never writes files,
restarts services, imports the staged operator, or changes Task014 replay.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys

# Section 1: exact original authority values from current approved Git source.
WORK = Path('/home/omnigpt/repos/omnilyzer-platform/.delivery')
STAGE = WORK / 'm05-pr316-source-stage-17972-20261122/root-source-stage-reviewed.py'
MANIFEST = WORK / 'm05-pr316-source-stage-17972-20261122/manifest.json'
SCRATCH = Path('/opt/omnilyzer/deployment/.m05-ordinary-reviewed-source-f4a69fc9a3afa361255365ed6d19419bcb58c1c8')
ROOT = Path('/opt/omnilyzer/deployment/analytics-app-release-330f3255f0067b9ddbe30d50466830bd71a55a11')
TARGET = Path('/opt/omnilyzer/deployment/analytics-app-release-17972bff312a3df7c6e5e4f3d83b239b9b11aba1')
OPERATOR = Path('/usr/local/libexec/omnilyzer-m05-ordinary-source-stage-cfc.py')
OP_SHA = '0da493f19704da9b5271f17371f0574dfa4b38013e89fd713353c4633c677c8f'
MANIFEST_SHA = '1d57383e82b7f0efe9f6b28a6d7168ad3736c9dd2a2f75d59b54b8ac1cbb8f5a'
OLD = '330f3255f0067b9ddbe30d50466830bd71a55a11'
NEW = '17972bff312a3df7c6e5e4f3d83b239b9b11aba1'
problems: list[str] = []


# Section 2: stable, no-follow reads and explicit identity constraints.
def read_regular(path: Path, *, uid: int, gid: int, mode: int | None, max_bytes: int) -> bytes:
    """Read once through O_NOFOLLOW, verify no content or metadata change."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        actual_mode = stat.S_IMODE(a.st_mode)
        if not stat.S_ISREG(a.st_mode) or (a.st_uid, a.st_gid, a.st_nlink) != (uid, gid, 1):
            raise ValueError('owner/link/type mismatch')
        if mode is not None and actual_mode != mode:
            raise ValueError('file mode mismatch')
        if mode is None and (actual_mode & 0o022):
            raise ValueError('group/other-writable source')
        if not 0 < a.st_size <= max_bytes:
            raise ValueError('unexpected file size')
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(max_bytes + 1 - len(data), 65536))
            if not chunk:
                break
            data.extend(chunk)
        b = os.fstat(fd)
        unchanged = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(data) != a.st_size or any(getattr(a, field) != getattr(b, field) for field in unchanged):
            raise ValueError('file changed during review')
        return bytes(data)
    finally:
        os.close(fd)


def check_ancestors(path: Path) -> None:
    """Require the root-owned source tree to have trustworthy parents."""
    for parent in path.parents:
        meta = parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError(f'untrusted parent {parent}')


def require_hash(raw: bytes, expected: str, label: str) -> None:
    """Record exact pinned SHA mismatch without exposing file content."""
    if hashlib.sha256(raw).hexdigest() != expected:
        problems.append(f'{label}: SHA256 differs from reviewed Git source')


# Section 3: parse, but never execute, the pinned review-stage Python source.
def parse_source_contract(raw: bytes) -> tuple[dict[str, str], set[str]]:
    """Extract fixed source pins using AST literal parsing only."""
    tree = ast.parse(raw.decode('utf-8'), filename='reviewed-source-stage.py')
    found: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        key = node.targets[0].id
        if key == 'EXTRA_IMPORT_SOURCE_SHA':
            found[key] = ast.literal_eval(node.value)
        elif key == 'REQUIRED_IMPORT_SOURCE_PATHS':
            value = node.value
            if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name) or value.func.id != 'frozenset' or len(value.args) != 1:
                raise ValueError('unreviewed module set declaration')
            found[key] = set(ast.literal_eval(value.args[0]))
    extras = found.get('EXTRA_IMPORT_SOURCE_SHA')
    required = found.get('REQUIRED_IMPORT_SOURCE_PATHS')
    if (type(extras) is not dict or type(required) is not set
            or len(extras) != 16 or len(required) != 61
            or any(type(k) is not str or type(v) is not str for k, v in extras.items())
            or any(type(k) is not str for k in required)):
        raise ValueError('unreviewed root importer module graph')
    return extras, required


# Section 4: consolidate all independent evidence, never modify live state.
def main() -> int:
    """Print all observed mismatches and return PASS only for exact native root."""
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        print('M05_NATIVE_ROOT_PREFLIGHT_HOLD: root required')
        return 2
    if socket.gethostname().split('.')[0] != 'omnilyzerdev':
        print('M05_NATIVE_ROOT_PREFLIGHT_HOLD: DEV host mismatch')
        return 2
    for path, label in ((TARGET, 'target installed source'), (OPERATOR, 'root installed operator')):
        if os.path.lexists(path):
            problems.append(f'{label}: unexpected preexisting path')

    try:
        stage_raw = read_regular(STAGE, uid=1005, gid=1005, mode=0o400, max_bytes=32768)
        require_hash(stage_raw, OP_SHA, 'review-stage operator')
    except Exception as exc:
        problems.append(f'review-stage operator: {type(exc).__name__}: {exc}')
        stage_raw = b''
    try:
        manifest_raw = read_regular(MANIFEST, uid=1005, gid=1005, mode=0o400, max_bytes=32768)
        require_hash(manifest_raw, MANIFEST_SHA, 'source manifest')
    except Exception as exc:
        problems.append(f'source manifest: {type(exc).__name__}: {exc}')
        manifest_raw = b''

    if stage_raw and manifest_raw and not problems:
        try:
            extras, required = parse_source_contract(stage_raw)
            manifest = json.loads(manifest_raw)
            baseline = manifest['baseline_files_sha256']
            if (manifest['baseline_commit'] != OLD or manifest['target_commit'] != NEW
                    or type(baseline) is not dict or len(baseline) != 76
                    or set(extras) != required - set(baseline)
                    or len(required & set(baseline)) != 45):
                raise ValueError('manifest and pinned import graph disagree')
            for relative in sorted(required):
                if ('..' in relative.split('/') or relative.startswith('/')
                        or not relative.endswith('.py') or relative.startswith('./')):
                    problems.append(f'{relative}: invalid relative source path')
                    continue
                # Only immutable manifest-approved ROOT may supply runtime
                # modules. Never attest the unproven historical SCRATCH copies.
                if relative in baseline:
                    target = ROOT / relative
                    expected = baseline[relative]
                    special_mode = 0o644
                else:
                    target = SCRATCH / relative
                    expected = extras[relative]
                    special_mode = 0o400 if relative == 'deployment/analytics_isolated_source_install.py' else None
                try:
                    check_ancestors(target)
                    data = read_regular(target, uid=0, gid=0, mode=special_mode, max_bytes=1048576)
                    require_hash(data, expected, relative)
                except Exception as exc:
                    problems.append(f'{relative}: {type(exc).__name__}: {exc}')
        except Exception as exc:
            problems.append(f'approval contract: {type(exc).__name__}: {exc}')
    if problems:
        for error in problems:
            print('M05_NATIVE_ROOT_PREFLIGHT_MISMATCH', error)
        print(f'M05_NATIVE_ROOT_PREFLIGHT_HOLD count={len(problems)}')
        return 1
    print('M05_NATIVE_ROOT_READONLY_SPLIT_CLOSURE_PASS module_count=61 runtime_330f=45 importer_extras=16 stage_operator_sha256=' + OP_SHA)
    print('M05_NO_INSTALL_NO_SERVICE_CHANGE_NO_REPLAY_NO_PROD')
    return 0


if __name__ == '__main__':
    sys.exit(main())
