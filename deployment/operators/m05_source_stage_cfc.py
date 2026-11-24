#!/usr/bin/python3 -I
"""File: /usr/local/libexec/omnilyzer-m05-ordinary-source-stage-cfc.py

Purpose: Stage precisely one new immutable 76-file Task014 Analytics DEV source
         generation from an independently reviewed installed root baseline.
Related: PR316 HEAD fcd56406e350b9b20ba107f357d18c0dfb7e6985,
         existing analytics_isolated_source_install.py root importer,
         .m05-ordinary-dev-review-handoff-330f-20261121/manifest.json,
         .m05-ordinary-dev-cutover-330f-20261121.py.
Sections: fixed pins; trusted bytes; reviewed exact handoff; root stage; CLI.
This script never changes systemd, active OCI, Task014 replay, Docker or PROD.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

# Section 1: exact audited source targets and pinned user-owned review bytes.
BASE = "330f3255f0067b9ddbe30d50466830bd71a55a11"
COMMIT = "fcd56406e350b9b20ba107f357d18c0dfb7e6985"
PARENT = Path("/opt/omnilyzer/deployment")
ROOT = PARENT / ("analytics-app-release-" + BASE)
DEST = PARENT / ("analytics-app-release-" + COMMIT)
OPERATOR = Path("/usr/local/libexec/omnilyzer-m05-ordinary-source-stage-cfc.py")
SCRATCH = PARENT / ".m05-ordinary-reviewed-source-f4a69fc9a3afa361255365ed6d19419bcb58c1c8"
HANDOFF = Path("/home/omnigpt/repos/omnilyzer-platform/.delivery/m05-pr316-source-stage-fcd564-20261124")
MANIFEST = HANDOFF / "manifest.json"
MANIFEST_SHA = "dded55ab8a8773c74ba5ac909628cf266849b1e09c66bcc9ee6c75710494d645"
# Owner-root verified after the broker SHA rebinding; this root-installed
# importer must remain bit-for-bit identical, not merely root-owned.
INSTALLER_SHA = "cc7dfd7fb022a01772bb2f18fd1705f6e4f15e706903e4b47c8833b7d7f9ac5b"
INSTALLER = SCRATCH / "deployment/analytics_isolated_source_install.py"
REPLACEMENTS_SHA = {
    "deployment/analytics_executor.py":
        "34de557ca2d5e63adb6cc5c18c827dd5f266040e699525670d21c9667b84f5ff",
    "deployment/analytics_route_journal.py":
        "b4029a2a1f152ac7848ff2b9e73e9fb8a6ce40101b58cb301d57fb82730171cc",
}
ERROR = "M05_ORDINARY_CFC_SOURCE_STAGE_HOLD"


# Section 2: accept root-owned old source only under closed, immutable ancestry.
def trusted_root_file(path: Path, mode: int) -> bytes:
    """Read a stable root:root single-link regular file, rejecting symlinks."""
    current = Path("/")
    for name in path.parts[1:-1]:
        current /= name
        item = current.lstat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
            raise ValueError("untrusted root-owned directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink)
                != (0, 0, mode, 1)
                or not 0 < before.st_size <= 1048576):
            raise ValueError("untrusted root-owned source file")
        data = bytearray()
        while len(data) <= 1048576:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(data) != before.st_size or len(data) > 1048576
                or any(getattr(before, key) != getattr(after, key) for key in fields)):
            raise ValueError("unstable root-owned file")
        return bytes(data)
    finally:
        os.close(fd)


# Section 3: user handoff files are untrusted until exact hash-verified.
def user_handoff_file(path: Path, expected_sha: str, limit: int) -> bytes:
    """Bind restricted UID1005 input to a reviewed immutable SHA256."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink)
                != (1005, 1005, 0o400, 1)
                or not 0 < before.st_size <= limit):
            raise ValueError("untrusted handoff file")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(data) != before.st_size or len(data) > limit
                or any(getattr(before, key) != getattr(after, key) for key in fields)
                or hashlib.sha256(data).hexdigest() != expected_sha):
            raise ValueError("handoff SHA256/metadata mismatch")
        return bytes(data)
    finally:
        os.close(fd)


# Section 4: exact 76-file audited root baseline; ONE reviewed replacement.
def reviewed_source() -> tuple[object, tuple[tuple[str, bytes], ...]]:
    """Check every old root-owned file and new source hash without executing it."""
    from collections import Counter

    raw = user_handoff_file(MANIFEST, MANIFEST_SHA, 16384)
    manifest = json.loads(raw)
    if (type(manifest) is not dict
            or set(manifest) != {"baseline_commit", "target_commit",
                                "baseline_files_sha256",
                                "replacement_sha256", "root_directories"}
            or manifest["baseline_commit"] != BASE
            or manifest["target_commit"] != COMMIT
            or manifest["replacement_sha256"] != REPLACEMENTS_SHA
            or type(manifest["baseline_files_sha256"]) is not dict
            or len(manifest["baseline_files_sha256"]) != 76
            or type(manifest["root_directories"]) is not list
            or len(manifest["root_directories"]) != 9):
        raise ValueError("unreviewed source inventory")
    # Exactly TWO reviewed previous-commit module replacements, no arbitrary paths.
    replacements = {
        path: user_handoff_file(
            HANDOFF / "payload" / path, digest, 1048576,
        )
        for path, digest in sorted(REPLACEMENTS_SHA.items())
    }
    oldstat = ROOT.lstat()
    if (not stat.S_ISDIR(oldstat.st_mode)
            or (oldstat.st_uid, oldstat.st_gid, stat.S_IMODE(oldstat.st_mode))
            != (0, 0, 0o755)):
        raise ValueError("untrusted installed baseline")
    actual_dirs, actual_files = [], []
    for current, dirs, files in os.walk(ROOT, followlinks=False):
        for name in dirs:
            path = Path(current, name)
            meta = path.lstat()
            if (not stat.S_ISDIR(meta.st_mode)
                    or (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))
                    != (0, 0, 0o755)):
                raise ValueError("unexpected source directory")
            actual_dirs.append(str(path.relative_to(ROOT)))
        for name in files:
            actual_files.append(str(Path(current, name).relative_to(ROOT)))
    mapping = manifest["baseline_files_sha256"]
    if not set(REPLACEMENTS_SHA).issubset(set(mapping)):
        raise ValueError("unreviewed source replacement path")
    if (sorted(actual_dirs) != manifest["root_directories"]
            or sorted(actual_files) != sorted(mapping)):
        raise ValueError("source file/directory count or identity changed")
    combined = []
    for relative, expected in sorted(mapping.items()):
        if (type(relative) is not str or relative.startswith("/")
                or any(part in ("", ".", "..") for part in relative.split("/"))
                or type(expected) is not str
                or len(expected) != 64
                or any(char not in "0123456789abcdef" for char in expected)):
            raise ValueError("invalid reviewed source member")
        old = trusted_root_file(ROOT / relative, 0o644)
        if hashlib.sha256(old).hexdigest() != expected:
            raise ValueError("baseline source mutated")
        combined.append((relative, replacements.get(relative, old)))

    # The source installer is not in the 76-file application runtime.
    # Owner-root SHA256 evidence binds this exact pre-existing private
    # importer. Checking only root ownership would execute changed code
    # with root privileges if a prior installer was silently replaced.
    importer_bytes = trusted_root_file(INSTALLER, 0o500)
    if hashlib.sha256(importer_bytes).hexdigest() != INSTALLER_SHA:
        raise ValueError("root-only source installer SHA is not approved")
    # A previously imported deployment package could shadow the pinned
    # SCRATCH modules even after sys.path insertion. Deny instead of
    # borrowing an unverified module from an unrelated Python environment.
    if any(k == "deployment" or k.startswith("deployment.")
           for k in sys.modules):
        raise ValueError("deployment Python modules already loaded")
    sys.path.insert(0, str(SCRATCH))
    sys.dont_write_bytecode = True
    from deployment import analytics_isolated_source_install as installer
    if (not isinstance(getattr(installer, "__file__", None), str)
            or os.path.abspath(installer.__file__) != str(INSTALLER)):
        raise ValueError("pinned root source installer import origin changed")
    if len(combined) != 76:
        raise ValueError("invalid successor file count")
    return installer, tuple(combined)


# Section 5: publish one SHA-named source only if absent. No live service touch.
def stage_once(installer: object, combined: tuple[tuple[str, bytes], ...]) -> None:
    """Use the original restricted stage+atomic-rename logic unchanged."""
    opened: list[int] = []
    try:
        fd = installer._open_checked_root(str(PARENT), opened, 0, 0)
        for name in (DEST.name, installer._STAGING):
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("source stage destination already exists")
        installer._stage_new_generation(fd, combined, uid=0, gid=0, successor_source=True)
        try:
            os.rename(installer._STAGING, DEST.name, src_dir_fd=fd, dst_dir_fd=fd)
        except OSError:
            installer._remove_verified_stage(fd, combined, uid=0, gid=0)
            raise
        os.fsync(fd)
    finally:
        installer._original._finish_close(opened)


# Section 6: fixed root-only --check or --stage. Fail closed without traceback.
def main(argv: list[str]) -> None:
    """Require exact operator filename root:root mode0500 and unused dest."""
    if argv not in (["--check"], ["--stage"]):
        raise ValueError("invalid operation")
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        raise PermissionError("only root may stage")
    if Path(__file__) != OPERATOR:
        raise PermissionError("untrusted installed operator path")
    trusted_root_file(OPERATOR, 0o500)
    if DEST.exists() or DEST.is_symlink():
        raise ValueError("source already staged")
    installer, combined = reviewed_source()
    if argv == ["--check"]:
        print("M05_CFC_ROOT_SOURCE_PREFLIGHT_PASS", COMMIT, len(combined))
        return
    stage_once(installer, combined)
    print("M05_CFC_ROOT_SOURCE_STAGED", COMMIT)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception:
        print(ERROR, file=sys.stderr)
        raise SystemExit(1)
