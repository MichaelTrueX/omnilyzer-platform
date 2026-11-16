#!/usr/bin/python3
"""Success-only removal of temporary S03 SQL/operator, preserving root receipts.

Not a generic delete primitive. Root-owned paths, owner/mode and SHA fixed.
Never touches learner data, PostgreSQL, or user-controlled source staging.
"""
import grp
import hashlib
import os
from pathlib import Path
import stat
import sys

BASE = Path("/var/lib/sumlaude-s03-current35-108-110-once")
PROTECTED = BASE / "protected"
RECEIPTS = BASE / "receipts"
OLD_OPERATOR = Path("/usr/local/sbin/s03-current35-108-110-owner-operator")
EXPECTED = {
    "s03-current35-readonly-preflight.sql": "9ff4827144e0534a54cb2025f1f33aa0c4ff668425f516d9619c0e62165fe71c",
    "s03-current35-atomic-108-109-110-NOT_APPROVED.sql": "526ba40b9bbdb592a69f41b20c003a541a46fee6ab5dd0fa55fad531cc5591a7",
    "s03-current35-readonly-postcheck.sql": "d60dd5fd352b38cb9fce80717c252d8b17e3d82b24de8ac90c4af98a0b4a4f2d",
}
OPERATOR_SHA = "72b4c9d1ee3f8bc195b12cf15b8f64ddadc2658264636c67e7d6c599bf564475"
COMMIT_MARKER = "S03_CURRENT35_LEDGERLESS_ATOMIC_COMMIT_AND_POSTCHECK_PASS"
POSTCHECK_MARKER = "S03_CURRENT35_LEDGERLESS_READONLY_POSTCHECK_PASS"


class Hold(Exception):
    pass


def require(path, *, directory=False, mode, uid=0, gid=None):
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise Hold(f"MISSING_REQUIRED_PATH:{path.name}") from exc
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(st.st_mode) or st.st_uid != uid
            or stat.S_IMODE(st.st_mode) != mode
            or (gid is not None and st.st_gid != gid)):
        raise Hold(f"OWNER_MODE_OR_LINK_MISMATCH:{path.name}")
    return path


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            result.update(block)
    return result.hexdigest()


def exact_lines(file, required):
    lines = set(file.read_text(encoding="utf-8").splitlines())
    if not set(required).issubset(lines):
        raise Hold(f"COMMIT_RECEIPT_NOT_PASS:{file.name}")


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise Hold("ROOT_NO_ARGS_REQUIRED")
    if os.uname().nodename != "truexmainserver":
        raise Hold("WRONG_PRODUCTION_HOST")
    postgres = grp.getgrnam("postgres").gr_gid
    require(Path("/var/lib"), directory=True, mode=0o755, gid=0)
    require(BASE, directory=True, mode=0o710, gid=postgres)
    require(PROTECTED, directory=True, mode=0o710, gid=postgres)
    require(RECEIPTS, directory=True, mode=0o700, gid=0)
    if {p.name for p in PROTECTED.iterdir()} != set(EXPECTED):
        raise Hold("PROTECTED_FOREIGN_OR_MISSING_FILE")
    for name, sha in EXPECTED.items():
        file = require(PROTECTED / name, mode=0o440, gid=postgres)
        if digest(file) != sha:
            raise Hold(f"PROTECTED_SOURCE_HASH_MISMATCH:{name}")
    require(OLD_OPERATOR, mode=0o500, gid=0)
    if digest(OLD_OPERATOR) != OPERATOR_SHA:
        raise Hold("ORIGINAL_OPERATOR_HASH_MISMATCH")
    for name in ("commit-attempted", "schema-verified.txt",
                 "install.log", "postcheck.log"):
        require(RECEIPTS / name, mode=0o600, gid=0)
    exact_lines(RECEIPTS / "schema-verified.txt",
                ("STATUS=POSTCOMMIT_SCHEMA_ONLY_PASS",
                 "SQL_SHA256=" + EXPECTED[
                    "s03-current35-atomic-108-109-110-NOT_APPROVED.sql"]))
    exact_lines(RECEIPTS / "install.log", (COMMIT_MARKER,))
    exact_lines(RECEIPTS / "postcheck.log", (POSTCHECK_MARKER,))
    print("S03_AGENT_POSTCOMMIT_RECEIPTS_VERIFIED_PASS", flush=True)
    # Verified paths only inside root-owned namespace. Receipts are retained.
    for name in EXPECTED:
        (PROTECTED / name).unlink()
    PROTECTED.rmdir()
    OLD_OPERATOR.unlink()
    require(RECEIPTS, directory=True, mode=0o700, gid=0)
    print("S03_AGENT_ROOT_TEMP_STAGE_REMOVED_RECEIPTS_PRESERVED_PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (Hold, KeyError, UnicodeError) as exc:
        print(f"S03_AGENT_CLEANUP_HOLD {exc}", file=sys.stderr)
        sys.exit(70)
