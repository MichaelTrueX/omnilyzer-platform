#!/usr/bin/python3
"""Root-owned fixed-purpose dispatcher for isolated AI operations agents.

Caller controls only two small tokens supplied by a polkit-authorized systemd
unit. The actual executable paths and SHA256 digests come from root-only policy.
No user-provided shell, command path, source directory, arguments or env.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path("/usr/local/libexec/shared-ai-ops")
POLICY = Path("/etc/shared-ai-ops/policy.json")
HOSTS = {"sumlaude": "truexmainserver", "omnilyzer": "omnilyzerdev"}
SAFE_TOKEN = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
SHA = re.compile(r"^[a-f0-9]{64}$")


class Hold(Exception):
    pass


def owned(path: Path, *, mode: int, uid: int = 0, group: int | None = None):
    try:
        s = path.lstat()
    except FileNotFoundError as exc:
        raise Hold("MISSING_ROOT_OWNED_SOURCE") from exc
    if not stat.S_ISREG(s.st_mode) or s.st_uid != uid or (
        stat.S_IMODE(s.st_mode) != mode
    ) or (group is not None and s.st_gid != group):
        raise Hold("SOURCE_CUSTODY_OR_MODE:" + path.name)
    return s


def root_directory(path: Path):
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise Hold("ROOT_DIRECTORY_MISSING") from exc
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Hold("ROOT_DIRECTORY_UNSAFE")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while part := fh.read(65536):
            h.update(part)
    return h.hexdigest()


def select_job(product: str, operation: str):
    if not SAFE_TOKEN.fullmatch(product) or not SAFE_TOKEN.fullmatch(operation):
        raise Hold("UNSAFE_JOB_NAME")
    if product not in HOSTS or os.uname().nodename != HOSTS[product]:
        raise Hold("PRODUCT_HOST_NOT_ALLOWED")
    for d in [Path("/etc"), POLICY.parent, Path("/usr/local"), Path("/usr/local/libexec"),
              ROOT, ROOT / "jobs", ROOT / "jobs" / product]:
        root_directory(d)
    owned(POLICY, mode=0o600)
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    if policy.get("version") != 1:
        raise Hold("UNSUPPORTED_POLICY_VERSION")
    jobs = policy.get("products", {}).get(product, {})
    entry = jobs.get(operation)
    if not isinstance(entry, dict) or set(entry) != {"sha256"}:
        raise Hold("JOB_NOT_REGISTERED")
    expected = entry["sha256"]
    if not isinstance(expected, str) or not SHA.fullmatch(expected):
        raise Hold("POLICY_HASH_INVALID")
    target = ROOT / "jobs" / product / (operation + ".py")
    owned(target, mode=0o500)
    if sha256(target) != expected:
        raise Hold("EXECUTABLE_HASH_CHANGED")
    return target


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        raise Hold("ROOT_AND_TWO_FIXED_ARGS_REQUIRED")
    product, job = sys.argv[1:]
    target = select_job(product, job)
    print(f"AI_OPS_VERIFIED_START product={product} job={job}", flush=True)
    # Launch exact pinned source with isolated Python and a fixed minimal env.
    result = subprocess.run(
        ["/usr/bin/python3", "-I", str(target)],
        cwd="/",
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "PYTHONNOUSERSITE": "1"},
        timeout=90,
        check=False,
    )
    if result.returncode:
        raise Hold(f"ROOT_JOB_EXIT_{result.returncode}")
    print(f"AI_OPS_JOB_PASS product={product} job={job}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (Hold, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"AI_OPS_HOLD {exc}", file=sys.stderr)
        sys.exit(70)
