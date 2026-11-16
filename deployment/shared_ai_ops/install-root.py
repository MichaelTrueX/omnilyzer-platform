#!/usr/bin/python3
"""One-time ROOT bootstrap, pinned source only, for a permanent narrow AI agent.

Owner runs a hash-checked ROOT-OWNED copy, never this user-owned source.
All source bytes are pinned and copied to a root-owned private temp directory.
"""
import grp
import hashlib
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile

JOB_ROOT = Path("/usr/local/libexec/shared-ai-ops")
POLICY_DIR = Path("/etc/shared-ai-ops")
POLKIT_DEST = Path("/etc/polkit-1/rules.d/50-shared-ai-ops.rules")
FILES = {
    "dispatcher.py": "50c112ee839582e854ee80ff962f405953eb1e26219d1618cdf6ca1941978289",
    "jobs/sumlaude/status.py": "0fc4b81856da371d63f12853efcf48d8ffbd92911a895fa043506e753326de81",
    "jobs/sumlaude/cleanup-108-110.py": "52567f5ad1b22b005b33b1eed7f18d77e3181a8361390d9ae7092a6ce8325e20",
    "jobs/omnilyzer/status.py": "7c1a9d4d5e7a480404564efa84a0526936cb1718d3f239471fc1bc617ea8b2f0",
    "policy.json": "4f16fa453cbf7adf5b4d91891a5a3d93ee9d0106037d6e8adbb4b5dbe7d8a345",
    "50-shared-ai-ops.rules": "3e6a558a8ee877b70832a12d7748f01e259eff36584b523118f1318c8c5caf64",
    "sumlaude-ai-ops@.service": "9cdaa376eaf910b995a42733697038081281e7c896f19720ea2bd2fa9a7c938e",
    "omnilyzer-ai-ops@.service": "f05adc9bd402b6e1d8a23805bc8bd4303e55ec656529c6e18b60879daddde6b4",
    "sumlaude-agent-remote.service": "98c6460647ae9c9e9e48095d70cade64ccceff8c8636834cb029103224fe9711",
    "omnilyzer-agent-remote.service": "7b3772a9cca4a4df0fd3d1a1a8e74f8f70e0fa0826a6d9afed6ee2f07830d2bc",
}
HOST_USER = {"truexmainserver": "sumlaude-agent", "omnilyzerdev": "omnilyzer-agent"}
SOURCE_OWNER = {"truexmainserver": "trusthansen", "omnilyzerdev": "omnigpt"}


def insist(ok, label):
    if not ok:
        raise RuntimeError("SHARED_AGENT_INSTALL_HOLD_" + label)


def check_bytes(p: Path, digest: str):
    st = p.lstat()
    insist(stat.S_ISREG(st.st_mode), "UNEXPECTED_SOURCE_TYPE")
    b = p.read_bytes()
    insist(hashlib.sha256(b).hexdigest() == digest, "SOURCE_SHA")
    return b


def install_bytes(data: bytes, path: Path, mode: int):
    insist(not path.exists() and not path.is_symlink(), "TARGET_NOT_EMPTY")
    path.write_bytes(data)
    os.chown(path, 0, 0)
    path.chmod(mode)
    insist(hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(data).digest(), "INSTALLED_SHA")


def main():
    insist(os.geteuid() == 0 and len(sys.argv) == 1, "ROOT_NO_ARGS")
    host = os.uname().nodename
    insist(host in HOST_USER, "WRONG_HOST")
    agent = HOST_USER[host]
    trust = pwd.getpwnam(SOURCE_OWNER[host])
    source = Path(trust.pw_dir) / "shared-ai-ops-source-20261115"
    srcstat = source.lstat()
    insist(stat.S_ISDIR(srcstat.st_mode)
           and srcstat.st_uid == trust.pw_uid
           and stat.S_IMODE(srcstat.st_mode) == 0o700, "SRC_OWNER_MODE")
    for path in (JOB_ROOT, POLICY_DIR, POLKIT_DEST,
                 Path("/etc/systemd/system/sumlaude-ai-ops@.service"),
                 Path("/etc/systemd/system/omnilyzer-ai-ops@.service"),
                 Path("/etc/systemd/system") / (HOST_USER[host] + "-remote.service")):
        insist(not path.exists() and not path.is_symlink(), "ALREADY_INSTALLED")
    try:
        pwd.getpwnam(agent)
    except KeyError:
        pass
    else:
        insist(False, "AGENT_USER_ALREADY_EXISTS")
    insist(Path("/var/lib").stat().st_uid == 0, "ROOT_VAR_PARENT")
    # Verify all source bytes BEFORE any new root-owned file or OS account.
    captured = {}
    for name, digest in FILES.items():
        p = source / name
        insist(not p.is_symlink(), "SYMLINK_SOURCE")
        captured[name] = check_bytes(p, digest)
    print("SHARED_AGENT_ALL_SOURCE_SHA_PASS", flush=True)

    subprocess.run(["/usr/sbin/useradd", "--create-home", "--shell", "/usr/sbin/nologin",
                    "--user-group", agent], check=True)
    user = pwd.getpwnam(agent)
    os.chmod(user.pw_dir, 0o700)
    insist(set(os.getgrouplist(agent, user.pw_gid)) == {user.pw_gid},
           "AGENT_EXTRA_PRIVILEGED_GROUP_MEMBERSHIP")

    for d in (JOB_ROOT, JOB_ROOT / "jobs", JOB_ROOT / "jobs" / "sumlaude",
              JOB_ROOT / "jobs" / "omnilyzer", POLICY_DIR):
        d.mkdir(parents=True, exist_ok=False)
        os.chown(d, 0, 0)
        d.chmod(0o700 if d == POLICY_DIR else 0o755)
    for name in ("dispatcher.py", "jobs/sumlaude/status.py",
                 "jobs/sumlaude/cleanup-108-110.py", "jobs/omnilyzer/status.py"):
        install_bytes(captured[name], JOB_ROOT / name, 0o500)
    install_bytes(captured["policy.json"], POLICY_DIR / "policy.json", 0o600)
    install_bytes(captured["50-shared-ai-ops.rules"], POLKIT_DEST, 0o644)
    local_template = ("sumlaude-ai-ops@.service" if host == "truexmainserver"
                      else "omnilyzer-ai-ops@.service")
    install_bytes(captured[local_template],
                  Path("/etc/systemd/system") / local_template, 0o644)
    remote_service = HOST_USER[host] + "-remote.service"
    install_bytes(captured[remote_service],
                  Path("/etc/systemd/system") / remote_service, 0o644)
    subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
    print("SHARED_AGENT_PERMANENT_NONADMIN_ROOT_DISPATCH_INSTALLED_PASS", flush=True)
    print("SHARED_AGENT_DEVICE_OAUTH_PAIRING_STILL_REQUIRED", flush=True)


if __name__ == "__main__":
    main()
