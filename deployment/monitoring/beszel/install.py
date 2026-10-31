#!/usr/bin/env python3
# File: deployment/monitoring/beszel/install.py
# Runtime: /home/trust/.local/share/beszel/install-staging/omnilyzer-20261031/install.py
# Purpose: Owner-authorized, hash-pinned installation and rollback of a UID 991
#          Beszel metrics-only adapter plus independent sandboxed agent.
# Related: metrics_proxy.py, test_metrics_proxy.py, test_install.py, README.md,
#          beszel-omnilyzer-{proxy,agent}.service, Omnilyzer rootless Task014.
# Exclusions: Never modify Docker daemon, Task014, app containers, user accounts,
#             sudoers, existing Beszel/Sumlaude services or public network routes.
"""Provision only the two independently approved Omnilyzer monitoring services."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import time

# Section: Fixed identities, deployment paths, executable sources and source pins.
UID = GID = 991
ROOT_UID = ROOT_GID = 0
ACCOUNT = "omnilyzer-executor"
EXPECTED_HOST = "omnilyzerdev"
SOURCE = Path("/home/trust/.local/share/beszel/install-staging/omnilyzer-20261031")
PREFIX = Path("/opt/omnilyzer-beszel-monitor")
STATE = Path("/var/lib/omnilyzer-beszel-monitor")
DATA = STATE / "data"
UNITDIR = Path("/etc/systemd/system")
DOCKER_SOCKET = Path("/run/user/991/docker.sock")
SOCKET = Path("/run/user/991/beszel-metrics.sock")
AGENT_PORT = 45878
BINARY = Path("/home/trust/.local/share/beszel/bin/beszel-agent")
PUBLIC = Path("/home/trust/.local/share/beszel/agent/hub-public-key")
MANIFEST = PREFIX / "install-manifest.json"
MARKER = "OMNILYZER-BESZEL-20261031"
UNITS = ("beszel-omnilyzer-proxy.service", "beszel-omnilyzer-agent.service")
SOURCE_HASHES = {
    "README.md": "c251ec972c3dc1c81a7c5f1a8837bd9b469587afcea59469bc443fc6b9725c9b",
    "metrics_proxy.py": "114e0be8843e0b9bcb7c0c252078aad10a14b7aa8458ef7a53524360370222c0",
    "test_metrics_proxy.py": "2064552c072a4565a5e3c508b73046068229d8603befd98b9ce2507e94793a85",
    "test_install.py": "605f6d98fd0ce75653e9075a104764063fc649724fe73dc872df6e6ee9d37e84",
    "beszel-omnilyzer-proxy.service": "2436014474a7a6b3e19c621230e42b5e549ab80e2e7396444d6733d07675c1fc",
    "beszel-omnilyzer-agent.service": "5f5d5543243b8e800f57c97a92e783663e49a383cd5748ee58f4118f74aabc46",
}
AGENT_SHA256 = "5c84416b63028f7ad86ebafa4c8a7a27977d485a838de357216ded3ab844b2b5"
PUBLIC_SHA256 = "8d2d96cf101d2aac642d280df74ee5af83bb5dd7db16223cae26a90a6c3abe54"


# Section: Strict checks of bytes, filesystem identity, Docker boundary and port.
def sha256(path: Path) -> str:
    """Read one bounded/known source path and compute its exact SHA-256."""
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def require_dir(path: Path, uid: int, gid: int, mode: int | None = None) -> None:
    """Reject symlinks, unexpected owners/groups, modes and non-directories."""
    st = path.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_gid != gid
            or (mode is not None and stat.S_IMODE(st.st_mode) != mode)):
        raise RuntimeError("Unsafe monitoring directory: " + str(path))


def require_new(path: Path) -> None:
    """Fail closed instead of overwriting or following existing objects."""
    if path.exists() or path.is_symlink():
        raise RuntimeError("Refusing to replace existing path: " + str(path))


def systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Call only the host systemd manager, never Task014 deployment commands."""
    return subprocess.run(
        ["/usr/bin/systemctl", *args], check=check, capture_output=True,
        text=True, timeout=35,
    )


def preflight() -> None:
    """Validate an exact authorized operator and immutable host boundary."""
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != EXPECTED_HOST:
        raise RuntimeError("Requires owner-authorized root on omnilyzerdev")
    identity = pwd.getpwnam(ACCOUNT)
    if identity.pw_uid != UID or identity.pw_gid != GID:
        raise RuntimeError("Protected executor identity changed")
    require_dir(Path("/run/user/991"), UID, GID, 0o700)
    st = DOCKER_SOCKET.lstat()
    if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != UID or st.st_gid != GID
            or stat.S_IMODE(st.st_mode) & 0o007):
        raise RuntimeError("Rootless Docker socket authority mismatch")
    # This monitor deliberately does not invoke Docker CLI or deployment tools.
    if systemctl("is-active", "user@991.service").stdout.strip() != "active":
        raise RuntimeError("Existing UID 991 manager is not active")
    require_dir(Path("/opt"), ROOT_UID, ROOT_GID)
    require_dir(Path("/etc/systemd/system"), ROOT_UID, ROOT_GID)
    require_dir(Path("/var/lib"), ROOT_UID, ROOT_GID)
    for name, digest in SOURCE_HASHES.items():
        path = SOURCE / name
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 1001
                or stat.S_IMODE(st.st_mode) & 0o022
                or sha256(path) != digest):
            raise RuntimeError("Pinned source mismatch: " + name)
    if sha256(BINARY) != AGENT_SHA256 or sha256(PUBLIC) != PUBLIC_SHA256:
        raise RuntimeError("Existing Beszel binary or public hub key changed")
    for path in [PREFIX, STATE, SOCKET, *(UNITDIR / unit for unit in UNITS)]:
        require_new(path)
    # Do not reserve or bind a port in preflight; the agent's exact loopback
    # listener is checked after service activation, with rollback on conflict.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1.0)
        if probe.connect_ex(("127.0.0.1", AGENT_PORT)) == 0:
            raise RuntimeError("Port 45878 already in use")
    print("PREFLIGHT PASS: UID991 and pinned, independent monitoring sources", flush=True)


# Section: Exclusive root/role-owned files and directories, no clobbering.
def add_dir(path: Path, uid: int, gid: int, mode: int) -> None:
    """Create one new directory and set exact ownership and permissions."""
    path.mkdir(mode=mode, exist_ok=False)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def add_file(path: Path, data: bytes, uid: int, gid: int, mode: int) -> None:
    """Atomically publish an exclusive regular file without following links."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fchown(out.fileno(), uid, gid)
            os.fchmod(out.fileno(), mode)
            os.fsync(out.fileno())
    except BaseException:
        if path.is_file() and not path.is_symlink():
            path.unlink()
        raise


# Section: Real filtered HTTP over a local Unix socket, without secrets/logs.
class UnixHTTP(http.client.HTTPConnection):
    """Connect only to the new filtered metrics socket for acceptance."""
    def __init__(self):
        super().__init__("localhost", timeout=6)

    def connect(self):
        """Open no TCP or raw Docker socket for verification."""
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(6)
        self.sock.connect(str(SOCKET))


def query(method: str, target: str) -> tuple[int, object]:
    """Return only HTTP status and bounded, sanitized JSON response."""
    conn = UnixHTTP()
    try:
        conn.request(method, target, headers={"Connection": "close"})
        response = conn.getresponse()
        data = response.read(3 * 1048576 + 1)
        if len(data) > 3 * 1048576:
            raise RuntimeError("Metrics response exceeds the bound")
        return response.status, json.loads(data)
    finally:
        conn.close()


def acceptance() -> int:
    """Verify permitted Docker readouts and reject mutation/secret endpoints."""
    st = SOCKET.lstat()
    if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != UID or st.st_gid != GID
            or stat.S_IMODE(st.st_mode) != 0o600):
        raise RuntimeError("Metrics socket is not private to UID991")
    status, version = query("GET", "/version")
    if status != 200 or set(version) != {"Version"}:
        raise RuntimeError("Unexpected filtered Docker version response")
    status, info = query("GET", "/info")
    if status != 200 or set(info) != {"OperatingSystem", "KernelVersion", "NCPU", "MemTotal"}:
        raise RuntimeError("Unexpected filtered system information")
    status, containers = query("GET", "/containers/json")
    allowed = {"Id", "Names", "State", "Status", "Health", "Image", "Ports"}
    if status != 200 or not isinstance(containers, list) or not 1 <= len(containers) <= 128:
        raise RuntimeError("Omnilyzer Docker inventory missing or oversized")
    for item in containers:
        if (set(item) != allowed or item.get("Image") != "redacted"
                or item.get("Ports") != [] or len(item.get("Id", "")) != 64):
            raise RuntimeError("Docker inventory contains forbidden metadata")
    first = containers[0]["Id"]
    status, stats = query("GET", "/containers/" + first[:12] + "/stats?stream=0&one-shot=1")
    if status != 200 or set(stats) != {"read", "cpu_stats", "memory_stats", "networks"}:
        raise RuntimeError("Container CPU/RAM/network counters unavailable")
    if stats["memory_stats"]["usage"] <= 0:
        raise RuntimeError("Invalid container memory sample")
    rejected = (
        ("POST", "/containers/create", 405),
        ("DELETE", "/containers/" + first, 405),
        ("GET", "/containers/" + first + "/json", 404),
        ("GET", "/containers/" + first + "/logs", 404),
        ("GET", "/containers/json?all=1", 404),
    )
    for method, path, expected in rejected:
        status, _ = query(method, path)
        if status != expected:
            raise RuntimeError("Forbidden Docker request was not denied")
    print(f"LIVE SECURITY PASS: {len(containers)} running/listed containers; 5 denied requests", flush=True)
    return len(containers)


# Section: Dedicated systemd startup and agent loopback-only SSH verification.
def start_and_check() -> None:
    """Activate only the two new units and prove metrics and SSH availability."""
    systemctl("daemon-reload")
    systemctl("enable", "--now", UNITS[0])
    for _ in range(48):
        if SOCKET.is_socket():
            break
        time.sleep(0.25)
    acceptance()
    systemctl("enable", "--now", UNITS[1])
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", AGENT_PORT), timeout=2) as stream:
                stream.settimeout(2)
                banner = stream.recv(128)
            if banner.startswith(b"SSH-2.0-beszel_0.21.1"):
                break
        except OSError:
            time.sleep(0.4)
    else:
        raise RuntimeError("Isolated agent SSH banner unavailable on localhost:45878")
    for unit in UNITS:
        if systemctl("is-active", unit).stdout.strip() != "active":
            raise RuntimeError("Monitor service is not active: " + unit)
        if systemctl("is-enabled", unit).stdout.strip() != "enabled":
            raise RuntimeError("Monitor service is not enabled: " + unit)
    print("LIVE AGENT PASS: 127.0.0.1:45878, both isolated services active", flush=True)


# Section: Manifest-bound teardown, including simulated startup failures.
def remove_known_unit(unit: str) -> None:
    """Only unlink exactly named, root-owned, previously installed systemd files."""
    target = UNITDIR / unit
    if target.exists() or target.is_symlink():
        st = target.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != ROOT_UID:
            raise RuntimeError("Cannot safely remove changed unit: " + unit)
        target.unlink()


def rollback(*, from_failure: bool = False) -> None:
    """Remove only newly created monitor resources, preserving Task014 and Docker."""
    if not from_failure:
        if not MANIFEST.is_file() or MANIFEST.is_symlink():
            raise RuntimeError("Refusing rollback without installed manifest")
        obj = json.loads(MANIFEST.read_text())
        if obj.get("marker") != MARKER:
            raise RuntimeError("Installed manifest does not match this monitor")
    for unit in reversed(UNITS):
        systemctl("disable", "--now", unit, check=False)
    for unit in UNITS:
        remove_known_unit(unit)
    systemctl("daemon-reload", check=False)
    if SOCKET.is_socket() and SOCKET.lstat().st_uid == UID:
        SOCKET.unlink()
    if DATA.is_dir() and not DATA.is_symlink():
        require_dir(DATA, UID, GID, 0o700)
        shutil.rmtree(DATA)
    if STATE.is_dir() and not STATE.is_symlink():
        require_dir(STATE, ROOT_UID, ROOT_GID, 0o755)
        STATE.rmdir()  # Fail rather than delete any unexpected files.
    if PREFIX.is_dir() and not PREFIX.is_symlink():
        require_dir(PREFIX, ROOT_UID, ROOT_GID, 0o755)
        for filename in (*SOURCE_HASHES, "beszel-agent", "install-manifest.json"):
            target = PREFIX / filename
            if target.exists() or target.is_symlink():
                st = target.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid != ROOT_UID:
                    raise RuntimeError("Unexpected file in installed monitor: " + filename)
                target.unlink()
        PREFIX.rmdir()  # Fail rather than delete unexpected files.
    print("ROLLBACK PASS: only Omnilyzer Beszel monitoring resources removed", flush=True)


# Section: Install one source generation; automatic rollback on a failed gate.
def install() -> None:
    """Create only new monitor files, run live acceptance and write a manifest."""
    preflight()
    os.umask(0o077)
    try:
        add_dir(PREFIX, ROOT_UID, ROOT_GID, 0o755)
        add_dir(STATE, ROOT_UID, ROOT_GID, 0o755)
        add_dir(DATA, UID, GID, 0o700)
        for filename in SOURCE_HASHES:
            add_file(PREFIX / filename, (SOURCE / filename).read_bytes(), ROOT_UID, ROOT_GID, 0o644)
        add_file(PREFIX / "beszel-agent", BINARY.read_bytes(), ROOT_UID, ROOT_GID, 0o755)
        add_file(DATA / "hub-public-key", PUBLIC.read_bytes(), UID, GID, 0o600)
        for unit in UNITS:
            add_file(UNITDIR / unit, (SOURCE / unit).read_bytes(), ROOT_UID, ROOT_GID, 0o644)
        start_and_check()
        add_file(MANIFEST, json.dumps({"marker": MARKER, "uid": UID}).encode(), ROOT_UID, ROOT_GID, 0o600)
        print("SUCCESS: Omnilyzer container monitor installed, Docker/Task014 unchanged", flush=True)
        print("NEXT: Beszel Add System omnilyzer-containers host 127.0.0.1 port 45878 SSH", flush=True)
    except BaseException:
        rollback(from_failure=True)
        raise


# Section: Refuse all undocumented or non-root entrypoints.
def main() -> None:
    """Require owner-entered sudo and one literal install/rollback operation."""
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ("install", "rollback"):
        raise RuntimeError("Usage: sudo python3 install.py install|rollback")
    if sys.argv[1] == "install":
        install()
    else:
        rollback()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print("OMNILYZER_MONITOR_ERROR:", type(err).__name__, str(err), flush=True)
        raise SystemExit(1)
