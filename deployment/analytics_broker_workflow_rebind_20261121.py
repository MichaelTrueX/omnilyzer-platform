"""File: deployment/analytics_broker_workflow_rebind_20261121.py

Purpose: One exact, owner-attended DEV Task014 original broker workflow-SHA
         correction, after the signed OIDC identity denial in run 44876028251.
Related: deployment/broker_service_config.py (unchanged canonical schema),
         deployment/analytics_broker_service.py (original config loader),
         deployment/analytics_active_state_review.py (immutable live image),
         deployment/analytics_route_journal.py (durable rollback reference),
         docs/operations/task014-pre-release-checklist.md, M05 Issue #281.

SECURITY: This is a one-pair, one-time, reviewed root-only operator. It does
not relax OIDC, accept tokens, trigger Task013/014, change an image, access a
database, or modify PROD. Only original broker/dev.json may change, exactly
one field. No untrusted path, SHA, permission or command is configurable.
The old canonical bytes remain in a root-only same-directory backup.
An interrupted or uncertain operation is HOLD, never implied success.
"""
from __future__ import annotations

from dataclasses import replace
import fcntl
import hashlib
import http.client
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

# Section 1: Exact immutable identities and files of the reviewed DEV source.
OLD = "c6d6b067f932e60d82f8b7a9d75a2629a62606c8"
NEW = "630db1ae5a05a691493764637e066e487f52f599"
SOURCE = Path(
    "/opt/omnilyzer/deployment/"
    "analytics-app-release-330f3255f0067b9ddbe30d50466830bd71a55a11"
)
SELF = Path("/usr/local/libexec/omnilyzer-m05-broker-workflow-rebind-630.py")
DIRECTORY = Path("/etc/omnilyzer/deployment/broker")
TARGET = "dev.json"
BACKUP = ".m05-task014-20261121-c6d6-to-630-original.bak"
STAGED = ".m05-task014-20261121-c6d6-to-630-staged.tmp"
RESTORE = ".m05-task014-20261121-c6d6-to-630-restore.tmp"
SERVICE = "omnilyzer-deployment-broker.service"
EXECUTOR_SOCKET = "omnilyzer-deployment-analytics-executor.socket"
LOOPBACK = "omnilyzer-analytics-loopback.service"
EXPECTED_IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/analytics@"
    "sha256:a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1"
)
SOURCE_SHA256 = {
    "deployment/broker_service_config.py":
        "cb5aa6ebde6071a3276b218bc85759ddadc52a172bf5b6e57235429b5e1b7967",
    "deployment/identity.py":
        "475ac95faf25fe832cc3a6e68e68ddb3340782f8e3a93d12da1c9a98584b2cbf",
    "deployment/oidc_verifier.py":
        "3b7c6abf5bc0a388bf62537b2912d8f1832b2897fb2439f285ea45347e8d91c1",
    "deployment/broker.py":
        "79cc91653ba53ed7c822a2d9035d9a3b0a6fc157c349233fe91837255d19fb5b",
    "deployment/analytics_promotion_broker.py":
        "4403ea71c730e9bb1e9b98785fb9459f68155fd5853e435a8a2bcd515270cd69",
    "deployment/analytics_active_state_review.py":
        "9d1d8bc48f83839da376c0312ce314401cf147a9be620b319bcaed6ea6d443ec",
    "deployment/analytics_route_journal.py":
        "a187b1242943b6b55f992e889e66e6a658095733755ec946e4be5cdc46764964",
}
_ERROR = "M05_ORIGINAL_BROKER_REBIND_HOLD"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class RebindDenied(Exception):
    """One strict, non-sensitive reason to refuse the entire operation."""


# Section 2: Pure, source-model-backed transformation of exactly one field.
def _rebound_bytes(raw: bytes) -> tuple[bytes, int]:
    """Accept only canonical installed broker schema and old workflow SHA."""
    from deployment.broker_service_config import (
        DevBrokerServiceConfiguration,
        parse_canonical_broker_service_configuration,
    )

    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        raise RebindDenied(_ERROR)
    old = parse_canonical_broker_service_configuration(raw)
    if (
        type(old) is not DevBrokerServiceConfiguration
        or old.expected_workflow_sha != OLD
        or old.canonical_bytes() != raw
    ):
        raise RebindDenied(_ERROR)
    new = replace(old, expected_workflow_sha=NEW)
    before, after = old.to_dict(), new.to_dict()
    if (
        set(before) != set(after)
        or {key for key in before if before[key] != after[key]}
        != {"expected_workflow_sha"}
        or new.expected_workflow_sha != NEW
    ):
        raise RebindDenied(_ERROR)
    result = new.canonical_bytes()
    if result == raw or len(result) > 4096:
        raise RebindDenied(_ERROR)
    if parse_canonical_broker_service_configuration(result).to_dict() != after:
        raise RebindDenied(_ERROR)
    return result, old.broker_gid


# Section 3: Exact root-installed source and protected-directory requirements.
def _trusted_regular(path: Path, *, mode: int, maximum: int) -> bytes:
    """Read one nonsymlinked root-owned single-link file using O_NOFOLLOW."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != mode
            or not 0 < info.st_size <= maximum
        ):
            raise RebindDenied(_ERROR)
        raw = os.read(fd, maximum + 1)
        if len(raw) != info.st_size:
            raise RebindDenied(_ERROR)
        return raw
    finally:
        os.close(fd)


def _trust_root() -> None:
    """Require root on omnilyzerdev and byte-exact installed review modules."""
    if (
        (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        != (0, 0, 0, 0)
        or socket.gethostname() != "omnilyzerdev"
        or Path(sys.argv[0]) != SELF
        or Path(sys.argv[0]).is_symlink()
    ):
        raise RebindDenied(_ERROR)
    _trusted_regular(SELF, mode=0o500, maximum=32768)
    for path in (
        Path("/etc"), Path("/etc/omnilyzer"),
        Path("/etc/omnilyzer/deployment"), DIRECTORY, SOURCE,
        SOURCE / "deployment",
    ):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise RebindDenied(_ERROR)
    if stat.S_IMODE(DIRECTORY.stat().st_mode) != 0o750:
        raise RebindDenied(_ERROR)
    for relative, expected in SOURCE_SHA256.items():
        if hashlib.sha256(
            _trusted_regular(SOURCE / relative, mode=0o644, maximum=1_048_576)
        ).hexdigest() != expected:
            raise RebindDenied(_ERROR)
    sys.path.insert(0, str(SOURCE))


def _read_at(parent: int, name: str, *, gid: int | None = None,
             mode: int = 0o640) -> tuple[bytes, tuple[int, ...]]:
    """Verify a named root-owned regular file without following a symlink."""
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    fd = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        dir_fd=parent,
    )
    try:
        opened = os.fstat(fd)
        if (
            (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_ctime_ns)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != 0
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != mode
            or (gid is not None and opened.st_gid != gid)
            or not 0 < opened.st_size <= 4096
        ):
            raise RebindDenied(_ERROR)
        data = os.read(fd, 4097)
        if len(data) != opened.st_size:
            raise RebindDenied(_ERROR)
        return data, (
            opened.st_dev, opened.st_ino, opened.st_mtime_ns,
            opened.st_ctime_ns, opened.st_gid,
        )
    finally:
        os.close(fd)


def _missing_at(parent: int, name: str) -> None:
    """Require a never-used one-time backup or temporary destination."""
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise RebindDenied(_ERROR)


# Section 4: Existing service and signed live-route checks, strictly read-only.
def _service_property(service: str, property_name: str) -> str:
    """Read a fixed systemd property, never issue a user-provided command."""
    out = subprocess.run(
        ["/usr/bin/systemctl", "show", service,
         "-p", property_name, "--value", "--no-pager"],
        capture_output=True, check=False, timeout=8,
    )
    if out.returncode != 0 or len(out.stdout) > 4096:
        raise RebindDenied(_ERROR)
    return out.stdout.decode("ascii", "strict").strip()


def _service_state() -> int:
    """Check broker loaded source, broker PID and two unaffected services."""
    if (
        _service_property(SERVICE, "ActiveState") != "active"
        or _service_property(SERVICE, "SubState") != "running"
        or _service_property(SERVICE, "WorkingDirectory") != str(SOURCE)
        or _service_property(SERVICE, "User") != "omnilyzer-broker"
        or _service_property(EXECUTOR_SOCKET, "ActiveState") != "active"
        or _service_property(LOOPBACK, "ActiveState") != "active"
    ):
        raise RebindDenied(_ERROR)
    value = _service_property(SERVICE, "MainPID")
    if not value.isascii() or not value.isdecimal() or int(value) < 2:
        raise RebindDenied(_ERROR)
    return int(value)


def _route_state() -> tuple[object, object]:
    """Reuse signed running-image and durable journal readers without writes."""
    from deployment.analytics_active_state_review import (
        inspect_analytics_active_state,
    )
    from deployment.analytics_route_journal import AnalyticsRouteJournal

    live = inspect_analytics_active_state()
    journal = AnalyticsRouteJournal()
    record = journal.read()
    if (
        live.active_slot != "green"
        or live.active_image != EXPECTED_IMAGE
        or live.candidate_slot != "blue"
        or live.candidate_probe_present is not False
        or live.read_only is not True
        or live.deployment_authorized is not False
        or not isinstance(record, dict)
        or record.get("phase") != "switched"
        or record.get("next_slot") != live.active_slot
        or record.get("next_image") != live.active_image
        or record.get("next_container_id") != live.active_container_id
        or journal.read_slot_retirement() is not None
    ):
        raise RebindDenied(_ERROR)
    connection = http.client.HTTPConnection("127.0.0.1", 3141, timeout=4)
    try:
        connection.request("GET", "/readyz", headers={"Cache-Control": "no-store"})
        response = connection.getresponse()
        response.read(2049)
        if response.status != 200:
            raise RebindDenied(_ERROR)
    finally:
        connection.close()
    return live, record


# Section 5: Root-only same-directory durable backup and atomic config replace.
def _stage_file(parent: int, name: str, content: bytes,
                *, gid: int, mode: int) -> None:
    """Create one new exact payload, fsync, and independently verify bytes."""
    _missing_at(parent, name)
    fd = os.open(
        name, os.O_RDWR | os.O_CREAT | os.O_EXCL
        | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent,
    )
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(content):
            written = os.write(fd, content[offset:])
            if written <= 0:
                raise RebindDenied(_ERROR)
            offset += written
        os.fsync(fd)
        observed = os.fstat(fd)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_gid != gid
            or stat.S_IMODE(observed.st_mode) != mode
            or observed.st_nlink != 1
            or observed.st_size != len(content)
            or os.pread(fd, len(content) + 1, 0) != content
        ):
            raise RebindDenied(_ERROR)
    finally:
        os.close(fd)
    os.fsync(parent)


def _publish(parent: int, name: str, expected: bytes, replacement: bytes,
             *, gid: int) -> None:
    """Atomically exchange one exact old broker config; never edit in place."""
    actual, _identity = _read_at(parent, TARGET, gid=gid)
    if actual != expected:
        raise RebindDenied(_ERROR)
    _stage_file(parent, name, replacement, gid=gid, mode=0o640)
    check, _ = _read_at(parent, name, gid=gid)
    if check != replacement:
        raise RebindDenied(_ERROR)
    os.replace(name, TARGET, src_dir_fd=parent, dst_dir_fd=parent)
    os.fsync(parent)
    confirmed, _ = _read_at(parent, TARGET, gid=gid)
    if confirmed != replacement:
        raise RebindDenied(_ERROR)


def _restart_broker() -> None:
    """Restart only the original broker to load its new immutable SHA pin."""
    result = subprocess.run(
        ["/usr/bin/systemctl", "restart", SERVICE],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=30, check=False,
    )
    if result.returncode != 0:
        raise RebindDenied(_ERROR)


# Section 6: One-shot apply with rollback if service or route acceptance fails.
def _execute(apply: bool) -> None:
    """Read-only preflight or single allowed root config exchange and restart."""
    _trust_root()
    parent = os.open(
        DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before, original_identity = _read_at(parent, TARGET)
        after, gid = _rebound_bytes(before)
        if original_identity[4] != gid or DIRECTORY.stat().st_gid != gid:
            raise RebindDenied(_ERROR)
        for name in (BACKUP, STAGED, RESTORE):
            _missing_at(parent, name)
        pid = _service_state()
        active, route = _route_state()
        if not apply:
            print("M05_ORIGINAL_BROKER_REBIND_PREFLIGHT_PASS")
            return

        changed = False
        try:
            _stage_file(parent, BACKUP, before, gid=0, mode=0o600)
            backup, _ = _read_at(parent, BACKUP, gid=0, mode=0o600)
            if backup != before or _read_at(parent, TARGET, gid=gid)[1] != original_identity:
                raise RebindDenied(_ERROR)
            _publish(parent, STAGED, before, after, gid=gid)
            changed = True
            _restart_broker()
            if _service_state() == pid or _read_at(parent, TARGET, gid=gid)[0] != after:
                raise RebindDenied(_ERROR)
            if _route_state() != (active, route):
                raise RebindDenied(_ERROR)
        except _CONTROL:
            raise
        except Exception:
            # A successful atomic replace followed by a failed fsync/readback
            # may raise BEFORE changed becomes True. Observe the exact target
            # and restore it if new bytes are already live. Never guess.
            try:
                current_bytes, _ = _read_at(parent, TARGET, gid=gid)
            except Exception:
                current_bytes = None
            if changed or current_bytes == after:
                try:
                    _publish(parent, RESTORE, after, before, gid=gid)
                    _restart_broker()
                    if (
                        _service_state() < 2
                        or _read_at(parent, TARGET, gid=gid)[0] != before
                        or _route_state() != (active, route)
                    ):
                        raise RebindDenied(_ERROR)
                    print("M05_ORIGINAL_BROKER_REBIND_RESTORED_0160_HOLD")
                except _CONTROL:
                    raise
                except Exception:
                    print("M05_ORIGINAL_BROKER_REBIND_RECOVERY_UNCONFIRMED_HOLD")
            raise RebindDenied(_ERROR) from None
        print("M05_ORIGINAL_BROKER_WORKFLOW_SHA_REBIND_PASS")
        print("M05_ANALYTICS_SIGNED_0160_ROUTE_UNCHANGED_PASS")
        print("M05_NO_TASK014_DISPATCH_NO_PROD")
    finally:
        os.close(parent)


def main() -> int:
    """Permit only exact --preflight or --apply; never an implicit mutation."""
    try:
        if sys.argv[1:] == ["--preflight"]:
            _execute(False)
        elif sys.argv[1:] == ["--apply"]:
            _execute(True)
        else:
            raise RebindDenied(_ERROR)
        return 0
    except _CONTROL:
        raise
    except Exception:
        print(_ERROR)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
