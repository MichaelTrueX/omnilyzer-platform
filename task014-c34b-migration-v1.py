#!/usr/bin/env python3
# File (delivery): task014-c34b-migration-v1.py
# File (execution host): /root/task014-c34b-migration-v1.py
# Purpose: Root-only, fail-closed Task014 C34B DEV authority migration from the
#   installed f2ece425 generation to the merged 176ed3a generation.
# Linked locations and existing repository modules:
#   /opt/omnilyzer/deployment/reviewed-source-176ed3a*-c34a/
#   /opt/omnilyzer/deployment/app/deployment/identity.py
#   /etc/omnilyzer/deployment/dev/executor.json
#   /etc/omnilyzer/deployment/broker/dev.json
#   deployment.application_source_set, deployment.application_manifest,
#   deployment.dev_host_provisioning_mechanics,
#   deployment.dev_host_provisioning_orchestration,
#   deployment.dev_post_c31_application_update,
#   deployment.root_{executor,broker}_configuration_reader,
#   deployment.state_store_successor_host_migration_runtime.
# Security: Preflight is read-only. --advance requires inactive services and
#   advances exactly ONE atomic file replacement per invocation. No service,
#   network, Docker, Git, or promotion mutation. No automatic retries.
"""Task 014 / C34B: controlled one-prefix live authority migration.

Usage:
    sudo /opt/omnilyzer/deployment/venv/bin/python -I -B \
        /root/task014-c34b-migration-v1.py --preflight-active

After separately authorized broker/socket shutdown:
    ... --qualify-inactive
    ... --advance    # once per explicitly verified next prefix, maximum three

The target workflow_sha and target reviewed_commit are the merged main commit.
All other configuration fields, source files and runtime inputs are unchanged.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys


# 1. Closed source, predecessor, and host authority.
HOST = "omnilyzerdev"
BASE = "f2ece4257b84090b1a6fff5d1aa7f0b6047765cd"
TARGET = "176ed3a31ffcf23346639ef22ac9bcab3794f0df"
TARGET_TREE = "c35c59c607c04b3d08875329fe1d18944187d24b"
SOURCE = Path("/opt/omnilyzer/deployment/reviewed-source-" + TARGET + "-c34a")
APPLICATION = Path("/opt/omnilyzer/deployment/app")
IDENTITY = APPLICATION / "deployment/identity.py"
EXECUTOR = Path("/etc/omnilyzer/deployment/dev/executor.json")
BROKER = Path("/etc/omnilyzer/deployment/broker/dev.json")
OLD_IDENTITY_SHA = "5c8a7519eff4293b9f057a2d27400967ff4d054c19e1e09b3ea33a90c217beeb"
NEW_IDENTITY_SHA = "475ac95faf25fe832cc3a6e68e68ddb3340782f8e3a93d12da1c9a98584b2cbf"
OLD_EXECUTOR_SHA = "b954895b5c95ed55ae254390a2f396167323f650f663daaad62928714f1748b9"
OLD_BROKER_SHA = "58c265133741c404ac67496aae62a83583032f369c4cc0b26d0cbf4b6f5368b9"
MANIFEST_SHA = "384f5b4e4ca9849da62ab17b624137a52b9292fd3e03d03fefcbabed3bc0ee4b"
PATHS_SHA = "c846e3d863f8c651ffc2de4d3671c9b8c0631c72366a360637d9cc45f98b60ab"
OLD_WORKFLOW = "eb7bd8a1d443e3fd9b1645cf18be9d73730a5aa9"
APP_STAGE = ".omnilyzer-c34b-identity.tmp"
EXECUTOR_STAGE = ".omnilyzer-c34b-executor.tmp"
BROKER_STAGE = ".omnilyzer-c34b-broker.tmp"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class MigrationRejected(Exception):
    """An unexpected state was encountered; fail without attempting recovery."""


# 2. Safe stat, hash and bounded Git helper functions.
def require(condition: bool, label: str) -> None:
    """Enforce a named fail-closed gate without printing private file content."""
    if not condition:
        raise MigrationRejected("REJECTED: " + label)


def digest(value: bytes) -> str:
    """Return the hexadecimal SHA-256 of one immutable byte sequence."""
    return hashlib.sha256(value).hexdigest()


def regular(path: Path, uid: int, gid: int, mode: int, maximum: int) -> bytes:
    """Read a bounded, single-link, exact-metadata file without symlink following."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        named = path.lstat()
        fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid,
                                 s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                "non-regular or linked file: " + path.name)
        require(fingerprint(before) == fingerprint(named),
                "file identity changed: " + path.name)
        require((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) ==
                (uid, gid, mode), "file ownership/mode: " + path.name)
        require(0 < before.st_size <= maximum, "file size: " + path.name)
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - len(raw)))
            require(bool(chunk), "truncated file: " + path.name)
            raw.extend(chunk)
        require(fingerprint(os.fstat(fd)) == fingerprint(before) and
                fingerprint(path.lstat()) == fingerprint(before),
                "file modified while reading: " + path.name)
        return bytes(raw)
    finally:
        os.close(fd)


def git_show(commit: str, filename: str) -> bytes:
    """Read a single immutable reviewed Git blob with a bounded subprocess."""
    require(commit in (BASE, TARGET), "unexpected Git commit")
    result = subprocess.run(
        ("/usr/bin/git", "-C", str(SOURCE), "show", commit + ":" + filename),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False, timeout=15, env={"PATH": "/usr/bin:/bin", "LANG": "C",
                                     "LC_ALL": "C", "GIT_NO_REPLACE_OBJECTS": "1",
                                     "GIT_NO_LAZY_FETCH": "1", "GIT_CONFIG_NOSYSTEM": "1",
                                     "GIT_CONFIG_GLOBAL": "/dev/null"},
    )
    require(result.returncode == 0 and 0 < len(result.stdout) <= 1048576,
            "unavailable reviewed Git blob: " + filename)
    return result.stdout


def git_head(argument: str) -> str:
    """Resolve the reviewed tree or commit without mutating the source checkout."""
    result = subprocess.run(
        ("/usr/bin/git", "-C", str(SOURCE), "rev-parse", argument),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False, timeout=10,
    )
    require(result.returncode == 0, "reviewed Git revision unavailable")
    return result.stdout.decode("ascii", "strict").strip()


# 3. Strict service lifecycle and rootless Docker continuity checks.
def unit_properties(name: str) -> tuple[str, ...]:
    """Read exact systemd lifecycle properties without changing the unit."""
    properties = ("LoadState", "ActiveState", "SubState", "UnitFileState",
                  "NeedDaemonReload", "MainPID")
    values = []
    for prop in properties:
        result = subprocess.run(
            ("/usr/bin/systemctl", "show", name, "--property=" + prop, "--value"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=10,
            env={"PATH": "/usr/bin:/usr/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        require(result.returncode == 0 and not result.stderr and len(result.stdout) < 4096,
                "systemd property unavailable")
        values.append(result.stdout.decode("utf-8", "strict").strip())
    return tuple(values)


def service_snapshot(mode: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Require active preflight or the original exact closed migration boundary."""
    units = (
        "omnilyzer-deployment-executor.socket",
        "omnilyzer-deployment-executor.service",
        "omnilyzer-deployment-broker.service",
    )
    states = tuple((unit, unit_properties(unit)) for unit in units)
    for unit, observed in states:
        load, active, sub, file_state, reload, pid = observed
        require(load == "loaded" and reload == "no", "service load/reload state")
        if unit.endswith("executor.socket"):
            target = ("active", "listening", "disabled") if mode == "active" else (
                "inactive", "dead", "disabled")
            require((active, sub, file_state) == target, "executor socket state")
        elif unit.endswith("executor.service"):
            require((active, sub, file_state, pid) ==
                    ("inactive", "dead", "static", "0"), "executor service state")
        elif unit.endswith("broker.service"):
            if mode == "active":
                require((active, sub, file_state) == ("active", "running", "static") and
                        pid.isdecimal() and int(pid) > 0, "broker active state")
            else:
                require((active, sub, file_state, pid) ==
                        ("inactive", "dead", "static", "0"), "broker inactive state")
    if mode == "inactive":
        socket_path = Path("/run/omnilyzer/deployment/executor.sock")
        require(not socket_path.exists() and not socket_path.is_symlink(),
                "executor socket remains")
    return states


def require_host() -> None:
    """Bind this script to the intended host and root-only execution identity."""
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
            "root real/effective identity required")
    require(os.uname().nodename == HOST, "wrong host")
    require(SOURCE.is_dir() and not SOURCE.is_symlink(), "reviewed source unavailable")
    require(git_head("HEAD") == TARGET and git_head("HEAD^{tree}") == TARGET_TREE,
            "reviewed source commit/tree mismatch")


# 4. Existing authoritative models and root-only protected configuration readers.
def reviewed_modules():
    """Load ONLY the immutable reviewed source code for validation/atomic primitives."""
    sys.path.insert(0, str(SOURCE))
    from deployment.application_source_set import DevApplicationSourceSet
    from deployment.application_manifest import ApplicationManifestEntry, DevApplicationManifest
    from deployment import dev_host_provisioning_mechanics as mechanics
    from deployment import dev_host_provisioning_orchestration as orchestration
    from deployment import dev_post_c31_application_update as stage_tools
    from deployment import state_store_successor_host_migration_runtime as runtime
    from deployment.root_executor_configuration_reader import read_root_dev_executor_configuration
    from deployment.root_broker_configuration_reader import read_root_dev_broker_configuration
    return (DevApplicationSourceSet, ApplicationManifestEntry, DevApplicationManifest,
            mechanics, orchestration, stage_tools, runtime,
            read_root_dev_executor_configuration, read_root_dev_broker_configuration)


@dataclass(frozen=True)
class Authority:
    """Validated exact phase and target byte sequences, with no output secrets."""
    phase: int
    before_manifest: object
    after_manifest: object
    executor_old: bytes
    executor_new: bytes
    broker_old: bytes
    broker_new: bytes
    target_identity: bytes
    executor_model: object


def manifest_evidence(modules):
    """Rebuild both generations from raw reviewed blobs and pin target manifest."""
    source_set, entry_cls, manifest_cls = modules[:3]
    paths = tuple(item.repository_path for item in source_set().files)
    require(len(paths) == 41 and digest(("\n".join(paths) + "\n").encode()) == PATHS_SHA,
            "41-file application path authority mismatch")
    old_entries, new_entries, delta = [], [], []
    for path in paths:
        old = git_show(BASE, path)
        new = git_show(TARGET, path)
        checked = SOURCE / path
        require(checked.is_file() and not checked.is_symlink() and
                checked.read_bytes() == new, "reviewed file mismatch: " + path)
        old_entries.append(entry_cls(path, digest(old), "0644"))
        new_entries.append(entry_cls(path, digest(new), "0644"))
        if old != new:
            delta.append(path)
    require(delta == ["deployment/identity.py"], "unexpected source delta")
    old_manifest = manifest_cls("canonical-relative-file-set-v1", "sha256", BASE,
                                tuple(old_entries))
    new_manifest = manifest_cls("canonical-relative-file-set-v1", "sha256", TARGET,
                                tuple(new_entries))
    require(digest(new_manifest.canonical_bytes()) == MANIFEST_SHA,
            "canonical target manifest mismatch")
    return old_manifest, new_manifest


def application_phase(old_manifest, new_manifest, mechanics) -> int:
    """Classify complete application generation with original full-tree verifier."""
    owned = []
    try:
        root, chain = mechanics._open_directory(str(APPLICATION), owned)
        require((os.fstat(root).st_uid, os.fstat(root).st_gid,
                 stat.S_IMODE(os.fstat(root).st_mode)) == (0, 0, 0o755),
                "application root metadata mismatch")
        try:
            mechanics._verify_application(root, old_manifest, 0, 0)
            phase = 0
        except OSError:
            mechanics._verify_application(root, new_manifest, 0, 0)
            phase = 1
        mechanics._revalidate_chain(chain)
        return phase
    finally:
        mechanics._finish_close(owned)


def read_authority(modules) -> Authority:
    """Read all installed identities and classify exactly four migration prefixes."""
    _, _, _, mechanics, _, _, _, executor_reader, broker_reader = modules
    old_manifest, new_manifest = manifest_evidence(modules)
    app_phase = application_phase(old_manifest, new_manifest, mechanics)
    executor = executor_reader()
    broker = broker_reader()
    require(executor.schema_version == 1 and broker.schema_version == 2,
            "configuration schema changed")
    require(executor.reviewed_commit in (BASE, TARGET) and
            broker.reviewed_commit in (BASE, TARGET) and
            broker.expected_workflow_sha in (OLD_WORKFLOW, TARGET),
            "unexpected config revision")
    require((executor.executor_gid, broker.broker_gid) == (991, 990),
            "unexpected config groups")
    executor_old = replace(executor, reviewed_commit=BASE).canonical_bytes()
    broker_old = replace(broker, reviewed_commit=BASE,
                         expected_workflow_sha=OLD_WORKFLOW).canonical_bytes()
    executor_new = replace(executor, reviewed_commit=TARGET).canonical_bytes()
    broker_new = replace(broker, reviewed_commit=TARGET,
                         expected_workflow_sha=TARGET).canonical_bytes()
    require(digest(executor_old) == OLD_EXECUTOR_SHA and digest(broker_old) == OLD_BROKER_SHA,
            "predecessor canonical configuration authority mismatch")
    installed_executor = regular(EXECUTOR, 0, 991, 0o640, 65536)
    installed_broker = regular(BROKER, 0, 990, 0o640, 65536)
    require(installed_executor == executor.canonical_bytes() and
            installed_broker == broker.canonical_bytes(), "installed configuration not canonical")
    require((installed_executor, installed_broker) in (
        (executor_old, broker_old),
        (executor_new, broker_old),
        (executor_new, broker_new),
    ), "unapproved configuration pairing")
    pair = (app_phase, installed_executor == executor_new,
            installed_broker == broker_new)
    states = {(0, False, False): 0, (1, False, False): 1,
              (1, True, False): 2, (1, True, True): 3}
    require(pair in states, "mixed or out-of-order migration phase")
    target_identity = git_show(TARGET, "deployment/identity.py")
    require(digest(target_identity) == NEW_IDENTITY_SHA and
            digest(git_show(BASE, "deployment/identity.py")) == OLD_IDENTITY_SHA,
            "identity blob mismatch")
    return Authority(states[pair], old_manifest, new_manifest, executor_old,
                     executor_new, broker_old, broker_new, target_identity,
                     executor)


def assert_no_stages() -> None:
    """Reject any prior partial write; recovery requires explicit human review."""
    for directory, filename in ((IDENTITY.parent, APP_STAGE),
                                (EXECUTOR.parent, EXECUTOR_STAGE),
                                (BROKER.parent, BROKER_STAGE)):
        path = directory / filename
        require(not path.exists() and not path.is_symlink(),
                "C34B staging file present: " + filename)


def continuity(modules, authority, mode: str):
    """Prove stable units, rootless Docker, and pristine persistent state."""
    runtime = modules[6]
    service_before = service_snapshot(mode)
    rootless_before = runtime._rootless_runtime_signature()
    runtime._persistent_state(authority.executor_model)
    require(rootless_before == runtime._rootless_runtime_signature() and
            service_before == service_snapshot(mode),
            "rootless/process continuity changed during qualification")
    return service_before, rootless_before


# 5. Atomic replacement, using the existing reviewed C31/C33 primitives.
def replace_single_file(modules, *, path: Path, stage_name: str,
                        old_bytes: bytes, new_bytes: bytes, gid: int,
                        parent_mode: int, file_mode: int) -> None:
    """Revalidate protected descriptors and atomically replace one fixed file."""
    mechanics, stage_tools = modules[3], modules[5]
    require(0 < len(old_bytes) <= 1048576 and 0 < len(new_bytes) <= 1048576,
            "replacement file size")
    owned = []
    try:
        parent, filename, chain = mechanics._open_parent(str(path), owned)
        metadata = os.fstat(parent)
        require((metadata.st_uid, metadata.st_gid,
                 stat.S_IMODE(metadata.st_mode)) == (0, gid, parent_mode),
                "replacement directory metadata")
        require(regular(path, 0, gid, file_mode, 1048576) == old_bytes,
                "replacement predecessor changed")
        require(not (path.parent / stage_name).exists() and
                not (path.parent / stage_name).is_symlink(),
                "unexpected replacement staging file")
        stage = stage_tools._stage(parent, stage_name, new_bytes, file_mode, 0, gid)
        require(stage is None, "unexpected existing staging state")
        mechanics._revalidate_chain(chain)
        stage_tools._write_replace_stage(parent, stage_name, filename,
                                         new_bytes, file_mode, 0, gid, stage)
        mechanics._revalidate_chain(chain)
    finally:
        mechanics._finish_close(owned)


def qualify(mode: str, modules) -> Authority:
    """Prove one stable, stage-free predecessor/partial/complete authority."""
    first = read_authority(modules)
    assert_no_stages()
    services, rootless = continuity(modules, first, mode)
    again = read_authority(modules)
    require(first.phase == again.phase and first == again,
            "authority changed during qualification")
    require(services == service_snapshot(mode) and
            rootless == modules[6]._rootless_runtime_signature(),
            "service/runtime changed during qualification")
    return first


def advance(modules) -> None:
    """Advance at most one prefix under the shared nonblocking process lock."""
    orchestration = modules[4]
    lock = orchestration._acquire_process_lock()
    try:
        before = qualify("inactive", modules)
        require(before.phase < 3, "C34B already complete; no replacement permitted")
        services = service_snapshot("inactive")
        rootless = modules[6]._rootless_runtime_signature()
        if before.phase == 0:
            replace_single_file(modules, path=IDENTITY, stage_name=APP_STAGE,
                                old_bytes=git_show(BASE, "deployment/identity.py"),
                                new_bytes=before.target_identity, gid=0,
                                parent_mode=0o755, file_mode=0o644)
        elif before.phase == 1:
            replace_single_file(modules, path=EXECUTOR, stage_name=EXECUTOR_STAGE,
                                old_bytes=before.executor_old,
                                new_bytes=before.executor_new, gid=991,
                                parent_mode=0o750, file_mode=0o640)
        else:
            replace_single_file(modules, path=BROKER, stage_name=BROKER_STAGE,
                                old_bytes=before.broker_old,
                                new_bytes=before.broker_new, gid=990,
                                parent_mode=0o750, file_mode=0o640)
        require(services == service_snapshot("inactive") and
                rootless == modules[6]._rootless_runtime_signature(),
                "runtime or service state changed after replacement")
        after = qualify("inactive", modules)
        require(after.phase == before.phase + 1,
                "migration did not advance exactly one reviewed prefix")
        print(f"C34B_ADVANCED={before.phase}->{after.phase}")
        print(f"C34B_NEXT_PHASE={after.phase}")
    finally:
        orchestration._release_process_lock(lock)


# 6. Explicit CLI; every failure exits without attempting rollback or retry.
def main() -> int:
    """Qualify active/inactive authority or advance one offline atomic prefix."""
    parser = argparse.ArgumentParser(description="Task014 C34B fail-closed authority migration")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preflight-active", action="store_true")
    modes.add_argument("--qualify-inactive", action="store_true")
    modes.add_argument("--advance", action="store_true")
    args = parser.parse_args()
    require_host()
    modules = reviewed_modules()
    if args.preflight_active:
        authority = qualify("active", modules)
        require(authority.phase == 0, "active-state preflight expects predecessor")
        print("C34B_ACTIVE_PREFLIGHT=PASS")
        print("C34B_PHASE=0")
    elif args.qualify_inactive:
        authority = qualify("inactive", modules)
        print("C34B_INACTIVE_QUALIFICATION=PASS")
        print(f"C34B_PHASE={authority.phase}")
    else:
        advance(modules)
    print("NO_SERVICE_ACTION=PASS")
    print("NO_DOCKER_ACTION=PASS")
    print("NO_DEPLOYMENT_EXECUTED=PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except _CONTROL:
        raise
    except Exception as exc:
        print("C34B_REJECTED: " + (str(exc) if isinstance(exc, MigrationRejected)
                                   else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
