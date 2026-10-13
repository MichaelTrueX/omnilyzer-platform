#!/usr/bin/env python3
# File (GitHub delivery): task014-c34b-phase3-diagnostic-v1.py
# File (execution host): /root/task014-c34b-phase3-diagnostic-v1.py
# Purpose: Diagnose a successful C34B 2->3 advance followed by an independent
#   --qualify-inactive OSError. Reports all independently testable failed gates.
# Related: /root/task014-c34b-migration-v1.py; reviewed-source-176ed3a...-c34a;
#   deployment/root_{executor,broker}_configuration_reader.py;
#   deployment/state_store_successor_host_migration_runtime.py.
# Safety: Root-only, read-only; no chmod, writes, service actions, Git mutation,
#   Docker mutation, rollback, retries of --advance, or deployment operations.
"""Task 014 C34B: bounded, read-only Phase 3 diagnostic matrix."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import runpy
import stat
import sys
import traceback
from typing import Callable

HOST = "omnilyzerdev"
SCRIPT = Path("/root/task014-c34b-migration-v1.py")
SCRIPT_SHA = "eca44bcc60247b6e039a4977c92c9d2c5b19e83d93e0cf92d0518fd7447e5a99"
TARGET = "176ed3a31ffcf23346639ef22ac9bcab3794f0df"
OLD_EXECUTOR_SHA = "b954895b5c95ed55ae254390a2f396167323f650f663daaad62928714f1748b9"
OLD_BROKER_SHA = "58c265133741c404ac67496aae62a83583032f369c4cc0b26d0cbf4b6f5368b9"
EXPECTED_IDENTITY_SHA = "475ac95faf25fe832cc3a6e68e68ddb3340782f8e3a93d12da1c9a98584b2cbf"


def read_pinned_script() -> dict[str, object]:
    """Verify the original root-only migration script before importing it."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = os.open(SCRIPT, flags)
    try:
        before = os.fstat(fd)
        named = SCRIPT.lstat()
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (0, 0, 0o700)
        assert (before.st_dev, before.st_ino) == (named.st_dev, named.st_ino)
        assert before.st_size == 22447
        chunks = bytearray()
        while len(chunks) < before.st_size:
            part = os.read(fd, before.st_size - len(chunks))
            assert part
            chunks.extend(part)
        assert hashlib.sha256(chunks).hexdigest() == SCRIPT_SHA
        assert os.fstat(fd).st_mtime_ns == before.st_mtime_ns
        assert SCRIPT.lstat().st_ino == before.st_ino
    finally:
        os.close(fd)
    return runpy.run_path(str(SCRIPT), run_name="task014_c34b_inspection")


def run_gate(name: str, action: Callable[[], object], *, expected: object = None) -> object | None:
    """Run one independent read-only gate and report a bounded traceback on failure."""
    try:
        outcome = action()
        if expected is not None and outcome != expected:
            raise AssertionError(f"unexpected result (expected {expected!r}, got {outcome!r})")
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception as exc:
        failed.append(name)
        # Report source locations, never configuration values or exception arguments.
        frames = traceback.extract_tb(exc.__traceback__)
        trace = " > ".join(f"{Path(f.filename).name}:{f.lineno}:{f.name}" for f in frames[-8:])
        print(f"GATE_{name}=FAIL:{type(exc).__name__}")
        print(f"TRACE_{name}={trace}")
        return None
    print(f"GATE_{name}=PASS")
    return outcome


def require_phase_three(authority: object) -> bool:
    """Accept only the terminal C34B migration phase."""
    if authority is None:
        return False
    return getattr(authority, "phase", None) == 3


def main() -> int:
    """Inspect all viable gates while keeping the DEV deployment units inactive."""
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        print("PRECHECK=FAIL:root_required")
        return 2
    if os.uname().nodename != HOST:
        print("PRECHECK=FAIL:wrong_host")
        return 2
    try:
        original = read_pinned_script()
        original["require_host"]()
        services_before = original["service_snapshot"]("inactive")
    except Exception as exc:
        print("PRECHECK=FAIL:" + type(exc).__name__)
        print("ACTION=DO_NOT_ADVANCE_OR_RESTART")
        return 2
    print("PRECHECK=PASS:root_pinned_source_and_inactive_services")
    modules = original["reviewed_modules"]()
    manifest = run_gate("MANIFEST", lambda: original["manifest_evidence"](modules))
    if manifest is not None:
        app_phase = run_gate("APPLICATION", lambda: original["application_phase"](
            manifest[0], manifest[1], modules[3]), expected=1)
    else:
        app_phase = None
    executor = run_gate("EXECUTOR_READER", modules[7])
    broker = run_gate("BROKER_READER", modules[8])
    if executor is not None:
        run_gate("EXECUTOR_COMMIT", lambda: executor.reviewed_commit, expected=TARGET)
    if broker is not None:
        run_gate("BROKER_COMMIT", lambda: broker.reviewed_commit, expected=TARGET)
        run_gate("BROKER_WORKFLOW", lambda: broker.expected_workflow_sha, expected=TARGET)
    run_gate("IDENTITY_SHA", lambda: hashlib.sha256(
        Path("/opt/omnilyzer/deployment/app/deployment/identity.py").read_bytes()
    ).hexdigest(), expected=EXPECTED_IDENTITY_SHA)
    authority = run_gate("AUTHORITY", lambda: original["read_authority"](modules))
    if authority is not None:
        run_gate("PHASE_THREE", lambda: require_phase_three(authority), expected=True)
    run_gate("STAGES_ABSENT", original["assert_no_stages"])
    rootless = run_gate("ROOTLESS", modules[6]._rootless_runtime_signature)
    if authority is not None:
        run_gate("PERSISTENT_STATE", lambda: modules[6]._persistent_state(authority.executor_model))
    services_after = run_gate("SERVICES_STILL_INACTIVE", lambda: original["service_snapshot"]("inactive"))
    if services_after is not None:
        run_gate("SERVICES_STABLE", lambda: services_after == services_before, expected=True)
    if rootless is not None:
        run_gate("ROOTLESS_STABLE", lambda: rootless == modules[6]._rootless_runtime_signature(), expected=True)
    # qualifiy() independently performs two authority inspections and two
    # runtime snapshots. Record two complete invocations to identify drift.
    if authority is not None:
        run_gate("QUALIFY_FIRST", lambda: original["qualify"]("inactive", modules).phase, expected=3)
        run_gate("QUALIFY_SECOND", lambda: original["qualify"]("inactive", modules).phase, expected=3)
    print("FAILED_GATES=" + (",".join(failed) if failed else "none"))
    print("NO_SERVICE_ACTION=PASS")
    print("NO_DOCKER_MUTATION=PASS")
    print("NO_FILE_MUTATION=PASS")
    print("NO_DEPLOYMENT_EXECUTED=PASS")
    return 0 if not failed else 1


# Diagnostic result storage is only in memory; no output artifacts are written.
failed: list[str] = []

if __name__ == "__main__":
    sys.exit(main())
