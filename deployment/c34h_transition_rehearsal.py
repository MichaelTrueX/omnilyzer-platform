"""File: deployment/c34h_transition_rehearsal.py

Purpose: Rehearse Task 014's five-file ordered atomic migration, interruption
recovery, and reverse rollback in an exclusively disposable local filesystem.
Related: deployment/c34g_migration_authority.py,
deployment/c34f_application_generation_evidence.py,
deployment/tests/test_c34h_transition_rehearsal.py.

This module CANNOT install to live DEV: it creates its own private
TemporaryDirectory, refuses root and has no configurable application path.
It does not touch systemd, Docker, replay/audit, network or external secrets.
It is non-authoritative test evidence; a separately reviewed host migrator,
merged release SHA and privilege boundary are still mandatory.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import tempfile

from . import c34f_application_generation_evidence as evidence
from .c34g_migration_authority import C34GMigrationAuthority, C34GMigrationState
from .broker_service_config import DevBrokerServiceConfiguration
from .executor_service_config import DevExecutorServiceConfiguration


# Section 1: Closed file selection and error surface.
_STAGE = ".c34h-stage"
_OPERATIONS = (*evidence.CHANGED, "executor.json", "broker.json")
_INTERRUPTIONS = frozenset({
    "after_stage_create", "after_half_write", "before_replace", "after_replace",
})
_ERROR = "C34H isolated transition rehearsal state is invalid"


class C34HRehearsalError(Exception):
    """Signal only fixed nonsecret test-state errors."""


class C34HInjectedInterruption(Exception):
    """Synthetic stop at one reviewed write boundary; never an actual crash."""


@dataclass(frozen=True, slots=True)
class C34HRehearsalReceipt:
    """A pure snapshot of disposable source/config state."""

    completed_steps: int
    next_operation: str
    rollback_operation: str


class C34HIsolatedRehearsal:
    """Own a temporary, non-root-only tree containing the 41 protected files.

    Existing C34F/C34G source evidence is the only payload authority. No
    caller-selected target directory or workflow revision is accepted.
    """

    def __init__(
        self, *,
        executor: DevExecutorServiceConfiguration,
        broker: DevBrokerServiceConfiguration,
    ) -> None:
        """Build a complete disposable predecessor with a closed config pair."""
        if os.getuid() == 0 or os.geteuid() == 0:
            raise C34HRehearsalError(_ERROR)
        self._temporary = tempfile.TemporaryDirectory(prefix="omnilyzer-c34h-")
        self._root = Path(self._temporary.name)
        try:
            old = evidence._manifest(evidence.PREDECESSOR, self._paths())
            new = evidence._manifest(evidence.C34E_PROPOSAL, self._paths())
            self.authority = C34GMigrationAuthority(
                predecessor_manifest=old,
                proposal_manifest=new,
                predecessor_executor=executor,
                predecessor_broker=broker,
            )
            self._old_blobs = dict(evidence.git_source._git_blobs(
                evidence.PREDECESSOR, self._paths()
            ))
            self._new_blobs = dict(evidence.git_source._git_blobs(
                evidence.C34E_PROPOSAL, self._paths()
            ))
            if set(self._old_blobs) != set(self._new_blobs):
                raise ValueError
            for name, raw in self._old_blobs.items():
                self._write_initial(self._root / "app" / name, raw, 0o644)
            self._write_initial(
                self._root / "config" / "executor.json",
                executor.canonical_bytes(), 0o640,
            )
            self._write_initial(
                self._root / "config" / "broker.json",
                broker.canonical_bytes(), 0o640,
            )
            self.current()
        except BaseException:
            self._temporary.cleanup()
            raise

    @staticmethod
    def _paths() -> tuple[str, ...]:
        """Select exactly the existing reviewed application source allowlist."""
        from .application_source_set import DevApplicationSourceSet
        return tuple(file.repository_path for file in DevApplicationSourceSet().files)

    @staticmethod
    def _write_initial(path: Path, raw: bytes, mode: int) -> None:
        """Populate only the freshly created private sandbox's initial files."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "xb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        path.chmod(mode)

    def __enter__(self) -> "C34HIsolatedRehearsal":
        """Return the owned sandbox for deterministic acceptance tests."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Remove the disposable sandbox on normal exit or test failure."""
        self.close()

    def close(self) -> None:
        """Dispose only the private TemporaryDirectory created by this object."""
        self._temporary.cleanup()

    def _file(self, name: str) -> Path:
        """Project one of exactly five known destination names into the sandbox."""
        if name not in _OPERATIONS:
            raise C34HRehearsalError(_ERROR)
        return self._root / ("app" if name.startswith("deployment/") else "config") / name

    @staticmethod
    def _read_file(path: Path, maximum: int = 1048576) -> bytes:
        """Reject link/nonregular/mode drift before reading a simulated file."""
        status = path.lstat()
        expected_mode = 0o644 if path.suffix == ".py" or path.suffix in (".yaml",) else None
        if expected_mode is None:
            expected_mode = 0o640 if path.name in ("executor.json", "broker.json") else 0o644
        if (not stat.S_ISREG(status.st_mode) or status.st_nlink != 1
                or stat.S_IMODE(status.st_mode) != expected_mode
                or not 0 < status.st_size <= maximum):
            raise C34HRehearsalError(_ERROR)
        with open(path, "rb") as file:
            read = file.read(maximum + 1)
            after = os.fstat(file.fileno())
        if (len(read) != status.st_size or after.st_ino != status.st_ino
                or after.st_mtime_ns != status.st_mtime_ns):
            raise C34HRehearsalError(_ERROR)
        return read

    def current(self) -> C34GMigrationState:
        """Classify all 41 exact file bytes and both canonical configs."""
        try:
            paths = self._paths()
            digest = tuple(
                (name, hashlib.sha256(
                    self._read_file(self._root / "app" / name)
                ).hexdigest()) for name in paths
            )
            executor = DevExecutorServiceConfiguration.from_dict(
                self._canonical(self._read_file(self._file("executor.json")))
            )
            broker = DevBrokerServiceConfiguration.from_dict(
                self._canonical(self._read_file(self._file("broker.json")))
            )
            return self.authority.classify(
                observed_application_digests=digest,
                executor=executor,
                broker=broker,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise C34HRehearsalError(_ERROR) from None

    @staticmethod
    def _canonical(raw: bytes) -> dict:
        """Parse only exact canonical JSON without duplicate object fields."""
        import json
        def unique(pairs):
            """Forbid repeated keys even in nested configuration objects."""
            result = {}
            for k, v in pairs:
                if k in result:
                    raise ValueError
                result[k] = v
            return result
        data = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
        if type(data) is not dict:
            raise ValueError
        if (json.dumps(data, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii") != raw:
            raise ValueError
        return data

    def _payload(self, step: int, reverse: bool) -> tuple[Path, bytes]:
        """Select the sole next source/config payload based on the prefix."""
        if type(step) is not int or not 0 <= step < 5:
            raise C34HRehearsalError(_ERROR)
        index = 4 - step if reverse else step
        name = _OPERATIONS[index]
        if index < 3:
            raw = (self._old_blobs if reverse else self._new_blobs)[name]
        else:
            ex, br = (
                (self.authority.predecessor_executor,
                 self.authority.predecessor_broker)
                if reverse else self.authority.target_configuration_pair()
            )
            raw = ex.canonical_bytes() if index == 3 else br.canonical_bytes()
        return self._file(name), raw

    @staticmethod
    def _atomic_replacement(
        target: Path, raw: bytes, *, interrupt: str | None,
    ) -> None:
        """Stage/revalidate a bounded exact-prefix payload, fsync, and replace.

        Interruption points model process failure at each durability boundary.
        A subsequent call can resume a verified partial stage without replaying
        a completed atomic rename.
        """
        if interrupt is not None and interrupt not in _INTERRUPTIONS:
            raise C34HRehearsalError(_ERROR)
        stage = target.parent / _STAGE
        required_mode = 0o640 if target.suffix == ".json" else 0o644
        if not stage.exists():
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            os.close(fd)
            if interrupt == "after_stage_create":
                raise C34HInjectedInterruption
        status = stage.lstat()
        if (not stat.S_ISREG(status.st_mode) or status.st_nlink != 1
                or stat.S_IMODE(status.st_mode) not in (0o600, required_mode)
                or status.st_size > len(raw)):
            raise C34HRehearsalError(_ERROR)
        with open(stage, "rb") as file:
            current = file.read(len(raw) + 1)
        if current != raw[:len(current)]:
            raise C34HRehearsalError(_ERROR)
        remaining = raw[len(current):]
        with open(stage, "ab") as file:
            if interrupt == "after_half_write" and remaining:
                part = max(1, len(remaining) // 2)
                file.write(remaining[:part])
                file.flush()
                os.fsync(file.fileno())
                raise C34HInjectedInterruption
            file.write(remaining)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(stage, required_mode)
        fd = os.open(stage, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        if interrupt == "before_replace":
            raise C34HInjectedInterruption
        os.replace(stage, target)
        parentfd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY
                           | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(parentfd)
        finally:
            os.close(parentfd)
        if interrupt == "after_replace":
            raise C34HInjectedInterruption

    def advance(self, *, interrupt: str | None = None) -> C34HRehearsalReceipt:
        """Advance at most one exact staged step in the private sandbox."""
        state = self.current()
        if state.completed_steps == 5:
            return self._receipt(state)
        dest, raw = self._payload(state.completed_steps, reverse=False)
        self._atomic_replacement(dest, raw, interrupt=interrupt)
        after = self.current()
        if after.completed_steps != state.completed_steps + 1:
            raise C34HRehearsalError(_ERROR)
        return self._receipt(after)

    def rollback_one(self) -> C34HRehearsalReceipt:
        """Undo at most one complete prefix, after discarding a valid staged prefix."""
        state = self.current()
        # A pending forward-stage prefix is allowed to be abandoned, but not
        # if its content differs from the exact expected next payload.
        if state.completed_steps < 5:
            next_dest, next_payload = self._payload(state.completed_steps, reverse=False)
            stage = next_dest.parent / _STAGE
            if stage.exists():
                data = stage.read_bytes()
                if (not stage.is_file() or stage.stat().st_nlink != 1
                        or len(data) > len(next_payload)
                        or data != next_payload[:len(data)]):
                    raise C34HRehearsalError(_ERROR)
                stage.unlink()
        if state.completed_steps == 0:
            return self._receipt(state)
        # Reverse next-step index is (5 - phase), so complete state first
        # restores the broker config, then executor, then 3 Python modules.
        dest, raw = self._payload(5 - state.completed_steps, reverse=True)
        self._atomic_replacement(dest, raw, interrupt=None)
        after = self.current()
        if after.completed_steps != state.completed_steps - 1:
            raise C34HRehearsalError(_ERROR)
        return self._receipt(after)

    @staticmethod
    def _receipt(state: C34GMigrationState) -> C34HRehearsalReceipt:
        """Report only fixed phase names, never local source or private data."""
        return C34HRehearsalReceipt(
            completed_steps=state.completed_steps,
            next_operation=state.next_operation,
            rollback_operation=state.rollback_operation(),
        )


__all__ = (
    "C34HIsolatedRehearsal",
    "C34HRehearsalError",
    "C34HInjectedInterruption",
    "C34HRehearsalReceipt",
)
