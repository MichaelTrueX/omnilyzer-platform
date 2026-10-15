"""File: deployment/c34n_root_predecessor_adapter.py

Purpose: Root-only, read-only and stopped-service Task 014 C34N observer
for the already verified 41-file DEV predecessor installation.
Related: deployment/c34m_descriptor_source_observation.py,
deployment/c34g_installed_predecessor_preflight.py,
deployment/state_store_successor_host_migration_runtime.py,
deployment/root_executor_configuration_reader.py,
deployment/root_broker_configuration_reader.py,
deployment/dev_host_provisioning_orchestration.py,
deployment/tests/test_c34n_root_predecessor_adapter.py.

This is NOT a migration installer or final-main authority. It cannot stop
or restart services, write files, rotate workflow SHA, fetch credentials,
alter persistent replay/audit state or authorize a promotion. An operator
must separately approve a maintenance window before any actual root run.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat

from . import c34f_application_generation_evidence as reference
from . import c34g_installed_predecessor_preflight as predecessor
from . import c34m_descriptor_source_observation as observer
from . import dev_host_provisioning_orchestration as orchestration
from . import state_store_successor_host_migration_runtime as runtime
from .root_executor_configuration_reader import read_root_dev_executor_configuration
from .root_broker_configuration_reader import read_root_dev_broker_configuration


# Section 1: Fixed, no-substitution absolute locations and bounded errors.
_ERROR = "C34N stopped predecessor observation is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_APP = ("opt", "omnilyzer", "deployment", "app")
_MODULE = _APP + ("deployment",)
_EXECUTOR = ("etc", "omnilyzer", "deployment", "dev")
_BROKER = ("etc", "omnilyzer", "deployment", "broker")
_EXPECTED = tuple(sorted(predecessor.EXPECTED.items()))


class C34NRootPredecessorError(Exception):
    """Use one fixed, nonsecret HOLD error on any root precondition failure."""


@dataclass(frozen=True, slots=True)
class C34NRootPredecessorReceipt:
    """Non-authorizing closed source/config/stopped-runtime evidence."""

    source_reviewed_commit: str
    expected_workflow_sha: str
    protected_files: int
    no_pending_stage: bool
    stopped_units_verified: bool
    rootless_runtime_preserved: bool
    migration_ready: bool

    def __post_init__(self) -> None:
        """Prevent caller-forged live install permission or new source SHA."""
        if (
            self.source_reviewed_commit != reference.PREDECESSOR
            or self.expected_workflow_sha != reference.C34D_MAIN
            or type(self.protected_files) is not int
            or self.protected_files != 41
            or self.no_pending_stage is not True
            or self.stopped_units_verified is not True
            or self.rootless_runtime_preserved is not True
            or self.migration_ready is not False
        ):
            raise ValueError(_ERROR)


def _snapshot(stat_value: os.stat_result) -> tuple[int, ...]:
    """Compare directory identity without access-time changes."""
    return (stat_value.st_mode, stat_value.st_dev, stat_value.st_ino,
            stat_value.st_uid, stat_value.st_gid, stat_value.st_nlink,
            stat_value.st_mtime_ns, stat_value.st_ctime_ns)


def _require_directory(stat_value: os.stat_result, *, uid: int, gid: int | None,
                       final_mode: int | None) -> None:
    """Require root-owned trusted ancestors and exact protected leaf modes."""
    if (
        not stat.S_ISDIR(stat_value.st_mode)
        or stat_value.st_uid != uid
        or (
            final_mode is None and stat.S_IMODE(stat_value.st_mode) & 0o022
        )
        or (
            final_mode is not None
            and (stat.S_IMODE(stat_value.st_mode) != final_mode
                 or stat_value.st_gid != gid)
        )
    ):
        raise ValueError


def _open_chain(
    anchor_fd: int, components: tuple[str, ...], *,
    owner_uid: int, final_gid: int, final_mode: int,
) -> tuple[tuple[int, int, str, tuple[int, ...]], ...]:
    """Open only exact relative components under one already-verified anchor.

    Returns retained child descriptors with parent-fd/entry identity so they
    can be revalidated after reading. The caller owns and closes children.
    Test fixtures supply their own private anchor; production alone opens
    filesystem root. Never accept arbitrary input path text on the public API.
    """
    if (
        type(anchor_fd) is not int or anchor_fd < 0
        or type(components) is not tuple or not components
        or any(type(x) is not str or not x or "/" in x
               or x in (".", "..") for x in components)
        or type(owner_uid) is not int or owner_uid < 0
        or type(final_gid) is not int or final_gid < 0
        or final_mode not in (0o755, 0o750)
    ):
        raise ValueError
    opened: list[tuple[int, int, str, tuple[int, ...]]] = []
    parent = anchor_fd
    try:
        for number, component in enumerate(components):
            final = number == len(components) - 1
            mode = final_mode if final else None
            named = os.stat(component, dir_fd=parent, follow_symlinks=False)
            _require_directory(named, uid=owner_uid,
                               gid=final_gid if final else None,
                               final_mode=mode)
            child = os.open(component, _FLAGS, dir_fd=parent)
            opened_status = os.fstat(child)
            _require_directory(opened_status, uid=owner_uid,
                               gid=final_gid if final else None,
                               final_mode=mode)
            if _snapshot(named) != _snapshot(opened_status):
                os.close(child)
                raise ValueError
            opened.append((child, parent, component, _snapshot(opened_status)))
            parent = child
        return tuple(opened)
    except BaseException:
        for child, _parent, _component, _identity in reversed(opened):
            os.close(child)
        raise


def _revalidate_chains(
    anchor_fd: int,
    chains: tuple[tuple[tuple[int, int, str, tuple[int, ...]], ...], ...],
    anchor_identity: tuple[int, ...],
) -> None:
    """Detect ancestor/leaf substitution or mode/ownership change on every FD."""
    if _snapshot(os.fstat(anchor_fd)) != anchor_identity:
        raise ValueError
    for chain in chains:
        for child, parent, component, original in chain:
            if (
                _snapshot(os.stat(
                    component, dir_fd=parent, follow_symlinks=False,
                )) != original
                or _snapshot(os.fstat(child)) != original
            ):
                raise ValueError


def _read_qualified(
    anchor_fd: int, *, owner_uid: int,
    executor_gid: int, broker_gid: int,
) -> observer.C34MSourceObservation:
    """Collect actual 41 source hashes through four trusted retained chains.

    The caller has already acquired exclusive process lock, qualified stopped
    units, verified original canonical configs and is responsible for keeping
    both the lock and systemd/rootless snapshots stable throughout this call.
    """
    anchor_stat = os.fstat(anchor_fd)
    _require_directory(anchor_stat, uid=owner_uid, gid=None, final_mode=None)
    root_identity = _snapshot(anchor_stat)
    chains: list[tuple[tuple[int, int, str, tuple[int, ...]], ...]] = []
    try:
        for location, gid, mode in (
            (_APP, 0, 0o755),
            (_MODULE, 0, 0o755),
            (_EXECUTOR, executor_gid, 0o750),
            (_BROKER, broker_gid, 0o750),
        ):
            chains.append(_open_chain(
                anchor_fd, location, owner_uid=owner_uid,
                final_gid=gid, final_mode=mode,
            ))
        _revalidate_chains(anchor_fd, tuple(chains), root_identity)
        result = observer.observe_c34m_closed_generation(
            application_fd=chains[0][-1][0],
            executor_configuration_fd=chains[2][-1][0],
            broker_configuration_fd=chains[3][-1][0],
            application_uid=owner_uid,
            application_gid=0,
            configuration_uid=owner_uid,
            executor_gid=executor_gid,
            broker_gid=broker_gid,
        )
        if (
            type(result) is not observer.C34MSourceObservation
            or result.source_digests != _EXPECTED
            or result.pending_stages != ()
        ):
            raise ValueError
        _revalidate_chains(anchor_fd, tuple(chains), root_identity)
        return result
    finally:
        for chain in reversed(chains):
            for child, _parent, _name, _id in reversed(chain):
                os.close(child)


def _qualify_locked() -> C34NRootPredecessorReceipt:
    """Read-only predecessor identity, stopped units and rootless signature."""
    identity = runtime._root_identity()
    units = runtime._service_snapshot()
    rootless = runtime._rootless_runtime_signature()
    executor = read_root_dev_executor_configuration()
    broker = read_root_dev_broker_configuration()
    if (
        executor.reviewed_commit != reference.PREDECESSOR
        or broker.reviewed_commit != reference.PREDECESSOR
        or broker.expected_workflow_sha != reference.C34D_MAIN
        or executor.runtime_configuration_sha256
        != broker.runtime_configuration_sha256
        or executor.ingress_file_sha256 != broker.ingress_file_sha256
    ):
        raise ValueError

    root = os.open("/", _FLAGS)
    try:
        first = _read_qualified(
            root, owner_uid=0, executor_gid=executor.executor_gid,
            broker_gid=broker.broker_gid,
        )
        if (
            read_root_dev_executor_configuration().canonical_bytes()
            != executor.canonical_bytes()
            or read_root_dev_broker_configuration().canonical_bytes()
            != broker.canonical_bytes()
            or runtime._root_identity() != identity
            or runtime._service_snapshot() != units
            or runtime._rootless_runtime_signature() != rootless
        ):
            raise ValueError
        second = _read_qualified(
            root, owner_uid=0, executor_gid=executor.executor_gid,
            broker_gid=broker.broker_gid,
        )
        if (
            second != first
            or runtime._root_identity() != identity
            or runtime._service_snapshot() != units
            or runtime._rootless_runtime_signature() != rootless
        ):
            raise ValueError
    finally:
        os.close(root)

    return C34NRootPredecessorReceipt(
        source_reviewed_commit=reference.PREDECESSOR,
        expected_workflow_sha=reference.C34D_MAIN,
        protected_files=41,
        no_pending_stage=True,
        stopped_units_verified=True,
        rootless_runtime_preserved=True,
        migration_ready=False,
    )


def qualify_c34n_root_predecessor() -> C34NRootPredecessorReceipt:
    """Root-only, locked read-only qualification; never stop or mutate services.

    The currently running DEV server should FAIL this stopped-service gate;
    operators must not run it as a workaround to incident #182.
    """
    lock = None
    receipt = None
    failed = False
    control = None
    try:
        runtime._root_identity()
        lock = orchestration._acquire_process_lock()
        if type(lock) is not orchestration._ProcessLock:
            raise ValueError
        receipt = _qualify_locked()
    except _CONTROL as e:
        control = e
    except Exception:
        failed = True
    finally:
        if lock is not None:
            try:
                orchestration._release_process_lock(lock)
            except _CONTROL as e:
                control = control or e
            except Exception:
                failed = True
    if control is not None:
        raise control
    if failed or type(receipt) is not C34NRootPredecessorReceipt:
        raise C34NRootPredecessorError(_ERROR) from None
    return receipt


__all__ = (
    "C34NRootPredecessorError",
    "C34NRootPredecessorReceipt",
    "qualify_c34n_root_predecessor",
)
