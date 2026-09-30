"""deployment/successor_host_migration_runtime.py - root-only C32ZM migration.

The runtime consumes C32ZJ ordering and C32ZL preflight authority. It can only
replace the pinned rootless runtime adapter, then executor configuration, then
broker configuration. It never installs Docker, starts/enables services, alters
Tailscale/ingress, or changes authentication/token handling. Every publication
uses the already-reviewed prefix-resumable fsync + atomic-replace primitive.

Related: successor_host_migration_authority.py,
successor_host_migration_qualification.py, dev_post_c31_application_update.py.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat

from . import broker_service_config as broker_config
from . import dev_host_provisioning_mechanics as mechanics
from . import dev_host_provisioning_orchestration as orchestration
from . import dev_post_c31_application_update as stage_tools
from . import executor_service_config as executor_config
from . import final_application_generation as c32w
from . import successor_application_generation as generation
from .identity import validate_expected_workflow_sha
from .root_broker_configuration_reader import read_root_dev_broker_configuration
from .root_executor_configuration_reader import read_root_dev_executor_configuration
from .successor_host_migration_authority import DevSuccessorHostMigrationAuthority
from .successor_host_migration_qualification import (
    SuccessorHostMigrationQualificationEvidence,
    _authority,
    _root_identity,
    _systemd_snapshot,
    qualify_successor_host_migration,
)


__all__ = (
    "SuccessorHostMigrationRuntimeError",
    "SuccessorHostMigrationRuntimeState",
    "qualify_successor_host_migration_runtime",
    "migrate_successor_host",
)

_ERROR = "successor DEV host migration runtime is unavailable"
_APP_ROOT = "/opt/omnilyzer/deployment/app"
_EXECUTOR_CONFIG = executor_config.PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH
_BROKER_CONFIG = broker_config.PRODUCTION_BROKER_SERVICE_CONFIG_PATH
_APP_UID = 0
_APP_GID = 0
_CONFIG_UID = 0
_APP_STAGE = ".omnilyzer-c32zm-application.tmp"
_EXECUTOR_STAGE = ".omnilyzer-c32zm-executor.tmp"
_BROKER_STAGE = ".omnilyzer-c32zm-broker.tmp"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_MAX_STEPS = 4
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class SuccessorHostMigrationRuntimeError(Exception):
    """One fixed external failure for qualification or migration."""

@dataclass(frozen=True, slots=True)
class SuccessorHostMigrationRuntimeState:
    """One exact clean or prefix-staged C32ZJ migration state."""

    phase: str
    next_operation: str
    application_stage_length: int | None
    executor_stage_length: int | None
    broker_stage_length: int | None
    expected_workflow_sha: str

    def __post_init__(self) -> None:
        """Accept only the stage corresponding to the next C32ZJ operation."""

        stages = (
            self.application_stage_length,
            self.executor_stage_length,
            self.broker_stage_length,
        )
        if (
            type(self.phase) is not str
            or type(self.next_operation) is not str
            or type(self.expected_workflow_sha) is not str
            or any(
                value is not None
                and (type(value) is not int or value < 0)
                for value in stages
            )
        ):
            raise ValueError(_ERROR)
        try:
            validate_expected_workflow_sha(self.expected_workflow_sha)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None
        allowed = {
            "c32w": ("replace-application", (True, False, False)),
            "application": (
                "replace-executor-configuration",
                (False, True, False),
            ),
            "executor": (
                "replace-broker-configuration",
                (False, False, True),
            ),
            "complete": ("complete", (False, False, False)),
        }
        if self.phase not in allowed:
            raise ValueError(_ERROR)
        operation, permitted = allowed[self.phase]
        present = tuple(value is not None for value in stages)
        if (
            self.next_operation != operation
            or any(flag and not allow for flag, allow in zip(present, permitted, strict=True))
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class _Inspection:
    state: SuccessorHostMigrationRuntimeState
    executor: executor_config.DevExecutorServiceConfiguration
    broker: broker_config.DevBrokerServiceConfiguration
    authority: DevSuccessorHostMigrationAuthority
    application_stage: tuple[int, int, tuple[int, ...]] | None
    executor_stage: tuple[int, int, tuple[int, ...]] | None
    broker_stage: tuple[int, int, tuple[int, ...]] | None


def _application_evidence():
    """Return exact C32W/C32ZH manifests and the pinned successor adapter bytes."""

    predecessor, _ = c32w._reviewed_target()
    target, target_blobs = generation._reviewed_target()
    blobs = dict(target_blobs)
    payload = blobs.get("deployment/docker_runtime.py")
    if (
        type(payload) is not bytes
        or not payload
        or predecessor.reviewed_commit != generation.PREDECESSOR_REVIEWED_COMMIT
        or target.reviewed_commit != generation.TARGET_REVIEWED_COMMIT
    ):
        raise OSError
    return predecessor, target, payload

def _application_state():
    """Verify C32W/C32ZH application bytes and an optional exact app stage."""

    predecessor, target, payload = _application_evidence()
    owned: list[int] = []
    try:
        root, chain = mechanics._open_directory(_APP_ROOT, owned)
        root_status = os.fstat(root)
        if (
            stat.S_IMODE(root_status.st_mode) != 0o755
            or (root_status.st_uid, root_status.st_gid) != (_APP_UID, _APP_GID)
        ):
            raise OSError
        directory = mechanics._claim(
            os.open("deployment", _DIRECTORY_FLAGS, dir_fd=root),
            owned,
        )
        directory_status = os.fstat(directory)
        if (
            not stat.S_ISDIR(directory_status.st_mode)
            or stat.S_IMODE(directory_status.st_mode) != 0o755
            or (directory_status.st_uid, directory_status.st_gid)
            != (_APP_UID, _APP_GID)
            or mechanics._directory_fingerprint(directory_status)
            != mechanics._directory_fingerprint(
                os.stat("deployment", dir_fd=root, follow_symlinks=False)
            )
        ):
            raise OSError
        stage = stage_tools._stage(
            directory, _APP_STAGE, payload, 0o644, _APP_UID, _APP_GID,
        )
        if stage is not None:
            mechanics._verify_application(
                root,
                predecessor,
                _APP_UID,
                _APP_GID,
                ("deployment/" + _APP_STAGE, stage[2]),
            )
            digest = generation.PREDECESSOR_DOCKER_SHA256
        else:
            try:
                mechanics._verify_application(
                    root, target, _APP_UID, _APP_GID,
                )
                digest = generation.TARGET_DOCKER_SHA256
            except OSError:
                mechanics._verify_application(
                    root, predecessor, _APP_UID, _APP_GID,
                )
                digest = generation.PREDECESSOR_DOCKER_SHA256
        mechanics._revalidate_chain(chain)
        return digest, stage
    finally:
        mechanics._finish_close(owned)


def _configuration_limit(path: str, stage_name: str) -> int:
    """Return the exact byte ceiling for one fixed configuration destination."""

    if path == _EXECUTOR_CONFIG and stage_name == _EXECUTOR_STAGE:
        return executor_config.MAX_EXECUTOR_SERVICE_CONFIG_BYTES
    if path == _BROKER_CONFIG and stage_name == _BROKER_STAGE:
        return broker_config.MAX_BROKER_SERVICE_CONFIG_BYTES
    raise OSError


def _stage_for_configuration(
    path: str,
    stage_name: str,
    payload: bytes,
    gid: int,
):
    """Inspect one exact resumable configuration stage beside its destination."""

    maximum = _configuration_limit(path, stage_name)
    if type(payload) is not bytes or not 0 < len(payload) <= maximum:
        raise OSError
    owned: list[int] = []
    try:
        parent, _name, chain = mechanics._open_parent(path, owned)
        status = os.fstat(parent)
        if (
            stat.S_IMODE(status.st_mode) != 0o750
            or (status.st_uid, status.st_gid) != (_CONFIG_UID, gid)
        ):
            raise OSError
        stage = stage_tools._stage(
            parent,
            stage_name,
            payload,
            0o640,
            _CONFIG_UID,
            gid,
            0,
        )
        mechanics._revalidate_chain(chain)
        return stage
    finally:
        mechanics._finish_close(owned)

def _inspect() -> _Inspection:
    """Read, normalize and classify one exact clean or staged host prefix."""

    executor = read_root_dev_executor_configuration()
    broker = read_root_dev_broker_configuration()
    authority = _authority(executor, broker)
    successor = authority.successor_pair()
    digest, application_stage = _application_state()
    state = authority.classify(
        application_sha256=digest,
        executor=executor,
        broker=broker,
    )
    executor_stage = _stage_for_configuration(
        _EXECUTOR_CONFIG,
        _EXECUTOR_STAGE,
        successor.executor.canonical_bytes(),
        executor.executor_gid,
    )
    broker_stage = _stage_for_configuration(
        _BROKER_CONFIG,
        _BROKER_STAGE,
        successor.broker.canonical_bytes(),
        broker.broker_gid,
    )
    runtime_state = SuccessorHostMigrationRuntimeState(
        state.phase,
        state.next_operation,
        application_stage[0] if application_stage else None,
        executor_stage[0] if executor_stage else None,
        broker_stage[0] if broker_stage else None,
        broker.expected_workflow_sha,
    )
    return _Inspection(
        runtime_state,
        executor,
        broker,
        authority,
        application_stage,
        executor_stage,
        broker_stage,
    )


def qualify_successor_host_migration_runtime() -> SuccessorHostMigrationRuntimeState:
    """Read-only root qualification that also accepts one exact resumable stage."""

    try:
        identity = _root_identity()
        services = _systemd_snapshot()
        first = _inspect()
        if _root_identity() != identity or _systemd_snapshot() != services:
            raise OSError
        second = _inspect()
        if (
            second.state != first.state
            or second.executor.canonical_bytes() != first.executor.canonical_bytes()
            or second.broker.canonical_bytes() != first.broker.canonical_bytes()
            or _root_identity() != identity
            or _systemd_snapshot() != services
        ):
            raise OSError
        return first.state
    except _CONTROL:
        raise
    except Exception:
        raise SuccessorHostMigrationRuntimeError(_ERROR) from None

def _write_configuration(
    path: str,
    stage_name: str,
    expected: bytes,
    target: bytes,
    gid: int,
    stage,
) -> None:
    """Atomically replace one exact protected canonical configuration file."""

    maximum = _configuration_limit(path, stage_name)
    if (
        type(expected) is not bytes
        or type(target) is not bytes
        or not 0 < len(expected) <= maximum
        or not 0 < len(target) <= maximum
        or type(gid) is not int
        or gid < 0
    ):
        raise OSError
    owned: list[int] = []
    try:
        parent, name, chain = mechanics._open_parent(path, owned)
        parent_status = os.fstat(parent)
        if (
            stat.S_IMODE(parent_status.st_mode) != 0o750
            or (parent_status.st_uid, parent_status.st_gid)
            != (_CONFIG_UID, gid)
        ):
            raise OSError
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = mechanics._claim(
            os.open(name, _FILE_FLAGS, dir_fd=parent),
            owned,
        )
        opened = os.fstat(descriptor)
        if (
            mechanics._fingerprint(named) != mechanics._fingerprint(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_uid, opened.st_gid) != (_CONFIG_UID, gid)
            or stat.S_IMODE(opened.st_mode) != 0o640
            or opened.st_size != len(expected)
        ):
            raise OSError
        content, _digest = mechanics._read_hash(
            descriptor,
            opened.st_size,
            maximum,
        )
        if (
            content != expected
            or mechanics._fingerprint(os.fstat(descriptor))
            != mechanics._fingerprint(opened)
            or mechanics._fingerprint(
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            )
            != mechanics._fingerprint(opened)
        ):
            raise OSError
        checked_stage = stage_tools._stage(
            parent,
            stage_name,
            target,
            0o640,
            _CONFIG_UID,
            gid,
            0,
        )
        if checked_stage != stage:
            raise OSError
        mechanics._revalidate_chain(chain)
        stage_tools._write_replace_stage(
            parent,
            stage_name,
            name,
            target,
            0o640,
            _CONFIG_UID,
            gid,
            stage,
        )
        mechanics._revalidate_chain(chain)
    finally:
        mechanics._finish_close(owned)


def _advance_application(inspection: _Inspection) -> None:
    """Publish the exact C32ZG adapter over the exact C32W adapter."""

    if inspection.state.phase != "c32w":
        raise OSError
    predecessor, _target, payload = _application_evidence()
    owned: list[int] = []
    try:
        root, chain = mechanics._open_directory(_APP_ROOT, owned)
        directory = mechanics._claim(
            os.open("deployment", _DIRECTORY_FLAGS, dir_fd=root),
            owned,
        )
        mechanics._verify_application(
            root,
            predecessor,
            _APP_UID,
            _APP_GID,
            (
                "deployment/" + _APP_STAGE,
                inspection.application_stage[2],
            )
            if inspection.application_stage
            else None,
        )
        checked = stage_tools._stage(
            directory, _APP_STAGE, payload, 0o644, _APP_UID, _APP_GID,
        )
        if checked != inspection.application_stage:
            raise OSError
        mechanics._revalidate_chain(chain)
        stage_tools._write_replace_stage(
            directory,
            _APP_STAGE,
            "docker_runtime.py",
            payload,
            0o644,
            _APP_UID,
            _APP_GID,
            inspection.application_stage,
        )
        mechanics._revalidate_chain(chain)
    finally:
        mechanics._finish_close(owned)

def _advance_executor(inspection: _Inspection) -> None:
    """Publish the successor executor configuration after application switch."""

    if inspection.state.phase != "application":
        raise OSError
    successor = inspection.authority.successor_pair()
    _write_configuration(
        _EXECUTOR_CONFIG,
        _EXECUTOR_STAGE,
        inspection.executor.canonical_bytes(),
        successor.executor.canonical_bytes(),
        inspection.executor.executor_gid,
        inspection.executor_stage,
    )


def _advance_broker(inspection: _Inspection) -> None:
    """Publish the successor broker configuration last, preserving workflow SHA."""

    if inspection.state.phase != "executor":
        raise OSError
    successor = inspection.authority.successor_pair()
    _write_configuration(
        _BROKER_CONFIG,
        _BROKER_STAGE,
        inspection.broker.canonical_bytes(),
        successor.broker.canonical_bytes(),
        inspection.broker.broker_gid,
        inspection.broker_stage,
    )


def _migrate_under_lock() -> SuccessorHostMigrationQualificationEvidence:
    """Advance exact prefixes until the clean successor is fully qualified."""

    identity = _root_identity()
    services = _systemd_snapshot()
    order = {"c32w": 0, "application": 1, "executor": 2, "complete": 3}
    previous_rank = -1
    for _step in range(_MAX_STEPS):
        inspection = _inspect()
        rank = order.get(inspection.state.phase)
        if rank is None or rank < previous_rank:
            raise OSError
        previous_rank = rank
        if _root_identity() != identity or _systemd_snapshot() != services:
            raise OSError
        if inspection.state.phase == "complete":
            if any((
                inspection.application_stage,
                inspection.executor_stage,
                inspection.broker_stage,
            )):
                raise OSError
            evidence = qualify_successor_host_migration()
            if (
                evidence.phase != "complete"
                or evidence.expected_workflow_sha
                != inspection.state.expected_workflow_sha
            ):
                raise OSError
            return evidence
        if inspection.state.phase == "c32w":
            _advance_application(inspection)
        elif inspection.state.phase == "application":
            _advance_executor(inspection)
        elif inspection.state.phase == "executor":
            _advance_broker(inspection)
        else:
            raise OSError
        if _root_identity() != identity or _systemd_snapshot() != services:
            raise OSError
    raise OSError


def migrate_successor_host() -> SuccessorHostMigrationQualificationEvidence:
    """Explicit root-only resumable migration; never installs or activates runtime."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        result = _migrate_under_lock()
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        if lock is not None:
            try:
                orchestration._release_process_lock(lock)
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise SuccessorHostMigrationRuntimeError(_ERROR) from None
    return result
