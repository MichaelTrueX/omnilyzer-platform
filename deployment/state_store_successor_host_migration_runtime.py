"""deployment/state_store_successor_host_migration_runtime.py - root-only C33AE migration steps.

Purpose:
- qualify the closed live state after broker.service and executor.socket stop;
- atomically advance at most one C33AE migration prefix per explicit call;
- preserve inactive deployment services, rootless Docker runtime, pristine
  persistent state, and all unrelated application/config bytes.

Links:
- state_store_successor_host_migration_authority.py owns the pure four-prefix
  state machine;
- state_store_successor_application_generation.py pins the old/new application manifests;
- dev_post_c31_application_update.py supplies the reviewed atomic replace
  primitive;
- state_store_successor_configuration_authority.py derives target configs.

This module never starts/stops/restarts/enables services, invokes Docker
mutations, submits a promotion, changes Tailscale, or retries automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
import stat
import subprocess

from . import broker_service_config as broker_config
from . import dev_host_provisioning_mechanics as mechanics
from . import dev_host_provisioning_orchestration as orchestration
from . import dev_persistent_state_prerequisites as persistent
from . import dev_post_c31_application_update as stage_tools
from . import executor_service_config as executor_config
from . import rootless_docker_fresh_manager_transition as c33t
from . import state_store_successor_configuration_authority as target_configuration
from . import state_store_successor_application_generation as generation
from . import successor_application_generation as predecessor_generation
from .identity import validate_expected_workflow_sha
from .root_broker_configuration_reader import read_root_dev_broker_configuration
from .root_executor_configuration_reader import read_root_dev_executor_configuration
from .state_store_successor_host_migration_authority import (
    DevStateStoreSuccessorHostMigrationAuthority,
    PREDECESSOR_WORKFLOW_SHA,
    StateStoreSuccessorHostMigrationState,
)


_ERROR = "C33AE state-store successor host migration runtime is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)

_APP_ROOT = "/opt/omnilyzer/deployment/app"
_EXECUTOR_CONFIG = executor_config.PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH
_BROKER_CONFIG = broker_config.PRODUCTION_BROKER_SERVICE_CONFIG_PATH
_APP_UID = 0
_APP_GID = 0
_CONFIG_UID = 0
_APP_STAGE = ".omnilyzer-c33ae-state-store.tmp"
_EXECUTOR_STAGE = ".omnilyzer-c33ae-executor.tmp"
_BROKER_STAGE = ".omnilyzer-c33ae-broker.tmp"
_EXECUTOR_SOCKET_PATH = "/run/omnilyzer/deployment/executor.sock"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK

_EXPECTED_UNIT_STATES = {
    "omnilyzer-deployment-executor.socket": (
        "loaded",
        "inactive",
        "dead",
        "disabled",
        "no",
    ),
    "omnilyzer-deployment-executor.service": (
        "loaded",
        "inactive",
        "dead",
        "static",
        "no",
    ),
    "omnilyzer-deployment-broker.service": (
        "loaded",
        "inactive",
        "dead",
        "static",
        "no",
    ),
}


class StateStoreSuccessorHostMigrationRuntimeError(Exception):
    """One fixed external failure for C33AE qualification or one-step mutation."""


@dataclass(frozen=True, slots=True)
class StateStoreSuccessorHostMigrationRuntimeState:
    """One exact runtime observation of a clean or prefix-staged C33AE phase."""

    phase: str
    next_operation: str
    application_stage_length: int | None
    executor_stage_length: int | None
    broker_stage_length: int | None
    target_workflow_sha: str

    def __post_init__(self) -> None:
        """Permit a stage only for the currently authorized next operation."""

        stages = (
            self.application_stage_length,
            self.executor_stage_length,
            self.broker_stage_length,
        )
        allowed = {
            "predecessor": ("replace-state-store", (True, False, False)),
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
        if (
            self.phase not in allowed
            or any(
                value is not None
                and (type(value) is not int or value < 0)
                for value in stages
            )
        ):
            raise ValueError(_ERROR)
        try:
            validate_expected_workflow_sha(self.target_workflow_sha)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None
        operation, permitted = allowed[self.phase]
        present = tuple(value is not None for value in stages)
        if (
            self.next_operation != operation
            or any(
                flag and not permit
                for flag, permit in zip(present, permitted, strict=True)
            )
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class _Inspection:
    """Internal exact host/config/application observation used by one call."""

    state: StateStoreSuccessorHostMigrationRuntimeState
    authority_state: StateStoreSuccessorHostMigrationState
    executor: executor_config.DevExecutorServiceConfiguration
    broker: broker_config.DevBrokerServiceConfiguration
    authority: DevStateStoreSuccessorHostMigrationAuthority
    application_stage: tuple[int, int, tuple[int, ...]] | None
    executor_stage: tuple[int, int, tuple[int, ...]] | None
    broker_stage: tuple[int, int, tuple[int, ...]] | None


def _root_identity() -> tuple[int, int]:
    """Require an explicit real/effective root process for host migration."""

    identity = (os.getuid(), os.geteuid())
    groups = (os.getgid(), os.getegid())
    if identity != (0, 0) or groups != (0, 0):
        raise OSError
    return identity


def _systemd_property(unit: str, name: str) -> str:
    """Read one bounded systemd property without changing service state."""

    result = subprocess.run(
        (
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=" + name,
            "--value",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=10.0,
        env={
            "PATH": "/usr/bin:/usr/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": "/root",
        },
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > 4096:
        raise OSError
    return result.stdout.decode("utf-8", "strict").strip()


def _service_snapshot() -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Require broker, executor service, and executor socket fully inactive."""

    observed: list[tuple[str, tuple[str, ...]]] = []
    for unit, expected in _EXPECTED_UNIT_STATES.items():
        state = tuple(
            _systemd_property(unit, name)
            for name in (
                "LoadState",
                "ActiveState",
                "SubState",
                "UnitFileState",
                "NeedDaemonReload",
            )
        )
        if state != expected:
            raise OSError
        observed.append((unit, state))

    if _systemd_property(
        "omnilyzer-deployment-executor.service",
        "MainPID",
    ) not in {"", "0"}:
        raise OSError
    if _systemd_property(
        "omnilyzer-deployment-broker.service",
        "MainPID",
    ) not in {"", "0"}:
        raise OSError
    if (
        os.path.exists(_EXECUTOR_SOCKET_PATH)
        or os.path.islink(_EXECUTOR_SOCKET_PATH)
    ):
        raise OSError
    return tuple(observed)


def _rootless_runtime_signature() -> tuple[
    int,
    int,
    tuple[tuple[str, int], ...],
]:
    """Qualify and return stable rootless manager/unit/runtime identities."""

    manager_state, manager_pid, user_runtime_state = c33t.c33q._user_manager_state()
    unit_state, _fragment, rootless_unit_pid = c33t._user_unit_evidence(
        c33t._AFTER_UNIT_STATE
    )
    runtime_pids = c33t._runtime_pids(rootless_unit_pid)
    if (
        manager_state != ("loaded", "active", "running", "static")
        or user_runtime_state != ("loaded", "active", "exited")
        or unit_state != c33t._AFTER_UNIT_STATE
        or manager_pid <= 0
        or rootless_unit_pid <= 0
    ):
        raise OSError

    c33t.persistence._global_enable_evidence()
    c33t.persistence._enable_link_evidence()
    c33t.c33q._boot_activation_contract()
    c33t.c33q._linger_state()
    c33t.c33f._socket_evidence()
    c33t.c33f._rootlesskit_state_evidence()
    c33t.c33f._runtime_artifacts_exact()
    c33t.c33f._docker_info_evidence()
    c33t.c33f._require_rootful_masks()
    c33t._uid_process_cgroup_boundary(manager_pid, runtime_pids)
    return manager_pid, rootless_unit_pid, runtime_pids


def _persistent_state(
    configuration: executor_config.DevExecutorServiceConfiguration,
) -> tuple[tuple[str, str], ...]:
    """Require initial state, validated replay, and pristine audit history."""

    result = persistent.DevPersistentStatePrerequisites(
        configuration=configuration
    ).verify_persistent_prerequisites()
    observed = tuple((item.kind, item.outcome) for item in result)
    expected = (
        ("deployment_state", "verified-initial"),
        ("replay_database", "verified"),
        ("audit_history", "pristine"),
    )
    if observed != expected:
        raise OSError
    return observed


def _application_evidence():
    """Return predecessor/target manifests and exact target state-store bytes."""

    predecessor, predecessor_blobs = predecessor_generation._reviewed_target()
    target, target_blobs = generation._reviewed_target()
    payload = dict(target_blobs).get("deployment/state_store.py")
    if (
        predecessor.reviewed_commit != generation.PREDECESSOR_REVIEWED_COMMIT
        or target.reviewed_commit != generation.TARGET_REVIEWED_COMMIT
        or type(payload) is not bytes
        or not payload
        or tuple(path for path, _raw in predecessor_blobs)
        != tuple(path for path, _raw in target_blobs)
    ):
        raise OSError
    return predecessor, target, payload


def _application_state() -> tuple[
    str,
    tuple[int, int, tuple[int, ...]] | None,
]:
    """Verify exact predecessor/target app bytes and an optional target stage."""

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
            directory,
            _APP_STAGE,
            payload,
            0o644,
            _APP_UID,
            _APP_GID,
        )
        if stage is not None:
            mechanics._verify_application(
                root,
                predecessor,
                _APP_UID,
                _APP_GID,
                ("deployment/" + _APP_STAGE, stage[2]),
            )
            commit = generation.PREDECESSOR_REVIEWED_COMMIT
        else:
            try:
                mechanics._verify_application(
                    root,
                    target,
                    _APP_UID,
                    _APP_GID,
                )
                commit = generation.TARGET_REVIEWED_COMMIT
            except OSError:
                mechanics._verify_application(
                    root,
                    predecessor,
                    _APP_UID,
                    _APP_GID,
                )
                commit = generation.PREDECESSOR_REVIEWED_COMMIT

        if stage_tools._stage(
            directory,
            _APP_STAGE,
            payload,
            0o644,
            _APP_UID,
            _APP_GID,
        ) != stage:
            raise OSError
        mechanics._revalidate_chain(chain)
        return commit, stage
    finally:
        mechanics._finish_close(owned)


def _configuration_limit(path: str, stage_name: str) -> int:
    """Return the exact byte ceiling for one protected configuration target."""

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


def _authority(
    executor: executor_config.DevExecutorServiceConfiguration,
    broker: broker_config.DevBrokerServiceConfiguration,
    target_workflow_sha: str,
) -> DevStateStoreSuccessorHostMigrationAuthority:
    """Reconstruct the fixed predecessor from either admitted executor phase."""

    if executor.reviewed_commit == generation.PREDECESSOR_REVIEWED_COMMIT:
        predecessor_executor = target_configuration._predecessor(executor)
    elif executor.reviewed_commit == generation.TARGET_REVIEWED_COMMIT:
        predecessor_executor = target_configuration._predecessor(
            replace(
                executor,
                reviewed_commit=generation.PREDECESSOR_REVIEWED_COMMIT,
            )
        )
    else:
        raise OSError

    predecessor_broker = target_configuration._predecessor_broker(
        predecessor_executor,
        PREDECESSOR_WORKFLOW_SHA,
    )
    return DevStateStoreSuccessorHostMigrationAuthority(
        predecessor_executor=predecessor_executor,
        predecessor_broker=predecessor_broker,
        target_workflow_sha=target_workflow_sha,
    )


def _inspect(target_workflow_sha: str) -> _Inspection:
    """Read, normalize, and classify one exact clean or staged migration prefix."""

    executor = read_root_dev_executor_configuration()
    broker = read_root_dev_broker_configuration()
    authority = _authority(executor, broker, target_workflow_sha)
    target = authority.target_pair()

    application_commit, application_stage = _application_state()
    authority_state = authority.classify(
        application_reviewed_commit=application_commit,
        executor=executor,
        broker=broker,
    )
    executor_stage = _stage_for_configuration(
        _EXECUTOR_CONFIG,
        _EXECUTOR_STAGE,
        target.executor.canonical_bytes(),
        executor.executor_gid,
    )
    broker_stage = _stage_for_configuration(
        _BROKER_CONFIG,
        _BROKER_STAGE,
        target.broker.canonical_bytes(),
        broker.broker_gid,
    )

    state = StateStoreSuccessorHostMigrationRuntimeState(
        phase=authority_state.phase,
        next_operation=authority_state.next_operation,
        application_stage_length=(
            application_stage[0] if application_stage else None
        ),
        executor_stage_length=executor_stage[0] if executor_stage else None,
        broker_stage_length=broker_stage[0] if broker_stage else None,
        target_workflow_sha=target_workflow_sha,
    )
    return _Inspection(
        state,
        authority_state,
        executor,
        broker,
        authority,
        application_stage,
        executor_stage,
        broker_stage,
    )


def qualify_state_store_successor_host_migration_runtime(
    *,
    target_workflow_sha: str,
) -> StateStoreSuccessorHostMigrationRuntimeState:
    """Read-only prove one stable prefix with broker and executor socket closed."""

    try:
        identity = _root_identity()
        services = _service_snapshot()
        rootless = _rootless_runtime_signature()
        first = _inspect(target_workflow_sha)
        _persistent_state(first.executor)

        if (
            _root_identity() != identity
            or _service_snapshot() != services
            or _rootless_runtime_signature() != rootless
        ):
            raise OSError

        second = _inspect(target_workflow_sha)
        _persistent_state(second.executor)
        if (
            second.state != first.state
            or second.executor.canonical_bytes()
            != first.executor.canonical_bytes()
            or second.broker.canonical_bytes()
            != first.broker.canonical_bytes()
            or _root_identity() != identity
            or _service_snapshot() != services
            or _rootless_runtime_signature() != rootless
        ):
            raise OSError
        return first.state
    except _CONTROL:
        raise
    except Exception:
        raise StateStoreSuccessorHostMigrationRuntimeError(_ERROR) from None


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
    """Replace only state_store.py over the exact predecessor application."""

    if inspection.state.phase != "predecessor":
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
        if stage_tools._stage(
            directory,
            _APP_STAGE,
            payload,
            0o644,
            _APP_UID,
            _APP_GID,
        ) != inspection.application_stage:
            raise OSError
        mechanics._revalidate_chain(chain)
        stage_tools._write_replace_stage(
            directory,
            _APP_STAGE,
            "state_store.py",
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
    """Replace only the executor configuration after application migration."""

    if inspection.state.phase != "application":
        raise OSError
    target = inspection.authority.target_pair()
    _write_configuration(
        _EXECUTOR_CONFIG,
        _EXECUTOR_STAGE,
        inspection.executor.canonical_bytes(),
        target.executor.canonical_bytes(),
        inspection.executor.executor_gid,
        inspection.executor_stage,
    )


def _advance_broker(inspection: _Inspection) -> None:
    """Replace only the broker configuration and bind final workflow authority."""

    if inspection.state.phase != "executor":
        raise OSError
    target = inspection.authority.target_pair()
    _write_configuration(
        _BROKER_CONFIG,
        _BROKER_STAGE,
        inspection.broker.canonical_bytes(),
        target.broker.canonical_bytes(),
        inspection.broker.broker_gid,
        inspection.broker_stage,
    )


def _migrate_under_lock(
    *,
    target_workflow_sha: str,
) -> StateStoreSuccessorHostMigrationRuntimeState:
    """Advance at most one reviewed prefix while the process lock is held."""

    identity = _root_identity()
    services = _service_snapshot()
    rootless = _rootless_runtime_signature()
    before = _inspect(target_workflow_sha)
    _persistent_state(before.executor)

    if before.state.phase == "complete":
        if (
            _root_identity() != identity
            or _service_snapshot() != services
            or _rootless_runtime_signature() != rootless
        ):
            raise OSError
        after = _inspect(target_workflow_sha)
        _persistent_state(after.executor)
        if after.state != before.state:
            raise OSError
        return before.state

    if before.state.phase == "predecessor":
        _advance_application(before)
        expected_phase = "application"
    elif before.state.phase == "application":
        _advance_executor(before)
        expected_phase = "executor"
    elif before.state.phase == "executor":
        _advance_broker(before)
        expected_phase = "complete"
    else:
        raise OSError

    if (
        _root_identity() != identity
        or _service_snapshot() != services
        or _rootless_runtime_signature() != rootless
    ):
        raise OSError

    after = _inspect(target_workflow_sha)
    _persistent_state(after.executor)
    if after.state.phase != expected_phase:
        raise OSError
    if (
        _root_identity() != identity
        or _service_snapshot() != services
        or _rootless_runtime_signature() != rootless
    ):
        raise OSError
    return after.state


def migrate_state_store_successor_host_step(
    *,
    target_workflow_sha: str,
) -> StateStoreSuccessorHostMigrationRuntimeState:
    """Root-only one-prefix migration under the existing deployment process lock."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        validate_expected_workflow_sha(target_workflow_sha)
        lock = orchestration._acquire_process_lock()
        result = _migrate_under_lock(
            target_workflow_sha=target_workflow_sha,
        )
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
        raise StateStoreSuccessorHostMigrationRuntimeError(_ERROR) from None
    return result
