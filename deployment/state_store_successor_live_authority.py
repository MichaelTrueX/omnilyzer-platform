"""deployment/state_store_successor_live_authority.py - C33AQ live workflow authority.

Purpose:
- qualify the installed C33AE-complete DEV executor/broker authority for one
  explicit GitHub workflow SHA;
- rotate only the broker configuration field expected_workflow_sha after a
  repository-only workflow change moves main to a new commit;
- keep the target application generation, persistent state, rootless Docker
  runtime, broker resources, and service files unchanged.

Links:
- state_store_successor_configuration_authority.py defines the target executor
  and broker configuration pair for application generation f2ece425...;
- state_store_successor_host_migration_runtime.py supplies the public,
  read-only C33AE complete-state qualifier and rootless continuity checks;
- dev_final_broker_resources.py supplies the existing protected atomic broker
  configuration replacement primitive;
- dev_host_provisioning_orchestration.py supplies the deployment process lock.

This module never starts, stops, restarts, enables, or reloads services. It
never invokes Docker and never submits a promotion. Rotation is a root-only,
one-shot operation. Failure after publication is not automatically retried or
rolled back; callers must qualify the resulting state before any next action.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib

from . import dev_final_broker_resources as resources
from . import dev_host_provisioning_orchestration as orchestration
from . import state_store_successor_host_migration_runtime as migration
from .broker_host_service_contract import DevBrokerHostServiceContract
from .root_broker_configuration_reader import read_root_dev_broker_configuration
from .root_executor_configuration_reader import read_root_dev_executor_configuration
from .state_store_successor_application_generation import TARGET_REVIEWED_COMMIT
from . import state_store_successor_configuration_authority as successor_config


__all__ = (
    "StateStoreSuccessorWorkflowAuthorityError",
    "StateStoreSuccessorWorkflowAuthorityEvidence",
    "StateStoreSuccessorWorkflowRotationEvidence",
    "qualify_state_store_successor_workflow_authority",
    "rotate_state_store_successor_workflow_authority",
)

_ERROR = "C33AQ state-store successor workflow authority is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_RUNTIME_NAMES = ("rootlesskit", "dockerd", "containerd", "slirp4netns")


class StateStoreSuccessorWorkflowAuthorityError(Exception):
    """Expose one fixed public failure for C33AQ authority operations."""


def _workflow_sha(value: object) -> bool:
    """Accept one nonzero lowercase forty-character Git commit SHA."""

    return (
        type(value) is str
        and len(value) == 40
        and value != "0" * 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _runtime_signature() -> tuple[int, int, tuple[tuple[str, int], ...]]:
    """Return one revalidated C33AE rootless Docker runtime signature."""

    value = migration._rootless_runtime_signature()
    if (
        type(value) is not tuple
        or len(value) != 3
        or type(value[0]) is not int
        or value[0] <= 0
        or type(value[1]) is not int
        or value[1] <= 0
        or type(value[2]) is not tuple
        or tuple(name for name, _pid in value[2]) != _RUNTIME_NAMES
        or any(type(pid) is not int or pid <= 0 for _name, pid in value[2])
        or len({pid for _name, pid in value[2]}) != 4
    ):
        raise OSError
    return value


def _installed_pair(
    expected_workflow_sha: str,
) -> successor_config.DevStateStoreSuccessorConfigurationPair:
    """Reconstruct and validate the exact installed target-generation pair."""

    if not _workflow_sha(expected_workflow_sha):
        raise OSError

    executor = read_root_dev_executor_configuration()
    broker = read_root_dev_broker_configuration()
    if (
        executor.reviewed_commit != TARGET_REVIEWED_COMMIT
        or broker.reviewed_commit != TARGET_REVIEWED_COMMIT
        or broker.expected_workflow_sha != expected_workflow_sha
    ):
        raise OSError

    pair = successor_config.DevStateStoreSuccessorConfigurationPair(
        executor=executor,
        broker=broker,
    )
    pair.__post_init__()
    if (
        pair.executor.canonical_bytes() != executor.canonical_bytes()
        or pair.broker.canonical_bytes() != broker.canonical_bytes()
    ):
        raise OSError
    return pair


def _project_pair(
    current: successor_config.DevStateStoreSuccessorConfigurationPair,
    new_expected_workflow_sha: str,
) -> successor_config.DevStateStoreSuccessorConfigurationPair:
    """Project only expected_workflow_sha from one exact installed pair."""

    if (
        type(current) is not successor_config.DevStateStoreSuccessorConfigurationPair
        or not _workflow_sha(new_expected_workflow_sha)
        or current.broker.expected_workflow_sha == new_expected_workflow_sha
    ):
        raise OSError

    projected = successor_config.DevStateStoreSuccessorConfigurationPair(
        executor=current.executor,
        broker=replace(
            current.broker,
            expected_workflow_sha=new_expected_workflow_sha,
        ),
    )
    before = current.broker.to_dict()
    after = projected.broker.to_dict()
    if (
        current.executor.canonical_bytes()
        != projected.executor.canonical_bytes()
        or before.keys() != after.keys()
        or {key for key in before if before[key] != after[key]}
        != {"expected_workflow_sha"}
    ):
        raise OSError
    return projected


def _resource_qualification(
    pair: successor_config.DevStateStoreSuccessorConfigurationPair,
) -> DevBrokerHostServiceContract:
    """Prove static broker resources against one target-generation pair."""

    if type(pair) is not successor_config.DevStateStoreSuccessorConfigurationPair:
        raise OSError
    pair.__post_init__()

    host = DevBrokerHostServiceContract(configuration=pair.broker)
    directories = resources._authorities(host)
    for item in (
        host.broker_configuration_directory(),
        *host.runtime_directory_requirements(),
    ):
        if not resources._directory_exists(item, directories):
            raise OSError

    config = host.broker_configuration_file()
    payload = host.canonical_configuration_bytes()
    if not resources._file_state(
        config.path,
        config.mode,
        config.owner_uid,
        config.group_gid,
        payload,
        directories,
    ):
        raise OSError

    asset = host.installed_asset_requirement()
    if not resources._installed_unit(
        asset.sha256,
        asset.destination_path,
        asset.mode,
        asset.owner_uid,
        asset.group_gid,
        directories,
    ):
        raise OSError

    resources._replay(host)
    sigstore = resources.sigstore_installer._qualify_installed(pair.broker)
    sigstore.__post_init__()
    return host


@dataclass(frozen=True, slots=True)
class StateStoreSuccessorWorkflowAuthorityEvidence:
    """Digest-only proof of exact installed post-C33AE workflow authority."""

    reviewed_commit: str
    expected_workflow_sha: str
    broker_configuration_sha256: str
    rootless_user_manager_pid: int
    rootless_user_unit_main_pid: int
    rootless_runtime_pids: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        """Reject malformed or non-target evidence."""

        if (
            self.reviewed_commit != TARGET_REVIEWED_COMMIT
            or not _workflow_sha(self.expected_workflow_sha)
            or type(self.broker_configuration_sha256) is not str
            or len(self.broker_configuration_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.broker_configuration_sha256
            )
            or type(self.rootless_user_manager_pid) is not int
            or self.rootless_user_manager_pid <= 0
            or type(self.rootless_user_unit_main_pid) is not int
            or self.rootless_user_unit_main_pid <= 0
            or type(self.rootless_runtime_pids) is not tuple
            or tuple(name for name, _pid in self.rootless_runtime_pids)
            != _RUNTIME_NAMES
            or any(
                type(pid) is not int or pid <= 0
                for _name, pid in self.rootless_runtime_pids
            )
            or len({pid for _name, pid in self.rootless_runtime_pids}) != 4
            or self.rootless_runtime_pids[0][1]
            != self.rootless_user_unit_main_pid
            or self.rootless_user_manager_pid
            in {pid for _name, pid in self.rootless_runtime_pids}
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class StateStoreSuccessorWorkflowRotationEvidence:
    """Proof that one rotation changed only broker workflow authority."""

    reviewed_commit: str
    old_workflow_sha: str
    new_workflow_sha: str
    old_broker_configuration_sha256: str
    new_broker_configuration_sha256: str
    rootless_user_manager_pid: int
    rootless_user_unit_main_pid: int
    rootless_runtime_pids: tuple[tuple[str, int], ...]
    operation: str

    def __post_init__(self) -> None:
        """Require one exact non-idempotent workflow-only transition."""

        if (
            self.reviewed_commit != TARGET_REVIEWED_COMMIT
            or not _workflow_sha(self.old_workflow_sha)
            or not _workflow_sha(self.new_workflow_sha)
            or self.old_workflow_sha == self.new_workflow_sha
            or self.old_broker_configuration_sha256
            == self.new_broker_configuration_sha256
            or self.operation != "rotated"
        ):
            raise ValueError(_ERROR)
        for digest in (
            self.old_broker_configuration_sha256,
            self.new_broker_configuration_sha256,
        ):
            if (
                type(digest) is not str
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ValueError(_ERROR)
        StateStoreSuccessorWorkflowAuthorityEvidence(
            self.reviewed_commit,
            self.new_workflow_sha,
            self.new_broker_configuration_sha256,
            self.rootless_user_manager_pid,
            self.rootless_user_unit_main_pid,
            self.rootless_runtime_pids,
        )


def _qualify(
    expected_workflow_sha: str,
) -> StateStoreSuccessorWorkflowAuthorityEvidence:
    """Read-only proof of one complete, closed C33AE target authority."""

    before_runtime = _runtime_signature()

    state = migration.qualify_state_store_successor_host_migration_runtime(
        target_workflow_sha=expected_workflow_sha,
    )
    if (
        state.phase != "complete"
        or state.next_operation != "complete"
        or state.target_workflow_sha != expected_workflow_sha
        or any(
            value is not None
            for value in (
                state.application_stage_length,
                state.executor_stage_length,
                state.broker_stage_length,
            )
        )
    ):
        raise OSError

    pair = _installed_pair(expected_workflow_sha)
    _resource_qualification(pair)

    after_runtime = _runtime_signature()
    if after_runtime != before_runtime:
        raise OSError

    return StateStoreSuccessorWorkflowAuthorityEvidence(
        reviewed_commit=pair.broker.reviewed_commit,
        expected_workflow_sha=pair.broker.expected_workflow_sha,
        broker_configuration_sha256=hashlib.sha256(
            pair.broker.canonical_bytes()
        ).hexdigest(),
        rootless_user_manager_pid=after_runtime[0],
        rootless_user_unit_main_pid=after_runtime[1],
        rootless_runtime_pids=after_runtime[2],
    )


def qualify_state_store_successor_workflow_authority(
    *,
    expected_workflow_sha: str,
) -> StateStoreSuccessorWorkflowAuthorityEvidence:
    """Public read-only proof of exact post-C33AE broker workflow authority."""

    try:
        if not _workflow_sha(expected_workflow_sha):
            raise OSError
        return _qualify(expected_workflow_sha)
    except _CONTROL:
        raise
    except Exception:
        raise StateStoreSuccessorWorkflowAuthorityError(_ERROR) from None


def _rotate_under_lock(
    current_expected_workflow_sha: str,
    new_expected_workflow_sha: str,
) -> StateStoreSuccessorWorkflowRotationEvidence:
    """Atomically replace only expected_workflow_sha under the process lock."""

    before = _qualify(current_expected_workflow_sha)
    current = _installed_pair(current_expected_workflow_sha)
    projected = _project_pair(current, new_expected_workflow_sha)

    old_host = DevBrokerHostServiceContract(configuration=current.broker)
    new_host = DevBrokerHostServiceContract(configuration=projected.broker)
    if (
        old_host.broker_configuration_file()
        != new_host.broker_configuration_file()
        or old_host.runtime_directory_requirements()
        != new_host.runtime_directory_requirements()
        or old_host.installed_asset_requirement()
        != new_host.installed_asset_requirement()
    ):
        raise OSError

    directories = resources._authorities(old_host)
    config = old_host.broker_configuration_file()
    resources._temporary_absent(config.path, directories)
    resources._replace_workflow_configuration(
        old_host,
        new_host,
        directories,
    )

    after = _qualify(new_expected_workflow_sha)
    if (
        after.reviewed_commit != before.reviewed_commit
        or after.rootless_user_manager_pid != before.rootless_user_manager_pid
        or after.rootless_user_unit_main_pid
        != before.rootless_user_unit_main_pid
        or after.rootless_runtime_pids != before.rootless_runtime_pids
    ):
        raise OSError

    return StateStoreSuccessorWorkflowRotationEvidence(
        reviewed_commit=after.reviewed_commit,
        old_workflow_sha=current_expected_workflow_sha,
        new_workflow_sha=new_expected_workflow_sha,
        old_broker_configuration_sha256=before.broker_configuration_sha256,
        new_broker_configuration_sha256=after.broker_configuration_sha256,
        rootless_user_manager_pid=after.rootless_user_manager_pid,
        rootless_user_unit_main_pid=after.rootless_user_unit_main_pid,
        rootless_runtime_pids=after.rootless_runtime_pids,
        operation="rotated",
    )


def rotate_state_store_successor_workflow_authority(
    *,
    current_expected_workflow_sha: str,
    new_expected_workflow_sha: str,
) -> StateStoreSuccessorWorkflowRotationEvidence:
    """Root-only one-shot C33AQ workflow-authority rotation.

    The function acquires the shared deployment process lock and performs at
    most one broker configuration publication. It never retries or rolls back
    automatically after a publication attempt.
    """

    lock = None
    result = None
    failure = False
    control = None
    try:
        resources._root()
        if (
            not _workflow_sha(current_expected_workflow_sha)
            or not _workflow_sha(new_expected_workflow_sha)
            or current_expected_workflow_sha == new_expected_workflow_sha
        ):
            raise OSError

        lock = orchestration._acquire_process_lock()
        if type(lock) is not orchestration._ProcessLock:
            raise OSError

        result = _rotate_under_lock(
            current_expected_workflow_sha,
            new_expected_workflow_sha,
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
        raise StateStoreSuccessorWorkflowAuthorityError(_ERROR) from None
    return result
