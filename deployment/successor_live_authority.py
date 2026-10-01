"""deployment/successor_live_authority.py - C33V successor pre-activation authority.

Purpose:
- qualify the installed C32ZH/C32ZI successor broker authority without
  reusing historical C32W-only resource qualifiers;
- provide the only reviewed root-only workflow-SHA rotation for the successor
  broker configuration;
- preserve the proven C33T fresh-manager rootless Docker lifecycle and C33U
  complete successor migration while rotating only expected_workflow_sha;
- supersede the two C32W-specific tail checks in the historical C32ZC edge
  qualification plan without rewriting that historical contract.

Links:
- successor_configuration_authority.py defines the successor executor/broker pair.
- successor_host_migration_runtime.py proves the complete successor host prefix
  and binds it to C33T rootless Docker authority.
- dev_final_broker_resources.py supplies already-reviewed generic protected-file
  and installed-resource primitives, but its C32W _pair() is not reused.
- broker_edge_contract.py remains the historical C32ZC edge contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib

from . import broker_edge_contract as historical_edge
from . import dev_final_broker_resources as historical_resources
from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_fresh_manager_transition as c33t
from . import successor_host_migration_runtime as c33u
from .broker_host_service_contract import DevBrokerHostServiceContract
from .root_broker_configuration_reader import read_root_dev_broker_configuration
from .root_executor_configuration_reader import read_root_dev_executor_configuration
from .successor_application_generation import (
    PREDECESSOR_REVIEWED_COMMIT,
    TARGET_REVIEWED_COMMIT,
)
from .successor_configuration_authority import (
    DevSuccessorConfigurationAuthority,
    DevSuccessorConfigurationPair,
)


__all__ = (
    "SuccessorBrokerWorkflowAuthorityError",
    "SuccessorBrokerWorkflowAuthorityEvidence",
    "SuccessorBrokerWorkflowRotationEvidence",
    "SuccessorDevBrokerEdgeQualificationPlan",
    "qualify_successor_broker_workflow_authority",
    "rotate_successor_broker_workflow_authority",
)

_ERROR = "successor DEV broker workflow authority is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_RUNTIME_NAMES = ("rootlesskit", "dockerd", "containerd", "slirp4netns")

_HISTORICAL_CHECKS = historical_edge.DevBrokerEdgeContract().qualification_plan().checks
_SUCCESSOR_CHECKS = tuple(
    (
        "successor-application-authority-exact-and-migration-complete"
        if check == "frozen-c32w-application-authority-unchanged"
        else "successor-static-resource-authority-otherwise-unchanged"
        if check == "c32y-static-resource-authority-otherwise-unchanged"
        else check
    )
    for check in _HISTORICAL_CHECKS
)


class SuccessorBrokerWorkflowAuthorityError(Exception):
    """Expose one fixed failure for successor broker authority operations."""


def _workflow_sha(value: object) -> bool:
    """Accept only one nonzero lowercase 40-character Git commit SHA."""

    return (
        type(value) is str
        and len(value) == 40
        and value != "0" * 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _runtime_pids(
    evidence: c33t.RootlessDockerFreshManagerLifecycleEvidence,
) -> tuple[tuple[str, int], ...]:
    """Return and revalidate the exact four C33T rootless runtime identities."""

    runtime = evidence.runtime_pids
    if (
        type(runtime) is not tuple
        or tuple(name for name, _pid in runtime) != _RUNTIME_NAMES
        or any(type(pid) is not int or pid <= 0 for _name, pid in runtime)
        or len({pid for _name, pid in runtime}) != len(runtime)
    ):
        raise OSError
    return runtime


@dataclass(frozen=True, slots=True)
class SuccessorBrokerWorkflowAuthorityEvidence:
    """Digest-only proof of exact installed successor broker authority."""

    reviewed_commit: str
    expected_workflow_sha: str
    broker_configuration_sha256: str
    rootless_user_manager_pid: int
    rootless_runtime_pids: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        """Reject malformed, predecessor, or incomplete evidence."""

        if (
            type(self.reviewed_commit) is not str
            or self.reviewed_commit != TARGET_REVIEWED_COMMIT
            or not _workflow_sha(self.expected_workflow_sha)
            or type(self.broker_configuration_sha256) is not str
            or len(self.broker_configuration_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.broker_configuration_sha256
            )
            or type(self.rootless_user_manager_pid) is not int
            or self.rootless_user_manager_pid <= 0
        ):
            raise ValueError(_ERROR)
        if (
            type(self.rootless_runtime_pids) is not tuple
            or tuple(name for name, _pid in self.rootless_runtime_pids)
            != _RUNTIME_NAMES
        ):
            raise ValueError(_ERROR)
        if any(
            type(pid) is not int or pid <= 0
            for _name, pid in self.rootless_runtime_pids
        ):
            raise ValueError(_ERROR)
        if len({pid for _name, pid in self.rootless_runtime_pids}) != 4:
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class SuccessorBrokerWorkflowRotationEvidence:
    """Proof that only successor broker workflow authority was replaced."""

    reviewed_commit: str
    old_workflow_sha: str
    new_workflow_sha: str
    old_broker_configuration_sha256: str
    new_broker_configuration_sha256: str
    rootless_user_manager_pid: int
    rootless_runtime_pids: tuple[tuple[str, int], ...]
    operation: str

    def __post_init__(self) -> None:
        """Require one exact non-idempotent workflow-authority transition."""

        if (
            self.reviewed_commit != TARGET_REVIEWED_COMMIT
            or not _workflow_sha(self.old_workflow_sha)
            or not _workflow_sha(self.new_workflow_sha)
            or self.old_workflow_sha == self.new_workflow_sha
            or self.operation != "rotated"
            or self.old_broker_configuration_sha256
            == self.new_broker_configuration_sha256
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
        SuccessorBrokerWorkflowAuthorityEvidence(
            self.reviewed_commit,
            self.new_workflow_sha,
            self.new_broker_configuration_sha256,
            self.rootless_user_manager_pid,
            self.rootless_runtime_pids,
        )


@dataclass(frozen=True, slots=True)
class SuccessorDevBrokerEdgeQualificationPlan:
    """C33V successor-aware continuation of the historical 38 edge checks."""

    status: str = field(init=False, default="pending-live-qualification")
    checks: tuple[str, ...] = field(init=False, default=_SUCCESSOR_CHECKS)

    def __post_init__(self) -> None:
        """Require the exact successor plan and retain the historical check count."""

        if (
            self.status != "pending-live-qualification"
            or type(self.checks) is not tuple
            or self.checks != _SUCCESSOR_CHECKS
            or len(self.checks) != len(_HISTORICAL_CHECKS)
            or len(self.checks) != 38
            or any(type(check) is not str or not check for check in self.checks)
        ):
            raise ValueError(_ERROR)


def _successor_pair(expected_workflow_sha: str) -> DevSuccessorConfigurationPair:
    """Reconstruct exact successor authority from the installed executor."""

    if not _workflow_sha(expected_workflow_sha):
        raise OSError
    installed_executor = read_root_dev_executor_configuration()
    if installed_executor.reviewed_commit != TARGET_REVIEWED_COMMIT:
        raise OSError
    predecessor = replace(
        installed_executor,
        reviewed_commit=PREDECESSOR_REVIEWED_COMMIT,
    )
    authority = DevSuccessorConfigurationAuthority(
        predecessor_configuration=predecessor,
    )
    pair = authority.configuration_pair(
        expected_workflow_sha=expected_workflow_sha,
    )
    if (
        type(pair) is not DevSuccessorConfigurationPair
        or pair.executor.canonical_bytes() != installed_executor.canonical_bytes()
    ):
        raise OSError
    pair.__post_init__()
    return pair


def _resource_qualification(
    pair: DevSuccessorConfigurationPair,
) -> DevBrokerHostServiceContract:
    """Prove installed broker resources against one successor configuration."""

    host = DevBrokerHostServiceContract(configuration=pair.broker)
    directories = historical_resources._authorities(host)
    for item in (
        host.broker_configuration_directory(),
        *host.runtime_directory_requirements(),
    ):
        if not historical_resources._directory_exists(item, directories):
            raise OSError
    config = host.broker_configuration_file()
    payload = host.canonical_configuration_bytes()
    if not historical_resources._file_state(
        config.path,
        config.mode,
        config.owner_uid,
        config.group_gid,
        payload,
        directories,
    ):
        raise OSError
    asset = host.installed_asset_requirement()
    if not historical_resources._installed_unit(
        asset.sha256,
        asset.destination_path,
        asset.mode,
        asset.owner_uid,
        asset.group_gid,
        directories,
    ):
        raise OSError
    historical_resources._replay(host)
    sigstore = historical_resources.sigstore_installer._qualify_installed(
        pair.broker,
    )
    sigstore.__post_init__()
    return host


def _qualify(
    expected_workflow_sha: str,
) -> SuccessorBrokerWorkflowAuthorityEvidence:
    """Prove complete successor authority while C33T runtime remains unchanged."""

    rootless_before = c33t.qualify_rootless_docker_fresh_manager_post()
    signature = c33t._observation_signature(rootless_before)
    runtime = _runtime_pids(rootless_before)

    migration = c33u.qualify_successor_host_migration_runtime()
    if (
        migration.phase != "complete"
        or migration.next_operation != "complete"
        or migration.expected_workflow_sha != expected_workflow_sha
        or any(
            value is not None
            for value in (
                migration.application_stage_length,
                migration.executor_stage_length,
                migration.broker_stage_length,
            )
        )
    ):
        raise OSError

    pair = _successor_pair(expected_workflow_sha)
    installed_broker = read_root_dev_broker_configuration()
    if installed_broker.canonical_bytes() != pair.broker.canonical_bytes():
        raise OSError
    _resource_qualification(pair)

    rootless_after = c33t.qualify_rootless_docker_fresh_manager_post()
    if c33t._observation_signature(rootless_after) != signature:
        raise OSError
    if _runtime_pids(rootless_after) != runtime:
        raise OSError

    return SuccessorBrokerWorkflowAuthorityEvidence(
        reviewed_commit=pair.broker.reviewed_commit,
        expected_workflow_sha=pair.broker.expected_workflow_sha,
        broker_configuration_sha256=hashlib.sha256(
            pair.broker.canonical_bytes(),
        ).hexdigest(),
        rootless_user_manager_pid=rootless_after.user_manager_pid,
        rootless_runtime_pids=runtime,
    )


def qualify_successor_broker_workflow_authority(
    *, expected_workflow_sha: str,
) -> SuccessorBrokerWorkflowAuthorityEvidence:
    """Read-only proof of exact installed successor workflow authority."""

    try:
        if not _workflow_sha(expected_workflow_sha):
            raise OSError
        return _qualify(expected_workflow_sha)
    except _CONTROL:
        raise
    except Exception:
        raise SuccessorBrokerWorkflowAuthorityError(_ERROR) from None


def _rotate_under_lock(
    current_expected_workflow_sha: str,
    new_expected_workflow_sha: str,
) -> SuccessorBrokerWorkflowRotationEvidence:
    """Replace only expected_workflow_sha while all successor gates remain stable."""

    before = _qualify(current_expected_workflow_sha)
    old_pair = _successor_pair(current_expected_workflow_sha)
    new_pair = _successor_pair(new_expected_workflow_sha)

    if (
        old_pair.executor.canonical_bytes() != new_pair.executor.canonical_bytes()
        or old_pair.broker.to_dict().keys() != new_pair.broker.to_dict().keys()
        or {
            key
            for key in old_pair.broker.to_dict()
            if old_pair.broker.to_dict()[key] != new_pair.broker.to_dict()[key]
        }
        != {"expected_workflow_sha"}
    ):
        raise OSError

    old_host = DevBrokerHostServiceContract(configuration=old_pair.broker)
    new_host = DevBrokerHostServiceContract(configuration=new_pair.broker)
    if (
        old_host.broker_configuration_file() != new_host.broker_configuration_file()
        or old_host.runtime_directory_requirements()
        != new_host.runtime_directory_requirements()
        or old_host.installed_asset_requirement()
        != new_host.installed_asset_requirement()
    ):
        raise OSError

    directories = historical_resources._authorities(old_host)
    config = old_host.broker_configuration_file()
    historical_resources._temporary_absent(config.path, directories)
    historical_resources._replace_workflow_configuration(
        old_host,
        new_host,
        directories,
    )

    after = _qualify(new_expected_workflow_sha)
    if (
        after.reviewed_commit != before.reviewed_commit
        or after.rootless_user_manager_pid != before.rootless_user_manager_pid
        or after.rootless_runtime_pids != before.rootless_runtime_pids
    ):
        raise OSError

    return SuccessorBrokerWorkflowRotationEvidence(
        reviewed_commit=after.reviewed_commit,
        old_workflow_sha=current_expected_workflow_sha,
        new_workflow_sha=new_expected_workflow_sha,
        old_broker_configuration_sha256=before.broker_configuration_sha256,
        new_broker_configuration_sha256=after.broker_configuration_sha256,
        rootless_user_manager_pid=after.rootless_user_manager_pid,
        rootless_runtime_pids=after.rootless_runtime_pids,
        operation="rotated",
    )


def rotate_successor_broker_workflow_authority(
    *,
    current_expected_workflow_sha: str,
    new_expected_workflow_sha: str,
) -> SuccessorBrokerWorkflowRotationEvidence:
    """Root-only one-shot successor workflow-authority rotation.

    Failure after publication never triggers automatic rollback or retry. A
    caller must use the read-only qualifier to determine the resulting state.
    """

    lock = None
    result = None
    failure = False
    control = None
    try:
        historical_resources._root()
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
        raise SuccessorBrokerWorkflowAuthorityError(_ERROR) from None
    return result
