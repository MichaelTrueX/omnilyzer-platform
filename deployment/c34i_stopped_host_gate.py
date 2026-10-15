"""File: deployment/c34i_stopped_host_gate.py

Purpose: Review-only root/stopped-unit qualification and exact C34D
predecessor identity check for a future C34I five-file DEV host migrator.
Related: deployment/c34g_installed_predecessor_preflight.py,
deployment/c34g_migration_authority.py,
deployment/state_store_successor_host_migration_runtime.py,
deployment/dev_host_provisioning_orchestration.py,
deployment/tests/test_c34i_stopped_host_gate.py.

This module has NO file writer, installer or workflow dispatcher.
It cannot stop services; qualification requires an operator to stop them
under independent approval. The proposed C34E draft source SHA is NOT
sufficient to authorize a final merged application generation.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import c34f_application_generation_evidence as evidence
from . import c34g_installed_predecessor_preflight as predecessor
from . import dev_host_provisioning_orchestration as orchestration
from . import state_store_successor_host_migration_runtime as prior_runtime
from .root_broker_configuration_reader import read_root_dev_broker_configuration
from .root_executor_configuration_reader import read_root_dev_executor_configuration


# Section 1: Closed operational invariants; no dynamic deployment target.
_ERROR = "C34I stopped-host transition preconditions unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_BLOCKED_TARGET = evidence.C34E_PROPOSAL


class C34IStoppedHostGateError(Exception):
    """A fixed, nonsecret precondition failure."""


@dataclass(frozen=True, slots=True)
class C34IStoppedHostEvidence:
    """Validated root-only prerequisite receipt, not a deployment capability."""

    predecessor_commit: str
    expected_workflow_sha: str
    protected_file_count: int
    broker_executor_stopped: bool
    rootless_runtime_preserved: bool
    migration_ready: bool

    def __post_init__(self) -> None:
        """Prevent manufacturing an approval flag from a synthetic receipt."""
        if (
            self.predecessor_commit != evidence.PREDECESSOR
            or self.expected_workflow_sha != evidence.C34D_MAIN
            or type(self.protected_file_count) is not int
            or self.protected_file_count != 41
            or self.broker_executor_stopped is not True
            or self.rootless_runtime_preserved is not True
            or self.migration_ready is not False
        ):
            raise ValueError(_ERROR)


def require_final_merge_authority(target_commit: str) -> None:
    """Fail closed until a separately approved final-main binding is implemented.

    The current draft source review is frozen to C34E_PROPOSAL. Actual future
    target manifests embed reviewed_commit and so must be recomputed and
    independently reviewed after merge; passing the draft SHA here is NOT
    enough. This hook intentionally rejects *every* supplied value.
    """
    if type(target_commit) is not str or target_commit == _BLOCKED_TARGET:
        raise C34IStoppedHostGateError(_ERROR)
    raise C34IStoppedHostGateError(_ERROR)


def _qualify_under_lock() -> C34IStoppedHostEvidence:
    """Check stable root-only stopped services, rootless runtime and source.

    The lock has already been acquired. Installed source may be read, never
    written. Reuse the previously reviewed C33AE resource probes only for
    environment evidence, not its historical source-generation migration.
    """
    before_identity = prior_runtime._root_identity()
    before_units = prior_runtime._service_snapshot()
    before_runtime = prior_runtime._rootless_runtime_signature()
    executor = read_root_dev_executor_configuration()
    broker = read_root_dev_broker_configuration()

    # The canonical legacy pair may have passed in an earlier read-only
    # preflight while services were running. Requalify it under the lock.
    predecessor.verify_source()
    predecessor.verify_configs()
    if (
        executor.reviewed_commit != evidence.PREDECESSOR
        or broker.reviewed_commit != evidence.PREDECESSOR
        or broker.expected_workflow_sha != evidence.C34D_MAIN
        or executor.runtime_configuration_sha256
        != broker.runtime_configuration_sha256
        or executor.ingress_file_sha256 != broker.ingress_file_sha256
    ):
        raise ValueError

    # The existing C33AE persistent-state check expects pristine audit state;
    # it must be reviewed against current DEV semantics before reuse here.
    # No new check assumes replay/audit are disposable or can be reset.
    second_executor = read_root_dev_executor_configuration()
    second_broker = read_root_dev_broker_configuration()
    predecessor.verify_source()
    predecessor.verify_configs()
    if (
        second_executor.canonical_bytes() != executor.canonical_bytes()
        or second_broker.canonical_bytes() != broker.canonical_bytes()
        or prior_runtime._root_identity() != before_identity
        or prior_runtime._service_snapshot() != before_units
        or prior_runtime._rootless_runtime_signature() != before_runtime
    ):
        raise ValueError

    return C34IStoppedHostEvidence(
        predecessor_commit=evidence.PREDECESSOR,
        expected_workflow_sha=evidence.C34D_MAIN,
        protected_file_count=41,
        broker_executor_stopped=True,
        rootless_runtime_preserved=True,
        migration_ready=False,
    )


def qualify_c34i_stopped_host_predecessor() -> C34IStoppedHostEvidence:
    """Read-only root qualification under the existing exclusive host lock.

    A passing receipt cannot authorize writing. No service changes occur.
    The lock ensures concurrent deployment operations cannot mutate host
    state while the frozen predecessor is being inspected.
    """
    lock = None
    receipt = None
    failure = False
    control = None
    try:
        prior_runtime._root_identity()
        lock = orchestration._acquire_process_lock()
        if type(lock) is not orchestration._ProcessLock:
            raise ValueError
        receipt = _qualify_under_lock()
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
    if failure or type(receipt) is not C34IStoppedHostEvidence:
        raise C34IStoppedHostGateError(_ERROR) from None
    return receipt


__all__ = (
    "C34IStoppedHostGateError",
    "C34IStoppedHostEvidence",
    "require_final_merge_authority",
    "qualify_c34i_stopped_host_predecessor",
)
