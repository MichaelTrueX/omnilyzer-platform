"""deployment/state_store_successor_host_migration_authority.py - pure C33AE migration state machine.

Purpose:
- define the only accepted prefix order for moving the live DEV application and
  executor/broker configuration from the installed C32ZH authority to C33AC;
- preserve the current C33W workflow SHA in the predecessor broker;
- bind the target broker to one explicit final workflow SHA.

Links:
- state_store_successor_application_generation.py pins old/new application commits;
- state_store_successor_configuration_authority.py derives target configs;
- state_store_successor_configuration_authority.py reconstructs the exact
  installed predecessor without relying on Python class identity.

This module is pure and inert. It performs no filesystem, network, Docker,
systemd, registry, process, or deployment I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import broker_service_config as broker_config
from . import executor_service_config as executor_config
from .identity import validate_expected_workflow_sha
from . import state_store_successor_configuration_authority as configuration_authority
from .state_store_successor_application_generation import (
    PREDECESSOR_REVIEWED_COMMIT,
    TARGET_REVIEWED_COMMIT,
)


PREDECESSOR_WORKFLOW_SHA = "48f1280302f85cb8db1af9bb25f1ab15382ae8cb"
_ERROR = "C33AE state-store successor host migration authority is invalid"
_PHASES = (
    ("predecessor", "replace-state-store"),
    ("application", "replace-executor-configuration"),
    ("executor", "replace-broker-configuration"),
    ("complete", "complete"),
)


@dataclass(frozen=True, slots=True)
class StateStoreSuccessorHostMigrationState:
    """One exact accepted prefix of the C33AC host migration."""

    phase: str
    next_operation: str
    application_reviewed_commit: str
    executor_reviewed_commit: str
    broker_reviewed_commit: str
    broker_expected_workflow_sha: str
    target_workflow_sha: str

    def __post_init__(self) -> None:
        """Reject malformed phase, commit, operation, or workflow evidence."""

        allowed = dict(_PHASES)
        if (
            self.phase not in allowed
            or self.next_operation != allowed[self.phase]
            or self.application_reviewed_commit
            not in {PREDECESSOR_REVIEWED_COMMIT, TARGET_REVIEWED_COMMIT}
            or self.executor_reviewed_commit
            not in {PREDECESSOR_REVIEWED_COMMIT, TARGET_REVIEWED_COMMIT}
            or self.broker_reviewed_commit
            not in {PREDECESSOR_REVIEWED_COMMIT, TARGET_REVIEWED_COMMIT}
        ):
            raise ValueError(_ERROR)
        try:
            validate_expected_workflow_sha(self.broker_expected_workflow_sha)
            validate_expected_workflow_sha(self.target_workflow_sha)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None


@dataclass(frozen=True, slots=True, kw_only=True)
class DevStateStoreSuccessorHostMigrationAuthority:
    """Bind one exact installed predecessor to one explicit C33AE target."""

    predecessor_executor: executor_config.DevExecutorServiceConfiguration
    predecessor_broker: broker_config.DevBrokerServiceConfiguration
    target_workflow_sha: str

    def __post_init__(self) -> None:
        """Reconstruct the exact predecessor and validate target workflow input."""

        try:
            validate_expected_workflow_sha(self.target_workflow_sha)
            if self.target_workflow_sha == PREDECESSOR_WORKFLOW_SHA:
                raise ValueError
            executor = configuration_authority._predecessor(
                self.predecessor_executor
            )
            broker = broker_config.DevBrokerServiceConfiguration.from_dict(
                self.predecessor_broker.to_dict()
            )
            expected_broker = configuration_authority._predecessor_broker(
                executor,
                PREDECESSOR_WORKFLOW_SHA,
            )
            if broker.canonical_bytes() != expected_broker.canonical_bytes():
                raise ValueError
            object.__setattr__(self, "predecessor_executor", executor)
            object.__setattr__(self, "predecessor_broker", broker)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def target_pair(self):
        """Return the exact C33AC executor/broker pair for target workflow SHA."""

        try:
            return configuration_authority.DevStateStoreSuccessorConfigurationAuthority(
                predecessor_configuration=self.predecessor_executor
            ).configuration_pair(
                expected_workflow_sha=self.target_workflow_sha,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def classify(
        self,
        *,
        application_reviewed_commit: str,
        executor: executor_config.DevExecutorServiceConfiguration,
        broker: broker_config.DevBrokerServiceConfiguration,
    ) -> StateStoreSuccessorHostMigrationState:
        """Classify only the four exact resumable migration prefixes."""

        try:
            if application_reviewed_commit not in {
                PREDECESSOR_REVIEWED_COMMIT,
                TARGET_REVIEWED_COMMIT,
            }:
                raise ValueError
            if type(executor) is not executor_config.DevExecutorServiceConfiguration:
                raise TypeError
            if type(broker) is not broker_config.DevBrokerServiceConfiguration:
                raise TypeError

            current_executor = executor_config.DevExecutorServiceConfiguration.from_dict(
                executor.to_dict()
            )
            current_broker = broker_config.DevBrokerServiceConfiguration.from_dict(
                broker.to_dict()
            )
            target = self.target_pair()

            old_executor = self.predecessor_executor.canonical_bytes()
            old_broker = self.predecessor_broker.canonical_bytes()
            new_executor = target.executor.canonical_bytes()
            new_broker = target.broker.canonical_bytes()
            actual_executor = current_executor.canonical_bytes()
            actual_broker = current_broker.canonical_bytes()

            if (
                application_reviewed_commit == PREDECESSOR_REVIEWED_COMMIT
                and actual_executor == old_executor
                and actual_broker == old_broker
            ):
                phase, operation = _PHASES[0]
            elif (
                application_reviewed_commit == TARGET_REVIEWED_COMMIT
                and actual_executor == old_executor
                and actual_broker == old_broker
            ):
                phase, operation = _PHASES[1]
            elif (
                application_reviewed_commit == TARGET_REVIEWED_COMMIT
                and actual_executor == new_executor
                and actual_broker == old_broker
            ):
                phase, operation = _PHASES[2]
            elif (
                application_reviewed_commit == TARGET_REVIEWED_COMMIT
                and actual_executor == new_executor
                and actual_broker == new_broker
            ):
                phase, operation = _PHASES[3]
            else:
                raise ValueError

            return StateStoreSuccessorHostMigrationState(
                phase=phase,
                next_operation=operation,
                application_reviewed_commit=application_reviewed_commit,
                executor_reviewed_commit=current_executor.reviewed_commit,
                broker_reviewed_commit=current_broker.reviewed_commit,
                broker_expected_workflow_sha=current_broker.expected_workflow_sha,
                target_workflow_sha=self.target_workflow_sha,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None
