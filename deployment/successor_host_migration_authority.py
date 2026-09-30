"""Pure C32ZJ authority for the successor DEV host-migration state machine.

This module defines the only accepted ordering from the frozen C32W host
authority to the C32ZH/C32ZI successor authority. It performs no filesystem,
network, Docker, service, or host mutation. A later root-only implementation
must consume this state machine rather than inventing its own transition order.

Related: final_configuration_authority.py, successor_application_generation.py,
successor_configuration_authority.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from .broker_service_config import DevBrokerServiceConfiguration
from .executor_service_config import DevExecutorServiceConfiguration
from .final_configuration_authority import DevFinalConfigurationPair
from .successor_application_generation import (
    PREDECESSOR_DOCKER_SHA256,
    TARGET_DOCKER_SHA256,
)
from .successor_configuration_authority import (
    DevSuccessorConfigurationAuthority,
    DevSuccessorConfigurationPair,
)


__all__ = (
    "DevSuccessorHostMigrationAuthority",
    "DevSuccessorHostMigrationState",
)

_ERROR = "successor DEV host migration authority is invalid"


def _hex(value: object, length: int) -> bool:
    """Require one nonzero lowercase hexadecimal authority value."""

    return (
        type(value) is str
        and len(value) == length
        and value != "0" * length
        and all(c in "0123456789abcdef" for c in value)
    )


_PHASES = (
    ("c32w", "replace-application"),
    ("application", "replace-executor-configuration"),
    ("executor", "replace-broker-configuration"),
    ("complete", "complete"),
)


@dataclass(frozen=True, slots=True)
class DevSuccessorHostMigrationState:
    """One exact accepted prefix of the successor host migration."""

    phase: str
    next_operation: str
    application_sha256: str
    executor_reviewed_commit: str
    broker_reviewed_commit: str
    expected_workflow_sha: str

    def __post_init__(self) -> None:
        """Reject unknown phases, operations, or malformed evidence."""

        mapping = dict(_PHASES)
        if (
            type(self.phase) is not str
            or self.phase not in mapping
            or type(self.next_operation) is not str
            or self.next_operation != mapping[self.phase]
            or not _hex(self.application_sha256, 64)
            or not _hex(self.executor_reviewed_commit, 40)
            or not _hex(self.broker_reviewed_commit, 40)
            or not _hex(self.expected_workflow_sha, 40)
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True, kw_only=True)
class DevSuccessorHostMigrationAuthority:
    """Bind one exact C32W pair to its deterministic C32ZH/C32ZI successor."""

    predecessor_executor: DevExecutorServiceConfiguration
    predecessor_broker: DevBrokerServiceConfiguration

    def __post_init__(self) -> None:
        """Reconstruct and prove the predecessor pair before accepting it."""

        try:
            pair = DevFinalConfigurationPair(
                executor=self.predecessor_executor,
                broker=self.predecessor_broker,
            )
            object.__setattr__(self, "predecessor_executor", pair.executor)
            object.__setattr__(self, "predecessor_broker", pair.broker)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def predecessor_pair(self) -> DevFinalConfigurationPair:
        """Return a freshly revalidated frozen C32W executor/broker pair."""

        try:
            return DevFinalConfigurationPair(
                executor=self.predecessor_executor,
                broker=self.predecessor_broker,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def successor_pair(self) -> DevSuccessorConfigurationPair:
        """Derive the exact successor pair while preserving workflow authority."""

        try:
            predecessor = self.predecessor_pair()
            authority = DevSuccessorConfigurationAuthority(
                predecessor_configuration=predecessor.executor,
            )
            return authority.configuration_pair(
                expected_workflow_sha=predecessor.broker.expected_workflow_sha,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def classify(
        self,
        *,
        application_sha256: str,
        executor: DevExecutorServiceConfiguration,
        broker: DevBrokerServiceConfiguration,
    ) -> DevSuccessorHostMigrationState:
        """Classify only the four exact resumable migration prefixes."""

        try:
            if (
                not _hex(application_sha256, 64)
                or type(executor) is not DevExecutorServiceConfiguration
                or type(broker) is not DevBrokerServiceConfiguration
            ):
                raise ValueError

            predecessor = self.predecessor_pair()
            successor = self.successor_pair()
            old_executor = predecessor.executor.canonical_bytes()
            old_broker = predecessor.broker.canonical_bytes()
            new_executor = successor.executor.canonical_bytes()
            new_broker = successor.broker.canonical_bytes()
            current_executor = DevExecutorServiceConfiguration.from_dict(
                executor.to_dict(),
            ).canonical_bytes()
            current_broker = DevBrokerServiceConfiguration.from_dict(
                broker.to_dict(),
            ).canonical_bytes()

            if (
                application_sha256 == PREDECESSOR_DOCKER_SHA256
                and current_executor == old_executor
                and current_broker == old_broker
            ):
                phase, operation = _PHASES[0]
            elif (
                application_sha256 == TARGET_DOCKER_SHA256
                and current_executor == old_executor
                and current_broker == old_broker
            ):
                phase, operation = _PHASES[1]
            elif (
                application_sha256 == TARGET_DOCKER_SHA256
                and current_executor == new_executor
                and current_broker == old_broker
            ):
                phase, operation = _PHASES[2]
            elif (
                application_sha256 == TARGET_DOCKER_SHA256
                and current_executor == new_executor
                and current_broker == new_broker
            ):
                phase, operation = _PHASES[3]
            else:
                raise ValueError

            return DevSuccessorHostMigrationState(
                phase=phase,
                next_operation=operation,
                application_sha256=application_sha256,
                executor_reviewed_commit=executor.reviewed_commit,
                broker_reviewed_commit=broker.reviewed_commit,
                expected_workflow_sha=broker.expected_workflow_sha,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None
