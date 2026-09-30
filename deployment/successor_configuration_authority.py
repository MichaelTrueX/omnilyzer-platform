"""Pure C32ZI authority for aligned successor DEV executor/broker configs.

The frozen C32W executor configuration is the sole predecessor. This module
changes only reviewed_commit to the C32ZH successor generation and derives the
matching broker configuration from one explicit workflow SHA. Import and
construction perform no host, filesystem, network, Docker, or service I/O.

Related: final_configuration_authority.py, successor_application_generation.py.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .broker_service_config import DevBrokerServiceConfiguration
from .executor_service_config import DevExecutorServiceConfiguration
from .final_configuration_authority import DevFinalConfigurationAuthority
from .sigstore_authority_provenance import DevSigstoreVerificationProvenance
from .successor_application_generation import (
    PREDECESSOR_REVIEWED_COMMIT,
    TARGET_INGRESS_SHA256,
    TARGET_REVIEWED_COMMIT,
    TARGET_RUNTIME_SHA256,
)


__all__ = (
    "DevSuccessorConfigurationAuthority",
    "DevSuccessorConfigurationPair",
)

_ERROR = "successor DEV configuration authority is invalid"
_SHARED = (
    "broker_uid", "broker_gid", "executor_uid", "executor_gid",
    "replay_group_gid", "socket_group_gid", "reviewed_commit",
    "runtime_configuration_sha256", "ingress_file_sha256",
)


def _predecessor(value: object) -> DevExecutorServiceConfiguration:
    """Reconstruct and verify one exact frozen C32W executor configuration."""

    if type(value) is not DevExecutorServiceConfiguration:
        raise ValueError(_ERROR)
    authority = DevFinalConfigurationAuthority(executor_configuration=value)
    predecessor = authority.executor()
    if (
        predecessor.reviewed_commit != PREDECESSOR_REVIEWED_COMMIT
        or predecessor.runtime_configuration_sha256 != TARGET_RUNTIME_SHA256
        or predecessor.ingress_file_sha256 != TARGET_INGRESS_SHA256
    ):
        raise ValueError(_ERROR)
    return predecessor


def _successor(value: object) -> DevExecutorServiceConfiguration:
    """Validate a successor config by reconstructing its exact C32W predecessor."""

    if type(value) is not DevExecutorServiceConfiguration:
        raise ValueError(_ERROR)
    normalized = DevExecutorServiceConfiguration.from_dict(value.to_dict())
    if (
        normalized.reviewed_commit != TARGET_REVIEWED_COMMIT
        or normalized.runtime_configuration_sha256 != TARGET_RUNTIME_SHA256
        or normalized.ingress_file_sha256 != TARGET_INGRESS_SHA256
    ):
        raise ValueError(_ERROR)
    predecessor = _predecessor(
        replace(normalized, reviewed_commit=PREDECESSOR_REVIEWED_COMMIT)
    )
    before = predecessor.to_dict()
    after = normalized.to_dict()
    if (
        before.keys() != after.keys()
        or {key for key in before if before[key] != after[key]}
        != {"reviewed_commit"}
    ):
        raise ValueError(_ERROR)
    return normalized


def _project(predecessor: DevExecutorServiceConfiguration
             ) -> DevExecutorServiceConfiguration:
    """Project exactly one C32W config to the C32ZH reviewed commit."""

    target = replace(predecessor, reviewed_commit=TARGET_REVIEWED_COMMIT)
    return _successor(target)


def _broker(executor: DevExecutorServiceConfiguration,
            expected_workflow_sha: str) -> DevBrokerServiceConfiguration:
    """Derive one broker config aligned to the successor executor authority."""

    executor = _successor(executor)
    provenance = DevSigstoreVerificationProvenance()
    provenance.__post_init__()
    values = {name: getattr(executor, name) for name in _SHARED}
    return DevBrokerServiceConfiguration(
        schema_version=2,
        stage="dev",
        expected_workflow_sha=expected_workflow_sha,
        **values,
        **provenance.broker_service_configuration_kwargs(),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class DevSuccessorConfigurationAuthority:
    """One exact C32W predecessor with pure successor projections."""

    predecessor_configuration: DevExecutorServiceConfiguration

    def __post_init__(self) -> None:
        """Reconstruct the predecessor to discard forged cached state."""

        try:
            object.__setattr__(
                self,
                "predecessor_configuration",
                _predecessor(self.predecessor_configuration),
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def executor(self) -> DevExecutorServiceConfiguration:
        """Return an independently reconstructed successor executor config."""

        try:
            return _project(_predecessor(self.predecessor_configuration))
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def broker_configuration(
        self, *, expected_workflow_sha: str,
    ) -> DevBrokerServiceConfiguration:
        """Bind one explicit workflow commit to successor application authority."""

        try:
            broker = _broker(self.executor(), expected_workflow_sha)
            return DevBrokerServiceConfiguration.from_dict(broker.to_dict())
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def configuration_pair(
        self, *, expected_workflow_sha: str,
    ) -> "DevSuccessorConfigurationPair":
        """Return one aligned successor executor/broker pair."""

        return DevSuccessorConfigurationPair(
            executor=self.executor(),
            broker=self.broker_configuration(
                expected_workflow_sha=expected_workflow_sha,
            ),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class DevSuccessorConfigurationPair:
    """Exact independently reconstructed successor executor/broker authority."""

    executor: DevExecutorServiceConfiguration
    broker: DevBrokerServiceConfiguration

    def __post_init__(self) -> None:
        """Revalidate nested configs and their shared installation authority."""

        try:
            executor = _successor(self.executor)
            if type(self.broker) is not DevBrokerServiceConfiguration:
                raise TypeError
            broker = DevBrokerServiceConfiguration.from_dict(self.broker.to_dict())
            expected = _broker(executor, broker.expected_workflow_sha)
            if broker.to_dict() != expected.to_dict():
                raise ValueError
            if any(
                getattr(executor, name) != getattr(broker, name)
                for name in _SHARED
            ):
                raise ValueError
            if executor.installation_contract() != broker.installation_contract():
                raise ValueError
            object.__setattr__(self, "executor", executor)
            object.__setattr__(self, "broker", broker)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None
