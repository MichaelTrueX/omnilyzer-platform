"""Pure C32X authority for aligned final DEV executor and broker configurations.

The installed executor config is the seed. The future workflow commit is the
sole independent input to broker derivation; this module does no host I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib

from .broker_service_config import DevBrokerServiceConfiguration
from . import dev_post_c31_application_update as c32d
from .executor_service_config import DevExecutorServiceConfiguration
from .final_application_generation import (
    TARGET_INGRESS_SHA256, TARGET_REVIEWED_COMMIT, TARGET_RUNTIME_SHA256,
)
from .sigstore_authority_provenance import DevSigstoreVerificationProvenance


__all__ = ("DevFinalConfigurationAuthority", "DevFinalConfigurationPair")

_ERROR = "final DEV configuration authority is invalid"
_SHARED = (
    "broker_uid", "broker_gid", "executor_uid", "executor_gid",
    "replay_group_gid", "socket_group_gid", "reviewed_commit",
    "runtime_configuration_sha256", "ingress_file_sha256",
)


def _executor(value: object) -> DevExecutorServiceConfiguration:
    """Reconstruct C17 and prove only its reviewed_commit changed since C31."""
    if type(value) is not DevExecutorServiceConfiguration:
        raise ValueError(_ERROR)
    normalized = DevExecutorServiceConfiguration.from_dict(value.to_dict())
    if (normalized.schema_version != 1 or normalized.stage != "dev"
            or normalized.reviewed_commit != TARGET_REVIEWED_COMMIT
            or normalized.runtime_configuration_sha256 != TARGET_RUNTIME_SHA256
            or normalized.ingress_file_sha256 != TARGET_INGRESS_SHA256):
        raise ValueError(_ERROR)
    historical = replace(normalized, reviewed_commit=c32d.PREDECESSOR)
    if hashlib.sha256(historical.canonical_bytes()).hexdigest() != c32d.PREDECESSOR_C17:
        raise ValueError(_ERROR)
    return normalized


def _broker(executor: DevExecutorServiceConfiguration,
            expected_workflow_sha: str) -> DevBrokerServiceConfiguration:
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
class DevFinalConfigurationAuthority:
    """One historically bound executor seed, with no workflow input yet."""

    executor_configuration: DevExecutorServiceConfiguration

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "executor_configuration",
                           _executor(self.executor_configuration))
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def executor(self) -> DevExecutorServiceConfiguration:
        """Return an independently reconstructed exact final executor config."""
        try:
            return _executor(self.executor_configuration)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def broker_configuration(self, *, expected_workflow_sha: str
                             ) -> DevBrokerServiceConfiguration:
        """Bind one explicit reviewed workflow commit to C17/C32W/C32I authority."""
        try:
            broker = _broker(self.executor(), expected_workflow_sha)
            return DevBrokerServiceConfiguration.from_dict(broker.to_dict())
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def configuration_pair(self, *, expected_workflow_sha: str
                           ) -> DevFinalConfigurationPair:
        return DevFinalConfigurationPair(
            executor=self.executor(),
            broker=self.broker_configuration(expected_workflow_sha=expected_workflow_sha),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class DevFinalConfigurationPair:
    """Exact independently reconstructed and aligned C17/C32S configurations."""

    executor: DevExecutorServiceConfiguration
    broker: DevBrokerServiceConfiguration

    def __post_init__(self) -> None:
        try:
            executor = DevFinalConfigurationAuthority(
                executor_configuration=self.executor,
            ).executor()
            if type(self.broker) is not DevBrokerServiceConfiguration:
                raise TypeError
            broker = DevBrokerServiceConfiguration.from_dict(self.broker.to_dict())
            expected = _broker(executor, broker.expected_workflow_sha)
            if broker.to_dict() != expected.to_dict():
                raise ValueError
            if any(getattr(executor, name) != getattr(broker, name) for name in _SHARED):
                raise ValueError
            if executor.installation_contract() != broker.installation_contract():
                raise ValueError
            object.__setattr__(self, "executor", executor)
            object.__setattr__(self, "broker", broker)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None
