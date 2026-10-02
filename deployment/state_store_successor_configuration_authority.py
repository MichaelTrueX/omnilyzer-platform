"""deployment/state_store_successor_configuration_authority.py - C33AE config authority.

Purpose:
- project the installed C32ZH executor/broker configuration to the C33AC
  application commit;
- change only reviewed_commit in the executor;
- change only reviewed_commit and expected_workflow_sha in the broker, with the
  workflow SHA supplied explicitly by the later reviewed live migration.

Links:
- dev_post_c31_application_update.py and successor_application_generation.py
  bind the installed predecessor through canonical historical config authority;
- state_store_successor_application_generation.py pins the exact target application bytes;
- broker_service_config.py and executor_service_config.py define canonical JSON.

Import and construction are inert and perform no filesystem, network, Docker,
systemd, registry, or deployment operation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib

from . import broker_service_config as broker_config
from . import executor_service_config as executor_config
from . import sigstore_authority_provenance as sigstore_provenance
from . import dev_post_c31_application_update as historical
from . import successor_application_generation as successor_generation
from .state_store_successor_application_generation import (
    PREDECESSOR_REVIEWED_COMMIT,
    TARGET_INGRESS_SHA256,
    TARGET_REVIEWED_COMMIT,
    TARGET_RUNTIME_SHA256,
)


_ERROR = "C33AE state-store successor configuration authority is invalid"
_SHARED = (
    "broker_uid",
    "broker_gid",
    "executor_uid",
    "executor_gid",
    "replay_group_gid",
    "socket_group_gid",
    "reviewed_commit",
    "runtime_configuration_sha256",
    "ingress_file_sha256",
)


def _predecessor(value: object) -> executor_config.DevExecutorServiceConfiguration:
    """Reconstruct the exact installed C32ZH executor without stale class aliases."""

    if type(value) is not executor_config.DevExecutorServiceConfiguration:
        raise ValueError(_ERROR)
    normalized = executor_config.DevExecutorServiceConfiguration.from_dict(
        value.to_dict()
    )
    if (
        normalized.schema_version != 1
        or normalized.stage != "dev"
        or normalized.reviewed_commit != PREDECESSOR_REVIEWED_COMMIT
        or normalized.runtime_configuration_sha256 != TARGET_RUNTIME_SHA256
        or normalized.ingress_file_sha256 != TARGET_INGRESS_SHA256
    ):
        raise ValueError(_ERROR)

    c32w = replace(
        normalized,
        reviewed_commit=successor_generation.PREDECESSOR_REVIEWED_COMMIT,
    )
    historical_bytes = replace(
        c32w,
        reviewed_commit=historical.PREDECESSOR,
    ).canonical_bytes()
    if (
        hashlib.sha256(historical_bytes).hexdigest()
        != historical.PREDECESSOR_C17
    ):
        raise ValueError(_ERROR)

    before = c32w.to_dict()
    after = normalized.to_dict()
    if (
        before.keys() != after.keys()
        or {
            key
            for key in before
            if before[key] != after[key]
        }
        != {"reviewed_commit"}
    ):
        raise ValueError(_ERROR)
    return normalized


def _target(value: object) -> executor_config.DevExecutorServiceConfiguration:
    """Validate one target config by reconstructing its exact predecessor."""

    if type(value) is not executor_config.DevExecutorServiceConfiguration:
        raise ValueError(_ERROR)
    normalized = executor_config.DevExecutorServiceConfiguration.from_dict(value.to_dict())
    if (
        normalized.reviewed_commit != TARGET_REVIEWED_COMMIT
        or normalized.runtime_configuration_sha256 != TARGET_RUNTIME_SHA256
        or normalized.ingress_file_sha256 != TARGET_INGRESS_SHA256
    ):
        raise ValueError(_ERROR)

    before = _predecessor(
        replace(normalized, reviewed_commit=PREDECESSOR_REVIEWED_COMMIT)
    )
    before_values = before.to_dict()
    after_values = normalized.to_dict()
    if (
        before_values.keys() != after_values.keys()
        or {
            key
            for key in before_values
            if before_values[key] != after_values[key]
        }
        != {"reviewed_commit"}
    ):
        raise ValueError(_ERROR)
    return normalized


def _project(
    source: executor_config.DevExecutorServiceConfiguration,
) -> executor_config.DevExecutorServiceConfiguration:
    """Project exactly one predecessor executor to the C33AE target commit."""

    return _target(
        replace(_predecessor(source), reviewed_commit=TARGET_REVIEWED_COMMIT)
    )


def _installation_contract_signature(value: object) -> tuple[object, ...]:
    """Return the complete closed installation contract as pure values.

    This intentionally avoids dataclass class identity. Historical tests reload
    installation_contract.py, so executor and broker can hold different Python
    class generations with identical reviewed contract values.
    """

    required_identity_names = (
        "broker_uid",
        "broker_gid",
        "executor_uid",
        "executor_gid",
        "replay_group_gid",
        "socket_group_gid",
    )
    identities = tuple(getattr(value, name) for name in required_identity_names)
    if any(type(item) is not int for item in identities):
        raise ValueError(_ERROR)

    broker_groups = getattr(value, "broker_required_group_gids")
    executor_groups = getattr(value, "executor_required_group_gids")
    if (
        type(broker_groups) is not tuple
        or type(executor_groups) is not tuple
        or any(type(item) is not int for item in (*broker_groups, *executor_groups))
    ):
        raise ValueError(_ERROR)

    resource_method = getattr(value, "resource_requirements", None)
    if not callable(resource_method):
        raise ValueError(_ERROR)
    resources = resource_method()
    if type(resources) is not tuple or len(resources) != 7:
        raise ValueError(_ERROR)

    resource_signature = []
    for resource in resources:
        item = (
            getattr(resource, "path", None),
            getattr(resource, "kind", None),
            getattr(resource, "mode", None),
            getattr(resource, "owner_uid", None),
            getattr(resource, "group_gid", None),
            getattr(resource, "lifecycle", None),
        )
        if (
            type(item[0]) is not str
            or type(item[1]) is not str
            or type(item[2]) is not int
            or type(item[3]) is not int
            or type(item[4]) is not int
            or type(item[5]) is not str
        ):
            raise ValueError(_ERROR)
        resource_signature.append(item)

    return (
        *identities,
        broker_groups,
        executor_groups,
        tuple(resource_signature),
    )


def _predecessor_broker(
    executor: executor_config.DevExecutorServiceConfiguration,
    expected_workflow_sha: str,
) -> broker_config.DevBrokerServiceConfiguration:
    """Derive the exact installed predecessor broker for one workflow SHA."""

    executor = _predecessor(executor)
    provenance = sigstore_provenance.DevSigstoreVerificationProvenance()
    provenance.__post_init__()
    values = {name: getattr(executor, name) for name in _SHARED}
    return broker_config.DevBrokerServiceConfiguration(
        schema_version=2,
        stage="dev",
        expected_workflow_sha=expected_workflow_sha,
        **values,
        **provenance.broker_service_configuration_kwargs(),
    )


def _broker(
    executor: executor_config.DevExecutorServiceConfiguration,
    expected_workflow_sha: str,
) -> broker_config.DevBrokerServiceConfiguration:
    """Derive the aligned target broker from one explicit workflow SHA."""

    executor = _target(executor)
    provenance = sigstore_provenance.DevSigstoreVerificationProvenance()
    provenance.__post_init__()
    values = {name: getattr(executor, name) for name in _SHARED}
    return broker_config.DevBrokerServiceConfiguration(
        schema_version=2,
        stage="dev",
        expected_workflow_sha=expected_workflow_sha,
        **values,
        **provenance.broker_service_configuration_kwargs(),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class DevStateStoreSuccessorConfigurationAuthority:
    """One exact installed predecessor with pure C33AC config projections."""

    predecessor_configuration: executor_config.DevExecutorServiceConfiguration

    def __post_init__(self) -> None:
        """Capture a normalized predecessor and discard forged cached state."""

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

    def executor(self) -> executor_config.DevExecutorServiceConfiguration:
        """Return an independently reconstructed C33AE executor config."""

        try:
            return _project(self.predecessor_configuration)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def configuration_pair(
        self,
        *,
        expected_workflow_sha: str,
    ) -> "DevStateStoreSuccessorConfigurationPair":
        """Return one aligned executor/broker pair for the explicit workflow."""

        executor = self.executor()
        return DevStateStoreSuccessorConfigurationPair(
            executor=executor,
            broker=_broker(executor, expected_workflow_sha),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class DevStateStoreSuccessorConfigurationPair:
    """Exact independently reconstructed C33AE executor/broker authority."""

    executor: executor_config.DevExecutorServiceConfiguration
    broker: broker_config.DevBrokerServiceConfiguration

    def __post_init__(self) -> None:
        """Revalidate nested configs and all shared installation identities."""

        try:
            executor = _target(self.executor)
            if type(self.broker) is not broker_config.DevBrokerServiceConfiguration:
                raise TypeError
            broker = broker_config.DevBrokerServiceConfiguration.from_dict(self.broker.to_dict())
            expected = _broker(executor, broker.expected_workflow_sha)
            if broker.to_dict() != expected.to_dict():
                raise ValueError
            if any(
                getattr(executor, name) != getattr(broker, name)
                for name in _SHARED
            ):
                raise ValueError
            if _installation_contract_signature(
                executor.installation_contract()
            ) != _installation_contract_signature(
                broker.installation_contract()
            ):
                raise ValueError
            object.__setattr__(self, "executor", executor)
            object.__setattr__(self, "broker", broker)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None
