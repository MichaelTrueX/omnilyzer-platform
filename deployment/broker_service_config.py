"""C32H pure immutable DEV broker authority configuration.

C13 supplies identity relationships; C23 supplies the distinct-group topology.
C32F workflow revision and C32G version/digests are independently reviewed inputs,
never inferred from source, HEAD, requests or environment. No digests or revision
are supplied here. Import, construction and parsing perform no I/O or activation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from types import MappingProxyType
from typing import Mapping

from .identity import validate_expected_workflow_sha as _validate_workflow_sha
from .installation_contract import (
    DevHostInstallationContract as _DevHostInstallationContract,
)
from .policy import (
    canonical_bytes as _canonical_bytes,
    validate_sha256 as _validate_sha256,
)


__all__ = (
    "BrokerServiceConfigurationError",
    "DevBrokerServiceConfiguration",
    "parse_canonical_broker_service_configuration",
    "PRODUCTION_BROKER_SERVICE_CONFIG_PATH",
    "BROKER_SERVICE_CONFIG_DIRECTORY_MODE",
    "BROKER_SERVICE_CONFIG_FILE_MODE",
    "MAX_BROKER_SERVICE_CONFIG_BYTES",
    "BROKER_SERVICE_CONFIG_DIRECTORY",
    "PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH",
    "COSIGN_VERSION",
)

BROKER_SERVICE_CONFIG_DIRECTORY = "/etc/omnilyzer/deployment/broker"
PRODUCTION_BROKER_SERVICE_CONFIG_PATH = BROKER_SERVICE_CONFIG_DIRECTORY + "/dev.json"
BROKER_SERVICE_CONFIG_DIRECTORY_MODE = 0o750
BROKER_SERVICE_CONFIG_FILE_MODE = 0o640
MAX_BROKER_SERVICE_CONFIG_BYTES = 4096

PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH = (
    BROKER_SERVICE_CONFIG_DIRECTORY + "/sigstore-trusted-root.json"
)
COSIGN_VERSION = "3.1.2"
_ERROR = "DEV broker authority configuration is invalid"
_SCHEMA_FIELDS = frozenset({
    "schema_version",
    "stage",
    "broker_uid",
    "broker_gid",
    "executor_uid",
    "executor_gid",
    "replay_group_gid",
    "socket_group_gid",
    "expected_workflow_sha",
    "cosign_version",
    "cosign_binary_sha256",
    "sigstore_trusted_root_sha256",
})


class BrokerServiceConfigurationError(Exception):
    """The DEV broker authority configuration is not trustworthy."""


def _exact_fields(value: object, expected: frozenset[str]) -> dict[str, object]:
    """Require one exact built-in dictionary with exact built-in string keys."""

    if type(value) is not dict:
        raise TypeError
    keys = tuple(value.keys())
    if any(type(key) is not str for key in keys) or set(keys) != expected:
        raise TypeError
    return value


def _validated_hash(value: object, context: str) -> str:
    """Validate one exact built-in SHA-256 string through shared policy."""

    if type(value) is not str or value == "0" * 64:
        raise TypeError
    return _validate_sha256(value, context)


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting duplicate or non-string keys."""

    value: dict[str, object] = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    """Reject non-standard JSON numeric constants without reflecting them."""

    raise ValueError


@dataclass(frozen=True, slots=True, kw_only=True)
class DevBrokerServiceConfiguration:
    """Hold one immutable, closed DEV broker process authority selection."""

    schema_version: int
    stage: str
    broker_uid: int
    broker_gid: int
    executor_uid: int
    executor_gid: int
    replay_group_gid: int
    socket_group_gid: int
    expected_workflow_sha: str
    cosign_version: str
    cosign_binary_sha256: str
    sigstore_trusted_root_sha256: str
    _installation: _DevHostInstallationContract = field(
        init=False, repr=False, compare=False,
    )

    def __post_init__(self) -> None:
        """Validate pure values and cache the authoritative C13 identity contract."""

        try:
            if type(self.schema_version) is not int or self.schema_version != 1:
                raise TypeError
            if type(self.stage) is not str or self.stage != "dev":
                raise TypeError
            installation = _DevHostInstallationContract(
                broker_uid=self.broker_uid,
                broker_gid=self.broker_gid,
                executor_uid=self.executor_uid,
                executor_gid=self.executor_gid,
                replay_group_gid=self.replay_group_gid,
                socket_group_gid=self.socket_group_gid,
            )
            # Preserve C13 relationships while requiring C23's distinct,
            # non-root installation topology. Aliases must not confer access
            # to the other process's private configuration boundary.
            if (
                self.executor_uid == 0
                or self.executor_gid == 0
                or len({self.broker_gid, self.executor_gid,
                        self.replay_group_gid, self.socket_group_gid}) != 4
                or self.executor_gid in installation.broker_required_group_gids
                or self.broker_gid in installation.executor_required_group_gids
            ):
                raise ValueError
            _validate_workflow_sha(self.expected_workflow_sha)
            if type(self.cosign_version) is not str or self.cosign_version != COSIGN_VERSION:
                raise TypeError
            _validated_hash(self.cosign_binary_sha256, "cosign_binary_sha256")
            _validated_hash(self.sigstore_trusted_root_sha256, "sigstore_trusted_root_sha256")
            object.__setattr__(self, "_installation", installation)
            encoded = _canonical_bytes(self.to_dict())
            if not encoded or len(encoded) > MAX_BROKER_SERVICE_CONFIG_BYTES:
                raise ValueError
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise BrokerServiceConfigurationError(_ERROR) from None

    @classmethod
    def from_dict(cls, value: object) -> "DevBrokerServiceConfiguration":
        """Parse one exact in-memory schema without coercion or I/O."""

        try:
            source = _exact_fields(value, _SCHEMA_FIELDS)
            return cls(
                schema_version=source["schema_version"],
                stage=source["stage"],
                broker_uid=source["broker_uid"],
                broker_gid=source["broker_gid"],
                executor_uid=source["executor_uid"],
                executor_gid=source["executor_gid"],
                replay_group_gid=source["replay_group_gid"],
                socket_group_gid=source["socket_group_gid"],
                expected_workflow_sha=source["expected_workflow_sha"],
                cosign_version=source["cosign_version"],
                cosign_binary_sha256=source["cosign_binary_sha256"],
                sigstore_trusted_root_sha256=source["sigstore_trusted_root_sha256"],
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise BrokerServiceConfigurationError(_ERROR) from None

    def to_dict(self) -> dict[str, object]:
        """Return a fresh built-in canonical-schema dictionary."""

        return {
            "schema_version": self.schema_version,
            "stage": self.stage,
            "broker_uid": self.broker_uid,
            "broker_gid": self.broker_gid,
            "executor_uid": self.executor_uid,
            "executor_gid": self.executor_gid,
            "replay_group_gid": self.replay_group_gid,
            "socket_group_gid": self.socket_group_gid,
            "expected_workflow_sha": self.expected_workflow_sha,
            "cosign_version": self.cosign_version,
            "cosign_binary_sha256": self.cosign_binary_sha256,
            "sigstore_trusted_root_sha256": self.sigstore_trusted_root_sha256,
        }

    def canonical_bytes(self) -> bytes:
        """Return bounded canonical ASCII JSON with exactly one final newline."""

        try:
            encoded = _canonical_bytes(self.to_dict())
            if not encoded or len(encoded) > MAX_BROKER_SERVICE_CONFIG_BYTES:
                raise ValueError
            return encoded
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise BrokerServiceConfigurationError(_ERROR) from None

    def installation_contract(self) -> _DevHostInstallationContract:
        """Return the immutable C13 contract for these exact six identities."""

        return self._installation

    def oidc_authorization_kwargs(self) -> Mapping[str, str]:
        """Project only independently reviewed C32F workflow authority."""

        return MappingProxyType({"expected_workflow_sha": self.expected_workflow_sha})

    def blob_verifier_kwargs(self) -> Mapping[str, str | int]:
        """Project only immutable C32G version, digests and broker identity."""

        return MappingProxyType({
            "expected_cosign_version": self.cosign_version,
            "expected_binary_sha256": self.cosign_binary_sha256,
            "expected_trusted_root_sha256": self.sigstore_trusted_root_sha256,
            "broker_uid": self.broker_uid,
            "broker_gid": self.broker_gid,
        })


def parse_canonical_broker_service_configuration(
    raw: bytes,
) -> DevBrokerServiceConfiguration:
    """Parse exact bounded canonical bytes without opening a configuration file."""

    try:
        if (
            type(raw) is not bytes
            or not raw
            or len(raw) > MAX_BROKER_SERVICE_CONFIG_BYTES
        ):
            raise TypeError
        text = raw.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_closed_json_object,
            parse_constant=_reject_json_constant,
        )
        configuration = DevBrokerServiceConfiguration.from_dict(value)
        if configuration.canonical_bytes() != raw:
            raise ValueError
        return configuration
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise BrokerServiceConfigurationError(_ERROR) from None
