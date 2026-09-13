"""deployment/executor_service_config.py — pure DEV executor service contract.

This module defines the canonical, bounded future root-owned configuration for
the Task 014 DEV executor service. It reuses C13's host identity contract and
projects the non-listener/non-clock inputs required by C15. C16 socket
activation remains a separate bootstrap concern. Import, construction, and
parsing perform no filesystem, host, socket, systemd, Docker, or network I/O;
the fixed future path is declared but never accessed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json

from .docker_runtime import validate_canary_image as _validate_canary_image
from .execution import INGRESS_PATHS as _INGRESS_PATHS
from .installation_contract import (
    DevHostInstallationContract as _DevHostInstallationContract,
)
from .policy import (
    canonical_bytes as _canonical_bytes,
    validate_sha256 as _validate_sha256,
    validate_source_sha as _validate_source_sha,
)


__all__ = (
    "ExecutorServiceConfigurationError",
    "DevExecutorServiceConfiguration",
    "parse_canonical_executor_service_configuration",
    "PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH",
    "EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE",
    "EXECUTOR_SERVICE_CONFIG_FILE_MODE",
    "MAX_EXECUTOR_SERVICE_CONFIG_BYTES",
)

PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH = (
    "/etc/omnilyzer/deployment/dev/executor.json"
)
EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE = 0o750
EXECUTOR_SERVICE_CONFIG_FILE_MODE = 0o640
MAX_EXECUTOR_SERVICE_CONFIG_BYTES = 4096

_CONFIGURATION_DIRECTORY = "/etc/omnilyzer/deployment/dev"
_CONFIGURATION_OWNER_UID = 0
_ERROR = "DEV executor service configuration is invalid"
_SCHEMA_FIELDS = frozenset({
    "schema_version",
    "stage",
    "broker_uid",
    "broker_gid",
    "executor_uid",
    "executor_gid",
    "replay_group_gid",
    "socket_group_gid",
    "canary_image",
    "reviewed_commit",
    "runtime_configuration_sha256",
    "ingress_file_sha256",
})
_INGRESS_FIELDS = frozenset(_INGRESS_PATHS)


class ExecutorServiceConfigurationError(Exception):
    """The DEV executor service authority configuration is not trustworthy."""


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

    if type(value) is not str:
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
class DevExecutorServiceConfiguration:
    """Hold one immutable, closed DEV executor process authority selection."""

    schema_version: int
    stage: str
    broker_uid: int
    broker_gid: int
    executor_uid: int
    executor_gid: int
    replay_group_gid: int
    socket_group_gid: int
    canary_image: str
    reviewed_commit: str
    runtime_configuration_sha256: str
    ingress_file_sha256: tuple[str, str, str]
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
            if type(self.canary_image) is not str:
                raise TypeError
            _validate_canary_image(self.canary_image)
            if type(self.reviewed_commit) is not str:
                raise TypeError
            _validate_source_sha(self.reviewed_commit)
            _validated_hash(
                self.runtime_configuration_sha256,
                "runtime_configuration_sha256",
            )
            if (
                type(self.ingress_file_sha256) is not tuple
                or len(self.ingress_file_sha256) != len(_INGRESS_PATHS)
            ):
                raise TypeError
            for path, digest in zip(
                _INGRESS_PATHS, self.ingress_file_sha256, strict=True,
            ):
                _validated_hash(digest, path)
            object.__setattr__(self, "_installation", installation)
            encoded = _canonical_bytes(self.to_dict())
            if not encoded or len(encoded) > MAX_EXECUTOR_SERVICE_CONFIG_BYTES:
                raise ValueError
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ExecutorServiceConfigurationError(_ERROR) from None

    @classmethod
    def from_dict(cls, value: object) -> "DevExecutorServiceConfiguration":
        """Parse one exact in-memory schema without coercion or I/O."""

        try:
            source = _exact_fields(value, _SCHEMA_FIELDS)
            ingress = _exact_fields(
                source["ingress_file_sha256"], _INGRESS_FIELDS,
            )
            ingress_hashes = tuple(ingress[path] for path in _INGRESS_PATHS)
            return cls(
                schema_version=source["schema_version"],
                stage=source["stage"],
                broker_uid=source["broker_uid"],
                broker_gid=source["broker_gid"],
                executor_uid=source["executor_uid"],
                executor_gid=source["executor_gid"],
                replay_group_gid=source["replay_group_gid"],
                socket_group_gid=source["socket_group_gid"],
                canary_image=source["canary_image"],
                reviewed_commit=source["reviewed_commit"],
                runtime_configuration_sha256=source[
                    "runtime_configuration_sha256"
                ],
                ingress_file_sha256=ingress_hashes,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ExecutorServiceConfigurationError(_ERROR) from None

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
            "canary_image": self.canary_image,
            "reviewed_commit": self.reviewed_commit,
            "runtime_configuration_sha256": self.runtime_configuration_sha256,
            "ingress_file_sha256": {
                path: digest
                for path, digest in zip(
                    _INGRESS_PATHS, self.ingress_file_sha256, strict=True,
                )
            },
        }

    def canonical_bytes(self) -> bytes:
        """Return bounded canonical ASCII JSON with exactly one final newline."""

        try:
            encoded = _canonical_bytes(self.to_dict())
            if not encoded or len(encoded) > MAX_EXECUTOR_SERVICE_CONFIG_BYTES:
                raise ValueError
            return encoded
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ExecutorServiceConfigurationError(_ERROR) from None

    def installation_contract(self) -> _DevHostInstallationContract:
        """Return the immutable C13 contract for these exact six identities."""

        return self._installation

    def executor_composition_kwargs(self) -> dict[str, object]:
        """Return fresh C15 arguments excluding operational listener and clock."""

        values: dict[str, object] = (
            self._installation.executor_composition_identity_kwargs()
        )
        values.update({
            "canary_image": self.canary_image,
            "reviewed_commit": self.reviewed_commit,
            "runtime_configuration_sha256": self.runtime_configuration_sha256,
            "ingress_file_sha256": self.ingress_file_sha256,
        })
        return values


def parse_canonical_executor_service_configuration(
    raw: bytes,
) -> DevExecutorServiceConfiguration:
    """Parse exact bounded canonical bytes without opening a configuration file."""

    try:
        if (
            type(raw) is not bytes
            or not raw
            or len(raw) > MAX_EXECUTOR_SERVICE_CONFIG_BYTES
        ):
            raise TypeError
        text = raw.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_closed_json_object,
            parse_constant=_reject_json_constant,
        )
        configuration = DevExecutorServiceConfiguration.from_dict(value)
        if configuration.canonical_bytes() != raw:
            raise ValueError
        return configuration
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise ExecutorServiceConfigurationError(_ERROR) from None
