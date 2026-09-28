"""Pure C32U future broker service and resource authority, separate from C23.

This module describes prerequisites only. Import, construction and projections
perform no host I/O, systemd operation, provisioning or network activity.
"""

from __future__ import annotations

from dataclasses import dataclass

from .blob_verifier import RUNTIME_DIRECTORY as _BLOB_RUNTIME_DIRECTORY
from .broker_https_ingress import (
    BROKER_LOOPBACK_HOST as _LOOPBACK_HOST,
    BROKER_LOOPBACK_PORT as _LOOPBACK_PORT,
)
from .broker_service_config import (
    BROKER_SERVICE_CONFIG_DIRECTORY as _CONFIG_DIRECTORY,
    BROKER_SERVICE_CONFIG_FILE_MODE as _CONFIG_FILE_MODE,
    PRODUCTION_BROKER_SERVICE_CONFIG_PATH as _CONFIG_PATH,
    DevBrokerServiceConfiguration as _Configuration,
)
from .host_provisioning_contract import HostInstalledAssetRequirement
from .host_service_layout import DevHostServiceLayout
from .installation_contract import (
    DevHostInstallationContract, HostResourceRequirement, MAX_UID_GID,
)
from .oci_verifier import _RUNTIME_DIRECTORY as _OCI_RUNTIME_DIRECTORY
from .replay_sqlite import PRODUCTION_REPLAY_DATABASE
from .sigstore_resource_contract import DevSigstoreResourceContract
from .unix_transport import PRODUCTION_EXECUTOR_SOCKET_PATH


__all__ = ("BrokerConfigurationFileRequirement", "DevBrokerHostServiceContract")

_ERROR = "DEV broker host service contract is invalid"
_BROKER_MODULE = "deployment.broker_service_entrypoint"
_BROKER_SERVICE_UNIT = "omnilyzer-deployment-broker.service"
_UNIT_SOURCE = "deployment/systemd/dev/" + _BROKER_SERVICE_UNIT
_UNIT_DESTINATION = "/etc/systemd/system/" + _BROKER_SERVICE_UNIT
_UNIT_SHA256 = "594c3038451ad867e80e1361bef81711814e7aec1a727f33e85de9fd590bf0c2"
_CONFIG_LIFECYCLE = "must-contain-canonical-schema-2-broker-config-before-activation"
_REQUIRED_LIFECYCLE = "must-exist-before-activation"


@dataclass(frozen=True, slots=True)
class BrokerConfigurationFileRequirement:
    """The future single-link canonical schema-2 root:broker config file."""

    path: str
    kind: str
    mode: int
    owner_uid: int
    group_gid: int
    nlink: int
    lifecycle: str

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str or self.path != _CONFIG_PATH
            or type(self.kind) is not str or self.kind != "regular_file"
            or type(self.mode) is not int or self.mode != _CONFIG_FILE_MODE
            or type(self.owner_uid) is not int or self.owner_uid != 0
            or type(self.group_gid) is not int or not 0 < self.group_gid <= MAX_UID_GID
            or type(self.nlink) is not int or self.nlink != 1
            or type(self.lifecycle) is not str or self.lifecycle != _CONFIG_LIFECYCLE
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True, kw_only=True)
class DevBrokerHostServiceContract:
    """Project one revalidated broker config into exact future host needs."""

    configuration: _Configuration

    def __post_init__(self) -> None:
        try:
            if type(self.configuration) is not _Configuration:
                raise TypeError
            # C32L also rejects forged cached C13 identity or static resources.
            sigstore = DevSigstoreResourceContract(configuration=self.configuration)
            configuration = sigstore.configuration
            if type(configuration.installation_contract()) is not DevHostInstallationContract:
                raise TypeError
            object.__setattr__(self, "configuration", configuration)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def _verified(self) -> tuple[DevSigstoreResourceContract, DevHostInstallationContract]:
        try:
            sigstore = DevSigstoreResourceContract(configuration=self.configuration)
            installation = sigstore.configuration.installation_contract()
            return sigstore, installation
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def broker_configuration_directory(self) -> HostResourceRequirement:
        sigstore, installation = self._verified()
        directory = sigstore.directory_requirements()[1]
        if (directory.path != _CONFIG_DIRECTORY
                or directory.owner_uid != 0
                or directory.group_gid != installation.broker_gid):
            raise ValueError(_ERROR)
        return directory

    def broker_configuration_file(self) -> BrokerConfigurationFileRequirement:
        _sigstore, installation = self._verified()
        return BrokerConfigurationFileRequirement(
            _CONFIG_PATH, "regular_file", _CONFIG_FILE_MODE, 0,
            installation.broker_gid, 1, _CONFIG_LIFECYCLE,
        )

    def canonical_configuration_bytes(self) -> bytes:
        sigstore, _installation = self._verified()
        return sigstore.configuration.canonical_bytes()

    def sigstore_resources(self) -> DevSigstoreResourceContract:
        sigstore, _installation = self._verified()
        return sigstore

    def runtime_directory_requirements(self) -> tuple[HostResourceRequirement, ...]:
        _sigstore, installation = self._verified()
        return (
            HostResourceRequirement("/run/omnilyzer", "directory", 0o755, 0, 0,
                                    _REQUIRED_LIFECYCLE),
            HostResourceRequirement("/run/omnilyzer/deployment", "directory", 0o755, 0, 0,
                                    _REQUIRED_LIFECYCLE),
            HostResourceRequirement("/run/omnilyzer/deployment/dev", "directory", 0o755, 0, 0,
                                    _REQUIRED_LIFECYCLE),
            HostResourceRequirement(_BLOB_RUNTIME_DIRECTORY, "directory", 0o700,
                                    installation.broker_uid, installation.broker_gid,
                                    _REQUIRED_LIFECYCLE),
            HostResourceRequirement(_OCI_RUNTIME_DIRECTORY, "directory", 0o700,
                                    installation.broker_uid, installation.broker_gid,
                                    _REQUIRED_LIFECYCLE),
        )

    def replay_requirements(self) -> tuple[HostResourceRequirement, HostResourceRequirement]:
        _sigstore, installation = self._verified()
        paths = (str(PRODUCTION_REPLAY_DATABASE.parent), str(PRODUCTION_REPLAY_DATABASE))
        selected = tuple(item for item in installation.resource_requirements()
                         if item.path in paths)
        if len(selected) != 2 or tuple(item.path for item in selected) != paths:
            raise ValueError(_ERROR)
        return selected

    def executor_socket_requirement(self) -> HostResourceRequirement:
        _sigstore, installation = self._verified()
        selected = tuple(item for item in installation.resource_requirements()
                         if item.path == PRODUCTION_EXECUTOR_SOCKET_PATH)
        if len(selected) != 1:
            raise ValueError(_ERROR)
        return selected[0]

    def service_layout(self) -> DevHostServiceLayout:
        self._verified()
        return DevHostServiceLayout()

    def broker_exec_argv(self) -> tuple[str, str, str]:
        layout = self.service_layout()
        return (layout.python_executable, "-m", _BROKER_MODULE)

    def broker_module(self) -> str:
        self._verified()
        return _BROKER_MODULE

    def broker_service_unit_name(self) -> str:
        self._verified()
        return _BROKER_SERVICE_UNIT

    def broker_principals(self) -> tuple[str, str, tuple[str, str]]:
        layout = self.service_layout()
        return (layout.broker_user, layout.broker_group,
                (layout.replay_group, layout.socket_group))

    def installed_asset_requirement(self) -> HostInstalledAssetRequirement:
        self._verified()
        return HostInstalledAssetRequirement(
            _UNIT_SOURCE, _UNIT_DESTINATION, _UNIT_SHA256, 0o644, 0, 0,
        )

    def writable_paths(self) -> tuple[str, str, str]:
        replay = self.replay_requirements()[0]
        runtime = self.runtime_directory_requirements()
        return (replay.path, runtime[3].path, runtime[4].path)

    def address_families(self) -> tuple[str, str, str]:
        self._verified()
        return ("AF_UNIX", "AF_INET", "AF_INET6")

    def loopback_bind(self) -> tuple[str, int]:
        self._verified()
        return _LOOPBACK_HOST, _LOOPBACK_PORT
