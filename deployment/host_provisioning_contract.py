"""deployment/host_provisioning_contract.py — inert C23 DEV provisioning plan.

Project C13 numeric identities, derived memberships and runtime resources;
C17 config path/modes and canonical content authority; C18 real runtime
identity/group validation; C21 symbolic principals and service layout; and
C22 inert systemd source assets into future host requirements. C23 performs
no host I/O and creates no account/group/path/file/venv. It installs no unit
and grants no Docker/sudo/capability authority. Application and interpreter/
venv integrity and privileged runtime mechanics require separate review.
Deployment remains disabled pending GitHub branch/environment protections.
"""

from dataclasses import dataclass as _dataclass, field as _field
from pathlib import PurePosixPath as _PurePosixPath
from re import fullmatch as _fullmatch

from .installation_contract import (
    DevHostInstallationContract as _DevHostInstallationContract,
    HostResourceRequirement as _HostResourceRequirement,
    MAX_UID_GID as _MAX_UID_GID,
)
from .executor_service_config import (
    PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH as _CONFIG_PATH,
    EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE as _CONFIG_DIRECTORY_MODE,
    EXECUTOR_SERVICE_CONFIG_FILE_MODE as _CONFIG_FILE_MODE,
)
from .host_service_layout import DevHostServiceLayout as _DevHostServiceLayout

__all__ = (
    "HostGroupRequirement",
    "HostUserRequirement",
    "HostPathRequirement",
    "HostInstalledAssetRequirement",
    "DevHostProvisioningContract",
)

# Fixed errors and closed textual domains contain no operational authority.
_ERROR = "DEV host provisioning contract is invalid"
_KINDS = ("directory", "regular_file")
_LIFECYCLES = (
    "must-exist-before-activation",
    "must-contain-reviewed-application-before-activation",
    "must-contain-reviewed-venv-before-activation",
    "must-contain-c17-canonical-config-before-activation",
    "future-systemd-socket-directory-creation-only",
)
_SYSTEMD_ASSET_SHA256 = (
    "4211b0a4498548a54c4aedeaeb419aef84fb76d16f9da5f60a40b20be1daf95f",
    "a79a89ccd97c1de6b7038337ab1f7089c4dad501532e376a71a811854d1e8c86",
)


def _valid_id(value: object, *, positive: bool = False) -> bool:
    """Require an exact bounded identity without coercion or host lookup."""
    return type(value) is int and (1 if positive else 0) <= value <= _MAX_UID_GID


def _valid_name(value: object) -> bool:
    """Require C21-compatible lowercase ASCII symbolic principal syntax."""
    return type(value) is str and _fullmatch(r"[a-z][a-z0-9-]{0,30}", value) is not None


def _valid_path(value: object, *, absolute: bool) -> bool:
    """Validate canonical absolute or repository-relative POSIX text only."""
    if type(value) is not str or not value or "\0" in value:
        return False
    path = _PurePosixPath(value)
    return (
        path.is_absolute() is absolute
        and not value.startswith("//")
        and not value.endswith("/")
        and str(path) == value
        and all(part not in ("", ".", "..") for part in
                (value[1:] if absolute else value).split("/"))
    )


def _valid_metadata(mode: object, owner: object, group: object) -> bool:
    """Require exact bounded mode and numeric ownership metadata."""
    return (
        type(mode) is int and 0 <= mode <= 0o7777
        and _valid_id(owner) and _valid_id(group)
    )


# Immutable value classes describe metadata and memberships, never operations.
@_dataclass(frozen=True, slots=True)
class HostGroupRequirement:
    """Describe one positive named-group binding without resolving it."""

    name: str
    gid: int

    def __post_init__(self) -> None:
        """Reject malformed symbolic or numeric group values with a fixed error."""
        if not _valid_name(self.name) or not _valid_id(self.gid, positive=True):
            raise TypeError(_ERROR)


@_dataclass(frozen=True, slots=True)
class HostUserRequirement:
    """Describe a positive user identity and exact required group memberships."""

    name: str
    uid: int
    primary_gid: int
    supplementary_gids: tuple[int, ...]

    def __post_init__(self) -> None:
        """Validate immutable positive memberships without account discovery."""
        if (
            not _valid_name(self.name)
            or not _valid_id(self.uid, positive=True)
            or not _valid_id(self.primary_gid, positive=True)
            or type(self.supplementary_gids) is not tuple
            or not all(_valid_id(gid, positive=True) for gid in self.supplementary_gids)
            or len(frozenset(self.supplementary_gids)) != len(self.supplementary_gids)
            or self.primary_gid in self.supplementary_gids
        ):
            raise TypeError(_ERROR)


@_dataclass(frozen=True, slots=True)
class HostPathRequirement:
    """Describe one additional future path's metadata and lifecycle only."""

    path: str
    kind: str
    mode: int
    owner_uid: int
    group_gid: int
    lifecycle: str

    def __post_init__(self) -> None:
        """Validate textual path, closed domains and exact numeric metadata."""
        if (
            not _valid_path(self.path, absolute=True)
            or type(self.kind) is not str or self.kind not in _KINDS
            or not _valid_metadata(self.mode, self.owner_uid, self.group_gid)
            or type(self.lifecycle) is not str or self.lifecycle not in _LIFECYCLES
        ):
            raise TypeError(_ERROR)


@_dataclass(frozen=True, slots=True)
class HostInstalledAssetRequirement:
    """Bind one future installed destination to exact reviewed source bytes."""

    source_path: str
    destination_path: str
    sha256: str
    mode: int
    owner_uid: int
    group_gid: int

    def __post_init__(self) -> None:
        """Validate mapping text and metadata without reading or copying files."""
        if (
            not _valid_path(self.source_path, absolute=False)
            or not _valid_path(self.destination_path, absolute=True)
            or type(self.sha256) is not str
            or _fullmatch(r"[0-9a-f]{64}", self.sha256) is None
            or not _valid_metadata(self.mode, self.owner_uid, self.group_gid)
        ):
            raise TypeError(_ERROR)


# C23 consumes one exact validated C13 object; all other inputs remain fixed.
@_dataclass(frozen=True, slots=True, kw_only=True)
class DevHostProvisioningContract:
    """Project one C13 contract into the fixed C21/C22 future host topology."""

    installation: _DevHostInstallationContract
    _layout: _DevHostServiceLayout = _field(init=False, repr=False)
    _groups: tuple[HostGroupRequirement, ...] = _field(init=False, repr=False)
    _users: tuple[HostUserRequirement, ...] = _field(init=False, repr=False)
    _paths: tuple[HostPathRequirement, ...] = _field(init=False, repr=False)
    _assets: tuple[HostInstalledAssetRequirement, ...] = _field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Reject incompatible topology and cache immutable pure projections."""
        installation = self.installation
        if type(installation) is not _DevHostInstallationContract:
            raise TypeError(_ERROR)
        try:
            gids = (
                installation.broker_gid, installation.executor_gid,
                installation.replay_group_gid, installation.socket_group_gid,
            )
            ids = (installation.broker_uid, installation.executor_uid) + gids
            broker_memberships = installation.broker_required_group_gids
            executor_memberships = installation.executor_required_group_gids
            resources = installation.resource_requirements()
        except AttributeError:
            # An exact-type object can still be forged without C13 construction.
            raise TypeError(_ERROR) from None
        if (
            not all(_valid_id(value) for value in ids)
            or type(resources) is not tuple
            or not all(type(item) is _HostResourceRequirement for item in resources)
        ):
            raise TypeError(_ERROR)
        if (
            not all(value > 0 for value in ids)
            or installation.broker_uid == installation.executor_uid
            or len(frozenset(gids)) != 4
        ):
            raise ValueError(_ERROR)

        layout = _DevHostServiceLayout()
        groups = (
            HostGroupRequirement(layout.broker_group, installation.broker_gid),
            HostGroupRequirement(layout.executor_group, installation.executor_gid),
            HostGroupRequirement(layout.replay_group, installation.replay_group_gid),
            HostGroupRequirement(layout.socket_group, installation.socket_group_gid),
        )
        users = (
            HostUserRequirement(
                layout.broker_user, installation.broker_uid, installation.broker_gid,
                broker_memberships,
            ),
            HostUserRequirement(
                layout.executor_user, installation.executor_uid, installation.executor_gid,
                executor_memberships,
            ),
        )
        config_directory = _PurePosixPath(_CONFIG_PATH).parent
        socket_directory = _PurePosixPath(layout.executor_socket_path).parent
        paths = (
            HostPathRequirement(str(_PurePosixPath(layout.installation_root).parent),
                                "directory", 0o755, 0, 0, _LIFECYCLES[0]),
            HostPathRequirement(layout.installation_root, "directory", 0o755, 0, 0, _LIFECYCLES[0]),
            HostPathRequirement(layout.application_root, "directory", 0o755, 0, 0, _LIFECYCLES[1]),
            HostPathRequirement(layout.virtualenv_root, "directory", 0o755, 0, 0, _LIFECYCLES[2]),
            HostPathRequirement(str(config_directory.parent.parent),
                                "directory", 0o755, 0, 0, _LIFECYCLES[0]),
            HostPathRequirement(str(config_directory.parent),
                                "directory", 0o755, 0, 0, _LIFECYCLES[0]),
            HostPathRequirement(str(config_directory), "directory", _CONFIG_DIRECTORY_MODE,
                                0, installation.executor_gid, _LIFECYCLES[0]),
            HostPathRequirement(_CONFIG_PATH, "regular_file", _CONFIG_FILE_MODE,
                                0, installation.executor_gid, _LIFECYCLES[3]),
            HostPathRequirement("/var/lib/omnilyzer", "directory", 0o755, 0, 0, _LIFECYCLES[0]),
            HostPathRequirement("/var/lib/omnilyzer/deployment", "directory", 0o755, 0, 0, _LIFECYCLES[0]),
            HostPathRequirement(str(socket_directory.parent),
                                "directory", 0o755, 0, 0, _LIFECYCLES[4]),
            HostPathRequirement(str(socket_directory),
                                "directory", 0o755, 0, 0, _LIFECYCLES[4]),
        )
        path_names = frozenset(item.path for item in paths)
        if (
            len(path_names) != len(paths)
            or any(item.path in path_names for item in resources)
        ):
            raise ValueError(_ERROR)
        assets = (
            HostInstalledAssetRequirement(
                "deployment/systemd/dev/" + layout.executor_socket_unit_name,
                "/etc/systemd/system/" + layout.executor_socket_unit_name,
                _SYSTEMD_ASSET_SHA256[0], 0o644, 0, 0,
            ),
            HostInstalledAssetRequirement(
                "deployment/systemd/dev/" + layout.executor_service_unit_name,
                "/etc/systemd/system/" + layout.executor_service_unit_name,
                _SYSTEMD_ASSET_SHA256[1], 0o644, 0, 0,
            ),
        )
        object.__setattr__(self, "_layout", layout)
        object.__setattr__(self, "_groups", groups)
        object.__setattr__(self, "_users", users)
        object.__setattr__(self, "_paths", paths)
        object.__setattr__(self, "_assets", assets)

    def group_requirements(self) -> tuple[HostGroupRequirement, ...]:
        """Return the four fixed symbolic-to-C13-numeric group bindings."""
        return self._groups

    def user_requirements(self) -> tuple[HostUserRequirement, ...]:
        """Return broker/executor identities with C13's derived memberships."""
        return self._users

    def runtime_resource_requirements(self) -> tuple[_HostResourceRequirement, ...]:
        """Return C13's exact immutable resources without reconstruction."""
        return self.installation.resource_requirements()

    def path_requirements(self) -> tuple[HostPathRequirement, ...]:
        """Return the ordered additional paths, excluding C13 runtime resources."""
        return self._paths

    def installed_asset_requirements(self) -> tuple[HostInstalledAssetRequirement, ...]:
        """Return two descriptive C22 source-to-destination mappings only."""
        return self._assets

    def service_layout(self) -> _DevHostServiceLayout:
        """Return the internally fixed immutable C21 service layout."""
        return self._layout
