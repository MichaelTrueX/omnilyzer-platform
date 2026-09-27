"""Pure C32L future static-resource authority, separate from historical C23.

No filesystem inspection, installation or activation occurs. C32H/C13 own the
identity relationship, broker configuration owns fixed paths/modes, and C32I
owns reviewed artifact identity. This grants no continuing trust in staged paths.
"""

from dataclasses import dataclass, field, fields, is_dataclass

from . import broker_service_config as _config
from .installation_contract import HostResourceRequirement, MAX_UID_GID
from .sigstore_authority_provenance import DevSigstoreVerificationProvenance

__all__ = ("SigstoreStaticFileRequirement", "DevSigstoreResourceContract")
_ERROR = "DEV Sigstore static resource contract is invalid"
_LIFECYCLE = "must-exist-before-activation"


def _same(actual: object, expected: object) -> bool:
    """Compare exact immutable nested types as well as values; bool is not int."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is tuple:
        return len(actual) == len(expected) and all(
            _same(left, right) for left, right in zip(actual, expected, strict=True)
        )
    if is_dataclass(expected):
        return all(_same(getattr(actual, item.name), getattr(expected, item.name))
                   for item in fields(expected))
    return actual == expected


def _artifacts() -> tuple[tuple[str, int, int, str], ...]:
    provenance = DevSigstoreVerificationProvenance()
    provenance.__post_init__()
    if (not _same(_config.COSIGN_VERSION, provenance.cosign.version)
            or not _same(_config.COSIGN_BINARY_SIZE, provenance.cosign.asset_size)):
        raise ValueError(_ERROR)
    return (
        (_config.PRODUCTION_COSIGN_PATH, _config.COSIGN_BINARY_MODE,
         provenance.cosign.asset_size, provenance.cosign.asset_sha256),
        (_config.PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH,
         _config.BROKER_SERVICE_CONFIG_FILE_MODE,
         provenance.trusted_root.target_size, provenance.trusted_root.target_sha256),
    )


@dataclass(frozen=True, slots=True)
class SigstoreStaticFileRequirement:
    """Extend the existing C13 metadata model with exact artifact size/digest/link."""

    resource: HostResourceRequirement
    size: int
    sha256: str
    nlink: int = field(init=False, default=1)

    def __post_init__(self) -> None:
        try:
            if type(self.resource) is not HostResourceRequirement:
                raise ValueError
            HostResourceRequirement.__post_init__(self.resource)
            if not 0 < self.resource.group_gid <= MAX_UID_GID or not _same(self.nlink, 1):
                raise ValueError
            for path, mode, size, digest in _artifacts():
                expected = HostResourceRequirement(
                    path, "regular_file", mode, 0, self.resource.group_gid, _LIFECYCLE,
                )
                if (_same(self.resource, expected) and _same(self.size, size)
                        and _same(self.sha256, digest)):
                    return
            raise ValueError
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None


def _configuration(value: object) -> _config.DevBrokerServiceConfiguration:
    if type(value) is not _config.DevBrokerServiceConfiguration:
        raise ValueError
    # Reconstruct C32H rather than trusting a forged cached C13 relationship.
    validated = _config.DevBrokerServiceConfiguration.from_dict(value.to_dict())
    if not _same(value.installation_contract(), validated.installation_contract()):
        raise ValueError
    provenance = DevSigstoreVerificationProvenance()
    for name, expected in provenance.broker_service_configuration_kwargs().items():
        if not _same(getattr(validated, name), expected):
            raise ValueError
    return validated


def _requirements(configuration: _config.DevBrokerServiceConfiguration) -> tuple[
    tuple[HostResourceRequirement, ...], tuple[SigstoreStaticFileRequirement, ...],
]:
    gid = configuration.installation_contract().broker_gid
    directories = (
        HostResourceRequirement(_config.COSIGN_TOOLS_DIRECTORY, "directory",
                                _config.COSIGN_TOOLS_DIRECTORY_MODE, 0, gid, _LIFECYCLE),
        HostResourceRequirement(_config.BROKER_SERVICE_CONFIG_DIRECTORY, "directory",
                                _config.BROKER_SERVICE_CONFIG_DIRECTORY_MODE, 0, gid, _LIFECYCLE),
    )
    files = tuple(SigstoreStaticFileRequirement(
        HostResourceRequirement(path, "regular_file", mode, 0, gid, _LIFECYCLE), size, digest,
    ) for path, mode, size, digest in _artifacts())
    return directories, files


@dataclass(frozen=True, slots=True, kw_only=True)
class DevSigstoreResourceContract:
    """Closed future requirements from one revalidated existing broker config.

Schema 1 remains unchanged. The future installer must independently re-open,
re-qualify and bind the bytes it copies; C32K path evidence is not a handoff.
"""

    configuration: _config.DevBrokerServiceConfiguration
    _directories: tuple[HostResourceRequirement, ...] = field(init=False, repr=False)
    _files: tuple[SigstoreStaticFileRequirement, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            configuration = _configuration(self.configuration)
            directories, files = _requirements(configuration)
            if hasattr(self, "_directories") or hasattr(self, "_files"):
                # Revalidation must reject forged captured projections, not repair them.
                if not _same(self._directories, directories) or not _same(self._files, files):
                    raise ValueError
            else:
                object.__setattr__(self, "configuration", configuration)
                object.__setattr__(self, "_directories", directories)
                object.__setattr__(self, "_files", files)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def directory_requirements(self) -> tuple[HostResourceRequirement, ...]:
        """Return two immutable exact root:broker directory policies, with no I/O."""
        self.__post_init__()
        return self._directories

    def file_requirements(self) -> tuple[SigstoreStaticFileRequirement, ...]:
        """Return two immutable exact files and mandatory strong content identity."""
        self.__post_init__()
        return self._files
