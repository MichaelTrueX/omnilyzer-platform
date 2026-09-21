"""Closed, read-only C31D verification of a provisioned DEV host."""

from dataclasses import InitVar as _InitVar, dataclass as _dataclass
import hashlib as _hashlib

from . import application_manifest as _c26
from . import dev_host_qualification as _c29
from . import dev_persistent_state_prerequisites as _c31c
from . import executor_service_config as _c17
from . import host_provisioning_contract as _c23
from . import installation_integrity_contract as _c24
from . import python_environment_qualification as _python_environment
from . import python_interpreter_provenance as _c27

__all__ = (
    "PostProvisionQualificationError",
    "DevPostProvisionEvidence",
    "qualify_dev_provisioned_host",
)

_ERROR = "DEV post-provision qualification is unavailable"
_MODEL_ERROR = "DEV post-provision qualification evidence is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_CONFIG_PATH = "/etc/omnilyzer/deployment/dev/executor.json"
_SNAPSHOT_PATH = "/opt/omnilyzer/deployment/.provisioning-inputs"
_FUTURE_DIRECTORY = "future-systemd-socket-directory-creation-only"


class PostProvisionQualificationError(Exception):
    """The provisioned host did not exactly satisfy reviewed C31D state."""


def _authority(configuration: object, manifest: object):
    if type(configuration) is not _c17.DevExecutorServiceConfiguration:
        raise ValueError
    _c17.DevExecutorServiceConfiguration.__post_init__(configuration)
    integrity = _c24.DevInstallationIntegrityContract(configuration=configuration)
    provisioning = _c23.DevHostProvisioningContract(
        installation=configuration.installation_contract(),
    )
    if type(manifest) is not _c26.DevApplicationManifest:
        raise ValueError
    _c26.DevApplicationManifest.__post_init__(manifest)
    if manifest.reviewed_commit != configuration.reviewed_commit:
        raise ValueError
    provenance = _c27.DevPythonInterpreterProvenance()
    _c27.DevPythonInterpreterProvenance.__post_init__(provenance)
    environment = integrity.python_environment_requirement()
    if (
        provenance.implementation,
        provenance.python_series,
        provenance.operating_system,
        provenance.distribution,
        provenance.architecture,
        provenance.libc,
    ) != (
        environment.implementation,
        environment.python_series,
        environment.operating_system,
        environment.distribution,
        environment.architecture,
        environment.libc,
    ):
        raise ValueError
    return integrity, provisioning, provenance


def _managed_requirements(provisioning: _c23.DevHostProvisioningContract):
    paths = tuple(
        item for item in provisioning.path_requirements()
        if item.lifecycle != _FUTURE_DIRECTORY
    )
    persistent_directories = tuple(
        item for item in provisioning.runtime_resource_requirements()
        if item.kind == "directory"
    )
    assets = provisioning.installed_asset_requirements()
    return paths, persistent_directories, assets


@_dataclass(frozen=True, slots=True)
class DevPostProvisionEvidence:
    """Immutable factual observations of exact pre-activation convergence."""

    reviewed_commit: str
    application_manifest_sha256: str
    platform: _c29.HostPlatformObservation
    groups: tuple[_c29.HostGroupObservation, ...]
    users: tuple[_c29.HostUserObservation, ...]
    managed_paths: tuple[_c29.HostManagedPathObservation, ...]
    packages: tuple[_c29.HostPackageObservation, ...]
    payload_files: tuple[_c29.HostPayloadFileObservation, ...]
    application: _c29.HostApplicationObservation
    python_environment: _python_environment.DevPythonEnvironmentEvidence
    persistent_prerequisites: tuple[_c31c.PersistentPrerequisiteEvidence, ...]
    provisioning_snapshot: _c29.HostManagedPathObservation
    payload_manifest_sha256: str
    configuration: _InitVar[_c17.DevExecutorServiceConfiguration]
    application_manifest: _InitVar[_c26.DevApplicationManifest]

    def __post_init__(self, configuration: object, application_manifest: object) -> None:
        try:
            _integrity, provisioning, provenance = _authority(
                configuration, application_manifest,
            )
            paths, directories, assets = _managed_requirements(provisioning)
            expected_managed = tuple(
                (item.path, item.kind, item.mode, item.owner_uid, item.group_gid)
                for item in (*paths, *directories)
            ) + tuple(
                (item.destination_path, "regular_file", item.mode,
                 item.owner_uid, item.group_gid)
                for item in assets
            )
            if (
                type(self.reviewed_commit) is not str
                or self.reviewed_commit != configuration.reviewed_commit
                or type(self.application_manifest_sha256) is not str
                or self.application_manifest_sha256 != _hashlib.sha256(
                    application_manifest.canonical_bytes()
                ).hexdigest()
                or type(self.platform) is not _c29.HostPlatformObservation
                or type(self.groups) is not tuple
                or type(self.users) is not tuple
                or type(self.managed_paths) is not tuple
                or type(self.packages) is not tuple
                or type(self.payload_files) is not tuple
                or type(self.application) is not _c29.HostApplicationObservation
                or type(self.python_environment)
                is not _python_environment.DevPythonEnvironmentEvidence
                or type(self.persistent_prerequisites) is not tuple
                or type(self.provisioning_snapshot)
                is not _c29.HostManagedPathObservation
                or self.payload_manifest_sha256 != _c29._PAYLOAD_SHA256
            ):
                raise ValueError
            _c29.HostPlatformObservation.__post_init__(self.platform)
            if (
                (self.platform.system, self.platform.distribution,
                 self.platform.version, self.platform.machine,
                 self.platform.archive_architecture)
                != ("Linux", "Ubuntu", "24.04", "x86_64", "amd64")
                or not self.platform.libc.startswith("glibc ")
            ):
                raise ValueError
            expected_groups = provisioning.group_requirements()
            expected_users = provisioning.user_requirements()
            expected_payload = tuple(
                item["observation"] for item in _c29._load_payload(provenance)
            )
            if tuple(
                (item.name, item.gid, item.state) for item in self.groups
            ) != tuple((item.name, item.gid, "exact") for item in expected_groups):
                raise ValueError
            if tuple(
                (item.name, item.uid, item.primary_gid,
                 item.supplementary_gids, item.state)
                for item in self.users
            ) != tuple(
                (item.name, item.uid, item.primary_gid,
                 item.supplementary_gids, "exact")
                for item in expected_users
            ):
                raise ValueError
            if tuple(
                (item.path, item.kind, item.mode, item.owner_uid,
                 item.group_gid, item.state)
                for item in self.managed_paths
            ) != tuple((*item, "exact") for item in expected_managed):
                raise ValueError
            if tuple(
                (item.package, item.version, item.architecture, item.status)
                for item in self.packages
            ) != tuple(
                (item.package, item.version, item.architecture, "installed")
                for item in provenance.packages
            ):
                raise ValueError
            for collection, kind in (
                (self.groups, _c29.HostGroupObservation),
                (self.users, _c29.HostUserObservation),
                (self.managed_paths, _c29.HostManagedPathObservation),
                (self.packages, _c29.HostPackageObservation),
                (self.payload_files, _c29.HostPayloadFileObservation),
                (self.persistent_prerequisites,
                 _c31c.PersistentPrerequisiteEvidence),
            ):
                if any(type(item) is not kind for item in collection):
                    raise ValueError
                for item in collection:
                    kind.__post_init__(item)
            if self.payload_files != expected_payload:
                raise ValueError
            _c29.HostApplicationObservation.__post_init__(self.application)
            if (
                self.application.state != "exact"
                or self.application.root
                != _integrity.application_requirement().root
                or self.application.reviewed_commit != configuration.reviewed_commit
                or self.application.manifest_sha256
                != self.application_manifest_sha256
            ):
                raise ValueError
            _python_environment.DevPythonEnvironmentEvidence.__post_init__(
                self.python_environment,
            )
            if len(self.persistent_prerequisites) != 3:
                raise ValueError
            if tuple(
                (item.resource, item.kind, item.outcome)
                for item in self.persistent_prerequisites
            ) not in (
                (
                    ("/var/lib/omnilyzer/deployment/dev/state.json",
                     "deployment_state", "verified-initial"),
                    ("/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
                     "replay_database", "verified"),
                    ("/var/log/omnilyzer/deployment/dev/events.jsonl",
                     "audit_history", "pristine"),
                ),
                (
                    ("/var/lib/omnilyzer/deployment/dev/state.json",
                     "deployment_state", "verified-existing"),
                    ("/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
                     "replay_database", "verified"),
                    ("/var/log/omnilyzer/deployment/dev/events.jsonl",
                     "audit_history", "existing"),
                ),
                (
                    ("/var/lib/omnilyzer/deployment/dev/state.json",
                     "deployment_state", "verified-initial"),
                    ("/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
                     "replay_database", "verified"),
                    ("/var/log/omnilyzer/deployment/dev/events.jsonl",
                     "audit_history", "existing"),
                ),
                (
                    ("/var/lib/omnilyzer/deployment/dev/state.json",
                     "deployment_state", "verified-existing"),
                    ("/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
                     "replay_database", "verified"),
                    ("/var/log/omnilyzer/deployment/dev/events.jsonl",
                     "audit_history", "pristine"),
                ),
            ):
                raise ValueError
            _c29.HostManagedPathObservation.__post_init__(self.provisioning_snapshot)
            if (
                self.provisioning_snapshot.path != _SNAPSHOT_PATH
                or self.provisioning_snapshot.kind != "directory"
                or self.provisioning_snapshot.state != "absent"
                or self.provisioning_snapshot.mode != 0o700
                or self.provisioning_snapshot.owner_uid != 0
                or self.provisioning_snapshot.group_gid != 0
            ):
                raise ValueError
        except _CONTROL:
            raise
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


def qualify_dev_provisioned_host(
    *, configuration: _c17.DevExecutorServiceConfiguration,
    application_manifest: _c26.DevApplicationManifest,
) -> DevPostProvisionEvidence:
    """Read-only verify exact provisioned, pre-activation DEV host state."""

    try:
        _integrity, provisioning, provenance = _authority(
            configuration, application_manifest,
        )
        platform = _c29._platform_observation()
        packages = _c29._query_packages(provenance)
        payload = _c29._observe_payload(_c29._load_payload(provenance))
        groups, users = _c29._observe_principals(provisioning)
        if any(item.state != "exact" for item in (*groups, *users)):
            raise OSError
        paths, directories, assets = _managed_requirements(provisioning)
        observations = []
        for item in (*paths, *directories):
            expected = (
                configuration.canonical_bytes()
                if item.path == _CONFIG_PATH else None
            )
            observed = _c29._observe_managed_path(
                item.path, item.kind, item.mode,
                item.owner_uid, item.group_gid, expected,
            )
            if observed.state != "exact":
                raise OSError
            observations.append(observed)
        for asset in assets:
            observed = _c29._observe_managed_path(
                asset.destination_path, "regular_file", asset.mode,
                asset.owner_uid, asset.group_gid,
                expected_sha256=asset.sha256,
            )
            if observed.state != "exact":
                raise OSError
            observations.append(observed)
        application_requirement = _integrity.application_requirement()
        roots = tuple(
            item for item in provisioning.path_requirements()
            if item.path == application_requirement.root
        )
        if len(roots) != 1:
            raise OSError
        application = _c29._observe_application(
            application_manifest, application_requirement, roots[0],
        )
        if application.state != "exact":
            raise OSError
        python = _python_environment.qualify_dev_python_environment(
            configuration=configuration,
        )
        persistent = _c31c.DevPersistentStatePrerequisites(
            configuration=configuration,
        ).verify_persistent_prerequisites()
        snapshot = _c29._observe_managed_path(
            _SNAPSHOT_PATH, "directory", 0o700, 0, 0,
        )
        if snapshot.state != "absent":
            raise OSError
        result = DevPostProvisionEvidence(
            configuration.reviewed_commit,
            _hashlib.sha256(application_manifest.canonical_bytes()).hexdigest(),
            platform, groups, users, tuple(observations), packages, payload,
            application, python, persistent, snapshot, _c29._PAYLOAD_SHA256,
            configuration, application_manifest,
        )
        return result
    except _CONTROL:
        raise
    except Exception:
        raise PostProvisionQualificationError(_ERROR) from None
