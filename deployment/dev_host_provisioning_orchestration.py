"""Closed, inert C31D composition of the reviewed DEV provisioning steps."""

from dataclasses import InitVar as _InitVar, dataclass as _dataclass
import fcntl as _fcntl
import hashlib as _hashlib
import os as _os
from pathlib import PurePosixPath as _PurePosixPath
import stat as _stat
import sys as _sys
import threading as _threading

from . import application_manifest as _c26
from . import dev_host_provisioning_mechanics as _c31b
from . import dev_host_provisioning_plan as _c31a
from . import dev_host_qualification as _c29
from . import dev_persistent_state_prerequisites as _c31c
from . import dev_post_provision_qualification as _post
from . import executor_service_config as _c17
from . import host_provisioning_contract as _c23
from . import installation_integrity_contract as _c24
from . import pip_installer_qualification as _pip_qualification
from . import privileged_host_runtime as _c30
from . import python_environment_qualification as _python_environment
from . import python_interpreter_provenance as _c27
from . import wheelhouse_qualification as _c28

__all__ = (
    "ProvisioningOrchestrationError",
    "ProvisioningFailureEvidence",
    "ProvisioningStepEvidence",
    "DevHostProvisioningEvidence",
    "DevHostProvisioningOrchestrator",
)

_ERROR = "DEV host provisioning orchestration is unavailable"
_MODEL_ERROR = "DEV host provisioning orchestration evidence is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_PROCESS_LOCK_ANCHOR = "/usr/bin"
_CONFIG_PATH = "/etc/omnilyzer/deployment/dev/executor.json"
_FUTURE_DIRECTORY = "future-systemd-socket-directory-creation-only"

_STEP_OUTCOMES = {
    1: ("verified",), 2: ("verified",), 3: ("verified",),
    4: ("verified",), 5: ("verified",), 6: ("verified",),
    7: ("verified",),
    8: ("created", "unchanged"),
    9: ("created", "unchanged"),
    10: ("created", "unchanged"),
    11: ("materialized", "unchanged"),
    12: ("installed", "unchanged"),
    13: ("installed", "unchanged"),
    14: ("created",), 15: ("verified",), 16: ("verified",),
    17: ("installed",), 18: ("verified",),
    19: ("initialized", "unchanged", "existing"),
    20: ("initialized", "existing"),
    21: ("pristine", "existing"),
    22: ("verified",),
}


@_dataclass(frozen=True, slots=True)
class ProvisioningFailureEvidence:
    """Fixed plan position and mutation status; contains no failure payload."""

    last_completed_sequence: int
    failed_step: _c31a.ProvisioningStep
    mutation_started: bool

    def __post_init__(self) -> None:
        if (
            type(self.last_completed_sequence) is not int
            or not 0 <= self.last_completed_sequence <= 22
            or type(self.failed_step) is not _c31a.ProvisioningStep
            or self.failed_step is not _c31a._STEPS[
                min(self.last_completed_sequence, 21)
            ]
            or type(self.mutation_started) is not bool
            or (self.mutation_started and self.last_completed_sequence < 7)
            or (self.last_completed_sequence >= 8
                and not self.mutation_started
                and self.last_completed_sequence != 22)
        ):
            raise ValueError(_MODEL_ERROR)


class ProvisioningOrchestrationError(Exception):
    """Fixed failure message with closed, immutable operator evidence."""

    def __init__(self, evidence: ProvisioningFailureEvidence) -> None:
        if type(evidence) is not ProvisioningFailureEvidence:
            raise ValueError(_MODEL_ERROR)
        ProvisioningFailureEvidence.__post_init__(evidence)
        self.evidence = evidence
        super().__init__(_ERROR)


def _failure(completed: list["ProvisioningStepEvidence"],
             mutation_started: bool) -> ProvisioningOrchestrationError:
    last = completed[-1].sequence if completed else 0
    return ProvisioningOrchestrationError(ProvisioningFailureEvidence(
        last, _c31a._STEPS[min(last, 21)], mutation_started,
    ))


@_dataclass(frozen=True, slots=True)
class ProvisioningStepEvidence:
    """One factual completed plan position."""

    sequence: int
    identifier: str
    boundary: str
    outcome: str

    def __post_init__(self) -> None:
        try:
            expected = _c31a._STEPS[self.sequence - 1]
            if (
                type(self.sequence) is not int
                or not 1 <= self.sequence <= 22
                or type(expected) is not _c31a.ProvisioningStep
                or (self.identifier, self.boundary)
                != (expected.identifier, expected.boundary)
                or type(self.outcome) is not str
                or self.outcome not in _STEP_OUTCOMES[self.sequence]
            ):
                raise ValueError
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


@_dataclass(frozen=True, slots=True)
class DevHostProvisioningEvidence:
    """Immutable result of initial provisioning or a read-only converged rerun."""

    operation: str
    reviewed_commit: str
    application_manifest_sha256: str
    plan_steps: tuple[_c31a.ProvisioningStep, ...]
    completed_steps: tuple[ProvisioningStepEvidence, ...]
    convergence: _post.DevPostProvisionEvidence
    configuration: _InitVar[_c17.DevExecutorServiceConfiguration]
    application_manifest: _InitVar[_c26.DevApplicationManifest]

    def __post_init__(self, configuration: object, application_manifest: object) -> None:
        try:
            if (
                self.operation not in ("initial-provisioning", "already-converged")
                or type(self.operation) is not str
                or type(configuration) is not _c17.DevExecutorServiceConfiguration
                or type(application_manifest) is not _c26.DevApplicationManifest
                or self.reviewed_commit != configuration.reviewed_commit
                or self.application_manifest_sha256 != _hashlib.sha256(
                    application_manifest.canonical_bytes()
                ).hexdigest()
                or self.plan_steps != _c31a._STEPS
                or type(self.completed_steps) is not tuple
                or any(type(item) is not ProvisioningStepEvidence
                       for item in self.completed_steps)
                or type(self.convergence) is not _post.DevPostProvisionEvidence
            ):
                raise ValueError
            for step in self.plan_steps:
                if type(step) is not _c31a.ProvisioningStep:
                    raise ValueError
                _c31a.ProvisioningStep.__post_init__(step)
            for item in self.completed_steps:
                ProvisioningStepEvidence.__post_init__(item)
            sequences = tuple(item.sequence for item in self.completed_steps)
            expected = (
                tuple(range(1, 23))
                if self.operation == "initial-provisioning"
                else (1, 2, 3, 22)
            )
            if sequences != expected:
                raise ValueError
            _post.DevPostProvisionEvidence.__post_init__(
                self.convergence, configuration, application_manifest,
            )
        except _CONTROL:
            raise
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


@_dataclass(frozen=True, slots=True)
class _ProcessLock:
    directory_chain: tuple[
        tuple[int, int | None, str | None, tuple[int, ...]], ...
    ]
    descriptor: int


@_dataclass(frozen=True, slots=True)
class _Authority:
    configuration: _c17.DevExecutorServiceConfiguration
    integrity: _c24.DevInstallationIntegrityContract
    provisioning: _c23.DevHostProvisioningContract
    runtime: _c30.DevPrivilegedHostRuntime
    mechanics: _c31b.DevHostProvisioningMechanics
    persistent: _c31c.DevPersistentStatePrerequisites


def _build_authority(configuration: object) -> _Authority:
    if type(configuration) is not _c17.DevExecutorServiceConfiguration:
        raise TypeError(_MODEL_ERROR)
    try:
        _c17.DevExecutorServiceConfiguration.__post_init__(configuration)
        integrity = _c24.DevInstallationIntegrityContract(configuration=configuration)
        provisioning = _c23.DevHostProvisioningContract(
            installation=configuration.installation_contract(),
        )
        return _Authority(
            configuration, integrity, provisioning,
            _c30.DevPrivilegedHostRuntime(configuration=configuration),
            _c31b.DevHostProvisioningMechanics(configuration=configuration),
            _c31c.DevPersistentStatePrerequisites(configuration=configuration),
        )
    except _CONTROL:
        raise
    except Exception:
        raise TypeError(_MODEL_ERROR) from None


def _locator(value: object) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or value in ("", "/")
        or value.startswith("//")
        or "\0" in value
        or str(_PurePosixPath(value)) != value
        or any(part in ("", ".", "..") for part in value[1:].split("/"))
    ):
        raise ValueError
    return value


def _lock_identity(value: _os.stat_result) -> tuple[int, ...]:
    return (
        value.st_mode, value.st_dev, value.st_ino, value.st_uid, value.st_gid,
    )


def _acquire_process_lock(path: str = _PROCESS_LOCK_ANCHOR) -> _ProcessLock:
    """Nonblocking exclusion anchored to one retained directory identity."""

    path = _locator(path)
    descriptors = []
    chain = []
    flags = _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    try:
        root_named = _os.stat("/", follow_symlinks=False)
        root = _os.open("/", flags | _os.O_DIRECTORY)
        descriptors.append(root)
        root_opened = _os.fstat(root)
        if (
            not _stat.S_ISDIR(root_opened.st_mode)
            or _stat.S_ISLNK(root_named.st_mode)
            or _lock_identity(root_opened) != _lock_identity(root_named)
        ):
            raise OSError
        chain.append((root, None, None, _lock_identity(root_opened)))
        parent = root
        parts = path[1:].split("/")
        for component in parts:
            named = _os.stat(component, dir_fd=parent, follow_symlinks=False)
            if not _stat.S_ISDIR(named.st_mode) or _stat.S_ISLNK(named.st_mode):
                raise OSError
            child = _os.open(
                component, flags | _os.O_DIRECTORY, dir_fd=parent,
            )
            descriptors.append(child)
            opened = _os.fstat(child)
            if (
                not _stat.S_ISDIR(opened.st_mode)
                or _lock_identity(opened) != _lock_identity(named)
            ):
                raise OSError
            chain.append((
                child, parent, component, _lock_identity(opened),
            ))
            parent = child
        descriptor = parent
        _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        return _ProcessLock(tuple(chain), descriptor)
    except BaseException as error:
        for descriptor in reversed(descriptors):
            try:
                _os.close(descriptor)
            except BaseException:
                pass
        if isinstance(error, _CONTROL):
            raise
        raise OSError from None


def _release_process_lock(value: _ProcessLock) -> None:
    failed = False
    try:
        descriptor = value.descriptor
        if not value.directory_chain or value.directory_chain[-1][0] != descriptor:
            failed = True
        for directory, parent, name, identity in value.directory_chain:
            current = (
                _os.stat("/", follow_symlinks=False)
                if parent is None
                else _os.stat(name, dir_fd=parent, follow_symlinks=False)
            )
            if (
                _stat.S_ISLNK(current.st_mode)
                or not _stat.S_ISDIR(current.st_mode)
                or _lock_identity(_os.fstat(directory)) != identity
                or _lock_identity(current) != identity
            ):
                failed = True
        _fcntl.flock(descriptor, _fcntl.LOCK_UN)
    except _CONTROL:
        descriptors = tuple(item[0] for item in value.directory_chain)
        for descriptor in reversed(descriptors):
            try:
                _os.close(descriptor)
            except BaseException:
                pass
        raise
    except Exception:
        failed = True
    descriptors = tuple(item[0] for item in value.directory_chain)
    for descriptor in reversed(descriptors):
        try:
            _os.close(descriptor)
        except _CONTROL:
            raise
        except Exception:
            failed = True
    if failed:
        raise OSError


def _step(sequence: int, outcome: str) -> ProvisioningStepEvidence:
    planned = _c31a._STEPS[sequence - 1]
    return ProvisioningStepEvidence(
        planned.sequence, planned.identifier, planned.boundary, outcome,
    )


def _mutation(
    value: object, *, kind: str, resource: str,
) -> _c30.HostMutationEvidence:
    if type(value) is not _c30.HostMutationEvidence:
        raise OSError
    _c30.HostMutationEvidence.__post_init__(value)
    if value.resource_kind != kind or value.resource != resource:
        raise OSError
    return value


def _directory_requirements(provisioning: _c23.DevHostProvisioningContract):
    return tuple(
        item for item in provisioning.path_requirements()
        if item.kind == "directory" and item.lifecycle != _FUTURE_DIRECTORY
    ) + tuple(
        item for item in provisioning.runtime_resource_requirements()
        if item.kind == "directory"
    )


def _created_outcome(values: list[str]) -> str:
    if not values or any(value not in ("created", "unchanged") for value in values):
        raise OSError
    return "created" if "created" in values else "unchanged"


class DevHostProvisioningOrchestrator:
    """Compose only the reviewed 22-step provisioning sequence."""

    __slots__ = ("_authority", "_lock")

    def __init__(self, *, configuration: _c17.DevExecutorServiceConfiguration) -> None:
        object.__setattr__(self, "_authority", _build_authority(configuration))
        object.__setattr__(self, "_lock", _threading.Lock())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_MODEL_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_MODEL_ERROR)

    def provision(
        self, *, repository_root: str, wheelhouse_path: str,
        pip_installer_staging: str,
    ) -> DevHostProvisioningEvidence:
        """Run the exact composition, ending at read-only C31D verification."""

        local = object.__getattribute__(self, "_lock")
        if not local.acquire(blocking=False):
            raise _failure([], False) from None
        process_lock = None
        result = None
        failed = False
        completed = []
        mutation_started = False
        try:
            repository_root = _locator(repository_root)
            wheelhouse_path = _locator(wheelhouse_path)
            pip_installer_staging = _locator(pip_installer_staging)
            process_lock = _acquire_process_lock()
            authority = object.__getattribute__(self, "_authority")
            configuration = authority.configuration

            _c17.DevExecutorServiceConfiguration.__post_init__(configuration)
            completed.append(_step(1, "verified"))
            integrity = _c24.DevInstallationIntegrityContract(
                configuration=configuration,
            )
            provisioning = _c23.DevHostProvisioningContract(
                installation=configuration.installation_contract(),
            )
            completed.append(_step(2, "verified"))
            manifest = _c26.generate_dev_application_manifest(
                repository_root=repository_root,
                reviewed_commit=configuration.reviewed_commit,
            )
            if type(manifest) is not _c26.DevApplicationManifest:
                raise OSError
            _c26.DevApplicationManifest.__post_init__(manifest)
            completed.append(_step(3, "verified"))

            try:
                convergence = _post.qualify_dev_provisioned_host(
                    configuration=configuration,
                    application_manifest=manifest,
                )
            except _CONTROL:
                raise
            except _post.PostProvisionQualificationError:
                convergence = None
            if convergence is not None:
                completed.append(_step(22, "verified"))
                result = DevHostProvisioningEvidence(
                    "already-converged", configuration.reviewed_commit,
                    _hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
                    _c31a._STEPS, tuple(completed), convergence,
                    configuration, manifest,
                )
            else:
                provenance = _c27.DevPythonInterpreterProvenance()
                _c27.DevPythonInterpreterProvenance.__post_init__(provenance)
                completed.append(_step(4, "verified"))
                wheels = _c28.qualify_dev_wheelhouse(
                    wheelhouse_path=wheelhouse_path,
                    integrity_contract=integrity,
                )
                completed.append(_step(5, "verified"))
                installer = _pip_qualification.qualify_dev_pip_installer(
                    staging_directory=pip_installer_staging,
                )
                completed.append(_step(6, "verified"))
                plan = _c31a.build_dev_host_provisioning_plan(
                    configuration=configuration,
                    application_manifest=manifest,
                    wheelhouse_evidence=wheels,
                    pip_installer_evidence=installer,
                )
                if plan.steps != _c31a._STEPS:
                    raise OSError
                host = _c29.qualify_dev_host(
                    configuration=configuration,
                    application_manifest=manifest,
                    wheelhouse_evidence=wheels,
                )
                if type(host) is not _c29.DevHostQualificationEvidence:
                    raise OSError
                _c29.DevHostQualificationEvidence.__post_init__(host)
                snapshot = _c29._observe_managed_path(
                    _post._SNAPSHOT_PATH, "directory", 0o700, 0, 0,
                )
                if snapshot.state != "absent":
                    raise OSError
                completed.append(_step(7, "verified"))

                mutation_outcomes = []
                for requirement in provisioning.group_requirements():
                    create_group = authority.runtime.create_required_group
                    mutation_started = True
                    evidence = _mutation(
                        create_group(requirement.name),
                        kind="group", resource=requirement.name,
                    )
                    mutation_outcomes.append(evidence.outcome)
                completed.append(_step(8, _created_outcome(mutation_outcomes)))
                mutation_outcomes = []
                for requirement in provisioning.user_requirements():
                    evidence = _mutation(
                        authority.runtime.create_required_user(requirement.name),
                        kind="user", resource=requirement.name,
                    )
                    mutation_outcomes.append(evidence.outcome)
                completed.append(_step(9, _created_outcome(mutation_outcomes)))
                mutation_outcomes = []
                for requirement in _directory_requirements(provisioning):
                    evidence = _mutation(
                        authority.runtime.create_required_directory(requirement.path),
                        kind="directory", resource=requirement.path,
                    )
                    mutation_outcomes.append(evidence.outcome)
                completed.append(_step(10, _created_outcome(mutation_outcomes)))

                application = authority.mechanics.materialize_application_tree(
                    repository_root=repository_root,
                    application_manifest=manifest,
                )
                if type(application) is not _c31b.ApplicationMaterializationEvidence:
                    raise OSError
                _c31b.ApplicationMaterializationEvidence.__post_init__(application)
                if (
                    application.reviewed_commit != configuration.reviewed_commit
                    or application.manifest_sha256 != _hashlib.sha256(
                        manifest.canonical_bytes()
                    ).hexdigest()
                ):
                    raise OSError
                completed.append(_step(11, application.outcome))
                config_result = _mutation(
                    authority.runtime.install_executor_configuration(),
                    kind="regular_file", resource=_CONFIG_PATH,
                )
                completed.append(_step(
                    12, "unchanged" if config_result.outcome == "unchanged" else "installed",
                ))
                asset_outcomes = []
                assets = provisioning.installed_asset_requirements()
                if len(assets) != 2:
                    raise OSError
                for asset in assets:
                    asset_result = _mutation(
                        authority.runtime.install_required_asset(asset.destination_path),
                        kind="regular_file", resource=asset.destination_path,
                    )
                    asset_outcomes.append(asset_result.outcome)
                completed.append(_step(
                    13,
                    "unchanged" if set(asset_outcomes) == {"unchanged"} else "installed",
                ))

                python = authority.mechanics.construct_python_environment(
                    host_qualification=host,
                    repository_root=repository_root,
                    wheelhouse_path=wheelhouse_path,
                    pip_installer_staging=pip_installer_staging,
                )
                if type(python) is not _python_environment.DevPythonEnvironmentEvidence:
                    raise OSError
                _python_environment.DevPythonEnvironmentEvidence.__post_init__(python)
                for sequence, outcome in (
                    (14, "created"), (15, "verified"), (16, "verified"),
                    (17, "installed"), (18, "verified"),
                ):
                    completed.append(_step(sequence, outcome))

                state = authority.persistent.initialize_deployment_state()
                if type(state) is not _c31c.PersistentPrerequisiteEvidence:
                    raise OSError
                _c31c.PersistentPrerequisiteEvidence.__post_init__(state)
                completed.append(_step(19, state.outcome))
                replay = authority.persistent.initialize_replay()
                if type(replay) is not _c31c.PersistentPrerequisiteEvidence:
                    raise OSError
                _c31c.PersistentPrerequisiteEvidence.__post_init__(replay)
                completed.append(_step(20, replay.outcome))
                audit = authority.persistent.prepare_audit()
                if type(audit) is not _c31c.PersistentPrerequisiteEvidence:
                    raise OSError
                _c31c.PersistentPrerequisiteEvidence.__post_init__(audit)
                completed.append(_step(21, audit.outcome))

                convergence = _post.qualify_dev_provisioned_host(
                    configuration=configuration,
                    application_manifest=manifest,
                )
                if type(convergence) is not _post.DevPostProvisionEvidence:
                    raise OSError
                _post.DevPostProvisionEvidence.__post_init__(
                    convergence, configuration, manifest,
                )
                completed.append(_step(22, "verified"))
                result = DevHostProvisioningEvidence(
                    "initial-provisioning", configuration.reviewed_commit,
                    _hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
                    plan.steps, tuple(completed), convergence,
                    configuration, manifest,
                )
        except _CONTROL:
            raise
        except Exception:
            failed = True
        finally:
            active = _sys.exception()
            if process_lock is not None:
                try:
                    _release_process_lock(process_lock)
                except _CONTROL:
                    if not isinstance(active, _CONTROL):
                        local.release()
                        raise
                except Exception:
                    failed = True
            local.release()
        if failed or result is None:
            raise _failure(completed, mutation_started) from None
        return result
