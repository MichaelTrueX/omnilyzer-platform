"""Pure C31A plan for future closed DEV host provisioning.

This module revalidates the reviewed C17/C24/C26/C27/C28/C31P inputs and
describes ordering and exact command requirements.  It performs no host
observation, filesystem access, process execution, provisioning or activation.
"""

from dataclasses import InitVar as _InitVar, dataclass as _dataclass
import hashlib as _hashlib

from . import application_manifest as _c26
from . import executor_service_config as _c17
from . import host_provisioning_contract as _c23
from . import installation_integrity_contract as _c24
from . import pip_installer_provenance as _c31p
from . import pip_installer_qualification as _pip_qualification
from . import python_interpreter_provenance as _c27
from . import wheelhouse_qualification as _c28

__all__ = (
    "ProvisioningPlanError",
    "ProvisioningStep",
    "DevHostProvisioningPlan",
    "build_dev_host_provisioning_plan",
)

_ERROR = "DEV host provisioning plan is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_RUNTIME_MANIFEST_PATH = (
    "deployment/provenance/python-runtime-py312-linux-x86_64-installed.json"
)
_RUNTIME_MANIFEST_SIZE = 57824
_RUNTIME_MANIFEST_SHA256 = (
    "92f5bd9d8db6fecc5880b82103a81e7c23d3efac68b70e9fc8634104e52bbdbe"
)
_RUNTIME_ENTRY_COUNT = 237
_BOUND_INSTALLER = "<identity-bound-pip-installer-wheel>"
_BOUND_RUNTIME = "<identity-bound-runtime-wheel-snapshot>"
_BOUND_LOCK = "<identity-bound-requirements-lock>"
_SNAPSHOT_ROOT = "/opt/omnilyzer/deployment/.provisioning-inputs"

_STEP_ROWS = (
    (1, "revalidate-c17-configuration", "C17"),
    (2, "reconstruct-c23-c24-authority", "C23/C24"),
    (3, "revalidate-c26-application-manifest", "C26"),
    (4, "construct-c27-interpreter-provenance", "C27"),
    (5, "freshly-qualify-c28-runtime-wheelhouse", "C28"),
    (6, "freshly-qualify-c31p-installer-staging", "C31P"),
    (7, "run-c29-pre-provision-host-qualification", "C29"),
    (8, "create-exact-c23-groups", "C30"),
    (9, "create-exact-c23-users", "C30"),
    (10, "create-exact-required-directories", "C30"),
    (11, "install-exact-c26-application-tree", "C31B/C30"),
    (12, "install-exact-c17-configuration", "C30"),
    (13, "install-exact-c22-c23-systemd-assets", "C30"),
    (14, "create-exact-no-pip-venv", "C31B/C30"),
    (15, "bind-fresh-c31p-qualification-to-consumption", "C31B/C30"),
    (16, "bind-fresh-c28-qualification-to-consumption", "C31B/C30"),
    (17, "install-exact-c24-runtime-wheels", "C31B/C30"),
    (18, "qualify-post-install-python-environment", "C31A"),
    (19, "establish-initial-deployment-state-prerequisites", "C31C"),
    (20, "initialize-replay-under-existing-lifecycle", "C31C"),
    (21, "establish-audit-prerequisites-preserving-history", "C31C"),
    (22, "verify-post-provision-convergence-and-integrity", "C31D"),
)

_VENV_ARGV = (
    "/usr/bin/python3.12", "-m", "venv", "--without-pip",
    "/opt/omnilyzer/deployment/venv",
)
_VENV_ENVIRONMENT = (
    ("HOME", "/nonexistent"),
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("PATH", "/usr/bin:/bin"),
)
_PIP_ARGUMENTS = (
    _BOUND_INSTALLER,
    "install",
    "--no-input",
    "--disable-pip-version-check",
    "--no-cache-dir",
    "--no-index",
    "--only-binary=:all:",
    "--no-deps",
    "--require-hashes",
    "--no-compile",
    "--find-links",
    _BOUND_RUNTIME,
    "--requirement",
    _BOUND_LOCK,
)
_PIP_ENVIRONMENT = (
    ("HOME", "/nonexistent"),
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("PATH", "/usr/bin:/bin"),
    ("PIP_CONFIG_FILE", "/dev/null"),
    ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
    ("PIP_NO_INDEX", "1"),
    ("PIP_NO_INPUT", "1"),
)
_C30_EXTENSIONS = (
    "materialize-exact-c26-application-tree",
    "materialize-identity-bound-python-input-snapshot",
    "construct-exact-no-pip-venv",
    "install-exact-offline-runtime-wheels",
    "remove-own-identity-bound-input-snapshot",
)
_LIFECYCLE = (
    "deployment-state: C31C owns fixed canonical no-active bootstrap bytes and "
    "sentinel metadata; initialize only an absent exact path; never reset existing state",
    "replay: initialize only an already-secured empty directory; never replace a database",
    "audit: establish prerequisites only; preserve every existing history entry",
)
_APPLICATION_SOURCE_MODEL = (
    "exact-reviewed-git-blob-bytes -> C26 path+sha256+0644 -> "
    "root-owned-0755-tree -> exact-post-install-verification"
)
_PROCESS_MODEL = (
    "absolute executable; exact internal argv; shell=False; stdin closed; "
    "closed environment; bounded output and timeout"
)
_VENV_PRECONDITION = (
    "C29-observed absent or exact empty C23 venv root; populated, symlinked or "
    "metadata-conflicting state fails without repair"
)
_CONSUMPTION_MODEL = (
    "C31B opens and verifies the untrusted C28/C31P sources, copies from those "
    "still-open descriptors into the fixed root-owned 0700 private snapshot, "
    "re-hashes and fsyncs it, retains snapshot identity through consumption, "
    "and removes only that C30-created identity afterward; directory ownership "
    "alone never confers byte trust"
)


class ProvisioningPlanError(Exception):
    """Reviewed inputs cannot produce the one closed C31A plan."""


@_dataclass(frozen=True, slots=True)
class ProvisioningStep:
    """One fixed sequence position without mutation or command authority."""

    sequence: int
    identifier: str
    boundary: str

    def __post_init__(self) -> None:
        if (
            type(self.sequence) is not int
            or type(self.identifier) is not str
            or type(self.boundary) is not str
            or (self.sequence, self.identifier, self.boundary) not in _STEP_ROWS
        ):
            raise ValueError(_ERROR)


_STEPS = tuple(ProvisioningStep(*row) for row in _STEP_ROWS)


def _inputs(
    configuration: object,
    application_manifest: object,
    wheelhouse_evidence: object,
    pip_installer_evidence: object,
) -> tuple[
    _c24.DevInstallationIntegrityContract,
    _c24.PythonEnvironmentIntegrityRequirement,
    _c31p.DevPipInstallerProvenance,
]:
    if type(configuration) is not _c17.DevExecutorServiceConfiguration:
        raise ValueError(_ERROR)
    integrity = _c24.DevInstallationIntegrityContract(configuration=configuration)
    _c23.DevHostProvisioningContract(
        installation=configuration.installation_contract(),
    )
    if type(application_manifest) is not _c26.DevApplicationManifest:
        raise ValueError(_ERROR)
    _c26.DevApplicationManifest.__post_init__(application_manifest)
    application = integrity.application_requirement()
    if (
        application_manifest.reviewed_commit != configuration.reviewed_commit
        or application_manifest.reviewed_commit != application.reviewed_commit
        or len(application_manifest.entries) != 28
    ):
        raise ValueError(_ERROR)
    environment = integrity.python_environment_requirement()
    interpreter = _c27.DevPythonInterpreterProvenance()
    _c27.DevPythonInterpreterProvenance.__post_init__(interpreter)
    if (
        interpreter.implementation,
        interpreter.python_series,
        interpreter.operating_system,
        interpreter.distribution,
        interpreter.architecture,
        interpreter.libc,
    ) != (
        environment.implementation,
        environment.python_series,
        environment.operating_system,
        environment.distribution,
        environment.architecture,
        environment.libc,
    ):
        raise ValueError(_ERROR)
    if type(wheelhouse_evidence) is not _c28.DevWheelhouseEvidence:
        raise ValueError(_ERROR)
    _c28.DevWheelhouseEvidence.__post_init__(wheelhouse_evidence, environment)
    if type(pip_installer_evidence) is not _pip_qualification.DevPipInstallerEvidence:
        raise ValueError(_ERROR)
    _pip_qualification.DevPipInstallerEvidence.__post_init__(pip_installer_evidence)
    installer = _c31p.DevPipInstallerProvenance()
    _c31p.DevPipInstallerProvenance.__post_init__(installer)
    if pip_installer_evidence.artifact != installer.artifact:
        raise ValueError(_ERROR)
    return integrity, environment, installer


@_dataclass(frozen=True, slots=True)
class DevHostProvisioningPlan:
    """Immutable exact C31A requirements; it cannot execute any step."""

    reviewed_commit: str
    application_manifest_sha256: str
    application_file_count: int
    application_source_model: str
    steps: tuple[ProvisioningStep, ...]
    venv_argv: tuple[str, ...]
    venv_environment: tuple[tuple[str, str], ...]
    venv_umask: int
    venv_precondition: str
    process_execution_model: str
    pip_python_executable: str
    pip_isolation_argument: str
    pip_bootstrap_source: str
    pip_arguments: tuple[str, ...]
    pip_environment: tuple[tuple[str, str], ...]
    pip_umask: int
    input_snapshot_root: str
    qualification_consumption_model: str
    runtime_manifest_path: str
    runtime_manifest_size: int
    runtime_manifest_sha256: str
    runtime_entry_count: int
    c30_extensions: tuple[str, ...]
    lifecycle_requirements: tuple[str, ...]
    configuration: _InitVar[_c17.DevExecutorServiceConfiguration]
    application_manifest: _InitVar[_c26.DevApplicationManifest]
    wheelhouse_evidence: _InitVar[_c28.DevWheelhouseEvidence]
    pip_installer_evidence: _InitVar[_pip_qualification.DevPipInstallerEvidence]

    def __post_init__(
        self,
        configuration: object,
        application_manifest: object,
        wheelhouse_evidence: object,
        pip_installer_evidence: object,
    ) -> None:
        try:
            _integrity, environment, installer = _inputs(
                configuration, application_manifest, wheelhouse_evidence,
                pip_installer_evidence,
            )
            expected = (
                (self.reviewed_commit, configuration.reviewed_commit),
                (self.application_manifest_sha256, _hashlib.sha256(
                    application_manifest.canonical_bytes()).hexdigest()),
                (self.application_file_count, 28),
                (self.application_source_model, _APPLICATION_SOURCE_MODEL),
                (self.steps, _STEPS),
                (self.venv_argv, _VENV_ARGV),
                (self.venv_environment, _VENV_ENVIRONMENT),
                (self.venv_umask, 0o022),
                (self.venv_precondition, _VENV_PRECONDITION),
                (self.process_execution_model, _PROCESS_MODEL),
                (self.pip_python_executable, environment.python_executable),
                (self.pip_isolation_argument, installer.invocation.isolation_argument),
                (self.pip_bootstrap_source, installer.invocation.bootstrap_source),
                (self.pip_arguments, _PIP_ARGUMENTS),
                (self.pip_environment, _PIP_ENVIRONMENT),
                (self.pip_umask, 0o022),
                (self.input_snapshot_root, _SNAPSHOT_ROOT),
                (self.qualification_consumption_model, _CONSUMPTION_MODEL),
                (self.runtime_manifest_path, _RUNTIME_MANIFEST_PATH),
                (self.runtime_manifest_size, _RUNTIME_MANIFEST_SIZE),
                (self.runtime_manifest_sha256, _RUNTIME_MANIFEST_SHA256),
                (self.runtime_entry_count, _RUNTIME_ENTRY_COUNT),
                (self.c30_extensions, _C30_EXTENSIONS),
                (self.lifecycle_requirements, _LIFECYCLE),
            )
            for actual, required in expected:
                if type(actual) is not type(required) or actual != required:
                    raise ValueError(_ERROR)
            if any(type(step) is not ProvisioningStep for step in self.steps):
                raise ValueError(_ERROR)
            for step in self.steps:
                ProvisioningStep.__post_init__(step)
        except _CONTROL:
            raise
        except Exception:
            raise ValueError(_ERROR) from None


def build_dev_host_provisioning_plan(
    *,
    configuration: _c17.DevExecutorServiceConfiguration,
    application_manifest: _c26.DevApplicationManifest,
    wheelhouse_evidence: _c28.DevWheelhouseEvidence,
    pip_installer_evidence: _pip_qualification.DevPipInstallerEvidence,
) -> DevHostProvisioningPlan:
    """Revalidate reviewed values and return the inert exact plan."""
    try:
        _integrity, environment, installer = _inputs(
            configuration, application_manifest, wheelhouse_evidence,
            pip_installer_evidence,
        )
        return DevHostProvisioningPlan(
            configuration.reviewed_commit,
            _hashlib.sha256(application_manifest.canonical_bytes()).hexdigest(),
            28,
            _APPLICATION_SOURCE_MODEL,
            _STEPS,
            _VENV_ARGV,
            _VENV_ENVIRONMENT,
            0o022,
            _VENV_PRECONDITION,
            _PROCESS_MODEL,
            environment.python_executable,
            installer.invocation.isolation_argument,
            installer.invocation.bootstrap_source,
            _PIP_ARGUMENTS,
            _PIP_ENVIRONMENT,
            0o022,
            _SNAPSHOT_ROOT,
            _CONSUMPTION_MODEL,
            _RUNTIME_MANIFEST_PATH,
            _RUNTIME_MANIFEST_SIZE,
            _RUNTIME_MANIFEST_SHA256,
            _RUNTIME_ENTRY_COUNT,
            _C30_EXTENSIONS,
            _LIFECYCLE,
            configuration,
            application_manifest,
            wheelhouse_evidence,
            pip_installer_evidence,
        )
    except _CONTROL:
        raise
    except Exception:
        raise ProvisioningPlanError(_ERROR) from None
