"""File: deployment/c34q_python_runtime_compatibility.py

Purpose: Cross-check the C34P 73-file static Python import closure against
the EXISTING C24 wheel lock, C27 interpreter archive provenance, C31A
installed-environment model, C31P pip and C32H Sigstore trust requirements.
Related: deployment/c34p_dependency_source_closure.py,
deployment/installation_integrity_contract.py,
deployment/python_interpreter_provenance.py,
deployment/python_environment_qualification.py,
deployment/wheelhouse_qualification.py,
deployment/pip_installer_provenance.py,
deployment/sigstore_authority_provenance.py,
deployment/tests/test_c34q_python_runtime_compatibility.py.

All comparisons are pure/read-only requirements checks. This module does
NOT inspect or approve an installed host runtime, execute imported source,
verify a live protected GitHub branch, install packages, create a root-owned
environment, or authorize a migration. Both approval flags stay False.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Callable

from . import c34p_dependency_source_closure as _source
from . import installation_integrity_contract as _integrity
from . import python_interpreter_provenance as _interpreter
from . import python_environment_qualification as _environment
from . import pip_installer_provenance as _pip
from . import sigstore_authority_provenance as _sigstore
from .executor_service_config import DevExecutorServiceConfiguration


# Section 1: Fixed comparison domain, not a new wheel/interpreter authority.
_ERROR = "C34Q Python runtime compatibility evidence is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EXPECTED_DISTRIBUTIONS = (
    ("cffi", "2.1.1", "cffi-2.1.1.dist-info"),
    ("cryptography", "50.0.1", "cryptography-50.0.1.dist-info"),
    ("pycparser", "3.0", "pycparser-3.0.dist-info"),
    ("PyJWT", "2.13.0", "pyjwt-2.13.0.dist-info"),
)
_EXPECTED_IMPORT_ROOTS = ("cryptography",)
_EXPECTED_WHEEL_COUNT = 4
_EXPECTED_CLOSURE_SIZE = 73


class C34QPythonRuntimeError(Exception):
    """Expose one fixed HOLD status without source, wheel or host secrets."""


@dataclass(frozen=True, slots=True)
class C34QRuntimeCompatibilityReceipt:
    """Immutable requirement reconciliation; never actual host acceptance."""

    candidate_commit: str
    transitive_module_count: int
    source_manifest_sha256: str
    python_version_series: str
    expected_environment_root: str
    installed_tree_manifest_sha256_requirement: str
    dependency_lock_sha256: str
    wheel_sha256_pairs: tuple[tuple[str, str], ...]
    unresolved_import_roots: tuple[str, ...]
    runtime_requirement_consistent: bool
    installed_runtime_qualified: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Reject forged positive host approval and malformed authority pins."""
        if (
            type(self.candidate_commit) is not str
            or _source._SHA.fullmatch(self.candidate_commit) is None
            or type(self.transitive_module_count) is not int
            or self.transitive_module_count != _EXPECTED_CLOSURE_SIZE
            or type(self.source_manifest_sha256) is not str
            or _SHA256.fullmatch(self.source_manifest_sha256) is None
            or self.python_version_series != "3.12"
            or self.expected_environment_root != _environment._ROOT
            or self.installed_tree_manifest_sha256_requirement
            != _environment._MANIFEST_SHA256
            or self.dependency_lock_sha256 != _integrity._LOCK[1]
            or type(self.wheel_sha256_pairs) is not tuple
            or self.wheel_sha256_pairs != _integrity._WHEELS
            or self.unresolved_import_roots != _EXPECTED_IMPORT_ROOTS
            or self.runtime_requirement_consistent is not True
            or self.installed_runtime_qualified is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


def qualify_c34q_runtime_requirements(
    *, candidate_sha: str,
    blob_reader: Callable[[str], bytes],
    executor_configuration: DevExecutorServiceConfiguration,
) -> C34QRuntimeCompatibilityReceipt:
    """Reconcile original C24/C27/C31/C32 authorities with C34P Git evidence.

    The caller must independently authenticate the named Git object source.
    This function re-reads all transitive blobs through C34P and the pinned
    lockfile bytes, and never reaches the actual Python environment.
    """
    try:
        if (
            type(executor_configuration) is not DevExecutorServiceConfiguration
            or not callable(blob_reader)
        ):
            raise TypeError
        # Bind requirements to the actual candidate source/config identity.
        integrity = _integrity.DevInstallationIntegrityContract(
            configuration=executor_configuration,
        )
        environment_requirement = integrity.python_environment_requirement()
        if (
            environment_requirement.dependency_lock.path != _integrity._LOCK[0]
            or environment_requirement.dependency_lock.sha256
            != _integrity._LOCK[1]
            or tuple((item.filename, item.sha256)
                     for item in environment_requirement.wheels)
            != _integrity._WHEELS
            or len(environment_requirement.wheels) != _EXPECTED_WHEEL_COUNT
            or environment_requirement.source_builds_allowed is not False
            or environment_requirement.network_install_allowed is not False
            or environment_requirement.extra_wheels_allowed is not False
        ):
            raise ValueError

        closure = _source.inspect_c34p_git_blob_closure(
            candidate_sha=candidate_sha,
            blob_reader=blob_reader,
        )
        if (
            type(closure) is not _source.C34PSourceClosureReceipt
            or closure.reviewed_candidate_sha != candidate_sha
            or closure.local_module_count != _EXPECTED_CLOSURE_SIZE
            or closure.unresolved_third_party != _EXPECTED_IMPORT_ROOTS
            or closure.root_execution_approved is not False
        ):
            raise ValueError

        lock = blob_reader(environment_requirement.dependency_lock.path)
        if (
            type(lock) is not bytes or not 0 < len(lock) <= 16384
            or hashlib.sha256(lock).hexdigest()
            != environment_requirement.dependency_lock.sha256
            or lock.count(b"--hash=sha256:") != _EXPECTED_WHEEL_COUNT
        ):
            raise ValueError
        # The exact lock digest is the C24 primary authority; C31A's four
        # distribution records additionally reconcile the wheels at runtime.
        runtime_model = _environment.DevPythonEnvironmentEvidence()
        _environment.DevPythonEnvironmentEvidence.__post_init__(runtime_model)
        interpreter = _interpreter.DevPythonInterpreterProvenance()
        _interpreter.DevPythonInterpreterProvenance.__post_init__(interpreter)
        installer = _pip.DevPipInstallerProvenance()
        _pip.DevPipInstallerProvenance.__post_init__(installer)
        sigstore = _sigstore.DevSigstoreVerificationProvenance()
        _sigstore.DevSigstoreVerificationProvenance.__post_init__(sigstore)
        if (
            tuple((item.name, item.version, item.dist_info)
                  for item in runtime_model.distributions)
            != _EXPECTED_DISTRIBUTIONS
            or runtime_model.python_series != environment_requirement.python_series
            or runtime_model.python_executable
            != environment_requirement.python_executable
            or interpreter.python_series != environment_requirement.python_series
            or interpreter.operating_system != environment_requirement.operating_system
            or interpreter.architecture != environment_requirement.architecture
            or interpreter.libc != environment_requirement.libc
            or runtime_model.payload_manifest_sha256
            != _environment._MANIFEST_SHA256
        ):
            raise ValueError
        return C34QRuntimeCompatibilityReceipt(
            candidate_commit=candidate_sha,
            transitive_module_count=closure.local_module_count,
            source_manifest_sha256=closure.closure_manifest_sha256,
            python_version_series=interpreter.python_series,
            expected_environment_root=runtime_model.root,
            installed_tree_manifest_sha256_requirement=
                runtime_model.payload_manifest_sha256,
            dependency_lock_sha256=environment_requirement.dependency_lock.sha256,
            wheel_sha256_pairs=tuple(
                (item.filename, item.sha256) for item in environment_requirement.wheels
            ),
            unresolved_import_roots=closure.unresolved_third_party,
            runtime_requirement_consistent=True,
            installed_runtime_qualified=False,
            root_execution_approved=False,
        )
    except _CONTROL:
        raise
    except Exception:
        raise C34QPythonRuntimeError(_ERROR) from None


__all__ = (
    "C34QPythonRuntimeError",
    "C34QRuntimeCompatibilityReceipt",
    "qualify_c34q_runtime_requirements",
)
