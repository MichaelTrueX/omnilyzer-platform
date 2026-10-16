"""File: deployment/c34r_installed_python_observation.py

Purpose: Reuse existing C31A's exact installed DEV virtualenv file-tree
qualification, and collect a bounded read-only witness of the system Python
binary, after independently consistent C34Q requirement reconciliation.
Related: deployment/c34q_python_runtime_compatibility.py,
deployment/python_environment_qualification.py,
deployment/python_interpreter_provenance.py,
deployment/installation_integrity_contract.py,
deployment/tests/test_c34r_installed_python_observation.py.

No installation, import from the inspected venv, subprocess execution, root
escalation, source write, service action, permission change or deployment.
The witnessed /usr/bin/python3.12 hash is NOT validated against a signed
Ubuntu .deb's installed-file hash: interpreter_package_approved=False.
The canonical protected root executor config cannot be read by omnigpt, so
installed_executor_config_verified=False and root_execution_approved=False.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat

from . import c34q_python_runtime_compatibility as requirements
from . import python_environment_qualification as environment
from .executor_service_config import DevExecutorServiceConfiguration


# Section 1 — Closed model, native program fingerprint and absolute path.
_ERROR = "C34R installed Python observation is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_INTERPRETER = "/usr/bin/python3.12"
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CHUNK = 65536
_BINARY_MAX = 64 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class C34RRuntimeObservationError(Exception):
    """Fail closed with a fixed, nonsecret error on all verification issues."""


@dataclass(frozen=True, slots=True)
class C34RInterpreterWitness:
    """Untrusted but stable byte observation of the fixed system executable."""

    path: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        """Require a stable nonempty file digest, never a provenance claim."""
        if (
            self.path != _INTERPRETER
            or type(self.sha256) is not str
            or _DIGEST.fullmatch(self.sha256) is None
            or type(self.size_bytes) is not int
            or not 0 < self.size_bytes <= _BINARY_MAX
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class C34RInstalledRuntimeReceipt:
    """Verified C31A virtualenv contents, without privileged runtime authority."""

    candidate_commit: str
    source_manifest_sha256: str
    populated_venv_manifest_sha256: str
    verified_regular_files: int
    verified_directories: int
    verified_symlinks: int
    interpreter: C34RInterpreterWitness
    installed_venv_tree_verified: bool
    interpreter_package_approved: bool = False
    installed_executor_config_verified: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Disallow converting nonroot observation into root authorization."""
        if (
            type(self.candidate_commit) is not str
            or requirements._source._SHA.fullmatch(self.candidate_commit) is None
            or type(self.source_manifest_sha256) is not str
            or _DIGEST.fullmatch(self.source_manifest_sha256) is None
            or self.populated_venv_manifest_sha256 != environment._MANIFEST_SHA256
            or type(self.verified_regular_files) is not int
            or self.verified_regular_files != environment._FILE_COUNT
            or type(self.verified_directories) is not int
            or self.verified_directories != environment._DIRECTORY_COUNT
            or type(self.verified_symlinks) is not int
            or self.verified_symlinks != environment._SYMLINK_COUNT
            or type(self.interpreter) is not C34RInterpreterWitness
            or self.installed_venv_tree_verified is not True
            or self.interpreter_package_approved is not False
            or self.installed_executor_config_verified is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    """Protect against inode or metadata mutation during a bounded file read."""
    return (
        value.st_dev, value.st_ino, value.st_mode,
        value.st_uid, value.st_gid, value.st_nlink,
        value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def _read_system_interpreter_witness() -> C34RInterpreterWitness:
    """Read, hash and revalidate fixed root-owned CPython binary, without executing it."""
    fd = os.open(_INTERPRETER, _FLAGS)
    try:
        named = os.stat(_INTERPRETER, follow_symlinks=False)
        original = os.fstat(fd)
        if (
            _fingerprint(original) != _fingerprint(named)
            or not stat.S_ISREG(original.st_mode)
            or stat.S_IMODE(original.st_mode) != 0o755
            or (original.st_uid, original.st_gid, original.st_nlink) != (0, 0, 1)
            or not 0 < original.st_size <= _BINARY_MAX
        ):
            raise ValueError
        digest = hashlib.sha256()
        left = original.st_size
        while left:
            block = os.read(fd, min(_CHUNK, left))
            if type(block) is not bytes or not block:
                raise ValueError
            digest.update(block)
            left -= len(block)
        if (
            os.read(fd, 1) != b""
            or _fingerprint(os.fstat(fd)) != _fingerprint(original)
            or _fingerprint(os.stat(_INTERPRETER, follow_symlinks=False))
            != _fingerprint(original)
        ):
            raise ValueError
        return C34RInterpreterWitness(
            path=_INTERPRETER,
            sha256=digest.hexdigest(),
            size_bytes=original.st_size,
        )
    finally:
        os.close(fd)


def inspect_c34r_installed_python_readonly(
    *, executor_configuration: DevExecutorServiceConfiguration,
    requirement_receipt: requirements.C34QRuntimeCompatibilityReceipt,
) -> C34RInstalledRuntimeReceipt:
    """Reuse C31A's full 237-entry installed tree qualification read-only.

    An independently reviewed candidate's C34Q receipt is a requirement
    input only. This function cannot verify the inaccessible live executor
    config, protected GitHub main, or signed Ubuntu binary/ABI provenance.
    """
    try:
        if (
            type(executor_configuration) is not DevExecutorServiceConfiguration
            or type(requirement_receipt) is not
            requirements.C34QRuntimeCompatibilityReceipt
        ):
            raise ValueError
        requirements.C34QRuntimeCompatibilityReceipt.__post_init__(
            requirement_receipt,
        )
        if (
            executor_configuration.reviewed_commit
            != requirement_receipt.candidate_commit
            or requirement_receipt.runtime_requirement_consistent is not True
            or requirement_receipt.installed_runtime_qualified is not False
            or requirement_receipt.root_execution_approved is not False
        ):
            raise ValueError
        witness_before = _read_system_interpreter_witness()
        installed = environment.qualify_dev_python_environment(
            configuration=executor_configuration,
        )
        if type(installed) is not environment.DevPythonEnvironmentEvidence:
            raise ValueError
        environment.DevPythonEnvironmentEvidence.__post_init__(installed)
        witness_after = _read_system_interpreter_witness()
        if witness_before != witness_after:
            raise ValueError
        return C34RInstalledRuntimeReceipt(
            candidate_commit=requirement_receipt.candidate_commit,
            source_manifest_sha256=requirement_receipt.source_manifest_sha256,
            populated_venv_manifest_sha256=installed.payload_manifest_sha256,
            verified_regular_files=installed.regular_file_count,
            verified_directories=installed.directory_count,
            verified_symlinks=installed.symbolic_link_count,
            interpreter=witness_after,
            installed_venv_tree_verified=True,
        )
    except _CONTROL:
        raise
    except Exception:
        raise C34RRuntimeObservationError(_ERROR) from None


__all__ = (
    "C34RRuntimeObservationError", "C34RInterpreterWitness",
    "C34RInstalledRuntimeReceipt",
    "inspect_c34r_installed_python_readonly",
)
