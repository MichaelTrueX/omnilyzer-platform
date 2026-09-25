"""Closed, inert C31B mechanics for future DEV host provisioning.

The two public operations have repository-contract-derived destinations and
commands.  Construction performs no I/O.  This module is not composed into the
deployment executor, broker, listener, workflow or any service entry point.
"""

from dataclasses import dataclass as _dataclass
import hashlib as _hashlib
import os as _os
from pathlib import PurePosixPath as _PurePosixPath
import re as _re
import selectors as _selectors
import stat as _stat
import subprocess as _subprocess
import sys as _sys
import threading as _threading
import time as _time

from . import application_manifest as _c26
from . import application_source_set as _c25
from . import dev_host_qualification as _c29
from . import executor_service_config as _c17
from . import host_provisioning_contract as _c23
from . import installation_integrity_contract as _c24
from . import pip_installer_provenance as _c31p
from . import pip_installer_qualification as _pip_qualification
from . import python_environment_qualification as _python_qualification
from . import python_interpreter_provenance as _c27
from . import wheelhouse_qualification as _c28

__all__ = (
    "ProvisioningMechanicsError",
    "ApplicationMaterializationEvidence",
    "DevHostProvisioningMechanics",
)

_ERROR = "DEV host provisioning mechanics are unavailable"
_MODEL_ERROR = "DEV host provisioning mechanics evidence is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_GIT = "/usr/bin/git"
_SYSTEM_PYTHON = "/usr/bin/python3.12"
_CHUNK = 64 * 1024
_MAX_BLOB = 1024 * 1024
_MAX_APPLICATION = 8 * 1024 * 1024
_MAX_INPUT = 32 * 1024 * 1024
_GIT_TIMEOUT = 5.0
_VENV_TIMEOUT = 30.0
_PIP_TIMEOUT = 120.0
_APPLICATION_TEMPORARY = ".omnilyzer-c31b-application.tmp"
_SNAPSHOT_NAME = ".provisioning-inputs"
_SNAPSHOT_DIRECTORIES = ("pip", "requirements", "wheels")
_LOCK_NAME = "requirements-linux-x86_64-py312.lock"
_VENV_ENVIRONMENT = {
    "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
_PIP_ENVIRONMENT = {
    **_VENV_ENVIRONMENT,
    "PIP_CONFIG_FILE": "/dev/null",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INDEX": "1",
    "PIP_NO_INPUT": "1",
}
_PYTHON_PHASES = (
    "operation-entry", "host-qualification", "repository-open",
    "snapshot-preparation", "repository-revalidation", "snapshot-validation",
    "venv-precondition", "argv-construction", "venv-command",
    "preinstall-venv-verification", "post-venv-snapshot-validation",
    "pip-command", "post-pip-snapshot-validation", "python-qualification",
    "snapshot-cleanup", "descriptor-cleanup",
)


class ProvisioningMechanicsError(Exception):
    """One closed C31B mechanic could not complete exactly."""

    def __init__(self, phase: str | None = None) -> None:
        if phase is not None and (type(phase) is not str or phase not in _PYTHON_PHASES):
            raise ValueError(_MODEL_ERROR)
        self.phase = phase
        super().__init__(_ERROR)


@_dataclass(frozen=True, slots=True)
class ApplicationMaterializationEvidence:
    """Explicit result for the exact C26 application tree."""

    root: str
    reviewed_commit: str
    manifest_sha256: str
    regular_file_count: int
    outcome: str

    def __post_init__(self) -> None:
        if (
            type(self.root) is not str
            or self.root != "/opt/omnilyzer/deployment/app"
            or type(self.reviewed_commit) is not str
            or _re.fullmatch(r"[0-9a-f]{40}", self.reviewed_commit) is None
            or type(self.manifest_sha256) is not str
            or _re.fullmatch(r"[0-9a-f]{64}", self.manifest_sha256) is None
            or type(self.regular_file_count) is not int
            or self.regular_file_count != 28
            or type(self.outcome) is not str
            or self.outcome not in ("materialized", "unchanged")
        ):
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class _Paths:
    application_root: str
    venv_root: str
    python_executable: str
    deployment_root: str
    snapshot_root: str
    repository_lock: str


@_dataclass(frozen=True, slots=True)
class _Authority:
    configuration: _c17.DevExecutorServiceConfiguration
    integrity: _c24.DevInstallationIntegrityContract
    provisioning: _c23.DevHostProvisioningContract
    paths: _Paths
    application_uid: int
    application_gid: int
    venv_uid: int
    venv_gid: int


@_dataclass(frozen=True, slots=True)
class _OpenFile:
    descriptor: int
    parent: int
    name: str
    fingerprint: tuple[int, ...]
    size: int
    sha256: str


@_dataclass(frozen=True, slots=True)
class _Snapshot:
    parent: int
    root: int
    directories: tuple[tuple[str, int, tuple[int, int]], ...]
    files: tuple[tuple[int, str, int, tuple[int, ...], int, str], ...]
    root_identity: tuple[int, int]
    pip_wheel: str
    wheel_directory: str
    lock_file: str


def _default_paths(
    environment: _c24.PythonEnvironmentIntegrityRequirement,
    application: _c24.ApplicationIntegrityRequirement,
) -> _Paths:
    deployment = str(_PurePosixPath(environment.root).parent)
    return _Paths(
        application.root,
        environment.root,
        environment.python_executable,
        deployment,
        deployment + "/" + _SNAPSHOT_NAME,
        environment.dependency_lock.path,
    )


def _build_authority(configuration: object) -> _Authority:
    if type(configuration) is not _c17.DevExecutorServiceConfiguration:
        raise TypeError(_MODEL_ERROR)
    try:
        integrity = _c24.DevInstallationIntegrityContract(configuration=configuration)
        provisioning = _c23.DevHostProvisioningContract(
            installation=configuration.installation_contract(),
        )
        environment = integrity.python_environment_requirement()
        application = integrity.application_requirement()
        interpreter = _c27.DevPythonInterpreterProvenance()
        _c27.DevPythonInterpreterProvenance.__post_init__(interpreter)
        if (
            interpreter.implementation != environment.implementation
            or interpreter.python_series != environment.python_series
            or environment.python_executable != "/opt/omnilyzer/deployment/venv/bin/python"
        ):
            raise ValueError
        requirements = provisioning.path_requirements()
        application_paths = tuple(item for item in requirements if item.path == application.root)
        venv_paths = tuple(item for item in requirements if item.path == environment.root)
        if (
            len(application_paths) != 1
            or len(venv_paths) != 1
            or application_paths[0].kind != "directory"
            or application_paths[0].mode != 0o755
            or venv_paths[0].kind != "directory"
            or venv_paths[0].mode != 0o755
        ):
            raise ValueError
        return _Authority(
            configuration, integrity, provisioning,
            _default_paths(environment, application),
            application_paths[0].owner_uid, application_paths[0].group_gid,
            venv_paths[0].owner_uid, venv_paths[0].group_gid,
        )
    except _CONTROL:
        raise
    except Exception:
        raise TypeError(_MODEL_ERROR) from None


def _fingerprint(value: _os.stat_result) -> tuple[int, ...]:
    return (
        value.st_mode, value.st_ino, value.st_dev, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _identity(value: _os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _fingerprint_identity(value: tuple[int, ...]) -> tuple[int, int]:
    if type(value) is not tuple or len(value) != 9:
        raise OSError
    return value[2], value[1]


def _directory_fingerprint(value: _os.stat_result) -> tuple[int, ...]:
    return value.st_mode, value.st_ino, value.st_dev, value.st_uid, value.st_gid


def _claim(value: object, owned: list[int]) -> int:
    if type(value) is not int or value < 0 or value in owned:
        raise OSError
    owned.append(value)
    if _os.get_inheritable(value) is not False:
        raise OSError
    return value


def _close(owned: list[int]) -> tuple[bool, BaseException | None]:
    failed = False
    control = None
    for descriptor in reversed(owned):
        try:
            if _os.close(descriptor) is not None:
                failed = True
        except _CONTROL as error:
            if control is None:
                control = error
        except Exception:
            failed = True
    owned.clear()
    return failed, control


def _finish_close(owned: list[int]) -> None:
    """Make descriptor cleanup observable without masking an active failure."""
    active = _sys.exception()
    failed, control = _close(owned)
    if control is not None and not isinstance(active, _CONTROL):
        raise control
    if failed and active is None:
        raise OSError


def _path(value: object) -> str:
    if (
        type(value) is not str
        or value in ("", "/")
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or "\0" in value
        or any(part in ("", ".", "..") for part in value[1:].split("/"))
    ):
        raise OSError
    return value


def _directory(value: _os.stat_result) -> _os.stat_result:
    if not _stat.S_ISDIR(value.st_mode) or _stat.S_ISLNK(value.st_mode):
        raise OSError
    return value


def _regular(value: _os.stat_result, maximum: int = _MAX_INPUT) -> _os.stat_result:
    if (
        not _stat.S_ISREG(value.st_mode)
        or _stat.S_ISLNK(value.st_mode)
        or value.st_nlink != 1
        or value.st_size < 0
        or value.st_size > maximum
    ):
        raise OSError
    return value


def _names(directory: int) -> tuple[str, ...]:
    with _os.scandir(directory) as iterator:
        names = tuple(sorted(entry.name for entry in iterator))
    if any(type(name) is not str or not name or "/" in name or "\0" in name for name in names):
        raise OSError
    return names


def _open_directory(path: str, owned: list[int]) -> tuple[int, list[tuple[int, int | None, str | None, tuple[int, ...]]]]:
    _path(path)
    flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    root_named = _directory(_os.stat("/", follow_symlinks=False))
    parent = _claim(_os.open("/", flags), owned)
    root_opened = _directory(_os.fstat(parent))
    if _identity(root_named) != _identity(root_opened):
        raise OSError
    chain = [(parent, None, None, _directory_fingerprint(root_opened))]
    for component in path[1:].split("/"):
        named = _directory(_os.stat(component, dir_fd=parent, follow_symlinks=False))
        child = _claim(_os.open(component, flags, dir_fd=parent), owned)
        opened = _directory(_os.fstat(child))
        if _identity(named) != _identity(opened):
            raise OSError
        chain.append((child, parent, component, _directory_fingerprint(opened)))
        parent = child
    return parent, chain


def _open_parent(path: str, owned: list[int]) -> tuple[int, str, list]:
    target = _path(path)
    parent_path, name = target.rsplit("/", 1)
    parent, chain = _open_directory(parent_path or "/", owned)
    return parent, name, chain


def _revalidate_chain(chain: list[tuple[int, int | None, str | None, tuple[int, ...]]]) -> None:
    for descriptor, parent, name, expected in chain:
        if _directory_fingerprint(_directory(_os.fstat(descriptor))) != expected:
            raise OSError
        named = (
            _os.stat("/", follow_symlinks=False)
            if parent is None
            else _os.stat(name, dir_fd=parent, follow_symlinks=False)
        )
        if _directory_fingerprint(_directory(named)) != expected:
            raise OSError


def _read_hash(descriptor: int, size: int, maximum: int) -> tuple[bytes, str]:
    if type(size) is not int or not 0 <= size <= maximum:
        raise OSError
    value = bytearray()
    digest = _hashlib.sha256()
    remaining = size
    while remaining:
        chunk = _os.read(descriptor, min(_CHUNK, remaining))
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            raise OSError
        value.extend(chunk)
        digest.update(chunk)
        remaining -= len(chunk)
    if _os.read(descriptor, 1) != b"":
        raise OSError
    return bytes(value), digest.hexdigest()


def _write_all(descriptor: int, payload: bytes) -> None:
    position = 0
    while position < len(payload):
        count = _os.write(descriptor, payload[position:position + _CHUNK])
        if type(count) is not int or count <= 0 or count > min(_CHUNK, len(payload) - position):
            raise OSError
        position += count


def _run_git(repository: int, arguments: tuple[str, ...], maximum: int) -> bytes:
    if (
        type(arguments) is not tuple
        or not arguments
        or arguments[0] not in ("rev-parse", "ls-tree", "cat-file")
        or any(type(item) is not str or not item for item in arguments)
        or type(maximum) is not int
        or not 0 <= maximum <= _MAX_APPLICATION
    ):
        raise OSError
    root = "/proc/self/fd/" + str(repository)
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
        "GIT_LITERAL_PATHSPECS": "1",
    }
    process = _subprocess.Popen(
        (_GIT, "--no-replace-objects", "-C", root, *arguments),
        stdin=_subprocess.DEVNULL, stdout=_subprocess.PIPE,
        stderr=_subprocess.DEVNULL, env=environment, shell=False,
        close_fds=True, pass_fds=(repository,),
    )
    try:
        if process.stdout is None:
            raise OSError
        output = bytearray()
        deadline = _time.monotonic() + _GIT_TIMEOUT
        with _selectors.DefaultSelector() as selector:
            selector.register(process.stdout, _selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - _time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                for key, _mask in selector.select(remaining):
                    chunk = _os.read(key.fileobj.fileno(), min(_CHUNK, maximum + 1 - len(output)))
                    if type(chunk) is not bytes:
                        raise OSError
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > maximum:
                            raise OSError
        remaining = deadline - _time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise OSError
        return bytes(output)
    finally:
        try:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=_GIT_TIMEOUT)
        finally:
            if process.stdout is not None:
                process.stdout.close()


def _application_blobs(
    repository_root: str,
    configuration: _c17.DevExecutorServiceConfiguration,
    manifest: _c26.DevApplicationManifest,
) -> tuple[tuple[str, bytes], ...]:
    if type(manifest) is not _c26.DevApplicationManifest:
        raise OSError
    _c26.DevApplicationManifest.__post_init__(manifest)
    if manifest.reviewed_commit != configuration.reviewed_commit:
        raise OSError
    owned: list[int] = []
    try:
        repository, chain = _open_directory(repository_root, owned)
        commit = configuration.reviewed_commit
        if _run_git(repository, ("rev-parse", "--verify", "HEAD^{commit}"), 41) != commit.encode() + b"\n":
            raise OSError
        paths = tuple(entry.path for entry in manifest.entries)
        tree = _run_git(
            repository,
            ("ls-tree", "-r", "-z", "--full-tree", commit, "--", *paths),
            16 * 1024,
        )
        expected_tree = b"".join(
            b"100644 blob " + _run_git(
                repository, ("rev-parse", commit + ":" + path), 41,
            ).strip() + b"\t" + path.encode("ascii") + b"\0"
            for path in paths
        )
        if tree != expected_tree:
            raise OSError
        blobs = []
        total = 0
        for entry in manifest.entries:
            payload = _run_git(
                repository, ("cat-file", "blob", commit + ":" + entry.path),
                _MAX_BLOB,
            )
            total += len(payload)
            if total > _MAX_APPLICATION or _hashlib.sha256(payload).hexdigest() != entry.sha256:
                raise OSError
            blobs.append((entry.path, payload))
        if _run_git(repository, ("rev-parse", "--verify", "HEAD^{commit}"), 41) != commit.encode() + b"\n":
            raise OSError
        _revalidate_chain(chain)
        return tuple(blobs)
    finally:
        _finish_close(owned)


def _ensure_exact_directory(parent: int, name: str, mode: int, uid: int, gid: int) -> tuple[int, bool, tuple[int, int]]:
    flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    created = False
    descriptor = None
    identity = None
    try:
        try:
            named = _os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            if _os.mkdir(name, 0o700, dir_fd=parent) is not None:
                raise OSError
            created = True
            named = _os.stat(name, dir_fd=parent, follow_symlinks=False)
            identity = _identity(named)
        descriptor = _os.open(name, flags, dir_fd=parent)
        opened = _directory(_os.fstat(descriptor))
        if _identity(named) != _identity(opened):
            raise OSError
        identity = _identity(opened)
        if created:
            if (opened.st_uid, opened.st_gid) != (uid, gid):
                _os.fchown(descriptor, uid, gid)
            _os.fchmod(descriptor, mode)
            _os.fsync(descriptor)
            _os.fsync(parent)
            opened = _directory(_os.fstat(descriptor))
        if (
            _stat.S_IMODE(opened.st_mode) != mode
            or opened.st_uid != uid
            or opened.st_gid != gid
            or _identity(_os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(opened)
        ):
            raise OSError
        return descriptor, created, _identity(opened)
    except BaseException:
        active = _sys.exception()
        try:
            if descriptor is not None:
                _os.close(descriptor)
            if created and identity is not None:
                current = _os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _identity(current) != identity or not _stat.S_ISDIR(current.st_mode):
                    raise OSError
                _os.rmdir(name, dir_fd=parent)
                _os.fsync(parent)
        except BaseException:
            if active is None:
                raise
        raise


def _hash_opened(descriptor: int, size: int) -> str:
    _os.lseek(descriptor, 0, _os.SEEK_SET)
    _payload, digest = _read_hash(descriptor, size, _MAX_INPUT)
    return digest


def _verify_application(root: int, manifest: _c26.DevApplicationManifest, uid: int, gid: int,
                        staging: tuple[str, tuple[int, ...]] | None = None) -> None:
    expected_files = {entry.path: entry for entry in manifest.entries}
    expected_directories = set()
    for path in expected_files:
        parts = path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            expected_directories.add("/".join(parts[:index]))
    found_files = set()
    found_directories = set()

    def scan(directory: int, prefix: str) -> None:
        for name in _names(directory):
            relative = name if not prefix else prefix + "/" + name
            status = _os.stat(name, dir_fd=directory, follow_symlinks=False)
            if relative in expected_directories:
                if (
                    not _stat.S_ISDIR(status.st_mode)
                    or _stat.S_ISLNK(status.st_mode)
                    or _stat.S_IMODE(status.st_mode) != 0o755
                    or (status.st_uid, status.st_gid) != (uid, gid)
                ):
                    raise OSError
                child = _os.open(
                    name,
                    _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                    dir_fd=directory,
                )
                try:
                    if _fingerprint(_os.fstat(child)) != _fingerprint(status):
                        raise OSError
                    found_directories.add(relative)
                    scan(child, relative)
                    if _fingerprint(_os.fstat(child)) != _fingerprint(
                        _os.stat(name, dir_fd=directory, follow_symlinks=False)
                    ):
                        raise OSError
                finally:
                    _os.close(child)
            elif relative in expected_files:
                requirement = expected_files[relative]
                opened = _regular(status, _MAX_BLOB)
                if (
                    _stat.S_IMODE(opened.st_mode) != 0o644
                    or (opened.st_uid, opened.st_gid) != (uid, gid)
                ):
                    raise OSError
                descriptor = _os.open(
                    name,
                    _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK,
                    dir_fd=directory,
                )
                try:
                    current = _regular(_os.fstat(descriptor), _MAX_BLOB)
                    before = _fingerprint(current)
                    if before != _fingerprint(opened):
                        raise OSError
                    _payload, digest = _read_hash(descriptor, current.st_size, _MAX_BLOB)
                    if digest != requirement.sha256 or _fingerprint(_os.fstat(descriptor)) != before:
                        raise OSError
                    if _fingerprint(_os.stat(name, dir_fd=directory, follow_symlinks=False)) != before:
                        raise OSError
                    found_files.add(relative)
                finally:
                    _os.close(descriptor)
            elif staging is not None and relative == staging[0]:
                if _fingerprint(status) != staging[1]:
                    raise OSError
            else:
                raise OSError

    scan(root, "")
    if found_files != set(expected_files) or found_directories != expected_directories:
        raise OSError


def _preflight_application(
    root: int, manifest: _c26.DevApplicationManifest, uid: int, gid: int,
) -> None:
    """Require every pre-existing entry to be an exact reviewed subset."""
    expected_files = {entry.path: entry for entry in manifest.entries}
    expected_directories = {
        "/".join(path.split("/")[:index])
        for path in expected_files
        for index in range(1, len(path.split("/")))
    }

    def scan(directory: int, prefix: str) -> None:
        for name in _names(directory):
            relative = name if not prefix else prefix + "/" + name
            status = _os.stat(name, dir_fd=directory, follow_symlinks=False)
            if relative in expected_directories:
                if (
                    not _stat.S_ISDIR(status.st_mode)
                    or _stat.S_ISLNK(status.st_mode)
                    or _stat.S_IMODE(status.st_mode) != 0o755
                    or (status.st_uid, status.st_gid) != (uid, gid)
                ):
                    raise OSError
                child = _os.open(
                    name,
                    _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                    dir_fd=directory,
                )
                try:
                    if _fingerprint(_os.fstat(child)) != _fingerprint(status):
                        raise OSError
                    scan(child, relative)
                finally:
                    _os.close(child)
            elif relative in expected_files:
                requirement = expected_files[relative]
                opened = _regular(status, _MAX_BLOB)
                if (
                    _stat.S_IMODE(opened.st_mode) != 0o644
                    or (opened.st_uid, opened.st_gid) != (uid, gid)
                ):
                    raise OSError
                descriptor = _os.open(
                    name,
                    _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK,
                    dir_fd=directory,
                )
                try:
                    current = _regular(_os.fstat(descriptor), _MAX_BLOB)
                    before = _fingerprint(current)
                    _payload, digest = _read_hash(descriptor, current.st_size, _MAX_BLOB)
                    if (
                        before != _fingerprint(opened)
                        or digest != requirement.sha256
                        or _fingerprint(_os.fstat(descriptor)) != before
                    ):
                        raise OSError
                finally:
                    _os.close(descriptor)
            else:
                raise OSError

    scan(root, "")


def _install_application(
    authority: _Authority,
    manifest: _c26.DevApplicationManifest,
    blobs: tuple[tuple[str, bytes], ...],
) -> ApplicationMaterializationEvidence:
    owned: list[int] = []
    created_files: list[tuple[int, str, tuple[int, int]]] = []
    created_directories: list[tuple[int, str, int, tuple[int, int]]] = []
    try:
        root, chain = _open_directory(authority.paths.application_root, owned)
        status = _os.fstat(root)
        if (
            _stat.S_IMODE(status.st_mode) != 0o755
            or (status.st_uid, status.st_gid) != (authority.application_uid, authority.application_gid)
        ):
            raise OSError
        # Existing state must be an exact subset before any mutation.
        _preflight_application(
            root, manifest, authority.application_uid, authority.application_gid,
        )
        expected = {entry.path: entry for entry in manifest.entries}
        blob_map = dict(blobs)
        directories = sorted({
            "/".join(path.split("/")[:index])
            for path in expected
            for index in range(1, len(path.split("/")))
        }, key=lambda value: (value.count("/"), value))
        directory_descriptors = {"": root}
        for relative in directories:
            parent_relative, name = relative.rsplit("/", 1) if "/" in relative else ("", relative)
            parent = directory_descriptors[parent_relative]
            descriptor, created, identity = _ensure_exact_directory(
                parent, name, 0o755, authority.application_uid, authority.application_gid,
            )
            owned.append(descriptor)
            directory_descriptors[relative] = descriptor
            if created:
                created_directories.append((parent, name, descriptor, identity))
        unchanged = 0
        for relative, payload in blobs:
            parent_relative, name = relative.rsplit("/", 1) if "/" in relative else ("", relative)
            parent = directory_descriptors[parent_relative]
            try:
                existing = _os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                current = _regular(existing, _MAX_BLOB)
                if (
                    _stat.S_IMODE(current.st_mode) != 0o644
                    or (current.st_uid, current.st_gid) != (
                        authority.application_uid, authority.application_gid,
                    )
                ):
                    raise OSError
                descriptor = _os.open(
                    name,
                    _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK,
                    dir_fd=parent,
                )
                try:
                    opened = _regular(_os.fstat(descriptor), _MAX_BLOB)
                    if _fingerprint(opened) != _fingerprint(current):
                        raise OSError
                    value, digest = _read_hash(descriptor, opened.st_size, _MAX_BLOB)
                    if value != payload or digest != expected[relative].sha256:
                        raise OSError
                finally:
                    _os.close(descriptor)
                unchanged += 1
                continue
            temporary_identity = None
            temporary = _os.open(
                _APPLICATION_TEMPORARY,
                _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                0o600, dir_fd=parent,
            )
            try:
                temporary_status = _regular(_os.fstat(temporary), _MAX_BLOB)
                temporary_identity = _identity(temporary_status)
                if (temporary_status.st_uid, temporary_status.st_gid) != (
                    authority.application_uid, authority.application_gid,
                ):
                    _os.fchown(temporary, authority.application_uid, authority.application_gid)
                _os.fchmod(temporary, 0o644)
                _write_all(temporary, payload)
                _os.fsync(temporary)
                ready = _regular(_os.fstat(temporary), _MAX_BLOB)
                if ready.st_size != len(payload):
                    raise OSError
                reader = _os.open(
                    _APPLICATION_TEMPORARY,
                    _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK,
                    dir_fd=parent,
                )
                try:
                    _copied, digest = _read_hash(reader, ready.st_size, _MAX_BLOB)
                    if digest != expected[relative].sha256:
                        raise OSError
                finally:
                    _os.close(reader)
                _os.link(
                    _APPLICATION_TEMPORARY, name,
                    src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False,
                )
                created_files.append((parent, name, temporary_identity))
                installed = _os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _identity(installed) != temporary_identity:
                    raise OSError
                _os.unlink(_APPLICATION_TEMPORARY, dir_fd=parent)
                _os.fsync(parent)
            finally:
                _os.close(temporary)
                try:
                    residue = _os.stat(
                        _APPLICATION_TEMPORARY, dir_fd=parent, follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    if temporary_identity is None or _identity(residue) != temporary_identity:
                        raise OSError
                    _os.unlink(_APPLICATION_TEMPORARY, dir_fd=parent)
                    _os.fsync(parent)
        _verify_application(
            root, manifest, authority.application_uid, authority.application_gid,
        )
        _revalidate_chain(chain)
        digest = _hashlib.sha256(manifest.canonical_bytes()).hexdigest()
        return ApplicationMaterializationEvidence(
            "/opt/omnilyzer/deployment/app", manifest.reviewed_commit, digest, 28,
            "unchanged" if unchanged == 28 else "materialized",
        )
    except BaseException:
        active = _sys.exception()
        try:
            # Remove only identities created by this invocation, never pre-existing state.
            for parent, name, identity in reversed(created_files):
                status = _os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _identity(status) != identity or not _stat.S_ISREG(status.st_mode):
                    raise OSError
            for parent, name, identity in reversed(created_files):
                _os.unlink(name, dir_fd=parent)
                _os.fsync(parent)
            for parent, name, descriptor, identity in reversed(created_directories):
                status = _os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _identity(status) != identity or _names(descriptor):
                    raise OSError
                _os.rmdir(name, dir_fd=parent)
                _os.fsync(parent)
        except _CONTROL:
            if not isinstance(active, _CONTROL):
                raise
        except BaseException:
            if active is None:
                raise
        raise
    finally:
        _finish_close(owned)


def _open_lock(authority: _Authority, repository: int, owned: list[int]) -> _OpenFile:
    requirement = authority.integrity.python_environment_requirement().dependency_lock
    components = requirement.path.split("/")
    if (
        tuple(components) != ("deployment", _LOCK_NAME)
        or authority.paths.repository_lock != requirement.path
    ):
        raise OSError
    parent = repository
    chain = []
    flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    for component in components[:-1]:
        named = _directory(_os.stat(component, dir_fd=parent, follow_symlinks=False))
        child = _claim(_os.open(component, flags, dir_fd=parent), owned)
        opened = _directory(_os.fstat(child))
        if _fingerprint(named) != _fingerprint(opened):
            raise OSError
        chain.append((child, parent, component, _directory_fingerprint(opened)))
        parent = child
    name = components[-1]
    if name != _LOCK_NAME:
        raise OSError
    named = _regular(_os.stat(name, dir_fd=parent, follow_symlinks=False), 64 * 1024)
    descriptor = _claim(_os.open(
        name, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK,
        dir_fd=parent,
    ), owned)
    opened = _regular(_os.fstat(descriptor), 64 * 1024)
    fingerprint = _fingerprint(opened)
    if _fingerprint(named) != fingerprint:
        raise OSError
    digest = _hash_opened(descriptor, opened.st_size)
    if digest != requirement.sha256:
        raise OSError
    if _fingerprint(_os.fstat(descriptor)) != fingerprint:
        raise OSError
    if _fingerprint(_os.stat(name, dir_fd=parent, follow_symlinks=False)) != fingerprint:
        raise OSError
    _revalidate_chain(chain)
    return _OpenFile(descriptor, parent, name, fingerprint, opened.st_size, digest)


def _copy_descriptor(
    source: int, destination_parent: int, name: str, size: int, sha256: str,
    uid: int, gid: int, owned: list[int],
) -> tuple[int, tuple[int, ...]]:
    descriptor = _claim(_os.open(
        name,
        _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | _os.O_NOFOLLOW | _os.O_CLOEXEC,
        0o600, dir_fd=destination_parent,
    ), owned)
    identity = None
    try:
        opened = _regular(_os.fstat(descriptor), _MAX_INPUT)
        identity = _identity(opened)
        if (opened.st_uid, opened.st_gid) != (uid, gid):
            _os.fchown(descriptor, uid, gid)
        _os.fchmod(descriptor, 0o400)
        _os.lseek(source, 0, _os.SEEK_SET)
        digest = _hashlib.sha256()
        remaining = size
        while remaining:
            chunk = _os.read(source, min(_CHUNK, remaining))
            if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
                raise OSError
            _write_all(descriptor, chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if _os.read(source, 1) != b"" or digest.hexdigest() != sha256:
            raise OSError
        _os.fsync(descriptor)
        current = _regular(_os.fstat(descriptor), _MAX_INPUT)
        if current.st_size != size:
            raise OSError
        reader = _claim(_os.open(
            name,
            _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK,
            dir_fd=destination_parent,
        ), owned)
        current = _regular(_os.fstat(reader), _MAX_INPUT)
        fingerprint = _fingerprint(current)
        if _identity(current) != identity or _hash_opened(reader, size) != sha256:
            raise OSError
        named = _regular(
            _os.stat(name, dir_fd=destination_parent, follow_symlinks=False),
            _MAX_INPUT,
        )
        if _fingerprint(named) != fingerprint:
            raise OSError
        _os.close(descriptor)
        owned.remove(descriptor)
        _os.fsync(destination_parent)
        return reader, fingerprint
    except BaseException:
        active = _sys.exception()
        try:
            if identity is not None:
                current = _os.stat(name, dir_fd=destination_parent, follow_symlinks=False)
                if _identity(current) != identity or not _stat.S_ISREG(current.st_mode):
                    raise OSError
                _os.unlink(name, dir_fd=destination_parent)
                _os.fsync(destination_parent)
        except BaseException:
            if active is None:
                raise
        raise


def _prepare_snapshot(
    authority: _Authority, repository: int, wheelhouse_path: str,
    installer_path: str, owned: list[int], source_owned: list[int],
    build: dict[str, object],
) -> _Snapshot:
    environment = authority.integrity.python_environment_requirement()
    wheel_result = _c28._qualify_open(wheelhouse_path, environment, source_owned)
    installer_result = _pip_qualification._qualify_open(installer_path, source_owned)
    _wheel_evidence, wheel_directory, wheel_files, wheel_directories = wheel_result
    _installer_evidence, installer_directory, installer_file, installer_directories = installer_result
    lock = _open_lock(authority, repository, owned)
    parent, name, chain = _open_parent(authority.paths.snapshot_root, owned)
    if name != _SNAPSHOT_NAME:
        raise OSError
    try:
        _os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise OSError
    _os.mkdir(name, 0o700, dir_fd=parent)
    root_named = _directory(_os.stat(name, dir_fd=parent, follow_symlinks=False))
    root_identity = _identity(root_named)
    build.update(parent=parent, root_identity=root_identity, directories=[], files=[])
    root = _claim(_os.open(
        name, _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
        dir_fd=parent,
    ), owned)
    build["root"] = root
    if _identity(_os.fstat(root)) != root_identity:
        raise OSError
    if (root_named.st_uid, root_named.st_gid) != (authority.venv_uid, authority.venv_gid):
        _os.fchown(root, authority.venv_uid, authority.venv_gid)
    _os.fchmod(root, 0o700)
    _os.fsync(root)
    _os.fsync(parent)
    directories = []
    build["directories"] = directories
    directory_map = {}
    for child_name in _SNAPSHOT_DIRECTORIES:
        descriptor, created, identity = _ensure_exact_directory(
            root, child_name, 0o700, authority.venv_uid, authority.venv_gid,
        )
        if not created:
            raise OSError
        owned.append(descriptor)
        directories.append((child_name, descriptor, identity))
        directory_map[child_name] = descriptor
    files = []
    build["files"] = files
    installer = _c31p.DevPipInstallerProvenance().artifact
    pip_descriptor, pip_name, _pip_fingerprint = installer_file
    if pip_name != installer.filename:
        raise OSError
    copied, fingerprint = _copy_descriptor(
        pip_descriptor, directory_map["pip"], pip_name, installer.size,
        installer.sha256, authority.venv_uid, authority.venv_gid, owned,
    )
    files.append((directory_map["pip"], pip_name, copied, fingerprint,
                  installer.size, installer.sha256))
    wheel_requirements = {item.filename: item.sha256 for item in environment.wheels}
    if tuple(name for _descriptor, name, _fingerprint_value in wheel_files) != tuple(
        item.filename for item in environment.wheels
    ):
        raise OSError
    for source, wheel_name, source_fingerprint in wheel_files:
        source_status = _os.fstat(source)
        copied, fingerprint = _copy_descriptor(
            source, directory_map["wheels"], wheel_name, source_status.st_size,
            wheel_requirements[wheel_name], authority.venv_uid, authority.venv_gid,
            owned,
        )
        files.append((directory_map["wheels"], wheel_name, copied, fingerprint,
                      source_status.st_size, wheel_requirements[wheel_name]))
        if _fingerprint(_os.fstat(source)) != source_fingerprint:
            raise OSError
    lock_copied, fingerprint = _copy_descriptor(
        lock.descriptor, directory_map["requirements"], _LOCK_NAME,
        lock.size, lock.sha256, authority.venv_uid, authority.venv_gid, owned,
    )
    files.append((directory_map["requirements"], _LOCK_NAME, lock_copied,
                  fingerprint, lock.size, lock.sha256))
    if _fingerprint(_os.fstat(lock.descriptor)) != lock.fingerprint:
        raise OSError
    if _fingerprint(_os.stat(lock.name, dir_fd=lock.parent, follow_symlinks=False)) != lock.fingerprint:
        raise OSError
    _c28._revalidate_files(wheel_directory, list(wheel_files))
    _c28._revalidate_directories(wheel_directories)
    pip_source, pip_name, pip_fingerprint = installer_file
    if _fingerprint(_os.fstat(pip_source)) != pip_fingerprint:
        raise OSError
    if _fingerprint(_os.stat(pip_name, dir_fd=installer_directory, follow_symlinks=False)) != pip_fingerprint:
        raise OSError
    _pip_qualification._revalidate_directories(installer_directories)
    _revalidate_chain(chain)
    snapshot = _Snapshot(
        parent, root, tuple(directories), tuple(files), root_identity,
        authority.paths.snapshot_root + "/pip/" + installer.filename,
        authority.paths.snapshot_root + "/wheels",
        authority.paths.snapshot_root + "/requirements/" + _LOCK_NAME,
    )
    return snapshot


def _cleanup_partial_snapshot(build: dict[str, object]) -> None:
    """Remove only the exact partial snapshot identities recorded by this call."""
    parent = build.get("parent")
    root = build.get("root")
    root_identity = build.get("root_identity")
    directories = build.get("directories", [])
    files = build.get("files", [])
    if (
        type(parent) is not int
        or type(root_identity) is not tuple
        or type(directories) is not list
        or type(files) is not list
    ):
        raise OSError
    temporary_root = False
    if type(root) is not int:
        root = _os.open(
            _SNAPSHOT_NAME,
            _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
            dir_fd=parent,
        )
        temporary_root = True
    try:
        _cleanup_partial_snapshot_open(
            parent, root, root_identity, directories, files,
        )
    finally:
        if temporary_root:
            _os.close(root)


def _cleanup_partial_snapshot_open(
    parent: int,
    root: int,
    root_identity: tuple[int, int],
    directories: list[tuple[str, int, tuple[int, int]]],
    files: list[tuple[int, str, int, tuple[int, int, int, int], int, str]],
) -> None:
    expected_root_names = tuple(sorted(item[0] for item in directories))
    if _names(root) != expected_root_names:
        raise OSError
    expected_files = {item[1]: [] for item in directories}
    for file_parent, name, descriptor, fingerprint, size, sha256 in files:
        expected_files[file_parent].append(name)
        opened = _regular(_os.fstat(descriptor), _MAX_INPUT)
        named = _regular(_os.stat(name, dir_fd=file_parent, follow_symlinks=False), _MAX_INPUT)
        if (
            _fingerprint(opened) != fingerprint
            or _fingerprint(named) != fingerprint
            or opened.st_size != size
            or _hash_opened(descriptor, size) != sha256
            or _fingerprint(_os.fstat(descriptor)) != fingerprint
        ):
            raise OSError
    for name, descriptor, identity in directories:
        opened = _directory(_os.fstat(descriptor))
        named = _directory(_os.stat(name, dir_fd=root, follow_symlinks=False))
        if (
            _identity(opened) != identity
            or _identity(named) != identity
            or _names(descriptor) != tuple(sorted(expected_files[descriptor]))
        ):
            raise OSError
    opened_root = _directory(_os.fstat(root))
    named_root = _directory(_os.stat(_SNAPSHOT_NAME, dir_fd=parent, follow_symlinks=False))
    if _identity(opened_root) != root_identity or _identity(named_root) != root_identity:
        raise OSError
    for file_parent, name, _descriptor, _fingerprint_value, _size, _sha256 in reversed(files):
        _os.unlink(name, dir_fd=file_parent)
        _os.fsync(file_parent)
    for name, descriptor, _identity_value in reversed(directories):
        if _names(descriptor):
            raise OSError
        _os.rmdir(name, dir_fd=root)
        _os.fsync(root)
    if _names(root):
        raise OSError
    _os.rmdir(_SNAPSHOT_NAME, dir_fd=parent)
    _os.fsync(parent)


def _validate_snapshot(snapshot: _Snapshot, authority: _Authority) -> None:
    if _names(snapshot.root) != _SNAPSHOT_DIRECTORIES:
        raise OSError
    expected_by_parent = {descriptor: [] for _name, descriptor, _identity_value in snapshot.directories}
    for parent, name, descriptor, fingerprint, size, sha256 in snapshot.files:
        expected_by_parent[parent].append(name)
        status = _regular(_os.fstat(descriptor), _MAX_INPUT)
        named = _regular(_os.stat(name, dir_fd=parent, follow_symlinks=False), _MAX_INPUT)
        if (
            _fingerprint(status) != fingerprint
            or _fingerprint(named) != fingerprint
            or _stat.S_IMODE(status.st_mode) != 0o400
            or (status.st_uid, status.st_gid) != (authority.venv_uid, authority.venv_gid)
            or status.st_size != size
            or _hash_opened(descriptor, size) != sha256
            or _fingerprint(_os.fstat(descriptor)) != fingerprint
        ):
            raise OSError
    for name, descriptor, identity in snapshot.directories:
        status = _directory(_os.fstat(descriptor))
        named = _directory(_os.stat(name, dir_fd=snapshot.root, follow_symlinks=False))
        if (
            _identity(status) != identity
            or _identity(named) != identity
            or _stat.S_IMODE(status.st_mode) != 0o700
            or (status.st_uid, status.st_gid) != (authority.venv_uid, authority.venv_gid)
            or _names(descriptor) != tuple(sorted(expected_by_parent[descriptor]))
        ):
            raise OSError
    root = _directory(_os.fstat(snapshot.root))
    named_root = _directory(_os.stat(_SNAPSHOT_NAME, dir_fd=snapshot.parent, follow_symlinks=False))
    if (
        _identity(root) != snapshot.root_identity
        or _identity(named_root) != snapshot.root_identity
        or _stat.S_IMODE(root.st_mode) != 0o700
        or (root.st_uid, root.st_gid) != (authority.venv_uid, authority.venv_gid)
    ):
        raise OSError


def _cleanup_snapshot(snapshot: _Snapshot, authority: _Authority) -> None:
    _validate_snapshot(snapshot, authority)
    for parent, name, _descriptor, _fingerprint_value, _size, _sha256 in reversed(snapshot.files):
        _os.unlink(name, dir_fd=parent)
        _os.fsync(parent)
    for name, descriptor, _identity_value in reversed(snapshot.directories):
        if _names(descriptor):
            raise OSError
        _os.rmdir(name, dir_fd=snapshot.root)
        _os.fsync(snapshot.root)
    if _names(snapshot.root):
        raise OSError
    _os.rmdir(_SNAPSHOT_NAME, dir_fd=snapshot.parent)
    _os.fsync(snapshot.parent)


def _run_process(argv: tuple[str, ...], environment: dict[str, str], timeout: float) -> None:
    if (
        type(argv) is not tuple
        or not argv
        or any(type(item) is not str or not item for item in argv)
        or not argv[0].startswith("/")
        or type(environment) is not dict
        or any(type(key) is not str or type(value) is not str for key, value in environment.items())
        or type(timeout) is not float
        or timeout <= 0
    ):
        raise OSError
    try:
        result = _subprocess.run(
            argv, shell=False, stdin=_subprocess.DEVNULL,
            stdout=_subprocess.DEVNULL, stderr=_subprocess.DEVNULL,
            env=dict(environment), timeout=timeout, check=False,
            close_fds=True, umask=0o022,
        )
    except _CONTROL:
        raise
    except Exception:
        raise OSError from None
    if type(result.returncode) is not int or result.returncode != 0:
        raise OSError


def _venv_precondition(authority: _Authority) -> None:
    owned = []
    try:
        parent, name, chain = _open_parent(authority.paths.venv_root, owned)
        try:
            status = _os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            _revalidate_chain(chain)
            return
        opened = _directory(status)
        descriptor = _claim(_os.open(
            name, _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
            dir_fd=parent,
        ), owned)
        if (
            _fingerprint(_os.fstat(descriptor)) != _fingerprint(opened)
            or _stat.S_IMODE(opened.st_mode) != 0o755
            or (opened.st_uid, opened.st_gid) != (authority.venv_uid, authority.venv_gid)
            or _names(descriptor)
        ):
            raise OSError
        _revalidate_chain(chain)
    finally:
        _finish_close(owned)


def _verify_preinstall_venv(authority: _Authority) -> None:
    environment = authority.integrity.python_environment_requirement()
    installer = _c31p.DevPipInstallerProvenance()
    entries = tuple(
        entry for entry in _python_qualification._load_manifest(environment, installer)
        if entry["source"] == "venv"
    )
    _python_qualification._observe_tree(
        authority.paths.venv_root, entries, authority.venv_uid, authority.venv_gid,
    )


def _python_argv(authority: _Authority, snapshot: _Snapshot) -> tuple[tuple[str, ...], tuple[str, ...]]:
    provenance = _c31p.DevPipInstallerProvenance()
    venv = (
        _SYSTEM_PYTHON, "-m", "venv", "--without-pip", authority.paths.venv_root,
    )
    pip = (
        authority.paths.python_executable,
        provenance.invocation.isolation_argument,
        "-c",
        provenance.invocation.bootstrap_source,
        snapshot.pip_wheel,
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
        snapshot.wheel_directory,
        "--requirement",
        snapshot.lock_file,
    )
    return venv, pip


def _validate_host_qualification(
    authority: _Authority, evidence: object, wheelhouse_path: str,
) -> None:
    """Require fresh C29 evidence for the interpreter and pre-venv state."""
    if type(evidence) is not _c29.DevHostQualificationEvidence:
        raise OSError
    _c29.DevHostQualificationEvidence.__post_init__(evidence)
    environment = authority.integrity.python_environment_requirement()
    provenance = _c27.DevPythonInterpreterProvenance()
    _c27.DevPythonInterpreterProvenance.__post_init__(provenance)
    platform = evidence.platform
    if (
        (platform.system, platform.distribution, platform.version,
         platform.machine, platform.archive_architecture)
        != ("Linux", "Ubuntu", "24.04", "x86_64", "amd64")
        or not platform.libc.startswith("glibc ")
        or evidence.payload_manifest_sha256 != _c29._PAYLOAD_SHA256
        or evidence.wheelhouse_path != wheelhouse_path
        or tuple((item.filename, item.sha256) for item in evidence.wheel_files)
        != tuple((item.filename, item.sha256) for item in environment.wheels)
        or tuple((item.package, item.version, item.architecture, item.status)
                 for item in evidence.packages)
        != tuple((item.package, item.version, item.architecture, "installed")
                 for item in provenance.packages)
    ):
        raise OSError
    venv = tuple(
        item for item in evidence.managed_paths
        if item.path == environment.root
    )
    if (
        len(venv) != 1
        or venv[0].kind != "directory"
        or venv[0].state not in ("absent", "exact")
        or venv[0].mode != 0o755
        or (venv[0].owner_uid, venv[0].group_gid)
        != (authority.venv_uid, authority.venv_gid)
    ):
        raise OSError


class DevHostProvisioningMechanics:
    """Constructor-bound C31B mechanics; no method accepts destination authority."""

    __slots__ = ("_authority", "_lock")

    def __init__(self, *, configuration: _c17.DevExecutorServiceConfiguration) -> None:
        object.__setattr__(self, "_authority", _build_authority(configuration))
        object.__setattr__(self, "_lock", _threading.Lock())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_MODEL_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_MODEL_ERROR)

    def _enter(self) -> _Authority:
        lock = object.__getattribute__(self, "_lock")
        if not lock.acquire(blocking=False):
            raise ProvisioningMechanicsError() from None
        return object.__getattribute__(self, "_authority")

    def materialize_application_tree(
        self, *, repository_root: str, application_manifest: _c26.DevApplicationManifest,
    ) -> ApplicationMaterializationEvidence:
        """Materialize only exact C26 Git blobs into the fixed application root."""
        authority = self._enter()
        try:
            blobs = _application_blobs(
                repository_root, authority.configuration, application_manifest,
            )
            return _install_application(authority, application_manifest, blobs)
        except _CONTROL:
            raise
        except Exception:
            raise ProvisioningMechanicsError() from None
        finally:
            object.__getattribute__(self, "_lock").release()

    def construct_python_environment(
        self, *, host_qualification: _c29.DevHostQualificationEvidence,
        repository_root: str, wheelhouse_path: str,
        pip_installer_staging: str,
    ) -> _python_qualification.DevPythonEnvironmentEvidence:
        """Snapshot exact inputs, construct/install offline, and require C31A evidence."""
        try:
            authority = self._enter()
        except _CONTROL:
            raise
        except Exception:
            raise ProvisioningMechanicsError("operation-entry") from None
        owned: list[int] = []
        source_owned: list[int] = []
        snapshot = None
        snapshot_build: dict[str, object] = {}
        phase = "host-qualification"
        try:
            _validate_host_qualification(
                authority, host_qualification, wheelhouse_path,
            )
            # The repository root is caller-selected only to locate the fixed C24 lock.
            phase = "repository-open"
            repository, repository_chain = _open_directory(repository_root, owned)
            phase = "snapshot-preparation"
            snapshot = _prepare_snapshot(
                authority, repository, wheelhouse_path, pip_installer_staging,
                owned, source_owned, snapshot_build,
            )
            phase = "repository-revalidation"
            _revalidate_chain(repository_chain)
            phase = "snapshot-validation"
            _validate_snapshot(snapshot, authority)
            phase = "venv-precondition"
            _venv_precondition(authority)
            phase = "argv-construction"
            venv_argv, pip_argv = _python_argv(authority, snapshot)
            phase = "venv-command"
            _run_process(venv_argv, _VENV_ENVIRONMENT, _VENV_TIMEOUT)
            phase = "preinstall-venv-verification"
            _verify_preinstall_venv(authority)
            phase = "post-venv-snapshot-validation"
            _validate_snapshot(snapshot, authority)
            phase = "pip-command"
            _run_process(pip_argv, _PIP_ENVIRONMENT, _PIP_TIMEOUT)
            phase = "post-pip-snapshot-validation"
            _validate_snapshot(snapshot, authority)
            phase = "python-qualification"
            evidence = _python_qualification.qualify_dev_python_environment(
                configuration=authority.configuration,
            )
            if type(evidence) is not _python_qualification.DevPythonEnvironmentEvidence:
                raise OSError
            _python_qualification.DevPythonEnvironmentEvidence.__post_init__(evidence)
            phase = "snapshot-cleanup"
            _cleanup_snapshot(snapshot, authority)
            snapshot = None
            snapshot_build.clear()
            return evidence
        except _CONTROL:
            raise
        except Exception:
            raise ProvisioningMechanicsError(phase) from None
        finally:
            # Never recursively remove a failed venv.  It remains for operator review.
            active = _sys.exception()
            try:
                if snapshot is not None:
                    _cleanup_snapshot(snapshot, authority)
                elif snapshot_build:
                    _cleanup_partial_snapshot(snapshot_build)
            except _CONTROL:
                if not isinstance(active, _CONTROL):
                    raise
            except BaseException:
                if active is None:
                    raise ProvisioningMechanicsError("snapshot-cleanup") from None
            finally:
                source_failed, source_control = _close(source_owned)
                owned_failed, owned_control = _close(owned)
                object.__getattribute__(self, "_lock").release()
                control = source_control or owned_control
                if control is not None and not isinstance(active, _CONTROL):
                    raise control
                if (source_failed or owned_failed) and active is None:
                    raise ProvisioningMechanicsError("descriptor-cleanup") from None
