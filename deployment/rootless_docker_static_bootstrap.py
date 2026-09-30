"""deployment/rootless_docker_static_bootstrap.py - C32ZZ static host bootstrap.

Purpose:
- consume the independently qualified C32ZX package-only host state;
- assign only the reviewed executor subordinate UID/GID ranges;
- publish only the reviewed persistent rootless Docker directories and assets;
- reload the system manager so reviewed drop-ins are visible;
- remain strictly before linger, the UID-991 user manager, rootless Docker startup,
  executor/broker activation, and any deployment action.

The private executor Docker projection directory is intentionally not created by
C32ZZ. Its lifecycle is owned by the executor service through the reviewed
RuntimeDirectory= drop-in so it is recreated correctly after reboot.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import subprocess

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_postinstall_qualification as postinstall
from . import rootless_docker_preinstall_qualification as preinstall
from .rootless_docker_authority import AUTHORITY
from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from .rootless_docker_package_bundle_qualification import (
    RootlessDockerPackageBundleEvidence,
    qualify_rootless_docker_package_bundle,
)
from .successor_application_generation import TARGET_REVIEWED_COMMIT
from .successor_host_migration_qualification import qualify_successor_host_migration


__all__ = (
    "RootlessDockerStaticBootstrapError",
    "RootlessDockerStaticBootstrapEvidence",
    "bootstrap_rootless_docker_static_host",
)

_ERROR = "rootless Docker static bootstrap is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_USERMOD = "/usr/sbin/usermod"
_DPKG_QUERY = "/usr/bin/dpkg-query"
_OUTPUT_LIMIT = 1024 * 1024
_TIMEOUT = 30.0
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CHUNK = 64 * 1024
_SOURCE_ROOT = Path(__file__).resolve().parent.parent
_SUBUID = "/etc/subuid"
_SUBGID = "/etc/subgid"
_USER_MANAGER = "user@991.service"
_DEPLOYMENT_UNITS = (
    "omnilyzer-deployment-broker.service",
    "omnilyzer-deployment-executor.service",
    "omnilyzer-deployment-executor.socket",
)
_EXPECTED_APPLICATION_SHA256 = (
    "9bb162e1712a8ec76874c229ce1af1c8a88f527686d4a43376ca93a8b0d00b88"
)
_TARGET_VERSIONS = {
    item.name: item.apt_version
    for item in (
        *INSTALLATION_AUTHORITY.packages,
        *INSTALLATION_AUTHORITY.supplemental_packages,
    )
}
_SUBID_END = AUTHORITY.subuid_start + AUTHORITY.subordinate_count - 1
_SUBID_RANGE = f"{AUTHORITY.subuid_start}-{_SUBID_END}"
_PARENT_AUTHORITY = {
    "/var/lib/omnilyzer/deployment": (0, 0, 0o755),
    "/var/lib/omnilyzer/deployment/dev": (AUTHORITY.executor_uid, AUTHORITY.executor_gid, 0o700),
    "/etc/omnilyzer/deployment": (0, 0, 0o755),
    "/opt/omnilyzer/deployment": (0, 0, 0o755),
    "/etc/systemd/system": (0, 0, 0o755),
    "/etc/systemd/user": (0, 0, 0o755),
}
_RUNTIME_PROJECTION = AUTHORITY.socket_directory
_USER_UNIT_ENABLE_LINK = (
    "/etc/systemd/user/default.target.wants/omnilyzer-task014-rootless-docker.service"
)
_EXPECTED_DIRECTORY_CHILDREN = {
    path: set() for path, _uid, _gid, _mode in AUTHORITY.provisioned_directories
}
for _source, _destination, _digest, _uid, _gid, _mode in AUTHORITY.installed_assets:
    _parent, _name = os.path.split(_destination)
    if _parent in _EXPECTED_DIRECTORY_CHILDREN:
        _EXPECTED_DIRECTORY_CHILDREN[_parent].add(_name)
_EXPECTED_DIRECTORY_CHILDREN = {
    path: frozenset(names) for path, names in _EXPECTED_DIRECTORY_CHILDREN.items()
}


class RootlessDockerStaticBootstrapError(Exception):
    """One fixed external failure for the privileged C32ZZ boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerStaticBootstrapEvidence:
    """Exact static bootstrap result returned only after closed requalification."""

    operation: str
    expected_workflow_sha: str
    subuid: tuple[str, int, int]
    subgid: tuple[str, int, int]
    directories: tuple[tuple[str, int, int, int], ...]
    assets: tuple[tuple[str, str, int, int, int], ...]
    masked_units: tuple[str, ...]
    packages: tuple[tuple[str, str, str], ...]
    bundle_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        expected_packages = tuple(
            (payload.package, _TARGET_VERSIONS[payload.package], "amd64")
            for payload in INSTALLATION_AUTHORITY.payloads
        )
        expected_assets = tuple(
            (destination, digest, uid, gid, mode)
            for _source, destination, digest, uid, gid, mode
            in AUTHORITY.installed_assets
        )
        expected_subuid = (
            AUTHORITY.executor_user,
            AUTHORITY.subuid_start,
            AUTHORITY.subordinate_count,
        )
        expected_subgid = (
            AUTHORITY.executor_user,
            AUTHORITY.subgid_start,
            AUTHORITY.subordinate_count,
        )
        if (
            self.operation not in {"bootstrapped", "resumed", "already-bootstrapped"}
            or type(self.expected_workflow_sha) is not str
            or len(self.expected_workflow_sha) != 40
            or self.expected_workflow_sha == "0" * 40
            or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
            or self.subuid != expected_subuid
            or self.subgid != expected_subgid
            or self.directories != AUTHORITY.provisioned_directories
            or self.assets != expected_assets
            or self.masked_units != INSTALLATION_AUTHORITY.rootful_units
            or self.packages != expected_packages
            or self.bundle_sha256s
            != tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads)
        ):
            raise ValueError(_ERROR)


def _root_identity() -> tuple[int, int, int, int]:
    return preinstall._root_identity()


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_mode,
        value.st_ino,
        value.st_dev,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _run(argv: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    """Run only the fixed system-manager and sub-ID mutation shapes."""

    if argv == (_SYSTEMCTL, "daemon-reload"):
        pass
    elif argv in (
        (
            _USERMOD,
            "--add-subuids",
            _SUBID_RANGE,
            AUTHORITY.executor_user,
        ),
        (
            _USERMOD,
            "--add-subgids",
            _SUBID_RANGE,
            AUTHORITY.executor_user,
        ),
    ):
        pass
    else:
        raise OSError

    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": "/root",
        },
        shell=False,
        timeout=_TIMEOUT,
        check=False,
    )
    if (
        type(result.returncode) is not int
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > _OUTPUT_LIMIT
        or len(result.stderr) > _OUTPUT_LIMIT
    ):
        raise OSError
    return result


def _read_systemctl(unit: str, property_name: str) -> str:
    if (
        unit not in (*_DEPLOYMENT_UNITS, _USER_MANAGER)
        or property_name not in {"LoadState", "ActiveState", "UnitFileState", "DropInPaths"}
    ):
        raise OSError
    result = subprocess.run(
        (
            _SYSTEMCTL,
            "show",
            "--property=" + property_name,
            "--value",
            unit,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False,
        timeout=5.0,
        check=False,
    )
    if (
        result.returncode != 0
        or type(result.stdout) is not bytes
        or len(result.stdout) > 256 * 1024
        or not result.stdout.endswith(b"\n")
        or b"\r" in result.stdout
        or b"\n" in result.stdout[:-1]
    ):
        raise OSError
    return result.stdout[:-1].decode("ascii")


def _require_inactive_control_plane() -> None:
    for unit in _DEPLOYMENT_UNITS:
        if _read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError
    if (
        _read_systemctl(_USER_MANAGER, "LoadState") != "loaded"
        or _read_systemctl(_USER_MANAGER, "ActiveState") != "inactive"
    ):
        raise OSError
    try:
        os.lstat(AUTHORITY.runtime_directory)
    except FileNotFoundError:
        pass
    else:
        raise OSError
    try:
        os.lstat(_RUNTIME_PROJECTION)
    except FileNotFoundError:
        pass
    else:
        raise OSError
    if os.path.lexists(_USER_UNIT_ENABLE_LINK):
        raise OSError


def _subid_state(path: str) -> str:
    if path not in {_SUBUID, _SUBGID}:
        raise OSError
    records = preinstall._subid_records(path)
    executor = tuple(item for item in records if item[0] == AUTHORITY.executor_user)
    if tuple(item for item in records if item[0] == "omnigpt") != (
        ("omnigpt", 427680, 65536),
    ):
        raise OSError
    if not executor:
        target_start = (
            AUTHORITY.subuid_start if path == _SUBUID else AUTHORITY.subgid_start
        )
        target_end = target_start + AUTHORITY.subordinate_count - 1
        for name, start, count in records:
            end = start + count - 1
            if not (end < target_start or start > target_end):
                raise OSError
        return "absent"
    expected = (
        AUTHORITY.executor_user,
        AUTHORITY.subuid_start if path == _SUBUID else AUTHORITY.subgid_start,
        AUTHORITY.subordinate_count,
    )
    if executor != (expected,):
        raise OSError
    return "exact"


def _ensure_subids() -> tuple[str, str]:
    subuid = _subid_state(_SUBUID)
    subgid = _subid_state(_SUBGID)

    if subuid == "absent":
        result = _run(
            (
                _USERMOD,
                "--add-subuids",
                _SUBID_RANGE,
                AUTHORITY.executor_user,
            )
        )
        if result.returncode != 0 or _subid_state(_SUBUID) != "exact":
            raise OSError
        subuid = "exact"

    if subgid == "absent":
        result = _run(
            (
                _USERMOD,
                "--add-subgids",
                _SUBID_RANGE,
                AUTHORITY.executor_user,
            )
        )
        if result.returncode != 0 or _subid_state(_SUBGID) != "exact":
            raise OSError
        subgid = "exact"

    preinstall._require_executor_identity()
    return subuid, subgid


def _directory_state(path: str, uid: int, gid: int, mode: int) -> str:
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if (
        not stat.S_ISDIR(value.st_mode)
        or (value.st_uid, value.st_gid) != (uid, gid)
        or stat.S_IMODE(value.st_mode) != mode
    ):
        raise OSError
    return "exact"


def _open_parent(path: str) -> tuple[int, str]:
    parent, name = os.path.split(path)
    if not parent or not name or parent not in _PARENT_AUTHORITY:
        raise OSError
    expected_uid, expected_gid, expected_mode = _PARENT_AUTHORITY[parent]
    descriptor = os.open(parent, _DIRECTORY_FLAGS)
    value = os.fstat(descriptor)
    named = os.stat(parent, follow_symlinks=False)
    if (
        not stat.S_ISDIR(value.st_mode)
        or (value.st_uid, value.st_gid) != (expected_uid, expected_gid)
        or stat.S_IMODE(value.st_mode) != expected_mode
        or _fingerprint(value) != _fingerprint(named)
    ):
        os.close(descriptor)
        raise OSError
    return descriptor, name


def _rename_noreplace(directory: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.renameat2
    operation.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    operation.restype = ctypes.c_int
    ctypes.set_errno(0)
    if operation(
        directory,
        source.encode("ascii"),
        directory,
        destination.encode("ascii"),
        1,
    ) != 0:
        raise OSError(ctypes.get_errno())


def _temporary_name(name: str) -> str:
    if not name or "/" in name or name in {".", ".."}:
        raise OSError
    return "." + name + ".omnilyzer-task014.tmp"


def _ensure_directory(path: str, uid: int, gid: int, mode: int) -> None:
    state = _directory_state(path, uid, gid, mode)
    parent, name = _open_parent(path)
    temporary = _temporary_name(name)
    try:
        if state == "exact":
            try:
                staged = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            staged_fd = os.open(temporary, _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                entries = os.listdir(staged_fd)
            finally:
                os.close(staged_fd)
            if (
                not stat.S_ISDIR(staged.st_mode)
                or (staged.st_uid, staged.st_gid) != (uid, gid)
                or stat.S_IMODE(staged.st_mode) != mode
                or entries
            ):
                raise OSError
            os.rmdir(temporary, dir_fd=parent)
            os.fsync(parent)
            return

        try:
            staged = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            os.mkdir(temporary, 0o700, dir_fd=parent)
            os.chown(temporary, uid, gid, dir_fd=parent, follow_symlinks=False)
            os.chmod(temporary, mode, dir_fd=parent, follow_symlinks=False)
            staged = os.stat(temporary, dir_fd=parent, follow_symlinks=False)

        staged_fd = os.open(temporary, _DIRECTORY_FLAGS, dir_fd=parent)
        try:
            entries = os.listdir(staged_fd)
        finally:
            os.close(staged_fd)
        if (
            not stat.S_ISDIR(staged.st_mode)
            or (staged.st_uid, staged.st_gid) != (uid, gid)
            or stat.S_IMODE(staged.st_mode) != mode
            or entries
        ):
            raise OSError

        os.fsync(parent)
        _rename_noreplace(parent, temporary, name)
        os.fsync(parent)
    finally:
        os.close(parent)

    if _directory_state(path, uid, gid, mode) != "exact":
        raise OSError


def _source_bytes(source: str, digest: str) -> bytes:
    candidate = _SOURCE_ROOT / source
    try:
        candidate.relative_to(_SOURCE_ROOT)
    except ValueError:
        raise OSError from None
    named = os.lstat(candidate)
    if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise OSError
    descriptor = os.open(candidate, _FILE_FLAGS)
    try:
        opened = os.fstat(descriptor)
        if _fingerprint(opened) != _fingerprint(named):
            raise OSError
        data = bytearray()
        while len(data) <= 1024 * 1024:
            chunk = os.read(descriptor, min(_CHUNK, 1024 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        payload = bytes(data)
        if (
            not payload
            or len(payload) > 1024 * 1024
            or hashlib.sha256(payload).hexdigest() != digest
            or _fingerprint(os.fstat(descriptor)) != _fingerprint(named)
            or _fingerprint(os.lstat(candidate)) != _fingerprint(named)
        ):
            raise OSError
        return payload
    finally:
        os.close(descriptor)


def _file_state(
    path: str,
    digest: str,
    uid: int,
    gid: int,
    mode: int,
) -> str:
    try:
        named = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    descriptor = None
    try:
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_nlink != 1
            or (named.st_uid, named.st_gid) != (uid, gid)
            or stat.S_IMODE(named.st_mode) != mode
            or named.st_size <= 0
            or named.st_size > 1024 * 1024
        ):
            raise OSError
        descriptor = os.open(path, _FILE_FLAGS)
        opened = os.fstat(descriptor)
        if _fingerprint(opened) != _fingerprint(named):
            raise OSError
        value = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(_CHUNK, remaining))
            if not chunk:
                raise OSError
            value.update(chunk)
            remaining -= len(chunk)
        if (
            os.read(descriptor, 1) != b""
            or value.hexdigest() != digest
            or _fingerprint(os.fstat(descriptor)) != _fingerprint(named)
            or _fingerprint(os.lstat(path)) != _fingerprint(named)
        ):
            raise OSError
        return "exact"
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _ensure_file(
    source: str,
    path: str,
    digest: str,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    payload = _source_bytes(source, digest)
    state = _file_state(path, digest, uid, gid, mode)
    parent_path, name = os.path.split(path)
    if parent_path in _PARENT_AUTHORITY:
        expected = _PARENT_AUTHORITY[parent_path]
    else:
        match = next(
            (
                (uid_value, gid_value, mode_value)
                for directory, uid_value, gid_value, mode_value
                in AUTHORITY.provisioned_directories
                if directory == parent_path
            ),
            None,
        )
        if match is None:
            raise OSError
        expected = match
    parent = os.open(parent_path, _DIRECTORY_FLAGS)
    parent_value = os.fstat(parent)
    named_parent = os.stat(parent_path, follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_value.st_mode)
        or (parent_value.st_uid, parent_value.st_gid) != expected[:2]
        or stat.S_IMODE(parent_value.st_mode) != expected[2]
        or _fingerprint(parent_value) != _fingerprint(named_parent)
    ):
        os.close(parent)
        raise OSError
    temporary = _temporary_name(name)
    descriptor = None
    try:
        if state == "exact":
            try:
                os.stat(temporary, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            # Only remove an exact staged duplicate belonging to this bootstrap.
            staged_path = parent_path + "/" + temporary
            if _file_state(staged_path, digest, uid, gid, mode) != "exact":
                raise OSError
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
            return

        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=parent,
            )
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if type(count) is not int or count <= 0:
                    raise OSError
                written += count
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
        except FileExistsError:
            staged_path = parent_path + "/" + temporary
            if _file_state(staged_path, digest, uid, gid, mode) != "exact":
                raise OSError

        os.fsync(parent)
        _rename_noreplace(parent, temporary, name)
        os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)

    if _file_state(path, digest, uid, gid, mode) != "exact":
        raise OSError




def _require_directory_contents(*, allow_temporary: bool) -> None:
    if type(allow_temporary) is not bool:
        raise OSError
    for path, expected in _EXPECTED_DIRECTORY_CHILDREN.items():
        try:
            descriptor = os.open(path, _DIRECTORY_FLAGS)
        except FileNotFoundError:
            continue
        try:
            observed = frozenset(os.listdir(descriptor))
        finally:
            os.close(descriptor)
        allowed = set(expected)
        if allow_temporary:
            allowed.update(_temporary_name(name) for name in expected)
        if not observed.issubset(allowed):
            raise OSError
        if not allow_temporary and observed != expected:
            raise OSError

def _static_package_host():
    """Requalify package/host state without requiring the sub-ID range free."""

    identity = _root_identity()
    migrated = qualify_successor_host_migration()
    if (
        migrated.phase != "complete"
        or migrated.next_operation != "complete"
        or migrated.application_sha256 != _EXPECTED_APPLICATION_SHA256
        or migrated.executor_reviewed_commit != TARGET_REVIEWED_COMMIT
        or migrated.broker_reviewed_commit != TARGET_REVIEWED_COMMIT
    ):
        raise OSError

    supplementary = preinstall._require_executor_identity()
    dependencies = tuple(
        preinstall._require_host_dependency(item)
        for item in INSTALLATION_AUTHORITY.host_dependencies
    )
    packages = tuple(
        postinstall._require_package(item)
        for item in INSTALLATION_AUTHORITY.payloads
    )
    postinstall._require_conflicts_absent()
    postinstall._require_rootful_masked()
    controllers = preinstall._require_kernel_prerequisites()
    postinstall._require_no_shadowing()
    executables = postinstall._require_critical_executables()
    bundle = qualify_rootless_docker_package_bundle()
    _require_inactive_control_plane()

    if _root_identity() != identity:
        raise OSError
    return (
        migrated.expected_workflow_sha,
        supplementary,
        dependencies,
        packages,
        controllers,
        executables,
        bundle,
    )


def _bootstrap_state() -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
    subuid = _subid_state(_SUBUID)
    subgid = _subid_state(_SUBGID)
    directories = tuple(
        _directory_state(path, uid, gid, mode)
        for path, uid, gid, mode in AUTHORITY.provisioned_directories
    )
    assets = tuple(
        _file_state(destination, digest, uid, gid, mode)
        for _source, destination, digest, uid, gid, mode in AUTHORITY.installed_assets
    )
    _require_inactive_control_plane()
    _require_directory_contents(allow_temporary=True)
    return subuid, subgid, directories, assets


def _phase(state) -> str:
    subuid, subgid, directories, assets = state
    values = (subuid, subgid, *directories, *assets)
    if any(value not in {"absent", "exact"} for value in values):
        raise OSError
    if all(value == "absent" for value in values):
        return "initial"
    if all(value == "exact" for value in values):
        return "complete"
    return "resume"


def _install_static_assets() -> None:
    for path, uid, gid, mode in AUTHORITY.provisioned_directories:
        _ensure_directory(path, uid, gid, mode)

    for source, destination, digest, uid, gid, mode in AUTHORITY.installed_assets:
        _ensure_file(source, destination, digest, uid, gid, mode)


def _expected_user_manager_dropins() -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                *(item.path for item in AUTHORITY.user_manager_template_dropins),
                AUTHORITY.cgroup_dropin,
            ),
            key=os.path.basename,
        )
    )


def _require_user_manager_template_dropins() -> tuple[str, ...]:
    observed = []
    allowed = AUTHORITY.user_manager_template_dropins
    for item in allowed:
        if _file_state(item.path, item.sha256, item.uid, item.gid, item.mode) != "exact":
            raise OSError

        package = subprocess.run(
            (_DPKG_QUERY, "-W", preinstall._DPKG_FORMAT, item.package),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            shell=False,
            timeout=5.0,
            check=False,
        )
        expected = f"ii \t{item.apt_version}\t{item.architecture}\n".encode("ascii")
        if package.returncode != 0 or package.stdout != expected:
            raise OSError

        owner = subprocess.run(
            (_DPKG_QUERY, "-S", item.path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            shell=False,
            timeout=5.0,
            check=False,
        )
        expected_owners = {
            f"{item.package}: {item.path}\n".encode("ascii"),
            f"{item.package}:{item.architecture}: {item.path}\n".encode("ascii"),
        }
        if owner.returncode != 0 or owner.stdout not in expected_owners:
            raise OSError
        observed.append(item.path)
    return tuple(observed)


def _require_systemd_assets_visible() -> None:
    executor_paths = tuple(
        _read_systemctl(
            "omnilyzer-deployment-executor.service", "DropInPaths"
        ).split()
    )
    user_paths = tuple(_read_systemctl(_USER_MANAGER, "DropInPaths").split())
    _require_user_manager_template_dropins()
    if (
        executor_paths != (AUTHORITY.executor_socket_dropin,)
        or user_paths != _expected_user_manager_dropins()
    ):
        raise OSError
    for unit in _DEPLOYMENT_UNITS:
        if _read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError


def _bootstrap_under_lock() -> RootlessDockerStaticBootstrapEvidence:
    identity = _root_identity()
    state = _bootstrap_state()
    phase = _phase(state)

    if phase == "initial":
        before = postinstall.qualify_rootless_docker_postinstall()
        static_before = (
            before.expected_workflow_sha,
            before.supplementary_gids,
            before.host_dependencies,
            before.packages,
            before.cgroup_controllers,
            before.critical_executables,
            before.bundle,
        )
    else:
        static_before = _static_package_host()

    if phase != "complete":
        _ensure_subids()
        _install_static_assets()
        result = _run((_SYSTEMCTL, "daemon-reload"))
        if result.returncode != 0:
            raise OSError

    final_state = _bootstrap_state()
    if _phase(final_state) != "complete":
        raise OSError
    _require_directory_contents(allow_temporary=False)
    _require_systemd_assets_visible()
    static_after = _static_package_host()
    if static_after != static_before or _root_identity() != identity:
        raise OSError

    return RootlessDockerStaticBootstrapEvidence(
        "already-bootstrapped" if phase == "complete"
        else "bootstrapped" if phase == "initial"
        else "resumed",
        static_after[0],
        (AUTHORITY.executor_user, AUTHORITY.subuid_start, AUTHORITY.subordinate_count),
        (AUTHORITY.executor_user, AUTHORITY.subgid_start, AUTHORITY.subordinate_count),
        AUTHORITY.provisioned_directories,
        tuple(
            (destination, digest, uid, gid, mode)
            for _source, destination, digest, uid, gid, mode
            in AUTHORITY.installed_assets
        ),
        INSTALLATION_AUTHORITY.rootful_units,
        static_after[3],
        tuple(item.sha256 for item in static_after[6].files),
    )


def bootstrap_rootless_docker_static_host() -> RootlessDockerStaticBootstrapEvidence:
    """Install only the static C32ZZ host authority under the shared lock."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        result = _bootstrap_under_lock()
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        if lock is not None:
            try:
                orchestration._release_process_lock(lock)
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise RootlessDockerStaticBootstrapError(_ERROR) from None
    return result
