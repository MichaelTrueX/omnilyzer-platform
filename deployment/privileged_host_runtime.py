"""Inert C30 privileged primitives for future DEV host provisioning.

This boundary is separate from the deployment executor and Docker runtime.  It
projects exact C17/C13/C21/C23 authority into single-resource host mutations;
it does not choose provisioning order, install an application or venv, operate
systemd, execute Docker, or activate deployment authority.
"""

from dataclasses import dataclass as _dataclass
import grp as _grp
import hashlib as _hashlib
import os as _os
from pathlib import PurePosixPath as _PurePosixPath
import pwd as _pwd
import re as _re
import stat as _stat
import subprocess as _subprocess
import sys as _sys
import threading as _threading

from . import executor_service_config as _c17
from . import host_provisioning_contract as _c23
from . import installation_integrity_contract as _c24

__all__ = (
    "HostRuntimeError",
    "HostMutationEvidence",
    "DevPrivilegedHostRuntime",
)

_ERROR = "DEV privileged host operation is unavailable"
_CONFIGURATION_ERROR = "DEV privileged host runtime configuration is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_GROUPADD = "/usr/sbin/groupadd"
_USERADD = "/usr/sbin/useradd"
_NOLOGIN = "/usr/sbin/nologin"
_NO_HOME = "/nonexistent"
_ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
_TIMEOUT = 10
_MAX_FILE_BYTES = 64 * 1024
_CHUNK = 64 * 1024
_TEMPORARY_NAME = ".omnilyzer-c30-install.tmp"


class HostRuntimeError(Exception):
    """A closed privileged primitive did not complete trustworthily."""


@_dataclass(frozen=True, slots=True)
class HostMutationEvidence:
    """One explicit result from a single closed C30 primitive."""

    resource_kind: str
    resource: str
    outcome: str

    def __post_init__(self) -> None:
        if (type(self.resource_kind) is not str
                or self.resource_kind not in ("group", "user", "directory", "regular_file")
                or type(self.resource) is not str or not self.resource
                or type(self.outcome) is not str
                or self.outcome not in ("created", "replaced", "unchanged")):
            raise ValueError(_CONFIGURATION_ERROR)
        if self.resource_kind in ("group", "user"):
            if _re.fullmatch(r"[a-z][a-z0-9-]{0,30}", self.resource) is None:
                raise ValueError(_CONFIGURATION_ERROR)
        elif (not self.resource.startswith("/") or self.resource.startswith("//")
              or str(_PurePosixPath(self.resource)) != self.resource
              or any(part in ("", ".", "..") for part in self.resource[1:].split("/"))):
            raise ValueError(_CONFIGURATION_ERROR)


@_dataclass(frozen=True, slots=True)
class _DirectoryAuthority:
    path: str
    mode: int
    owner_uid: int
    group_gid: int


@_dataclass(frozen=True, slots=True)
class _FileAuthority:
    path: str
    mode: int
    owner_uid: int
    group_gid: int


@_dataclass(frozen=True, slots=True)
class _Authority:
    groups: tuple[_c23.HostGroupRequirement, ...]
    users: tuple[_c23.HostUserRequirement, ...]
    directories: tuple[_DirectoryAuthority, ...]
    configuration_file: _FileAuthority
    configuration_bytes: bytes
    assets: tuple[_c23.HostInstalledAssetRequirement, ...]


def _fingerprint(value: _os.stat_result) -> tuple[int, ...]:
    return (value.st_mode, value.st_ino, value.st_dev, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _directory_fingerprint(value: _os.stat_result) -> tuple[int, ...]:
    """Retain stable directory identity/metadata while allowing child mutation."""
    return (value.st_mode, value.st_ino, value.st_dev, value.st_uid, value.st_gid)


def _claim(value: object, owned: list[int]) -> int:
    if type(value) is not int or value < 0 or value in owned:
        raise OSError
    owned.append(value)
    if _os.get_inheritable(value) is not False:
        raise OSError
    return value


def _directory(value: _os.stat_result, requirement: _DirectoryAuthority | None) -> _os.stat_result:
    if not _stat.S_ISDIR(value.st_mode) or _stat.S_ISLNK(value.st_mode):
        raise OSError
    mode = _stat.S_IMODE(value.st_mode)
    if requirement is None:
        if value.st_uid != 0 or (mode & 0o022 and not (mode & _stat.S_ISVTX)):
            raise OSError
    elif (mode != requirement.mode or value.st_uid != requirement.owner_uid
          or value.st_gid != requirement.group_gid):
        raise OSError
    return value


def _source_directory(value: _os.stat_result) -> _os.stat_result:
    """Accept untrusted checkout ownership while still rejecting path substitution."""
    if not _stat.S_ISDIR(value.st_mode) or _stat.S_ISLNK(value.st_mode):
        raise OSError
    return value


def _regular(value: _os.stat_result, requirement: _FileAuthority) -> _os.stat_result:
    if (not _stat.S_ISREG(value.st_mode) or _stat.S_ISLNK(value.st_mode)
            or value.st_nlink != 1 or _stat.S_IMODE(value.st_mode) != requirement.mode
            or value.st_uid != requirement.owner_uid or value.st_gid != requirement.group_gid
            or value.st_size < 0 or value.st_size > _MAX_FILE_BYTES):
        raise OSError
    return value


def _directory_map(authorities: tuple[_DirectoryAuthority, ...]) -> dict[str, _DirectoryAuthority]:
    result = {item.path: item for item in authorities}
    if len(result) != len(authorities):
        raise OSError
    return result


def _open_parent(path: str, authorities: tuple[_DirectoryAuthority, ...],
                 owned: list[int]) -> tuple[int, str, list[tuple[int, int | None, str | None, tuple[int, ...]]]]:
    directory_flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    requirements = _directory_map(authorities)
    root_named = _directory(_os.stat("/", follow_symlinks=False), requirements.get("/"))
    root = _claim(_os.open("/", directory_flags), owned)
    root_opened = _directory(_os.fstat(root), requirements.get("/"))
    if (root_named.st_dev, root_named.st_ino) != (root_opened.st_dev, root_opened.st_ino):
        raise OSError
    chain = [(root, None, None, _directory_fingerprint(root_opened))]
    parent = root
    current = ""
    parts = path[1:].split("/")
    for component in parts[:-1]:
        current += "/" + component
        requirement = requirements.get(current)
        named = _directory(_os.stat(component, dir_fd=parent, follow_symlinks=False), requirement)
        child = _claim(_os.open(component, directory_flags, dir_fd=parent), owned)
        opened = _directory(_os.fstat(child), requirement)
        if _directory_fingerprint(named) != _directory_fingerprint(opened):
            raise OSError
        chain.append((child, parent, component, _directory_fingerprint(opened)))
        parent = child
    return parent, parts[-1], chain


def _open_source_parent(
        path: str, owned: list[int],
) -> tuple[int, str, list[tuple[int, int | None, str | None, tuple[int, ...]]]]:
    """Open an untrusted source checkout by identity without following symlinks."""
    directory_flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    root_named = _source_directory(_os.stat("/", follow_symlinks=False))
    root = _claim(_os.open("/", directory_flags), owned)
    root_opened = _source_directory(_os.fstat(root))
    if _directory_fingerprint(root_named) != _directory_fingerprint(root_opened):
        raise OSError
    chain = [(root, None, None, _directory_fingerprint(root_opened))]
    parent = root
    parts = path[1:].split("/")
    for component in parts[:-1]:
        named = _source_directory(
            _os.stat(component, dir_fd=parent, follow_symlinks=False))
        child = _claim(_os.open(component, directory_flags, dir_fd=parent), owned)
        opened = _source_directory(_os.fstat(child))
        if _directory_fingerprint(named) != _directory_fingerprint(opened):
            raise OSError
        chain.append((child, parent, component, _directory_fingerprint(opened)))
        parent = child
    return parent, parts[-1], chain


def _revalidate_chain(chain: list[tuple[int, int | None, str | None, tuple[int, ...]]]) -> None:
    for descriptor, parent, name, expected in chain:
        if _directory_fingerprint(_os.fstat(descriptor)) != expected:
            raise OSError
        if parent is not None and name is not None:
            current = _os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _directory_fingerprint(current) != expected:
                raise OSError


def _close(owned: list[int]) -> None:
    active = _sys.exception()
    failure = None
    for descriptor in reversed(owned):
        try:
            _os.close(descriptor)
        except OSError as error:
            failure = error
    if failure is not None and active is None:
        raise failure


def _lookup(items: tuple[object, ...], attribute: str, value: object):
    if type(value) is not str:
        raise OSError
    matches = tuple(item for item in items if getattr(item, attribute) == value)
    if len(matches) != 1:
        raise OSError
    return matches[0]


def _group_state(requirement: _c23.HostGroupRequirement) -> str:
    try:
        by_name = _grp.getgrnam(requirement.name)
    except KeyError:
        by_name = None
    try:
        by_id = _grp.getgrgid(requirement.gid)
    except KeyError:
        by_id = None
    if by_name is None and by_id is None:
        return "absent"
    if (by_name is None or by_id is None or by_name.gr_gid != requirement.gid
            or by_id.gr_name != requirement.name):
        raise OSError
    return "exact"


def _group_names(groups: tuple[_c23.HostGroupRequirement, ...]) -> dict[int, str]:
    result = {item.gid: item.name for item in groups}
    if len(result) != len(groups):
        raise OSError
    return result


def _user_state(requirement: _c23.HostUserRequirement,
                groups: tuple[_c23.HostGroupRequirement, ...]) -> str:
    names = _group_names(groups)
    required_gids = (requirement.primary_gid, *requirement.supplementary_gids)
    if any(gid not in names for gid in required_gids):
        raise OSError
    for gid in required_gids:
        group = _lookup(groups, "name", names[gid])
        if _group_state(group) != "exact":
            raise OSError
    try:
        by_name = _pwd.getpwnam(requirement.name)
    except KeyError:
        by_name = None
    try:
        by_id = _pwd.getpwuid(requirement.uid)
    except KeyError:
        by_id = None
    if by_name is None and by_id is None:
        return "absent"
    if (by_name is None or by_id is None or by_name.pw_uid != requirement.uid
            or by_id.pw_name != requirement.name or by_name.pw_gid != requirement.primary_gid
            or by_name.pw_dir != _NO_HOME or by_name.pw_shell != _NOLOGIN):
        raise OSError
    actual = tuple(sorted(set(_os.getgrouplist(requirement.name, requirement.primary_gid))
                          - {requirement.primary_gid}))
    if actual != tuple(sorted(requirement.supplementary_gids)):
        raise OSError
    return "exact"


def _run_account_command(argv: tuple[str, ...]) -> None:
    if (type(argv) is not tuple or not argv or argv[0] not in (_GROUPADD, _USERADD)
            or any(type(item) is not str or not item for item in argv)):
        raise OSError
    result = _subprocess.run(
        argv, shell=False, stdin=_subprocess.DEVNULL,
        stdout=_subprocess.DEVNULL, stderr=_subprocess.DEVNULL,
        env=dict(_ENVIRONMENT), timeout=_TIMEOUT, check=False,
    )
    if type(result.returncode) is not int or result.returncode != 0:
        raise OSError


def _create_group(requirement: _c23.HostGroupRequirement) -> HostMutationEvidence:
    if _group_state(requirement) == "exact":
        return HostMutationEvidence("group", requirement.name, "unchanged")
    _run_account_command((_GROUPADD, "--system", "--gid", str(requirement.gid), requirement.name))
    if _group_state(requirement) != "exact":
        raise OSError
    return HostMutationEvidence("group", requirement.name, "created")


def _create_user(requirement: _c23.HostUserRequirement,
                 groups: tuple[_c23.HostGroupRequirement, ...]) -> HostMutationEvidence:
    if _user_state(requirement, groups) == "exact":
        return HostMutationEvidence("user", requirement.name, "unchanged")
    names = _group_names(groups)
    supplementary = ",".join(names[gid] for gid in requirement.supplementary_gids)
    argv = (
        _USERADD, "--system", "--uid", str(requirement.uid),
        "--gid", names[requirement.primary_gid],
        "--groups", supplementary, "--no-user-group", "--no-create-home",
        "--home-dir", _NO_HOME, "--shell", _NOLOGIN, requirement.name,
    )
    _run_account_command(argv)
    if _user_state(requirement, groups) != "exact":
        raise OSError
    return HostMutationEvidence("user", requirement.name, "created")


def _cleanup_created_directory(parent: int, name: str, identity: tuple[int, int]) -> None:
    """Remove only the still-empty directory created by this primitive attempt."""
    current = _os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not _stat.S_ISDIR(current.st_mode) or _stat.S_ISLNK(current.st_mode)
            or (current.st_dev, current.st_ino) != identity):
        raise OSError
    if _os.rmdir(name, dir_fd=parent) is not None:
        raise OSError
    if _os.fsync(parent) is not None:
        raise OSError


def _ensure_directory(requirement: _DirectoryAuthority,
                      authorities: tuple[_DirectoryAuthority, ...]) -> HostMutationEvidence:
    owned: list[int] = []
    created_identity = None
    completed = False
    try:
        parent, name, chain = _open_parent(requirement.path, authorities, owned)
        try:
            existing = _os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            _directory(existing, requirement)
            descriptor = _claim(_os.open(
                name, _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                dir_fd=parent), owned)
            if _fingerprint(_directory(_os.fstat(descriptor), requirement)) != _fingerprint(existing):
                raise OSError
            _revalidate_chain(chain)
            return HostMutationEvidence("directory", requirement.path, "unchanged")
        if _os.mkdir(name, 0o700, dir_fd=parent) is not None:
            raise OSError
        created_named = _os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not _stat.S_ISDIR(created_named.st_mode) or _stat.S_ISLNK(created_named.st_mode):
            raise OSError
        created_identity = (created_named.st_dev, created_named.st_ino)
        descriptor = _claim(_os.open(
            name, _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
            dir_fd=parent), owned)
        opened = _os.fstat(descriptor)
        if (not _stat.S_ISDIR(opened.st_mode) or _stat.S_ISLNK(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != created_identity):
            raise OSError
        if (opened.st_uid, opened.st_gid) != (requirement.owner_uid, requirement.group_gid):
            if _os.fchown(descriptor, requirement.owner_uid, requirement.group_gid) is not None:
                raise OSError
        if _os.fchmod(descriptor, requirement.mode) is not None or _os.fsync(descriptor) is not None:
            raise OSError
        exact = _directory(_os.fstat(descriptor), requirement)
        named = _directory(_os.stat(name, dir_fd=parent, follow_symlinks=False), requirement)
        if _fingerprint(exact) != _fingerprint(named):
            raise OSError
        _revalidate_chain(chain)
        if _os.fsync(parent) is not None:
            raise OSError
        evidence = HostMutationEvidence("directory", requirement.path, "created")
        completed = True
        return evidence
    finally:
        active = _sys.exception()
        try:
            if created_identity is not None and not completed and "parent" in locals():
                _cleanup_created_directory(parent, name, created_identity)
        except _CONTROL:
            if not isinstance(active, _CONTROL):
                raise
        except BaseException:
            if active is None:
                raise
        finally:
            _close(owned)


def _write_all(descriptor: int, payload: bytes) -> None:
    position = 0
    calls = 0
    while position < len(payload):
        calls += 1
        if calls > len(payload) + 1:
            raise OSError
        count = _os.write(descriptor, payload[position:position + _CHUNK])
        if type(count) is not int or not 0 < count <= min(_CHUNK, len(payload) - position):
            raise OSError
        position += count


def _read_exact(descriptor: int, size: int) -> bytes:
    if type(size) is not int or not 0 <= size <= _MAX_FILE_BYTES:
        raise OSError
    output = bytearray()
    while len(output) < size:
        chunk = _os.read(descriptor, min(_CHUNK, size - len(output)))
        if type(chunk) is not bytes or not chunk:
            raise OSError
        output.extend(chunk)
    if _os.read(descriptor, 1) != b"":
        raise OSError
    return bytes(output)


def _existing_file(parent: int, name: str, requirement: _FileAuthority,
                   owned: list[int]) -> tuple[tuple[int, ...], bytes] | None:
    try:
        named = _regular(_os.stat(name, dir_fd=parent, follow_symlinks=False), requirement)
    except FileNotFoundError:
        return None
    descriptor = _claim(_os.open(
        name, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC, dir_fd=parent), owned)
    opened = _regular(_os.fstat(descriptor), requirement)
    if _fingerprint(named) != _fingerprint(opened):
        raise OSError
    payload = _read_exact(descriptor, opened.st_size)
    if (_fingerprint(_regular(_os.fstat(descriptor), requirement)) != _fingerprint(opened)
            or _fingerprint(_regular(
                _os.stat(name, dir_fd=parent, follow_symlinks=False), requirement
            )) != _fingerprint(opened)):
        raise OSError
    return _fingerprint(opened), payload


def _cleanup_temporary(parent: int, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        status = _os.stat(_TEMPORARY_NAME, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (status.st_dev, status.st_ino) != identity or not _stat.S_ISREG(status.st_mode):
        raise OSError
    if _os.unlink(_TEMPORARY_NAME, dir_fd=parent) is not None:
        raise OSError
    if _os.fsync(parent) is not None:
        raise OSError


def _install_atomic(requirement: _FileAuthority, payload: bytes,
                    directories: tuple[_DirectoryAuthority, ...]) -> HostMutationEvidence:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_FILE_BYTES:
        raise OSError
    owned: list[int] = []
    temporary_identity = None
    replaced = False
    try:
        parent, name, chain = _open_parent(requirement.path, directories, owned)
        existing = _existing_file(parent, name, requirement, owned)
        if existing is not None and existing[1] == payload:
            _revalidate_chain(chain)
            if requirement.path == _c17.PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH:
                # A previous C17 rename may have succeeded while its parent
                # fsync failed.  Retry durability before reporting unchanged.
                if _os.fsync(parent) is not None:
                    raise OSError
                verified = _existing_file(parent, name, requirement, owned)
                if verified != existing:
                    raise OSError
            _revalidate_chain(chain)
            return HostMutationEvidence("regular_file", requirement.path, "unchanged")
        temporary = _claim(_os.open(
            _TEMPORARY_NAME,
            _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | _os.O_NOFOLLOW | _os.O_CLOEXEC,
            0o600, dir_fd=parent), owned)
        created = _os.fstat(temporary)
        if not _stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise OSError
        temporary_identity = (created.st_dev, created.st_ino)
        named_temporary = _os.stat(_TEMPORARY_NAME, dir_fd=parent, follow_symlinks=False)
        if (named_temporary.st_dev, named_temporary.st_ino) != temporary_identity:
            raise OSError
        if (created.st_uid, created.st_gid) != (requirement.owner_uid, requirement.group_gid):
            if _os.fchown(temporary, requirement.owner_uid, requirement.group_gid) is not None:
                raise OSError
        if _os.fchmod(temporary, requirement.mode) is not None:
            raise OSError
        _write_all(temporary, payload)
        if _os.fsync(temporary) is not None:
            raise OSError
        exact = _regular(_os.fstat(temporary), requirement)
        if exact.st_size != len(payload):
            raise OSError
        current = _os.stat(_TEMPORARY_NAME, dir_fd=parent, follow_symlinks=False)
        if _fingerprint(_regular(current, requirement)) != _fingerprint(exact):
            raise OSError
        if existing is None:
            try:
                _os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise OSError
        elif _fingerprint(_regular(
                _os.stat(name, dir_fd=parent, follow_symlinks=False), requirement)) != existing[0]:
            raise OSError
        _revalidate_chain(chain)
        if _os.replace(_TEMPORARY_NAME, name, src_dir_fd=parent, dst_dir_fd=parent) is not None:
            raise OSError
        replaced = True
        if _os.fsync(parent) is not None:
            raise OSError
        verified = _existing_file(parent, name, requirement, owned)
        if verified is None or verified[1] != payload or verified[0][:2] != _fingerprint(exact)[:2]:
            raise OSError
        _revalidate_chain(chain)
        return HostMutationEvidence(
            "regular_file", requirement.path, "created" if existing is None else "replaced")
    finally:
        active = _sys.exception()
        try:
            if not replaced and "parent" in locals():
                _cleanup_temporary(parent, temporary_identity)
        except _CONTROL:
            if not isinstance(active, _CONTROL):
                raise
        except BaseException:
            if active is None:
                raise
        finally:
            _close(owned)


def _read_reviewed_source(path: str, expected_sha256: str) -> bytes:
    owned: list[int] = []
    try:
        if (type(expected_sha256) is not str
                or _re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None):
            raise OSError
        parent, name, chain = _open_source_parent(path, owned)
        named = _os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not _stat.S_ISREG(named.st_mode) or _stat.S_ISLNK(named.st_mode)
                or named.st_nlink != 1
                or named.st_size <= 0 or named.st_size > _MAX_FILE_BYTES):
            raise OSError
        descriptor = _claim(_os.open(
            name, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC, dir_fd=parent), owned)
        opened = _os.fstat(descriptor)
        if _fingerprint(opened) != _fingerprint(named):
            raise OSError
        raw = _read_exact(descriptor, opened.st_size)
        if (_fingerprint(_os.fstat(descriptor)) != _fingerprint(opened)
                or _fingerprint(_os.stat(name, dir_fd=parent, follow_symlinks=False))
                != _fingerprint(opened)):
            raise OSError
        _revalidate_chain(chain)
        if _hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise OSError
        return raw
    finally:
        _close(owned)


def _build_authority(configuration: _c17.DevExecutorServiceConfiguration) -> _Authority:
    if type(configuration) is not _c17.DevExecutorServiceConfiguration:
        raise TypeError(_CONFIGURATION_ERROR)
    try:
        integrity = _c24.DevInstallationIntegrityContract(configuration=configuration)
        provisioning = _c23.DevHostProvisioningContract(
            installation=configuration.installation_contract())
        paths = provisioning.path_requirements()
        resources = provisioning.runtime_resource_requirements()
        directories = tuple(_DirectoryAuthority(
            item.path, item.mode, item.owner_uid, item.group_gid)
            for item in (*paths, *resources) if item.kind == "directory")
        config_items = tuple(item for item in paths
                             if item.path == _c17.PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH)
        if len(config_items) != 1:
            raise ValueError
        config = config_items[0]
        if (integrity.service_layout() != provisioning.service_layout()
                or config.kind != "regular_file"):
            raise ValueError
        return _Authority(
            provisioning.group_requirements(), provisioning.user_requirements(), directories,
            _FileAuthority(config.path, config.mode, config.owner_uid, config.group_gid),
            configuration.canonical_bytes(), provisioning.installed_asset_requirements())
    except _CONTROL:
        raise
    except Exception:
        raise TypeError(_CONFIGURATION_ERROR) from None


class DevPrivilegedHostRuntime:
    """Constructor-bound, closed C30 mutation primitives for future C31 use."""

    __slots__ = ("_authority", "_lock")

    def __init__(self, *, configuration: _c17.DevExecutorServiceConfiguration) -> None:
        object.__setattr__(self, "_authority", _build_authority(configuration))
        object.__setattr__(self, "_lock", _threading.Lock())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_CONFIGURATION_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_CONFIGURATION_ERROR)

    def _perform(self, operation: str, selector: str | None) -> HostMutationEvidence:
        """Dispatch only a closed operation name; retain no generic callable authority."""
        lock = object.__getattribute__(self, "_lock")
        if not lock.acquire(blocking=False):
            raise HostRuntimeError(_ERROR) from None
        try:
            authority = object.__getattribute__(self, "_authority")
            if operation == "group" and type(selector) is str:
                requirement = _lookup(authority.groups, "name", selector)
                result = _create_group(requirement)
                resource_kind, resource = "group", requirement.name
            elif operation == "user" and type(selector) is str:
                requirement = _lookup(authority.users, "name", selector)
                result = _create_user(requirement, authority.groups)
                resource_kind, resource = "user", requirement.name
            elif operation == "directory" and type(selector) is str:
                requirement = _lookup(authority.directories, "path", selector)
                result = _ensure_directory(requirement, authority.directories)
                resource_kind, resource = "directory", requirement.path
            elif operation == "configuration" and selector is None:
                requirement = authority.configuration_file
                result = _install_atomic(
                    requirement, authority.configuration_bytes, authority.directories)
                resource_kind, resource = "regular_file", requirement.path
            elif operation == "asset" and type(selector) is str:
                asset = _lookup(authority.assets, "destination_path", selector)
                repository = _os.path.dirname(_os.path.dirname(__file__))
                payload = _read_reviewed_source(
                    repository + "/" + asset.source_path, asset.sha256)
                requirement = _FileAuthority(
                    asset.destination_path, asset.mode, asset.owner_uid, asset.group_gid)
                result = _install_atomic(requirement, payload, authority.directories)
                resource_kind, resource = "regular_file", requirement.path
            else:
                raise TypeError
            if type(result) is not HostMutationEvidence:
                raise TypeError
            HostMutationEvidence.__post_init__(result)
            if result.resource_kind != resource_kind or result.resource != resource:
                raise TypeError
            return result
        except _CONTROL:
            raise
        except Exception:
            raise HostRuntimeError(_ERROR) from None
        finally:
            lock.release()

    def create_required_group(self, name: str) -> HostMutationEvidence:
        """Create or verify one exact C23 group selected only by its reviewed name."""
        return self._perform("group", name)

    def create_required_user(self, name: str) -> HostMutationEvidence:
        """Create or verify one exact C23 non-login user and memberships."""
        return self._perform("user", name)

    def create_required_directory(self, path: str) -> HostMutationEvidence:
        """Create or verify one exact reviewed C23/C13 directory."""
        return self._perform("directory", path)

    def install_executor_configuration(self) -> HostMutationEvidence:
        """Atomically install only the constructor-bound canonical C17 bytes."""
        return self._perform("configuration", None)

    def install_required_asset(self, destination: str) -> HostMutationEvidence:
        """Atomically install one exact C23 repository asset at its fixed destination."""
        return self._perform("asset", destination)
