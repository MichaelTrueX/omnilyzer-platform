"""deployment/rootless_docker_static_bootstrap_qualification.py - C33A proof.

Purpose:
- independently qualify the static host state created by C32ZZ;
- prove exact executor subordinate UID/GID authority, reviewed persistent
  directories/assets, systemd drop-in visibility, package/runtime invariants,
  and continued inactivity before linger/user-manager/rootless-Docker startup;
- remain fully read-only and independent from the C32ZZ mutating module.

C33A does not import rootless_docker_static_bootstrap and performs no package,
filesystem, account, systemd, Docker, network, or deployment mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
import subprocess

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
    "RootlessDockerStaticBootstrapQualificationError",
    "RootlessDockerStaticBootstrapEvidence",
    "qualify_rootless_docker_static_bootstrap",
)

_ERROR = "rootless Docker static bootstrap qualification is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_TIMEOUT = 5.0
_OUTPUT_LIMIT = 256 * 1024
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CHUNK = 64 * 1024
_SUBUID = "/etc/subuid"
_SUBGID = "/etc/subgid"
_USER_MANAGER = "user@991.service"
_LINGER_PATH = "/var/lib/systemd/linger/omnilyzer-executor"
_USER_UNIT_ENABLE_LINK = (
    "/etc/systemd/user/default.target.wants/omnilyzer-task014-rootless-docker.service"
)
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


class RootlessDockerStaticBootstrapQualificationError(Exception):
    """One fixed external failure for the C33A read-only boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerStaticBootstrapEvidence:
    """Exact static bootstrap evidence observed twice without mutation."""

    application_reviewed_commit: str
    expected_workflow_sha: str
    executor_uid: int
    executor_gid: int
    supplementary_gids: tuple[int, ...]
    subuid_records: tuple[tuple[str, int, int], ...]
    subgid_records: tuple[tuple[str, int, int], ...]
    directories: tuple[tuple[str, int, int, int], ...]
    assets: tuple[tuple[str, str, int, int, int], ...]
    packages: tuple[tuple[str, str, str], ...]
    host_dependencies: tuple[tuple[str, str, str], ...]
    masked_units: tuple[str, ...]
    critical_executables: tuple[tuple[str, str, int, str], ...]
    cgroup_controllers: tuple[str, ...]
    executor_dropins: tuple[str, ...]
    user_manager_dropins: tuple[str, ...]
    bundle: RootlessDockerPackageBundleEvidence

    def __post_init__(self) -> None:
        expected_packages = tuple(
            (item.package, _TARGET_VERSIONS[item.package], "amd64")
            for item in INSTALLATION_AUTHORITY.payloads
        )
        expected_assets = tuple(
            (destination, digest, uid, gid, mode)
            for _source, destination, digest, uid, gid, mode
            in AUTHORITY.installed_assets
        )
        expected_executor = (
            AUTHORITY.executor_user,
            AUTHORITY.subuid_start,
            AUTHORITY.subordinate_count,
        )
        if (
            self.application_reviewed_commit != TARGET_REVIEWED_COMMIT
            or type(self.expected_workflow_sha) is not str
            or len(self.expected_workflow_sha) != 40
            or self.expected_workflow_sha == "0" * 40
            or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
            or (self.executor_uid, self.executor_gid)
            != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
            or self.supplementary_gids != (992,)
            or self.subuid_records != self.subgid_records
            or tuple(
                item for item in self.subuid_records
                if item[0] == AUTHORITY.executor_user
            ) != (expected_executor,)
            or tuple(
                item for item in self.subuid_records if item[0] == "omnigpt"
            ) != (("omnigpt", 427680, 65536),)
            or self.directories != AUTHORITY.provisioned_directories
            or self.assets != expected_assets
            or self.packages != expected_packages
            or type(self.host_dependencies) is not tuple
            or len(self.host_dependencies)
            != len(INSTALLATION_AUTHORITY.host_dependencies)
            or any(
                type(observed) is not tuple
                or len(observed) != 3
                or observed[0] != requirement.package
                or type(observed[1]) is not str
                or not observed[1]
                or any(char not in preinstall._VERSION_CHARS for char in observed[1])
                or observed[2] != requirement.architecture
                for observed, requirement in zip(
                    self.host_dependencies,
                    INSTALLATION_AUTHORITY.host_dependencies,
                    strict=True,
                )
            )
            or self.masked_units != INSTALLATION_AUTHORITY.rootful_units
            or type(self.critical_executables) is not tuple
            or len(self.critical_executables)
            != len(postinstall._REQUIRED_EXECUTABLES)
            or tuple(
                (package, path, mode)
                for package, path, mode, _sha256 in self.critical_executables
            )
            != tuple(
                (package, path, postinstall._EXECUTABLE_MODES[path])
                for package, path in postinstall._REQUIRED_EXECUTABLES
            )
            or any(
                type(sha256) is not str
                or len(sha256) != 64
                or any(c not in "0123456789abcdef" for c in sha256)
                for _package, _path, _mode, sha256 in self.critical_executables
            )
            or next(
                sha256
                for _package, path, _mode, sha256 in self.critical_executables
                if path == AUTHORITY.vendor_rootless_script
            ) != AUTHORITY.vendor_rootless_script_sha256
            or not {"cpu", "memory", "pids"}.issubset(
                frozenset(self.cgroup_controllers)
            )
            or self.executor_dropins != (AUTHORITY.executor_socket_dropin,)
            or self.user_manager_dropins != (AUTHORITY.cgroup_dropin,)
            or type(self.bundle) is not RootlessDockerPackageBundleEvidence
            or self.bundle.staging_directory
            != INSTALLATION_AUTHORITY.staging_directory
            or tuple(item.sha256 for item in self.bundle.files)
            != tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads)
        ):
            raise ValueError(_ERROR)
        RootlessDockerPackageBundleEvidence.__post_init__(self.bundle)


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
        timeout=_TIMEOUT,
        check=False,
    )
    if (
        type(result.returncode) is not int
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or len(result.stdout) > _OUTPUT_LIMIT
        or not result.stdout.endswith(b"\n")
        or b"\r" in result.stdout
        or b"\n" in result.stdout[:-1]
    ):
        raise OSError
    return result.stdout[:-1].decode("ascii")


def _require_subids() -> tuple[
    tuple[tuple[str, int, int], ...],
    tuple[tuple[str, int, int], ...],
]:
    subuid = preinstall._subid_records(_SUBUID)
    subgid = preinstall._subid_records(_SUBGID)
    expected_executor = (
        AUTHORITY.executor_user,
        AUTHORITY.subuid_start,
        AUTHORITY.subordinate_count,
    )
    if (
        subuid != subgid
        or tuple(item for item in subuid if item[0] == AUTHORITY.executor_user)
        != (expected_executor,)
        or tuple(item for item in subuid if item[0] == "omnigpt")
        != (("omnigpt", 427680, 65536),)
    ):
        raise OSError
    return subuid, subgid


def _require_directory(
    path: str,
    uid: int,
    gid: int,
    mode: int,
    expected_children: frozenset[str],
) -> tuple[str, int, int, int]:
    descriptor = None
    try:
        named = os.lstat(path)
        if (
            not stat.S_ISDIR(named.st_mode)
            or (named.st_uid, named.st_gid) != (uid, gid)
            or stat.S_IMODE(named.st_mode) != mode
        ):
            raise OSError
        descriptor = os.open(path, _DIRECTORY_FLAGS)
        opened = os.fstat(descriptor)
        if (
            _fingerprint(opened) != _fingerprint(named)
            or frozenset(os.listdir(descriptor)) != expected_children
            or _fingerprint(os.fstat(descriptor)) != _fingerprint(named)
            or _fingerprint(os.lstat(path)) != _fingerprint(named)
        ):
            raise OSError
        return path, uid, gid, mode
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_file(
    path: str,
    digest: str,
    uid: int,
    gid: int,
    mode: int,
) -> tuple[str, str, int, int, int]:
    descriptor = None
    try:
        named = os.lstat(path)
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
        fingerprint = _fingerprint(opened)
        if fingerprint != _fingerprint(named):
            raise OSError
        value = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(_CHUNK, remaining))
            if type(chunk) is not bytes or not chunk:
                raise OSError
            value.update(chunk)
            remaining -= len(chunk)
        if (
            os.read(descriptor, 1) != b""
            or value.hexdigest() != digest
            or _fingerprint(os.fstat(descriptor)) != fingerprint
            or _fingerprint(os.lstat(path)) != fingerprint
        ):
            raise OSError
        return path, digest, uid, gid, mode
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_static_assets() -> tuple[
    tuple[tuple[str, int, int, int], ...],
    tuple[tuple[str, str, int, int, int], ...],
]:
    directories = tuple(
        _require_directory(
            path,
            uid,
            gid,
            mode,
            _EXPECTED_DIRECTORY_CHILDREN[path],
        )
        for path, uid, gid, mode in AUTHORITY.provisioned_directories
    )
    assets = tuple(
        _require_file(destination, digest, uid, gid, mode)
        for _source, destination, digest, uid, gid, mode
        in AUTHORITY.installed_assets
    )
    return directories, assets


def _require_inert_systemd() -> tuple[tuple[str, ...], tuple[str, ...]]:
    for unit in _DEPLOYMENT_UNITS:
        if _read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError
    if (
        _read_systemctl(_USER_MANAGER, "LoadState") != "loaded"
        or _read_systemctl(_USER_MANAGER, "ActiveState") != "inactive"
    ):
        raise OSError
    executor_dropins = tuple(
        _read_systemctl(
            "omnilyzer-deployment-executor.service", "DropInPaths"
        ).split()
    )
    user_dropins = tuple(_read_systemctl(_USER_MANAGER, "DropInPaths").split())
    if (
        executor_dropins != (AUTHORITY.executor_socket_dropin,)
        or user_dropins != (AUTHORITY.cgroup_dropin,)
        or os.path.lexists(_LINGER_PATH)
        or os.path.lexists(_USER_UNIT_ENABLE_LINK)
    ):
        raise OSError
    for path in (AUTHORITY.runtime_directory, AUTHORITY.socket_directory):
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        raise OSError
    return executor_dropins, user_dropins


def _require_package_host():
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


def _qualify_once() -> RootlessDockerStaticBootstrapEvidence:
    identity = _root_identity()
    package_host = _require_package_host()
    subuid, subgid = _require_subids()
    directories, assets = _require_static_assets()
    executor_dropins, user_dropins = _require_inert_systemd()
    if _root_identity() != identity:
        raise OSError
    return RootlessDockerStaticBootstrapEvidence(
        application_reviewed_commit=TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=package_host[0],
        executor_uid=AUTHORITY.executor_uid,
        executor_gid=AUTHORITY.executor_gid,
        supplementary_gids=package_host[1],
        subuid_records=subuid,
        subgid_records=subgid,
        directories=directories,
        assets=assets,
        packages=package_host[3],
        host_dependencies=package_host[2],
        masked_units=INSTALLATION_AUTHORITY.rootful_units,
        critical_executables=package_host[5],
        cgroup_controllers=package_host[4],
        executor_dropins=executor_dropins,
        user_manager_dropins=user_dropins,
        bundle=package_host[6],
    )


def qualify_rootless_docker_static_bootstrap() -> RootlessDockerStaticBootstrapEvidence:
    """Require two identical independent C32ZZ static-host observations."""

    try:
        first = _qualify_once()
        second = _qualify_once()
        if second != first:
            raise OSError
        return first
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerStaticBootstrapQualificationError(_ERROR) from None
