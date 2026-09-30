"""deployment/rootless_docker_postinstall_qualification.py - C32ZX proof.

Purpose:
- independently qualify the exact C32ZW package-only installed state;
- prove exact package versions/architecture, critical executable ownership,
  vendor rootless bootstrap identity, persistent rootful masks/inactivity,
  unchanged non-package host authority, and the unchanged C32ZS bundle;
- remain read-only so package installation cannot self-authorize later bootstrap.

C32ZX performs no package, filesystem, service, subordinate-ID, Docker, network,
or deployment mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
import subprocess

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
    "RootlessDockerPostinstallQualificationError",
    "RootlessDockerPostinstallEvidence",
    "qualify_rootless_docker_postinstall",
)

_ERROR = "rootless Docker postinstall qualification is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_DPKG_QUERY = "/usr/bin/dpkg-query"
_TIMEOUT = 5.0
_OUTPUT_LIMIT = 256 * 1024
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CHUNK = 64 * 1024
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
_REQUIRED_EXECUTABLES = tuple(
    (item.name, path)
    for item in AUTHORITY.packages
    for path in item.required_executables
)
_EXECUTABLE_MODES = {
    "/usr/bin/dockerd": 0o755,
    "/usr/bin/docker": 0o755,
    "/usr/bin/dockerd-rootless.sh": 0o755,
    "/usr/bin/rootlesskit": 0o755,
    "/usr/libexec/docker/cli-plugins/docker-compose": 0o755,
    "/usr/bin/containerd": 0o755,
    "/usr/bin/newuidmap": 0o4755,
    "/usr/bin/newgidmap": 0o4755,
    "/usr/bin/slirp4netns": 0o755,
}
_ROOTFUL_MASK_PATHS = tuple(
    "/etc/systemd/system/" + unit
    for unit in INSTALLATION_AUTHORITY.rootful_units
)
_RUNTIME_FORBIDDEN = (
    "/var/run/docker.sock",
    "/run/user/991/docker.sock",
    "/run/omnilyzer/deployment/rootless-docker/docker.sock",
    "/run/user/991",
    INSTALLATION_AUTHORITY.docker_key_path,
    INSTALLATION_AUTHORITY.docker_source_path,
    INSTALLATION_AUTHORITY.policy_rc_d_path,
    INSTALLATION_AUTHORITY.staging_directory + ".incoming",
)
_ROOTLESSKIT_SHADOWS = (
    "/usr/sbin/docker-rootlesskit",
    "/usr/bin/docker-rootlesskit",
    "/bin/docker-rootlesskit",
    "/usr/sbin/rootlesskit",
)
_COMPOSE_SHADOWS = (
    "/etc/omnilyzer/deployment/docker-client/cli-plugins/docker-compose",
    "/usr/local/lib/docker/cli-plugins/docker-compose",
    "/usr/local/libexec/docker/cli-plugins/docker-compose",
    "/usr/lib/docker/cli-plugins/docker-compose",
)
_BUILDX_SHADOWS = (
    "/etc/omnilyzer/deployment/docker-client/cli-plugins/docker-buildx",
    "/usr/local/lib/docker/cli-plugins/docker-buildx",
    "/usr/local/libexec/docker/cli-plugins/docker-buildx",
    "/usr/lib/docker/cli-plugins/docker-buildx",
    "/usr/libexec/docker/cli-plugins/docker-buildx",
)


class RootlessDockerPostinstallQualificationError(Exception):
    """One fixed external failure for the C32ZX read-only boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerPostinstallEvidence:
    """Exact package-only installed-state evidence."""

    application_reviewed_commit: str
    expected_workflow_sha: str
    executor_uid: int
    executor_gid: int
    supplementary_gids: tuple[int, ...]
    packages: tuple[tuple[str, str, str], ...]
    host_dependencies: tuple[tuple[str, str, str], ...]
    masked_units: tuple[str, ...]
    critical_executables: tuple[tuple[str, str, int, str], ...]
    vendor_rootless_script_sha256: str
    subuid_start: int
    subgid_start: int
    subordinate_count: int
    cgroup_controllers: tuple[str, ...]
    bundle: RootlessDockerPackageBundleEvidence

    def __post_init__(self) -> None:
        expected_packages = tuple(
            (item.package, _TARGET_VERSIONS[item.package], "amd64")
            for item in INSTALLATION_AUTHORITY.payloads
        )
        expected_executables = tuple(
            (package, path, _EXECUTABLE_MODES[path])
            for package, path in _REQUIRED_EXECUTABLES
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
            or len(self.critical_executables) != len(expected_executables)
            or any(
                type(item) is not tuple
                or len(item) != 4
                or type(item[0]) is not str
                or type(item[1]) is not str
                or type(item[2]) is not int
                or type(item[3]) is not str
                for item in self.critical_executables
            )
            or tuple(
                (package, path, mode)
                for package, path, mode, _sha256 in self.critical_executables
            ) != expected_executables
            or any(
                type(sha256) is not str
                or len(sha256) != 64
                or any(c not in "0123456789abcdef" for c in sha256)
                for _package, _path, _mode, sha256 in self.critical_executables
            )
            or next(
                sha256
                for package, path, _mode, sha256 in self.critical_executables
                if path == AUTHORITY.vendor_rootless_script
            ) != AUTHORITY.vendor_rootless_script_sha256
            or self.vendor_rootless_script_sha256
            != AUTHORITY.vendor_rootless_script_sha256
            or self.subuid_start != AUTHORITY.subuid_start
            or self.subgid_start != AUTHORITY.subgid_start
            or self.subordinate_count != AUTHORITY.subordinate_count
            or not {"cpu", "memory", "pids"}.issubset(
                frozenset(self.cgroup_controllers)
            )
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


def _run_owner(path: str) -> str:
    """Return the exact dpkg owner for one reviewed executable path."""

    reviewed_paths = frozenset(candidate for _package, candidate in _REQUIRED_EXECUTABLES)
    if (
        type(path) is not str
        or path not in reviewed_paths
    ):
        raise OSError
    result = subprocess.run(
        (_DPKG_QUERY, "-S", path),
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
        or result.stdout.count(b"\n") != 1
        or b"\r" in result.stdout
    ):
        raise OSError
    try:
        line = result.stdout[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None
    suffix = ": " + path
    if not line.endswith(suffix):
        raise OSError
    owner = line[: -len(suffix)]
    expected = next(
        package
        for package, candidate in _REQUIRED_EXECUTABLES
        if candidate == path
    )
    if owner not in {expected, expected + ":amd64"}:
        raise OSError
    return expected


def _require_package(payload) -> tuple[str, str, str]:
    """Require one exact target package to be fully installed."""

    if payload not in INSTALLATION_AUTHORITY.payloads:
        raise OSError
    result = preinstall._run(
        (
            preinstall._DPKG_QUERY,
            "-W",
            preinstall._DPKG_FORMAT,
            payload.package,
        )
    )
    if (
        result.returncode != 0
        or not result.stdout.endswith(b"\n")
        or result.stdout.count(b"\n") != 1
        or b"\r" in result.stdout
    ):
        raise OSError
    fields = result.stdout[:-1].split(b"\t")
    if len(fields) != 3 or fields[0] != b"ii ":
        raise OSError
    try:
        version = fields[1].decode("ascii")
        architecture = fields[2].decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None
    if (
        version != _TARGET_VERSIONS[payload.package]
        or architecture != "amd64"
    ):
        raise OSError
    return payload.package, version, architecture


def _require_rootful_masked() -> None:
    """Require exact persistent masks, inactivity, and no rootful runtime."""

    for unit, path in zip(
        INSTALLATION_AUTHORITY.rootful_units,
        _ROOTFUL_MASK_PATHS,
        strict=True,
    ):
        value = os.lstat(path)
        if (
            not stat.S_ISLNK(value.st_mode)
            or (value.st_uid, value.st_gid) != (0, 0)
            or os.readlink(path) != "/dev/null"
            or preinstall._systemctl_value(unit, "LoadState") != "masked"
            or preinstall._systemctl_value(unit, "UnitFileState") != "masked"
            or preinstall._systemctl_value(unit, "ActiveState") != "inactive"
        ):
            raise OSError
    for name in ("dockerd", "containerd"):
        result = preinstall._run((preinstall._PGREP, "-x", name))
        if result.returncode != 1 or result.stdout != b"":
            raise OSError
    for path in _RUNTIME_FORBIDDEN:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        raise OSError


def _require_conflicts_absent() -> None:
    targets = frozenset(_TARGET_VERSIONS)
    for name in INSTALLATION_AUTHORITY.conflicting_packages:
        if name not in targets:
            preinstall._require_package_not_installed(name)


def _hash_exact_file(
    path: str,
    *,
    mode: int,
    expected_sha256: str | None = None,
) -> tuple[tuple[int, ...], str]:
    """Require one root-owned regular single-link executable and hash it."""

    descriptor = None
    try:
        named = os.lstat(path)
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_nlink != 1
            or (named.st_uid, named.st_gid) != (0, 0)
            or stat.S_IMODE(named.st_mode) != mode
            or named.st_size <= 0
            or named.st_size > 256 * 1024 * 1024
        ):
            raise OSError
        descriptor = os.open(path, _FILE_FLAGS)
        opened = os.fstat(descriptor)
        fingerprint = _fingerprint(opened)
        if fingerprint != _fingerprint(named):
            raise OSError
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(_CHUNK, remaining))
            if type(chunk) is not bytes or not chunk:
                raise OSError
            digest.update(chunk)
            remaining -= len(chunk)
        sha256 = digest.hexdigest()
        if (
            os.read(descriptor, 1) != b""
            or expected_sha256 is not None
            and sha256 != expected_sha256
        ):
            raise OSError
        if (
            _fingerprint(os.fstat(descriptor)) != fingerprint
            or _fingerprint(os.lstat(path)) != fingerprint
        ):
            raise OSError
        return fingerprint, sha256
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_critical_executables() -> tuple[tuple[str, str, int, str], ...]:
    evidence = []
    for package, path in _REQUIRED_EXECUTABLES:
        if _run_owner(path) != package:
            raise OSError
        expected_sha = (
            AUTHORITY.vendor_rootless_script_sha256
            if path == AUTHORITY.vendor_rootless_script
            else None
        )
        _fingerprint_value, sha256 = _hash_exact_file(
            path,
            mode=_EXECUTABLE_MODES[path],
            expected_sha256=expected_sha,
        )
        evidence.append((package, path, _EXECUTABLE_MODES[path], sha256))
    return tuple(evidence)


def _require_no_shadowing() -> None:
    """Reject alternate rootless/bootstrap/Compose/Buildx plugin selections."""

    for path in _ROOTLESSKIT_SHADOWS:
        if os.path.lexists(path):
            raise OSError
    for path in _COMPOSE_SHADOWS:
        if not os.path.lexists(path):
            continue
        try:
            if not os.path.samefile(path, AUTHORITY.compose_plugin):
                raise OSError
        except (FileNotFoundError, OSError):
            raise OSError from None
    for path in _BUILDX_SHADOWS:
        if os.path.lexists(path):
            raise OSError


def _qualify_once() -> RootlessDockerPostinstallEvidence:
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
        _require_package(item)
        for item in INSTALLATION_AUTHORITY.payloads
    )
    _require_conflicts_absent()
    _require_rootful_masked()
    preinstall._require_subid_authority()
    controllers = preinstall._require_kernel_prerequisites()
    _require_no_shadowing()
    executables = _require_critical_executables()
    bundle = qualify_rootless_docker_package_bundle()

    if _root_identity() != identity:
        raise OSError

    return RootlessDockerPostinstallEvidence(
        application_reviewed_commit=TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=migrated.expected_workflow_sha,
        executor_uid=AUTHORITY.executor_uid,
        executor_gid=AUTHORITY.executor_gid,
        supplementary_gids=supplementary,
        packages=packages,
        host_dependencies=dependencies,
        masked_units=INSTALLATION_AUTHORITY.rootful_units,
        critical_executables=executables,
        vendor_rootless_script_sha256=AUTHORITY.vendor_rootless_script_sha256,
        subuid_start=AUTHORITY.subuid_start,
        subgid_start=AUTHORITY.subgid_start,
        subordinate_count=AUTHORITY.subordinate_count,
        cgroup_controllers=controllers,
        bundle=bundle,
    )


def qualify_rootless_docker_postinstall() -> RootlessDockerPostinstallEvidence:
    """Require two identical independent package-only installed observations."""

    try:
        first = _qualify_once()
        second = _qualify_once()
        if second != first:
            raise OSError
        return first
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerPostinstallQualificationError(_ERROR) from None
