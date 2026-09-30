"""deployment/rootless_docker_preinstall_qualification.py - C32ZQ/C32ZT preflight.

Purpose:
- perform the privileged read-only host checks required immediately before
  any rootless Docker package/bootstrap mutation;
- prove the C32ZM successor migration is complete, the corrected subordinate
  ID range is free, Docker/rootful runtime is absent, executor identity remains
  isolated, and the exact preinstalled package dependency closure is satisfied.

Linked files:
- deployment/rootless_docker_installation_authority.py
- deployment/rootless_docker_authority.py
- deployment/successor_host_migration_qualification.py
"""

from __future__ import annotations

from dataclasses import dataclass
import grp
import os
import pwd
import stat
import subprocess

from .rootless_docker_authority import AUTHORITY
from .rootless_docker_installation_authority import (
    HostDependencyRequirement,
    INSTALLATION_AUTHORITY,
)
from .successor_application_generation import TARGET_REVIEWED_COMMIT
from .successor_host_migration_qualification import qualify_successor_host_migration

__all__ = (
    "RootlessDockerPreinstallQualificationError",
    "RootlessDockerPreinstallEvidence",
    "qualify_rootless_docker_preinstall",
)

_ERROR = "rootless Docker preinstall qualification is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_DPKG_QUERY = "/usr/bin/dpkg-query"
_DPKG = "/usr/bin/dpkg"
_SYSTEMCTL = "/usr/bin/systemctl"
_PGREP = "/usr/bin/pgrep"
_TIMEOUT = 5.0
_SUBUID = "/etc/subuid"
_SUBGID = "/etc/subgid"
_APPARMOR_PROFILE = "/etc/apparmor.d/rootlesskit"
_COMMON_FORBIDDEN_PATHS = (
    "/var/run/docker.sock",
    "/run/user/991/docker.sock",
    "/run/omnilyzer/deployment/rootless-docker/docker.sock",
    INSTALLATION_AUTHORITY.docker_key_path,
    INSTALLATION_AUTHORITY.docker_source_path,
    INSTALLATION_AUTHORITY.policy_rc_d_path,
    "/run/user/991",
)
_FINAL_STAGING_PATH = INSTALLATION_AUTHORITY.staging_directory
_ROOTFUL_MASK_PATHS = tuple(
    "/etc/systemd/system/" + unit
    for unit in INSTALLATION_AUTHORITY.rootful_units
)
_REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids"})
_MAX_SUBID_BYTES = 1024 * 1024
_ABSENT_PACKAGE_NAMES = frozenset(
    item.name for item in INSTALLATION_AUTHORITY.packages
) | frozenset(
    item.name for item in INSTALLATION_AUTHORITY.supplemental_packages
) | frozenset(INSTALLATION_AUTHORITY.conflicting_packages)
_DEPENDENCY_NAMES = frozenset(
    item.package for item in INSTALLATION_AUTHORITY.host_dependencies
)
_QUERY_PACKAGE_NAMES = _ABSENT_PACKAGE_NAMES | _DEPENDENCY_NAMES
_VERSION_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+:~-"
)
_DPKG_FORMAT = (
    "-f=" + "$" + "{db:Status-Abbrev}\t" + "$" + "{Version}\t"
    + "$" + "{Architecture}\n"
)


class RootlessDockerPreinstallQualificationError(Exception):
    """One fixed external failure for the privileged read-only preflight."""


@dataclass(frozen=True, slots=True)
class RootlessDockerPreinstallEvidence:
    """Compact evidence for the exact clean pre-install host boundary."""

    application_reviewed_commit: str
    expected_workflow_sha: str
    executor_uid: int
    executor_gid: int
    supplementary_gids: tuple[int, ...]
    subuid_start: int
    subgid_start: int
    subordinate_count: int
    direct_packages: tuple[str, ...]
    supplemental_packages: tuple[str, ...]
    host_dependencies: tuple[tuple[str, str, str], ...]
    cgroup_controllers: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject evidence that differs from the reviewed authority."""

        if (
            self.application_reviewed_commit != TARGET_REVIEWED_COMMIT
            or type(self.expected_workflow_sha) is not str
            or len(self.expected_workflow_sha) != 40
            or self.expected_workflow_sha == "0" * 40
            or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
            or (self.executor_uid, self.executor_gid)
            != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
            or self.supplementary_gids != (992,)
            or self.subuid_start != AUTHORITY.subuid_start
            or self.subgid_start != AUTHORITY.subgid_start
            or self.subordinate_count != AUTHORITY.subordinate_count
            or self.direct_packages
            != tuple(item.name for item in INSTALLATION_AUTHORITY.packages)
            or self.supplemental_packages
            != tuple(item.name for item in INSTALLATION_AUTHORITY.supplemental_packages)
            or type(self.host_dependencies) is not tuple
            or len(self.host_dependencies) != len(INSTALLATION_AUTHORITY.host_dependencies)
            or any(
                type(observed) is not tuple
                or len(observed) != 3
                or observed[0] != requirement.package
                or type(observed[1]) is not str
                or not observed[1]
                or any(char not in _VERSION_CHARS for char in observed[1])
                or observed[2] != requirement.architecture
                for observed, requirement in zip(
                    self.host_dependencies,
                    INSTALLATION_AUTHORITY.host_dependencies,
                    strict=True,
                )
            )
            or not _REQUIRED_CONTROLLERS.issubset(frozenset(self.cgroup_controllers))
        ):
            raise ValueError(_ERROR)


def _root_identity() -> tuple[int, int, int, int]:
    """Require unchanged real/effective root identity."""

    identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if any(type(value) is not int or value != 0 for value in identity):
        raise OSError
    return identity


def _run(argv: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    """Run one closed read-only command with bounded execution."""

    if (
        type(argv) is not tuple
        or not argv
        or any(type(value) is not str or not value for value in argv)
    ):
        raise OSError
    if argv[0] == _DPKG_QUERY:
        if (
            len(argv) != 4
            or argv[1:3] != ("-W", _DPKG_FORMAT)
            or argv[3] not in _QUERY_PACKAGE_NAMES
        ):
            raise OSError
    elif argv[0] == _DPKG:
        allowed_minimums = frozenset(
            item.minimum_version
            for item in INSTALLATION_AUTHORITY.host_dependencies
            if item.minimum_version is not None
        )
        if (
            len(argv) != 5
            or argv[1] != "--compare-versions"
            or not argv[2]
            or any(char not in _VERSION_CHARS for char in argv[2])
            or argv[3] != "ge"
            or argv[4] not in allowed_minimums
        ):
            raise OSError
    elif argv[0] == _SYSTEMCTL:
        if (
            len(argv) != 5
            or argv[1] != "show"
            or argv[2] not in {
                "--property=LoadState",
                "--property=ActiveState",
                "--property=UnitFileState",
            }
            or argv[3] != "--value"
            or argv[4] not in INSTALLATION_AUTHORITY.rootful_units
        ):
            raise OSError
    elif argv[0] == _PGREP:
        if len(argv) != 3 or argv[1] != "-x" or argv[2] not in {"dockerd", "containerd"}:
            raise OSError
    else:
        raise OSError
    result = subprocess.run(
        argv,
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
        or type(result.stdout) is not bytes
        or len(result.stdout) > 256 * 1024
    ):
        raise OSError
    return result


def _require_package_absent(name: str) -> None:
    """Require one package to have no dpkg record at all."""

    if type(name) is not str or name not in _ABSENT_PACKAGE_NAMES:
        raise OSError
    result = _run((_DPKG_QUERY, "-W", _DPKG_FORMAT, name))
    if result.returncode != 1 or result.stdout != b"":
        raise OSError


def _require_host_dependency(requirement) -> tuple[str, str, str]:
    """Require one exact-architecture installed dependency satisfying its floor."""

    if (
        type(requirement) is not HostDependencyRequirement
        or requirement not in INSTALLATION_AUTHORITY.host_dependencies
    ):
        raise OSError
    result = _run((_DPKG_QUERY, "-W", _DPKG_FORMAT, requirement.package))
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
        not version
        or any(char not in _VERSION_CHARS for char in version)
        or architecture != requirement.architecture
    ):
        raise OSError
    if requirement.minimum_version is not None:
        compared = _run(
            (
                _DPKG,
                "--compare-versions",
                version,
                "ge",
                requirement.minimum_version,
            )
        )
        if compared.returncode != 0 or compared.stdout != b"":
            raise OSError
    return requirement.package, version, architecture


def _systemctl_value(unit: str, property_name: str) -> str:
    """Read one rootful unit property through a fixed systemctl boundary."""

    if (
        unit not in INSTALLATION_AUTHORITY.rootful_units
        or property_name not in {"LoadState", "ActiveState", "UnitFileState"}
    ):
        raise OSError
    result = _run(
        (
            _SYSTEMCTL,
            "show",
            "--property=" + property_name,
            "--value",
            unit,
        )
    )
    if (
        result.returncode != 0
        or not result.stdout.endswith(b"\n")
        or b"\n" in result.stdout[:-1]
        or b"\r" in result.stdout
    ):
        raise OSError
    return result.stdout[:-1].decode("ascii")


def _require_rootful_runtime_absent() -> None:
    """Require no rootful unit, daemon process, socket, or mask residue."""

    for unit in INSTALLATION_AUTHORITY.rootful_units:
        if (
            _systemctl_value(unit, "LoadState") != "not-found"
            or _systemctl_value(unit, "ActiveState") != "inactive"
            or _systemctl_value(unit, "UnitFileState") != ""
        ):
            raise OSError
    for process_name in ("dockerd", "containerd"):
        result = _run((_PGREP, "-x", process_name))
        if result.returncode != 1 or result.stdout != b"":
            raise OSError
    for path in (*_COMMON_FORBIDDEN_PATHS, *_ROOTFUL_MASK_PATHS):
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        raise OSError


def _require_final_bundle_absent() -> None:
    """Require the fixed published C32ZS staging path to be absent."""

    try:
        os.lstat(_FINAL_STAGING_PATH)
    except FileNotFoundError:
        return
    raise OSError


def _read_root_regular(path: str, maximum: int) -> bytes:
    """Read one small root-owned regular file without following symlinks."""

    descriptor = None
    try:
        named = os.lstat(path)
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_nlink != 1
            or named.st_uid != 0
            or named.st_gid != 0
            or stat.S_IMODE(named.st_mode) != 0o644
            or named.st_size < 0
            or named.st_size > maximum
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened = os.fstat(descriptor)
        fingerprint = (
            opened.st_mode, opened.st_ino, opened.st_dev, opened.st_nlink,
            opened.st_uid, opened.st_gid, opened.st_size,
            opened.st_mtime_ns, opened.st_ctime_ns,
        )
        named_fingerprint = (
            named.st_mode, named.st_ino, named.st_dev, named.st_nlink,
            named.st_uid, named.st_gid, named.st_size,
            named.st_mtime_ns, named.st_ctime_ns,
        )
        if fingerprint != named_fingerprint:
            raise OSError
        chunks = bytearray()
        while len(chunks) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) != opened.st_size:
            raise OSError
        current = os.fstat(descriptor)
        named_after = os.lstat(path)
        if (
            (
                current.st_mode, current.st_ino, current.st_dev,
                current.st_nlink, current.st_uid, current.st_gid,
                current.st_size, current.st_mtime_ns, current.st_ctime_ns,
            ) != fingerprint
            or (
                named_after.st_mode, named_after.st_ino, named_after.st_dev,
                named_after.st_nlink, named_after.st_uid, named_after.st_gid,
                named_after.st_size, named_after.st_mtime_ns,
                named_after.st_ctime_ns,
            ) != fingerprint
        ):
            raise OSError
        return bytes(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _subid_records(path: str) -> tuple[tuple[str, int, int], ...]:
    """Parse one canonical subordinate-ID file and reject overlapping ranges."""

    raw = _read_root_regular(path, _MAX_SUBID_BYTES)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None
    records: list[tuple[str, int, int]] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 3 or not fields[0]:
            raise OSError
        start_text, count_text = fields[1], fields[2]
        if (
            not start_text.isdecimal()
            or not count_text.isdecimal()
            or str(int(start_text)) != start_text
            or str(int(count_text)) != count_text
        ):
            raise OSError
        start, count = int(start_text), int(count_text)
        if start <= 0 or count <= 0 or start + count > 2**32:
            raise OSError
        records.append((fields[0], start, count))
    intervals = sorted(
        (start, start + count - 1, name)
        for name, start, count in records
    )
    for previous, current in zip(intervals, intervals[1:]):
        if current[0] <= previous[1]:
            raise OSError
    return tuple(records)


def _require_subid_authority() -> None:
    """Require target range free and old omnigpt allocation exact in both files."""

    target_start = AUTHORITY.subuid_start
    target_end = target_start + AUTHORITY.subordinate_count - 1
    for path in (_SUBUID, _SUBGID):
        records = _subid_records(path)
        if tuple(item for item in records if item[0] == AUTHORITY.executor_user):
            raise OSError
        if tuple(item for item in records if item[0] == "omnigpt") != (
            ("omnigpt", 427680, 65536),
        ):
            raise OSError
        for _name, start, count in records:
            end = start + count - 1
            if not (end < target_start or start > target_end):
                raise OSError


def _require_executor_identity() -> tuple[int, ...]:
    """Require the executor account and supplementary replay group unchanged."""

    account = pwd.getpwnam(AUTHORITY.executor_user)
    primary = grp.getgrnam(AUTHORITY.executor_user)
    replay = grp.getgrnam("omnilyzer-replay")
    if (
        account.pw_uid != AUTHORITY.executor_uid
        or account.pw_gid != AUTHORITY.executor_gid
        or account.pw_dir != "/nonexistent"
        or account.pw_shell != "/usr/sbin/nologin"
        or primary.gr_gid != AUTHORITY.executor_gid
        or replay.gr_gid != 992
    ):
        raise OSError
    groups = tuple(sorted(set(os.getgrouplist(account.pw_name, account.pw_gid))))
    if groups != (991, 992):
        raise OSError
    return (992,)


def _read_virtual_scalar(path: str) -> str:
    """Read one bounded kernel scalar without treating it as durable authority."""

    with open(path, "rb", buffering=0) as source:
        raw = source.read(4097)
    if len(raw) > 4096 or not raw.endswith(b"\n"):
        raise OSError
    value = raw[:-1].decode("ascii")
    if not value or "\n" in value or "\r" in value:
        raise OSError
    return value


def _require_kernel_prerequisites() -> tuple[str, ...]:
    """Require user namespaces, AppArmor rootless profile, and cgroup controls."""

    if _read_virtual_scalar(
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
    ) != "1":
        raise OSError
    if _read_virtual_scalar(
        "/proc/sys/kernel/unprivileged_userns_clone"
    ) != "1":
        raise OSError
    controllers = tuple(
        sorted(
            _read_virtual_scalar("/sys/fs/cgroup/cgroup.controllers").split()
        )
    )
    if not _REQUIRED_CONTROLLERS.issubset(frozenset(controllers)):
        raise OSError
    profile = _read_root_regular(_APPARMOR_PROFILE, 64 * 1024)
    if (
        b"profile rootlesskit /usr/bin/rootlesskit" not in profile
        or b"userns," not in profile
    ):
        raise OSError
    return controllers


def _qualify_host_once() -> RootlessDockerPreinstallEvidence:
    """Perform the shared read-only host qualification without staging policy."""

    identity = _root_identity()
    migrated = qualify_successor_host_migration()
    if (
        migrated.phase != "complete"
        or migrated.next_operation != "complete"
        or migrated.application_sha256
        != "9bb162e1712a8ec76874c229ce1af1c8a88f527686d4a43376ca93a8b0d00b88"
        or migrated.executor_reviewed_commit != TARGET_REVIEWED_COMMIT
        or migrated.broker_reviewed_commit != TARGET_REVIEWED_COMMIT
    ):
        raise OSError
    supplementary = _require_executor_identity()
    dependencies = tuple(
        _require_host_dependency(item)
        for item in INSTALLATION_AUTHORITY.host_dependencies
    )
    direct = tuple(item.name for item in INSTALLATION_AUTHORITY.packages)
    supplemental = tuple(
        item.name for item in INSTALLATION_AUTHORITY.supplemental_packages
    )
    checked: set[str] = set()
    for name in (
        *direct,
        *supplemental,
        *INSTALLATION_AUTHORITY.conflicting_packages,
    ):
        if name in checked:
            continue
        _require_package_absent(name)
        checked.add(name)
    _require_rootful_runtime_absent()
    _require_subid_authority()
    controllers = _require_kernel_prerequisites()
    if _root_identity() != identity:
        raise OSError
    return RootlessDockerPreinstallEvidence(
        application_reviewed_commit=TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=migrated.expected_workflow_sha,
        executor_uid=AUTHORITY.executor_uid,
        executor_gid=AUTHORITY.executor_gid,
        supplementary_gids=supplementary,
        subuid_start=AUTHORITY.subuid_start,
        subgid_start=AUTHORITY.subgid_start,
        subordinate_count=AUTHORITY.subordinate_count,
        direct_packages=direct,
        supplemental_packages=supplemental,
        host_dependencies=dependencies,
        cgroup_controllers=controllers,
    )


def _qualify_once() -> RootlessDockerPreinstallEvidence:
    """Require the shared host boundary while no final package bundle exists."""

    _require_final_bundle_absent()
    result = _qualify_host_once()
    _require_final_bundle_absent()
    return result


def qualify_rootless_docker_preinstall() -> RootlessDockerPreinstallEvidence:
    """Require two identical read-only observations before installation."""

    try:
        first = _qualify_once()
        second = _qualify_once()
        if second != first:
            raise OSError
        return first
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerPreinstallQualificationError(_ERROR) from None
