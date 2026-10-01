"""Read-only, non-fail-fast preflight before rootless Docker restart.

The restart preflight exists to prove the currently installed reviewed launcher
and its live-host preconditions before any intentional stop/restart/reboot.
It does not invoke the launcher main(), does not stop/start/enable a unit, and
does not mutate Docker or filesystem state.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import ModuleType
from typing import Callable

from . import rootless_docker_daemon_preflight as daemon_preflight
from . import rootless_docker_daemon_qualification as daemonq
from .rootless_docker_authority import AUTHORITY


__all__ = (
    "RootlessDockerRestartPreflightCheck",
    "RootlessDockerRestartPreflightEvidence",
    "preflight_rootless_docker_restart_candidate",
    "preflight_rootless_docker_restart",
)

_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_TIMEOUT = 5.0
_OUTPUT_LIMIT = 1024 * 1024
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"
_LAUNCHER_SOURCE = (
    Path(__file__).resolve().parent
    / "systemd"
    / "rootless"
    / "rootless-docker-launcher.py"
)
_LAUNCH_ENVIRONMENT = {
    "HOME": AUTHORITY.home,
    "XDG_RUNTIME_DIR": AUTHORITY.runtime_directory,
    "PATH": "/usr/bin:/usr/sbin:/bin",
    "LANG": "C.UTF-8",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/991/bus",
    "NOTIFY_SOCKET": "/run/user/991/systemd/notify",
    **dict(AUTHORITY.rootless_environment),
}
_RUNTIME_ENVIRONMENT = dict(_LAUNCH_ENVIRONMENT)
if AUTHORITY.detach_netns:
    _RUNTIME_ENVIRONMENT["DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS"] = (
        "--detach-netns "
        + _LAUNCH_ENVIRONMENT["DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS"]
    )
_RUNTIME_ENVIRONMENT["_DOCKERD_ROOTLESS_CHILD"] = "1"
_FORBIDDEN_ENVIRONMENT = frozenset(
    {
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    }
)


class RootlessDockerRestartPreflightError(Exception):
    """Reserved for callers that choose to require a green matrix."""


@dataclass(frozen=True, slots=True)
class RootlessDockerRestartPreflightCheck:
    name: str
    passed: bool
    error_type: str | None

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or type(self.passed) is not bool
            or (self.passed and self.error_type is not None)
            or (
                not self.passed
                and (type(self.error_type) is not str or not self.error_type)
            )
        ):
            raise ValueError("invalid rootless Docker restart preflight check")


@dataclass(frozen=True, slots=True)
class RootlessDockerRestartPreflightEvidence:
    checks: tuple[RootlessDockerRestartPreflightCheck, ...]

    def __post_init__(self) -> None:
        if (
            type(self.checks) is not tuple
            or not self.checks
            or any(
                type(item) is not RootlessDockerRestartPreflightCheck
                for item in self.checks
            )
            or len({item.name for item in self.checks}) != len(self.checks)
        ):
            raise ValueError("invalid rootless Docker restart preflight evidence")

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.checks)

    @property
    def failures(self) -> tuple[RootlessDockerRestartPreflightCheck, ...]:
        return tuple(item for item in self.checks if not item.passed)


def _evaluate(
    name: str,
    function: Callable[[], object],
) -> RootlessDockerRestartPreflightCheck:
    try:
        function()
        return RootlessDockerRestartPreflightCheck(name, True, None)
    except _CONTROL:
        raise
    except Exception as error:
        return RootlessDockerRestartPreflightCheck(
            name,
            False,
            type(error).__name__,
        )


def _launcher_digest() -> str:
    digest = hashlib.sha256(_LAUNCHER_SOURCE.read_bytes()).hexdigest()
    expected = next(
        item[2]
        for item in AUTHORITY.installed_assets
        if item[1] == AUTHORITY.launcher
    )
    if digest != expected:
        raise OSError
    return digest


def _launcher_module() -> ModuleType:
    _launcher_digest()
    spec = importlib.util.spec_from_file_location(
        "_task014_restart_preflight_launcher",
        _LAUNCHER_SOURCE,
    )
    if spec is None or spec.loader is None:
        raise OSError
    module = importlib.util.module_from_spec(spec)
    before = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = before
    return module


def _installed_launcher() -> None:
    expected = next(
        item
        for item in AUTHORITY.installed_assets
        if item[1] == AUTHORITY.launcher
    )
    _source, destination, digest, uid, gid, mode = expected
    daemonq.userq.staticq._require_file(
        destination,
        digest,
        uid,
        gid,
        mode,
    )


def _launcher_static_live() -> None:
    launcher = _launcher_module()
    launcher._directory(
        launcher.RUNTIME,
        launcher.UID,
        launcher.GID,
        0o700,
    )
    launcher._directory(
        launcher.HOME,
        launcher.UID,
        launcher.GID,
        0o700,
    )
    launcher._data_root()
    launcher._directory(
        "/etc/omnilyzer/deployment/rootless-docker",
        0,
        0,
        0o755,
    )
    launcher._file(launcher.CONFIG, 0, 0, 0o644)
    with open(launcher.CONFIG, "rb") as source:
        if source.read() != launcher.DAEMON_CONFIG_BYTES:
            raise OSError
    launcher._file(launcher.VENDOR_SCRIPT, 0, 0, 0o755)
    with open(launcher.VENDOR_SCRIPT, "rb") as source:
        if (
            hashlib.sha256(source.read()).hexdigest()
            != launcher.VENDOR_SCRIPT_SHA256
        ):
            raise OSError
    for path in (
        "/usr/sbin/docker-rootlesskit",
        "/usr/bin/docker-rootlesskit",
        "/bin/docker-rootlesskit",
        "/usr/sbin/rootlesskit",
    ):
        if os.path.lexists(path):
            raise OSError
    launcher._file("/usr/bin/rootlesskit", 0, 0, 0o755)
    launcher._file("/usr/bin/dockerd", 0, 0, 0o755)
    launcher._file("/usr/bin/slirp4netns", 0, 0, 0o755)
    launcher._rootlesskit_state()
    socket_state = os.lstat(AUTHORITY.daemon_socket)
    launcher._socket_identity(socket_state)
    if os.path.lexists(launcher.CONTAINERD_ROOTLESS_STATE):
        raise OSError


def _read_proc_environment(pid: int) -> dict[str, str]:
    data = daemonq._read_proc_file(f"/proc/{pid}/environ", 256 * 1024)
    if not data or not data.endswith(b"\0"):
        raise OSError
    try:
        items = tuple(item.decode("utf-8") for item in data[:-1].split(b"\0"))
    except UnicodeDecodeError:
        raise OSError from None
    result: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise OSError
        name, value = item.split("=", 1)
        if not name or name in result:
            raise OSError
        result[name] = value
    return result


def _runtime_principal_and_environment() -> None:
    state, _fragment, main_pid = daemonq._user_unit_evidence()
    if state != ("loaded", "active", "running", "disabled"):
        raise OSError
    rootlesskit_pid, _argv, _dockerd_pid, _dockerd_argv = (
        daemonq._process_evidence(main_pid)
    )
    status = daemonq._read_proc_file(
        f"/proc/{rootlesskit_pid}/status",
        256 * 1024,
    )
    try:
        text = status.decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None

    gid_values = None
    groups = None
    for line in text.splitlines():
        if line.startswith("Gid:"):
            parts = line.split()
            if len(parts) != 5:
                raise OSError
            gid_values = tuple(int(item) for item in parts[1:])
        elif line.startswith("Groups:"):
            groups = tuple(sorted(int(item) for item in line.split()[1:]))

    if (
        gid_values is None
        or len(set(gid_values)) != 1
        or gid_values[0] != AUTHORITY.executor_gid
        or groups not in {(992,), (991, 992)}
    ):
        raise OSError

    environment = _read_proc_environment(rootlesskit_pid)
    for name, expected in _RUNTIME_ENVIRONMENT.items():
        if environment.get(name) != expected:
            raise OSError
    if any(name in environment for name in _FORBIDDEN_ENVIRONMENT):
        raise OSError


def _user_systemctl_value(property_name: str) -> str:
    if property_name not in {"Restart", "Type", "NotifyAccess", "UnitFileState"}:
        raise OSError
    result = subprocess.run(
        (
            _SYSTEMCTL,
            "--user",
            "--machine=omnilyzer-executor@.host",
            "show",
            "--property=" + property_name,
            "--value",
            _USER_UNIT,
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
        result.returncode != 0
        or type(result.stdout) is not bytes
        or len(result.stdout) > _OUTPUT_LIMIT
        or not result.stdout.endswith(b"\n")
        or b"\r" in result.stdout
        or b"\n" in result.stdout[:-1]
    ):
        raise OSError
    return result.stdout[:-1].decode("ascii")


def _restart_unit_policy() -> None:
    if (
        _user_systemctl_value("Restart") != "always"
        or _user_systemctl_value("Type") != "notify"
        or _user_systemctl_value("NotifyAccess") != "all"
        or _user_systemctl_value("UnitFileState") != "disabled"
    ):
        raise OSError


def _daemon_matrix() -> None:
    evidence = daemon_preflight.preflight_rootless_docker_daemon()
    if not evidence.passed:
        raise OSError


def _candidate_checks() -> tuple[tuple[str, Callable[[], object]], ...]:
    return (
        ("launcher_source_digest", _launcher_digest),
        ("launcher_static_live", _launcher_static_live),
        ("runtime_principal_and_environment", _runtime_principal_and_environment),
        ("restart_unit_policy", _restart_unit_policy),
    )


def _component_checks() -> tuple[tuple[str, Callable[[], object]], ...]:
    return (
        ("daemon_preflight_all_pass", _daemon_matrix),
        ("installed_launcher_exact", _installed_launcher),
        *_candidate_checks(),
    )


def preflight_rootless_docker_restart_candidate() -> RootlessDockerRestartPreflightEvidence:
    """Prove the proposed launcher against live state before file replacement."""

    return RootlessDockerRestartPreflightEvidence(
        tuple(_evaluate(name, function) for name, function in _candidate_checks())
    )


def preflight_rootless_docker_restart() -> RootlessDockerRestartPreflightEvidence:
    """Run all post-replacement restart prerequisites without mutation."""

    return RootlessDockerRestartPreflightEvidence(
        tuple(_evaluate(name, function) for name, function in _component_checks())
    )
