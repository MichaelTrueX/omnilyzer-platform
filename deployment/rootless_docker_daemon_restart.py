"""C33M reviewed one-shot restart of the qualified rootless Docker daemon.

The transition performs exactly one systemd user-unit restart after the complete
C33L restart preflight and public C33F qualification pass. It then proves a new
runtime process set, stable daemon authority, two identical post-restart
preflights, and a final public C33F qualification.

It does not enable the user unit, touch rootful Docker, start broker/executor,
or activate deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import os
import subprocess

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_daemon_qualification as c33f
from . import rootless_docker_restart_preflight as restart_preflight


__all__ = (
    "RootlessDockerDaemonRestartError",
    "RootlessDockerDaemonRestartEvidence",
    "restart_rootless_docker_daemon",
)

_ERROR = "rootless Docker daemon restart is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"
_TIMEOUT = 120.0
_OUTPUT_LIMIT = 1024 * 1024
_PID_NAMES = ("rootlesskit", "dockerd", "containerd", "slirp4netns")
_VOLATILE_DAEMON_FIELDS = frozenset(
    {"user_unit_main_pid", "rootlesskit_pid", "dockerd_pid"}
)


class RootlessDockerDaemonRestartError(Exception):
    """One fixed external failure for the privileged C33M boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerDaemonRestartEvidence:
    operation: str
    before_pids: tuple[tuple[str, int], ...]
    after_pids: tuple[tuple[str, int], ...]
    preflight_checks: tuple[str, ...]
    postflight_checks: tuple[str, ...]
    daemon_signature_equal: bool
    user_unit_state: tuple[str, str, str, str]
    containers: tuple[int, int, int, int]
    images: int

    def __post_init__(self) -> None:
        expected_names = _PID_NAMES
        if (
            self.operation != "restarted"
            or tuple(name for name, _pid in self.before_pids) != expected_names
            or tuple(name for name, _pid in self.after_pids) != expected_names
            or any(type(pid) is not int or pid <= 1 for _name, pid in self.before_pids)
            or any(type(pid) is not int or pid <= 1 for _name, pid in self.after_pids)
            or set(pid for _name, pid in self.before_pids)
            & set(pid for _name, pid in self.after_pids)
            or not self.preflight_checks
            or not self.postflight_checks
            or self.preflight_checks != self.postflight_checks
            or self.daemon_signature_equal is not True
            or self.user_unit_state != ("loaded", "active", "running", "disabled")
            or self.containers != (0, 0, 0, 0)
            or self.images != 0
        ):
            raise ValueError(_ERROR)


def _root_identity() -> tuple[int, int]:
    value = (os.geteuid(), os.getegid())
    if value != (0, 0):
        raise OSError
    return value


def _require_green_preflight():
    evidence = restart_preflight.preflight_rootless_docker_restart()
    if not evidence.passed:
        raise OSError
    return evidence


def _runtime_pids() -> tuple[tuple[str, int], ...]:
    unit_state, _fragment, main_pid = c33f._user_unit_evidence()
    if unit_state != ("loaded", "active", "running", "disabled"):
        raise OSError

    rootlesskit_pid, _rk_argv, dockerd_pid, _dockerd_argv = c33f._process_evidence(
        main_pid
    )
    containerd = c33f._pids("containerd")
    slirp = c33f._pids("slirp4netns")
    if len(containerd) != 1 or len(slirp) != 1:
        raise OSError

    result = (
        ("rootlesskit", rootlesskit_pid),
        ("dockerd", dockerd_pid),
        ("containerd", containerd[0]),
        ("slirp4netns", slirp[0]),
    )
    pids = tuple(pid for _name, pid in result)
    if len(set(pids)) != len(pids):
        raise OSError
    return result


def _stable_daemon_signature(
    evidence: c33f.RootlessDockerDaemonEvidence,
) -> tuple[tuple[str, object], ...]:
    return tuple(
        (field.name, getattr(evidence, field.name))
        for field in fields(c33f.RootlessDockerDaemonEvidence)
        if field.name not in _VOLATILE_DAEMON_FIELDS
    )


def _run_restart() -> None:
    argv = (
        _SYSTEMCTL,
        "--user",
        "--machine=omnilyzer-executor@.host",
        "restart",
        _USER_UNIT,
    )
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/bin:/bin",
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
        or result.returncode != 0
    ):
        raise OSError


def _restart_under_lock() -> RootlessDockerDaemonRestartEvidence:
    preflight = _require_green_preflight()
    before_daemon = c33f.qualify_rootless_docker_daemon()
    before_pids = _runtime_pids()

    _run_restart()

    after_pids = _runtime_pids()
    if set(pid for _name, pid in before_pids) & set(
        pid for _name, pid in after_pids
    ):
        raise OSError

    first_postflight = _require_green_preflight()
    second_postflight = _require_green_preflight()
    if first_postflight != second_postflight:
        raise OSError

    after_daemon = c33f.qualify_rootless_docker_daemon()
    if _stable_daemon_signature(before_daemon) != _stable_daemon_signature(
        after_daemon
    ):
        raise OSError

    preflight_names = tuple(check.name for check in preflight.checks)
    postflight_names = tuple(check.name for check in first_postflight.checks)
    if preflight_names != postflight_names:
        raise OSError

    return RootlessDockerDaemonRestartEvidence(
        operation="restarted",
        before_pids=before_pids,
        after_pids=after_pids,
        preflight_checks=preflight_names,
        postflight_checks=postflight_names,
        daemon_signature_equal=True,
        user_unit_state=after_daemon.user_unit_state,
        containers=after_daemon.containers,
        images=after_daemon.images,
    )


def restart_rootless_docker_daemon() -> RootlessDockerDaemonRestartEvidence:
    """Perform the single reviewed restart after complete live qualification."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        result = _restart_under_lock()
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
        raise RootlessDockerDaemonRestartError(_ERROR) from None
    return result
