"""C33N persistence enablement and immediate post-enable qualification.

Persistent install state and the already-running user manager's cached unit-file
state are intentionally distinct. The global enable link is the persistence
authority. The current user manager remains otherwise unchanged and continues
to report UnitFileState=disabled until that manager is replaced.

No --now operation, daemon reload, restart, or automatic disable rollback is
authorized here.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
import subprocess

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_daemon_qualification as c33f
from .rootless_docker_authority import AUTHORITY


__all__ = (
    "RootlessDockerPersistenceEnablementError",
    "RootlessDockerPersistenceEnablementEvidence",
    "RootlessDockerPersistenceQualificationError",
    "RootlessDockerPersistenceStateEvidence",
    "enable_rootless_docker_persistence",
    "qualify_rootless_docker_persistence",
)

_ERROR = "rootless Docker persistence enablement is unavailable"
_QUALIFICATION_ERROR = "rootless Docker persistence qualification is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"
_ENABLE_LINK = "/etc/systemd/user/default.target.wants/" + _USER_UNIT
_LIVE_POST_ENABLE_STATE = ("loaded", "active", "running", "disabled")
_PERSISTENT_STATE = "enabled"
_TIMEOUT = 30.0
_OUTPUT_LIMIT = 256 * 1024


class RootlessDockerPersistenceEnablementError(Exception):
    """One fixed external failure for the privileged C33N mutation boundary."""


class RootlessDockerPersistenceQualificationError(Exception):
    """One fixed external failure for post-enable persistence qualification."""


@dataclass(frozen=True, slots=True)
class RootlessDockerPersistenceStateEvidence:
    persistent_state: str
    enable_link: tuple[str, str, int, int, int]
    daemon: c33f.RootlessDockerDaemonEvidence

    def __post_init__(self) -> None:
        if (
            self.persistent_state != _PERSISTENT_STATE
            or self.enable_link
            != (_ENABLE_LINK, AUTHORITY.user_unit, 0, 0, 0o777)
            or self.daemon.user_unit_state != _LIVE_POST_ENABLE_STATE
            or self.daemon.containers != (0, 0, 0, 0)
            or self.daemon.images != 0
        ):
            raise ValueError(_QUALIFICATION_ERROR)


@dataclass(frozen=True, slots=True)
class RootlessDockerPersistenceEnablementEvidence:
    operation: str
    persistent_state: str
    enable_link: tuple[str, str, int, int, int]
    before_unit_state: tuple[str, str, str, str]
    after_unit_state: tuple[str, str, str, str]
    before_pids: tuple[int, int]
    after_pids: tuple[int, int]
    daemon_signature_equal: bool
    containers: tuple[int, int, int, int]
    images: int

    def __post_init__(self) -> None:
        if (
            self.operation != "enabled"
            or self.persistent_state != _PERSISTENT_STATE
            or self.enable_link
            != (_ENABLE_LINK, AUTHORITY.user_unit, 0, 0, 0o777)
            or self.before_unit_state != _LIVE_POST_ENABLE_STATE
            or self.after_unit_state != _LIVE_POST_ENABLE_STATE
            or self.before_pids != self.after_pids
            or len(set(self.before_pids)) != 2
            or any(type(pid) is not int or pid <= 1 for pid in self.before_pids)
            or self.daemon_signature_equal is not True
            or self.containers != (0, 0, 0, 0)
            or self.images != 0
        ):
            raise ValueError(_ERROR)


def _root_identity() -> tuple[int, int]:
    value = (os.geteuid(), os.getegid())
    if value != (0, 0):
        raise OSError
    return value


def _run_enable() -> None:
    result = subprocess.run(
        (_SYSTEMCTL, "--global", "enable", _USER_UNIT),
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
        or result.returncode != 0
        or len(result.stdout) > _OUTPUT_LIMIT
        or len(result.stderr) > _OUTPUT_LIMIT
    ):
        raise OSError


def _global_enable_evidence() -> str:
    result = subprocess.run(
        (_SYSTEMCTL, "--global", "is-enabled", _USER_UNIT),
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
        result.returncode != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or result.stdout != b"enabled\n"
        or len(result.stderr) > _OUTPUT_LIMIT
    ):
        raise OSError
    return _PERSISTENT_STATE


def _enable_link_evidence() -> tuple[str, str, int, int, int]:
    value = os.lstat(_ENABLE_LINK)
    target = os.readlink(_ENABLE_LINK)
    evidence = (
        _ENABLE_LINK,
        target,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
    )
    if (
        not stat.S_ISLNK(value.st_mode)
        or value.st_nlink != 1
        or evidence != (_ENABLE_LINK, AUTHORITY.user_unit, 0, 0, 0o777)
    ):
        raise OSError
    return evidence


def _post_enable_user_unit_evidence() -> tuple[
    tuple[str, str, str, str], str, int
]:
    state = (
        c33f._read_user_systemctl("LoadState"),
        c33f._read_user_systemctl("ActiveState"),
        c33f._read_user_systemctl("SubState"),
        c33f._read_user_systemctl("UnitFileState"),
    )
    fragment = c33f._canonical_user_unit_fragment(
        c33f._read_user_systemctl("FragmentPath")
    )
    try:
        main_pid = int(c33f._read_user_systemctl("MainPID"))
    except ValueError:
        raise OSError from None
    if (
        state != _LIVE_POST_ENABLE_STATE
        or fragment != AUTHORITY.user_unit
        or main_pid <= 1
    ):
        raise OSError

    _enable_link_evidence()
    _global_enable_evidence()
    return state, fragment, main_pid


def _qualify_persistence_once() -> RootlessDockerPersistenceStateEvidence:
    persistent_state = _global_enable_evidence()
    link = _enable_link_evidence()
    daemon = c33f._qualify_once_with_user_unit(
        _post_enable_user_unit_evidence
    )
    return RootlessDockerPersistenceStateEvidence(
        persistent_state=persistent_state,
        enable_link=link,
        daemon=daemon,
    )


def qualify_rootless_docker_persistence() -> (
    RootlessDockerPersistenceStateEvidence
):
    """Qualify enabled-on-disk persistence with the current manager unchanged."""

    try:
        first = _qualify_persistence_once()
        second = _qualify_persistence_once()
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerPersistenceQualificationError(
            _QUALIFICATION_ERROR
        ) from None
    if second != first:
        raise RootlessDockerPersistenceQualificationError(
            _QUALIFICATION_ERROR
        ) from None
    return first


def _post_enable_matches(
    before: c33f.RootlessDockerDaemonEvidence,
) -> tuple[
    tuple[str, str, str, str],
    tuple[int, int],
    tuple[str, str, int, int, int],
    str,
]:
    after = qualify_rootless_docker_persistence()
    if after.daemon != before:
        raise OSError
    return (
        after.daemon.user_unit_state,
        (after.daemon.rootlesskit_pid, after.daemon.dockerd_pid),
        after.enable_link,
        after.persistent_state,
    )


def _enable_under_lock() -> RootlessDockerPersistenceEnablementEvidence:
    before = c33f.qualify_rootless_docker_daemon()
    before_pids = (before.rootlesskit_pid, before.dockerd_pid)

    _run_enable()

    after_state, after_pids, link, persistent_state = _post_enable_matches(
        before
    )
    return RootlessDockerPersistenceEnablementEvidence(
        operation="enabled",
        persistent_state=persistent_state,
        enable_link=link,
        before_unit_state=before.user_unit_state,
        after_unit_state=after_state,
        before_pids=before_pids,
        after_pids=after_pids,
        daemon_signature_equal=True,
        containers=before.containers,
        images=before.images,
    )


def enable_rootless_docker_persistence() -> (
    RootlessDockerPersistenceEnablementEvidence
):
    """Enable boot persistence without starting or restarting the daemon."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        result = _enable_under_lock()
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
        raise RootlessDockerPersistenceEnablementError(_ERROR) from None
    return result
