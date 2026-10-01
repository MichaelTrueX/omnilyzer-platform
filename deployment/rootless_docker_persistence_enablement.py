"""C33N persistence enablement for the qualified rootless Docker user unit.

C33N changes only the system-wide user-unit install link. The unit remains
restricted by its reviewed ConditionUser=omnilyzer-executor guard. The running
daemon must remain byte/state equivalent to the pre-enable C33F observation and
must not restart.

No --now operation is allowed. No automatic disable rollback is attempted after
a failed postcondition.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
import subprocess

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_daemon_qualification as c33f
from .rootless_docker_authority import AUTHORITY
from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY


__all__ = (
    "RootlessDockerPersistenceEnablementError",
    "RootlessDockerPersistenceEnablementEvidence",
    "enable_rootless_docker_persistence",
)

_ERROR = "rootless Docker persistence enablement is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"
_ENABLE_LINK = "/etc/systemd/user/default.target.wants/" + _USER_UNIT
_TIMEOUT = 30.0
_OUTPUT_LIMIT = 256 * 1024


class RootlessDockerPersistenceEnablementError(Exception):
    """One fixed external failure for the privileged C33N boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerPersistenceEnablementEvidence:
    operation: str
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
            or self.enable_link
            != (_ENABLE_LINK, AUTHORITY.user_unit, 0, 0, 0o777)
            or self.before_unit_state
            != ("loaded", "active", "running", "disabled")
            or self.after_unit_state
            != ("loaded", "active", "running", "enabled")
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


def _enabled_user_unit_evidence() -> tuple[
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
        state != ("loaded", "active", "running", "enabled")
        or fragment != AUTHORITY.user_unit
        or main_pid <= 1
    ):
        raise OSError
    _enable_link_evidence()
    return state, fragment, main_pid


def _post_enable_matches(
    before: c33f.RootlessDockerDaemonEvidence,
) -> tuple[
    tuple[str, str, str, str],
    tuple[int, int],
    tuple[str, str, int, int, int],
]:
    identity = _root_identity()
    package_host = c33f._package_host()
    subuid, subgid = c33f.userq.staticq._require_subids()
    directories, assets = c33f._require_post_daemon_static_assets()
    c33f.userq.staticq._require_user_manager_template_dropins()

    executor_dropins = tuple(
        c33f.userq.staticq._read_systemctl(
            "omnilyzer-deployment-executor.service", "DropInPaths"
        ).split()
    )
    user_dropins = tuple(
        c33f.userq.staticq._read_systemctl(
            "user@991.service", "DropInPaths"
        ).split()
    )
    if (
        executor_dropins != before.executor_dropins
        or user_dropins != before.user_manager_dropins
    ):
        raise OSError
    for unit in c33f._DEPLOYMENT_UNITS:
        if c33f.userq._read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError

    state, fragment, main_pid = _enabled_user_unit_evidence()
    rootlesskit_pid, rootlesskit_argv, dockerd_pid, dockerd_argv = (
        c33f._process_evidence(main_pid)
    )
    socket_evidence = c33f._socket_evidence()
    rootlesskit_state = c33f._rootlesskit_state_evidence()
    c33f._runtime_artifacts_exact()
    info = c33f._docker_info_evidence()
    linger_mode, runtime, control_group, delegates = c33f._user_manager_evidence()

    if (
        _root_identity() != identity
        or fragment != before.user_unit_fragment
        or main_pid != before.user_unit_main_pid
        or rootlesskit_pid != before.rootlesskit_pid
        or dockerd_pid != before.dockerd_pid
        or rootlesskit_argv != before.rootlesskit_argv
        or dockerd_argv != before.dockerd_argv
        or socket_evidence
        != (
            before.daemon_socket,
            before.socket_uid,
            before.socket_gid,
            before.socket_mode,
        )
        or rootlesskit_state != before.rootlesskit_state
        or info
        != (
            before.server_version,
            before.storage_driver,
            before.docker_root_dir,
            before.cgroup_driver,
            before.cgroup_version,
            before.security_options,
            before.containers,
            before.images,
        )
        or (linger_mode, runtime, control_group, delegates)
        != (
            before.linger_mode,
            before.runtime_directory,
            before.user_manager_control_group,
            before.delegate_controllers,
        )
        or subuid != before.subuid_records
        or subgid != before.subgid_records
        or directories != before.directories
        or assets != before.assets
        or package_host[0] != before.expected_workflow_sha
        or package_host[2] != before.host_dependencies
        or package_host[3] != before.packages
        or package_host[4] != before.cgroup_controllers
        or package_host[5] != before.critical_executables
        or package_host[6] != before.bundle
        or before.masked_units != INSTALLATION_AUTHORITY.rootful_units
    ):
        raise OSError

    return (
        state,
        (rootlesskit_pid, dockerd_pid),
        _enable_link_evidence(),
    )


def _enable_under_lock() -> RootlessDockerPersistenceEnablementEvidence:
    before = c33f.qualify_rootless_docker_daemon()
    before_pids = (before.rootlesskit_pid, before.dockerd_pid)

    _run_enable()

    after_state, after_pids, link = _post_enable_matches(before)
    return RootlessDockerPersistenceEnablementEvidence(
        operation="enabled",
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
