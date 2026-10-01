"""deployment/rootless_docker_fresh_manager_transition.py - C33S lifecycle transition.

Purpose:
- recycle the already-qualified UID-991 user manager exactly once;
- prove global persistence starts the rootless Docker user unit in a fresh manager;
- preserve rootless Docker authority, empty inventory, rootful masks, and inactive
  deployment broker/executor surfaces.

Links:
- deployment/rootless_docker_fresh_manager_preflight.py provides the exhaustive
  read-only C33R gate that must pass immediately before mutation.
- deployment/rootless_docker_daemon_qualification.py provides the established
  low-level Docker, process, socket, mask, and systemd evidence helpers.
- deployment/rootless_docker_persistence_enablement.py provides persistence-link
  and global-enable authority.
- deployment/dev_host_provisioning_orchestration.py provides the privileged
  process lock.

The only mutation in this module is the exact command:
    /usr/bin/systemctl restart user@991.service

There is no retry, fallback, daemon-reload, enable/disable action, Docker restart,
broker/executor activation, or deployment activation.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import os
import subprocess

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_daemon_qualification as c33f
from . import rootless_docker_fresh_manager_preflight as c33q
from . import rootless_docker_persistence_enablement as persistence
from .rootless_docker_authority import AUTHORITY
from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY


__all__ = (
    "RootlessDockerFreshManagerPostQualificationError",
    "RootlessDockerFreshManagerTransitionError",
    "RootlessDockerFreshManagerLifecycleEvidence",
    "RootlessDockerFreshManagerTransitionEvidence",
    "qualify_rootless_docker_fresh_manager_post",
    "recycle_rootless_docker_user_manager",
)

_ERROR = "rootless Docker fresh-manager transition is unavailable"
_POST_ERROR = "rootless Docker fresh-manager post-qualification is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_USER_MANAGER = "user@991.service"
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"
_ENABLE_LINK = "/etc/systemd/user/default.target.wants/" + _USER_UNIT
_RESTART_COMMAND = (_SYSTEMCTL, "restart", _USER_MANAGER)
_TIMEOUT = 120.0
_OUTPUT_LIMIT = 1024 * 1024
_CGROUP_ROOT = "/user.slice/user-991.slice/user@991.service"
_PID_NAMES = ("rootlesskit", "dockerd", "containerd", "slirp4netns")
_BEFORE_UNIT_STATE = ("loaded", "active", "running", "disabled")
_AFTER_UNIT_STATE = ("loaded", "active", "running", "enabled")
_USER_MANAGER_STATE = ("loaded", "active", "running", "static")
_USER_RUNTIME_STATE = ("loaded", "active", "exited")
_VOLATILE_FIELDS = frozenset(
    {
        "user_manager_pid",
        "user_unit_state",
        "runtime_pids",
        "cgroup_processes",
    }
)
_OBSERVATION_VOLATILE_FIELDS = frozenset({"cgroup_processes"})


class RootlessDockerFreshManagerTransitionError(Exception):
    """Expose one fixed error for the privileged C33S transition boundary."""


class RootlessDockerFreshManagerPostQualificationError(Exception):
    """Expose one fixed error for the read-only C33S post-transition boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerFreshManagerLifecycleEvidence:
    """Exact lifecycle evidence for either side of the fresh-manager recycle."""

    persistent_state: str
    enable_link: tuple[str, str, int, int, int]
    user_manager_state: tuple[str, str, str, str]
    user_manager_pid: int
    user_runtime_state: tuple[str, str, str]
    linger_state: tuple[str, str, str, str, str, str, str]
    user_unit_state: tuple[str, str, str, str]
    user_unit_fragment: str
    runtime_pids: tuple[tuple[str, int], ...]
    daemon_socket: tuple[str, int, int, int]
    rootlesskit_state: tuple[str, int, int, int]
    docker_info: tuple[
        str,
        str,
        str,
        str,
        str,
        tuple[str, ...],
        tuple[int, int, int, int],
        int,
    ]
    masked_units: tuple[str, ...]
    inactive_deployment_units: tuple[str, ...]
    cgroup_processes: tuple[tuple[int, str], ...]

    def __post_init__(self) -> None:
        """Reject incomplete, non-authoritative, or non-empty lifecycle evidence."""

        expected_link = (_ENABLE_LINK, AUTHORITY.user_unit, 0, 0, 0o777)
        runtime_map = dict(self.runtime_pids)
        required_pids = {self.user_manager_pid, *runtime_map.values()}
        if (
            self.persistent_state != "enabled"
            or self.enable_link != expected_link
            or self.user_manager_state != _USER_MANAGER_STATE
            or type(self.user_manager_pid) is not int
            or self.user_manager_pid <= 1
            or self.user_runtime_state != _USER_RUNTIME_STATE
            or self.linger_state
            != (
                "yes",
                AUTHORITY.runtime_directory,
                str(AUTHORITY.executor_uid),
                AUTHORITY.executor_user,
                "lingering",
                "",
                "",
            )
            or self.user_unit_state not in {_BEFORE_UNIT_STATE, _AFTER_UNIT_STATE}
            or self.user_unit_fragment != AUTHORITY.user_unit
            or tuple(name for name, _pid in self.runtime_pids) != _PID_NAMES
            or len(runtime_map) != len(_PID_NAMES)
            or any(type(pid) is not int or pid <= 1 for pid in runtime_map.values())
            or len(set(runtime_map.values())) != len(runtime_map)
            or len(required_pids) != 5
            or runtime_map["rootlesskit"] == self.user_manager_pid
            or self.daemon_socket
            != (
                AUTHORITY.daemon_socket,
                AUTHORITY.executor_uid,
                AUTHORITY.executor_gid,
                AUTHORITY.daemon_socket_mode,
            )
            or self.rootlesskit_state
            != (
                AUTHORITY.rootlesskit_state,
                AUTHORITY.executor_uid,
                AUTHORITY.executor_gid,
                AUTHORITY.rootlesskit_state_mode,
            )
            or type(self.docker_info) is not tuple
            or len(self.docker_info) != 8
            or type(self.docker_info[5]) is not tuple
            or type(self.docker_info[6]) is not tuple
            or self.docker_info[0] != AUTHORITY.engine_version
            or self.docker_info[1] != "overlay2"
            or self.docker_info[2] != AUTHORITY.data_root
            or self.docker_info[3] != "systemd"
            or self.docker_info[4] != "2"
            or "name=rootless" not in self.docker_info[5]
            or "name=cgroupns" not in self.docker_info[5]
            or self.docker_info[6] != (0, 0, 0, 0)
            or self.docker_info[7] != 0
            or self.masked_units != INSTALLATION_AUTHORITY.rootful_units
            or self.inactive_deployment_units != c33f._DEPLOYMENT_UNITS
            or not self.cgroup_processes
            or not required_pids.issubset(
                {pid for pid, _path in self.cgroup_processes}
            )
            or any(
                path != _CGROUP_ROOT and not path.startswith(_CGROUP_ROOT + "/")
                for _pid, path in self.cgroup_processes
            )
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class RootlessDockerFreshManagerTransitionEvidence:
    """Proof that one user-manager recycle produced the expected fresh lifecycle."""

    operation: str
    restart_command: tuple[str, str, str]
    preflight_checks: tuple[str, ...]
    before: RootlessDockerFreshManagerLifecycleEvidence
    after: RootlessDockerFreshManagerLifecycleEvidence
    daemon_signature_equal: bool

    def __post_init__(self) -> None:
        """Require the precise before-to-after transition and complete PID turnover."""

        before_runtime = {pid for _name, pid in self.before.runtime_pids}
        after_runtime = {pid for _name, pid in self.after.runtime_pids}
        if (
            self.operation != "recycled"
            or self.restart_command != _RESTART_COMMAND
            or not self.preflight_checks
            or self.before.user_unit_state != _BEFORE_UNIT_STATE
            or self.after.user_unit_state != _AFTER_UNIT_STATE
            or self.before.user_manager_pid == self.after.user_manager_pid
            or before_runtime & after_runtime
            or self.daemon_signature_equal is not True
            or _stable_signature(self.before) != _stable_signature(self.after)
        ):
            raise ValueError(_ERROR)


def _root_identity() -> tuple[int, int]:
    """Require effective root for every C33S privileged boundary."""

    value = (os.geteuid(), os.getegid())
    if value != (0, 0):
        raise OSError
    return value


def _user_unit_evidence(
    expected_state: tuple[str, str, str, str],
) -> tuple[tuple[str, str, str, str], str, int]:
    """Read the rootless Docker user unit with lifecycle-specific state semantics."""

    if expected_state not in {_BEFORE_UNIT_STATE, _AFTER_UNIT_STATE}:
        raise OSError
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
    if state != expected_state or fragment != AUTHORITY.user_unit or main_pid <= 1:
        raise OSError
    if persistence._global_enable_evidence() != "enabled":
        raise OSError
    persistence._enable_link_evidence()
    return state, fragment, main_pid


def _runtime_pids(main_pid: int) -> tuple[tuple[str, int], ...]:
    """Bind RootlessKit, dockerd, containerd, and slirp4netns to one exact PID set."""

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
    if len({pid for _name, pid in result}) != len(result):
        raise OSError
    return result


def _deployment_inactive_evidence() -> tuple[str, ...]:
    """Prove broker, executor, and executor socket remain inactive."""

    for unit in c33f._DEPLOYMENT_UNITS:
        if c33f.userq._read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError
    return c33f._DEPLOYMENT_UNITS


def _uid_process_cgroup_boundary(
    user_manager_pid: int,
    runtime_pids: tuple[tuple[str, int], ...],
) -> tuple[tuple[int, str], ...]:
    """Require every UID-991 process to remain below the user@991.service cgroup."""

    required = {user_manager_pid, *(pid for _name, pid in runtime_pids)}
    observed: list[tuple[int, str]] = []
    try:
        entries = tuple(os.scandir("/proc"))
    except OSError:
        raise OSError from None

    for entry in entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        try:
            pid = int(entry.name)
        except ValueError:
            continue
        if pid <= 1:
            continue
        try:
            uid = c33f._proc_dir_uid(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            if not os.path.exists(f"/proc/{pid}"):
                continue
            raise
        if uid != AUTHORITY.executor_uid:
            continue
        try:
            path = c33q._read_cgroup(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            if not os.path.exists(f"/proc/{pid}"):
                continue
            raise
        if path != _CGROUP_ROOT and not path.startswith(_CGROUP_ROOT + "/"):
            raise OSError
        observed.append((pid, path))

    result = tuple(sorted(observed))
    if not result or not required.issubset({pid for pid, _path in result}):
        raise OSError
    return result


def _lifecycle_once(
    expected_unit_state: tuple[str, str, str, str],
) -> RootlessDockerFreshManagerLifecycleEvidence:
    """Collect one complete read-only lifecycle observation."""

    identity = _root_identity()
    persistent_state = persistence._global_enable_evidence()
    enable_link = persistence._enable_link_evidence()
    c33q._boot_activation_contract()
    user_manager_state, user_manager_pid, user_runtime_state = (
        c33q._user_manager_state()
    )
    linger_state = c33q._linger_state()
    user_unit_state, fragment, main_pid = _user_unit_evidence(expected_unit_state)
    runtime_pids = _runtime_pids(main_pid)
    daemon_socket = c33f._socket_evidence()
    rootlesskit_state = c33f._rootlesskit_state_evidence()
    c33f._runtime_artifacts_exact()
    docker_info = c33f._docker_info_evidence()
    c33f._require_rootful_masks()
    inactive_units = _deployment_inactive_evidence()
    cgroup_processes = _uid_process_cgroup_boundary(
        user_manager_pid,
        runtime_pids,
    )
    if _root_identity() != identity:
        raise OSError
    return RootlessDockerFreshManagerLifecycleEvidence(
        persistent_state=persistent_state,
        enable_link=enable_link,
        user_manager_state=user_manager_state,
        user_manager_pid=user_manager_pid,
        user_runtime_state=user_runtime_state,
        linger_state=linger_state,
        user_unit_state=user_unit_state,
        user_unit_fragment=fragment,
        runtime_pids=runtime_pids,
        daemon_socket=daemon_socket,
        rootlesskit_state=rootlesskit_state,
        docker_info=docker_info,
        masked_units=INSTALLATION_AUTHORITY.rootful_units,
        inactive_deployment_units=inactive_units,
        cgroup_processes=cgroup_processes,
    )


def _observation_signature(
    evidence: RootlessDockerFreshManagerLifecycleEvidence,
) -> tuple[tuple[str, object], ...]:
    """Compare lifecycle observations while allowing unrelated contained PID churn."""

    return tuple(
        (field.name, getattr(evidence, field.name))
        for field in fields(RootlessDockerFreshManagerLifecycleEvidence)
        if field.name not in _OBSERVATION_VOLATILE_FIELDS
    )


def _stable_lifecycle(
    expected_unit_state: tuple[str, str, str, str],
) -> RootlessDockerFreshManagerLifecycleEvidence:
    """Require two stable lifecycle observations before accepting state."""

    first = _lifecycle_once(expected_unit_state)
    second = _lifecycle_once(expected_unit_state)
    if _observation_signature(second) != _observation_signature(first):
        raise OSError
    return second


def qualify_rootless_docker_fresh_manager_post() -> (
    RootlessDockerFreshManagerLifecycleEvidence
):
    """Qualify the post-recycle lifecycle where the fresh manager sees enabled."""

    try:
        return _stable_lifecycle(_AFTER_UNIT_STATE)
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerFreshManagerPostQualificationError(
            _POST_ERROR
        ) from None


def _stable_signature(
    evidence: RootlessDockerFreshManagerLifecycleEvidence,
) -> tuple[tuple[str, object], ...]:
    """Return the immutable lifecycle signature, excluding intentional PID/state churn."""

    return tuple(
        (field.name, getattr(evidence, field.name))
        for field in fields(RootlessDockerFreshManagerLifecycleEvidence)
        if field.name not in _VOLATILE_FIELDS
    )


def _require_green_preflight() -> c33q.RootlessDockerFreshManagerPreflightEvidence:
    """Run the complete C33R gate and reject any component failure."""

    evidence = c33q.preflight_rootless_docker_fresh_manager()
    if not evidence.passed:
        raise OSError
    return evidence


def _require_preflight_snapshot_match(
    snapshot: c33q.RootlessDockerFreshManagerSnapshot,
    lifecycle: RootlessDockerFreshManagerLifecycleEvidence,
) -> None:
    """Bind the exhaustive C33R snapshot to the immediate pre-mutation lifecycle."""

    expected_runtime = (
        ("rootlesskit", snapshot.rootlesskit_pid),
        ("dockerd", snapshot.dockerd_pid),
        ("containerd", snapshot.containerd_pid),
        ("slirp4netns", snapshot.slirp4netns_pid),
    )
    if (
        snapshot.persistent_state != lifecycle.persistent_state
        or snapshot.live_user_unit_state != lifecycle.user_unit_state
        or snapshot.user_manager_state != lifecycle.user_manager_state
        or snapshot.user_manager_pid != lifecycle.user_manager_pid
        or snapshot.user_runtime_state != lifecycle.user_runtime_state
        or snapshot.linger_state != lifecycle.linger_state
        or lifecycle.runtime_pids != expected_runtime
        or snapshot.containers != lifecycle.docker_info[6]
        or snapshot.images != lifecycle.docker_info[7]
    ):
        raise OSError


def _run_user_manager_restart() -> None:
    """Execute the single authorized C33S mutation with closed subprocess semantics."""

    result = subprocess.run(
        _RESTART_COMMAND,
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


def _transition_under_lock() -> RootlessDockerFreshManagerTransitionEvidence:
    """Perform one gated recycle and then require the new lifecycle to qualify."""

    preflight = _require_green_preflight()
    snapshot = c33q.snapshot_rootless_docker_fresh_manager_candidate()
    before = _stable_lifecycle(_BEFORE_UNIT_STATE)
    _require_preflight_snapshot_match(snapshot, before)

    _run_user_manager_restart()

    after = qualify_rootless_docker_fresh_manager_post()
    before_runtime = {pid for _name, pid in before.runtime_pids}
    after_runtime = {pid for _name, pid in after.runtime_pids}
    if (
        before.user_manager_pid == after.user_manager_pid
        or before_runtime & after_runtime
        or _stable_signature(before) != _stable_signature(after)
    ):
        raise OSError

    return RootlessDockerFreshManagerTransitionEvidence(
        operation="recycled",
        restart_command=_RESTART_COMMAND,
        preflight_checks=tuple(check.name for check in preflight.checks),
        before=before,
        after=after,
        daemon_signature_equal=True,
    )


def recycle_rootless_docker_user_manager() -> (
    RootlessDockerFreshManagerTransitionEvidence
):
    """Run the root-locked C33S transition without retrying any failed mutation."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        result = _transition_under_lock()
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
        raise RootlessDockerFreshManagerTransitionError(_ERROR) from None
    return result
