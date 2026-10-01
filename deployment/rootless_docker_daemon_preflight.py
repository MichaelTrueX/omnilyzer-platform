"""Read-only, non-fail-fast preflight for the running rootless Docker daemon.

This module exists to prevent live-host assertion drift from being discovered one
generic qualifier failure at a time. It exercises C33F's component assertions
independently, records every failure, and only reports success when the full
matrix and composite qualifier all pass.

It performs no mutation and does not import the C33E mutator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import rootless_docker_daemon_qualification as daemonq
from .rootless_docker_authority import AUTHORITY
from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY


__all__ = (
    "RootlessDockerDaemonPreflightCheck",
    "RootlessDockerDaemonPreflightEvidence",
    "preflight_rootless_docker_daemon",
)

_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


@dataclass(frozen=True, slots=True)
class RootlessDockerDaemonPreflightCheck:
    """One named read-only assertion outcome."""

    name: str
    passed: bool
    error_type: str | None

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or type(self.passed) is not bool
            or (
                self.passed
                and self.error_type is not None
            )
            or (
                not self.passed
                and (
                    type(self.error_type) is not str
                    or not self.error_type
                )
            )
        ):
            raise ValueError("invalid rootless Docker daemon preflight check")


@dataclass(frozen=True, slots=True)
class RootlessDockerDaemonPreflightEvidence:
    """Complete non-fail-fast assertion matrix."""

    checks: tuple[RootlessDockerDaemonPreflightCheck, ...]

    def __post_init__(self) -> None:
        if (
            type(self.checks) is not tuple
            or not self.checks
            or any(
                type(item) is not RootlessDockerDaemonPreflightCheck
                for item in self.checks
            )
            or len({item.name for item in self.checks}) != len(self.checks)
        ):
            raise ValueError("invalid rootless Docker daemon preflight evidence")

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.checks)

    @property
    def failures(self) -> tuple[RootlessDockerDaemonPreflightCheck, ...]:
        return tuple(item for item in self.checks if not item.passed)


def _evaluate(
    name: str,
    function: Callable[[], object],
) -> RootlessDockerDaemonPreflightCheck:
    try:
        function()
        return RootlessDockerDaemonPreflightCheck(name, True, None)
    except _CONTROL:
        raise
    except Exception as error:
        return RootlessDockerDaemonPreflightCheck(
            name,
            False,
            type(error).__name__,
        )


def _migration() -> None:
    staticq = daemonq.userq.staticq
    migrated = staticq.qualify_successor_host_migration()
    if (
        migrated.phase != "complete"
        or migrated.next_operation != "complete"
        or migrated.application_sha256 != staticq._EXPECTED_APPLICATION_SHA256
        or migrated.executor_reviewed_commit != staticq.TARGET_REVIEWED_COMMIT
        or migrated.broker_reviewed_commit != staticq.TARGET_REVIEWED_COMMIT
    ):
        raise OSError


def _executor_dropins() -> None:
    value = tuple(
        daemonq.userq.staticq._read_systemctl(
            "omnilyzer-deployment-executor.service",
            "DropInPaths",
        ).split()
    )
    if value != (AUTHORITY.executor_socket_dropin,):
        raise OSError


def _user_dropins() -> None:
    staticq = daemonq.userq.staticq
    value = tuple(
        staticq._read_systemctl("user@991.service", "DropInPaths").split()
    )
    if value != staticq._expected_user_manager_dropins():
        raise OSError


def _deployment_units() -> None:
    for unit in daemonq._DEPLOYMENT_UNITS:
        if daemonq.userq._read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError


def _process_evidence() -> None:
    _state, _fragment, main_pid = daemonq._user_unit_evidence()
    daemonq._process_evidence(main_pid)


def _component_checks() -> tuple[tuple[str, Callable[[], object]], ...]:
    staticq = daemonq.userq.staticq
    preinstall = staticq.preinstall
    postinstall = staticq.postinstall

    checks: list[tuple[str, Callable[[], object]]] = [
        ("root_identity_initial", daemonq._root_identity),
        ("successor_migration", _migration),
        ("executor_identity", preinstall._require_executor_identity),
    ]

    for requirement in INSTALLATION_AUTHORITY.host_dependencies:
        checks.append(
            (
                "host_dependency:" + requirement.package,
                lambda requirement=requirement: preinstall._require_host_dependency(
                    requirement
                ),
            )
        )

    for payload in INSTALLATION_AUTHORITY.payloads:
        checks.append(
            (
                "package:" + payload.package,
                lambda payload=payload: postinstall._require_package(payload),
            )
        )

    checks.extend(
        (
            ("conflicting_packages_absent", postinstall._require_conflicts_absent),
            ("rootful_masks", daemonq._require_rootful_masks),
            ("kernel_prerequisites", preinstall._require_kernel_prerequisites),
            ("executable_shadowing", postinstall._require_no_shadowing),
            ("critical_executables", postinstall._require_critical_executables),
            ("package_bundle", staticq.qualify_rootless_docker_package_bundle),
            ("package_host_composite", daemonq._package_host),
            ("subids", staticq._require_subids),
            (
                "user_manager_template_dropins",
                staticq._require_user_manager_template_dropins,
            ),
            ("post_daemon_data_root", daemonq._require_post_daemon_data_root),
        )
    )

    for path, uid, gid, mode in AUTHORITY.post_daemon_provisioned_directories:
        if path == AUTHORITY.data_root:
            continue
        checks.append(
            (
                "directory:" + path,
                lambda path=path, uid=uid, gid=gid, mode=mode: staticq._require_directory(
                    path,
                    uid,
                    gid,
                    mode,
                    staticq._EXPECTED_DIRECTORY_CHILDREN[path],
                ),
            )
        )

    for _source, destination, digest, uid, gid, mode in AUTHORITY.installed_assets:
        checks.append(
            (
                "asset:" + destination,
                lambda destination=destination, digest=digest, uid=uid, gid=gid, mode=mode: staticq._require_file(
                    destination,
                    digest,
                    uid,
                    gid,
                    mode,
                ),
            )
        )

    checks.extend(
        (
            ("post_daemon_static_assets", daemonq._require_post_daemon_static_assets),
            ("executor_dropins", _executor_dropins),
            ("user_dropins", _user_dropins),
            ("deployment_units", _deployment_units),
            ("user_unit", daemonq._user_unit_evidence),
            ("process_evidence", _process_evidence),
            ("daemon_socket", daemonq._socket_evidence),
            ("rootlesskit_state", daemonq._rootlesskit_state_evidence),
            ("runtime_artifacts", daemonq._runtime_artifacts_exact),
            ("docker_info", daemonq._docker_info_evidence),
            ("user_manager", daemonq._user_manager_evidence),
            ("root_identity_final", daemonq._root_identity),
            ("qualify_once_first", daemonq._qualify_once),
            ("qualify_once_second", daemonq._qualify_once),
            ("public_c33f", daemonq.qualify_rootless_docker_daemon),
        )
    )

    return tuple(checks)


def preflight_rootless_docker_daemon() -> RootlessDockerDaemonPreflightEvidence:
    """Run the complete read-only assertion matrix without fail-fast behavior."""

    results = tuple(
        _evaluate(name, function)
        for name, function in _component_checks()
    )
    return RootlessDockerDaemonPreflightEvidence(results)
