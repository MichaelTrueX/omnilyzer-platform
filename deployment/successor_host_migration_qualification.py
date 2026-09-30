"""Read-only C32ZL qualification for the successor DEV host migration.

Qualification requires real/effective root, exact inactive systemd state, the
hardened root executor/broker readers, and an exact full predecessor or
successor application manifest. It performs no host mutation. A later root-only
migration implementation must preserve these gates under the process lock.

Related: successor_host_migration_authority.py,
root_executor_configuration_reader.py, root_broker_configuration_reader.py.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
import subprocess

from . import dev_host_provisioning_mechanics as mechanics
from . import final_application_generation as c32w
from . import successor_application_generation as successor
from .broker_service_config import DevBrokerServiceConfiguration
from .executor_service_config import DevExecutorServiceConfiguration
from .host_service_layout import DevHostServiceLayout
from .root_broker_configuration_reader import read_root_dev_broker_configuration
from .root_executor_configuration_reader import read_root_dev_executor_configuration
from .successor_host_migration_authority import (
    DevSuccessorHostMigrationAuthority,
    DevSuccessorHostMigrationState,
)


__all__ = (
    "SuccessorHostMigrationQualificationError",
    "SuccessorHostMigrationQualificationEvidence",
    "qualify_successor_host_migration",
)

_ERROR = "successor DEV host migration qualification is unavailable"
_APP_ROOT = "/opt/omnilyzer/deployment/app"
_SYSTEMCTL = "/usr/bin/systemctl"
_BROKER_UNIT = "omnilyzer-deployment-broker.service"
_SYSTEMCTL_TIMEOUT = 5.0


class SuccessorHostMigrationQualificationError(Exception):
    """One fixed external failure for the read-only privileged qualifier."""


@dataclass(frozen=True, slots=True)
class SuccessorHostMigrationQualificationEvidence:
    """Digest-only state returned by one complete read-only qualification."""

    phase: str
    next_operation: str
    application_sha256: str
    executor_reviewed_commit: str
    broker_reviewed_commit: str
    expected_workflow_sha: str

    def __post_init__(self) -> None:
        """Reuse the pure migration-state validator for evidence closure."""

        DevSuccessorHostMigrationState(
            self.phase,
            self.next_operation,
            self.application_sha256,
            self.executor_reviewed_commit,
            self.broker_reviewed_commit,
            self.expected_workflow_sha,
        )


def _root_identity() -> tuple[int, int, int, int]:
    """Require exact real/effective root identity."""

    identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if any(type(value) is not int or value != 0 for value in identity):
        raise OSError
    return identity


def _systemctl_property(unit: str, property_name: str) -> str:
    """Read one exact systemd property through a closed command boundary."""

    if (
        type(unit) is not str
        or unit not in {
            _BROKER_UNIT,
            DevHostServiceLayout().executor_service_unit_name,
            DevHostServiceLayout().executor_socket_unit_name,
        }
        or property_name not in {"ActiveState", "UnitFileState"}
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
        timeout=_SYSTEMCTL_TIMEOUT,
        check=False,
    )
    if (
        type(result.returncode) is not int
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or len(result.stdout) > 64
        or not result.stdout.endswith(b"\n")
    ):
        raise OSError
    value = result.stdout[:-1].decode("ascii")
    if not value or "\n" in value or "\r" in value:
        raise OSError
    return value


def _systemd_snapshot() -> tuple[tuple[str, str, str], ...]:
    """Require the exact pre-activation state of broker/executor units."""

    layout = DevHostServiceLayout()
    expected = (
        (_BROKER_UNIT, "inactive", "static"),
        (layout.executor_service_unit_name, "inactive", "static"),
        (layout.executor_socket_unit_name, "inactive", "disabled"),
    )
    observed = tuple(
        (
            unit,
            _systemctl_property(unit, "ActiveState"),
            _systemctl_property(unit, "UnitFileState"),
        )
        for unit, _active, _enabled in expected
    )
    if observed != expected:
        raise OSError
    return observed


def _application_digest() -> str:
    """Verify the complete installed application as exact C32W or C32ZH."""

    predecessor, _predecessor_blobs = c32w._reviewed_target()
    target, _target_blobs = successor._reviewed_target()
    owned: list[int] = []
    try:
        root, chain = mechanics._open_directory(_APP_ROOT, owned)
        status = os.fstat(root)
        if (
            (status.st_uid, status.st_gid) != (0, 0)
            or (status.st_mode & 0o7777) != 0o755
        ):
            raise OSError
        for manifest, digest in (
            (predecessor, successor.PREDECESSOR_DOCKER_SHA256),
            (target, successor.TARGET_DOCKER_SHA256),
        ):
            try:
                mechanics._verify_application(root, manifest, 0, 0)
                mechanics._revalidate_chain(chain)
                return digest
            except OSError:
                continue
        raise OSError
    finally:
        mechanics._finish_close(owned)


def _authority(
    executor: DevExecutorServiceConfiguration,
    broker: DevBrokerServiceConfiguration,
) -> DevSuccessorHostMigrationAuthority:
    """Normalize any accepted prefix back to the exact C32W predecessor pair."""

    if (
        type(executor) is not DevExecutorServiceConfiguration
        or type(broker) is not DevBrokerServiceConfiguration
    ):
        raise OSError
    predecessor_executor = replace(
        executor, reviewed_commit=successor.PREDECESSOR_REVIEWED_COMMIT,
    )
    predecessor_broker = replace(
        broker, reviewed_commit=successor.PREDECESSOR_REVIEWED_COMMIT,
    )
    return DevSuccessorHostMigrationAuthority(
        predecessor_executor=predecessor_executor,
        predecessor_broker=predecessor_broker,
    )


def _snapshot() -> tuple[
    DevSuccessorHostMigrationState,
    DevExecutorServiceConfiguration,
    DevBrokerServiceConfiguration,
]:
    """Read and classify one complete migration snapshot."""

    executor = read_root_dev_executor_configuration()
    broker = read_root_dev_broker_configuration()
    digest = _application_digest()
    authority = _authority(executor, broker)
    state = authority.classify(
        application_sha256=digest,
        executor=executor,
        broker=broker,
    )
    return state, executor, broker


def qualify_successor_host_migration() -> SuccessorHostMigrationQualificationEvidence:
    """Return a stable read-only migration prefix or fail closed."""

    try:
        identity = _root_identity()
        services = _systemd_snapshot()
        first, first_executor, first_broker = _snapshot()
        if _root_identity() != identity or _systemd_snapshot() != services:
            raise OSError
        second, second_executor, second_broker = _snapshot()
        if (
            second != first
            or second_executor.canonical_bytes() != first_executor.canonical_bytes()
            or second_broker.canonical_bytes() != first_broker.canonical_bytes()
            or _root_identity() != identity
            or _systemd_snapshot() != services
        ):
            raise OSError
        return SuccessorHostMigrationQualificationEvidence(
            first.phase,
            first.next_operation,
            first.application_sha256,
            first.executor_reviewed_commit,
            first.broker_reviewed_commit,
            first.expected_workflow_sha,
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise SuccessorHostMigrationQualificationError(_ERROR) from None
