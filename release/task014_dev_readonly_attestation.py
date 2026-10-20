"""File: release/task014_dev_readonly_attestation.py

Purpose: Produce a bounded, nonsecret, root-controlled DEV installation
attestation before any Task014 private Zot source/config migration.
This is an OFFLINE LIBRARY (no CLI, import-time actions or service controls).
Related: deployment/application_manifest.py,
release/task014_source_cutover.py, release/task014_config_cutover.py,
release/tests/test_task014_dev_readonly_attestation.py and Task014 issue #182.

Sections:
  1. Fixed existing DEV paths and bounded, no-follow config reads.
  2. Existing canonical broker/executor identity and source verification.
  3. Strict read-only systemd sandbox checks and sanitized evidence.
Never writes host files, mints OIDC credentials, invokes Docker, deploys,
modifies replay, resets a service, reads PROD, or prints configuration bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import subprocess
from typing import Mapping

from deployment.broker_service_config import (
    BROKER_SERVICE_CONFIG_FILE_MODE,
    PRODUCTION_BROKER_SERVICE_CONFIG_PATH,
    parse_canonical_broker_service_configuration,
)
from deployment.executor_service_config import (
    EXECUTOR_SERVICE_CONFIG_FILE_MODE,
    PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH,
    parse_canonical_executor_service_configuration,
)
from release import task014_source_cutover as source_cutover

# Section 1: existing, immutable DEV configuration paths. No configurable
# destination or command-line path override is available in production.
BROKER_PATH = Path(PRODUCTION_BROKER_SERVICE_CONFIG_PATH)
EXECUTOR_PATH = Path(PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH)
SOURCE_PATH = Path("/opt/omnilyzer/deployment/app")
DEV_UNITS = (
    "omnilyzer-deployment-broker.service",
    "omnilyzer-deployment-executor.socket",
    "omnilyzer-deployment-executor.service",
    "nginx.service",
)
MAX_BYTES = 4096


class DevAttestationHold(Exception):
    """Untrusted host state: return a redacted failure, never raw config bytes."""


@dataclass(frozen=True, slots=True)
class ReadOnlyDevEvidence:
    """Approved-for-display checksums, pinned identifiers and health states."""

    source_manifest_sha256: str
    prior_source_matches: bool
    selected_source_count: int
    broker_config_sha256: str
    executor_config_sha256: str
    installed_reviewed_commit: str
    expected_workflow_sha: str
    identities_valid: bool
    systemd_sandbox_valid: bool
    systemd_unit_states: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, object]:
        """Export only allowlisted nonsecret values for operator review."""
        return {
            "source_manifest_sha256": self.source_manifest_sha256,
            "prior_source_matches": self.prior_source_matches,
            "selected_source_count": self.selected_source_count,
            "broker_config_sha256": self.broker_config_sha256,
            "executor_config_sha256": self.executor_config_sha256,
            "installed_reviewed_commit": self.installed_reviewed_commit,
            "expected_workflow_sha": self.expected_workflow_sha,
            "identities_valid": self.identities_valid,
            "systemd_sandbox_valid": self.systemd_sandbox_valid,
            "systemd_unit_states": dict(self.systemd_unit_states),
        }


def _require_root() -> None:
    """Fail closed unless the independently authorized OS operator is root."""
    if os.getuid() != 0 or os.geteuid() != 0:
        raise DevAttestationHold("authorized root preflight required")


def _is_root_service_owned(state: os.stat_result, service_gid: int) -> bool:
    """Match the protected root:service-group identity, not process umask."""
    return state.st_uid == 0 and state.st_gid == service_gid


def _read_protected_json(path: Path, service_gid: int, mode: int) -> bytes:
    """Read one root:service-group regular file, with no symlink or FD race."""
    parent = path.parent
    try:
        d = parent.lstat()
        if (
            not stat.S_ISDIR(d.st_mode) or stat.S_ISLNK(d.st_mode)
            or not _is_root_service_owned(d, service_gid)
            or stat.S_IMODE(d.st_mode) != 0o750
        ):
            raise ValueError
        f = path.lstat()
        if (
            not stat.S_ISREG(f.st_mode) or stat.S_ISLNK(f.st_mode)
            or not _is_root_service_owned(f, service_gid)
            or stat.S_IMODE(f.st_mode) != mode or f.st_nlink != 1
            or not 1 <= f.st_size <= MAX_BYTES
        ):
            raise ValueError
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        )
        try:
            before = os.fstat(descriptor)
            checked = ("st_dev", "st_ino", "st_uid", "st_gid",
                       "st_mode", "st_nlink", "st_size")
            if any(getattr(before, key) != getattr(f, key) for key in checked):
                raise ValueError
            payload = os.read(descriptor, MAX_BYTES + 1)
            after = os.fstat(descriptor)
            if (
                len(payload) != f.st_size
                or any(getattr(after, key) != getattr(f, key) for key in checked)
            ):
                raise ValueError
            return payload
        finally:
            os.close(descriptor)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise DevAttestationHold("protected configuration unavailable") from None


# Section 2: use existing canonical models; never invent an old SHA/identity.
def _validated_pair() -> tuple[bytes, bytes, object, object]:
    """Read and compare closed, canonical authority without exposing values."""
    try:
        # These groups are already installed service identities, not user input.
        broker_bytes = _read_protected_json(
            BROKER_PATH, 990, BROKER_SERVICE_CONFIG_FILE_MODE
        )
        executor_bytes = _read_protected_json(
            EXECUTOR_PATH, 991, EXECUTOR_SERVICE_CONFIG_FILE_MODE
        )
        broker = parse_canonical_broker_service_configuration(broker_bytes)
        executor = parse_canonical_executor_service_configuration(executor_bytes)
        if (
            broker.broker_uid != 990 or broker.broker_gid != 990
            or broker.executor_uid != 991 or broker.executor_gid != 991
            or broker.replay_group_gid != 992 or broker.socket_group_gid != 993
            or executor.broker_uid != 990 or executor.broker_gid != 990
            or executor.executor_uid != 991 or executor.executor_gid != 991
            or executor.replay_group_gid != 992 or executor.socket_group_gid != 993
            or broker.installation_contract() != executor.installation_contract()
            or broker.reviewed_commit != executor.reviewed_commit
            or broker.runtime_configuration_sha256
               != executor.runtime_configuration_sha256
            or broker.ingress_file_sha256 != executor.ingress_file_sha256
        ):
            raise ValueError
        return broker_bytes, executor_bytes, broker, executor
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise DevAttestationHold("DEV configuration authority mismatch") from None


# Section 3: fixed systemd read-only queries; no environment output or logs.
def _systemctl_properties(
    unit: str, properties: tuple[str, ...],
) -> dict[str, str]:
    """Read exact safe systemd property names using a bounded no-shell call."""
    try:
        if unit not in DEV_UNITS:
            raise ValueError
        arguments = ["/usr/bin/systemctl", "show", unit, "--no-pager"]
        for item in properties:
            if item not in (
                "User", "Group", "RuntimeDirectory", "RuntimeDirectoryMode",
                "ProtectSystem", "UMask", "BindReadOnlyPaths",
                "SocketUser", "SocketGroup", "SocketMode", "Listen",
            ):
                raise ValueError
            arguments.extend(("-p", item))
        r = subprocess.run(
            arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=8, check=False,
        )
        if r.returncode != 0 or len(r.stdout) > 8192:
            raise ValueError
        data = dict(line.split("=", 1) for line in
                    r.stdout.decode("utf-8", "strict").splitlines()
                    if "=" in line)
        if set(data) != set(properties):
            raise ValueError
        return data
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise DevAttestationHold("systemd read-only preflight unavailable") from None


def _systemd_evidence() -> tuple[bool, tuple[tuple[str, str], ...]]:
    """Require the executor rootless sandbox and disclose only unit states."""
    service = "omnilyzer-deployment-executor.service"
    properties = _systemctl_properties(service, (
        "User", "Group", "RuntimeDirectory", "RuntimeDirectoryMode",
        "ProtectSystem", "UMask", "BindReadOnlyPaths",
    ))
    broker = _systemctl_properties(
        "omnilyzer-deployment-broker.service",
        ("User", "Group", "ProtectSystem", "UMask"),
    )
    socket_unit = _systemctl_properties(
        "omnilyzer-deployment-executor.socket",
        ("SocketUser", "SocketGroup", "SocketMode", "Listen"),
    )
    socket = "/run/user/991/docker.sock:/run/omnilyzer/deployment/rootless-docker/docker.sock"
    expected = (
        broker == {
            "User": "omnilyzer-broker",
            "Group": "omnilyzer-broker",
            "ProtectSystem": "strict",
            "UMask": "0077",
        }
        and socket_unit == {
            "SocketUser": "omnilyzer-executor",
            "SocketGroup": "omnilyzer-deployment",
            "SocketMode": "0660",
            "Listen": "/run/omnilyzer/deployment/executor.sock (Stream)",
        }
        and properties["User"] == "omnilyzer-executor"
        and properties["Group"] == "omnilyzer-executor"
        and properties["RuntimeDirectory"] == "omnilyzer/deployment/rootless-docker"
        and properties["RuntimeDirectoryMode"] == "0700"
        and properties["ProtectSystem"] == "strict"
        and properties["UMask"] == "0077"
        and socket in properties["BindReadOnlyPaths"]
    )
    states: list[tuple[str, str]] = []
    for unit in DEV_UNITS:
        try:
            r = subprocess.run(
                ["/usr/bin/systemctl", "is-active", unit],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=5, check=False,
            )
            status = r.stdout.decode("ascii", "strict").strip()
            if status not in ("active", "inactive", "failed"):
                raise ValueError
            states.append((unit, status))
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise DevAttestationHold("systemd state unavailable") from None
    return expected, tuple(states)


def attest_dev_host(
    reviewed_source_plan: source_cutover.SourceGenerationPlan,
) -> ReadOnlyDevEvidence:
    """Check full old source + canonical configs + systemd without writes.

    The caller independently generates/reviews SourceGenerationPlan from a
    trusted, exact-SHA checkout. No source, config or workflow pins are
    inferred from the live OS or ambient environment.
    """
    _require_root()
    try:
        if type(reviewed_source_plan) is not source_cutover.SourceGenerationPlan:
            raise ValueError
        if len(reviewed_source_plan.prior_entries) != 41:
            raise ValueError
        # Existing source tree is expected to be the old 41-file generation.
        old = source_cutover._observed_tree(SOURCE_PATH)
        if old != reviewed_source_plan.prior_entries:
            raise ValueError
        broker_bytes, executor_bytes, broker, executor = _validated_pair()
        if broker.reviewed_commit != source_cutover.PRIOR_SOURCE_SHA:
            raise ValueError
        sandbox, states = _systemd_evidence()
        if not sandbox:
            raise ValueError("executor sandbox inconsistent")
        return ReadOnlyDevEvidence(
            source_manifest_sha256=reviewed_source_plan.target_manifest_sha256,
            prior_source_matches=True,
            selected_source_count=len(reviewed_source_plan.target_entries),
            broker_config_sha256=hashlib.sha256(broker_bytes).hexdigest(),
            executor_config_sha256=hashlib.sha256(executor_bytes).hexdigest(),
            installed_reviewed_commit=broker.reviewed_commit,
            expected_workflow_sha=broker.expected_workflow_sha,
            identities_valid=True,
            systemd_sandbox_valid=sandbox,
            systemd_unit_states=states,
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise DevAttestationHold("DEV root-only read preflight HOLD") from None
