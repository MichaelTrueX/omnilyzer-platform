"""File: deployment/analytics_first_install.py

Purpose: One signed Analytics 0.15.0 PRIVATE DEV first-install operation for
         original Task014 AnalyticsPrivilegedExecutor.deploy_analytics().
         Reuse original rootless Docker runner, exact Compose YAML, sealed Zot
         registry adapter, and fail-closed first-slot rollback.
Related: deployment/analytics_execution.py (closed signed request),
         deployment/analytics_private_registry.py (exact digest private pull),
         deployment/analytics_dev_release_review.py (four host secret refs),
         deployment/rootless_docker_authority.py (UID 10001 host mapping),
         deployment/runtime/dev/analytics.compose.review.yaml (only blue slot),
         deployment/docker_runtime.py (original rootless Docker commands),
         deployment/tests/test_analytics_first_install.py.

Sections: fixed product authority and command contracts; required preflight
          (source, secrets, empty blue slot, isolated network); exact signed
          pull and local RepoDigest; blue-only startup, private health checks,
          stop-only fail-closed rollback preserving database writes.

SECURITY: Construction/import are inert. This module cannot authorize itself:
a root-controlled installed source manifest, original OIDC/Cosign/Sigstore,
broker replay/FD, rootless host, four UID-mapped files, and separately verified
PostgreSQL auth/collector isolation MUST precede privileged activation. The
module is not in the installed Task014 source set; no systemd service, live
Docker, secret, PostgreSQL or production operation is authorized by this PR.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time

from .analytics_execution import AnalyticsExecutorRequest
from .analytics_private_registry import (
    AnalyticsPrivateZotPullAdapter, ANALYTICS_PULL_TIMEOUT_SECONDS,
)
from .analytics_signed_release_consumer import PINNED_IMAGE
from .analytics_dev_release_review import (
    COMPOSE_FILE, REQUIRED_SECRET_NAMES, SECRET_DIRECTORY,
    review_private_secret_paths,
)
from .docker_runtime import (
    COMMAND_TIMEOUT_SECONDS, WORKING_DIRECTORY, CommandResult,
    _candidate_command_run, _docker, _require_rootless_socket,
)
from .rootless_docker_authority import RootlessDockerAuthority
from .unix_transport import _Deadline

_ERROR = "TASK014_ANALYTICS_FIRST_INSTALL_UNAVAILABLE"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_PROJECT = "omnilyzer-analytics-dev"
_SERVICE = "analytics-blue"
_NETWORK = "omnilyzer-analytics-backend-dev"
_CONTAINER_UID = 10001
_LOOPBACK = "127.0.0.1"
_PORT = "3141"
_HEALTH_PROBES = 12
_INTERVAL_SECONDS = 2.0
_RUN_TIMEOUT = 45.0
_STOP_TIMEOUT = 45.0
_MAX_OUTPUT = 16 * 1024
# Cover all normal first-install work, including the cold pull. The independent
# stop-only cleanup remains45+30s; manifest preflight is30s before this operation.
# Those phases and replay/response reserve fit the720s Analytics response window.
ANALYTICS_OPERATION_TIMEOUT_SECONDS = 570.0
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")

# Never pass token bytes, file contents, operator-provided args, or public
# ingress references to the Docker CLI or subprocess environment.
_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "ANALYTICS_BLUE_IMAGE": PINNED_IMAGE,
    # The green profile remains disabled. Compose still resolves its image.
    "ANALYTICS_GREEN_IMAGE": PINNED_IMAGE,
}
_COMPOSE = (
    "compose", "--project-name", _PROJECT,
    "--file", str(COMPOSE_FILE), "--profile", "blue",
)
# A successful HTTP GET must come from the container itself (not host ingress).
_READY_SCRIPT = (
    'fetch("http://127.0.0.1:3000/readyz",{cache:"no-store"})'
    '.then(r=>{if(!r.ok)process.exit(1);'
    'process.stdout.write("READY\\n")}).catch(()=>process.exit(1))'
)


class AnalyticsFirstInstallError(Exception):
    """One private first-install operation failed; no user-provided details."""


def _strict_json(raw: str) -> object:
    """Parse bounded Docker metadata without duplicate keys or NaN."""
    if type(raw) is not str or len(raw.encode("utf-8")) > _MAX_OUTPUT:
        raise AnalyticsFirstInstallError(_ERROR)

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Reject an ambiguous Docker metadata object."""
        data: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in data:
                raise ValueError
            data[key] = value
        return data

    try:
        return json.loads(
            raw, object_pairs_hook=no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError),
        )
    except (ValueError, TypeError, UnicodeError):
        raise AnalyticsFirstInstallError(_ERROR) from None


def _require_mapped_secret_groups(mapped_gid: int) -> None:
    """Check ONLY secret-file mapped GID, not the root-owned source directory.

    The existing review_private_secret_paths() independently enforces a
    root:991, mode0710 source DIRECTORY and UID503216/mode0600 files. Requiring
    the directory itself to have container-mapped GID503216 contradicts that
    rootless Docker traversal contract and would block every real install.
    These four regular FILES, not their parent, require mapped container GID.
    """
    if type(mapped_gid) is not int or mapped_gid < 1:
        raise AnalyticsFirstInstallError(_ERROR)
    try:
        for name in REQUIRED_SECRET_NAMES:
            if (SECRET_DIRECTORY / name).stat(follow_symlinks=False).st_gid != mapped_gid:
                raise AnalyticsFirstInstallError(_ERROR)
    except (OSError, ValueError) as exc:
        raise AnalyticsFirstInstallError(_ERROR) from exc


class AnalyticsFirstInstallOperation:
    """Closed first blue-slot only, with stop-only rollback on every failure."""

    __slots__ = ("_run", "_pull", "_source", "_clock", "_sleep",
                 "_completed_request_hash", "_deadline")

    def __init__(
        self, *, runner: object,
        private_registry: AnalyticsPrivateZotPullAdapter,
        reviewed_installed_source: dict[str, str],
    ) -> None:
        """Capture only original verified collaborators; do not touch host."""
        from .analytics_unix_boundary import _root_reviewed_source

        try:
            if type(private_registry) is not AnalyticsPrivateZotPullAdapter:
                raise TypeError
            source = _root_reviewed_source(reviewed_installed_source)
            # Both dependencies MUST use the same root-controlled manifest.
            if object.__getattribute__(private_registry, "_source") != source:
                raise TypeError
            object.__setattr__(
                self, "_run", _candidate_command_run(runner),
            )
            object.__setattr__(self, "_pull", private_registry.pull_analytics)
            object.__setattr__(self, "_source", source)
            object.__setattr__(self, "_clock", time.monotonic)
            object.__setattr__(self, "_sleep", time.sleep)
            object.__setattr__(self, "_completed_request_hash", None)
            object.__setattr__(self, "_deadline", None)
        except _CONTROL:
            raise
        except Exception:
            raise TypeError(_ERROR) from None

    def __setattr__(self, name: str, value: object) -> None:
        """No post-review runtime/runner or policy substitution."""
        raise AttributeError("Analytics first-install operation is immutable")

    def __delattr__(self, name: str) -> None:
        """No deletion of original rootless authority collaborators."""
        raise AttributeError("Analytics first-install operation is immutable")

    def _work_timeout(self, timeout: float) -> float:
        """Clamp normal work to one validated monotonic operation deadline."""
        if type(timeout) is not float or not math.isfinite(timeout) or timeout <= 0:
            raise AnalyticsFirstInstallError(_ERROR)
        deadline = object.__getattribute__(self, "_deadline")
        return min(timeout, deadline.remaining()) if deadline is not None else timeout

    def _invoke_docker(
        self, *parts: str, timeout: float = COMMAND_TIMEOUT_SECONDS,
    ) -> CommandResult:
        """Execute ONLY rootless original Docker command with no secret env."""
        _require_rootless_socket()
        result = object.__getattribute__(self, "_run")(
            _docker(*parts), cwd=WORKING_DIRECTORY,
            environment=dict(_ENV), timeout=timeout,
        )
        if (
            type(result) is not CommandResult
            or type(result.returncode) is not int
            or result.returncode != 0
            or type(result.stdout) is not str
            or type(result.stderr) is not str
            or len(result.stdout.encode("utf-8")) > _MAX_OUTPUT
        ):
            raise AnalyticsFirstInstallError(_ERROR)
        return result

    def _docker(
        self, *parts: str, timeout: float = COMMAND_TIMEOUT_SECONDS,
    ) -> CommandResult:
        bounded = self._work_timeout(timeout)
        result = self._invoke_docker(*parts, timeout=bounded)
        self._work_timeout(1.0)
        return result

    def _compose(
        self, *parts: str, timeout: float = COMMAND_TIMEOUT_SECONDS,
    ) -> CommandResult:
        """Use exact immutable project/file/profile, never compose down."""
        return self._docker(*_COMPOSE, *parts, timeout=timeout)

    def _preflight(self, request: AnalyticsExecutorRequest) -> None:
        """Verify signed contract and rootless host before Docker mutations."""
        if (
            type(request) is not AnalyticsExecutorRequest
            or request.exact_image_reference != PINNED_IMAGE
            or request.ingress_reference.get("slot") != "blue"
            or request.ingress_reference.get("loopback_address") != _LOOPBACK
            or request.ingress_reference.get("loopback_port") != int(_PORT)
            or request.ingress_reference.get("backend_network") != _NETWORK
            or request.ingress_reference.get("public_origin") is not None
            or request.rollback_reference.get("previous_digest") is not None
            or request.rollback_reference.get("preserve_database_writes") is not True
            or request.secrets_reference.get("required")
                != list(REQUIRED_SECRET_NAMES)
        ):
            raise AnalyticsFirstInstallError(_ERROR)
        source = dict(object.__getattribute__(self, "_source"))
        if (
            request.runtime_configuration_reference["compose_sha256"]
                != source["reviewed_compose_sha256"]
            or request.runtime_configuration_reference["product_profile_sha256"]
                != source["reviewed_product_profile_sha256"]
            or request.runtime_configuration_reference["runtime_profile_sha256"]
                != source["reviewed_runtime_profile_sha256"]
        ):
            raise AnalyticsFirstInstallError(_ERROR)

        # Exact source digest: no mutated Compose, symlink, or alternate file.
        if (
            COMPOSE_FILE.is_symlink() or not COMPOSE_FILE.is_file()
            or hashlib.sha256(COMPOSE_FILE.read_bytes()).hexdigest()
                != source["reviewed_compose_sha256"]
        ):
            raise AnalyticsFirstInstallError(_ERROR)

        # In original Task014 rootless uidmap, internal UID10001 == host
        # subordinate UID503216. Local file-secrets ignore uid/gid/mode values
        # in Compose; DO NOT blindly trust the YAML.
        authority = RootlessDockerAuthority()
        mapped_uid = authority.subuid_start + _CONTAINER_UID - 1
        mapped_gid = authority.subgid_start + _CONTAINER_UID - 1
        if (
            mapped_uid != authority.canary_host_uid
            or mapped_gid != authority.canary_host_gid
            or request.secrets_reference.get("container_uid") != _CONTAINER_UID
            or request.secrets_reference.get("file_mode") != "0600"
            or request.secrets_reference.get("rootless_required") is not True
            or tuple(review_private_secret_paths(
                directory=SECRET_DIRECTORY, owner_uid=mapped_uid,
                directory_owner_uid=0,
                directory_group_gid=authority.executor_gid,
            )) != REQUIRED_SECRET_NAMES
        ):
            raise AnalyticsFirstInstallError(_ERROR)
        # The root-owned private directory itself is group-traversable only
        # by the rootless executor. Each file uses mapped container GID.
        _require_mapped_secret_groups(mapped_gid)

        _require_rootless_socket()
        # Read-only network name check. Docker cannot create/manage it from
        # this task. No public network/ingress change is permitted.
        network = self._docker(
            "network", "inspect", "--format", "{{json .Name}}", _NETWORK,
        )
        if _strict_json(network.stdout.strip()) != _NETWORK:
            raise AnalyticsFirstInstallError(_ERROR)
        # Compose manifest must be parsable using exact immutable image vars.
        if self._compose("config", "--quiet").stdout != "":
            raise AnalyticsFirstInstallError(_ERROR)
        # An existing or stopped blue container is NOT a first install.
        slots = self._compose(
            "ps", "--all", "--format", "json", _SERVICE,
        ).stdout.strip()
        if slots not in ("", "[]"):
            raise AnalyticsFirstInstallError(_ERROR)

    def _container_id(self) -> str:
        """Locate exactly one private blue container, never another product."""
        output = self._compose("ps", "-q", _SERVICE).stdout.strip()
        if _CONTAINER_ID.fullmatch(output) is None:
            raise AnalyticsFirstInstallError(_ERROR)
        return output

    def _verify_local_digest(self) -> None:
        """Verify pulled local image RepoDigests matches only signed 0.15.0."""
        output = self._docker(
            "image", "inspect", "--format", "{{json .RepoDigests}}",
            PINNED_IMAGE,
        )
        if _strict_json(output.stdout.strip()) != [PINNED_IMAGE]:
            raise AnalyticsFirstInstallError(_ERROR)

    def _verify_private_container(self, container_id: str) -> None:
        """Verify runtime user, no public bind, privileges and network."""
        checks = (
            ("{{json .Config.Image}}", PINNED_IMAGE),
            ("{{json .Config.User}}", "10001:10001"),
            ("{{json .HostConfig.ReadonlyRootfs}}", True),
            ("{{json .HostConfig.Privileged}}", False),
            ("{{json .HostConfig.CapDrop}}", ["ALL"]),
            ("{{json .HostConfig.SecurityOpt}}", ["no-new-privileges:true"]),
            ("{{json .HostConfig.PortBindings}}", {
                "3000/tcp": [{"HostIp": _LOOPBACK, "HostPort": _PORT}],
            }),
        )
        for template, expected in checks:
            output = self._docker(
                "container", "inspect", "--format", template,
                container_id,
            )
            if _strict_json(output.stdout.strip()) != expected:
                raise AnalyticsFirstInstallError(_ERROR)
        # Container must have exactly the already reviewed PG backend network.
        output = self._docker(
            "container", "inspect", "--format",
            "{{json .NetworkSettings.Networks}}", container_id,
        )
        networks = _strict_json(output.stdout.strip())
        if type(networks) is not dict or set(networks) != {_NETWORK}:
            raise AnalyticsFirstInstallError(_ERROR)

    def _private_ready(self, container_id: str) -> None:
        """Bounded Docker health state plus in-container loopback HTTP /readyz."""
        clock = object.__getattribute__(self, "_clock")
        sleep = object.__getattribute__(self, "_sleep")
        deadline = clock() + _HEALTH_PROBES * (_INTERVAL_SECONDS + 3.0)
        for attempt in range(_HEALTH_PROBES):
            status = _strict_json(
                self._docker(
                    "container", "inspect", "--format",
                    "{{json .State.Health.Status}}", container_id,
                ).stdout.strip()
            )
            if status == "healthy":
                probe = self._compose(
                    "exec", "--no-TTY", _SERVICE,
                    "node", "-e", _READY_SCRIPT, timeout=5.0,
                )
                if probe.stdout != "READY\n":
                    raise AnalyticsFirstInstallError(_ERROR)
                return
            if status not in ("starting",):
                raise AnalyticsFirstInstallError(_ERROR)
            if clock() + _INTERVAL_SECONDS >= deadline:
                break
            if attempt < _HEALTH_PROBES - 1:
                sleep(self._work_timeout(_INTERVAL_SECONDS))
        raise AnalyticsFirstInstallError(_ERROR)

    def _stop_first_slot(self) -> bool:
        """Only stop private blue, never delete DB, volumes, image or network."""
        try:
            # These TWO exact cleanup commands have their independent75s
            # reserve even when the normal operation deadline has elapsed.
            self._invoke_docker(
                *_COMPOSE,
                "stop", "--timeout", "15", _SERVICE,
                timeout=_STOP_TIMEOUT,
            )
            # Running list must now be empty. No docker compose down/rm.
            output = self._invoke_docker(
                *_COMPOSE,
                "ps", "--status", "running", "--format", "json", _SERVICE,
            ).stdout.strip()
            return output in ("", "[]")
        except _CONTROL:
            raise
        except Exception:
            return False

    def deploy_analytics(self, request: AnalyticsExecutorRequest) -> None:
        """First install one private candidate or stop it, preserving DB writes.

        This is called only inside the original executor's scoped, previously
        verified and consumed single-use request/FD/replay context. An
        untrusted caller constructing the dataclass is not an admission.
        """
        candidate_may_exist = False
        object.__setattr__(self, "_deadline", _Deadline(
            object.__getattribute__(self, "_clock"),
            int(ANALYTICS_OPERATION_TIMEOUT_SECONDS * 1000),
        ))
        try:
            self._preflight(request)
            pull_timeout = self._work_timeout(ANALYTICS_PULL_TIMEOUT_SECONDS)
            object.__getattribute__(self, "_pull")(request, timeout=pull_timeout)
            self._work_timeout(1.0)
            self._verify_local_digest()
            # Docker may partially start a container before returning failure;
            # set cleanup duty BEFORE invoking the first mutating operation.
            candidate_may_exist = True
            self._compose(
                "up", "--detach", "--no-deps", "--force-recreate",
                "--no-build", "--pull", "never", _SERVICE,
                timeout=_RUN_TIMEOUT,
            )
            container_id = self._container_id()
            self._verify_private_container(container_id)
            self._private_ready(container_id)
            self._work_timeout(1.0)
            # A successful readiness probe alone is not final Task014
            # acceptance: executor replay.finish may still fail. Retain
            # nonsecret request identity for its bound stop-only cleanup.
            object.__setattr__(
                self, "_completed_request_hash",
                hashlib.sha256(request.canonical_bytes()).hexdigest(),
            )
            return None
        except _CONTROL:
            # For operator signals, preserve fail-safe cleanup but propagate.
            if candidate_may_exist:
                self._stop_first_slot()
            raise
        except Exception:
            if candidate_may_exist:
                safe = self._stop_first_slot()
                sys.stderr.write(
                    "TASK014_ANALYTICS_FIRST_INSTALL_DENIED "
                    + ("rollback=stopped" if safe else "rollback=unconfirmed")
                    + "\n"
                )
            raise AnalyticsFirstInstallError(_ERROR) from None


    def rollback_first_analytics(self, request: AnalyticsExecutorRequest) -> None:
        """Stop only this newly healthy slot if executor finalization fails.

        No rollback of a previous image is possible on the first install;
        DB writes, network, volumes and images are never deleted. This method
        is captured by the privileged executor at construction. It never
        accepts an arbitrary container/project/slot name from its caller.
        """
        if type(request) is not AnalyticsExecutorRequest:
            raise AnalyticsFirstInstallError(_ERROR)
        completed = object.__getattribute__(self, "_completed_request_hash")
        request_hash = hashlib.sha256(request.canonical_bytes()).hexdigest()
        if completed is None:
            # The operation either never started or already performed its
            # own internal start-failure rollback.
            return None
        if completed != request_hash:
            raise AnalyticsFirstInstallError(_ERROR)
        if not self._stop_first_slot():
            raise AnalyticsFirstInstallError(_ERROR)
        object.__setattr__(self, "_completed_request_hash", None)
        return None


__all__ = ("AnalyticsFirstInstallError", "AnalyticsFirstInstallOperation")
