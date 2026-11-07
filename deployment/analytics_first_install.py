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
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
import time

from .analytics_execution import (
    AnalyticsExecutorRequest, AnalyticsSuccessorRequest,
)
from .analytics_private_registry import (
    AnalyticsPrivateZotPullAdapter, ANALYTICS_PULL_TIMEOUT_SECONDS,
)
from .analytics_signed_release_consumer import PINNED_IMAGE, PINNED_DIGEST
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


# Section: first-successor-only, still UNWIRED candidate container staging.
# Reuse the original Task014 rootless Docker runner, sealed Zot image pull,
# UID-mapped secret checks, and closed two-profile Compose sources. The
# protected V2 root manifest now attests the exact port-reset overlay YAML.
_SUCCESSOR_COMPOSE_OVERLAY = (
    COMPOSE_FILE.parent / "analytics.compose.successor-ports.yaml"
)
# Independently check both healthy endpoints inside the candidate without
# Docker host publishing or importing browser/session/user tokens.
_SUCCESSOR_LIVE_SCRIPT = _READY_SCRIPT.replace("/readyz", "/livez")
_SUCCESSOR_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "ANALYTICS_BLUE_IMAGE": PINNED_IMAGE,
}


class AnalyticsSuccessorCandidateOperation:
    """Stage only a signed first successor green image, not public activation.

    The future schema-3 executor MUST first authenticate broker OIDC, signed
    Task013 evidence, the owner-held signature and durable SQLite replay.
    A caller-constructible schema-3 dataclass is never a release grant.
    The installed V1 broker/executor do not call this class.
    """

    __slots__ = (
        "_run", "_pull", "_source", "_completed_hash", "_completed_id",
        "_deadline", "_clock",
    )

    def __init__(
        self, *, runner: object,
        private_registry: AnalyticsPrivateZotPullAdapter,
        reviewed_installed_source: dict[str, str],
    ) -> None:
        """Bind precisely the existing Task014 runner and same source scope."""
        from .analytics_unix_boundary import _root_reviewed_source
        try:
            if type(private_registry) is not AnalyticsPrivateZotPullAdapter:
                raise TypeError
            source = _root_reviewed_source(reviewed_installed_source)
            if object.__getattribute__(private_registry, "_source") != source:
                raise TypeError
            object.__setattr__(self, "_run", _candidate_command_run(runner))
            object.__setattr__(
                self, "_pull", private_registry.pull_analytics_successor,
            )
            object.__setattr__(self, "_source", source)
            object.__setattr__(self, "_completed_hash", None)
            object.__setattr__(self, "_completed_id", None)
            object.__setattr__(self, "_deadline", None)
            object.__setattr__(self, "_clock", time.monotonic)
        except _CONTROL:
            raise
        except Exception:
            raise TypeError(_ERROR) from None

    def __setattr__(self, _name: str, _value: object) -> None:
        """Prevent a runtime caller from substituting source or Docker runner."""
        raise AttributeError("Analytics candidate operation is immutable")

    def __delattr__(self, _name: str) -> None:
        """Prevent deletion of captured protected collaborators."""
        raise AttributeError("Analytics candidate operation is immutable")

    def _docker(
        self, image: str, *parts: str, timeout: float = _RUN_TIMEOUT,
    ) -> CommandResult:
        """Execute the existing fixed rootless Docker CLI with no token in env."""
        from .docker_runtime import _docker as docker_cli
        _require_rootless_socket()
        if (
            type(image) is not str
            or not image.startswith("oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:")
            or type(timeout) is not float
            or not math.isfinite(timeout) or not 0 < timeout <= 45.0
        ):
            raise AnalyticsFirstInstallError(_ERROR)
        deadline = object.__getattribute__(self, "_deadline")
        if deadline is not None:
            # One coherent bound for preflight, 500s pull, candidate start
            # and health, well inside the original 720s Unix reply limit.
            # Emergency stop has a separate original 45s reserve.
            timeout = min(timeout, deadline.remaining())
        result = object.__getattribute__(self, "_run")(
            docker_cli(*parts), cwd=WORKING_DIRECTORY,
            environment={**_SUCCESSOR_ENV, "ANALYTICS_GREEN_IMAGE": image},
            timeout=timeout,
        )
        if (
            type(result) is not CommandResult
            or type(result.returncode) is not int or result.returncode != 0
            or type(result.stdout) is not str
            or len(result.stdout.encode("utf-8")) > _MAX_OUTPUT
        ):
            raise AnalyticsFirstInstallError(_ERROR)
        if deadline is not None:
            deadline.remaining()
        return result

    def _compose(self, image: str, *parts: str) -> CommandResult:
        """Use only two independently root-attested Compose files and green."""
        args = (
            "compose", "--project-name", _PROJECT,
            "--file", str(COMPOSE_FILE),
            "--file", str(_SUCCESSOR_COMPOSE_OVERLAY),
            "--profile", "green", *parts,
        )
        return self._docker(image, *args)

    def _stop_green_if_owned(self, image: str) -> bool:
        """Stop only a newly created exact-digest green, not other services.

        Never remove networks, volumes, database data, image or blue writer.
        If identity cannot be established, retain the existing container
        and return False to require explicit recovery.
        """
        try:
            candidate = self._compose(
                image, "ps", "--all", "-q", "analytics-green",
            ).stdout.strip()
            if not candidate:
                return True
            if _CONTAINER_ID.fullmatch(candidate) is None:
                return False
            actual = _strict_json(self._docker(
                image, "container", "inspect", "--format",
                "{{json .Config.Image}}", candidate,
            ).stdout.strip())
            if actual != image:
                return False
            self._compose(
                image, "stop", "--timeout", "15", "analytics-green",
            )
            running = self._compose(
                image, "ps", "--status", "running", "--format",
                "json", "analytics-green",
            ).stdout.strip()
            return running in ("", "[]")
        except _CONTROL:
            raise
        except Exception:
            return False

    def stage_first_successor_green(
        self, request: AnalyticsSuccessorRequest,
    ) -> str:
        """Start only a locally healthy green container, never route traffic.

        Requires an independently root-approved V2 source generation and
        exact UID991, genuine owner signature, sealed scoped successor FD,
        signed previous blue runtime, actual empty green, immutable local
        RepoDigest, rootless UID-mapped secrets, exact hardened Compose,
        and private in-container health. No root/user data is modified.
        A result is a container ID, NOT a deployment receipt or 3141 switch.
        """
        candidate_may_exist = False
        object.__setattr__(
            self, "_deadline",
            _Deadline(
                object.__getattribute__(self, "_clock"),
                int(ANALYTICS_OPERATION_TIMEOUT_SECONDS * 1000),
            ),
        )
        try:
            from .analytics_executor import _verify_executor_owner_source
            from .analytics_executor_service_config import (
                load_analytics_executor_service_config,
                _SUCCESSOR_INSTALLED_ROOT,
            )
            from .analytics_active_state_review import (
                AnalyticsActiveState, inspect_analytics_active_state,
                verify_empty_analytics_successor_slot,
            )
            from .private_registry_fd import _successor_request_image
            if (
                type(request) is not AnalyticsSuccessorRequest
                or (
                    os.getuid(), os.geteuid(),
                    os.getgid(), os.getegid()
                ) != (991, 991, 991, 991)
                or request.ingress_reference.get("slot") != "green"
                or request.ingress_reference.get("active_slot") != "blue"
                or request.ingress_reference.get("loopback_port") != 3142
                or request.rollback_reference.get("previous_digest")
                    != PINNED_DIGEST
                or request.rollback_reference.get("previous_slot") != "blue"
                or request.rollback_reference.get("preserve_database_writes")
                    is not True
                or request.secrets_reference.get("required")
                    != list(REQUIRED_SECRET_NAMES)
            ):
                raise ValueError("wrong source, principal or rollout stage")
            raw = request.canonical_bytes()
            image = _successor_request_image(raw)
            if image != request.exact_image_reference or image == PINNED_IMAGE:
                raise ValueError("mutable or original release image")
            _verify_executor_owner_source(request.to_dict())
            source, identity = load_analytics_executor_service_config(
                require_successor=True,
            )
            if (
                type(source) is not dict
                or source != dict(object.__getattribute__(self, "_source"))
                or type(identity) is not dict
                or identity.get("expected_executor_uid") != 991
                or identity.get("expected_executor_gid") != 991
                # The Docker CLI MUST consume those exact installed files
                # whose bytes the root-owned V2 verifier just checked.
                # Otherwise a test/dev worktree YAML could be substituted
                # while the protected installed hashes remained correct.
                or COMPOSE_FILE != (
                    _SUCCESSOR_INSTALLED_ROOT
                    / "deployment/runtime/dev/analytics.compose.review.yaml"
                )
                or _SUCCESSOR_COMPOSE_OVERLAY != (
                    _SUCCESSOR_INSTALLED_ROOT
                    / "deployment/runtime/dev/analytics.compose.successor-ports.yaml"
                )
                or COMPOSE_FILE.is_symlink()
                or _SUCCESSOR_COMPOSE_OVERLAY.is_symlink()
                or not COMPOSE_FILE.is_file()
                or not _SUCCESSOR_COMPOSE_OVERLAY.is_file()
                or hashlib.sha256(COMPOSE_FILE.read_bytes()).hexdigest()
                    != source["reviewed_compose_sha256"]
            ):
                raise ValueError("unreviewed source generation")
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
                raise ValueError("UID-mapped secret files unavailable")
            _require_mapped_secret_groups(mapped_gid)
            previous = inspect_analytics_active_state()
            if (
                type(previous) is not AnalyticsActiveState
                or previous.active_slot != "blue"
                or previous.active_image != PINNED_IMAGE
                or previous.active_digest != PINNED_DIGEST
                or previous.candidate_slot != "green"
                or previous.candidate_probe_present is not False
                or previous.candidate_container_id is not None
                or previous.candidate_digest is not None
                or previous.read_only is not True
                or previous.deployment_authorized is not False
            ):
                raise ValueError("previous signed 0.15.0 unavailable")
            verify_empty_analytics_successor_slot()
            # The existing named bridge is not sufficient. The next
            # runtime must use the same immutable internal network ID as
            # the signed active 0.15.0, never an externally reachable bridge.
            network_name = self._docker(
                image, "network", "inspect", "--format",
                "{{json .Name}}", _NETWORK,
            )
            network_id = self._docker(
                image, "network", "inspect", "--format",
                "{{json .Id}}", _NETWORK,
            )
            network_internal = self._docker(
                image, "network", "inspect", "--format",
                "{{json .Internal}}", _NETWORK,
            )
            if (
                _strict_json(network_name.stdout.strip()) != _NETWORK
                or _strict_json(network_id.stdout.strip())
                    != previous.active_network_id
                or _strict_json(network_internal.stdout.strip()) is not True
            ):
                raise ValueError("wrong existing private network")
            if self._compose(image, "config", "--quiet").stdout != "":
                raise ValueError("invalid protected two-file Compose")
            present = self._compose(
                image, "ps", "--all", "--format",
                "json", "analytics-green",
            ).stdout.strip()
            if present not in ("", "[]"):
                raise ValueError("previous green instance exists")
            # This pull is scoped to the broker's genuine sealed capability;
            # only its future durable replay-admitted executor may call us.
            object.__getattribute__(self, "_pull")(
                request,
                timeout=min(
                    ANALYTICS_PULL_TIMEOUT_SECONDS,
                    object.__getattribute__(self, "_deadline").remaining(),
                ),
            )
            if (
                inspect_analytics_active_state() != previous
            ):
                raise ValueError("active image/route moved during pull")
            verify_empty_analytics_successor_slot()
            digest = _strict_json(self._docker(
                image, "image", "inspect", "--format",
                "{{json .RepoDigests}}", image,
            ).stdout.strip())
            if digest != [image]:
                raise ValueError("pulled OCI RepoDigest mismatch")
            # From this instant a failed Docker command MAY have created
            # green. Cleanup is limited to the exact image and green service.
            candidate_may_exist = True
            self._compose(
                image, "up", "--detach", "--no-deps", "--no-recreate",
                "--no-build", "--pull", "never", "analytics-green",
            )
            identifier = self._compose(
                image, "ps", "-q", "analytics-green",
            ).stdout.strip()
            if _CONTAINER_ID.fullmatch(identifier) is None:
                raise ValueError("unconfirmed candidate container")
            checks = (
                ("{{json .Config.Image}}", image),
                ("{{json .Config.User}}", "10001:10001"),
                ("{{json .HostConfig.ReadonlyRootfs}}", True),
                ("{{json .HostConfig.Privileged}}", False),
                ("{{json .HostConfig.CapDrop}}", ["ALL"]),
                ("{{json .HostConfig.SecurityOpt}}", ["no-new-privileges:true"]),
                ("{{json .HostConfig.PortBindings}}", {}),
            )
            for template, wanted in checks:
                actual = _strict_json(self._docker(
                    image, "container", "inspect", "--format",
                    template, identifier,
                ).stdout.strip())
                if actual != wanted:
                    raise ValueError("candidate runtime hardening weakened")
            networks = _strict_json(self._docker(
                image, "container", "inspect", "--format",
                "{{json .NetworkSettings.Networks}}", identifier,
            ).stdout.strip())
            if type(networks) is not dict or set(networks) != {_NETWORK}:
                raise ValueError("candidate has unreviewed network")
            connected = networks[_NETWORK]
            if (
                type(connected) is not dict
                or connected.get("NetworkID") != previous.active_network_id
                or connected.get("Gateway") not in ("", None)
            ):
                raise ValueError("candidate network differs from previous writer")
            address = ipaddress.ip_address(connected.get("IPAddress"))
            if (
                type(address) is not ipaddress.IPv4Address
                or not address.is_private or address.is_loopback
                or address.is_link_local or address.is_reserved
                or address.is_multicast or address.is_unspecified
                or str(address) == previous.active_child_ip
            ):
                raise ValueError("candidate has nonprivate or shared address")
            healthy = False
            for _ in range(_HEALTH_PROBES):
                status = _strict_json(self._docker(
                    image, "container", "inspect", "--format",
                    "{{json .State.Health.Status}}", identifier,
                ).stdout.strip())
                if status == "healthy":
                    result = self._compose(
                        image, "exec", "--no-TTY", "analytics-green",
                        "node", "-e", _READY_SCRIPT,
                    )
                    if result.stdout != "READY\n":
                        raise ValueError("candidate readiness denied")
                    live = self._compose(
                        image, "exec", "--no-TTY", "analytics-green",
                        "node", "-e", _SUCCESSOR_LIVE_SCRIPT,
                    )
                    if live.stdout != "READY\n":
                        raise ValueError("candidate liveness denied")
                    healthy = True
                    break
                if status != "starting":
                    raise ValueError("unhealthy signed candidate")
                time.sleep(min(
                    _INTERVAL_SECONDS,
                    object.__getattribute__(self, "_deadline").remaining(),
                ))
            if not healthy or inspect_analytics_active_state() != previous:
                raise ValueError("active writer changed during startup")
            # Candidate is running but NOT exposed on 3142 or switched on 3141.
            object.__getattribute__(self, "_deadline").remaining()
            object.__setattr__(
                self, "_completed_hash", hashlib.sha256(raw).hexdigest(),
            )
            object.__setattr__(self, "_completed_id", identifier)
            object.__setattr__(self, "_deadline", None)
            return identifier
        except _CONTROL:
            # Preserve an independent 45s stop reserve when the original
            # full operation has exhausted its own 570s budget.
            object.__setattr__(self, "_deadline", None)
            if candidate_may_exist:
                self._stop_green_if_owned(request.exact_image_reference)
            raise
        except Exception:
            object.__setattr__(self, "_deadline", None)
            if candidate_may_exist:
                safe = self._stop_green_if_owned(request.exact_image_reference)
                sys.stderr.write(
                    "TASK014_ANALYTICS_SUCCESSOR_CANDIDATE_HOLD "
                    + ("rollback=stopped" if safe else "rollback=unconfirmed")
                    + "\n"
                )
            raise AnalyticsFirstInstallError(_ERROR) from None

    def rollback_staged_successor(
        self, request: AnalyticsSuccessorRequest, identifier: str,
    ) -> None:
        """Stop only this exact green after a later replay/finalization error."""
        if (
            type(request) is not AnalyticsSuccessorRequest
            or type(identifier) is not str
            or _CONTAINER_ID.fullmatch(identifier) is None
            or hashlib.sha256(request.canonical_bytes()).hexdigest()
                != object.__getattribute__(self, "_completed_hash")
            or identifier != object.__getattribute__(self, "_completed_id")
            or not self._stop_green_if_owned(request.exact_image_reference)
        ):
            raise AnalyticsFirstInstallError(_ERROR)
        object.__setattr__(self, "_completed_hash", None)
        object.__setattr__(self, "_completed_id", None)
        return None


__all__ = (
    "AnalyticsFirstInstallError", "AnalyticsFirstInstallOperation",
    "AnalyticsSuccessorCandidateOperation",
)
