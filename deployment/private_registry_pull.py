"""File: deployment/private_registry_pull.py

Purpose: Give one already-verified, sealed Zot read credential to an exact
DEV Docker manifest inspection or image pull, without a persistent login.
Related: deployment/private_registry_fd.py, deployment/docker_runtime.py,
deployment/execution.py, deployment/tests/test_private_registry_pull.py.

Sections: private runtime-directory checks, exact Docker command construction,
volatile auth-config creation, bounded command execution and cleanup.

This is an inert adapter until the reviewed broker/executor connection is
wired to invoke it. It does not alter Docker, registry permissions or state
during import or construction.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import stat
import tempfile
import time

from .docker_runtime import (
    COMMAND_TIMEOUT_SECONDS, DOCKER_CLI, DOCKER_HOST,
    WORKING_DIRECTORY, CommandResult, CommandRunner,
    validate_canary_image, _require_rootless_socket,
)
from .execution import ExecutorRequest, parse_canonical_request
from .private_registry_fd import read_sealed_credential

# Section 1: closed host path, invocation modes and limited lifetime.
VOLATILE_DOCKER_DIRECTORY = Path("/run/omnilyzer/deployment/rootless-docker")
ZOT_HOST = "oci-dev.omnilyzer.ai"
PROBE = "manifest"
PULL = "pull"
COMMANDS = frozenset((PROBE, PULL))
# The Docker CLI can run for 30 seconds; a larger threshold avoids starting
# a command with a credential likely to expire during that bounded call.
MIN_VALIDITY_SECONDS = 45
# Thread/task-local nonsecret binding; JWT bytes remain only in the sealed fd.
_PRIVATE_REQUEST: ContextVar[tuple[int, bytes] | None] = ContextVar(
    "omnilyzer_private_zot_request", default=None,
)


@contextmanager
def scoped_private_zot_request(credential_fd: int, canonical_request: bytes):
    """Bind a verified descriptor to this single executor request and reset."""
    if type(credential_fd) is not int or credential_fd < 0 \
            or type(canonical_request) is not bytes or not canonical_request:
        raise PrivateRegistryPullError("private Zot pull is unavailable")
    token = _PRIVATE_REQUEST.set((credential_fd, canonical_request))
    try:
        yield
    finally:
        _PRIVATE_REQUEST.reset(token)


def current_private_zot_request() -> tuple[int, bytes] | None:
    """Return only this task's descriptor binding, never a token string."""
    return _PRIVATE_REQUEST.get()


class PrivateRegistryPullError(Exception):
    """Uniform nonsecret failure: details and JWT must never reach logs."""


def _private_runtime_directory() -> Path:
    """Require an executor-owned private directory on the ephemeral /run mount."""
    target = VOLATILE_DOCKER_DIRECTORY
    status = os.lstat(target)
    if (
        not stat.S_ISDIR(status.st_mode)
        or stat.S_IMODE(status.st_mode) != 0o700
        or (status.st_uid, status.st_gid) != (os.geteuid(), os.getegid())
        or os.getuid() != os.geteuid()
        or os.getgid() != os.getegid()
    ):
        raise PrivateRegistryPullError("private Zot pull is unavailable")
    return target


# Section 2: exact command construction without credentials on argv or env.
def _command(workspace: Path, image: str, operation: str) -> tuple[str, ...]:
    """Bind Docker to only the approved digest and ephemeral config path."""
    if operation == PROBE:
        suffix = ("manifest", "inspect", image)
    elif operation == PULL:
        suffix = ("pull", image)
    else:
        raise PrivateRegistryPullError("private Zot pull is unavailable")
    return (
        DOCKER_CLI, "--config", str(workspace), "--host", DOCKER_HOST, *suffix,
    )


def _write_config(workspace: Path, token: str) -> None:
    """Create a single exclusive, no-follow 0600 Zot registrytoken config."""
    raw = (
        json.dumps(
            {"auths": {ZOT_HOST: {"registrytoken": token}}},
            separators=(",", ":"), sort_keys=True, ensure_ascii=True,
        ) + "\n"
    ).encode("ascii")
    descriptor = os.open(
        workspace / "config.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


# Section 3: one time-bound operation with automatic cleanup on all paths.
def execute_private_zot_read(
    runner: CommandRunner, *, credential_fd: int, canonical_request: bytes,
    image: str, operation: str,
) -> None:
    """Perform an authenticated, exact, scoped Docker probe or image pull.

    The caller retains responsibility for closing credential_fd. This operation
    accepts no caller-selected registry host/repository, Docker command, config
    directory or command environment. The verifier must have authorized the
    broker-supplied credential before the FD reaches this method.
    """
    try:
        if operation not in COMMANDS or type(operation) is not str:
            raise ValueError("invalid operation")
        image = validate_canary_image(image)
        request = parse_canonical_request(canonical_request)
        if type(request) is not ExecutorRequest or request.exact_image_reference != image:
            raise ValueError("request/image mismatch")
        now = int(time.time())
        authority = read_sealed_credential(
            credential_fd, canonical_request=canonical_request,
            image=image, now=now,
        )
        if authority.expires_at - now < MIN_VALIDITY_SECONDS:
            raise ValueError("credential expires before bounded operation")
        directory = _private_runtime_directory()
        _require_rootless_socket()

        # The only registry credential exists briefly as a rootless-executor
        # owned file in tmpfs /run, with mode 0600 inside a 0700 directory.
        # Neither token nor config file bytes appear on argv or in env.
        with tempfile.TemporaryDirectory(
            prefix=".zot-read-", dir=str(directory)
        ) as temporary:
            workspace = Path(temporary)
            os.chmod(workspace, 0o700)
            _write_config(workspace, authority.token)
            argv = _command(workspace, image, operation)
            output = runner.run(
                argv, cwd=WORKING_DIRECTORY,
                environment={
                    "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                    "CANARY_IMAGE": image,
                },
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            if type(output) is not CommandResult or output.returncode != 0:
                raise ValueError("Docker operation returned failure")
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise PrivateRegistryPullError("private Zot pull is unavailable") from None


__all__ = (
    "PrivateRegistryPullError", "execute_private_zot_read",
    "scoped_private_zot_request", "current_private_zot_request",
)
