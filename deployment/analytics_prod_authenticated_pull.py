#!/usr/bin/env python3
"""File: deployment/analytics_prod_authenticated_pull.py

Purpose: Admit ONLY the original signed Analytics 0.16.0 image to the existing
         PROD UID990 rootless Docker daemon with an ephemeral, registry-approved
         GitHub Actions OIDC credential. No container, DB or ingress actions.
Related: deployment/private_registry_pull.py (original Task014 volatile config),
         deployment/runtime/prod/analytics.compose.private.yaml,
         deployment/analytics_prod_db_install.py,
         docs/operations/dev-prod-direct-delivery.md.

Sections:
  1. Immutable original image, signature bundle and rootless identity.
  2. Read-only source, file custody and Sigstore verification.
  3. Short-lived OIDC credential validation and volatile Docker config.
  4. One bounded authenticated manifest read, Docker pull and digest postcheck.
  5. Explicit --preflight and --pull-only command boundaries.

The registry and cryptographic signature remain independent required checks.
The short-lived token is read only from stdin. Never log, persist or put it
on argv/env. --pull-only does NOT create or start a container. The sender
must be the existing authorized Task014 GitHub OIDC release boundary.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

HOST = "truexmainserver"
USER = "omnilyzer-analytics"
UID = 990
GID = 982
IMAGE_DIGEST = "sha256:a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1"
IMAGE = "oci-dev.omnilyzer.ai/omnilyzer/analytics@" + IMAGE_DIGEST
CONFIG_DIGEST = "sha256:8ddf7273804b8c9a5a964fb85b573de25f66915dd5ef33465522742f5a5df76e"
ZOT = "oci-dev.omnilyzer.ai"
AUDIENCE = "https://oci-dev.omnilyzer.ai"
ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOW = "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-promote.yml@refs/heads/main"
COSIGN = Path("/usr/local/libexec/omnilyzer-cosign-v3.1.3")
COSIGN_SHA = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
BUNDLE = Path("/var/lib/omnilyzer/analytics/prod/analytics016.sigstore.json")
BUNDLE_SHA = "497d022244af510e3763290b19c0a2d6a37984eb083eadbe6f523992aaad1593"
DOCKER = "/usr/bin/docker"
DOCKER_SOCKET = Path("/run/user/990/docker.sock")
RUNTIME = Path("/run/user/990")
SIGNER = "https://github.com/MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C.UTF-8"}
MAX_TOKEN = 8192
MIN_TOKEN_SECONDS = 230
PULL_TIMEOUT_SECONDS = 240


class PullHold(RuntimeError):
    """Fixed nonsecret failure for source, signature, auth or Docker drift."""


def owned_file(path: Path, *, uid: int, gid: int, mode: int, limit: int) -> bytes:
    """Read a single owned inode without following a symlink or exceeding limit."""
    try:
        before = os.lstat(path)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_uid, before.st_gid) != (uid, gid)
                or stat.S_IMODE(before.st_mode) != mode or before.st_size > limit):
            raise PullHold("trusted input metadata differs")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino, after.st_size) != (
                    before.st_dev, before.st_ino, before.st_size):
                raise PullHold("trusted input changed during read")
            with os.fdopen(fd, "rb", closefd=False) as f:
                data = f.read(limit + 1)
            if len(data) != before.st_size:
                raise PullHold("trusted input length differs")
            return data
        finally:
            os.close(fd)
    except OSError:
        raise PullHold("trusted input unavailable") from None


def check_identity() -> None:
    """Require exact PROD service identity and pre-existing isolated socket."""
    if (socket.gethostname().split(".")[0] != HOST
            or (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
            != (UID, UID, GID, GID)):
        raise PullHold("dedicated PROD rootless identity required")
    try:
        principal = pwd.getpwnam(USER)
        runtime = os.lstat(RUNTIME)
        sock = os.lstat(DOCKER_SOCKET)
        if (principal.pw_uid, principal.pw_gid) != (UID, GID):
            raise PullHold("rootless UID/GID changed")
        if (not stat.S_ISDIR(runtime.st_mode)
                or runtime.st_uid != UID or stat.S_IMODE(runtime.st_mode) != 0o700):
            raise PullHold("private rootless runtime differs")
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != UID:
            raise PullHold("private Docker socket differs")
    except (OSError, KeyError):
        raise PullHold("private Docker socket unavailable") from None


def signature_preflight() -> None:
    """Verify exact original Sigstore bundle with pinned Cosign, never trusting a claim alone."""
    data = owned_file(BUNDLE, uid=0, gid=GID, mode=0o440, limit=100000)
    if hashlib.sha256(data).hexdigest() != BUNDLE_SHA:
        raise PullHold("original signed release bundle changed")
    executable = owned_file(COSIGN, uid=0, gid=0, mode=0o555, limit=160_000_000)
    if hashlib.sha256(executable).hexdigest() != COSIGN_SHA:
        raise PullHold("original verification binary changed")
    command = (
        str(COSIGN), "verify-blob-attestation",
        "--bundle", str(BUNDLE),
        "--certificate-identity", SIGNER,
        "--certificate-oidc-issuer", ISSUER,
        "--type", "https://sigstore.dev/cosign/sign/v1",
        "--digest", IMAGE_DIGEST.removeprefix("sha256:"),
        "--digestAlg", "sha256",
    )
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, env=ENV,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=40, check=False)
    except (OSError, subprocess.SubprocessError):
        raise PullHold("Sigstore verifier unavailable") from None
    if result.returncode != 0 or b"Verified OK" not in result.stdout:
        raise PullHold("original release signature not verified")


def preflight() -> None:
    """Qualify exact runtime+signature without token, Docker pull or state changes."""
    check_identity()
    signature_preflight()
    print("ANALYTICS_PROD_SIGNED_REGISTRY_PULL_READONLY_PASS no_changes=true", flush=True)


def read_oidc_stdin() -> str:
    """Accept only one fresh Task014 workflow JWT, never a static registry password.

    JWT payload is an UNTRUSTED prefilter only; the Zot registry independently
    verifies cryptographic signature and authorizes the repository pull.
    """
    token = sys.stdin.buffer.read(MAX_TOKEN + 1)
    if len(token) > MAX_TOKEN or not token or token.count(b".") != 2:
        raise PullHold("scoped GitHub OIDC credential unavailable")
    if not re.fullmatch(rb"[A-Za-z0-9_\-.]+", token):
        raise PullHold("scoped GitHub OIDC credential malformed")
    try:
        raw = token.split(b".")[1]
        payload = base64.urlsafe_b64decode(raw + b"=" * ((-len(raw)) % 4))
        claims = json.loads(payload)
        if not isinstance(claims, dict):
            raise ValueError
        exp = claims.get("exp")
        aud = claims.get("aud")
        if (type(exp) is not int or exp - int(time.time()) < MIN_TOKEN_SECONDS
                or claims.get("iss") != ISSUER
                or claims.get("repository") != "MichaelTrueX/omnilyzer-platform"
                or claims.get("workflow_ref") != WORKFLOW
                or (aud != AUDIENCE and aud != [AUDIENCE])):
            raise ValueError
        return token.decode("ascii")
    except (UnicodeError, ValueError, TypeError, OverflowError):
        raise PullHold("scoped GitHub OIDC credential not admitted") from None


def docker(argv: tuple[str, ...], *, timeout: int, workspace: Path) -> bytes:
    """Run fixed rootless Docker command, scrub stdout/stderr on errors."""
    cmd = (DOCKER, "--config", str(workspace), "--host",
           "unix:///run/user/990/docker.sock", *argv)
    try:
        result = subprocess.run(cmd, env={**ENV, "HOME": str(workspace)},
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        raise PullHold("rootless Docker action unavailable") from None
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise PullHold("authenticated rootless Docker action rejected")
    return result.stdout


def write_volatile_auth(directory: Path, token: str) -> None:
    """Use existing Task014 oidc:JWT Docker auth exchange, private 0600 tmpfs only."""
    auth = base64.b64encode(("oidc:" + token).encode("ascii")).decode("ascii")
    data = json.dumps({"auths": {ZOT: {"auth": auth}}}, separators=(",", ":")).encode()
    fd = os.open(directory / "config.json",
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def pull_only() -> None:
    """Perform one authenticated original OCI pull; do not start anything."""
    preflight()
    token = read_oidc_stdin()
    # Recheck the signature before authorizing a network transfer.
    with tempfile.TemporaryDirectory(prefix=".m05-prod-zot-", dir=RUNTIME) as tmp:
        workspace = Path(tmp)
        os.chmod(workspace, 0o700)
        write_volatile_auth(workspace, token)
        token = ""  # Do not retain an extra token reference after writing.
        docker(("manifest", "inspect", IMAGE), timeout=35, workspace=workspace)
        docker(("pull", "--quiet", IMAGE), timeout=PULL_TIMEOUT_SECONDS, workspace=workspace)
        evidence = docker(("image", "inspect", "--format",
                           "{{json .RepoDigests}}|{{.Id}}", IMAGE),
                          timeout=20, workspace=workspace)
    fields = evidence.strip().decode("utf-8", "strict").split("|")
    if len(fields) != 2 or fields[1] != CONFIG_DIGEST:
        raise PullHold("postpull signed config digest differs")
    try:
        digests = json.loads(fields[0])
    except (ValueError, TypeError):
        raise PullHold("postpull immutable digest unavailable") from None
    if type(digests) is not list or IMAGE not in digests:
        raise PullHold("postpull OCI reference differs")
    print("ANALYTICS_PROD_SIGNED_IMAGE_AUTHENTICATED_PULL_PASS container=not_started public_routes=unchanged",
          flush=True)


def main() -> int:
    """Expose only a read-only preflight and one bounded, token-bound image pull."""
    parser = argparse.ArgumentParser(description="Original signed Analytics PROD OCI admission")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preflight", action="store_true")
    modes.add_argument("--pull-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.preflight:
            preflight()
        else:
            pull_only()
        return 0
    except (PullHold, OSError, UnicodeError) as exc:
        print(f"ANALYTICS_PROD_SIGNED_REGISTRY_PULL_HOLD {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
