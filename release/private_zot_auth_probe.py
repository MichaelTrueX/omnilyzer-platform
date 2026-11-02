#!/usr/bin/env python3
"""File: release/private_zot_auth_probe.py

Purpose: Read-only, single-shot GitHub-OIDC-to-private-Zot Docker manifest
authentication diagnostic for Task 014. Used ONLY by the explicit
diagnostic-only job in .github/workflows/platform-promote.yml.
Links: deployment/identity.py (the exact DEV GitHub identity contract),
release/request_oidc.py (the pre-existing read-only issuance precedent),
deployment/private_registry_pull.py (Docker's OIDC Basic-to-Bearer exchange),
and release/tests/test_private_zot_auth_probe.py.

Sections: static authority policy; GitHub JWT acquisition; claims/expiry
preflight; isolated Docker credential config; daemonless manifest lookup.
No deployment, Docker pull, traffic changes, broker POST, replay operations,
GitHub changes, or PROD credentials. Neither JWT nor Docker output is logged.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from typing import Mapping
from urllib import parse, request


# Section 1: strictly fixed, reviewed read-only target and GitHub workload.
REPOSITORY = "MichaelTrueX/omnilyzer-platform"
WORKFLOW_REF = (
    REPOSITORY + "/.github/workflows/platform-promote.yml@refs/heads/main"
)
ENVIRONMENT = "task014-dev"
AUDIENCE = "https://oci-dev.omnilyzer.ai"
FORGEJO_AUDIENCE = "u:3:d4f50b90-f001-4b9f-ad1e-487080ec44fb"
OCI_HOST = "oci-dev.omnilyzer.ai"
CANARY_IMAGE = (
    OCI_HOST + "/omnilyzer/task013-release-canary@sha256:"
    + "2f9db44a1cb475bec5a82ad7f81508e2b6ecd327f32b358ec1f1deca95e5385e"
)
DOCKER_CLI = "/usr/bin/docker"
MAX_OIDC_RESPONSE = 16384
MAX_DOCKER_STDOUT = 128 * 1024
_JWT_SEGMENT = re.compile(r"[A-Za-z0-9_-]+\Z")
_SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")


class ProbeUnavailableError(Exception):
    """Redacted authority/registry failure, with no token or response detail."""


class NoRedirect(request.HTTPRedirectHandler):
    """Reject any GitHub OIDC endpoint redirect."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        """Fail closed; OIDC JWT must not follow a redirect."""
        raise ProbeUnavailableError("private Zot diagnostic unavailable")


# Section 2: bounded OIDC URL and response decoding, no claim logging.
def _read_json_unique(raw: bytes) -> dict[str, object]:
    """Decode a JSON object once, rejecting duplicate keys and invalid size."""
    if not 1 <= len(raw) <= MAX_OIDC_RESPONSE:
        raise ProbeUnavailableError("private Zot diagnostic unavailable")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Reject JSON ambiguity rather than accepting last-value-wins."""
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if type(value) is not dict:
        raise ValueError("invalid JSON object")
    return value


def _oidc_token(environment: Mapping[str, str], *, audience: str = AUDIENCE) -> str:
    """Issue one exact-audience JWT using the protected GitHub Actions endpoint."""
    if audience not in (AUDIENCE, FORGEJO_AUDIENCE):
        raise ProbeUnavailableError("private Zot diagnostic unavailable")
    raw_url = environment.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    runner_token = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    url = parse.urlsplit(raw_url)
    host = (url.hostname or "").lower()
    if (
        url.scheme != "https" or not host.endswith(".actions.githubusercontent.com")
        or url.username is not None or url.password is not None
        or url.port not in (None, 443) or bool(url.fragment)
        or not runner_token or len(runner_token) > 8192
        or any(key == "audience" for key, _ in parse.parse_qsl(
            url.query, keep_blank_values=True
        ))
    ):
        raise ProbeUnavailableError("private Zot diagnostic unavailable")
    target = raw_url + ("&" if url.query else "?") + parse.urlencode(
        {"audience": audience}
    )
    http = request.Request(
        target, headers={"Authorization": "Bearer " + runner_token}
    )
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect)
    with opener.open(http, timeout=20) as reply:
        if reply.status != 200:
            raise ProbeUnavailableError("private Zot diagnostic unavailable")
        payload = reply.read(MAX_OIDC_RESPONSE + 1)
    value = _read_json_unique(payload)
    if set(value) != {"value"}:
        raise ProbeUnavailableError("private Zot diagnostic unavailable")
    token = value["value"]
    if type(token) is not str or len(token) > 8192:
        raise ProbeUnavailableError("private Zot diagnostic unavailable")
    parts = token.split(".")
    if len(parts) != 3 or any(_JWT_SEGMENT.fullmatch(part) is None for part in parts):
        raise ProbeUnavailableError("private Zot diagnostic unavailable")
    return token


# Section 3: exact GitHub workflow/environment and short-lived decoded claims.
def _workflow_context_preflight(environment: Mapping[str, str]) -> str:
    """Reject unapproved workflow contexts before requesting a GitHub token."""
    sha = environment.get("GITHUB_SHA", "")
    if (
        environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_WORKFLOW_REF") != WORKFLOW_REF
        or environment.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or _SOURCE_SHA.fullmatch(sha) is None
    ):
        raise ProbeUnavailableError("private Zot diagnostic unavailable")
    return sha


def _claims_preflight(token: str, environment: Mapping[str, str], now: int,
                      *, audience: str = AUDIENCE) -> None:
    """Only request private registry reads for the approved DEV main workflow.

    Decoded claims are untrusted preflight metadata. Zot must independently
    authenticate the GitHub JWT signature before returning a registry Bearer.
    """
    if audience not in (AUDIENCE, FORGEJO_AUDIENCE):
        raise ProbeUnavailableError("private Zot diagnostic unavailable")
    sha = _workflow_context_preflight(environment)
    try:
        padded = token.split(".")[1]
        decoded = base64.urlsafe_b64decode(padded + "=" * (-len(padded) % 4))
        claims = _read_json_unique(decoded)
    except Exception:
        raise ProbeUnavailableError("private Zot diagnostic unavailable") from None
    expected = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": audience,
        "repository": REPOSITORY,
        "repository_id": "1350104356",
        "repository_owner_id": "130741173",
        "ref": "refs/heads/main",
        "workflow_ref": WORKFLOW_REF,
        "workflow_sha": sha,
        "event_name": "workflow_dispatch",
        "environment": ENVIRONMENT,
        "runner_environment": "github-hosted",
    }
    if any(
        type(claims.get(name)) is not str or claims[name] != value
        for name, value in expected.items()
    ):
        raise ProbeUnavailableError("private Zot diagnostic unavailable")
    iat, nbf, exp = (
        claims.get("iat"), claims.get("nbf"), claims.get("exp")
    )
    if (
        any(type(item) is not int for item in (iat, nbf, exp))
        or not 45 <= exp - now <= 300
        or not 0 < exp - iat <= 300
        or iat > now + 30 or iat < now - 60
        or nbf > now + 30
    ):
        raise ProbeUnavailableError("private Zot diagnostic unavailable")


# Section 4: disposable 0600 Docker auth config, exact digest, no daemon.
def _docker_manifest_probe(token: str) -> None:
    """Perform one bounded authenticated, read-only Docker manifest inspection."""
    with tempfile.TemporaryDirectory(prefix="task014-zot-oidc-probe-") as location:
        directory = Path(location)
        directory.chmod(0o700)
        value = base64.b64encode(("oidc:" + token).encode("ascii")).decode("ascii")
        config = (
            json.dumps({"auths": {OCI_HOST: {"auth": value}}},
                       sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        descriptor = os.open(
            directory / "config.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(config)
        finally:
            os.close(descriptor)
        result = subprocess.run(
            [DOCKER_CLI, "--config", str(directory), "manifest",
             "inspect", CANARY_IMAGE],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=35, check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "HOME": str(directory)},
        )
        if result.returncode != 0 or len(result.stdout) > MAX_DOCKER_STDOUT:
            raise ProbeUnavailableError("private Zot diagnostic unavailable")
        parsed = _read_json_unique(result.stdout[:MAX_OIDC_RESPONSE]) if (
            len(result.stdout) <= MAX_OIDC_RESPONSE
        ) else json.loads(result.stdout)
        if (
            type(parsed) is not dict or parsed.get("schemaVersion") != 2
            or parsed.get("mediaType") not in (
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
            )
        ):
            raise ProbeUnavailableError("private Zot diagnostic unavailable")


# Section 5: a single redacted, fail-closed CLI result.
def main() -> int:
    """Print no JWT, token endpoint response, credentials or raw Docker output."""
    try:
        product = os.environ.get("DIAGNOSTIC_PRODUCT_ID", "canary")
        if product not in ("canary", "analytics"):
            raise ProbeUnavailableError("private Zot diagnostic unavailable")
        _workflow_context_preflight(os.environ)
        token = _oidc_token(os.environ)
        _claims_preflight(token, os.environ, int(time.time()))
        if product == "analytics":
            from .analytics_task014_readonly_probe import run
            return run(os.environ, token)
        _docker_manifest_probe(token)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        print("TASK014_PRIVATE_ZOT_AUTH_PROBE_HOLD")
        return 2
    print("TASK014_PRIVATE_ZOT_AUTH_PROBE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
