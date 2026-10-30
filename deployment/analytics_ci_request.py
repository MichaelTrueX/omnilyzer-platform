"""File: deployment/analytics_ci_request.py

Purpose: Select exactly the signed Analytics 0.15.0 Task014 schema-v2 DEV
         request from the EXISTING GitHub workflow_dispatch CI job.
Related: .github/workflows/platform-promote.yml (original canary default),
         deployment/analytics_execution.py (closed request parser),
         deployment/ci_oidc_diagnostics.py (unverified JWT diagnostics),
         deployment/analytics_signed_release_consumer.py (pinned release),
         deployment/tests/test_analytics_ci_request.py.

Sections: exact dispatch input preflight; unverified but bounded CI identity
          field projection; canonical Analytics request creation; inert CLI.

SECURITY: CI decoding of a JWT NEVER authenticates it or grants a deployment.
Only the existing protected Task014 broker independently verifies three OIDC
audiences, signed Zot/Forgejo/Cosign release, root-owned source and replay.
This module does not send a request, read secrets, install source or expose
a new route. The original canary request creator is unchanged.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sys
from typing import Mapping

from .analytics_execution import (
    ANALYTICS_COMPOSE_PATH, ANALYTICS_FIRST_PORT, ANALYTICS_NETWORK,
    ANALYTICS_REQUEST_SCHEMA, ANALYTICS_ROLLBACK_MODE,
    ANALYTICS_SECRETS_DIRECTORY, parse_analytics_request,
    AnalyticsRequestError,
)
from .analytics_signed_release_consumer import (
    PINNED_DIGEST, PINNED_IMAGE, PINNED_PLATFORM_COMMIT,
    PINNED_RUN_ID, PINNED_VERSION,
)
from .analytics_signed_source_pin import SOURCE_COMMIT
from .ci_oidc_diagnostics import _decode_untrusted
from .identity import (
    DEV_AUDIENCE, DEV_ENVIRONMENT, DEV_EVENT_NAME, DEV_REF,
    DEV_REPOSITORY, DEV_REPOSITORY_ID, DEV_RUNNER_ENVIRONMENT,
    DEV_WORKFLOW_REF, MAX_TOKEN_LIFETIME_SECONDS, validate_jti,
)
from .policy import APPROVED_OCI_ORIGIN, canonical_bytes
from .saas_product_contract import (
    REQUIRED_ANALYTICS_SECRET_NAMES, load_reviewed_profile,
)
from .saas_product_runtime import load_review_profile

_ROOT = Path(__file__).resolve().parents[1]
_PRODUCT = _ROOT / "deployment/products/analytics-dev.json"
_RUNTIME = _ROOT / "deployment/products/analytics-runtime-dev.json"
_COMPOSE = _ROOT / ANALYTICS_COMPOSE_PATH
_ERROR = "Task014 Analytics CI request rejected"
_MAX_BODY = 4096
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")
_SHA64 = re.compile(r"[a-f0-9]{64}\Z")
_NONZERO_DECIMAL = re.compile(r"[1-9][0-9]{0,18}\Z")
_REQUIRED_INPUTS = (
    "RELEASE_VERSION", "SOURCE_SHA", "MANIFEST_DIGEST",
    "RELEASE_MANIFEST_SHA256", "PROVENANCE_SHA256",
    "ORIGINATING_RELEASE_RUN_ID", "ANALYTICS_INSTALLED_COMMIT",
    "ANALYTICS_SOURCE_CLAIM_SHA256",
)
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsCIDispatchError(Exception):
    """A malformed Analytics-only manual DEV dispatch cannot proceed."""


def _decimal(value: object) -> int:
    """Require one positive, nonzero GitHub numeric identifier string."""
    if type(value) is not str or _NONZERO_DECIMAL.fullmatch(value) is None:
        raise ValueError
    n = int(value)
    if n > 2**63 - 1:
        raise ValueError
    return n


def _hash(value: object, length: int = 64) -> str:
    """Require one nonzero exact lowercase hex hash; no coercion."""
    if (
        type(value) is not str or len(value) != length
        or (length == 64 and _SHA64.fullmatch(value) is None)
        or (length == 40 and _SHA40.fullmatch(value) is None)
        or value == "0" * length
    ):
        raise ValueError
    return value


def validate_analytics_ci_inputs(environment: Mapping[str, str]) -> dict[str, str]:
    """Check only selected release/runner input shape, not signed authority.

    The workflow has no product-wide allowlist: the sole supported Analytics
    release version/source/digest/run is fixed in existing signed source code.
    Manually supplied hashes remain UNTRUSTED until the real broker compares
    them with the signed release and actual root-controlled config.
    """
    try:
        if not isinstance(environment, Mapping):
            raise ValueError
        data = {key: environment.get(key) for key in _REQUIRED_INPUTS}
        if (
            environment.get("TASK014_PRODUCT") != "analytics"
            or environment.get("TARGET_STAGE") != "dev"
            or environment.get("GITHUB_REPOSITORY") != DEV_REPOSITORY
            or environment.get("GITHUB_REF") != DEV_REF
            or environment.get("GITHUB_EVENT_NAME") != DEV_EVENT_NAME
            or data["RELEASE_VERSION"] != PINNED_VERSION
            or data["SOURCE_SHA"] != PINNED_PLATFORM_COMMIT
            or data["MANIFEST_DIGEST"] != PINNED_DIGEST
            or _decimal(data["ORIGINATING_RELEASE_RUN_ID"]) != PINNED_RUN_ID
        ):
            raise ValueError
        for key in (
            "RELEASE_MANIFEST_SHA256", "PROVENANCE_SHA256",
            "ANALYTICS_SOURCE_CLAIM_SHA256",
        ):
            _hash(data[key])
        _hash(data["ANALYTICS_INSTALLED_COMMIT"], 40)
        return data
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsCIDispatchError(_ERROR) from None


def build_analytics_ci_request(
    *, deployment_oidc_token: str, environment: Mapping[str, str],
) -> bytes:
    """Project CI claim fields to schema-v2 AFTER the original OIDC fetch.

    OIDC JWT payloads are intentionally UNVERIFIED here and only used to
    construct bytes. The original broker verifies signature, issuer, audience,
    workflow SHA, run/replay identity, registry credentials, Cosign and source.
    If even one runner or signed claim value disagrees, deny before HTTP POST.
    """
    try:
        selected = validate_analytics_ci_inputs(environment)
        identity = _decode_untrusted(deployment_oidc_token)
        if (
            identity.get("iss") != "https://token.actions.githubusercontent.com"
            or identity.get("aud") != DEV_AUDIENCE
            or identity.get("repository") != DEV_REPOSITORY
            or identity.get("repository_id") != str(DEV_REPOSITORY_ID)
            or identity.get("workflow_ref") != DEV_WORKFLOW_REF
            or identity.get("ref") != DEV_REF
            or identity.get("environment") != DEV_ENVIRONMENT
            or identity.get("event_name") != DEV_EVENT_NAME
            or identity.get("runner_environment") != DEV_RUNNER_ENVIRONMENT
            or identity.get("workflow_sha") != environment.get("GITHUB_SHA")
            or _hash(identity.get("workflow_sha"), 40) != identity["workflow_sha"]
        ):
            raise ValueError
        run = _decimal(identity.get("run_id"))
        attempt = _decimal(identity.get("run_attempt"))
        actor = _decimal(identity.get("actor_id"))
        if (
            run != _decimal(environment.get("GITHUB_RUN_ID"))
            or attempt != _decimal(environment.get("GITHUB_RUN_ATTEMPT"))
            or actor != _decimal(environment.get("GITHUB_ACTOR_ID"))
        ):
            raise ValueError
        iat = identity.get("iat")
        exp = identity.get("exp")
        if (
            type(iat) is not int or type(exp) is not int
            or iat < 0 or not 0 < exp - iat <= MAX_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError
        jti = validate_jti(identity.get("jti"))
        product_sha = load_reviewed_profile(_PRODUCT).sha256()
        runtime_sha = load_review_profile(_RUNTIME).sha256()
        compose_sha = hashlib.sha256(_COMPOSE.read_bytes()).hexdigest()
        reviewed = selected["ANALYTICS_INSTALLED_COMMIT"]

        # Audit a single fixed release intent; NOT a signature or permission.
        intent = canonical_bytes({
            "product_id": "analytics", "release_version": PINNED_VERSION,
            "source_sha": PINNED_PLATFORM_COMMIT, "image": PINNED_IMAGE,
            "run_id": run, "run_attempt": attempt,
            "release_manifest_sha256": selected["RELEASE_MANIFEST_SHA256"],
            "provenance_sha256": selected["PROVENANCE_SHA256"],
            "source_claim_sha256": selected["ANALYTICS_SOURCE_CLAIM_SHA256"],
        })
        request = {
            "schema_version": ANALYTICS_REQUEST_SCHEMA,
            "product_id": "analytics", "operation": "deploy", "stage": "dev",
            "release_version": PINNED_VERSION,
            "source_sha": PINNED_PLATFORM_COMMIT,
            "product_source_sha": SOURCE_COMMIT,
            "source_claim_sha256": selected["ANALYTICS_SOURCE_CLAIM_SHA256"],
            "oci_origin": APPROVED_OCI_ORIGIN,
            "oci_repository": "omnilyzer/analytics",
            "manifest_digest": PINNED_DIGEST,
            "exact_image_reference": PINNED_IMAGE,
            "release_manifest_sha256": selected["RELEASE_MANIFEST_SHA256"],
            "provenance_sha256": selected["PROVENANCE_SHA256"],
            "originating_release_run_id": PINNED_RUN_ID,
            "promotion_request_sha256": hashlib.sha256(intent).hexdigest(),
            "requested_by_actor_id": actor,
            "github_repository_id": DEV_REPOSITORY_ID,
            "github_workflow_ref": DEV_WORKFLOW_REF,
            "github_workflow_sha": identity["workflow_sha"],
            "github_run_id": run,
            "github_run_attempt": attempt,
            "oidc_jti": jti,
            "oidc_issued_at": iat,
            "oidc_expires_at": exp,
            "runtime_configuration_reference": {
                "kind": "reviewed-repository-product-profile-set",
                "repository_id": DEV_REPOSITORY_ID,
                "reviewed_commit": reviewed,
                "compose_path": ANALYTICS_COMPOSE_PATH,
                "compose_sha256": compose_sha,
                "product_profile_sha256": product_sha,
                "runtime_profile_sha256": runtime_sha,
            },
            "secrets_reference": {
                "kind": "private-host-files-name-only",
                "directory": ANALYTICS_SECRETS_DIRECTORY,
                "required": list(REQUIRED_ANALYTICS_SECRET_NAMES),
                "container_uid": 10001,
                "file_mode": "0600", "rootless_required": True,
            },
            "ingress_reference": {
                "kind": "private-no-public-ingress", "slot": "blue",
                "loopback_address": "127.0.0.1",
                "loopback_port": ANALYTICS_FIRST_PORT,
                "backend_network": ANALYTICS_NETWORK,
                "public_origin": None, "active_slot": None,
            },
            "rollback_reference": {
                "kind": ANALYTICS_ROLLBACK_MODE,
                "previous_digest": None, "previous_slot": None,
                "preserve_database_writes": True,
            },
        }
        raw = canonical_bytes(request)
        if not 0 < len(raw) <= _MAX_BODY:
            raise ValueError
        parsed = parse_analytics_request(
            raw,
            reviewed_installed_commit=reviewed,
            reviewed_compose_sha256=compose_sha,
            reviewed_product_profile_sha256=product_sha,
            reviewed_runtime_profile_sha256=runtime_sha,
        )
        if parsed.canonical_bytes() != raw:
            raise ValueError
        return raw
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsCIDispatchError(_ERROR) from None


def main() -> int:
    """Read-only workflow gate, no OIDC token, network, files or privileges."""
    if sys.argv[1:] != ["--preflight"]:
        return 2
    validate_analytics_ci_inputs(os.environ)
    print("analytics_task014_preflight_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
