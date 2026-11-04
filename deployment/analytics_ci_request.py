"""File: deployment/analytics_ci_request.py

Purpose: Preserve the immutable signed Analytics 0.15.0 Task014 schema-v2
         CI request and prepare an inert reviewed-successor schema-v3 request.
         Neither CI serialization path is a signer or a deployment grant.
Related: .github/workflows/platform-promote.yml (original canary default),
         deployment/analytics_execution.py (closed request parser),
         deployment/ci_oidc_diagnostics.py (unverified JWT diagnostics),
         deployment/analytics_signed_release_consumer.py (pinned release),
         deployment/tests/test_analytics_ci_request.py.

Sections: immutable original dispatch preflight, optional private metadata
          lookup, strict CI JWT projection, original canonical request;
          successor source/slot preflight, private Forgejo metadata projection,
          and canonical future request matching the independent schema-v3 parser.

SECURITY: CI decoding a JWT or reading private Forgejo metadata NEVER
authenticates the signer, owner key or active server. The root-owned Task014
broker must independently verify ALL OIDC audiences, Ed25519 approval,
Sigstore/Cosign, current active release and replay before an executor action.
The successor path is NOT wired to the active promotion workflow. No broker
request, host secret, Docker, database or public route is touched here.
Canary and original Analytics 0.15.0 dispatch behavior are unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Mapping

from .analytics_execution import (
    ANALYTICS_COMPOSE_PATH, ANALYTICS_FIRST_PORT, ANALYTICS_NETWORK,
    ANALYTICS_REQUEST_SCHEMA, ANALYTICS_ROLLBACK_MODE,
    ANALYTICS_SUCCESSOR_SCHEMA, ANALYTICS_PRIVATE_SLOT_PORTS,
    ANALYTICS_SUCCESSOR_CANDIDATE_PORT,
    ANALYTICS_UPGRADE_ROLLBACK_MODE,
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
_METADATA_INPUTS = (
    "RELEASE_MANIFEST_SHA256", "PROVENANCE_SHA256",
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


def validate_analytics_ci_inputs(
    environment: Mapping[str, str], *, allow_metadata_resolution: bool = False,
) -> dict[str, str]:
    """Check only selected release/runner input shape, not signed authority.

    The workflow has no product-wide allowlist: the sole supported Analytics
    release version/source/digest/run is fixed in existing signed source code.
    Manually supplied hashes remain UNTRUSTED until the real broker compares
    them with the signed release and actual root-controlled config.
    """
    try:
        if not isinstance(environment, Mapping) or type(allow_metadata_resolution) is not bool:
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
        unresolved = all(data[key] == "" for key in _METADATA_INPUTS)
        if not (allow_metadata_resolution and unresolved):
            for key in _METADATA_INPUTS:
                _hash(data[key])
        _hash(data["ANALYTICS_INSTALLED_COMMIT"], 40)
        return data
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsCIDispatchError(_ERROR) from None


def resolve_analytics_ci_release_inputs(
    *, environment: Mapping[str, str], forgejo_oidc_token: str,
) -> dict[str, str]:
    """Read exact private release metadata using the existing Forgejo audience.

    These hashes are UNTRUSTED request inputs, not signature or deployment
    authority. The original broker still independently downloads/verifies the
    immutable package, signatures, source, OIDC and replay before deployment.
    Preserve explicit manual inputs; only the all-empty three-hash mode reads
    the one pinned Analytics package. Never print tokens or archive contents.
    """
    try:
        selected = validate_analytics_ci_inputs(
            environment, allow_metadata_resolution=True,
        )
        resolved = dict(environment)
        if all(selected[key] for key in _METADATA_INPUTS):
            return resolved
        if (
            type(forgejo_oidc_token) is not str
            or not 1 <= len(forgejo_oidc_token) <= 8192
            or not forgejo_oidc_token.isascii()
            or any(ord(c) < 33 or ord(c) > 126 for c in forgejo_oidc_token)
            or _decode_untrusted(forgejo_oidc_token).get("aud")
            != "u:3:d4f50b90-f001-4b9f-ad1e-487080ec44fb"
        ):
            raise ValueError
        from .release_consumer import _get, _connection
        from .analytics_signed_release_consumer import _analytics_archive, _signed_fields

        archive, _headers = _get(
            "forgejo", PINNED_VERSION, forgejo_oidc_token, _connection,
            product="analytics",
        )
        evidence, scanner_hashes = _analytics_archive(archive)
        manifest, _provenance = _signed_fields(evidence, scanner_hashes)
        resolved.update({
            "RELEASE_MANIFEST_SHA256": hashlib.sha256(
                evidence["release-manifest.json"],
            ).hexdigest(),
            "PROVENANCE_SHA256": hashlib.sha256(
                evidence["release-provenance.json"],
            ).hexdigest(),
            "ANALYTICS_SOURCE_CLAIM_SHA256": hashlib.sha256(
                canonical_bytes(manifest["external_source"]),
            ).hexdigest(),
        })
        validate_analytics_ci_inputs(resolved)
        return resolved
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


# Section 4: ordinary successor CI bytes, no source/release pins.
# The original v2 builder above remains fixed for signed 0.15.0. This
# companion is purely a CI projection: it cannot independently authenticate
# an owner signature, active server, JWT, Forgejo archive, or OCI image.
_SUCCESSOR_INPUT_FIELDS = (
    "ANALYTICS_PRODUCT_SOURCE_SHA",
    "ANALYTICS_OWNER_APPROVAL_SHA256",
    "ANALYTICS_ACTIVE_DIGEST",
    "ANALYTICS_ACTIVE_SLOT",
)
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


def validate_analytics_successor_ci_inputs(
    environment: Mapping[str, str], *, allow_metadata_resolution: bool = False,
) -> dict[str, str]:
    """Require complete future release and prior-slot inputs, NEVER authority.

    The actual ROOT-owned broker must separately bind all request fields to
    actual signed Task013 evidence, owner Ed25519 approval, real observed
    active image/slot and original Task014 OIDC/replay before deployment.
    """
    try:
        if (
            not isinstance(environment, Mapping)
            or type(allow_metadata_resolution) is not bool
        ):
            raise ValueError
        data = {
            key: environment.get(key)
            for key in (*_REQUIRED_INPUTS, *_SUCCESSOR_INPUT_FIELDS)
        }
        if (
            environment.get("TASK014_PRODUCT") != "analytics"
            or environment.get("TARGET_STAGE") != "dev"
            or environment.get("GITHUB_REPOSITORY") != DEV_REPOSITORY
            or environment.get("GITHUB_REF") != DEV_REF
            or environment.get("GITHUB_EVENT_NAME") != DEV_EVENT_NAME
            or type(data["RELEASE_VERSION"]) is not str
            or _SEMVER.fullmatch(data["RELEASE_VERSION"]) is None
            or tuple(map(int, data["RELEASE_VERSION"].split("."))) <= (0, 15, 0)
            or data["ANALYTICS_PRODUCT_SOURCE_SHA"] == SOURCE_COMMIT
            or data["ANALYTICS_ACTIVE_SLOT"] not in ANALYTICS_PRIVATE_SLOT_PORTS
            or _decimal(data["ORIGINATING_RELEASE_RUN_ID"]) == PINNED_RUN_ID
        ):
            raise ValueError
        for key in (
            "SOURCE_SHA", "ANALYTICS_PRODUCT_SOURCE_SHA",
            "ANALYTICS_INSTALLED_COMMIT",
        ):
            _hash(data[key], 40)
        unresolved = all(data[key] == "" for key in _METADATA_INPUTS)
        if not (allow_metadata_resolution and unresolved):
            for name in _METADATA_INPUTS:
                _hash(data[name])
        _hash(data["ANALYTICS_OWNER_APPROVAL_SHA256"])
        for name in ("MANIFEST_DIGEST", "ANALYTICS_ACTIVE_DIGEST"):
            digest = data[name]
            if (
                type(digest) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                or digest == "sha256:" + "0" * 64
            ):
                raise ValueError
        if (
            data["MANIFEST_DIGEST"] in (PINNED_DIGEST, data["ANALYTICS_ACTIVE_DIGEST"])
            or data["ANALYTICS_OWNER_APPROVAL_SHA256"] == "0" * 64
        ):
            raise ValueError
        return data
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsCIDispatchError(_ERROR) from None


def resolve_analytics_successor_ci_release_inputs(
    *, environment: Mapping[str, str], forgejo_oidc_token: str,
) -> dict[str, str]:
    """Resolve three optional hashes from one exact private Forgejo release.

    The archive is only an UNTRUSTED CI metadata source. The root broker
    MUST independently re-download the release, check owner Ed25519,
    Sigstore/Cosign and actual active state before any replay/transport.
    """
    try:
        chosen = validate_analytics_successor_ci_inputs(
            environment, allow_metadata_resolution=True,
        )
        result = dict(environment)
        if all(chosen[key] for key in _METADATA_INPUTS):
            return result
        if (
            type(forgejo_oidc_token) is not str
            or not 0 < len(forgejo_oidc_token) <= 8192
            or not forgejo_oidc_token.isascii()
            or any(ord(char) < 33 or ord(char) > 126
                   for char in forgejo_oidc_token)
            or _decode_untrusted(forgejo_oidc_token).get("aud")
            != "u:3:d4f50b90-f001-4b9f-ad1e-487080ec44fb"
        ):
            raise ValueError
        from .release_consumer import _get, _connection
        from .analytics_signed_release_consumer import (
            _analytics_archive, _signed_fields,
        )

        archive, _headers = _get(
            "forgejo", chosen["RELEASE_VERSION"], forgejo_oidc_token,
            _connection, product="analytics",
        )
        evidence, scanner_hashes = _analytics_archive(archive)
        manifest, _provenance = _signed_fields(
            evidence, scanner_hashes,
            expected_version=chosen["RELEASE_VERSION"],
            expected_platform_commit=chosen["SOURCE_SHA"],
            expected_digest=chosen["MANIFEST_DIGEST"],
            expected_run_id=_decimal(chosen["ORIGINATING_RELEASE_RUN_ID"]),
        )
        claim = manifest["external_source"]
        if (
            type(claim) is not dict or claim.get("schema_version") != 2
            or type(claim.get("schema_version")) is not int
            or claim.get("source_commit") != chosen["ANALYTICS_PRODUCT_SOURCE_SHA"]
            or claim.get("owner_approval_sha256")
                != chosen["ANALYTICS_OWNER_APPROVAL_SHA256"]
            or claim.get("platform_source_commit") != chosen["SOURCE_SHA"]
            or claim.get("oci_manifest_digest") != chosen["MANIFEST_DIGEST"]
            or claim.get("release_version") != chosen["RELEASE_VERSION"]
        ):
            raise ValueError
        result.update({
            "RELEASE_MANIFEST_SHA256": hashlib.sha256(
                evidence["release-manifest.json"],
            ).hexdigest(),
            "PROVENANCE_SHA256": hashlib.sha256(
                evidence["release-provenance.json"],
            ).hexdigest(),
            "ANALYTICS_SOURCE_CLAIM_SHA256": hashlib.sha256(
                canonical_bytes(claim),
            ).hexdigest(),
        })
        validate_analytics_successor_ci_inputs(result)
        return result
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsCIDispatchError(_ERROR) from None


def build_analytics_successor_ci_request(
    *, deployment_oidc_token: str, environment: Mapping[str, str],
) -> bytes:
    """Build canonical schema-3 CI request; does not authorize deployment.

    Reuse the original strict CI JWT projection, reviewed runtime/secrets and
    OIDC metadata, then substitute the owner-selected successor identities.
    This does not authenticate the CI inputs or owner key. The root-owned
    broker must obtain and check actual signatures and current slot state.
    """
    try:
        future = validate_analytics_successor_ci_inputs(environment)
        # The pinned original CI path is deliberately reused as a *template*
        # for immutable runtime/secret and original unverified JWT controls.
        # No synthetic data are sent or trusted. This is local CI formatting.
        baseline = {
            **environment,
            "RELEASE_VERSION": PINNED_VERSION,
            "SOURCE_SHA": PINNED_PLATFORM_COMMIT,
            "MANIFEST_DIGEST": PINNED_DIGEST,
            "ORIGINATING_RELEASE_RUN_ID": str(PINNED_RUN_ID),
        }
        base_raw = build_analytics_ci_request(
            deployment_oidc_token=deployment_oidc_token,
            environment=baseline,
        )
        request = json.loads(base_raw.decode("ascii"))
        active_slot = future["ANALYTICS_ACTIVE_SLOT"]
        opposite = "green" if active_slot == "blue" else "blue"
        image = (
            "oci-dev.omnilyzer.ai/omnilyzer/analytics@"
            + future["MANIFEST_DIGEST"]
        )
        request.update({
            "schema_version": ANALYTICS_SUCCESSOR_SCHEMA,
            "release_version": future["RELEASE_VERSION"],
            "source_sha": future["SOURCE_SHA"],
            "product_source_sha": future["ANALYTICS_PRODUCT_SOURCE_SHA"],
            "source_claim_sha256": future["ANALYTICS_SOURCE_CLAIM_SHA256"],
            "owner_approval_sha256": future["ANALYTICS_OWNER_APPROVAL_SHA256"],
            "manifest_digest": future["MANIFEST_DIGEST"],
            "exact_image_reference": image,
            "release_manifest_sha256": future["RELEASE_MANIFEST_SHA256"],
            "provenance_sha256": future["PROVENANCE_SHA256"],
            "originating_release_run_id": _decimal(
                future["ORIGINATING_RELEASE_RUN_ID"]
            ),
            "ingress_reference": {
                "kind": "private-no-public-ingress",
                "slot": opposite,
                "loopback_address": "127.0.0.1",
                "loopback_port": ANALYTICS_SUCCESSOR_CANDIDATE_PORT,
                "backend_network": ANALYTICS_NETWORK,
                "public_origin": None,
                "active_slot": active_slot,
            },
            "rollback_reference": {
                "kind": ANALYTICS_UPGRADE_ROLLBACK_MODE,
                "previous_digest": future["ANALYTICS_ACTIVE_DIGEST"],
                "previous_slot": active_slot,
                "preserve_database_writes": True,
            },
        })
        intent = canonical_bytes({
            "product_id": "analytics",
            "release_version": future["RELEASE_VERSION"],
            "source_sha": future["SOURCE_SHA"],
            "image": image,
            "run_id": request["github_run_id"],
            "run_attempt": request["github_run_attempt"],
            "release_manifest_sha256": future["RELEASE_MANIFEST_SHA256"],
            "provenance_sha256": future["PROVENANCE_SHA256"],
            "source_claim_sha256": future["ANALYTICS_SOURCE_CLAIM_SHA256"],
            "owner_approval_sha256": future["ANALYTICS_OWNER_APPROVAL_SHA256"],
            "previous_digest": future["ANALYTICS_ACTIVE_DIGEST"],
        })
        request["promotion_request_sha256"] = hashlib.sha256(intent).hexdigest()
        raw = canonical_bytes(request)
        if not 0 < len(raw) <= _MAX_BODY:
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
    validate_analytics_ci_inputs(os.environ, allow_metadata_resolution=True)
    print("analytics_task014_preflight_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
