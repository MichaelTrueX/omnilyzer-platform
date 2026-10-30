"""File: deployment/analytics_execution.py

Purpose: Closed, product-specific Task014 Analytics DEV first-install request
         grammar. The original canary-only ExecutorRequest, private registry
         credential transfer, broker, privileged executor and controller are
         deliberately UNCHANGED and DO NOT accept this schema.

Related: deployment/analytics_signed_release_consumer.py (original Sigstore
         and Cosign verified evidence reader; read-only),
         deployment/analytics_signed_source_pin.py,
         deployment/saas_product_contract.py,
         deployment/saas_product_runtime.py,
         deployment/identity.py (existing authorized OIDC identity),
         deployment/execution.py (unchanged canary schema v1),
         deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/analytics_dev_release_review.py,
         deployment/tests/test_analytics_execution.py.

Sections: closed first-install authority fields, reviewed runtime+secret
          references, canonical parsing, exact identity binding.

SECURITY: Parsing is NOT authorization. This module has NO installer, broker
entrypoint, transport, replay mutation, secret access, Docker command, or
signature authority. A caller can construct request-shaped bytes. The future
privileged boundary MUST first require real verified signed evidence, OIDC,
sealed registry credentials, root-owned installation source and replay checks.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Mapping

from .analytics_signed_release_consumer import (
    AnalyticsSignedEvidenceReview,
    PINNED_DIGEST, PINNED_IMAGE, PINNED_PLATFORM_COMMIT,
    PINNED_RUN_ID, PINNED_VERSION,
)
from .analytics_signed_source_pin import SOURCE_COMMIT
from .execution import DEV_STAGE, EXECUTOR_REQUEST_FIELDS
from .identity import (
    AuthorizedGitHubIdentity, DEV_REPOSITORY_ID, DEV_WORKFLOW_REF,
    MAX_TOKEN_LIFETIME_SECONDS, validate_jti,
)
from .policy import (
    APPROVED_OCI_ORIGIN, DeploymentPolicyError, canonical_bytes,
    validate_sha256, validate_source_sha,
)
from .saas_product_contract import REQUIRED_ANALYTICS_SECRET_NAMES

# Section 1: exclusively one signed Analytics first deployment on DEV.
ANALYTICS_REQUEST_SCHEMA = 2
ANALYTICS_OCI_REPOSITORY = "omnilyzer/analytics"
ANALYTICS_COMPOSE_PATH = "deployment/runtime/dev/analytics.compose.review.yaml"
ANALYTICS_SECRETS_DIRECTORY = (
    "/var/lib/omnilyzer/deployment/analytics/dev/secrets"
)
ANALYTICS_NETWORK = "omnilyzer-analytics-backend-dev"
ANALYTICS_FIRST_SLOT = "blue"
ANALYTICS_FIRST_PORT = 3141
ANALYTICS_ROLLBACK_MODE = "stop-first-private-slot-preserve-writes"
MAX_ANALYTICS_REQUEST_BYTES = 16 * 1024
ERROR = "TASK014_ANALYTICS_REQUEST_REJECTED"

_REQUIRED_REQUEST_FIELDS = frozenset(EXECUTOR_REQUEST_FIELDS) | {
    "product_id", "product_source_sha", "source_claim_sha256",
    "rollback_reference",
}
_RUNTIME_FIELDS = frozenset({
    "kind", "repository_id", "reviewed_commit", "compose_path",
    "compose_sha256", "product_profile_sha256", "runtime_profile_sha256",
})
_SECRET_FIELDS = frozenset({
    "kind", "directory", "required", "container_uid",
    "file_mode", "rootless_required",
})
_INGRESS_FIELDS = frozenset({
    "kind", "slot", "loopback_address", "loopback_port", "backend_network",
    "public_origin", "active_slot",
})
_ROLLBACK_FIELDS = frozenset({
    "kind", "previous_digest", "previous_slot", "preserve_database_writes",
})


class AnalyticsRequestError(DeploymentPolicyError):
    """No unreviewed Analytics first-install request is accepted."""


def _closed(value: object, fields: frozenset[str]) -> dict[str, Any]:
    """Reject missing/unknown keys, non-plain dicts and ambiguous objects."""
    if type(value) is not dict or set(value) != fields:
        raise AnalyticsRequestError(ERROR)
    return value


def _sha(value: object) -> str:
    """Require a real, exact, nonzero lowercase SHA256 string."""
    try:
        result = validate_sha256(value, "Analytics request hash")
    except (ValueError, TypeError) as exc:
        raise AnalyticsRequestError(ERROR) from exc
    if result == "0" * 64:
        raise AnalyticsRequestError(ERROR)
    return result


def _commit(value: object) -> str:
    """Require a non-zero SHA-1 Git object name, not a mutable branch."""
    try:
        return validate_source_sha(value)
    except (ValueError, TypeError) as exc:
        raise AnalyticsRequestError(ERROR) from exc


@dataclass(frozen=True, slots=True)
class AnalyticsExecutorRequest:
    """Read-only immutable *shape*, not a cryptographically authorized grant."""

    schema_version: int
    product_id: str
    operation: str
    stage: str
    release_version: str
    source_sha: str
    product_source_sha: str
    source_claim_sha256: str
    oci_origin: str
    oci_repository: str
    manifest_digest: str
    exact_image_reference: str
    release_manifest_sha256: str
    provenance_sha256: str
    originating_release_run_id: int
    promotion_request_sha256: str
    requested_by_actor_id: int
    github_repository_id: int
    github_workflow_ref: str
    github_workflow_sha: str
    github_run_id: int
    github_run_attempt: int
    oidc_jti: str
    oidc_issued_at: int
    oidc_expires_at: int
    runtime_configuration_reference: Mapping[str, Any]
    secrets_reference: Mapping[str, Any]
    ingress_reference: Mapping[str, Any]
    rollback_reference: Mapping[str, Any]

    @classmethod
    def from_dict(
        cls, value: object, *,
        reviewed_installed_commit: str,
        reviewed_compose_sha256: str,
        reviewed_product_profile_sha256: str,
        reviewed_runtime_profile_sha256: str,
    ) -> "AnalyticsExecutorRequest":
        """Validate request against separately reviewed *installed* source.

        The four expected values MUST come from the root-controlled reviewed
        host source and signed profile admission, never the incoming request.
        This parser does not perform those inspections or grant permissions.
        """
        try:
            if cls is not AnalyticsExecutorRequest:
                raise ValueError
            data = _closed(value, _REQUIRED_REQUEST_FIELDS)
            reviewed_installed_commit = _commit(reviewed_installed_commit)
            reviewed_compose_sha256 = _sha(reviewed_compose_sha256)
            reviewed_product_profile_sha256 = _sha(reviewed_product_profile_sha256)
            reviewed_runtime_profile_sha256 = _sha(reviewed_runtime_profile_sha256)
            runtime = _closed(data["runtime_configuration_reference"], _RUNTIME_FIELDS)
            secrets = _closed(data["secrets_reference"], _SECRET_FIELDS)
            ingress = _closed(data["ingress_reference"], _INGRESS_FIELDS)
            rollback = _closed(data["rollback_reference"], _ROLLBACK_FIELDS)

            if (
                type(data["schema_version"]) is not int
                or data["schema_version"] != ANALYTICS_REQUEST_SCHEMA
                or data["product_id"] != "analytics"
                or type(data["product_id"]) is not str
                or data["operation"] != "deploy"
                or type(data["operation"]) is not str
                or data["stage"] != DEV_STAGE
                or type(data["stage"]) is not str
                or data["release_version"] != PINNED_VERSION
                or data["source_sha"] != PINNED_PLATFORM_COMMIT
                or data["product_source_sha"] != SOURCE_COMMIT
                or data["oci_origin"] != APPROVED_OCI_ORIGIN
                or data["oci_repository"] != ANALYTICS_OCI_REPOSITORY
                or data["manifest_digest"] != PINNED_DIGEST
                or data["exact_image_reference"] != PINNED_IMAGE
                or data["originating_release_run_id"] != PINNED_RUN_ID
                or type(data["originating_release_run_id"]) is not int
                or type(data["requested_by_actor_id"]) is not int
                or not 0 < data["requested_by_actor_id"] <= 2**63 - 1
                or type(data["github_repository_id"]) is not int
                or data["github_repository_id"] != DEV_REPOSITORY_ID
                or data["github_workflow_ref"] != DEV_WORKFLOW_REF
                or type(data["github_workflow_ref"]) is not str
                or type(data["github_run_id"]) is not int
                or not 0 < data["github_run_id"] <= 2**63 - 1
                or type(data["github_run_attempt"]) is not int
                or not 0 < data["github_run_attempt"] <= 2**63 - 1
                or type(data["oidc_issued_at"]) is not int
                or type(data["oidc_expires_at"]) is not int
                or data["oidc_issued_at"] < 0
                or not 0 < data["oidc_expires_at"] - data["oidc_issued_at"]
                <= MAX_TOKEN_LIFETIME_SECONDS
                or type(runtime["repository_id"]) is not int
                or runtime != {
                    "kind": "reviewed-repository-product-profile-set",
                    "repository_id": DEV_REPOSITORY_ID,
                    "reviewed_commit": reviewed_installed_commit,
                    "compose_path": ANALYTICS_COMPOSE_PATH,
                    "compose_sha256": reviewed_compose_sha256,
                    "product_profile_sha256": reviewed_product_profile_sha256,
                    "runtime_profile_sha256": reviewed_runtime_profile_sha256,
                }
                or type(secrets["container_uid"]) is not int
                or type(secrets["rootless_required"]) is not bool
                or secrets != {
                    "kind": "private-host-files-name-only",
                    "directory": ANALYTICS_SECRETS_DIRECTORY,
                    "required": list(REQUIRED_ANALYTICS_SECRET_NAMES),
                    "container_uid": 10001,
                    "file_mode": "0600",
                    "rootless_required": True,
                }
                or type(ingress["loopback_port"]) is not int
                or ingress != {
                    "kind": "private-no-public-ingress",
                    "slot": ANALYTICS_FIRST_SLOT,
                    "loopback_address": "127.0.0.1",
                    "loopback_port": ANALYTICS_FIRST_PORT,
                    "backend_network": ANALYTICS_NETWORK,
                    "public_origin": None,
                    "active_slot": None,
                }
                or type(rollback["preserve_database_writes"]) is not bool
                or rollback != {
                    "kind": ANALYTICS_ROLLBACK_MODE,
                    "previous_digest": None,
                    "previous_slot": None,
                    "preserve_database_writes": True,
                }
            ):
                raise ValueError

            for field in (
                "source_claim_sha256", "release_manifest_sha256",
                "provenance_sha256", "promotion_request_sha256",
            ):
                _sha(data[field])
            _commit(data["github_workflow_sha"])
            validate_jti(data["oidc_jti"])
            # Keep nested input values as canonical independently owned dicts.
            # No caller-owned mutable container may be retained by the model.
            items = dict(data)
            items["runtime_configuration_reference"] = dict(runtime)
            items["secrets_reference"] = {
                **secrets, "required": list(REQUIRED_ANALYTICS_SECRET_NAMES),
            }
            items["ingress_reference"] = dict(ingress)
            items["rollback_reference"] = dict(rollback)
            return cls(**items)
        except Exception:
            raise AnalyticsRequestError(ERROR) from None

    def to_dict(self) -> dict[str, Any]:
        """Serialize for review; root-bound parser must revalidate the result."""
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        """Return canonical ASCII JSON bytes; never self-authorize on format."""
        return canonical_bytes(self.to_dict())

    def sha256(self) -> str:
        """Compute an auditable hash to bind one future replay entry."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def parse_analytics_request(
    raw: bytes, *, reviewed_installed_commit: str,
    reviewed_compose_sha256: str,
    reviewed_product_profile_sha256: str,
    reviewed_runtime_profile_sha256: str,
) -> AnalyticsExecutorRequest:
    """Strict duplicate-free canonical parse; no broker/executor routing."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ANALYTICS_REQUEST_BYTES:
        raise AnalyticsRequestError(ERROR)

    def no_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Reject any duplicate JSON key, including inside references."""
        value: dict[str, Any] = {}
        for name, item in pairs:
            if name in value:
                raise AnalyticsRequestError(ERROR)
            value[name] = item
        return value

    try:
        parsed = json.loads(raw.decode("ascii"), object_pairs_hook=no_duplicate)
        request = AnalyticsExecutorRequest.from_dict(
            parsed, reviewed_installed_commit=reviewed_installed_commit,
            reviewed_compose_sha256=reviewed_compose_sha256,
            reviewed_product_profile_sha256=reviewed_product_profile_sha256,
            reviewed_runtime_profile_sha256=reviewed_runtime_profile_sha256,
        )
        if request.canonical_bytes() != raw:
            raise ValueError
        return request
    except Exception:
        raise AnalyticsRequestError(ERROR) from None


def bind_analytics_request_to_identity(
    request: AnalyticsExecutorRequest,
    identity: AuthorizedGitHubIdentity,
) -> None:
    """Require all original Task014 OIDC/replay identity fields to match.

    The identity MUST already be verified by the original Task014 JWKS/OIDC
    authorization, not constructed from untrusted JSON or this dataclass.
    """
    if (
        type(request) is not AnalyticsExecutorRequest
        or type(identity) is not AuthorizedGitHubIdentity
        or (
            request.requested_by_actor_id,
            request.github_repository_id,
            request.github_workflow_ref,
            request.github_workflow_sha,
            request.github_run_id,
            request.github_run_attempt,
            request.oidc_jti,
            request.oidc_issued_at,
            request.oidc_expires_at,
        )
        != (
            identity.actor_id, identity.repository_id, identity.workflow_ref,
            identity.workflow_sha, identity.run_id, identity.run_attempt,
            identity.jti, identity.issued_at, identity.expires_at,
        )
    ):
        raise AnalyticsRequestError(ERROR)


def bind_analytics_request_to_verified_evidence(
    request: AnalyticsExecutorRequest,
    review: AnalyticsSignedEvidenceReview,
) -> None:
    """Cross-bind request hashes to the actual reviewed signed source.

    This comparison is necessary but NEVER sufficient authorization: both
    public dataclasses are constructible. The original signature-verifying
    registry consumer MUST execute inside the protected OIDC broker before
    any request becomes eligible for replay, transport or privileged action.
    """
    if (
        type(request) is not AnalyticsExecutorRequest
        or type(review) is not AnalyticsSignedEvidenceReview
        or review.deployment_authorized is not False
        or review.source.release_authorized is not False
        or review.source.deployment_authorized is not False
        or review.release_version != request.release_version
        or review.release_run_id != request.originating_release_run_id
        or review.image != request.exact_image_reference
        or review.manifest_sha256 != request.release_manifest_sha256
        or review.provenance_sha256 != request.provenance_sha256
        or review.source.source_commit != request.product_source_sha
        or review.source.oci_manifest_digest != request.manifest_digest
        or review.source.claim_sha256 != request.source_claim_sha256
        or review.source.product_profile_sha256 != (
            request.runtime_configuration_reference["product_profile_sha256"]
        )
        or review.source.runtime_profile_sha256 != (
            request.runtime_configuration_reference["runtime_profile_sha256"]
        )
    ):
        raise AnalyticsRequestError(ERROR)
