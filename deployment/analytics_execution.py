"""File: deployment/analytics_execution.py

Purpose: Preserve original closed Task014 Analytics DEV first-install
         request grammar and validate an inert successor blue/green request.
         Original Canary, sealed credentials, installed broker, privileged
         executor and controller remain UNCHANGED and reject successors.

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
from release.analytics_owner_source_selection import (
    AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
    expected_owner_approval_bytes,
)
from .execution import DEV_STAGE, EXECUTOR_REQUEST_FIELDS
from .identity import (
    AuthorizedGitHubIdentity, DEV_REPOSITORY_ID, DEV_WORKFLOW_REF,
    MAX_TOKEN_LIFETIME_SECONDS, validate_jti,
)
from .policy import (
    APPROVED_OCI_ORIGIN, DeploymentPolicyError, canonical_bytes,
    validate_digest, validate_sha256, validate_source_sha,
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
# Section: successor-only inert request shape. Original schema 2 stays immutable.
ANALYTICS_SUCCESSOR_SCHEMA = 3
ANALYTICS_PRIVATE_SLOT_PORTS = {"blue": 3141, "green": 3142}
# Separate stable Analytics ingress3141 from successor candidate health3142.
# The new runtime override has no Docker-published host slot ports.
ANALYTICS_SUCCESSOR_CANDIDATE_PORT = 3142
ANALYTICS_UPGRADE_ROLLBACK_MODE = "switch-private-slot-preserve-writes"
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

# Closed additional field for a successor. No modification to schema-v2 grammar.
_SUCCESSOR_REQUEST_FIELDS = _REQUIRED_REQUEST_FIELDS | {"owner_approval_sha256"}


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


# Section 4: root-owned read-only live-state binding. NO deployment route.
def review_analytics_successor_with_live_active(
    raw: bytes, *, signed_previous: AnalyticsSignedEvidenceReview,
    reviewed_installed_commit: str, reviewed_compose_sha256: str,
    reviewed_product_profile_sha256: str,
    reviewed_runtime_profile_sha256: str,
    signed_release: AnalyticsSignedEvidenceReview,
    selected: AnalyticsOwnerSourceSelection,
    owner_approval: AnalyticsOwnerSignatureReceipt,
    identity: AuthorizedGitHubIdentity,
    require_staged_candidate: bool = False,
) -> AnalyticsSuccessorRequest:
    """Compare real routes and, when staged, probe the signed next image.

    No client-provided active-slot/digest is admitted as installed authority.
    This function does NOT authenticate passed Python objects. The
    restricted broker authenticates the original/new signed releases and
    GitHub OIDC; only the separate UID991 executor can measure actual Docker
    state. A future installed executor must obtain its evidence through
    the protected broker-to-executor trust boundary, not public dataclasses,
    and remeasure live state before any route mutation to prevent TOCTOU.
    """
    try:
        from .analytics_active_state_review import (
            AnalyticsActiveState, inspect_analytics_active_state,
        )

        live = inspect_analytics_active_state()
        if (
            type(live) is not AnalyticsActiveState
            or type(signed_previous) is not AnalyticsSignedEvidenceReview
            or live.read_only is not True
            or live.deployment_authorized is not False
            or type(live.active_slot) is not str
            or live.active_slot not in ANALYTICS_PRIVATE_SLOT_PORTS
            or type(live.active_digest) is not str
            or type(live.active_image) is not str
            or live.private_ingress_port != ANALYTICS_FIRST_PORT
            or live.candidate_slot != (
                "green" if live.active_slot == "blue" else "blue"
            )
            or live.candidate_port != ANALYTICS_SUCCESSOR_CANDIDATE_PORT
            or type(require_staged_candidate) is not bool
            or (
                require_staged_candidate
                and live.candidate_probe_present is not True
            )
            or (
                live.candidate_probe_present
                and (
                    type(signed_release) is not AnalyticsSignedEvidenceReview
                    or live.candidate_digest
                        != signed_release.source.oci_manifest_digest
                    or type(live.candidate_container_id) is not str
                    or len(live.candidate_container_id) != 64
                )
            )
            or live.active_image != signed_previous.image
            or live.active_digest != signed_previous.source.oci_manifest_digest
            or signed_previous.deployment_authorized is not False
            or signed_previous.source.release_authorized is not False
            or signed_previous.source.deployment_authorized is not False
            or type(selected) is not AnalyticsOwnerSourceSelection
            or type(signed_previous.release_version) is not str
            or tuple(map(int, signed_previous.release_version.split(".")))
                >= tuple(map(int, selected.release_version.split(".")))
        ):
            raise ValueError("current private signed release not verified")
        return parse_analytics_successor_request(
            raw,
            reviewed_installed_commit=reviewed_installed_commit,
            reviewed_compose_sha256=reviewed_compose_sha256,
            reviewed_product_profile_sha256=reviewed_product_profile_sha256,
            reviewed_runtime_profile_sha256=reviewed_runtime_profile_sha256,
            signed_release=signed_release,
            selected=selected, owner_approval=owner_approval,
            identity=identity,
            observed_active_digest=live.active_digest,
            observed_active_slot=live.active_slot,
        )
    except Exception:
        raise AnalyticsRequestError(ERROR) from None


# Section 3: reusable successor from independently reviewed active slot.
# This is an inert read-only request review. The installed broker/executor
# still rejects schema 3 and MUST independently verify real owner signature,
# Sigstore/Cosign, three OIDC audiences, replay and actual active-slot state.
@dataclass(frozen=True, slots=True)
class AnalyticsSuccessorRequest(AnalyticsExecutorRequest):
    """Review-only closed schema-3 upgrade request, never deploy authority."""

    owner_approval_sha256: str


def parse_analytics_successor_request(
    raw: bytes, *, reviewed_installed_commit: str,
    reviewed_compose_sha256: str,
    reviewed_product_profile_sha256: str,
    reviewed_runtime_profile_sha256: str,
    signed_release: AnalyticsSignedEvidenceReview,
    selected: AnalyticsOwnerSourceSelection,
    owner_approval: AnalyticsOwnerSignatureReceipt,
    identity: AuthorizedGitHubIdentity,
    observed_active_digest: str,
    observed_active_slot: str,
) -> AnalyticsSuccessorRequest:
    """Bind opposite candidate slot to trusted active signed version.

    Externally supplied dataclasses, even if internally consistent, cannot
    authenticate their own contents. Broker-verified signature/OIDC data and
    rootless-executor-verified active state are separate authority domains.
    This parser has NO executor routing, registry or state-changing operations.
    """
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_ANALYTICS_REQUEST_BYTES:
            raise ValueError
        # Reject duplicate JSON keys even in nested rollback and runtime maps.
        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        parsed = _closed(
            json.loads(raw.decode("ascii"), object_pairs_hook=unique),
            _SUCCESSOR_REQUEST_FIELDS,
        )
        runtime = _closed(parsed["runtime_configuration_reference"], _RUNTIME_FIELDS)
        ingress = _closed(parsed["ingress_reference"], _INGRESS_FIELDS)
        rollback = _closed(parsed["rollback_reference"], _ROLLBACK_FIELDS)
        secrets = _closed(parsed["secrets_reference"], _SECRET_FIELDS)
        if (
            type(observed_active_slot) is not str
            or observed_active_slot not in ANALYTICS_PRIVATE_SLOT_PORTS
        ):
            raise ValueError
        validate_digest(observed_active_digest)
        candidate_slot = (
            "green" if observed_active_slot == "blue" else "blue"
        )
        if (
            type(signed_release) is not AnalyticsSignedEvidenceReview
            or type(selected) is not AnalyticsOwnerSourceSelection
            or type(owner_approval) is not AnalyticsOwnerSignatureReceipt
            or type(identity) is not AuthorizedGitHubIdentity
            or observed_active_digest == signed_release.source.oci_manifest_digest
            or type(parsed["schema_version"]) is not int
            or parsed["schema_version"] != ANALYTICS_SUCCESSOR_SCHEMA
            or parsed["release_version"] != selected.release_version
            or signed_release.release_version != selected.release_version
            or signed_release.source.source_commit != selected.source_commit
            or signed_release.source.source_tree != selected.source_tree
            or owner_approval.source_commit != selected.source_commit
            or owner_approval.source_tree != selected.source_tree
            or owner_approval.release_version != selected.release_version
            or parsed["source_sha"] != selected.platform_workflow_commit
            or parsed["product_source_sha"] != selected.source_commit
            or parsed["originating_release_run_id"] != signed_release.release_run_id
            or type(parsed["originating_release_run_id"]) is not int
            or parsed["manifest_digest"] != signed_release.source.oci_manifest_digest
            or parsed["exact_image_reference"] != signed_release.image
            or parsed["release_manifest_sha256"] != signed_release.manifest_sha256
            or parsed["provenance_sha256"] != signed_release.provenance_sha256
            or parsed["source_claim_sha256"] != signed_release.source.claim_sha256
            or parsed["owner_approval_sha256"] != owner_approval.approval_sha256
            or owner_approval.approval_sha256 != hashlib.sha256(
                expected_owner_approval_bytes(selected)
            ).hexdigest()
            or owner_approval.owner_signature_verified is not True
            or selected.release_authorized is not False
            or selected.deployment_authorized is not False
            or owner_approval.release_authorized is not False
            or owner_approval.deployment_authorized is not False
            or signed_release.deployment_authorized is not False
            or signed_release.source.release_authorized is not False
            or signed_release.source.deployment_authorized is not False
            or selected.source_commit == SOURCE_COMMIT
            or selected.owner_actor_id != "130741173"
            or tuple(map(int, selected.release_version.split("."))) <= (0, 15, 0)
            or runtime["product_profile_sha256"] != signed_release.source.product_profile_sha256
            or runtime["runtime_profile_sha256"] != signed_release.source.runtime_profile_sha256
            or parsed["github_workflow_sha"] != identity.workflow_sha
            or parsed["requested_by_actor_id"] != identity.actor_id
            or parsed["github_repository_id"] != identity.repository_id
            or parsed["github_workflow_ref"] != identity.workflow_ref
            or parsed["github_run_id"] != identity.run_id
            or parsed["github_run_attempt"] != identity.run_attempt
            or parsed["oidc_jti"] != identity.jti
            or parsed["oidc_issued_at"] != identity.issued_at
            or parsed["oidc_expires_at"] != identity.expires_at
            or type(ingress["loopback_port"]) is not int
            or ingress != {
                "kind": "private-no-public-ingress",
                "slot": candidate_slot,
                "loopback_address": "127.0.0.1",
                "loopback_port": ANALYTICS_SUCCESSOR_CANDIDATE_PORT,
                "backend_network": ANALYTICS_NETWORK,
                "public_origin": None,
                "active_slot": observed_active_slot,
            }
            or type(rollback["preserve_database_writes"]) is not bool
            or rollback != {
                "kind": ANALYTICS_UPGRADE_ROLLBACK_MODE,
                "previous_digest": observed_active_digest,
                "previous_slot": observed_active_slot,
                "preserve_database_writes": True,
            }
        ):
            raise ValueError
        # Reuse the ORIGINAL schema-2 validator for every unchanged
        # reviewed runtime/profile/secret/identity field, without widening it.
        legacy = dict(parsed)
        del legacy["owner_approval_sha256"]
        legacy.update({
            "schema_version": ANALYTICS_REQUEST_SCHEMA,
            "release_version": PINNED_VERSION,
            "source_sha": PINNED_PLATFORM_COMMIT,
            "product_source_sha": SOURCE_COMMIT,
            "manifest_digest": PINNED_DIGEST,
            "exact_image_reference": PINNED_IMAGE,
            "originating_release_run_id": PINNED_RUN_ID,
            "ingress_reference": {
                "kind": "private-no-public-ingress", "slot": ANALYTICS_FIRST_SLOT,
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
        })
        baseline = AnalyticsExecutorRequest.from_dict(
            legacy,
            reviewed_installed_commit=reviewed_installed_commit,
            reviewed_compose_sha256=reviewed_compose_sha256,
            reviewed_product_profile_sha256=reviewed_product_profile_sha256,
            reviewed_runtime_profile_sha256=reviewed_runtime_profile_sha256,
        )
        if (baseline.github_workflow_sha != identity.workflow_sha
                or type(secrets["rootless_required"]) is not bool):
            raise ValueError
        for key in (
            "owner_approval_sha256", "source_claim_sha256",
            "release_manifest_sha256", "provenance_sha256",
            "promotion_request_sha256",
        ):
            _sha(parsed[key])
        if parsed["exact_image_reference"] != (
            "oci-dev.omnilyzer.ai/omnilyzer/analytics@" + parsed["manifest_digest"]
        ):
            raise ValueError
        # Same audit-intent construction as original CI request, extended
        # with the owner's approval and exact previously active digest.
        intent = canonical_bytes({
            "product_id": "analytics",
            "release_version": selected.release_version,
            "source_sha": selected.platform_workflow_commit,
            "image": signed_release.image,
            "run_id": identity.run_id,
            "run_attempt": identity.run_attempt,
            "release_manifest_sha256": signed_release.manifest_sha256,
            "provenance_sha256": signed_release.provenance_sha256,
            "source_claim_sha256": signed_release.source.claim_sha256,
            "owner_approval_sha256": owner_approval.approval_sha256,
            "previous_digest": observed_active_digest,
        })
        if parsed["promotion_request_sha256"] != hashlib.sha256(intent).hexdigest():
            raise ValueError
        result = AnalyticsSuccessorRequest(**parsed)
        if result.canonical_bytes() != raw:
            raise ValueError
        return result
    except Exception:
        raise AnalyticsRequestError(ERROR) from None
