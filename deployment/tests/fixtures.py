from __future__ import annotations

import hashlib
import json

from deployment.audit import AuditEvent, AuditExecutionIdentity
from deployment.execution import (
    DEV_LOOPBACK_ADDRESS,
    DEV_LOOPBACK_PORT,
    DEV_PUBLIC_ORIGIN,
    INGRESS_PATHS,
    NO_SECRETS_REASON,
    RUNTIME_CONFIGURATION_PATH,
    ExecutorRequest,
)
from deployment.identity import DEV_REPOSITORY_ID, DEV_WORKFLOW_REF
from deployment.policy import (
    EXPECTED_CERTIFICATE_IDENTITY,
    EXPECTED_CERTIFICATE_ISSUER,
    EXPECTED_RELEASE_WORKFLOW,
    canonical_bytes,
)
from deployment.promotion import PromotionRequest
from deployment.state import DeploymentState


VERSION = "0.13.4"
SOURCE_SHA = "534ed17561f43b17d4d1efe6d98e9c33e3df5c28"
REPOSITORY = "omnilyzer/task013-release-canary"
DIGEST = "sha256:1e459732e5aeb124e333a80fb71714c788f3274b25d8747f0ffe1ccfda4e8a7c"
OTHER_DIGEST = "sha256:" + "2" * 64
IMAGE = f"oci-dev.omnilyzer.ai/{REPOSITORY}@{DIGEST}"
TIMESTAMP = "2026-09-07T06:30:00Z"
WORKFLOW_SHA = "4" * 40
PROMOTION_REQUEST_SHA256 = "c" * 64


def executor_request_value() -> dict[str, object]:
    return {
        "schema_version": 1,
        "operation": "deploy",
        "stage": "dev",
        "release_version": VERSION,
        "source_sha": SOURCE_SHA,
        "oci_origin": "https://oci-dev.omnilyzer.ai",
        "oci_repository": REPOSITORY,
        "manifest_digest": DIGEST,
        "exact_image_reference": f"oci-dev.omnilyzer.ai/{REPOSITORY}@{DIGEST}",
        "release_manifest_sha256": "a" * 64,
        "provenance_sha256": "b" * 64,
        "originating_release_run_id": 34088735049,
        "promotion_request_sha256": PROMOTION_REQUEST_SHA256,
        "requested_by_actor_id": 130741173,
        "github_repository_id": DEV_REPOSITORY_ID,
        "github_workflow_ref": DEV_WORKFLOW_REF,
        "github_workflow_sha": WORKFLOW_SHA,
        "github_run_id": 34150000000,
        "github_run_attempt": 1,
        "oidc_jti": "a95bf7cc-7c30-4c90-b85b-f001144c1c6e",
        "oidc_issued_at": 1_778_000_000,
        "oidc_expires_at": 1_778_000_300,
        "runtime_configuration_reference": {
            "schema_version": 1,
            "kind": "repository-blob-sha256",
            "repository_id": DEV_REPOSITORY_ID,
            "reviewed_commit": WORKFLOW_SHA,
            "path": RUNTIME_CONFIGURATION_PATH,
            "sha256": "d" * 64,
        },
        "secrets_reference": {
            "schema_version": 1,
            "kind": "none",
            "required": [],
            "reason": NO_SECRETS_REASON,
        },
        "ingress_reference": {
            "schema_version": 1,
            "kind": "repository-file-set-sha256",
            "repository_id": DEV_REPOSITORY_ID,
            "reviewed_commit": WORKFLOW_SHA,
            "files": [
                {"path": path, "sha256": f"{index + 1:x}" * 64}
                for index, path in enumerate(INGRESS_PATHS)
            ],
            "loopback_address": DEV_LOOPBACK_ADDRESS,
            "loopback_port": DEV_LOOPBACK_PORT,
            "public_origin": DEV_PUBLIC_ORIGIN,
        },
    }


def executor_request() -> ExecutorRequest:
    return ExecutorRequest.from_dict(executor_request_value())


def execution_identity() -> dict[str, object]:
    return AuditExecutionIdentity.from_executor_request(executor_request()).to_dict()


def evidence() -> tuple[bytes, bytes]:
    manifest = canonical_bytes({
        "schema_version": 1,
        "platform_version": VERSION,
        "source_commit": SOURCE_SHA,
        "oci": {
            "registry": "https://oci-dev.omnilyzer.ai",
            "repository": REPOSITORY,
            "manifest_digest": DIGEST,
            "deployment_identity": f"{REPOSITORY}@{DIGEST}",
        },
    })
    provenance = canonical_bytes({
        "schema_version": 1,
        "platform_version": VERSION,
        "source_commit": SOURCE_SHA,
        "workflow_ref": EXPECTED_RELEASE_WORKFLOW,
        "subjects": {"oci_manifest_digest": DIGEST},
        "claim": "build-once release evidence; no formal SLSA level is asserted",
    })
    return manifest, provenance


def request(stage: str = "dev", digest: str = DIGEST) -> PromotionRequest:
    manifest, provenance = evidence()
    return PromotionRequest.from_dict({
        "schema_version": 1,
        "release_version": VERSION,
        "source_sha": SOURCE_SHA,
        "oci_repository": REPOSITORY,
        "manifest_digest": digest,
        "exact_image_reference": f"oci-dev.omnilyzer.ai/{REPOSITORY}@{digest}",
        "release_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "provenance_sha256": hashlib.sha256(provenance).hexdigest(),
        "originating_release_run_id": 34088735049,
        "target_stage": stage,
        "requested_by": "github:release-operator",
    })


def sigstore_result() -> dict[str, object]:
    return {
        "release_manifest_verified": True,
        "provenance_verified": True,
        "certificate_identity": EXPECTED_CERTIFICATE_IDENTITY,
        "issuer": EXPECTED_CERTIFICATE_ISSUER,
    }


def oci_signature_result(digest: str = DIGEST) -> dict[str, object]:
    return {
        "verified": True,
        "repository": REPOSITORY,
        "manifest_digest": digest,
        "certificate_identity": EXPECTED_CERTIFICATE_IDENTITY,
        "issuer": EXPECTED_CERTIFICATE_ISSUER,
    }


def event(stage: str, digest: str = DIGEST, event_type: str = "promotion_succeeded") -> AuditEvent:
    return AuditEvent.from_dict({
        "schema_version": 2,
        "event_id": f"event-{stage}",
        "event_type": event_type,
        "stage": stage,
        "release_version": VERSION,
        "source_sha": SOURCE_SHA,
        "oci_repository": REPOSITORY,
        "digest": digest,
        "previous_digest": None,
        "active_slot": "green",
        "candidate_slot": None,
        "execution_identity": execution_identity(),
        "migration_identity": None,
        "result": "succeeded",
        "timestamp": TIMESTAMP,
    })


def state(*, previous: bool = True, candidate: bool = False) -> DeploymentState:
    return DeploymentState.from_dict({
        "schema_version": 1,
        "stage": "dev",
        "active_release": "0.13.3",
        "active_source_sha": "a" * 40,
        "active_digest": OTHER_DIGEST,
        "active_slot": "blue",
        "previous_release": "0.13.2" if previous else None,
        "previous_source_sha": "b" * 40 if previous else None,
        "previous_digest": "sha256:" + "3" * 64 if previous else None,
        "previous_slot": "green" if previous else None,
        "candidate_release": VERSION if candidate else None,
        "candidate_source_sha": SOURCE_SHA if candidate else None,
        "candidate_digest": DIGEST if candidate else None,
        "candidate_slot": "green" if candidate else None,
        "migration_state": {
            "status": "pending" if candidate else "none",
            "identity": "014_additive" if candidate else None,
            "checksum": "c" * 64 if candidate else None,
            "serialized_lock_required": True,
        },
        "updated_at": TIMESTAMP,
        "event_id": "state-1",
    })
