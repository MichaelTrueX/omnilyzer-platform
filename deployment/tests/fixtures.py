from __future__ import annotations

import hashlib
import json

from deployment.audit import AuditEvent
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
        "schema_version": 1,
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
        "actor": "github:task014",
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
