"""File: deployment/direct_dev_prod_preflight.py

Purpose: Validate an exact DEV success as the direct prerequisite for a
    future PROD release without mutating frozen Task014/Analytics DEV sources.
Related: deployment/controller.py (historical STAGING-only control),
    deployment/promotion.py, deployment/audit.py, deployment/tests/
    test_direct_dev_prod_preflight.py, ADR 0012 and AGENTS.md.

Security boundary: This is SOURCE-ONLY validation. It NEVER authorizes a PROD
deployment, verifies signatures, loads a root audit log, opens sockets,
changes routes, creates a release receipt, or replaces an existing operator.
The caller must independently obtain cryptographically verified release
evidence, trusted/immutable DEV audit events and explicit owner approval.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .audit import AuditEvent
from .policy import DeploymentPolicyError
from .promotion import PromotionRequest, TrustedRelease


@dataclass(frozen=True, slots=True)
class DirectProdPrerequisite:
    """Describe one exact DEV match; provide no deployment authority."""

    version: str
    source_sha: str
    repository: str
    digest: str
    dev_event_id: str
    can_deploy: bool = False


def check_direct_prod_prerequisite(
    request: PromotionRequest,
    trusted_release: TrustedRelease,
    dev_events: Iterable[AuditEvent],
) -> DirectProdPrerequisite:
    """Match exactly one successful DEV audit event to signed source identity.

    The input TrustedRelease must be produced by the EXISTING signature and
    provenance verifier. This check cannot independently authenticate it.
    No success event from historical STAGING can substitute for a DEV event.
    Matching one event is NOT an authorization, review or deployment GO.
    """
    if type(request) is not PromotionRequest or request.target_stage != "prod":
        raise DeploymentPolicyError("direct PROD preflight requires PROD request")
    if type(trusted_release) is not TrustedRelease:
        raise DeploymentPolicyError("direct PROD preflight requires verified release")
    if (
        trusted_release.release_version != request.release_version
        or trusted_release.source_sha != request.source_sha
        or trusted_release.oci_repository != request.oci_repository
        or trusted_release.manifest_digest != request.manifest_digest
        or trusted_release.exact_image_reference != request.exact_image_reference
    ):
        raise DeploymentPolicyError("direct PROD signed release identity differs")
    if type(dev_events) not in (tuple, list):
        raise DeploymentPolicyError("direct PROD preflight requires bounded audit collection")
    if len(dev_events) > 10000:
        raise DeploymentPolicyError("direct PROD audit collection exceeds review bound")
    events = dev_events
    if any(type(event) is not AuditEvent for event in events):
        raise DeploymentPolicyError("direct PROD requires trusted audit event objects")
    matches = [
        event for event in events
        if event.event_type == "promotion_succeeded"
        and event.result == "succeeded"
        and event.stage == "dev"
        and event.release_version == request.release_version
        and event.source_sha == request.source_sha
        and event.oci_repository == request.oci_repository
        and event.digest == request.manifest_digest
    ]
    if len(matches) != 1:
        raise DeploymentPolicyError("direct PROD requires one exact DEV success")
    event = matches[0]
    return DirectProdPrerequisite(
        version=request.release_version,
        source_sha=request.source_sha,
        repository=request.oci_repository,
        digest=request.manifest_digest,
        dev_event_id=event.event_id,
    )
