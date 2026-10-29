"""File: deployment/analytics_signed_release_consumer.py

Purpose: Fail-closed, READ-ONLY original Task014 consumption of the genuine
         Analytics-only Task013 signed schema-v1 evidence and OCI digest.
         The original canary Task014 schema-v2 consumer remains unchanged.
Related: deployment/release_consumer.py (original TLS and credential controls),
         deployment/promotion.py (signed external-source claim validation),
         deployment/analytics_signed_source_pin.py (independent source pin),
         deployment/blob_verifier.py and deployment/oci_verifier.py (original
         Sigstore and Cosign implementations),
         release/analytics_release_evidence.py (original schema-v1 producer),
         release/analytics_forgejo_evidence.py (archive producer),
         deployment/tests/test_analytics_signed_release_consumer.py.

Sections:
  1. Exactly one reviewed, immutable release and bounded archive grammar.
  2. Actual Task013 schema-v1 manifest/provenance and scanner hash validation.
  3. Independent original Sigstore/OCI verification and source-pin receipt.
  4. Original authenticated registry reads; never broker/executor authority.

IMPORTANT: These helpers do NOT return a privileged ExecutorRequest, perform
Docker operations, install secrets, authorize OIDC, replay, or activate Nginx.
All public result types remain *review only*. No caller-constructed
TrustedRelease or verifier result is permitted at the privileged boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import io
import tarfile
from typing import Any

from .analytics_signed_source_pin import (
    AnalyticsSourceReviewReceipt, review_signed_analytics_source,
)
from .policy import (
    APPROVED_OCI_ORIGIN, EXPECTED_CERTIFICATE_IDENTITY,
    EXPECTED_CERTIFICATE_ISSUER, EXPECTED_RELEASE_WORKFLOW,
    DeploymentPolicyError, closed_object, validate_sha256,
)
from .promotion import (
    ANALYTICS_REPOSITORY, PromotionRequest, TrustedRelease,
    _verified_external_source_claim, RELEASE_EXECUTION_FIELDS,
    RELEASE_REPOSITORY, RELEASE_REPOSITORY_ID,
)
from .release_consumer import (
    ForgejoCredentialProvider, ForgejoReadCredential,
    ReleaseBlobSignatureVerifier, OCISignatureVerifier,
    ZotCredentialProvider, ZotReadCredential, _connection, _credential,
    _get, _json, OCI_MEDIA_TYPE,
)

# Section 1: review exactly the immutable signed 2026-10-29 release.
PINNED_VERSION = "0.15.0"
PINNED_RUN_ID = 40881693662
PINNED_PLATFORM_COMMIT = "b9e22e745ecbaf96dc15998e91d1a74f70e5ad77"
PINNED_DIGEST = "sha256:6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1"
PINNED_IMAGE = f"oci-dev.omnilyzer.ai/{ANALYTICS_REPOSITORY}@{PINNED_DIGEST}"
ERROR = "TASK014_ANALYTICS_SIGNED_EVIDENCE_DENIED"
_SIGNER_METHOD = "keyless Sigstore/Fulcio/Rekor with GitHub OIDC"
_PROVENANCE_TYPE = "https://omnilyzer.ai/analytics-release-provenance/v1"
_SIGNED_FILES = frozenset({
    "release-manifest.json", "release-provenance.json",
    "release-manifest.sigstore.json", "release-provenance.sigstore.json",
})
_SOURCE_FILES = frozenset({"analytics-source-claim.json", "oci-publication.json"})
_SCANNER_FILES = frozenset({
    "oci-sbom.cdx.json", "oci-grype.json", "grype-db-status.json",
    "vulnerability-policy.json",
})
_ARCHIVE_FILES = _SIGNED_FILES | _SOURCE_FILES | _SCANNER_FILES
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
_MAX_SCANNER_BYTES = 128 * 1024 * 1024
_MAX_UNCOMPRESSED = 280 * 1024 * 1024
_MANIFEST_FIELDS = frozenset({
    "schema_version", "product_id", "version", "source_commit",
    "external_source", "oci", "provenance", "signing",
})
_PROVENANCE_FIELDS = frozenset({
    "schema_version", "statement_type", "product_id", "version",
    "source_commit", "execution", "external_source", "subjects",
})


@dataclass(frozen=True, slots=True)
class AnalyticsSignedEvidenceReview:
    """An inert result of successful original-signature checks, NOT deploy authority."""

    release_version: str
    image: str
    release_run_id: int
    manifest_sha256: str
    provenance_sha256: str
    source: AnalyticsSourceReviewReceipt
    signature_verified: bool = True
    deployment_authorized: bool = False


class AnalyticsSignedEvidenceError(DeploymentPolicyError):
    """The reviewed original Task013 Analytics release was not fully verified."""


def _sha(raw: bytes) -> str:
    """Hash one bounded signed or scanner artifact as lowercase SHA256."""
    return hashlib.sha256(raw).hexdigest()


def _analytics_archive(raw: bytes) -> tuple[dict[str, bytes], dict[str, str]]:
    """Stream an authenticated gzip/TAR archive with exact closed file names.

    Return only six bounded evidence files and four scanner *hashes*; scanner
    contents are not retained. Reject links, duplicate names, excess bytes
    and even otherwise well-formed extra archive members.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ARCHIVE_BYTES:
        raise AnalyticsSignedEvidenceError(ERROR)
    extracted: dict[str, bytes] = {}
    scanner_hashes: dict[str, str] = {}
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            with tarfile.open(fileobj=compressed, mode="r|") as stream:
                for member in stream:
                    if (
                        not member.isfile() or member.name not in _ARCHIVE_FILES
                        or member.name in extracted or member.name in scanner_hashes
                        or type(member.size) is not int or member.size < 1
                    ):
                        raise ValueError("invalid archive member")
                    limit = (_MAX_SCANNER_BYTES if member.name in _SCANNER_FILES
                             else _MAX_EVIDENCE_BYTES)
                    total += member.size
                    if member.size > limit or total > _MAX_UNCOMPRESSED:
                        raise ValueError("oversized signed evidence archive")
                    reader = stream.extractfile(member)
                    if reader is None:
                        raise ValueError("missing archive member")
                    hasher = hashlib.sha256()
                    chunks = bytearray() if member.name not in _SCANNER_FILES else None
                    remaining = member.size
                    while remaining:
                        chunk = reader.read(min(65536, remaining))
                        if not chunk:
                            raise ValueError("truncated archive member")
                        hasher.update(chunk)
                        if chunks is not None:
                            chunks.extend(chunk)
                        remaining -= len(chunk)
                    if chunks is None:
                        scanner_hashes[member.name] = hasher.hexdigest()
                    else:
                        extracted[member.name] = bytes(chunks)
    except (OSError, EOFError, ValueError, tarfile.TarError) as exc:
        raise AnalyticsSignedEvidenceError(ERROR) from exc
    if set(extracted) != _SIGNED_FILES | _SOURCE_FILES or set(scanner_hashes) != _SCANNER_FILES:
        raise AnalyticsSignedEvidenceError(ERROR)
    return extracted, scanner_hashes


def _signed_fields(
    evidence: dict[str, bytes], scanner_hashes: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Check actual Analytics Task013 v1 grammar and scanner hash linkage."""
    manifest = _json(evidence["release-manifest.json"], _MANIFEST_FIELDS, schema=1)
    provenance = _json(evidence["release-provenance.json"], _PROVENANCE_FIELDS, schema=1)
    claim = _json(
        evidence["analytics-source-claim.json"],
        frozenset(manifest["external_source"].keys())
        if type(manifest["external_source"]) is dict else frozenset(),
        schema=1,
    )
    receipt = _json(
        evidence["oci-publication.json"],
        frozenset({"schema_version", "registry", "repository", "tag",
                   "manifest_digest"}),
        schema=1,
    )
    execution = closed_object(provenance["execution"], RELEASE_EXECUTION_FIELDS,
                              "signed Analytics release execution")
    subjects = closed_object(
        provenance["subjects"],
        {"oci_repository", "oci_manifest_digest", "oci_archive_sha256",
         "scanner_sha256", "security_exceptions"},
        "signed Analytics subject",
    )
    signed_scanners = closed_object(
        subjects["scanner_sha256"], set(_SCANNER_FILES),
        "signed Analytics scanner hashes",
    )
    if any(validate_sha256(signed_scanners[name], name) != scanner_hashes[name]
           for name in _SCANNER_FILES):
        raise AnalyticsSignedEvidenceError(ERROR)
    if (
        type(manifest["schema_version"]) is not int
        or type(provenance["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or provenance["schema_version"] != 1
        or manifest["product_id"] != "analytics"
        or provenance["product_id"] != "analytics"
        or manifest["version"] != PINNED_VERSION
        or provenance["version"] != PINNED_VERSION
        or manifest["source_commit"] != PINNED_PLATFORM_COMMIT
        or provenance["source_commit"] != PINNED_PLATFORM_COMMIT
        or provenance["statement_type"] != _PROVENANCE_TYPE
        or manifest["external_source"] != claim
        or provenance["external_source"] != claim
        or type(subjects["security_exceptions"]) is not int
        or subjects["security_exceptions"] != 0
        or subjects["oci_repository"] != ANALYTICS_REPOSITORY
        or subjects["oci_manifest_digest"] != PINNED_DIGEST
        or subjects["oci_archive_sha256"] != claim.get("oci_archive_sha256")
        or execution != {
            "repository": RELEASE_REPOSITORY,
            "repository_id": RELEASE_REPOSITORY_ID,
            "workflow_ref": EXPECTED_RELEASE_WORKFLOW,
            "workflow_sha": PINNED_PLATFORM_COMMIT,
            "run_id": PINNED_RUN_ID,
            "run_attempt": execution["run_attempt"],
            "event_name": "workflow_dispatch",
            "source_commit": PINNED_PLATFORM_COMMIT,
        }
        or type(execution["run_attempt"]) is not int
        or not 1 <= execution["run_attempt"] <= 2**63 - 1
        or manifest["oci"] != {
            "registry": APPROVED_OCI_ORIGIN,
            "repository": ANALYTICS_REPOSITORY,
            "manifest_digest": PINNED_DIGEST,
            "deployment_identity": ANALYTICS_REPOSITORY + "@" + PINNED_DIGEST,
        }
        or manifest["provenance"] != {
            "filename": "release-provenance.json",
            "sha256": _sha(evidence["release-provenance.json"]),
        }
        or manifest["signing"] != {
            "method": _SIGNER_METHOD,
            "release_manifest_bundle": "release-manifest.sigstore.json",
            "provenance_bundle": "release-provenance.sigstore.json",
            "oci_signature": ANALYTICS_REPOSITORY + "@" + PINNED_DIGEST,
        }
        or receipt.get("registry") != APPROVED_OCI_ORIGIN
        or receipt.get("repository") != ANALYTICS_REPOSITORY
        or receipt.get("tag") != PINNED_VERSION
        or receipt.get("manifest_digest") != PINNED_DIGEST
    ):
        raise AnalyticsSignedEvidenceError(ERROR)
    return manifest, provenance


def verify_analytics_signed_evidence(
    evidence: dict[str, bytes], scanner_hashes: dict[str, str],
    blob_signatures: ReleaseBlobSignatureVerifier,
    oci_signatures: OCISignatureVerifier, *,
    received_at: int,
) -> AnalyticsSignedEvidenceReview:
    """Apply the original Sigstore and OCI verifiers *before* source review.

    The caller must bind these collaborators to the original verified Task014
    implementations in deployment/blob_verifier.py and oci_verifier.py.
    Synthetic collaborators are acceptable ONLY in isolated regression tests.
    """
    try:
        if (
            type(received_at) is not int or received_at < 1
            or type(evidence) is not dict
            or set(evidence) != _SIGNED_FILES | _SOURCE_FILES
            or type(scanner_hashes) is not dict or set(scanner_hashes) != _SCANNER_FILES
            or not all(type(raw) is bytes and 0 < len(raw) <= _MAX_EVIDENCE_BYTES
                       for raw in evidence.values())
        ):
            raise ValueError("invalid signed evidence shape")
        manifest, provenance = _signed_fields(evidence, scanner_hashes)
        # Preserve original Task014 signature-verifier invocation semantics.
        signer = blob_signatures.verify(
            evidence["release-manifest.json"], evidence["release-provenance.json"],
            evidence["release-manifest.sigstore.json"],
            evidence["release-provenance.sigstore.json"],
        )
        oci = oci_signatures.verify(PINNED_IMAGE, received_at)
        closed_object(
            signer,
            {"release_manifest_verified", "provenance_verified",
             "certificate_identity", "issuer"}, "Sigstore result",
        )
        closed_object(
            oci,
            {"verified", "repository", "manifest_digest",
             "certificate_identity", "issuer"}, "OCI signature result",
        )
        if (
            signer["release_manifest_verified"] is not True
            or signer["provenance_verified"] is not True
            or signer["certificate_identity"] != EXPECTED_CERTIFICATE_IDENTITY
            or signer["issuer"] != EXPECTED_CERTIFICATE_ISSUER
            or oci["verified"] is not True
            or oci["repository"] != ANALYTICS_REPOSITORY
            or oci["manifest_digest"] != PINNED_DIGEST
            or oci["certificate_identity"] != EXPECTED_CERTIFICATE_IDENTITY
            or oci["issuer"] != EXPECTED_CERTIFICATE_ISSUER
        ):
            raise ValueError("signature identity mismatch")

        # Internal-only compatibility with the original signed-source parser.
        # This PromotionRequest is NOT a valid canary promotion and cannot be
        # sent to the canary-only original Task014 executor/broker.
        request = PromotionRequest(
            1, PINNED_VERSION, PINNED_PLATFORM_COMMIT, ANALYTICS_REPOSITORY,
            PINNED_DIGEST, PINNED_IMAGE, _sha(evidence["release-manifest.json"]),
            _sha(evidence["release-provenance.json"]), PINNED_RUN_ID,
            "dev", "analytics-signed-evidence-read-only",
        )
        claim = _verified_external_source_claim(manifest, provenance, request)
        if claim is None:
            raise ValueError("Analytics source attestation missing")
        reviewed = review_signed_analytics_source(TrustedRelease(
            PINNED_VERSION, PINNED_PLATFORM_COMMIT, ANALYTICS_REPOSITORY,
            PINNED_DIGEST, PINNED_IMAGE, EXPECTED_RELEASE_WORKFLOW,
            EXPECTED_CERTIFICATE_IDENTITY, EXPECTED_CERTIFICATE_ISSUER, claim,
        ))
        if reviewed.release_authorized or reviewed.deployment_authorized:
            raise ValueError("review must not authorize deployment")
        return AnalyticsSignedEvidenceReview(
            PINNED_VERSION, PINNED_IMAGE, PINNED_RUN_ID,
            _sha(evidence["release-manifest.json"]),
            _sha(evidence["release-provenance.json"]), reviewed,
        )
    except Exception:
        raise AnalyticsSignedEvidenceError(ERROR) from None


def acquire_and_review_analytics_release(
    zot_provider: ZotCredentialProvider,
    forgejo_provider: ForgejoCredentialProvider,
    blob_signatures: ReleaseBlobSignatureVerifier,
    oci_signatures: OCISignatureVerifier, *,
    received_at: int,
    zot_factory=_connection,
    forgejo_factory=_connection,
) -> AnalyticsSignedEvidenceReview:
    """Use existing authenticated TLS registry reads, then verify full evidence.

    This performs ONLY private GETs of the exact pinned digest and fixed
    original Forgejo Analytics evidence version. No Docker, secret or replay
    mutation, publication, Task014 authorization or return of TrustedRelease.
    """
    try:
        zot_token = _credential(
            zot_provider.zot_read_credential(), ZotReadCredential, received_at,
        )
        # _get keeps original TLS CA/hostname, no redirects, bounded headers.
        body, headers = _get(
            "zot", PINNED_DIGEST, zot_token, zot_factory, product="analytics",
        )
        if (
            headers.get("docker-content-digest") != PINNED_DIGEST
            or "sha256:" + _sha(body) != PINNED_DIGEST
        ):
            raise ValueError("OCI digest mismatch")
        oci_manifest = _json(
            body, frozenset({"schemaVersion", "mediaType", "config", "layers"}),
            schema=None,
        )
        if oci_manifest["schemaVersion"] != 2 or oci_manifest["mediaType"] != OCI_MEDIA_TYPE:
            raise ValueError("OCI media type mismatch")
        forgejo_token = _credential(
            forgejo_provider.forgejo_read_credential(),
            ForgejoReadCredential, received_at,
        )
        archive, _ = _get(
            "forgejo", PINNED_VERSION, forgejo_token,
            forgejo_factory, product="analytics",
        )
        evidence, scanner_hashes = _analytics_archive(archive)
        return verify_analytics_signed_evidence(
            evidence, scanner_hashes, blob_signatures, oci_signatures,
            received_at=received_at,
        )
    except Exception:
        raise AnalyticsSignedEvidenceError(ERROR) from None
