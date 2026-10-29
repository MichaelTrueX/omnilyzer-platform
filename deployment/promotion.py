"""File: deployment/promotion.py

Purpose: Original Task013 signed release identity and immutable promotion
requests. Additive Analytics external Git source claims are verified ONLY when
present in BOTH original Cosign-verified release evidence blobs. This does NOT
change the canary promotion allowlist or original Task014 installed executor.

Related: deployment/policy.py, deployment/release_consumer.py,
deployment/saas_product_contract.py,
release/analytics_release_source_binding.py, release/provenance.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .policy import (
    APPROVED_OCI_ORIGIN,
    APPROVED_OCI_HOST,
    EXPECTED_CERTIFICATE_IDENTITY,
    EXPECTED_CERTIFICATE_ISSUER,
    EXPECTED_RELEASE_WORKFLOW,
    SCHEMA_VERSION,
    DeploymentPolicyError,
    canonical_bytes,
    closed_object,
    exact_image_reference,
    nonempty_string,
    validate_digest,
    validate_identity,
    validate_repository,
    validate_semver,
    validate_sha256,
    validate_source_sha,
    validate_stage,
)


REQUEST_FIELDS = {
    "schema_version", "release_version", "source_sha", "oci_repository",
    "manifest_digest", "exact_image_reference", "release_manifest_sha256",
    "provenance_sha256", "originating_release_run_id", "target_stage", "requested_by",
}
RELEASE_EXECUTION_FIELDS = {
    "repository", "repository_id", "workflow_ref", "workflow_sha",
    "run_id", "run_attempt", "event_name", "source_commit",
}
RELEASE_REPOSITORY = "MichaelTrueX/omnilyzer-platform"
RELEASE_REPOSITORY_ID = 1350104356
MAX_GITHUB_NUMBER = 2**63 - 1


@dataclass(frozen=True)
class PromotionRequest:
    schema_version: int
    release_version: str
    source_sha: str
    oci_repository: str
    manifest_digest: str
    exact_image_reference: str
    release_manifest_sha256: str
    provenance_sha256: str
    originating_release_run_id: int
    target_stage: str
    requested_by: str

    @classmethod
    def from_dict(cls, value: Any) -> "PromotionRequest":
        data = closed_object(value, REQUEST_FIELDS, "promotion request")
        if data["schema_version"] != SCHEMA_VERSION:
            raise DeploymentPolicyError("unsupported promotion-request schema_version")
        version = validate_semver(data["release_version"])
        source_sha = validate_source_sha(data["source_sha"])
        repository = validate_repository(data["oci_repository"])
        digest = validate_digest(data["manifest_digest"])
        expected_reference = exact_image_reference(repository, digest)
        if data["exact_image_reference"] != expected_reference:
            raise DeploymentPolicyError("exact_image_reference does not bind the approved repository and digest")
        release_manifest_sha256 = validate_sha256(
            data["release_manifest_sha256"], "release_manifest_sha256",
        )
        provenance_sha256 = validate_sha256(data["provenance_sha256"], "provenance_sha256")
        run_id = data["originating_release_run_id"]
        if type(run_id) is not int or not 0 < run_id <= MAX_GITHUB_NUMBER:
            raise DeploymentPolicyError("originating_release_run_id must be a positive integer")
        return cls(
            SCHEMA_VERSION, version, source_sha, repository, digest, expected_reference,
            release_manifest_sha256, provenance_sha256, run_id,
            validate_stage(data["target_stage"]), validate_identity(data["requested_by"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


# Section: immutable signed external-source claim. Values are only returned
# AFTER the original Sigstore and OCI signature verification gates pass.
ANALYTICS_REPOSITORY = "omnilyzer/analytics"
ANALYTICS_SOURCE_REPOSITORY = "MichaelTrueX/omnilyzer"
SIGNED_SOURCE_FIELDS = frozenset({
    "schema_version", "product_id", "platform_source_commit", "platform_tree",
    "source_repository", "source_commit", "source_tree",
    "source_manifest_sha256", "source_binding_sha256", "source_files_verified",
    "dockerfile_sha256", "dockerignore_sha256", "oci_test_source_sha256",
    "build_context_sha256", "oci_repository", "oci_archive_sha256",
    "oci_manifest_digest", "product_profile_sha256", "runtime_profile_sha256",
    "readiness_path",
})
SIGNED_HASH_FIELDS = frozenset(name for name in SIGNED_SOURCE_FIELDS if name.endswith("_sha256"))
SIGNED_GIT_FIELDS = frozenset({
    "platform_source_commit", "platform_tree", "source_commit", "source_tree",
})


@dataclass(frozen=True)
class SignedExternalSource:
    """Immutable projection of a claim contained in verified signed blobs."""

    product_id: str
    source_repository: str
    source_commit: str
    source_tree: str
    build_context_sha256: str
    product_profile_sha256: str
    runtime_profile_sha256: str
    oci_archive_sha256: str
    oci_manifest_digest: str
    claim_sha256: str


@dataclass(frozen=True)
class TrustedRelease:
    """A release bound to the original verified signer and OCI digest."""

    release_version: str
    source_sha: str
    oci_repository: str
    manifest_digest: str
    exact_image_reference: str
    release_workflow: str
    certificate_identity: str
    certificate_issuer: str
    external_source: SignedExternalSource | None = None


def _verified_external_source_claim(
    manifest: dict[str, Any], provenance: dict[str, Any], request: PromotionRequest,
) -> SignedExternalSource | None:
    """Parse a closed claim inside the ORIGINAL verified evidence only.

    Presence alone is NOT proof of signature. The caller MUST complete the
    original Sigstore+OCI signature and certificate identity verification
    before returning a TrustedRelease containing this immutable claim.
    """
    if request.oci_repository != ANALYTICS_REPOSITORY:
        if "external_source" in manifest or "external_source" in provenance:
            raise DeploymentPolicyError("unexpected external source in canary evidence")
        return None
    claim = provenance.get("external_source")
    mirror = manifest.get("external_source")
    if (type(claim) is not dict or type(mirror) is not dict
            or set(claim) != SIGNED_SOURCE_FIELDS or set(mirror) != SIGNED_SOURCE_FIELDS
            or canonical_bytes(claim) != canonical_bytes(mirror)
            or type(claim["schema_version"]) is not int or claim["schema_version"] != 1
            or claim["product_id"] != "analytics"
            or claim["source_repository"] != ANALYTICS_SOURCE_REPOSITORY
            or claim["oci_repository"] != ANALYTICS_REPOSITORY
            or type(claim["source_files_verified"]) is not int
            or claim["source_files_verified"] != 72
            or claim["readiness_path"] != "/readyz"
            or claim["platform_source_commit"] != request.source_sha
            or claim["oci_manifest_digest"] != request.manifest_digest):
        raise DeploymentPolicyError("signed external-source claim is invalid")
    for key in SIGNED_HASH_FIELDS:
        validate_sha256(claim[key], key)
    for key in SIGNED_GIT_FIELDS:
        validate_source_sha(claim[key])
    validate_digest(claim["oci_manifest_digest"])
    return SignedExternalSource(
        "analytics", ANALYTICS_SOURCE_REPOSITORY,
        claim["source_commit"], claim["source_tree"],
        claim["build_context_sha256"], claim["product_profile_sha256"],
        claim["runtime_profile_sha256"], claim["oci_archive_sha256"],
        claim["oci_manifest_digest"],
        hashlib.sha256(canonical_bytes(claim)).hexdigest(),
    )


def _json_object(raw: bytes, context: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise DeploymentPolicyError(f"{context} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise DeploymentPolicyError(f"{context} must be an object")
    return value


def verify_release_evidence(
    request: PromotionRequest,
    release_manifest_bytes: bytes,
    provenance_bytes: bytes,
    sigstore_result: Any,
    oci_signature_result: Any,
) -> TrustedRelease:
    if hashlib.sha256(release_manifest_bytes).hexdigest() != request.release_manifest_sha256:
        raise DeploymentPolicyError("release manifest hash differs from the promotion request")
    if hashlib.sha256(provenance_bytes).hexdigest() != request.provenance_sha256:
        raise DeploymentPolicyError("provenance hash differs from the promotion request")
    manifest = _json_object(release_manifest_bytes, "release manifest")
    provenance = _json_object(provenance_bytes, "release provenance")
    original_fields = {
        "schema_version", "statement_type", "claim", "platform_version",
        "source_commit", "execution", "subjects",
    }
    if request.oci_repository == ANALYTICS_REPOSITORY:
        original_fields.add("external_source")
    closed_object(provenance, original_fields, "release provenance")
    execution = closed_object(provenance.get("execution"), RELEASE_EXECUTION_FIELDS,
                              "signed release execution")
    if (type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 2
            or type(provenance.get("schema_version")) is not int or provenance["schema_version"] != 2
            or provenance.get("statement_type") != "https://omnilyzer.ai/release-provenance/v2"
            or execution["repository"] != RELEASE_REPOSITORY
            or type(execution["repository"]) is not str
            or type(execution["repository_id"]) is not int
            or execution["repository_id"] != RELEASE_REPOSITORY_ID
            or type(execution["workflow_ref"]) is not str
            or execution["workflow_ref"] != EXPECTED_RELEASE_WORKFLOW
            or type(execution["workflow_sha"]) is not str
            or execution["workflow_sha"] != request.source_sha
            or type(execution["event_name"]) is not str
            or execution["event_name"] != "workflow_dispatch"
            or type(execution["source_commit"]) is not str
            or execution["source_commit"] != request.source_sha
            or any(type(execution[name]) is not int or not 0 < execution[name] <= MAX_GITHUB_NUMBER
                   for name in ("run_id", "run_attempt"))
            or execution["run_id"] != request.originating_release_run_id
            or manifest.get("provenance") != {
                "filename": "release-provenance.json",
                "sha256": hashlib.sha256(provenance_bytes).hexdigest(),
            }):
        raise DeploymentPolicyError("signed release execution or evidence schema differs from promotion")
    try:
        manifest_oci = manifest["oci"]
        subjects = provenance["subjects"]
        if not isinstance(manifest_oci, dict) or not isinstance(subjects, dict):
            raise TypeError
        if request.oci_repository == ANALYTICS_REPOSITORY:
            if manifest_oci["repository"] != ANALYTICS_REPOSITORY:
                raise DeploymentPolicyError("signed product repository mismatch")
            manifest_reference = (
                f"{APPROVED_OCI_HOST}/{ANALYTICS_REPOSITORY}@"
                f"{validate_digest(manifest_oci['manifest_digest'])}"
            )
        else:
            manifest_reference = exact_image_reference(
                manifest_oci["repository"], manifest_oci["manifest_digest"],
            )
    except (KeyError, TypeError, DeploymentPolicyError) as exc:
        raise DeploymentPolicyError("release evidence lacks a valid immutable OCI identity") from exc
    expected = (
        manifest.get("platform_version") == request.release_version
        and manifest.get("source_commit") == request.source_sha
        and manifest_oci.get("registry") == APPROVED_OCI_ORIGIN
        and manifest_oci.get("repository") == request.oci_repository
        and manifest_oci.get("manifest_digest") == request.manifest_digest
        and manifest_oci.get("deployment_identity")
        == f"{request.oci_repository}@{request.manifest_digest}"
        and manifest_reference == request.exact_image_reference
        and provenance.get("platform_version") == request.release_version
        and provenance.get("source_commit") == request.source_sha
        and subjects.get("oci_manifest_digest") == request.manifest_digest
    )
    if not expected:
        raise DeploymentPolicyError("release manifest or provenance disagrees with the candidate")
    signed_source = _verified_external_source_claim(manifest, provenance, request)
    if signed_source is not None and subjects.get("oci_archive_sha256") != signed_source.oci_archive_sha256:
        raise DeploymentPolicyError("signed OCI archive differs from external source claim")
    sigstore = closed_object(
        sigstore_result,
        {"release_manifest_verified", "provenance_verified", "certificate_identity", "issuer"},
        "Sigstore verification result",
    )
    if (sigstore["release_manifest_verified"] is not True
            or sigstore["provenance_verified"] is not True
            or sigstore["certificate_identity"] != EXPECTED_CERTIFICATE_IDENTITY
            or sigstore["issuer"] != EXPECTED_CERTIFICATE_ISSUER):
        raise DeploymentPolicyError("Sigstore verification does not match the trusted release identity")
    oci = closed_object(
        oci_signature_result,
        {"verified", "repository", "manifest_digest", "certificate_identity", "issuer"},
        "OCI signature verification result",
    )
    if (oci["verified"] is not True or oci["repository"] != request.oci_repository
            or oci["manifest_digest"] != request.manifest_digest
            or oci["certificate_identity"] != EXPECTED_CERTIFICATE_IDENTITY
            or oci["issuer"] != EXPECTED_CERTIFICATE_ISSUER):
        raise DeploymentPolicyError("OCI signature verification does not match the candidate")
    return TrustedRelease(
        request.release_version, request.source_sha, request.oci_repository,
        request.manifest_digest, request.exact_image_reference, EXPECTED_RELEASE_WORKFLOW,
        EXPECTED_CERTIFICATE_IDENTITY, EXPECTED_CERTIFICATE_ISSUER,
        signed_source,
    )


def load_request(path: Path) -> PromotionRequest:
    if path.is_symlink() or not path.is_file():
        raise DeploymentPolicyError("promotion request must be a regular file")
    return PromotionRequest.from_dict(json.loads(path.read_text(encoding="utf-8")))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--provenance-sha256", required=True)
    parser.add_argument("--originating-release-run-id", required=True, type=int)
    parser.add_argument("--target-stage", required=True)
    parser.add_argument("--requested-by", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    repository = "omnilyzer/task013-release-canary"
    digest = validate_digest(args.manifest_digest)
    request = PromotionRequest.from_dict({
        "schema_version": SCHEMA_VERSION,
        "release_version": args.release_version,
        "source_sha": args.source_sha,
        "oci_repository": repository,
        "manifest_digest": digest,
        "exact_image_reference": exact_image_reference(repository, digest),
        "release_manifest_sha256": args.release_manifest_sha256,
        "provenance_sha256": args.provenance_sha256,
        "originating_release_run_id": args.originating_release_run_id,
        "target_stage": args.target_stage,
        "requested_by": nonempty_string(args.requested_by, "requested_by"),
    })
    if args.output.exists() or args.output.is_symlink():
        raise DeploymentPolicyError("promotion request output must be new")
    args.output.write_bytes(request.canonical_bytes())
    args.output.chmod(0o600)
    print(request.sha256())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
