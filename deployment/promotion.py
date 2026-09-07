"""Immutable promotion requests and Task 013 release-evidence binding."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .policy import (
    APPROVED_OCI_ORIGIN,
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
        if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
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


@dataclass(frozen=True)
class TrustedRelease:
    release_version: str
    source_sha: str
    oci_repository: str
    manifest_digest: str
    exact_image_reference: str
    release_workflow: str
    certificate_identity: str
    certificate_issuer: str


def _json_object(raw: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
    try:
        manifest_oci = manifest["oci"]
        subjects = provenance["subjects"]
        if not isinstance(manifest_oci, dict) or not isinstance(subjects, dict):
            raise TypeError
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
        and provenance.get("workflow_ref") == EXPECTED_RELEASE_WORKFLOW
        and subjects.get("oci_manifest_digest") == request.manifest_digest
    )
    if not expected:
        raise DeploymentPolicyError("release manifest or provenance disagrees with the candidate")
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
