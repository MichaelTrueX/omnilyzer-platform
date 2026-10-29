#!/usr/bin/env python3
"""File: release/analytics_release_source_binding.py

Purpose: Bind an immutable committed Analytics Git context and actual OCI
manifest to the ORIGINAL Task013 release provenance BEFORE its existing
Cosign/Forgejo signing step. This is a source-evidence adapter, not a signer,
registry publisher, deployment controller or authorization gate.

Related complete files:
  release/analytics_source_admission.py (M01 source pin and 72 Git blobs)
  release/analytics_task013_build_input.py (M05 review input)
  release/analytics_oci_context.py (M01 immutable Git-only Docker context)
  release/analytics_oci_archive.py (M05 OCI manifest and layer validation)
  release/provenance.py (original Task013 evidence creator, unchanged)
  deployment/promotion.py (original signed evidence verifier, unchanged)
  deployment/release_consumer.py (original Task014 canary, unchanged)
  release/tests/test_analytics_release_source_binding.py
  .github/workflows/platform-release.yml (protected signer, unchanged)

Security: All outputs explicitly remain UNSIGNED and unauthorized. Only
release-manifest and release-provenance bytes prepared for future use by the
ORIGINAL protected-main signer are produced; no signed evidence is claimed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any

from deployment.policy import DeploymentPolicyError, canonical_bytes
from release.analytics_task013_build_input import build_input
from release.analytics_oci_context import snapshot_committed_tree
from release.analytics_oci_archive import verify_archive

ERROR = "TASK013_ANALYTICS_SOURCE_BINDING_DENIED"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
READ_LIMIT = 4 * 1024 * 1024
CHUNK = 1024 * 1024
REQUIRED_SOURCE_CLAIM = frozenset({
    "schema_version", "product_id", "platform_source_commit",
    "platform_tree", "source_repository", "source_commit", "source_tree",
    "source_manifest_sha256", "source_binding_sha256",
    "source_files_verified", "dockerfile_sha256", "dockerignore_sha256",
    "oci_test_source_sha256", "build_context_sha256", "oci_repository",
    "oci_archive_sha256", "oci_manifest_digest",
    "product_profile_sha256", "runtime_profile_sha256",
    "readiness_path",
})


def _canonical_json(raw: bytes, context: str) -> dict[str, Any]:
    """Read bounded, duplicate-free original Task013 JSON evidence."""
    if type(raw) is not bytes or not 0 < len(raw) <= READ_LIMIT:
        raise DeploymentPolicyError(f"{context}: oversized or invalid")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """No last-value-wins ambiguity for a signed identity field."""
        item: dict[str, Any] = {}
        for name, value in pairs:
            if name in item:
                raise DeploymentPolicyError(f"{context}: duplicate field")
            item[name] = value
        return item

    try:
        data = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise DeploymentPolicyError(f"{context}: invalid JSON") from exc
    if type(data) is not dict:
        raise DeploymentPolicyError(f"{context}: must be an object")
    return data


def _hash_existing_regular(path: Path) -> tuple[str, int]:
    """Hash a single opened, regular, non-symlinked input, no path re-open."""
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise DeploymentPolicyError("untrusted release input file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise DeploymentPolicyError("release input not regular")
            digest = hashlib.sha256()
            size = 0
            for data in iter(lambda: stream.read(CHUNK), b""):
                digest.update(data)
                size += len(data)
                if size > 3 * 1024 * 1024 * 1024:
                    raise DeploymentPolicyError("release input too large")
            return digest.hexdigest(), size
    except OSError as exc:
        raise DeploymentPolicyError("unable to read release input") from exc


def prepare_source_claim(
    analytics_checkout: Path, immutable_context: Path, oci_archive: Path,
    *, platform_root: Path,
) -> dict[str, Any]:
    """Recheck one exact source→build-context→OCI identity without signing.

    The existing original Task013 protected-main workflow MUST build its
    published image directly from the immutable context it verifies.
    A claim alone cannot prove which build context an arbitrary builder used.
    """
    if any(not isinstance(v, Path) for v in (
        analytics_checkout, immutable_context, oci_archive, platform_root
    )):
        raise DeploymentPolicyError("release path input has wrong type")

    source = build_input(analytics_checkout, platform_root=platform_root)
    # Compare the supplied builder input with an independently regenerated
    # canonical archive of ONLY the exact committed Git blobs.
    with tempfile.TemporaryDirectory(prefix="m05-task013-source-binding-") as root:
        regenerated = Path(root) / "verified-context.tar"
        context_receipt = snapshot_committed_tree(
            analytics_checkout, source["analytics_source_commit"], regenerated,
        )
        expected_context_sha = context_receipt["context_sha256"]
        expected_size = regenerated.stat().st_size
        supplied_sha, supplied_size = _hash_existing_regular(immutable_context)
        if (supplied_sha != expected_context_sha or supplied_size != expected_size
                or context_receipt["source_commit"] != source["analytics_source_commit"]
                or context_receipt["release_authorized"] is not False
                or context_receipt["deployment_authorized"] is not False):
            raise DeploymentPolicyError("builder context differs from reviewed Git tree")
    # The existing M05 OCI reader checks one manifest and ALL referenced
    # content-addressed layers under the same opened archive descriptor.
    artifact = verify_archive(oci_archive, source)
    if (artifact["source_commit"] != source["analytics_source_commit"]
            or artifact["source_tree"] != source["analytics_tree"]
            or artifact["oci_repository"] != source["oci_repository"]
            or artifact["release_authorized"] is not False
            or artifact["deployment_authorized"] is not False):
        raise DeploymentPolicyError("OCI identity differs from verified source")

    return {
        "schema_version": 1,
        "product_id": "analytics",
        "platform_source_commit": source["platform_source_commit"],
        "platform_tree": source["platform_tree"],
        "source_repository": source["analytics_repository"],
        "source_commit": source["analytics_source_commit"],
        "source_tree": source["analytics_tree"],
        "source_manifest_sha256": source["source_manifest_sha256"],
        "source_binding_sha256": source["source_binding_sha256"],
        "source_files_verified": source["source_files_verified"],
        "dockerfile_sha256": source["dockerfile_sha256"],
        "dockerignore_sha256": source["dockerignore_sha256"],
        "oci_test_source_sha256": source["oci_test_source_sha256"],
        "build_context_sha256": supplied_sha,
        "oci_repository": source["oci_repository"],
        "oci_archive_sha256": artifact["archive_sha256"],
        "oci_manifest_digest": artifact["local_manifest_digest"],
        "product_profile_sha256": source["product_profile_sha256"],
        "runtime_profile_sha256": source["runtime_profile_sha256"],
        "readiness_path": source["readiness_path"],
    }


def prepare_original_signed_evidence_inputs(
    original_manifest: bytes, original_provenance: bytes,
    analytics_checkout: Path, immutable_context: Path, oci_archive: Path,
    *, platform_root: Path,
) -> tuple[bytes, bytes]:
    """Extend ORIGINAL pre-sign Task013 evidence with exact Analytics binding.

    The original release.provenance.create() must have already verified the
    immutable handoff, registry publication, protected platform workflow
    identity and hashes. This step MUST execute before original Cosign signing,
    NEVER after. The original Task014 currently rejects the new product until
    an independently reviewed product-aware release consumer is installed.
    """
    # Never accept a caller-crafted source claim. Recompute it from the exact
    # committed source tree, verified build-context tar and OCI archive.
    verified_source_claim = prepare_source_claim(
        analytics_checkout, immutable_context, oci_archive,
        platform_root=platform_root,
    )
    manifest = _canonical_json(original_manifest, "original release manifest")
    provenance = _canonical_json(original_provenance, "original release provenance")
    if (type(verified_source_claim) is not dict
            or set(verified_source_claim) != REQUIRED_SOURCE_CLAIM
            or verified_source_claim["schema_version"] != 1
            or verified_source_claim["product_id"] != "analytics"
            or verified_source_claim["source_repository"] != "MichaelTrueX/omnilyzer"
            or verified_source_claim["oci_repository"] != "omnilyzer/analytics"
            or verified_source_claim["source_files_verified"] != 72
            or verified_source_claim["readiness_path"] != "/readyz"):
        raise DeploymentPolicyError("external product provenance claim is invalid")
    for name, value in verified_source_claim.items():
        if name.endswith("_sha256") or name in {"source_binding_sha256", "source_manifest_sha256"}:
            if type(value) is not str or SHA256.fullmatch(value) is None:
                raise DeploymentPolicyError("external source hash invalid")
    for name in ("source_commit", "platform_source_commit", "source_tree", "platform_tree"):
        value = verified_source_claim[name]
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise DeploymentPolicyError("external Git identity invalid")
    if (type(verified_source_claim["oci_manifest_digest"]) is not str
            or DIGEST.fullmatch(verified_source_claim["oci_manifest_digest"]) is None):
        raise DeploymentPolicyError("external OCI digest invalid")
    if (manifest.get("schema_version") != 2
            or provenance.get("schema_version") != 2
            or provenance.get("statement_type") !=
            "https://omnilyzer.ai/release-provenance/v2"
            or "external_source" in manifest or "external_source" in provenance
            or set(provenance) != {
                "schema_version", "statement_type", "claim",
                "platform_version", "source_commit", "execution", "subjects"
            }
            or manifest.get("source_commit") != verified_source_claim["platform_source_commit"]
            or provenance.get("source_commit") != verified_source_claim["platform_source_commit"]
            or manifest.get("source_commit") != provenance.get("source_commit")
            or manifest.get("platform_version") != provenance.get("platform_version")
            or manifest.get("provenance") != {
                "filename": "release-provenance.json",
                "sha256": hashlib.sha256(original_provenance).hexdigest(),
            }):
        raise DeploymentPolicyError("original Task013 provenance chain is invalid")
    execution = provenance.get("execution")
    if (type(execution) is not dict
            or execution.get("source_commit") != verified_source_claim["platform_source_commit"]
            or execution.get("workflow_sha") != verified_source_claim["platform_source_commit"]
            or execution.get("repository") != "MichaelTrueX/omnilyzer-platform"
            or execution.get("repository_id") != 1350104356
            or execution.get("workflow_ref") != (
                "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml"
                "@refs/heads/main"
            )
            or execution.get("event_name") != "workflow_dispatch"):
        raise DeploymentPolicyError("original protected-main signer identity mismatch")
    oci = manifest.get("oci")
    subjects = provenance.get("subjects")
    if (type(oci) is not dict or type(subjects) is not dict
            or oci.get("registry") != "https://oci-dev.omnilyzer.ai"
            or oci.get("repository") != verified_source_claim["oci_repository"]
            or oci.get("manifest_digest") != verified_source_claim["oci_manifest_digest"]
            or subjects.get("oci_archive_sha256") != verified_source_claim["oci_archive_sha256"]
            or subjects.get("oci_manifest_digest") != verified_source_claim["oci_manifest_digest"]
            or oci.get("deployment_identity") != (
                f'{verified_source_claim["oci_repository"]}@'
                f'{verified_source_claim["oci_manifest_digest"]}'
            )):
        raise DeploymentPolicyError("published OCI manifest is not the reviewed source subject")

    # The same immutable external-source claim is embedded in the ORIGINAL
    # provenance and manifest. The existing provenance-hash chain is renewed
    # BEFORE the existing Cosign sign-blob. No signing is performed here.
    manifest["external_source"] = verified_source_claim.copy()
    provenance["external_source"] = verified_source_claim.copy()
    updated_provenance = canonical_bytes(provenance)
    manifest["provenance"] = {
        "filename": "release-provenance.json",
        "sha256": hashlib.sha256(updated_provenance).hexdigest(),
    }
    return canonical_bytes(manifest), updated_provenance


def main() -> int:
    """Materialize a source claim only, no signer or live registry requests."""
    parser = argparse.ArgumentParser(description="Review-only original Task013 Analytics signed-source input")
    parser.add_argument("--analytics-checkout", required=True, type=Path)
    parser.add_argument("--immutable-context", required=True, type=Path)
    parser.add_argument("--oci-archive", required=True, type=Path)
    parser.add_argument("--original-evidence-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        if (args.original_evidence_dir is None) != (args.output_dir is None):
            raise DeploymentPolicyError("original evidence and output must be paired")
        if args.original_evidence_dir is not None:
            original = args.original_evidence_dir
            destination = args.output_dir
            if (original.is_symlink() or not original.is_dir()
                    or destination.exists() or destination.is_symlink()):
                raise DeploymentPolicyError("original evidence or new output path invalid")
            if {p.name for p in original.iterdir()} != {
                "release-manifest.json", "release-provenance.json"
            }:
                raise DeploymentPolicyError("original unsigned Task013 evidence files differ")
            manifest_path = original / "release-manifest.json"
            provenance_path = original / "release-provenance.json"
            if (manifest_path.is_symlink() or provenance_path.is_symlink()
                    or any(p.stat().st_size > READ_LIMIT for p in (manifest_path, provenance_path))):
                raise DeploymentPolicyError("original unsigned evidence paths are unsafe")
            manifest, provenance = prepare_original_signed_evidence_inputs(
                manifest_path.read_bytes(), provenance_path.read_bytes(),
                args.analytics_checkout, args.immutable_context, args.oci_archive,
                platform_root=Path(__file__).resolve().parents[1],
            )
            # NEVER overwrite or silently sign existing blobs. This directory
            # contains bytes for the ORIGINAL Cosign signer to consume later.
            destination.mkdir(mode=0o700)
            try:
                for name, payload in (
                    ("release-manifest.json", manifest),
                    ("release-provenance.json", provenance),
                ):
                    fd = os.open(destination / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(payload)
            except BaseException:
                for path in destination.iterdir():
                    path.unlink()
                destination.rmdir()
                raise
            print(canonical_bytes({
                "schema_version": 1,
                "original_task013_unsigned_evidence_prepared": True,
                "release_authorized": False,
                "deployment_authorized": False,
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "provenance_sha256": hashlib.sha256(provenance).hexdigest(),
            }).decode("utf-8"))
        else:
            result = prepare_source_claim(
                args.analytics_checkout, args.immutable_context, args.oci_archive,
                platform_root=Path(__file__).resolve().parents[1],
            )
            # Never label this as signed: it is prepared only for a future
            # authorized original Task013 Cosign signing step.
            print(canonical_bytes({
                "schema_version": 1, "claim": result, "signed": False,
                "release_authorized": False, "deployment_authorized": False,
            }).decode("utf-8"))
    except (DeploymentPolicyError, OSError, ValueError) as exc:
        print(f"{ERROR}: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
