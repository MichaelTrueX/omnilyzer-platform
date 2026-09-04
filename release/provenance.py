#!/usr/bin/env python3
"""Create deterministic release evidence after zot returns an immutable digest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    from .release_plan import load_json
    from .verify_handoff import verify
    from .vulnerability_policy import canonical_bytes
except ImportError:
    from release_plan import load_json
    from verify_handoff import verify
    from vulnerability_policy import canonical_bytes

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create(handoff: Path, publication_path: Path, output: Path, repository: Path,
           version: str, source_sha: str) -> None:
    checked = verify(handoff, repository, version, source_sha, require_production_evidence=True)
    plan, build = checked["plan"], checked["build_manifest"]
    if (publication_path.name != "oci-publication.json" or publication_path.is_symlink()
            or not publication_path.is_file()
            or {path.name for path in publication_path.parent.iterdir()} != {"oci-publication.json"}):
        raise ValueError("OCI publication handoff must contain exactly oci-publication.json")
    publication = load_json(publication_path)
    publication_keys = {"schema_version", "registry", "repository", "tag", "manifest_digest"}
    if not isinstance(publication, dict) or set(publication) != publication_keys or publication["schema_version"] != 1:
        raise ValueError("OCI publication differs from its closed schema")
    if publication["registry"] != plan["registries"]["zot_origin"] or publication["repository"] != plan["packages"]["oci"]["repository"]:
        raise ValueError("OCI publication destination mismatch")
    if publication["tag"] != version or not DIGEST_RE.fullmatch(publication["manifest_digest"]):
        raise ValueError("OCI publication tag/digest invalid")
    if publication["manifest_digest"] != build["expected_oci_manifest_digest"]:
        raise ValueError("registry-derived OCI digest differs from locally built manifest")
    artifact_hashes = {key: value["sha256"] for key, value in build["artifacts"].items()}
    provenance = {
        "schema_version": 1,
        "statement_type": "https://omnilyzer.ai/release-provenance/v1",
        "claim": "build-once release evidence; no formal SLSA level is asserted",
        "platform_version": version, "source_commit": source_sha,
        "workflow_ref": "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main",
        "subjects": {
            "python_wheel_sha256": artifact_hashes["python"],
            "npm_tarball_sha256": artifact_hashes["npm"],
            "oci_archive_sha256": artifact_hashes["oci"],
            "oci_manifest_digest": publication["manifest_digest"],
            "sbom_sha256": {key: value["sha256"] for key, value in build["sboms"].items()},
            "vulnerability_policy_sha256": build["vulnerability_policy_sha256"],
            "vulnerability_policy_result_sha256": build["vulnerability_policy_result_sha256"],
        },
    }
    if output.exists() or output.is_symlink():
        raise ValueError("release evidence output must be new")
    output.mkdir(parents=True)
    provenance_path = output / "release-provenance.json"
    provenance_path.write_bytes(canonical_bytes(provenance))
    release_manifest = {
        "schema_version": 1, "platform_version": version, "source_commit": source_sha,
        "python": {"identity": plan["packages"]["python"], "artifact": build["artifacts"]["python"]},
        "npm": {"identity": plan["packages"]["npm"], "artifact": build["artifacts"]["npm"]},
        "oci": {
            "registry": publication["registry"],
            "repository": publication["repository"], "tag": publication["tag"],
            "manifest_digest": publication["manifest_digest"],
            "deployment_identity": f"{publication['repository']}@{publication['manifest_digest']}",
        },
        "sbom_sha256": {key: value["sha256"] for key, value in build["sboms"].items()},
        "vulnerability_policy_sha256": build["vulnerability_policy_sha256"],
        "vulnerability_policy_result_sha256": build["vulnerability_policy_result_sha256"],
        "vulnerability_report_sha256": {
            key: value["sha256"] for key, value in build["vulnerability_reports"].items()
        },
        "grype_database_status_sha256": build["grype_database_status_sha256"],
        "release_plan_sha256": build["plan_sha256"],
        "build_manifest_sha256": _sha(handoff / "build-manifest.json"),
        "tool_versions": build["tool_versions"],
        "evidence": {"identity": plan["packages"]["evidence"],
                     "artifact_filename": "release-evidence.tar.gz"},
        "provenance": {"filename": provenance_path.name, "sha256": _sha(provenance_path)},
        "signing": {
            "method": "keyless Sigstore/Fulcio/Rekor with GitHub OIDC",
            "release_manifest_bundle": "release-manifest.sigstore.json",
            "provenance_bundle": "release-provenance.sigstore.json",
            "oci_signature": f"{publication['repository']}@{publication['manifest_digest']}",
        },
    }
    (output / "release-manifest.json").write_bytes(canonical_bytes(release_manifest))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--oci-publication", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    create(args.handoff, args.oci_publication, args.output, args.repository, args.version, args.source_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
