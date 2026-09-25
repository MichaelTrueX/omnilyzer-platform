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
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = "MichaelTrueX/omnilyzer-platform"
REPOSITORY_ID = 1350104356
WORKFLOW_REF = REPOSITORY + "/.github/workflows/platform-release.yml@refs/heads/main"
MAX_GITHUB_NUMBER = 2**63 - 1


def _github_number(value: str, name: str) -> int:
    if type(value) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", value):
        raise ValueError(f"{name} must be a positive decimal GitHub identifier")
    number = int(value)
    if number > MAX_GITHUB_NUMBER:
        raise ValueError(f"{name} exceeds the supported GitHub identifier range")
    return number


def release_execution(*, repository: str, repository_id: str, workflow_ref: str,
                      workflow_sha: str, run_id: str, run_attempt: str,
                      event_name: str, source_commit: str) -> dict[str, object]:
    """Validate the exact workflow context before it enters signed evidence."""
    if (type(repository) is not str or repository != REPOSITORY
            or _github_number(repository_id, "repository_id") != REPOSITORY_ID
            or type(workflow_ref) is not str or workflow_ref != WORKFLOW_REF
            or type(workflow_sha) is not str or SHA_RE.fullmatch(workflow_sha) is None
            or workflow_sha == "0" * 40 or workflow_sha != source_commit
            or type(event_name) is not str or event_name != "workflow_dispatch"
            or type(source_commit) is not str or SHA_RE.fullmatch(source_commit) is None
            or source_commit == "0" * 40):
        raise ValueError("release execution differs from the reviewed GitHub workflow policy")
    return {
        "repository": repository, "repository_id": REPOSITORY_ID,
        "workflow_ref": workflow_ref, "workflow_sha": workflow_sha,
        "run_id": _github_number(run_id, "run_id"),
        "run_attempt": _github_number(run_attempt, "run_attempt"),
        "event_name": event_name, "source_commit": source_commit,
    }


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create(handoff: Path, publication_path: Path, output: Path, repository: Path,
           version: str, source_sha: str, *, execution: dict[str, object]) -> None:
    if type(execution) is not dict or set(execution) != {
            "repository", "repository_id", "workflow_ref", "workflow_sha",
            "run_id", "run_attempt", "event_name", "source_commit",
    }:
        raise ValueError("release execution fields differ from the closed schema")
    checked_execution = release_execution(
        repository=execution["repository"], repository_id=str(execution["repository_id"])
        if type(execution["repository_id"]) is int else "",
        workflow_ref=execution["workflow_ref"], workflow_sha=execution["workflow_sha"],
        run_id=str(execution["run_id"]) if type(execution["run_id"]) is int else "",
        run_attempt=str(execution["run_attempt"]) if type(execution["run_attempt"]) is int else "",
        event_name=execution["event_name"], source_commit=execution["source_commit"],
    )
    if checked_execution != execution or execution["source_commit"] != source_sha:
        raise ValueError("release execution source or identity differs from release")
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
        "schema_version": 2,
        "statement_type": "https://omnilyzer.ai/release-provenance/v2",
        "claim": "build-once release evidence; no formal SLSA level is asserted",
        "platform_version": version, "source_commit": source_sha,
        "execution": checked_execution,
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
        "schema_version": 2, "platform_version": version, "source_commit": source_sha,
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
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--github-repository-id", required=True)
    parser.add_argument("--github-workflow-ref", required=True)
    parser.add_argument("--github-workflow-sha", required=True)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--github-run-attempt", required=True)
    parser.add_argument("--github-event-name", required=True)
    args = parser.parse_args()
    execution = release_execution(
        repository=args.github_repository, repository_id=args.github_repository_id,
        workflow_ref=args.github_workflow_ref, workflow_sha=args.github_workflow_sha,
        run_id=args.github_run_id, run_attempt=args.github_run_attempt,
        event_name=args.github_event_name, source_commit=args.source_sha,
    )
    create(args.handoff, args.oci_publication, args.output, args.repository,
           args.version, args.source_sha, execution=execution)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
