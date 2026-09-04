#!/usr/bin/env python3
"""Verify the complete immutable build-to-publisher handoff before OIDC."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    from .release_plan import load_json, validate_plan, validate_semver, validate_source_sha
    from .vulnerability_policy import validate_database_status
except ImportError:
    from release_plan import load_json, validate_plan, validate_semver, validate_source_sha
    from vulnerability_policy import validate_database_status

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
BUILD_KEYS = {
    "schema_version", "platform_version", "source_commit", "plan_sha256", "artifacts", "sboms",
    "vulnerability_reports", "vulnerability_policy_sha256", "expected_oci_manifest_digest",
    "vulnerability_policy_result_sha256", "grype_database_status_sha256",
    "tool_versions", "evidence_mode",
}


class HandoffError(ValueError):
    pass


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def expected_files(plan: dict[str, Any]) -> set[str]:
    artifacts = plan["artifacts"]
    return {
        "release-plan.json", "build-manifest.json", "vulnerability-policy.json",
        "vulnerability-policy-result.json", "grype-db-status.json",
        artifacts["python_wheel"], artifacts["npm_tarball"], artifacts["oci_archive"],
        *artifacts["sboms"].values(), *artifacts["vulnerability_reports"].values(),
    }


def _record(root: Path, value: Any, expected_name: str, context: str) -> None:
    if not isinstance(value, dict) or set(value) != {"filename", "sha256", "size"}:
        raise HandoffError(f"{context} record fields differ from schema")
    if value["filename"] != expected_name:
        raise HandoffError(f"{context} filename mismatch")
    path = root / expected_name
    raw = path.read_bytes()
    if value["size"] != len(raw) or value["sha256"] != _sha(raw):
        raise HandoffError(f"{context} checksum or size mismatch")


def verify(root: Path, repository: Path, expected_version: str, expected_sha: str,
           *, require_production_evidence: bool = False) -> dict[str, Any]:
    validate_semver(expected_version)
    validate_source_sha(expected_sha)
    if not root.is_dir() or root.is_symlink():
        raise HandoffError("handoff must be a real directory")
    actual: set[str] = set()
    for entry in root.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise HandoffError(f"handoff contains unsupported entry: {entry.name}")
        actual.add(entry.name)
    plan_path = root / "release-plan.json"
    plan = validate_plan(load_json(plan_path), repository)
    wanted = expected_files(plan)
    if actual != wanted:
        raise HandoffError(f"handoff file set differs: missing={sorted(wanted-actual)} unexpected={sorted(actual-wanted)}")
    if plan["platform_version"] != expected_version or plan["source_commit"] != expected_sha:
        raise HandoffError("handoff version/source commit differs from workflow authority")

    build = load_json(root / "build-manifest.json")
    if not isinstance(build, dict) or set(build) != BUILD_KEYS or build["schema_version"] != 1:
        raise HandoffError("build manifest differs from closed schema")
    if build["platform_version"] != expected_version or build["source_commit"] != expected_sha:
        raise HandoffError("build manifest version/source mismatch")
    if build["plan_sha256"] != _sha(plan_path.read_bytes()):
        raise HandoffError("release plan checksum mismatch")
    if build["tool_versions"] != plan["tool_versions"]:
        raise HandoffError("tool version mismatch")
    if require_production_evidence and build["evidence_mode"] != "production-tools":
        raise HandoffError("publisher refuses non-production scanner evidence")
    if build["evidence_mode"] not in {"production-tools", "local-synthetic-canary"}:
        raise HandoffError("unknown evidence mode")
    if not DIGEST_RE.fullmatch(build["expected_oci_manifest_digest"]):
        raise HandoffError("OCI manifest digest is not exact sha256")

    fields = {"python": "python_wheel", "npm": "npm_tarball", "oci": "oci_archive"}
    for section in ("artifacts", "sboms", "vulnerability_reports"):
        if not isinstance(build[section], dict) or set(build[section]) != set(fields):
            raise HandoffError(f"build manifest {section} keys differ from schema")
    for kind, field in fields.items():
        _record(root, build["artifacts"].get(kind), plan["artifacts"][field], f"artifact {kind}")
        _record(root, build["sboms"].get(kind), plan["artifacts"]["sboms"][kind], f"SBOM {kind}")
        _record(root, build["vulnerability_reports"].get(kind),
                plan["artifacts"]["vulnerability_reports"][kind], f"report {kind}")
        sbom = load_json(root / plan["artifacts"]["sboms"][kind])
        if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
            raise HandoffError(f"{kind} SBOM is not CycloneDX 1.6")
    policy_raw = (root / "vulnerability-policy.json").read_bytes()
    if build["vulnerability_policy_sha256"] != _sha(policy_raw):
        raise HandoffError("vulnerability policy checksum mismatch")
    result = load_json(root / "vulnerability-policy-result.json")
    result_keys = {"schema_version", "evaluation_date_utc", "decision", "policy_sha256",
                   "report_sha256", "blocked_findings"}
    if not isinstance(result, dict) or set(result) != result_keys or result.get("schema_version") != 1:
        raise HandoffError("vulnerability policy result differs from closed schema")
    if result.get("decision") != "PASS" or result.get("policy_sha256") != _sha(policy_raw) or result.get("blocked_findings") != []:
        raise HandoffError("vulnerability policy evidence is not an exact PASS")
    result_path = root / "vulnerability-policy-result.json"
    if build["vulnerability_policy_result_sha256"] != _sha(result_path.read_bytes()):
        raise HandoffError("vulnerability policy result checksum mismatch")
    database_path = root / "grype-db-status.json"
    if build["grype_database_status_sha256"] != _sha(database_path.read_bytes()):
        raise HandoffError("Grype database evidence checksum mismatch")
    validate_database_status(load_json(database_path))
    for kind in fields:
        if result.get("report_sha256", {}).get(kind) != build["vulnerability_reports"][kind]["sha256"]:
            raise HandoffError(f"vulnerability report hash mismatch: {kind}")
    return {"plan": plan, "build_manifest": build}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--require-production-evidence", action="store_true")
    args = parser.parse_args()
    verify(args.handoff, args.repository, args.expected_version, args.expected_sha,
           require_production_evidence=args.require_production_evidence)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
