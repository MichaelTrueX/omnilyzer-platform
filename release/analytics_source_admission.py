#!/usr/bin/env python3
# File: release/analytics_source_admission.py
# Purpose: Bind the pinned PR45 Analytics OCI source to original Task 013/014
#          release boundary, without changing the signed-canary permit list.
# Links: release/products/analytics-source.json;
#        release/release_plan.py; deployment/promotion.py;
#        deployment/execution.py; docs/operations/analytics-platform-bridge-20261027.md.
# Section 1: validate a closed cross-repository source reference; Section 2:
# read pinned Git objects; Section 3: validate full PR36 source manifest;
# Section 4: emit an explicitly UNSIGNED source-admission record.
# This adapter is not a release signer, broker, executor or deployment authority.
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from deployment.policy import DeploymentPolicyError, validate_sha256, validate_source_sha

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "release/products/analytics-source.json"
GIT_ORIGINS = {
    "https://github.com/MichaelTrueX/omnilyzer.git",
    "git@github.com:MichaelTrueX/omnilyzer.git",
}
CLOSED_BINDING = {
    "schema_version", "product", "source_repository", "source_commit",
    "source_manifest_path", "source_manifest_sha256", "source_critical_files",
    "runtime", "authorization",
}
CLOSED_RUNTIME = {
    "framework", "auth", "session", "tenant_isolation", "database",
    "http_ready_path", "authenticated_api_path", "dashboard_path",
}
RUNTIME = {
    "framework": "nextjs-15",
    "auth": "json-bearer-localstorage",
    "session": "postgresql-revocable",
    "tenant_isolation": "postgresql-force-rls",
    "database": "dedicated-analytics-postgresql",
    "http_ready_path": "/readyz",
    "authenticated_api_path": "/api/v1/workspaces",
    "dashboard_path": "/dashboard/workspaces",
}
CRITICAL_PATHS = frozenset((
    "package-lock.json", "prisma/schema.prisma", "lib/server-api-auth.ts",
    "app/api/v1/auth/login/route.ts", "app/dashboard/workspaces/page.tsx",
    "lib/website-management.ts",
    "components/websites/WebsiteOverview.tsx",
    "components/websites/WebsiteDetail.tsx",
    "__tests__/m03-website-overview-isolation.test.cjs",
    "__tests__/m03-website-refresh-isolation.test.cjs",
    "app/livez/route.ts",
    "app/readyz/route.ts",
    "__tests__/m03-platform-product-health.test.cjs",
    "scripts/accept-m03-product-health-pg16.py",
    "docs/qa/m03-platform-first-consumer-20261027.md",
    "prisma/rls/analytics-app-events.install.sql",
    "prisma/rls/analytics-app-events.rollback.sql",
    "scripts/accept-platform-integration-dev.py",
    "__tests__/secure-analytics-postgres.e2e.cjs",
    "Dockerfile.analytics",
    ".dockerignore",
    "scripts/accept-m05-analytics-oci-dev.py",
    "__tests__/m01-migration-provenance.test.cjs",
    "__tests__/m02-auth-cross-tab.test.cjs",
    "__tests__/workspace-analytics-dashboard.test.cjs",
    "__tests__/workspace-site-collector.test.cjs",
    "app/api/v1/workspaces/[workspaceId]/events/route.ts",
    "app/api/v1/workspaces/[workspaceId]/members/route.ts",
    "app/api/v1/workspaces/[workspaceId]/site/route.ts",
    "app/api/v1/workspaces/[workspaceId]/sites/[siteId]/diagnostics/route.ts",
    "app/api/v1/workspaces/[workspaceId]/sites/[siteId]/route.ts",
    "app/api/v1/workspaces/[workspaceId]/sites/[siteId]/summary/route.ts",
    "app/api/v1/workspaces/[workspaceId]/sites/route.ts",
    "app/api/v1/workspaces/[workspaceId]/summary/route.ts",
    "app/api/v1/workspaces/route.ts",
    "docs/qa/m01-node22-security-repin-20261028.md",
    "docs/qa/m01-nonowner-app-runtime-20261028.md",
    "lib/app-workspace-scope.ts",
    "lib/auth-context.tsx",
    "prisma/rls/analytics-app-workspace.install.sql",
    "scripts/accept_m01_nonowner_http_pg16.py",
    "scripts/accept_m01_nonowner_workspace_pg16.py",
    "scripts/test_m01_node22_analytics_oci.py",
    "app/api/chatbot/route.ts",
    "docs/qa/m01-security-runtime-repin-20261029.md",
    "docs/qa/m01-pr50-debian13-runtime-20261029.md",
    "next.config.js",
    "package.json",
))
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
BASELINE_SOURCE = "8648adba2db884cc78274080b9836ca46bafd630" # audited original PR45 ancestry

class AnalyticsAdmissionError(ValueError):
    """Reject an unreviewed Analytics source or incomplete release identity."""

def _closed(value: Any, keys: set[str], context: str) -> dict:
    """Reject unknown and missing fields before trusting a source reference."""
    if type(value) is not dict or set(value) != keys:
        raise AnalyticsAdmissionError(f"{context} has unexpected or missing fields")
    return value

def _safe_path(path: Any) -> str:
    """Reject absolute, traversal, dot and escaped source manifest paths."""
    if not isinstance(path, str) or not path or len(path) > 250 or "\\" in path:
        raise AnalyticsAdmissionError("invalid source path")
    parts = path.split("/")
    if any(not x or x in (".", "..") for x in parts) or path.startswith("/"):
        raise AnalyticsAdmissionError("untrusted source path")
    return path

def _digest(value: Any) -> str:
    """Require canonical lowercase SHA-256, no truncated or mutable identity."""
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise AnalyticsAdmissionError("invalid source digest")
    return value

def _git(checkout: Path, *args: str) -> bytes:
    """Read Git metadata and blobs with no network and no shell evaluation."""
    try:
        p = subprocess.run(["git", "-C", str(checkout), *args],
                           capture_output=True, timeout=15, check=True)
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as exc:
        raise AnalyticsAdmissionError("source checkout Git object unavailable") from exc
    if len(p.stdout) > 4 * 1024 * 1024:
        raise AnalyticsAdmissionError("unbounded source metadata")
    return p.stdout

def _blob(checkout: Path, commit: str, path: str) -> bytes:
    """Read only a file from the exact committed Git tree, not working-copy bytes."""
    path = _safe_path(path)
    entries = _git(checkout, "ls-tree", commit, "--", path).splitlines()
    # Git mode 100644 or 100755: regular source only; reject symlink/submodule.
    if (len(entries) != 1
            or not entries[0].startswith((b"100644 blob ", b"100755 blob "))
            or not entries[0].endswith(b"\t" + path.encode())):
        raise AnalyticsAdmissionError("source file is absent, untracked or non-regular: " + path)
    return _git(checkout, "show", f"{commit}:{path}")

def verify_source(checkout: Path, binding: dict[str, Any]) -> dict[str, Any]:
    """Admit a PINNED review candidate; never authorize signing/promotion."""
    config = _closed(binding, CLOSED_BINDING, "analytics source binding")
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise AnalyticsAdmissionError("unsupported source binding")
    if config["product"] != "analytics" or config["source_repository"] != "MichaelTrueX/omnilyzer":
        raise AnalyticsAdmissionError("source product/repository not authorized")
    if config["authorization"] != "review-only-not-a-signed-release":
        raise AnalyticsAdmissionError("source admission may not grant release authority")
    try:
        commit = validate_source_sha(config["source_commit"])
    except DeploymentPolicyError as exc:
        raise AnalyticsAdmissionError("invalid source commit") from exc
    critical = config["source_critical_files"]
    if type(critical) is not dict or set(critical) != CRITICAL_PATHS:
        raise AnalyticsAdmissionError("critical source set is incomplete")
    _closed(config["runtime"], CLOSED_RUNTIME, "analytics runtime")
    if config["runtime"] != RUNTIME:
        raise AnalyticsAdmissionError("runtime contract differs from approved Analytics")
    checkout = checkout.resolve(strict=True)
    if _git(checkout, "rev-parse", "HEAD").decode().strip() != commit:
        raise AnalyticsAdmissionError("unreviewed HEAD: wrong Analytics Git revision")
    # Retain PR45 original 29-entry manifest as an immutable historical baseline.
    # Every subsequent file change MUST be independently SHA256-pinned below.
    _git(checkout, "merge-base", "--is-ancestor", BASELINE_SOURCE, commit)
    changed = set(_git(checkout, "diff", "--name-only", BASELINE_SOURCE, commit, "--").decode().splitlines())
    if changed - set(critical):
        raise AnalyticsAdmissionError("unreviewed changed source paths")
    if _git(checkout, "config", "--get", "remote.origin.url").decode().strip() not in GIT_ORIGINS:
        raise AnalyticsAdmissionError("source origin differs from exact Analytics repository")
    # The only trusted source is committed Git content. Working tree must not
    # have staged or unstaged tracked-file modifications; ignored builds are okay.
    if _git(checkout, "diff", "--quiet", "HEAD", "--"):
        raise AnalyticsAdmissionError("dirty source checkout")
    manifest_path = _safe_path(config["source_manifest_path"])
    manifest_bytes = _blob(checkout, commit, manifest_path)
    if hashlib.sha256(manifest_bytes).hexdigest() != _digest(config["source_manifest_sha256"]):
        raise AnalyticsAdmissionError("source manifest hash mismatch")
    try:
        manifest = json.loads(manifest_bytes)
        entries = manifest["r3_r4_original_seven"] + manifest["other_complete_files"]
    except (ValueError, KeyError, TypeError) as exc:
        raise AnalyticsAdmissionError("incompatible PR36 source manifest") from exc
    if type(entries) is not list or len(entries) != 29:
        raise AnalyticsAdmissionError("incomplete source manifest")
    seen = set()
    for entry in entries:
        if type(entry) is not dict or not {"path", "sha256", "bytes"}.issubset(entry):
            raise AnalyticsAdmissionError("incomplete source manifest file record")
        rel = _safe_path(entry["path"])
        if rel in seen:
            raise AnalyticsAdmissionError("duplicate source file")
        seen.add(rel)
        data = _blob(checkout, commit, rel)
        # A changed baseline file is allowed ONLY when separately covered by an
        # exact reviewed critical-file pin; unchanged files retain size and SHA.
        overridden = rel in changed
        if overridden and rel not in critical:
            raise AnalyticsAdmissionError("changed historical source lacks new pin: " + rel)
        expected = critical[rel] if overridden else entry["sha256"]
        if hashlib.sha256(data).hexdigest() != _digest(expected) or (not overridden and len(data) != entry["bytes"]):
            raise AnalyticsAdmissionError("source hash or size mismatch: " + rel)
    for rel, expected in critical.items():
        data = _blob(checkout, commit, rel)
        if hashlib.sha256(data).hexdigest() != _digest(expected):
            raise AnalyticsAdmissionError("critical source hash mismatch: " + rel)
    # Link the immutable reviewed source to Task 013; this record is NOT signed,
    # issued, accepted by Task 014 broker, or usable as a deployment request.
    receipt = {
        "schema_version": 1,
        "product": "analytics",
        "source_repository": config["source_repository"],
        "source_commit": commit,
        "source_manifest_sha256": config["source_manifest_sha256"],
        "source_files_verified": len(entries) + len(critical),
        "release_authorized": False,
        "deployment_authorized": False,
        "status": "source-admission-only",
    }
    return receipt

def main() -> int:
    """Run explicit offline admission of an existing reviewable checkout."""
    parser = argparse.ArgumentParser(description="Read-only Analytics source gate")
    parser.add_argument("--analytics-checkout", required=True, type=Path)
    opts = parser.parse_args()
    try:
        config = json.loads(BINDING.read_text(encoding="utf-8"))
        receipt = verify_source(opts.analytics_checkout, config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(1, "SOURCE_ADMISSION_DENIED: " + str(exc) + "\n")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
