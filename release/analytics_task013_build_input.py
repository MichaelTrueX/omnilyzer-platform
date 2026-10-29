#!/usr/bin/env python3
"""File: release/analytics_task013_build_input.py

Purpose: Create a reproducible, source-verified and explicitly UNSIGNED input
for a FUTURE original Task 013 Analytics OCI producer. This is an additive
preflight, not a release signer, OCI publisher or Task 014 deployment authority.

Links: release/analytics_source_admission.py and products/analytics-source.json;
deployment/saas_product_contract.py and products/analytics-dev.json;
deployment/saas_product_runtime.py and products/analytics-runtime-dev.json;
release/release_plan.py; .github/workflows/platform-release.yml;
deployment/promotion.py, release/provenance.py, deployment/release_consumer.py.

No live services, registry, credentials, database or deployment files are read.
Only local committed Git objects and review profiles are inspected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from deployment.policy import DeploymentPolicyError, canonical_bytes
from deployment.saas_product_contract import load_reviewed_profile
from deployment.saas_product_runtime import load_review_profile
from release.analytics_source_admission import AnalyticsAdmissionError, verify_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "release/products/analytics-source.json"
PRODUCT = ROOT / "deployment/products/analytics-dev.json"
RUNTIME = ROOT / "deployment/products/analytics-runtime-dev.json"
ERROR = "TASK013_ANALYTICS_INPUT_DENIED"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_PRODUCT = "analytics"
EXPECTED_SOURCE_REPO = "MichaelTrueX/omnilyzer"
EXPECTED_OCI_REPO = "omnilyzer/analytics"
EXPECTED_ROUTES = ("/livez", "/readyz")
REQUIRED_INPUT_PATHS = (
    "Dockerfile.analytics",
    ".dockerignore",
    "scripts/accept-m05-analytics-oci-dev.py",
)


def _load_object(path: Path) -> dict[str, Any]:
    """Read a bounded review JSON file and reject duplicate object members."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
        raise DeploymentPolicyError("review input is missing or oversized")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Reject ambiguous last-value-wins JSON input."""
        obj: dict[str, Any] = {}
        for name, value in pairs:
            if name in obj:
                raise DeploymentPolicyError("duplicate review input field")
            obj[name] = value
        return obj

    try:
        result = json.loads(path.read_bytes(), object_pairs_hook=unique)
    except (UnicodeError, ValueError, OSError) as exc:
        raise DeploymentPolicyError("invalid review input JSON") from exc
    if type(result) is not dict:
        raise DeploymentPolicyError("review input is not an object")
    return result


def _git(checkout: Path, *args: str) -> str:
    """Read Git metadata without a shell, network or worktree mutation."""
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), *args],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise DeploymentPolicyError("required immutable Git object unavailable") from exc
    if len(result.stdout) > 4096:
        raise DeploymentPolicyError("unbounded Git response")
    return result.stdout.decode("ascii").strip()


def _coherent_profiles(source: dict[str, Any], product: Any, runtime: Any) -> None:
    """Require one exact product, Git SHA, OCI identity, health and secret set."""
    if (
        source.get("product") != EXPECTED_PRODUCT
        or source.get("source_repository") != EXPECTED_SOURCE_REPO
        or source.get("source_commit") != product.source_commit
        or source.get("authorization") != "review-only-not-a-signed-release"
        or product.product_id != EXPECTED_PRODUCT
        or runtime.product_id != EXPECTED_PRODUCT
        or product.source_repository != EXPECTED_SOURCE_REPO
        or product.oci_repository != EXPECTED_OCI_REPO
        or runtime.oci_repository != EXPECTED_OCI_REPO
        or product.oci_repository != runtime.oci_repository
        or product.app_port != runtime.container_port
        or product.app_port != 3000
        or (runtime.live_path, runtime.ready_path) != EXPECTED_ROUTES
        or product.readiness_path != runtime.ready_path
        or source.get("runtime", {}).get("http_ready_path") != runtime.ready_path
        or product.secret_names != runtime.runtime_secret_names
    ):
        raise DeploymentPolicyError("source, product and runtime profiles disagree")


def build_input(analytics_checkout: Path, *, platform_root: Path = ROOT) -> dict[str, Any]:
    """Bind 72 source identities and the reviewed product profiles, never sign.

    The returned dictionary is NOT an approved Task 013 release plan and may
    not be converted to a Task 014 promotion without existing verified, signed
    provenance plus an independently authorized product-aware executor.
    """
    if not isinstance(analytics_checkout, Path) or analytics_checkout.is_symlink():
        raise DeploymentPolicyError("Analytics checkout must be a real directory")
    if not isinstance(platform_root, Path) or platform_root.is_symlink():
        raise DeploymentPolicyError("platform checkout must be a real directory")
    platform_root = platform_root.resolve(strict=True)
    analytics_checkout = analytics_checkout.resolve(strict=True)
    if not analytics_checkout.is_dir() or not (platform_root / "release").is_dir():
        raise DeploymentPolicyError("review checkout is not a repository")
    binding = _load_object(platform_root / "release/products/analytics-source.json")
    product = load_reviewed_profile(platform_root / "deployment/products/analytics-dev.json")
    runtime = load_review_profile(platform_root / "deployment/products/analytics-runtime-dev.json")
    _coherent_profiles(binding, product, runtime)

    # Only exact reviewed committed bytes are accepted. The existing M01
    # admission verifies the original 29-entry manifest plus 22 critical files.
    verified = verify_source(analytics_checkout, binding)
    if (
        verified.get("source_files_verified") != 72
        or verified.get("release_authorized") is not False
        or verified.get("deployment_authorized") is not False
        or verified.get("source_commit") != product.source_commit
    ):
        raise DeploymentPolicyError("source admission was not the exact review-only gate")
    critical = binding["source_critical_files"]
    if any(path not in critical or SHA256.fullmatch(critical[path]) is None
           for path in REQUIRED_INPUT_PATHS):
        raise DeploymentPolicyError("OCI source files absent from critical source gate")

    tree = _git(analytics_checkout, "rev-parse", "HEAD^{tree}")
    platform_commit = _git(platform_root, "rev-parse", "HEAD")
    platform_tree = _git(platform_root, "rev-parse", "HEAD^{tree}")
    if any(SHA40.fullmatch(v) is None for v in (tree, platform_commit, platform_tree)):
        raise DeploymentPolicyError("noncanonical Git source identity")
    # This is a bounded, canonical signing INPUT, not a signature. No JWT,
    # database URL, credential material, mutable image tag or deploy request.
    return {
        "schema_version": 1,
        "input_kind": "task013-analytics-oci-review-only",
        "platform_source_commit": platform_commit,
        "platform_tree": platform_tree,
        "analytics_repository": EXPECTED_SOURCE_REPO,
        "analytics_source_commit": product.source_commit,
        "analytics_tree": tree,
        "oci_repository": EXPECTED_OCI_REPO,
        "dockerfile_sha256": critical["Dockerfile.analytics"],
        "dockerignore_sha256": critical[".dockerignore"],
        "oci_test_source_sha256": critical["scripts/accept-m05-analytics-oci-dev.py"],
        "source_manifest_sha256": binding["source_manifest_sha256"],
        "source_binding_sha256": hashlib.sha256(canonical_bytes(binding)).hexdigest(),
        "product_profile_sha256": product.sha256(),
        "runtime_profile_sha256": runtime.sha256(),
        "source_files_verified": 72,
        "readiness_path": runtime.ready_path,
        "release_authorized": False,
        "deployment_authorized": False,
    }


def main() -> int:
    """Emit deterministic, clearly UNSIGNED review evidence on stdout only."""
    parser = argparse.ArgumentParser(description="Review-only Analytics Task013 OCI input")
    parser.add_argument("--analytics-checkout", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build_input(args.analytics_checkout)
    except (AnalyticsAdmissionError, DeploymentPolicyError, OSError, ValueError) as exc:
        print(f"{ERROR}: {exc}", file=sys.stderr)
        return 1
    print(canonical_bytes(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
