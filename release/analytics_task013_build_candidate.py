#!/usr/bin/env python3
"""File: release/analytics_task013_build_candidate.py

Purpose: One ORIGINAL Task013 candidate build path: checked external Analytics
         Git source -> sanitized immutable tar -> pinned Buildx/BuildKit ->
         verified local OCI archive. Reuses M01's and M05's existing tools.
Related: release/analytics_task013_build_input.py, analytics_oci_context.py,
         analytics_oci_archive.py, builder_versions.py, PR45 Dockerfile.analytics,
         .github/workflows/platform-release.yml (NOT changed here).
Security: no publishing, signing, secrets, registry or Task014 deployment.
         An OCI manifest SHA from this command is always LOCAL and UNSIGNED.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

from deployment.policy import DeploymentPolicyError
from release.analytics_task013_build_input import build_input
from release.analytics_oci_context import snapshot_committed_tree
from release.analytics_oci_archive import verify_archive
from release.builder_versions import (
    BuilderVersionError, verify_buildx_output, verify_buildkit_output,
)

ERROR = "TASK013_ANALYTICS_BUILD_CANDIDATE_DENIED"
BUILDER_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
OCI_REPOSITORY = "omnilyzer/analytics"
EXPECTED_SOURCE = "8648adba2db884cc78274080b9836ca46bafd630"


def _preflight_builder(builder: str) -> None:
    """Require the exact original pinned Buildx and BuildKit tool versions.

    A caller supplies the existing inspected CI builder identity. Do not create,
    delete, select a remote context, or overwrite an installed builder. The
    host/CI must separately enforce a private trusted Docker daemon.
    """
    if type(builder) is not str or BUILDER_NAME.fullmatch(builder) is None:
        raise DeploymentPolicyError(ERROR)
    try:
        buildx = subprocess.run(
            ["docker", "buildx", "version"],
            check=True, capture_output=True, timeout=10, text=True,
        )
        verify_buildx_output(buildx.stdout)
        inspect = subprocess.run(
            ["docker", "buildx", "inspect", "--builder", builder],
            check=True, capture_output=True, timeout=15, text=True,
        )
        verify_buildkit_output(inspect.stdout)
        # Only original Task013's docker-container builder with the pinned
        # BuildKit version can be used, never the daemon/default builder.
        if not any(
            line.startswith("Driver:")
            and line.partition(":")[2].strip() == "docker-container"
            for line in inspect.stdout.splitlines()
        ):
            raise DeploymentPolicyError(ERROR)
    except (OSError, subprocess.SubprocessError, BuilderVersionError) as exc:
        raise DeploymentPolicyError(ERROR) from exc


def build_candidate(
    analytics_checkout: Path, builder: str,
    *,
    execute: bool = False,
) -> dict[str, Any]:
    """Compile and validate a LOCAL OCI artifact using original platform tools.

    When execute=False, only source/profiles and builder identity are checked,
    so unit tests can fail closed without launching a build. When True, the
    already provisioned/pinned Buildx docker-container builder executes the
    exact PR45 Dockerfile using source-only TAR on stdin. No tag, --push,
    registry, credentials, publisher, signer or broker is called.
    """
    if type(execute) is not bool or not isinstance(analytics_checkout, Path):
        raise DeploymentPolicyError(ERROR)
    receipt = build_input(analytics_checkout)
    if (
        receipt.get("analytics_source_commit") != EXPECTED_SOURCE
        or receipt.get("oci_repository") != OCI_REPOSITORY
        or receipt.get("release_authorized") is not False
        or receipt.get("deployment_authorized") is not False
    ):
        raise DeploymentPolicyError(ERROR)
    _preflight_builder(builder)
    if not execute:
        return {
            "schema_version": 1,
            "status": "reviewed-build-input-only",
            "source_commit": EXPECTED_SOURCE,
            "release_authorized": False,
            "deployment_authorized": False,
        }
    with tempfile.TemporaryDirectory(prefix="task013-analytics-build-") as dirname:
        tmp = Path(dirname)
        tar = tmp / "source.tar"
        oci = tmp / "analytics.oci.tar"
        context = snapshot_committed_tree(
            analytics_checkout, receipt["analytics_source_commit"], tar,
        )
        if context["release_authorized"] is not False:
            raise DeploymentPolicyError(ERROR)
        # Section 3: pass precisely verified Git objects, no checkout dir, no
        # mutable tag/secret, and never --push; a local OCI tar is the output.
        command = [
            "docker", "buildx", "build",
            "--builder", builder,
            "--platform", "linux/amd64",
            "--file", "Dockerfile.analytics",
            "--progress", "plain",
            "--provenance=false",
            "--sbom=false",
            "--output", f"type=oci,dest={oci}",
            "-",
        ]
        try:
            with tar.open("rb") as source:
                result = subprocess.run(
                    command, stdin=source, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=900, check=False,
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DeploymentPolicyError(ERROR) from exc
        if result.returncode != 0:
            raise DeploymentPolicyError(ERROR)
        validated = verify_archive(oci, receipt)
        if (
            validated["release_authorized"] is not False
            or validated["deployment_authorized"] is not False
            or validated["source_commit"] != EXPECTED_SOURCE
            or validated["source_tree"] != receipt["analytics_tree"]
            or validated["oci_repository"] != OCI_REPOSITORY
        ):
            raise DeploymentPolicyError(ERROR)
        # Section 4: transient OCI archive and Git TAR are deleted when the
        # context manager exits. Manifest digest is evidence of local bytes,
        # NOT signed/released provenance or an active registry OCI reference.
        return {
            "schema_version": 1,
            "status": "verified-local-oci-unsigned",
            "source_commit": EXPECTED_SOURCE,
            "source_tree": receipt["analytics_tree"],
            "source_context_sha256": context["context_sha256"],
            "local_oci_manifest_digest": validated["local_manifest_digest"],
            "local_oci_archive_sha256": validated["archive_sha256"],
            "oci_repository": OCI_REPOSITORY,
            "release_authorized": False,
            "deployment_authorized": False,
        }


def main() -> int:
    """Read only an explicitly selected local Git checkout and CI builder."""
    parser = argparse.ArgumentParser(description="Unsigned original Task013 Analytics OCI candidate")
    parser.add_argument("--analytics-checkout", type=Path, required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    try:
        value = build_candidate(args.analytics_checkout, args.builder, execute=args.build)
    except (DeploymentPolicyError, OSError, ValueError) as exc:
        print(f"{ERROR}: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
