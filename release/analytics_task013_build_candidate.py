#!/usr/bin/env python3
"""File: release/analytics_task013_build_candidate.py

Purpose: One ORIGINAL Task013 candidate build path: checked external Analytics
         Git source -> sanitized immutable tar -> pinned Buildx/BuildKit ->
         verified local OCI archive. Reuses M01's and M05's existing tools.
Related: release/analytics_task013_build_input.py, analytics_oci_context.py,
         analytics_oci_archive.py, builder_versions.py, PR45 Dockerfile.analytics,
         release/analytics_release_source_binding.py (original Task013
         signer-preparation input), .github/workflows/platform-release.yml
         (protected workflow NOT changed by this module).
Security: no publishing, signing, secrets, registry or Task014 deployment.
         An OCI manifest SHA from this command is always LOCAL and UNSIGNED.
         Retained files are an explicitly requested, protected pre-sign handoff.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

from deployment.policy import DeploymentPolicyError, canonical_bytes
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


def _private_handoff_destination(path: Path) -> Path:
    """Permit output only under a caller-owned private parent directory.

    Reject shared /tmp directly, symlinks, existing output and relative paths.
    No secret file is ever copied into this handoff. Original Task013 signing
    must still independently verify the retained bytes before publication.
    """
    if (not isinstance(path, Path) or not path.is_absolute()
            or path.exists() or path.is_symlink()
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", path.name) is None):
        raise DeploymentPolicyError(ERROR)
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir() or parent.resolve(strict=True) != parent:
        raise DeploymentPolicyError(ERROR)
    info = parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise DeploymentPolicyError(ERROR)
    return path


def _sha(path: Path) -> str:
    """Verify retained exact bytes without reading large OCI images into RAM."""
    digest = hashlib.sha256()
    with path.open("rb") as reader:
        for data in iter(lambda: reader.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def build_candidate(
    analytics_checkout: Path, builder: str,
    *,
    execute: bool = False,
    retain_verified_artifacts: Path | None = None,
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
    # Section: explicitly requested handoff is only meaningful after a real
    # pinned builder execution. Never persist review-only or failed artifacts.
    if retain_verified_artifacts is not None:
        if not execute:
            raise DeploymentPolicyError(ERROR)
        retained = _private_handoff_destination(retain_verified_artifacts)
    else:
        retained = None
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
    with tempfile.TemporaryDirectory(
        prefix=".task013-analytics-build-",
        dir=str(retained.parent) if retained is not None else None,
    ) as dirname:
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
        # Section 4: the existing behavior deletes the context and OCI on
        # successful verification. Optional explicit handoff retains exactly
        # the already-validated files, without a second Docker build.
        result: dict[str, Any] = {
            "schema_version": 1,
            "status": "verified-local-oci-unsigned",
            "source_commit": EXPECTED_SOURCE,
            "source_tree": receipt["analytics_tree"],
            "platform_source_commit": receipt.get("platform_source_commit"),
            "source_context_sha256": context["context_sha256"],
            "local_oci_manifest_digest": validated["local_manifest_digest"],
            "local_oci_archive_sha256": validated["archive_sha256"],
            "oci_repository": OCI_REPOSITORY,
            "release_authorized": False,
            "deployment_authorized": False,
        }
        if retained is not None:
            # Check again after BuildKit finishes, under one private parent.
            _private_handoff_destination(retained)
            if (_sha(tar) != context["context_sha256"]
                    or _sha(oci) != validated["archive_sha256"]):
                raise DeploymentPolicyError("verified OCI handoff bytes changed")
            os.chmod(tar, 0o600)
            os.chmod(oci, 0o600)
            result["status"] = "verified-local-oci-unsigned-retained"
            result["retained_filenames"] = {
                "source_context": "source.tar",
                "oci_archive": "analytics.oci.tar",
                "receipt": "unsigned-handoff.json",
            }
            # Receipt and the two artifacts become visible together ONLY
            # after all verification succeeds. Output is never auto-signed.
            metadata = tmp / "unsigned-handoff.json"
            fd = os.open(metadata, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical_bytes(result))
            os.chmod(tmp, 0o700)
            os.replace(tmp, retained)
        return result


def main() -> int:
    """Read only an explicitly selected local Git checkout and CI builder."""
    parser = argparse.ArgumentParser(description="Unsigned original Task013 Analytics OCI candidate")
    parser.add_argument("--analytics-checkout", type=Path, required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--retain-verified-artifacts", type=Path,
                        help="New path beneath private 0700 parent for UNSIGNED Task013 handoff")
    args = parser.parse_args()
    try:
        value = build_candidate(
            args.analytics_checkout, args.builder, execute=args.build,
            retain_verified_artifacts=args.retain_verified_artifacts,
        )
    except (DeploymentPolicyError, OSError, ValueError) as exc:
        print(f"{ERROR}: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
