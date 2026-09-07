#!/usr/bin/env python3
"""Stage a closed, credential-free diagnostic bundle before policy evaluation."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re

try:
    from .build_release import oci_digest_from_archive
    from .release_plan import load_json, validate_plan, validate_semver, validate_source_sha
    from .vulnerability_policy import canonical_bytes
except ImportError:  # Direct execution in GitHub Actions.
    from build_release import oci_digest_from_archive
    from release_plan import load_json, validate_plan, validate_semver, validate_source_sha
    from vulnerability_policy import canonical_bytes


DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTITY_FILENAME = "denied-release-identity.json"
POLICY_FILENAME = "vulnerability-policy.json"


class DenialEvidenceError(ValueError):
    pass


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise DenialEvidenceError(f"diagnostic source is not a regular file: {path.name}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage_denial_evidence(
    handoff: Path,
    policy_path: Path,
    output: Path,
    repository: Path,
    expected_version: str,
    expected_sha: str,
) -> dict[str, object]:
    validate_semver(expected_version)
    validate_source_sha(expected_sha)
    if handoff.is_symlink() or not handoff.is_dir():
        raise DenialEvidenceError("handoff must be a real directory")
    plan = validate_plan(load_json(handoff / "release-plan.json"), repository)
    if plan["platform_version"] != expected_version or plan["source_commit"] != expected_sha:
        raise DenialEvidenceError("diagnostic identity differs from workflow authority")
    if output.exists() or output.is_symlink():
        raise DenialEvidenceError("diagnostic output must not already exist")

    artifacts = plan["artifacts"]
    wheel = handoff / artifacts["python_wheel"]
    npm = handoff / artifacts["npm_tarball"]
    oci = handoff / artifacts["oci_archive"]
    manifest_digest = oci_digest_from_archive(oci)
    if DIGEST_RE.fullmatch(manifest_digest) is None:
        raise DenialEvidenceError("OCI manifest digest is not exact sha256")

    identity: dict[str, object] = {
        "schema_version": 1,
        "release_version": expected_version,
        "source_sha": expected_sha,
        "oci_archive_filename": oci.name,
        "oci_archive_sha256": _sha256(oci),
        "oci_manifest_digest": manifest_digest,
        "python_wheel_filename": wheel.name,
        "python_wheel_sha256": _sha256(wheel),
        "npm_tarball_filename": npm.name,
        "npm_tarball_sha256": _sha256(npm),
    }

    diagnostic_names = {
        "grype-db-status.json",
        *artifacts["sboms"].values(),
        *artifacts["vulnerability_reports"].values(),
    }
    sources = {name: handoff / name for name in diagnostic_names}
    sources[POLICY_FILENAME] = policy_path
    for path in sources.values():
        _sha256(path)

    output.mkdir(mode=0o700)
    for name, source in sorted(sources.items()):
        destination = output / name
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o600)
    identity_path = output / IDENTITY_FILENAME
    identity_path.write_bytes(canonical_bytes(identity))
    identity_path.chmod(0o600)
    return identity


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args()
    stage_denial_evidence(
        args.handoff, args.policy, args.output, args.repository,
        args.expected_version, args.expected_sha,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
