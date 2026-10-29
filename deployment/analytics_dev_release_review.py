#!/usr/bin/env python3
"""File: deployment/analytics_dev_release_review.py

Purpose: Read-only, fail-closed Task014 Analytics product-slot review. Validate
         exactly the existing pinned original-platform Analytics product and
         runtime profiles, two immutable signed-release-shaped OCI references,
         separate blue/green slots, and required private secret file references.
         This DOES NOT admit a signature, start Docker, write files, install
         services, approve a release, or change the original canary.

Related: deployment/products/analytics-dev.json,
         deployment/products/analytics-runtime-dev.json,
         deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/promotion.py, deployment/analytics_signed_source_pin.py,
         deployment/broker.py, deployment/executor.py, deployment/docker_runtime.py,
         deployment/runtime/dev/compose.yaml (unchanged installed canary),
         release/analytics_release_source_binding.py.

Authority: The original Task013 signed producer and original Task014 verified
           release consumer / OIDC broker / replay / executor are the ONLY
           future sources of installation authority. Public dataclass inputs,
           this review, and syntactically valid sha256 are NEVER permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from .policy import (
    APPROVED_OCI_HOST, DeploymentPolicyError,
    validate_digest, validate_semver,
)
from .saas_product_contract import load_reviewed_profile
from .saas_product_runtime import load_review_profile

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_FILE = ROOT / "deployment/products/analytics-dev.json"
RUNTIME_FILE = ROOT / "deployment/products/analytics-runtime-dev.json"
COMPOSE_FILE = ROOT / "deployment/runtime/dev/analytics.compose.review.yaml"
PRODUCT_ID = "analytics"
IMAGE_REPOSITORY = "omnilyzer/analytics"
REQUIRED_SECRET_NAMES = (
    "COLLECTOR_DATABASE_URL", "DATABASE_URL", "JWT_REFRESH_SECRET", "JWT_SECRET",
)
SECRET_DIRECTORY = Path("/var/lib/omnilyzer/deployment/analytics/dev/secrets")
STAGE = "dev"
SLOTS = ("blue", "green")
ERROR = "TASK014_ANALYTICS_DEV_REVIEW_DENIED"


@dataclass(frozen=True, slots=True)
class AnalyticsDevRolloutReview:
    """Inert, immutable proposal; never proof of signer/executor authorization."""

    schema_version: int
    product_id: str
    source_commit: str
    release_version: str
    proposed_slot: str
    proposed_image: str
    existing_slot: str | None
    existing_image: str | None
    secret_names: tuple[str, ...]
    ready_path: str
    rollback_kind: str
    release_authorized: bool = False
    deployment_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize nonsecret diagnostic fields only (no credentials)."""
        return {
            "schema_version": self.schema_version,
            "product_id": self.product_id,
            "source_commit": self.source_commit,
            "release_version": self.release_version,
            "proposed_slot": self.proposed_slot,
            "proposed_image": self.proposed_image,
            "existing_slot": self.existing_slot,
            "existing_image": self.existing_image,
            "secret_names": list(self.secret_names),
            "ready_path": self.ready_path,
            "rollback_kind": self.rollback_kind,
            "release_authorized": False,
            "deployment_authorized": False,
        }


def _exact_image(digest: object) -> str:
    """Reject mutable tags, alternative registries and arbitrary repositories."""
    if type(digest) is not str:
        raise DeploymentPolicyError(ERROR)
    return f"{APPROVED_OCI_HOST}/{IMAGE_REPOSITORY}@{validate_digest(digest)}"


def review_dev_rollout(
    *, release_version: str, candidate_digest: str,
    target_slot: str, active_slot: str | None = None,
    active_digest: str | None = None,
) -> AnalyticsDevRolloutReview:
    """Inspect a future original verified release and rollback target.

    The image SHA can be proposed for review only. This function is NOT a
    signer, a Task014 promotion request, or an executor-request factory; a
    caller supplying a digest has no right to start the resulting container.
    """
    product = load_reviewed_profile(PRODUCT_FILE)
    runtime = load_review_profile(RUNTIME_FILE)
    if (
        product.product_id != PRODUCT_ID
        or runtime.product_id != PRODUCT_ID
        or product.oci_repository != IMAGE_REPOSITORY
        or runtime.oci_repository != IMAGE_REPOSITORY
        or product.secret_names != REQUIRED_SECRET_NAMES
        or runtime.runtime_secret_names != REQUIRED_SECRET_NAMES
        or product.app_port != 3000 or runtime.container_port != 3000
        or product.readiness_path != "/readyz"
        or runtime.ready_path != "/readyz" or runtime.live_path != "/livez"
        or not COMPOSE_FILE.is_file() or COMPOSE_FILE.is_symlink()
        or target_slot not in SLOTS or type(target_slot) is not str
    ):
        raise DeploymentPolicyError(ERROR)
    if (active_slot is None) != (active_digest is None):
        raise DeploymentPolicyError(ERROR)
    if active_slot is not None and (
        type(active_slot) is not str or active_slot not in SLOTS
        or active_slot == target_slot
    ):
        raise DeploymentPolicyError(ERROR)
    candidate = _exact_image(candidate_digest)
    existing = None if active_digest is None else _exact_image(active_digest)
    if existing == candidate:
        raise DeploymentPolicyError(ERROR)
    version = validate_semver(release_version)
    return AnalyticsDevRolloutReview(
        schema_version=1,
        product_id=PRODUCT_ID,
        source_commit=product.source_commit,
        release_version=version,
        proposed_slot=target_slot,
        proposed_image=candidate,
        existing_slot=active_slot,
        existing_image=existing,
        secret_names=REQUIRED_SECRET_NAMES,
        ready_path="/readyz",
        rollback_kind="original-task014-immutable-digest-preserve-database-writes",
    )


def compose_image_variables(review: AnalyticsDevRolloutReview) -> dict[str, str]:
    """Return two immutable-image-only variables for the existing Compose CLI.

    The absent rollback slot is populated with candidate bytes for parsing,
    but MUST NOT be started: the first deployment has no previous release.
    Only original Task014 may start a slot after signed release verification.
    """
    if type(review) is not AnalyticsDevRolloutReview:
        raise DeploymentPolicyError(ERROR)
    if (
        review.product_id != PRODUCT_ID
        or review.release_authorized is not False
        or review.deployment_authorized is not False
        or review.secret_names != REQUIRED_SECRET_NAMES
        or review.proposed_slot not in SLOTS
    ):
        raise DeploymentPolicyError(ERROR)
    # Recheck all references rather than trust a manually constructed object.
    current = review_dev_rollout(
        release_version=review.release_version,
        candidate_digest=review.proposed_image.rsplit("@", 1)[-1],
        target_slot=review.proposed_slot,
        active_slot=review.existing_slot,
        active_digest=None if review.existing_image is None
        else review.existing_image.rsplit("@", 1)[-1],
    )
    if review != current:
        raise DeploymentPolicyError(ERROR)
    return {
        "ANALYTICS_BLUE_IMAGE": (
            review.proposed_image if review.proposed_slot == "blue"
            else (review.existing_image or review.proposed_image)
        ),
        "ANALYTICS_GREEN_IMAGE": (
            review.proposed_image if review.proposed_slot == "green"
            else (review.existing_image or review.proposed_image)
        ),
    }


def review_private_secret_paths(
    *, directory: Path = SECRET_DIRECTORY, owner_uid: int,
) -> tuple[str, ...]:
    """Read ONLY filesystem metadata of four preprovisioned owner-only secrets.

    No file content is opened, returned, logged, supplied as an environment
    variable, copied, or persisted. Actual secret validation/injection must
    occur under an approved original Task014 restricted host executor.
    """
    if (
        type(owner_uid) is not int or owner_uid < 1
        or not isinstance(directory, Path)
        or directory != SECRET_DIRECTORY
        or not directory.is_absolute()
    ):
        raise DeploymentPolicyError(ERROR)
    current = Path("/")
    # Reject symlinks in every component, including /var/lib paths.
    for part in directory.parts[1:]:
        current /= part
        if current.is_symlink():
            raise DeploymentPolicyError(ERROR)
    try:
        folder = directory.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(folder.st_mode) or folder.st_uid != owner_uid
                or folder.st_mode & 0o077):
            raise DeploymentPolicyError(ERROR)
        for name in REQUIRED_SECRET_NAMES:
            path = directory / name
            info = path.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                    or info.st_mode & 0o777 != 0o600
                    or not 1 <= info.st_size <= 8192):
                raise DeploymentPolicyError(ERROR)
    except (OSError, ValueError) as exc:
        raise DeploymentPolicyError(ERROR) from exc
    return REQUIRED_SECRET_NAMES


def _main() -> int:
    """CLI review, emitting redacted nonsecret data but never deploy authority."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="INERT Task014 Analytics DEV proposal")
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--target-slot", required=True, choices=SLOTS)
    parser.add_argument("--active-slot", choices=SLOTS)
    parser.add_argument("--active-digest")
    args = parser.parse_args()
    try:
        result = review_dev_rollout(
            release_version=args.release_version,
            candidate_digest=args.candidate_digest,
            target_slot=args.target_slot,
            active_slot=args.active_slot,
            active_digest=args.active_digest,
        )
        # No approval, secret or actual signed-release evidence in this CLI.
        # Never serialize review inputs or runtime secret references to logs.
        # This CLI is a validation probe, not a manifest export facility.
        if result.release_authorized or result.deployment_authorized:
            raise DeploymentPolicyError(ERROR)
        print("TASK014_ANALYTICS_DEV_INERT_REVIEW_PASS")
        return 0
    except (DeploymentPolicyError, OSError) as exc:
        print(f"{ERROR}: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
