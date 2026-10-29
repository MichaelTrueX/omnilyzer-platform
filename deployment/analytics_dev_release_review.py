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
        # First install has NO previously signed Analytics image to restore.
        # Rollback must deactivate the private, unexposed candidate only;
        # subsequent upgrades may return to the previous immutable digest.
        rollback_kind=(
            "original-task014-stop-first-slot-preserve-database-writes"
            if existing is None else
            "original-task014-immutable-digest-preserve-database-writes"
        ),
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
    directory_owner_uid: int | None = None,
    directory_group_gid: int | None = None,
) -> tuple[str, ...]:
    """Read only metadata of four source files; require least privilege.

    Original inert review callers retain private mode0700 directory owned by
    owner_uid. For REAL rootless Compose file bind sources, the directory
    must instead be root:executor-group mode0710: root controls which four
    names can be bound, while only the original rootless executor group can
    traverse it. Each source FILE must still be owned by mapped container
    UID503216 and be exact 0600 (mapped container UID10001 can read, unrelated
    users cannot). Do not make the directory owned/writable by Docker UID991.

    Does not open, copy, expose, or log file contents. Actual positive/negative
    rootless UID10001 mount-access and database-role isolation remain required.
    """
    reviewed_rootless = directory_owner_uid is not None or directory_group_gid is not None
    if (
        type(owner_uid) is not int or owner_uid < 1
        or not isinstance(directory, Path) or directory != SECRET_DIRECTORY
        or not directory.is_absolute()
        or (reviewed_rootless and (
            type(directory_owner_uid) is not int or directory_owner_uid != 0
            or type(directory_group_gid) is not int or directory_group_gid < 1
        ))
    ):
        raise DeploymentPolicyError(ERROR)
    expected_owner = 0 if reviewed_rootless else owner_uid
    expected_mode = 0o710 if reviewed_rootless else 0o700
    current = Path("/")
    # Deny symlinks in any component before checking exact source inode.
    for part in directory.parts[1:]:
        current /= part
        if current.is_symlink():
            raise DeploymentPolicyError(ERROR)
    try:
        folder = directory.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(folder.st_mode)
                or folder.st_uid != expected_owner
                or stat.S_IMODE(folder.st_mode) != expected_mode
                or (reviewed_rootless and folder.st_gid != directory_group_gid)):
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
