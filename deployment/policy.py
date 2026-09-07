"""Closed validation rules shared by the deployment control plane."""

from __future__ import annotations

import json
import re
from typing import Any


SCHEMA_VERSION = 1
STAGES = ("dev", "staging", "prod")
SLOTS = ("blue", "green")
APPROVED_OCI_ORIGIN = "https://oci-dev.omnilyzer.ai"
APPROVED_OCI_HOST = "oci-dev.omnilyzer.ai"
APPROVED_OCI_REPOSITORIES = ("omnilyzer/task013-release-canary",)
EXPECTED_RELEASE_WORKFLOW = (
    "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml"
    "@refs/heads/main"
)
EXPECTED_CERTIFICATE_IDENTITY = "https://github.com/" + EXPECTED_RELEASE_WORKFLOW
EXPECTED_CERTIFICATE_ISSUER = "https://token.actions.githubusercontent.com"

SEMVER_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}\Z")
EVENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)


class DeploymentPolicyError(ValueError):
    """Input violates a closed Task 014 deployment policy."""


def closed_object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DeploymentPolicyError(f"{context} must be an object")
    actual = set(value)
    if actual != fields:
        raise DeploymentPolicyError(
            f"{context} fields differ: missing={sorted(fields - actual)} "
            f"unknown={sorted(actual - fields)}"
        )
    return value


def nonempty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeploymentPolicyError(f"{context} must be a non-empty string")
    return value


def validate_semver(value: Any) -> str:
    value = nonempty_string(value, "release_version")
    if SEMVER_RE.fullmatch(value) is None:
        raise DeploymentPolicyError("release_version must be strict X.Y.Z")
    return value


def validate_source_sha(value: Any) -> str:
    value = nonempty_string(value, "source_sha")
    if SOURCE_SHA_RE.fullmatch(value) is None or value == "0" * 40:
        raise DeploymentPolicyError("source_sha must be a non-zero lowercase 40-character SHA")
    return value


def validate_digest(value: Any, context: str = "manifest_digest") -> str:
    value = nonempty_string(value, context)
    if DIGEST_RE.fullmatch(value) is None:
        raise DeploymentPolicyError(f"{context} must be sha256:<64 lowercase hexadecimal>")
    return value


def validate_sha256(value: Any, context: str) -> str:
    value = nonempty_string(value, context)
    if SHA256_RE.fullmatch(value) is None:
        raise DeploymentPolicyError(f"{context} must be 64 lowercase hexadecimal characters")
    return value


def validate_stage(value: Any) -> str:
    if value not in STAGES:
        raise DeploymentPolicyError(f"stage must be one of {STAGES}")
    return value


def validate_slot(value: Any, context: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if value not in SLOTS:
        raise DeploymentPolicyError(f"{context} must be one of {SLOTS}")
    return value


def validate_repository(value: Any) -> str:
    value = nonempty_string(value, "oci_repository")
    if value not in APPROVED_OCI_REPOSITORIES:
        raise DeploymentPolicyError("OCI repository is outside the explicit deployment allowlist")
    if ":" in value or "@" in value:
        raise DeploymentPolicyError("OCI repository may not include a mutable tag or digest")
    return value


def exact_image_reference(repository: str, digest: str) -> str:
    return f"{APPROVED_OCI_HOST}/{validate_repository(repository)}@{validate_digest(digest)}"


def validate_identity(value: Any, context: str = "actor identity") -> str:
    value = nonempty_string(value, context)
    if IDENTITY_RE.fullmatch(value) is None:
        raise DeploymentPolicyError(f"{context} is not a bounded identity")
    return value


def validate_event_id(value: Any) -> str:
    value = nonempty_string(value, "event_id")
    if EVENT_ID_RE.fullmatch(value) is None:
        raise DeploymentPolicyError("event_id is not bounded")
    return value


def validate_timestamp(value: Any) -> str:
    value = nonempty_string(value, "timestamp")
    if TIMESTAMP_RE.fullmatch(value) is None:
        raise DeploymentPolicyError("timestamp must be second-precision UTC RFC3339")
    return value


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
