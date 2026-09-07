"""Deterministic append-oriented deployment audit event contract."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Protocol

from .policy import (
    SCHEMA_VERSION,
    DeploymentPolicyError,
    canonical_bytes,
    closed_object,
    validate_digest,
    validate_event_id,
    validate_identity,
    validate_repository,
    validate_semver,
    validate_slot,
    validate_source_sha,
    validate_stage,
    validate_timestamp,
)


EVENT_TYPES = (
    "promotion_requested", "promotion_rejected", "promotion_started",
    "migration_started", "migration_succeeded", "migration_failed",
    "liveness_passed", "liveness_failed", "readiness_passed", "readiness_failed",
    "traffic_switch_started", "traffic_switch_succeeded", "traffic_switch_failed",
    "promotion_succeeded", "rollback_started", "rollback_succeeded", "rollback_failed",
)
RESULTS = ("started", "succeeded", "failed", "rejected")
EVENT_FIELDS = {
    "schema_version", "event_id", "event_type", "stage", "release_version",
    "source_sha", "oci_repository", "digest", "previous_digest", "active_slot",
    "candidate_slot", "actor", "migration_identity", "result", "timestamp",
}
SENSITIVE_MARKERS = ("password=", "secret=", "token=", "credential=")


@dataclass(frozen=True)
class AuditEvent:
    schema_version: int
    event_id: str
    event_type: str
    stage: str
    release_version: str
    source_sha: str
    oci_repository: str
    digest: str
    previous_digest: str | None
    active_slot: str | None
    candidate_slot: str | None
    actor: str
    migration_identity: str | None
    result: str
    timestamp: str

    @classmethod
    def from_dict(cls, value: Any) -> "AuditEvent":
        data = closed_object(value, EVENT_FIELDS, "audit event")
        if data["schema_version"] != SCHEMA_VERSION:
            raise DeploymentPolicyError("unsupported audit-event schema_version")
        event_type = data["event_type"]
        result = data["result"]
        if event_type not in EVENT_TYPES or result not in RESULTS:
            raise DeploymentPolicyError("audit event type or result is invalid")
        previous_digest = data["previous_digest"]
        if previous_digest is not None:
            previous_digest = validate_digest(previous_digest, "previous_digest")
        active_slot = validate_slot(data["active_slot"], "active_slot", nullable=True)
        candidate_slot = validate_slot(data["candidate_slot"], "candidate_slot", nullable=True)
        migration_identity = data["migration_identity"]
        if migration_identity is not None:
            migration_identity = validate_identity(migration_identity, "migration_identity")
        if event_type.startswith("migration_") and migration_identity is None:
            raise DeploymentPolicyError("migration events require migration_identity")
        if event_type.startswith("rollback_") and previous_digest is None:
            raise DeploymentPolicyError("rollback events require previous_digest")
        event = cls(
            SCHEMA_VERSION, validate_event_id(data["event_id"]), event_type,
            validate_stage(data["stage"]), validate_semver(data["release_version"]),
            validate_source_sha(data["source_sha"]), validate_repository(data["oci_repository"]),
            validate_digest(data["digest"]), previous_digest, active_slot, candidate_slot,
            validate_identity(data["actor"]), migration_identity, result,
            validate_timestamp(data["timestamp"]),
        )
        encoded = event.canonical_bytes().decode("ascii").lower()
        if any(marker in encoded for marker in SENSITIVE_MARKERS):
            raise DeploymentPolicyError("audit event contains secret-like data")
        return event

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())


class AuditSink(Protocol):
    """Phase 2 supplies an append-only durable backend implementing this contract."""

    def append(self, event: AuditEvent) -> None:
        ...
