"""Closed blue/green deployment state with atomic persistence."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .policy import (
    SCHEMA_VERSION,
    DeploymentPolicyError,
    canonical_bytes,
    closed_object,
    validate_digest,
    validate_event_id,
    validate_semver,
    validate_slot,
    validate_source_sha,
    validate_stage,
    validate_timestamp,
)


MIGRATION_STATUSES = ("none", "pending", "running", "succeeded", "failed")
DEV_STATE_PATH = Path("/var/lib/omnilyzer/deployment/dev/state.json")
STATE_DIRECTORY_MODE = 0o700
STATE_FILE_MODE = 0o600
STATE_FIELDS = {
    "schema_version", "stage",
    "active_release", "active_source_sha", "active_digest", "active_slot",
    "previous_release", "previous_source_sha", "previous_digest", "previous_slot",
    "candidate_release", "candidate_source_sha", "candidate_digest", "candidate_slot",
    "migration_state", "updated_at", "event_id",
}
MIGRATION_FIELDS = {"status", "identity", "checksum", "serialized_lock_required"}


@dataclass(frozen=True)
class MigrationState:
    status: str
    identity: str | None
    checksum: str | None
    serialized_lock_required: bool

    @classmethod
    def from_dict(cls, value: Any) -> "MigrationState":
        data = closed_object(value, MIGRATION_FIELDS, "migration state")
        status = data["status"]
        if status not in MIGRATION_STATUSES:
            raise DeploymentPolicyError("unknown migration status")
        identity, checksum = data["identity"], data["checksum"]
        if status == "none":
            if identity is not None or checksum is not None:
                raise DeploymentPolicyError("empty migration state may not carry identity or checksum")
        else:
            if not isinstance(identity, str) or not identity or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in identity):
                raise DeploymentPolicyError("migration identity is not bounded")
            if not isinstance(checksum, str) or len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum):
                raise DeploymentPolicyError("migration checksum must be 64 lowercase hexadecimal characters")
        if data["serialized_lock_required"] is not True:
            raise DeploymentPolicyError("migration execution must require a serialized lock")
        return cls(status, identity, checksum, True)


def verify_migration_history(identity: str, checksum: str, history: dict[str, str]) -> bool:
    candidate = MigrationState.from_dict({
        "status": "pending", "identity": identity, "checksum": checksum,
        "serialized_lock_required": True,
    })
    recorded = history.get(candidate.identity)
    if recorded is not None and recorded != candidate.checksum:
        raise DeploymentPolicyError("previously recorded migration checksum changed")
    return recorded == candidate.checksum


@dataclass(frozen=True)
class DeploymentState:
    schema_version: int
    stage: str
    active_release: str | None
    active_source_sha: str | None
    active_digest: str | None
    active_slot: str | None
    previous_release: str | None
    previous_source_sha: str | None
    previous_digest: str | None
    previous_slot: str | None
    candidate_release: str | None
    candidate_source_sha: str | None
    candidate_digest: str | None
    candidate_slot: str | None
    migration_state: MigrationState
    updated_at: str
    event_id: str

    @staticmethod
    def _identity(
        release: Any, source_sha: Any, digest: Any, slot: Any, context: str,
    ) -> tuple[str | None, str | None, str | None, str | None]:
        values = (release, source_sha, digest, slot)
        if values == (None, None, None, None):
            return values
        if any(value is None for value in values):
            raise DeploymentPolicyError(f"{context} identity must be complete or empty")
        return (
            validate_semver(release), validate_source_sha(source_sha),
            validate_digest(digest, f"{context}_digest"), validate_slot(slot, f"{context}_slot"),
        )

    @classmethod
    def from_dict(cls, value: Any) -> "DeploymentState":
        data = closed_object(value, STATE_FIELDS, "deployment state")
        if data["schema_version"] != SCHEMA_VERSION:
            raise DeploymentPolicyError("unsupported deployment-state schema_version")
        active = cls._identity(
            data["active_release"], data["active_source_sha"], data["active_digest"],
            data["active_slot"], "active",
        )
        previous = cls._identity(
            data["previous_release"], data["previous_source_sha"], data["previous_digest"],
            data["previous_slot"], "previous",
        )
        candidate = cls._identity(
            data["candidate_release"], data["candidate_source_sha"], data["candidate_digest"],
            data["candidate_slot"], "candidate",
        )
        if active[3] is not None and candidate[3] == active[3]:
            raise DeploymentPolicyError("candidate slot must differ from the active slot")
        if active[3] is not None and previous[3] == active[3]:
            raise DeploymentPolicyError("previous slot must differ from the active slot")
        return cls(
            SCHEMA_VERSION, validate_stage(data["stage"]), *active, *previous, *candidate,
            MigrationState.from_dict(data["migration_state"]),
            validate_timestamp(data["updated_at"]), validate_event_id(data["event_id"]),
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["migration_state"] = asdict(self.migration_state)
        return value

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())


def load_state(path: Path) -> DeploymentState:
    if path.is_symlink() or not path.is_file():
        raise DeploymentPolicyError("deployment state must be a regular file")
    try:
        return DeploymentState.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentPolicyError("deployment state is not valid JSON") from exc


def write_state_atomic(path: Path, state: DeploymentState) -> None:
    path = Path(path)
    path.parent.mkdir(mode=STATE_DIRECTORY_MODE, parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise DeploymentPolicyError("deployment state directory must be a real directory")
    os.chmod(path.parent, STATE_DIRECTORY_MODE)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, STATE_FILE_MODE)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(state.canonical_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
