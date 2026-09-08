"""Deterministic append-oriented deployment audit event contract."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import datetime as dt
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
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
AUDIT_PATH = Path("/var/log/omnilyzer/deployment/dev/events.jsonl")
MAX_EVENT_BYTES = 16 * 1024
ROTATE_BYTES = 10 * 1024 * 1024
ROTATION_RETENTION = 14
CHAIN_FIELDS = {"event", "previous_event_sha256"}
ROTATED_RE = re.compile(r"events\.jsonl\.[0-9]{8}T[0-9]{6}Z\.[0-9a-f]{12}(?:\.gz)?\Z")


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


@dataclass(frozen=True)
class ChainedAuditRecord:
    event: AuditEvent
    previous_event_sha256: str | None

    @classmethod
    def from_dict(cls, value: Any) -> "ChainedAuditRecord":
        data = closed_object(value, CHAIN_FIELDS, "chained audit record")
        previous = data["previous_event_sha256"]
        if previous is not None:
            if not isinstance(previous, str) or re.fullmatch(r"[0-9a-f]{64}", previous) is None:
                raise DeploymentPolicyError("previous audit event hash is invalid")
        return cls(AuditEvent.from_dict(data["event"]), previous)

    def canonical_bytes(self) -> bytes:
        return canonical_bytes({
            "event": self.event.to_dict(),
            "previous_event_sha256": self.previous_event_sha256,
        })

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class FilesystemAuditSink:
    """Owner-controlled, tamper-evident JSONL sink with bounded rotation.

    This detects chain modification under normal operation. It is not resistant
    to a root user rewriting both logs and chain history.
    """

    def __init__(
        self, path: Path = AUDIT_PATH, *, rotate_bytes: int = ROTATE_BYTES,
        retention: int = ROTATION_RETENTION,
    ) -> None:
        self.path = Path(path)
        if not 1024 <= rotate_bytes <= ROTATE_BYTES:
            raise DeploymentPolicyError("audit rotation threshold is outside its bound")
        if retention != ROTATION_RETENTION:
            raise DeploymentPolicyError("audit retention must be exactly 14 rotations")
        self.rotate_bytes = rotate_bytes
        self.retention = retention

    @staticmethod
    def _decode_lines(raw: bytes, context: str) -> list[ChainedAuditRecord]:
        if raw and not raw.endswith(b"\n"):
            raise DeploymentPolicyError(f"{context} has a partial final event")
        records: list[ChainedAuditRecord] = []
        for line in raw.splitlines(keepends=True):
            if len(line) > MAX_EVENT_BYTES:
                raise DeploymentPolicyError(f"{context} contains an oversized event")
            try:
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DeploymentPolicyError(f"{context} contains malformed JSON") from exc
            record = ChainedAuditRecord.from_dict(value)
            if record.canonical_bytes() != line:
                raise DeploymentPolicyError(f"{context} contains noncanonical JSON")
            records.append(record)
        return records

    def _files(self) -> list[Path]:
        if not self.path.parent.exists():
            return []
        values = []
        for candidate in self.path.parent.iterdir():
            if candidate.name == self.path.name or ROTATED_RE.fullmatch(candidate.name):
                if candidate.is_symlink() or not candidate.is_file():
                    raise DeploymentPolicyError("audit history contains a non-regular file")
                values.append(candidate)
        rotations = sorted(item for item in values if item != self.path)
        return rotations + ([self.path] if self.path in values else [])

    @staticmethod
    def _read(path: Path) -> bytes:
        if path.suffix == ".gz":
            try:
                with gzip.open(path, "rb") as stream:
                    raw = stream.read(ROTATE_BYTES + MAX_EVENT_BYTES + 1)
            except (OSError, EOFError) as exc:
                raise DeploymentPolicyError("compressed audit history is malformed") from exc
        else:
            raw = path.read_bytes()
        if len(raw) > ROTATE_BYTES + MAX_EVENT_BYTES:
            raise DeploymentPolicyError("audit history file exceeds its rotation bound")
        return raw

    def _validate_history(self) -> tuple[str | None, set[str], str | None]:
        previous: str | None = None
        event_ids: set[str] = set()
        last_day: str | None = None
        files = self._files()
        anchored_retained_history = bool(files and files[0] != self.path)
        first = True
        for path in files:
            records = self._decode_lines(self._read(path), path.name)
            for record in records:
                if first and anchored_retained_history:
                    previous = record.previous_event_sha256
                if record.previous_event_sha256 != previous:
                    raise DeploymentPolicyError("audit hash-chain continuity failed")
                if record.event.event_id in event_ids:
                    raise DeploymentPolicyError("duplicate audit event_id")
                event_ids.add(record.event.event_id)
                previous = record.sha256()
                last_day = record.event.timestamp[:10]
                first = False
        return previous, event_ids, last_day

    def _compress_delayed(self, newest_rotation: Path) -> None:
        rotations = [item for item in self._files() if item != self.path]
        plain = [item for item in rotations if item.suffix != ".gz" and item != newest_rotation]
        for source in plain:
            target = source.with_name(source.name + ".gz")
            descriptor, name = tempfile.mkstemp(prefix=".audit-compress.", dir=source.parent)
            temporary = Path(name)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as raw_stream:
                    with gzip.GzipFile(filename="", mode="wb", fileobj=raw_stream, mtime=0) as stream:
                        stream.write(source.read_bytes())
                    raw_stream.flush()
                    os.fsync(raw_stream.fileno())
                if target.exists():
                    raise DeploymentPolicyError("audit compression target already exists")
                os.replace(temporary, target)
                source.unlink()
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
        rotations = [item for item in self._files() if item != self.path]
        while len(rotations) > self.retention:
            rotations.pop(0).unlink()

    def _rotate(self, previous_hash: str, last_timestamp: str) -> None:
        suffix = last_timestamp.replace("-", "").replace(":", "")
        target = self.path.with_name(f"events.jsonl.{suffix}.{previous_hash[:12]}")
        if target.exists():
            raise DeploymentPolicyError("audit rotation target already exists")
        os.replace(self.path, target)
        self._compress_delayed(target)

    def append(self, event: AuditEvent) -> None:
        if not isinstance(event, AuditEvent):
            raise DeploymentPolicyError("audit sink accepts validated AuditEvent values only")
        directory = self.path.parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise DeploymentPolicyError("audit directory must be a real directory")
        os.chmod(directory, 0o700)
        lock_path = directory / ".events.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "r+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                previous, event_ids, last_day = self._validate_history()
                if event.event_id in event_ids:
                    raise DeploymentPolicyError("duplicate audit event_id")
                record = ChainedAuditRecord(event, previous)
                payload = record.canonical_bytes()
                if len(payload) > MAX_EVENT_BYTES:
                    raise DeploymentPolicyError("audit event exceeds its byte bound")
                current_size = self.path.stat().st_size if self.path.exists() else 0
                rotate = current_size > 0 and (
                    current_size + len(payload) > self.rotate_bytes
                    or (last_day is not None and last_day != event.timestamp[:10])
                )
                if rotate:
                    assert previous is not None
                    records = self._decode_lines(self.path.read_bytes(), self.path.name)
                    self._rotate(previous, records[-1].event.timestamp)
                output = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                try:
                    os.fchmod(output, 0o600)
                    if os.write(output, payload) != len(payload):
                        raise DeploymentPolicyError("short audit append")
                    os.fsync(output)
                finally:
                    os.close(output)
                directory_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except OSError as exc:
            raise DeploymentPolicyError("audit filesystem operation failed closed") from exc
