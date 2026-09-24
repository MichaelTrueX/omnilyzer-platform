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

from .execution import (
    ExecutorRequest,
    IngressFileReference,
    IngressReference,
    MAX_IDENTIFIER,
    NoSecretsReference,
    RuntimeConfigurationReference,
)
from .identity import (
    DEV_REPOSITORY_ID,
    DEV_WORKFLOW_REF,
    MAX_TOKEN_LIFETIME_SECONDS,
    validate_jti,
)
from .policy import (
    DeploymentPolicyError,
    canonical_bytes,
    closed_object,
    validate_digest,
    validate_event_id,
    validate_identity,
    validate_repository,
    validate_semver,
    validate_sha256,
    validate_slot,
    validate_source_sha,
    validate_stage,
    validate_timestamp,
)


AUDIT_SCHEMA_VERSION = 2
AUDIT_EXECUTION_IDENTITY_SCHEMA_VERSION = 1
EVENT_TYPES = (
    "promotion_requested", "promotion_rejected", "promotion_started",
    "migration_started", "migration_succeeded", "migration_failed",
    "liveness_passed", "liveness_failed", "readiness_passed", "readiness_failed",
    "traffic_switch_started", "traffic_switch_succeeded", "traffic_switch_failed",
    "promotion_succeeded", "promotion_failed",
    "rollback_started", "rollback_succeeded", "rollback_failed",
)
RESULTS = ("started", "succeeded", "failed", "rejected")
EVENT_FIELDS = {
    "schema_version", "event_id", "event_type", "stage", "release_version",
    "source_sha", "oci_repository", "digest", "previous_digest", "active_slot",
    "candidate_slot", "execution_identity", "migration_identity", "result", "timestamp",
}
EXECUTION_IDENTITY_FIELDS = {
    "schema_version", "requested_by_actor_id", "github_repository_id",
    "github_workflow_ref", "github_workflow_sha", "github_run_id",
    "github_run_attempt", "oidc_jti", "oidc_issued_at", "oidc_expires_at",
    "promotion_request_sha256", "executor_request_sha256",
}
SENSITIVE_MARKERS = ("password=", "secret=", "token=", "credential=")
AUDIT_PATH = Path("/var/lib/omnilyzer/deployment/audit/events.jsonl")
MAX_EVENT_BYTES = 16 * 1024
ROTATE_BYTES = 10 * 1024 * 1024
ROTATION_RETENTION = 14
CHAIN_FIELDS = {"event", "previous_event_sha256"}
ROTATED_RE = re.compile(r"events\.jsonl\.[0-9]{8}T[0-9]{6}Z\.[0-9a-f]{12}(?:\.gz)?\Z")


def _positive_integer(value: Any, context: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_IDENTIFIER:
        raise DeploymentPolicyError(f"{context} must be a bounded positive integer")
    return value


def _epoch(value: Any, context: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_IDENTIFIER:
        raise DeploymentPolicyError(f"{context} must be a bounded non-negative integer")
    return value


def _executor_request_mapping(request: ExecutorRequest) -> dict[str, Any]:
    runtime = request.runtime_configuration_reference
    secrets = request.secrets_reference
    ingress = request.ingress_reference
    if (type(runtime) is not RuntimeConfigurationReference
            or type(secrets) is not NoSecretsReference
            or type(ingress) is not IngressReference
            or type(ingress.files) is not tuple
            or type(secrets.required) is not tuple
            or secrets.required != ()):
        raise DeploymentPolicyError("executor request nested values are invalid")
    files: list[dict[str, Any]] = []
    for item in ingress.files:
        if type(item) is not IngressFileReference:
            raise DeploymentPolicyError("executor ingress file value is invalid")
        files.append({"path": item.path, "sha256": item.sha256})
    return {
        "schema_version": request.schema_version,
        "operation": request.operation,
        "stage": request.stage,
        "release_version": request.release_version,
        "source_sha": request.source_sha,
        "oci_origin": request.oci_origin,
        "oci_repository": request.oci_repository,
        "manifest_digest": request.manifest_digest,
        "exact_image_reference": request.exact_image_reference,
        "release_manifest_sha256": request.release_manifest_sha256,
        "provenance_sha256": request.provenance_sha256,
        "originating_release_run_id": request.originating_release_run_id,
        "promotion_request_sha256": request.promotion_request_sha256,
        "requested_by_actor_id": request.requested_by_actor_id,
        "github_repository_id": request.github_repository_id,
        "github_workflow_ref": request.github_workflow_ref,
        "github_workflow_sha": request.github_workflow_sha,
        "github_run_id": request.github_run_id,
        "github_run_attempt": request.github_run_attempt,
        "oidc_jti": request.oidc_jti,
        "oidc_issued_at": request.oidc_issued_at,
        "oidc_expires_at": request.oidc_expires_at,
        "runtime_configuration_reference": {
            "schema_version": runtime.schema_version,
            "kind": runtime.kind,
            "repository_id": runtime.repository_id,
            "reviewed_commit": runtime.reviewed_commit,
            "path": runtime.path,
            "sha256": runtime.sha256,
        },
        "secrets_reference": {
            "schema_version": secrets.schema_version,
            "kind": secrets.kind,
            "required": [],
            "reason": secrets.reason,
        },
        "ingress_reference": {
            "schema_version": ingress.schema_version,
            "kind": ingress.kind,
            "repository_id": ingress.repository_id,
            "reviewed_commit": ingress.reviewed_commit,
            "files": files,
            "loopback_address": ingress.loopback_address,
            "loopback_port": ingress.loopback_port,
            "public_origin": ingress.public_origin,
        },
    }


def _revalidate_executor_request(request: ExecutorRequest) -> ExecutorRequest:
    if type(request) is not ExecutorRequest:
        raise DeploymentPolicyError("audit projection requires an ExecutorRequest")
    try:
        first_pass = ExecutorRequest.from_dict(_executor_request_mapping(request))
        normalized = json.loads(canonical_bytes(_executor_request_mapping(first_pass)))
        return ExecutorRequest.from_dict(normalized)
    except (AttributeError, TypeError, ValueError, DeploymentPolicyError) as exc:
        raise DeploymentPolicyError("executor request failed audit validation") from exc


@dataclass(frozen=True)
class AuditExecutionIdentity:
    schema_version: int
    requested_by_actor_id: int
    github_repository_id: int
    github_workflow_ref: str
    github_workflow_sha: str
    github_run_id: int
    github_run_attempt: int
    oidc_jti: str
    oidc_issued_at: int
    oidc_expires_at: int
    promotion_request_sha256: str
    executor_request_sha256: str

    @classmethod
    def from_dict(cls, value: Any) -> "AuditExecutionIdentity":
        data = closed_object(value, EXECUTION_IDENTITY_FIELDS, "audit execution identity")
        if (type(data["schema_version"]) is not int
                or data["schema_version"] != AUDIT_EXECUTION_IDENTITY_SCHEMA_VERSION):
            raise DeploymentPolicyError("unsupported audit execution-identity schema_version")
        for name in (
            "github_workflow_ref", "github_workflow_sha", "oidc_jti",
            "promotion_request_sha256", "executor_request_sha256",
        ):
            if type(data[name]) is not str:
                raise DeploymentPolicyError(f"audit execution identity {name} type is invalid")
        repository_id = _positive_integer(
            data["github_repository_id"], "github_repository_id",
        )
        if repository_id != DEV_REPOSITORY_ID:
            raise DeploymentPolicyError("audit GitHub repository ID is not authorized")
        if data["github_workflow_ref"] != DEV_WORKFLOW_REF:
            raise DeploymentPolicyError("audit GitHub workflow ref is not authorized")
        issued_at = _epoch(data["oidc_issued_at"], "oidc_issued_at")
        expires_at = _epoch(data["oidc_expires_at"], "oidc_expires_at")
        if not 0 < expires_at - issued_at <= MAX_TOKEN_LIFETIME_SECONDS:
            raise DeploymentPolicyError("audit OIDC lifetime is invalid")
        return cls(
            AUDIT_EXECUTION_IDENTITY_SCHEMA_VERSION,
            _positive_integer(data["requested_by_actor_id"], "requested_by_actor_id"),
            repository_id,
            DEV_WORKFLOW_REF,
            validate_source_sha(data["github_workflow_sha"]),
            _positive_integer(data["github_run_id"], "github_run_id"),
            _positive_integer(data["github_run_attempt"], "github_run_attempt"),
            validate_jti(data["oidc_jti"]),
            issued_at,
            expires_at,
            validate_sha256(data["promotion_request_sha256"], "promotion_request_sha256"),
            validate_sha256(data["executor_request_sha256"], "executor_request_sha256"),
        )

    @classmethod
    def from_executor_request(cls, request: ExecutorRequest) -> "AuditExecutionIdentity":
        validated = _revalidate_executor_request(request)
        return cls.from_dict({
            "schema_version": AUDIT_EXECUTION_IDENTITY_SCHEMA_VERSION,
            "requested_by_actor_id": validated.requested_by_actor_id,
            "github_repository_id": validated.github_repository_id,
            "github_workflow_ref": validated.github_workflow_ref,
            "github_workflow_sha": validated.github_workflow_sha,
            "github_run_id": validated.github_run_id,
            "github_run_attempt": validated.github_run_attempt,
            "oidc_jti": validated.oidc_jti,
            "oidc_issued_at": validated.oidc_issued_at,
            "oidc_expires_at": validated.oidc_expires_at,
            "promotion_request_sha256": validated.promotion_request_sha256,
            "executor_request_sha256": validated.sha256(),
        })

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    execution_identity: AuditExecutionIdentity
    migration_identity: str | None
    result: str
    timestamp: str

    @classmethod
    def from_dict(cls, value: Any) -> "AuditEvent":
        data = closed_object(value, EVENT_FIELDS, "audit event")
        if (type(data["schema_version"]) is not int
                or data["schema_version"] != AUDIT_SCHEMA_VERSION):
            raise DeploymentPolicyError("unsupported audit-event schema_version")
        for name in (
            "event_id", "event_type", "stage", "release_version", "source_sha",
            "oci_repository", "digest", "result", "timestamp",
        ):
            if type(data[name]) is not str:
                raise DeploymentPolicyError(f"audit event {name} type is invalid")
        for name in (
            "previous_digest", "active_slot", "candidate_slot", "migration_identity",
        ):
            if data[name] is not None and type(data[name]) is not str:
                raise DeploymentPolicyError(f"audit event {name} type is invalid")
        event_type = data["event_type"]
        result = data["result"]
        if event_type not in EVENT_TYPES or result not in RESULTS:
            raise DeploymentPolicyError("audit event type or result is invalid")
        if event_type == "promotion_failed" and result != "failed":
            raise DeploymentPolicyError("promotion_failed requires failed result")
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
            AUDIT_SCHEMA_VERSION, validate_event_id(data["event_id"]), event_type,
            validate_stage(data["stage"]), validate_semver(data["release_version"]),
            validate_source_sha(data["source_sha"]), validate_repository(data["oci_repository"]),
            validate_digest(data["digest"]), previous_digest, active_slot, candidate_slot,
            AuditExecutionIdentity.from_dict(data["execution_identity"]),
            migration_identity, result,
            validate_timestamp(data["timestamp"]),
        )
        encoded = event.canonical_bytes()
        if len(encoded) > MAX_EVENT_BYTES:
            raise DeploymentPolicyError("audit event exceeds its byte bound")
        lowered = encoded.decode("ascii").lower()
        if any(marker in lowered for marker in SENSITIVE_MARKERS):
            raise DeploymentPolicyError("audit event contains secret-like data")
        return event

    @classmethod
    def for_executor_request(
        cls, request: ExecutorRequest, *, event_id: str, event_type: str,
        previous_digest: str | None, active_slot: str | None,
        candidate_slot: str | None, migration_identity: str | None,
        result: str, timestamp: str,
    ) -> "AuditEvent":
        validated = _revalidate_executor_request(request)
        return cls.from_dict({
            "schema_version": AUDIT_SCHEMA_VERSION,
            "event_id": event_id,
            "event_type": event_type,
            "stage": validated.stage,
            "release_version": validated.release_version,
            "source_sha": validated.source_sha,
            "oci_repository": validated.oci_repository,
            "digest": validated.manifest_digest,
            "previous_digest": previous_digest,
            "active_slot": active_slot,
            "candidate_slot": candidate_slot,
            "execution_identity": AuditExecutionIdentity.from_executor_request(validated).to_dict(),
            "migration_identity": migration_identity,
            "result": result,
            "timestamp": timestamp,
        })

    def require_executor_request(self, request: ExecutorRequest) -> None:
        """Fail unless this validated event belongs to one exact executor request."""

        if type(self) is not AuditEvent:
            raise DeploymentPolicyError("audit event binding requires an AuditEvent")
        validated_event = AuditEvent.from_dict(_audit_event_mapping(self))
        validated_request = _revalidate_executor_request(request)
        expected_identity = AuditExecutionIdentity.from_executor_request(validated_request)
        if (
            validated_event.stage != validated_request.stage
            or validated_event.release_version != validated_request.release_version
            or validated_event.source_sha != validated_request.source_sha
            or validated_event.oci_repository != validated_request.oci_repository
            or validated_event.digest != validated_request.manifest_digest
            or validated_event.execution_identity != expected_identity
        ):
            raise DeploymentPolicyError("audit event does not bind its executor request")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())


def _audit_execution_identity_mapping(identity: AuditExecutionIdentity) -> dict[str, Any]:
    if type(identity) is not AuditExecutionIdentity:
        raise DeploymentPolicyError("audit execution identity type is invalid")
    return {
        "schema_version": identity.schema_version,
        "requested_by_actor_id": identity.requested_by_actor_id,
        "github_repository_id": identity.github_repository_id,
        "github_workflow_ref": identity.github_workflow_ref,
        "github_workflow_sha": identity.github_workflow_sha,
        "github_run_id": identity.github_run_id,
        "github_run_attempt": identity.github_run_attempt,
        "oidc_jti": identity.oidc_jti,
        "oidc_issued_at": identity.oidc_issued_at,
        "oidc_expires_at": identity.oidc_expires_at,
        "promotion_request_sha256": identity.promotion_request_sha256,
        "executor_request_sha256": identity.executor_request_sha256,
    }


def _audit_event_mapping(event: AuditEvent) -> dict[str, Any]:
    if type(event) is not AuditEvent:
        raise DeploymentPolicyError("audit event type is invalid")
    return {
        "schema_version": event.schema_version,
        "event_id": event.event_id,
        "event_type": event.event_type,
        "stage": event.stage,
        "release_version": event.release_version,
        "source_sha": event.source_sha,
        "oci_repository": event.oci_repository,
        "digest": event.digest,
        "previous_digest": event.previous_digest,
        "active_slot": event.active_slot,
        "candidate_slot": event.candidate_slot,
        "execution_identity": _audit_execution_identity_mapping(event.execution_identity),
        "migration_identity": event.migration_identity,
        "result": event.result,
        "timestamp": event.timestamp,
    }


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
        if type(event) is not AuditEvent:
            raise DeploymentPolicyError("audit sink accepts validated AuditEvent values only")
        try:
            event = AuditEvent.from_dict(_audit_event_mapping(event))
        except (AttributeError, TypeError, DeploymentPolicyError) as exc:
            raise DeploymentPolicyError("audit sink rejected an invalid AuditEvent") from exc
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
