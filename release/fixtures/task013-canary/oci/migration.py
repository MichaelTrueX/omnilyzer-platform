"""Explicit synthetic migration marker; never invoked by application startup."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any


RUNTIME_ROOT = Path("/run/omnilyzer-canary")
DEFINITION_PATH = Path("/app/migration-definition.json")
MARKER_PATH = RUNTIME_ROOT / "migration.json"
LOCK_PATH = RUNTIME_ROOT / "migration.lock"
IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
DEFINITION_FIELDS = {"schema_version", "migration_identity", "operation"}
MARKER_FIELDS = {"schema_version", "migration_identity", "migration_checksum", "completed"}


class MigrationError(ValueError):
    pass


def _object(raw: bytes, fields: set[str], context: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError(f"{context} is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != fields:
        raise MigrationError(f"{context} differs from its closed schema")
    return value


def expected_migration(definition_path: Path = DEFINITION_PATH) -> tuple[str, str]:
    if definition_path.is_symlink() or not definition_path.is_file():
        raise MigrationError("migration definition must be a regular file")
    raw = definition_path.read_bytes()
    value = _object(raw, DEFINITION_FIELDS, "migration definition")
    identity = value["migration_identity"]
    if (value["schema_version"] != 1 or value["operation"] != "write-readiness-marker"
            or not isinstance(identity, str) or IDENTITY_RE.fullmatch(identity) is None):
        raise MigrationError("migration definition values are invalid")
    return identity, hashlib.sha256(raw).hexdigest()


def validate_marker(marker_path: Path, definition_path: Path = DEFINITION_PATH) -> bool:
    identity, checksum = expected_migration(definition_path)
    if marker_path.is_symlink() or not marker_path.is_file():
        return False
    value = _object(marker_path.read_bytes(), MARKER_FIELDS, "migration marker")
    if value != {
        "schema_version": 1,
        "migration_identity": identity,
        "migration_checksum": checksum,
        "completed": True,
    }:
        raise MigrationError("migration marker identity or checksum differs")
    return True


def _write_marker(marker_path: Path, identity: str, checksum: str) -> None:
    payload = (json.dumps({
        "completed": True,
        "migration_checksum": checksum,
        "migration_identity": identity,
        "schema_version": 1,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{marker_path.name}.", dir=marker_path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, marker_path)
        directory = os.open(marker_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def execute(
    marker_path: Path = MARKER_PATH,
    lock_path: Path = LOCK_PATH,
    definition_path: Path = DEFINITION_PATH,
) -> None:
    marker_path.parent.mkdir(parents=False, exist_ok=True)
    if marker_path.parent != lock_path.parent:
        raise MigrationError("marker and lock must share the narrow runtime directory")
    identity, checksum = expected_migration(definition_path)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if marker_path.exists() or marker_path.is_symlink():
                if not validate_marker(marker_path, definition_path):
                    raise MigrationError("existing migration marker is invalid")
                return
            _write_marker(marker_path, identity, checksum)
    except OSError as exc:
        raise MigrationError("migration lock or marker operation failed") from exc


if __name__ == "__main__":
    execute()
