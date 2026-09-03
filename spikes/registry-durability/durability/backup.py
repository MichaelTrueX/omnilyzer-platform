"""Strict integrity-manifested cold backup for a filesystem-backed zot store."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any

from .zot_process import VerifiedBinary


SCHEMA_VERSION = 1
BACKUP_FILES = {"manifest.json", "payload.tar", "payload.tar.sha256"}
SOURCE_CLASSIFICATION = "synthetic Task 012 data"


class BackupError(RuntimeError):
    """The source or backup violates the fail-closed Task 012A format."""


def _digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BackupError("backup path contains unsafe characters")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in ("", ".", "..") for part in path.parts):
        raise BackupError("backup path is not a normalized relative path")
    return path


def _walk_source(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    files: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative)
            if stat.S_ISLNK(metadata.st_mode):
                raise BackupError(f"symbolic link is not permitted: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.append({"path": relative, "mode": stat.S_IMODE(metadata.st_mode)})
                visit(path)
            elif stat.S_ISREG(metadata.st_mode):
                files.append({
                    "path": relative,
                    "size": metadata.st_size,
                    "sha256": _digest_file(path),
                    "mode": stat.S_IMODE(metadata.st_mode),
                })
            else:
                raise BackupError(f"unsupported filesystem object: {relative}")

    visit(root)
    return files, directories


def create_backup(source: Path, destination: Path, binary: VerifiedBinary) -> dict[str, Any]:
    """Create a cold backup; the caller must already have stopped zot."""
    if source.is_symlink():
        raise BackupError("source storage root must not be a symbolic link")
    source = source.resolve(strict=True)
    if source == Path("/var/lib/zot") or not source.is_dir():
        raise BackupError("source must be an isolated regular directory")
    if destination.exists():
        raise BackupError("backup destination must not already exist")
    destination.mkdir(mode=0o700, parents=False)
    os.chmod(destination, 0o700)
    files, directories = _walk_source(source)
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "zot_version": binary.version,
        "zot_binary_sha256": binary.sha256,
        "backup_mode": "cold",
        "source_classification": SOURCE_CLASSIFICATION,
        "root_mode": stat.S_IMODE(source.stat().st_mode),
        "directories": directories,
        "files": files,
    }
    payload = destination / "payload.tar"
    with tarfile.open(payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for item in directories:
            member = tarfile.TarInfo(item["path"])
            member.type = tarfile.DIRTYPE
            member.mode = item["mode"]
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = 0
            archive.addfile(member)
        for item in files:
            member = tarfile.TarInfo(item["path"])
            member.type = tarfile.REGTYPE
            member.size = item["size"]
            member.mode = item["mode"]
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = 0
            with (source / item["path"]).open("rb") as stream:
                archive.addfile(member, stream)
    payload_sha = _digest_file(payload)
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (destination / "payload.tar.sha256").write_text(
        f"{payload_sha}  payload.tar\n", encoding="ascii"
    )
    for path in destination.iterdir():
        path.chmod(0o600)
    return manifest


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BackupError(f"{label} fields are not exact")
    return value


def verify_backup(
    backup: Path,
    *,
    expected_zot_version: str,
    expected_binary_sha256: str,
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, int]]:
    """Fully validate backup metadata and archive without extracting it."""
    if backup.is_symlink():
        raise BackupError("backup directory must not be a symbolic link")
    backup = backup.resolve(strict=True)
    if not backup.is_dir():
        raise BackupError("backup must be a regular directory")
    entries = list(backup.iterdir())
    if {entry.name for entry in entries} != BACKUP_FILES:
        raise BackupError("backup file set is not exact")
    if any(not entry.is_file() or entry.is_symlink() for entry in entries):
        raise BackupError("backup contains a non-regular top-level object")
    checksum_line = (backup / "payload.tar.sha256").read_text(encoding="ascii")
    expected_line = f"{_digest_file(backup / 'payload.tar')}  payload.tar\n"
    if checksum_line != expected_line:
        raise BackupError("payload archive SHA-256 mismatch")
    try:
        manifest_value = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BackupError("backup manifest is malformed") from error
    manifest = _exact_mapping(manifest_value, {
        "schema_version", "created_at_utc", "zot_version", "zot_binary_sha256",
        "backup_mode", "source_classification", "root_mode", "directories", "files",
    }, "backup manifest")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise BackupError("unknown backup manifest schema")
    if not isinstance(manifest["created_at_utc"], str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        manifest["created_at_utc"],
    ) is None:
        raise BackupError("backup creation timestamp is invalid")
    if manifest["backup_mode"] != "cold" or manifest["source_classification"] != SOURCE_CLASSIFICATION:
        raise BackupError("backup provenance is outside Task 012A")
    if manifest["zot_version"] != expected_zot_version:
        raise BackupError("backup zot version does not match the tested contract")
    if manifest["zot_binary_sha256"] != expected_binary_sha256:
        raise BackupError("backup zot binary SHA-256 does not match the tested contract")
    if not isinstance(manifest["root_mode"], int) or not 0 <= manifest["root_mode"] <= 0o777:
        raise BackupError("backup root mode is invalid")

    file_records: dict[str, dict[str, Any]] = {}
    for raw in manifest["files"] if isinstance(manifest["files"], list) else ():
        item = _exact_mapping(raw, {"path", "size", "sha256", "mode"}, "file record")
        path = str(_safe_relative(item["path"]))
        if path in file_records:
            raise BackupError("duplicate manifest file path")
        if (
            not isinstance(item["size"], int)
            or item["size"] < 0
            or not isinstance(item["mode"], int)
            or not 0 <= item["mode"] <= 0o777
            or not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in item["sha256"])
        ):
            raise BackupError("file record metadata is invalid")
        file_records[path] = item
    if list(file_records) != sorted(file_records):
        raise BackupError("manifest files are not sorted")

    directory_records: dict[str, int] = {}
    for raw in manifest["directories"] if isinstance(manifest["directories"], list) else ():
        item = _exact_mapping(raw, {"path", "mode"}, "directory record")
        path = str(_safe_relative(item["path"]))
        if path in directory_records or path in file_records:
            raise BackupError("duplicate manifest path")
        if not isinstance(item["mode"], int) or not 0 <= item["mode"] <= 0o777:
            raise BackupError("directory mode is invalid")
        directory_records[path] = item["mode"]
    if list(directory_records) != sorted(directory_records):
        raise BackupError("manifest directories are not sorted")

    archive_files: dict[str, bytes] = {}
    archive_file_modes: dict[str, int] = {}
    archive_directories: dict[str, int] = {}
    seen: set[str] = set()
    try:
        with tarfile.open(backup / "payload.tar", mode="r:") as archive:
            for member in archive:
                path = str(_safe_relative(member.name))
                if path in seen:
                    raise BackupError("duplicate archive path")
                seen.add(path)
                if member.isdir():
                    archive_directories[path] = member.mode
                elif member.isreg():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise BackupError("regular archive member is unreadable")
                    content = stream.read()
                    if len(content) != member.size:
                        raise BackupError("archive member size mismatch")
                    archive_files[path] = content
                    archive_file_modes[path] = member.mode
                else:
                    raise BackupError("unsupported archive member type")
    except (tarfile.TarError, EOFError, OSError) as error:
        raise BackupError("payload archive is corrupt") from error
    if set(archive_files) != set(file_records):
        raise BackupError("archive and manifest file sets differ")
    if archive_directories != directory_records:
        raise BackupError("archive and manifest directory sets differ")
    for path, content in archive_files.items():
        item = file_records[path]
        if len(content) != item["size"]:
            raise BackupError(f"size mismatch for {path}")
        if hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise BackupError(f"SHA-256 mismatch for {path}")
        if archive_file_modes[path] != item["mode"]:
            raise BackupError(f"mode mismatch for {path}")
    return manifest, archive_files, archive_directories
