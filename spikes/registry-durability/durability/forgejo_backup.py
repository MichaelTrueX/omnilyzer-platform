"""Small integrity wrapper around Forgejo's supported cold dump format."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile

from .forgejo_process import ForgejoBinary, ForgejoProcess


SCHEMA_VERSION = 1
BACKUP_NAMES = {"manifest.json", "forgejo-data.tar", "forgejo-data.tar.sha256"}
LOGICAL_COMPONENTS = ["forgejo-database-metadata", "forgejo-package-storage", "forgejo-config-state"]


class ForgejoBackupError(RuntimeError):
    pass


def _sqlite_unistr(value: str) -> str:
    """Compatibility implementation for SQL dumps from newer Forgejo SQLite."""
    pattern = re.compile(r"\\(?:\\|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|\+([0-9A-Fa-f]{6})|([0-9A-Fa-f]{4}))")

    def replace(match: re.Match[str]) -> str:
        if match.group(0) == "\\\\":
            return "\\"
        codepoint = next(group for group in match.groups() if group is not None)
        return chr(int(codepoint, 16))

    return pattern.sub(replace, value)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_name(name: str) -> str:
    if not name or "\\" in name or "\x00" in name:
        raise ForgejoBackupError("unsafe archive path")
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name or any(part in ("", ".", "..") for part in path.parts):
        raise ForgejoBackupError("unsafe archive path")
    allowed = name in {"app.ini", "forgejo-db.sql"} or name.startswith(("custom/", "data/", "repos/"))
    if not allowed:
        raise ForgejoBackupError("unexpected Forgejo dump structure")
    return name


def create_forgejo_backup(
    process: ForgejoProcess,
    destination: Path,
    package_evidence: dict[str, dict[str, object]],
) -> dict[str, object]:
    if process.process is not None:
        raise ForgejoBackupError("Forgejo must be stopped for a cold dump")
    if destination.exists():
        raise ForgejoBackupError("backup destination already exists")
    destination.mkdir(mode=0o700)
    archive = destination / "forgejo-data.tar"
    with tempfile.TemporaryDirectory(prefix="task012b-forgejo-dump-") as temporary:
        process._command(
            "dump", "--file", str(archive), "--type", "tar", "--skip-log", "--tempdir", temporary
        )
    archive_sha = _sha(archive)
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "forgejo_version": process.binary.version,
        "forgejo_binary_path": process.binary.recorded_path,
        "forgejo_binary_sha256": process.binary.sha256,
        "backup_mode": "cold",
        "source": "synthetic Task 012B data",
        "logical_components": LOGICAL_COMPONENTS,
        "archive_sha256": archive_sha,
        "packages": package_evidence,
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (destination / "forgejo-data.tar.sha256").write_text(
        f"{archive_sha}  forgejo-data.tar\n", encoding="ascii"
    )
    destination.chmod(0o700)
    for path in destination.iterdir():
        path.chmod(0o600)
    verify_forgejo_backup(destination, process.binary)
    return manifest


def verify_forgejo_backup(
    backup: Path, binary: ForgejoBinary
) -> tuple[dict[str, object], dict[str, tuple[bytes, int]], set[str]]:
    if backup.is_symlink() or not backup.is_dir():
        raise ForgejoBackupError("backup must be a regular directory")
    entries = list(backup.iterdir())
    if {path.name for path in entries} != BACKUP_NAMES or any(
        path.is_symlink() or not path.is_file() for path in entries
    ):
        raise ForgejoBackupError("backup structure is not exact")
    archive = backup / "forgejo-data.tar"
    archive_sha = _sha(archive)
    if (backup / "forgejo-data.tar.sha256").read_text(encoding="ascii") != (
        f"{archive_sha}  forgejo-data.tar\n"
    ):
        raise ForgejoBackupError("archive checksum mismatch")
    try:
        manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ForgejoBackupError("backup manifest is malformed") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "forgejo_version", "forgejo_binary_path", "forgejo_binary_sha256",
        "backup_mode", "source", "logical_components", "archive_sha256", "packages",
    }:
        raise ForgejoBackupError("backup manifest fields are not exact")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ForgejoBackupError("unknown backup schema")
    if (
        manifest["forgejo_version"] != binary.version
        or manifest["forgejo_binary_path"] != binary.recorded_path
        or manifest["forgejo_binary_sha256"] != binary.sha256
    ):
        raise ForgejoBackupError("Forgejo binary metadata mismatch")
    if manifest["backup_mode"] != "cold" or manifest["source"] != "synthetic Task 012B data":
        raise ForgejoBackupError("backup source or mode is unexpected")
    if manifest["logical_components"] != LOGICAL_COMPONENTS or manifest["archive_sha256"] != archive_sha:
        raise ForgejoBackupError("backup component or archive integrity mismatch")
    packages = manifest["packages"]
    if not isinstance(packages, dict) or set(packages) != {"Generic", "PyPI", "npm"}:
        raise ForgejoBackupError("package evidence is incomplete")
    for package in packages.values():
        if (
            not isinstance(package, dict)
            or set(package) != {"sha256", "length"}
            or not isinstance(package["sha256"], str)
            or len(package["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in package["sha256"])
            or not isinstance(package["length"], int)
            or package["length"] <= 0
        ):
            raise ForgejoBackupError("package evidence is malformed")

    files: dict[str, tuple[bytes, int]] = {}
    directories: set[str] = set()
    seen: set[str] = set()
    try:
        with tarfile.open(archive, mode="r:") as payload:
            for member in payload:
                name = _safe_name(member.name)
                if name in seen:
                    raise ForgejoBackupError("duplicate archive path")
                seen.add(name)
                if member.isdir():
                    directories.add(name)
                elif member.isreg():
                    stream = payload.extractfile(member)
                    if stream is None:
                        raise ForgejoBackupError("unreadable archive file")
                    content = stream.read()
                    if len(content) != member.size:
                        raise ForgejoBackupError("archive file size mismatch")
                    files[name] = (content, member.mode)
                else:
                    raise ForgejoBackupError("links and special archive members are forbidden")
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ForgejoBackupError("Forgejo dump archive is corrupt") from error
    if "forgejo-db.sql" not in files or "custom/conf/app.ini" not in files:
        raise ForgejoBackupError("Forgejo database or config component is missing")
    if not any(name.startswith("data/packages/") for name in files):
        raise ForgejoBackupError("Forgejo package storage component is missing")
    return manifest, files, directories


def restore_forgejo_backup(backup: Path, destination: Path, binary: ForgejoBinary) -> dict[str, object]:
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ForgejoBackupError("restore destination must be a new empty directory")
    manifest, files, directories = verify_forgejo_backup(backup, binary)
    staging = Path(tempfile.mkdtemp(prefix=".task012b-restore-", dir=destination.parent))
    installed = False
    try:
        (staging / "data").mkdir(mode=0o700)
        for name in sorted(directories):
            if name == "data" or not name.startswith("data/"):
                continue
            (staging / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        for name, (content, mode) in files.items():
            if not name.startswith("data/"):
                continue
            target = staging / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(stat.S_IMODE(mode))
        database = sqlite3.connect(staging / "forgejo.db")
        try:
            database.create_function("unistr", 1, _sqlite_unistr, deterministic=True)
            database.executescript(files["forgejo-db.sql"][0].decode("utf-8"))
        except (UnicodeDecodeError, sqlite3.DatabaseError) as error:
            raise ForgejoBackupError("Forgejo database dump cannot be restored") from error
        finally:
            database.close()
        destination.rmdir()
        os.replace(staging, destination)
        installed = True
    finally:
        if not installed and staging.exists():
            shutil.rmtree(staging)
    return {
        "restored": True,
        "logical_components": manifest["logical_components"],
        "archive_sha256": manifest["archive_sha256"],
    }
