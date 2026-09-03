"""Fail-closed fresh restore for a verified Task 012A backup."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile

from .backup import BackupError, verify_backup
from .zot_process import VerifiedBinary


def restore_backup(backup: Path, destination: Path, binary: VerifiedBinary) -> dict[str, object]:
    """Verify completely, stage separately, then atomically install into an empty root."""
    if destination.is_symlink():
        raise BackupError("restore destination must not be a symbolic link")
    absolute_destination = destination.absolute()
    if absolute_destination in (Path("/var/lib/zot"), Path("/etc/zot")):
        raise BackupError("refusing to restore into a live zot path")
    if not destination.exists() or destination.is_symlink() or not destination.is_dir():
        raise BackupError("restore destination must be a new empty directory")
    if any(destination.iterdir()):
        raise BackupError("restore destination is not empty")
    manifest, files, directories = verify_backup(
        backup,
        expected_zot_version=binary.version,
        expected_binary_sha256=binary.sha256,
    )
    parent = destination.resolve().parent
    staging = Path(tempfile.mkdtemp(prefix=".task012-restore-", dir=parent))
    os.chmod(staging, 0o700)
    installed = False
    try:
        for path, mode in sorted(directories.items(), key=lambda item: (item[0].count("/"), item[0])):
            target = staging / path
            target.mkdir(mode=mode)
            target.chmod(mode)
        file_records = {item["path"]: item for item in manifest["files"]}
        for path, content in files.items():
            target = staging / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(file_records[path]["mode"])
        for path, content in files.items():
            target = staging / path
            if target.read_bytes() != content:
                raise BackupError(f"staged restore bytes changed for {path}")
            if hashlib.sha256(target.read_bytes()).hexdigest() != file_records[path]["sha256"]:
                raise BackupError(f"staged restore digest changed for {path}")
        staging.chmod(manifest["root_mode"])
        destination.rmdir()
        os.replace(staging, destination)
        installed = True
    finally:
        if not installed and staging.exists():
            shutil.rmtree(staging)
    return {
        "restored": True,
        "file_count": len(files),
        "directory_count": len(directories),
    }
