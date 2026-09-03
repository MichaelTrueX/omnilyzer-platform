#!/usr/bin/env python3
"""Run Task 012A entirely in temporary storage on isolated loopback ports."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import time
from typing import Callable

from durability.backup import BackupError, create_backup, verify_backup
from durability.fixture import Release, build_fixture
from durability.restore import restore_backup
from durability.zot_process import ZotProcess, verify_binary


PASS = "TASK 012A — PASS"


def _payload_checksum(backup: Path) -> None:
    digest = hashlib.sha256((backup / "payload.tar").read_bytes()).hexdigest()
    (backup / "payload.tar.sha256").write_text(f"{digest}  payload.tar\n", encoding="ascii")
    (backup / "payload.tar.sha256").chmod(0o600)


def _archive_members(payload: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    items: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(payload, mode="r:") as archive:
        for member in archive:
            stream = archive.extractfile(member) if member.isreg() else None
            items.append((copy.copy(member), stream.read() if stream is not None else None))
    return items


def _rewrite_archive(
    backup: Path,
    mutate: Callable[[list[tuple[tarfile.TarInfo, bytes | None]]], None],
) -> None:
    payload = backup / "payload.tar"
    members = _archive_members(payload)
    mutate(members)
    with tarfile.open(payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, content in members:
            archive.addfile(member, io.BytesIO(content) if content is not None else None)
    payload.chmod(0o600)
    _payload_checksum(backup)


def _negative_restore(
    root: Path,
    valid_backup: Path,
    name: str,
    binary,
    mutation: Callable[[Path], None],
    *,
    nonempty: bool = False,
) -> bool:
    candidate = root / f"negative-{name}-backup"
    shutil.copytree(valid_backup, candidate)
    mutation(candidate)
    destination = root / f"negative-{name}-restore"
    destination.mkdir(mode=0o700)
    if nonempty:
        (destination / "existing-registry-data").write_bytes(b"must-not-be-overwritten")
    before = {path.name: path.read_bytes() for path in destination.iterdir() if path.is_file()}
    try:
        restore_backup(candidate, destination, binary)
    except BackupError:
        after = {path.name: path.read_bytes() for path in destination.iterdir() if path.is_file()}
        if after != before or any(path.is_dir() for path in destination.iterdir()):
            raise RuntimeError(f"negative restore {name} modified its destination")
        return True
    raise RuntimeError(f"negative restore {name} was unexpectedly accepted")


def _corruption_matrix(root: Path, backup: Path, binary) -> dict[str, bool]:
    def flip_content(candidate: Path) -> None:
        def mutate(items):
            for index, (member, content) in enumerate(items):
                if member.isreg() and content:
                    changed = bytes([content[0] ^ 1]) + content[1:]
                    items[index] = (member, changed)
                    return
            raise RuntimeError("valid archive has no non-empty regular file")
        _rewrite_archive(candidate, mutate)

    def remove_file(candidate: Path) -> None:
        def mutate(items):
            index = next(index for index, (member, _) in enumerate(items) if member.isreg())
            items.pop(index)
        _rewrite_archive(candidate, mutate)

    def add_regular(candidate: Path) -> None:
        def mutate(items):
            member = tarfile.TarInfo("unexpected.txt")
            member.size = 10
            member.mode = 0o600
            member.mtime = 0
            items.append((member, b"unexpected"))
        _rewrite_archive(candidate, mutate)

    def truncate(candidate: Path) -> None:
        payload = candidate / "payload.tar"
        content = payload.read_bytes()
        payload.write_bytes(content[:257])
        payload.chmod(0o600)
        _payload_checksum(candidate)

    def add_member(name: str, member_type: bytes = tarfile.REGTYPE):
        def mutation(candidate: Path) -> None:
            def mutate(items):
                member = tarfile.TarInfo(name)
                member.type = member_type
                member.mode = 0o600
                member.mtime = 0
                if member_type == tarfile.SYMTYPE:
                    member.linkname = "elsewhere"
                    items.append((member, None))
                else:
                    member.size = 1
                    items.append((member, b"x"))
            _rewrite_archive(candidate, mutate)
        return mutation

    def duplicate(candidate: Path) -> None:
        def mutate(items):
            member, content = next((item for item in items if item[0].isreg()))
            items.append((copy.copy(member), content))
        _rewrite_archive(candidate, mutate)

    return {
        "modified_payload_byte_rejected": _negative_restore(root, backup, "byte", binary, flip_content),
        "missing_required_file_rejected": _negative_restore(root, backup, "missing", binary, remove_file),
        "unexpected_file_rejected": _negative_restore(root, backup, "unexpected", binary, add_regular),
        "truncated_archive_rejected": _negative_restore(root, backup, "truncated", binary, truncate),
        "nonempty_destination_rejected": _negative_restore(
            root, backup, "nonempty", binary, lambda _: None, nonempty=True
        ),
        "path_traversal_rejected": _negative_restore(
            root, backup, "traversal", binary, add_member("../escape")
        ),
        "absolute_path_rejected": _negative_restore(
            root, backup, "absolute", binary, add_member("/absolute")
        ),
        "duplicate_path_rejected": _negative_restore(root, backup, "duplicate", binary, duplicate),
        "symlink_rejected": _negative_restore(
            root, backup, "symlink", binary, add_member("unsafe-link", tarfile.SYMTYPE)
        ),
    }


def _verify_releases(client, releases: tuple[Release, Release]) -> dict[str, dict[str, bool]]:
    return {release.name: client.verify_release(release) for release in releases}


def run_validation() -> dict[str, object]:
    binary = verify_binary()
    releases = build_fixture()
    verification_duration = 0.0
    with tempfile.TemporaryDirectory(prefix="task012-zot-durability-") as temporary:
        root = Path(temporary).resolve()
        source_storage = root / "source-storage"
        source_storage.mkdir(mode=0o700)
        source_process = ZotProcess(binary, root / "source-runtime", source_storage)
        try:
            source_client = source_process.start()
            for release in releases:
                source_client.publish(release)
            started = time.monotonic()
            pre_backup = _verify_releases(source_client, releases)
            verification_duration += time.monotonic() - started
        finally:
            clean_shutdown = source_process.stop()
        if not clean_shutdown:
            raise RuntimeError("source zot did not shut down cleanly")

        backup = root / "backup"
        started = time.monotonic()
        backup_manifest = create_backup(source_storage, backup, binary)
        backup_duration = time.monotonic() - started
        started = time.monotonic()
        verified_manifest, _, _ = verify_backup(
            backup,
            expected_zot_version=binary.version,
            expected_binary_sha256=binary.sha256,
        )
        verification_duration += time.monotonic() - started
        if verified_manifest != backup_manifest:
            raise RuntimeError("verified backup manifest changed")

        source_storage.relative_to(root)
        shutil.rmtree(source_storage)
        source_destroyed = not source_storage.exists()
        if not source_destroyed:
            raise RuntimeError("temporary source registry was not removed")

        corruption_results = _corruption_matrix(root, backup, binary)
        if not all(corruption_results.values()):
            raise RuntimeError("a mandatory corrupt backup was accepted")

        restored_storage = root / "restored-storage"
        restored_storage.mkdir(mode=0o700)
        started = time.monotonic()
        restore_result = restore_backup(backup, restored_storage, binary)
        restore_duration = time.monotonic() - started

        restored_process = ZotProcess(binary, root / "restored-runtime", restored_storage)
        try:
            restored_client = restored_process.start()
            started = time.monotonic()
            post_restore = _verify_releases(restored_client, releases)
            verification_duration += time.monotonic() - started
        finally:
            restored_clean_shutdown = restored_process.stop()
        if not restored_clean_shutdown:
            raise RuntimeError("restored zot did not shut down cleanly")

        evidence = {
            "task": "012A",
            "classification": PASS,
            "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "zot": {
                "version": binary.version,
                "binary_sha256": binary.sha256,
                "version_command_verified": True,
            },
            "isolation": {
                "address": "127.0.0.1",
                "dynamic_ports": True,
                "temporary_storage_only": True,
                "gc": False,
                "authentication_in_scope": False,
                "live_registry_accessed": False,
            },
            "releases": {release.name: release.evidence() for release in releases},
            "pre_backup_validation": pre_backup,
            "cold_shutdown": {"source_clean": clean_shutdown, "restored_clean": restored_clean_shutdown},
            "backup": {
                "mode": "cold",
                "manifest_complete": True,
                "integrity_verified": True,
                "file_count": len(backup_manifest["files"]),
                "directory_count": len(backup_manifest["directories"]),
            },
            "source_destruction": {"temporary_source_removed": source_destroyed},
            "restore": restore_result,
            "post_restore_exact_digest_verification": post_restore,
            "corruption_negative_results": corruption_results,
            "durations_seconds": {
                "backup": round(backup_duration, 6),
                "restore": round(restore_duration, 6),
                "verification": round(verification_duration, 6),
            },
            "claims": {
                "retained_exact_digest_recoverability_after_restore": True,
                "application_deployment_rollback": False,
                "production_rpo_or_rto": False,
                "indefinite_retention": False,
            },
        }
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "results" / "zot-recovery-validation.json",
    )
    arguments = parser.parse_args()
    evidence = run_validation()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = arguments.output.with_suffix(arguments.output.suffix + ".tmp")
    temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(arguments.output)
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
