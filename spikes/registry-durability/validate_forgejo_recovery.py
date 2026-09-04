#!/usr/bin/env python3
"""Task 012B cold Forgejo dump, fresh restore, and package recovery validation."""

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

from durability.forgejo_backup import (
    ForgejoBackupError,
    create_forgejo_backup,
    restore_forgejo_backup,
    verify_forgejo_backup,
)
from durability.forgejo_packages import ForgejoPackageClient, build_packages
from durability.forgejo_process import ForgejoProcess, prepare_binary


PASS = "TASK 012B — PASS"


def _members(archive: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    result = []
    with tarfile.open(archive, mode="r:") as payload:
        for member in payload:
            stream = payload.extractfile(member) if member.isreg() else None
            result.append((copy.copy(member), stream.read() if stream is not None else None))
    return result


def _rewrite(backup: Path, mutate: Callable[[list[tuple[tarfile.TarInfo, bytes | None]]], None]) -> None:
    archive = backup / "forgejo-data.tar"
    members = _members(archive)
    mutate(members)
    with tarfile.open(archive, mode="w", format=tarfile.PAX_FORMAT) as payload:
        for member, content in members:
            payload.addfile(member, io.BytesIO(content) if content is not None else None)
    _refresh_integrity(backup)


def _refresh_integrity(backup: Path) -> None:
    archive = backup / "forgejo-data.tar"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (backup / "forgejo-data.tar.sha256").write_text(
        f"{digest}  forgejo-data.tar\n", encoding="ascii"
    )
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["archive_sha256"] = digest
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _negative(
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
        (destination / "existing").write_bytes(b"preserve")
    before = {path.name: path.read_bytes() for path in destination.iterdir() if path.is_file()}
    try:
        restore_forgejo_backup(candidate, destination, binary)
    except ForgejoBackupError:
        after = {path.name: path.read_bytes() for path in destination.iterdir() if path.is_file()}
        if before != after or any(path.is_dir() for path in destination.iterdir()):
            raise RuntimeError(f"negative {name} modified its restore destination")
        return True
    raise RuntimeError(f"negative {name} was unexpectedly accepted")


def negative_matrix(root: Path, backup: Path, binary) -> dict[str, bool]:
    def corrupt_archive(candidate: Path) -> None:
        archive = candidate / "forgejo-data.tar"
        archive.write_bytes(archive.read_bytes()[:257])
        _refresh_integrity(candidate)

    def checksum_mismatch(candidate: Path) -> None:
        archive = candidate / "forgejo-data.tar"
        content = archive.read_bytes()
        archive.write_bytes(bytes([content[0] ^ 1]) + content[1:])

    def traversal(candidate: Path) -> None:
        def mutate(items):
            member = tarfile.TarInfo("../escape")
            member.size = 1
            member.mode = 0o600
            items.append((member, b"x"))
        _rewrite(candidate, mutate)

    def remove_database(candidate: Path) -> None:
        _rewrite(candidate, lambda items: items.__setitem__(slice(None), [
            item for item in items if item[0].name != "forgejo-db.sql"
        ]))

    def remove_packages(candidate: Path) -> None:
        _rewrite(candidate, lambda items: items.__setitem__(slice(None), [
            item for item in items if not item[0].name.startswith("data/packages")
        ]))

    return {
        "corrupt_archive_rejected": _negative(root, backup, "corrupt", binary, corrupt_archive),
        "checksum_mismatch_rejected": _negative(root, backup, "checksum", binary, checksum_mismatch),
        "path_traversal_rejected": _negative(root, backup, "traversal", binary, traversal),
        "nonempty_destination_rejected": _negative(
            root, backup, "nonempty", binary, lambda _: None, nonempty=True
        ),
        "database_metadata_loss_rejected": _negative(
            root, backup, "metadata-loss", binary, remove_database
        ),
        "package_storage_loss_rejected": _negative(
            root, backup, "storage-loss", binary, remove_packages
        ),
    }


def run_validation() -> dict[str, object]:
    fixtures = build_packages()
    package_evidence = fixtures.evidence()
    with tempfile.TemporaryDirectory(prefix="task012b-forgejo-durability-") as temporary:
        root = Path(temporary).resolve()
        binary = prepare_binary(root)
        source = root / "source-state"
        forgejo_a = ForgejoProcess(binary, source)
        forgejo_a.initialize()
        token = forgejo_a.create_publisher()
        try:
            forgejo_a.start()
            client_a = ForgejoPackageClient(forgejo_a.base_url, token)
            client_a.publish_generic(fixtures.generic)
            client_a.publish_pypi(fixtures.wheel)
            client_a.publish_npm(fixtures.npm)
            pre_backup = client_a.verify(fixtures)
        finally:
            source_clean_shutdown = forgejo_a.stop()
        if not source_clean_shutdown:
            raise RuntimeError("source Forgejo did not shut down cleanly")

        backup = root / "backup"
        started = time.monotonic()
        manifest = create_forgejo_backup(forgejo_a, backup, package_evidence)
        backup_duration = time.monotonic() - started
        verify_forgejo_backup(backup, binary)

        source.relative_to(root)
        shutil.rmtree(source)
        source_removed = not source.exists()
        if not source_removed:
            raise RuntimeError("temporary Forgejo source state was not removed")

        negatives = negative_matrix(root, backup, binary)
        if not all(negatives.values()):
            raise RuntimeError("a mandatory negative did not fail closed")

        restored = root / "restored-state"
        restored.mkdir(mode=0o700)
        started = time.monotonic()
        restore_result = restore_forgejo_backup(backup, restored, binary)
        restore_duration = time.monotonic() - started
        forgejo_b = ForgejoProcess(binary, restored, exclude_port=forgejo_a.port)
        forgejo_b.configure_restored()
        try:
            forgejo_b.start()
            post_restore = ForgejoPackageClient(forgejo_b.base_url, token).verify(fixtures)
        finally:
            restored_clean_shutdown = forgejo_b.stop()
        if not restored_clean_shutdown:
            raise RuntimeError("restored Forgejo did not shut down cleanly")

        return {
            "task": "012B",
            "classification": PASS,
            "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "forgejo": {
                "version": binary.version,
                "binary_path": binary.recorded_path,
                "binary_sha256": binary.sha256,
                "binary_source": binary.source,
            },
            "isolation": {
                "address": "127.0.0.1",
                "source_port": forgejo_a.port,
                "restored_port": forgejo_b.port,
                "different_ports": forgejo_a.port != forgejo_b.port,
                "temporary_sqlite": True,
                "temporary_package_storage": True,
                "external_services": False,
                "live_infrastructure_accessed": False,
            },
            "packages": package_evidence,
            "pre_backup_results": pre_backup,
            "clean_shutdown": {
                "source": source_clean_shutdown,
                "restored": restored_clean_shutdown,
            },
            "backup": {
                "mode": manifest["backup_mode"],
                "archive_sha256": manifest["archive_sha256"],
                "logical_components": manifest["logical_components"],
                "integrity_verified": True,
            },
            "source_removal": {"temporary_source_removed": source_removed},
            "restore": restore_result,
            "post_restore_results": post_restore,
            "negative_test_matrix": negatives,
            "durations_seconds": {
                "backup": round(backup_duration, 6),
                "restore": round(restore_duration, 6),
            },
            "limitations": [
                "cold backup only",
                "synthetic local data only",
                "not production RPO or RTO",
                "not online backup, HA, or disaster recovery",
                "not off-host or encrypted backup",
                "not Forgejo OCI validation",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "results/forgejo-recovery-validation.json",
    )
    arguments = parser.parse_args()
    result = run_validation()
    temporary = arguments.output.with_suffix(arguments.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(arguments.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
