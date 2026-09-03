"""Cold-backup format and source filesystem policy tests."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tarfile
import tempfile
import unittest


SPIKE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SPIKE))

from durability.backup import BackupError, create_backup, verify_backup  # noqa: E402
from durability.zot_process import (  # noqa: E402
    EXPECTED_BINARY_SHA256,
    EXPECTED_VERSION,
    VerifiedBinary,
)


BINARY = VerifiedBinary(Path("/usr/local/bin/zot"), EXPECTED_VERSION, EXPECTED_BINARY_SHA256, "test")


class BackupPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        (self.source / "repository").mkdir(mode=0o750)
        (self.source / "repository" / "manifest.json").write_bytes(b'{"schemaVersion":2}\n')
        (self.source / "blob").write_bytes(b"synthetic-blob")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _backup(self) -> Path:
        target = self.root / "backup"
        create_backup(self.source, target, BINARY)
        return target

    def test_backup_has_exact_owner_only_integrity_format(self) -> None:
        backup = self._backup()
        self.assertEqual({path.name for path in backup.iterdir()}, {
            "manifest.json", "payload.tar", "payload.tar.sha256"
        })
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in backup.iterdir()))
        manifest, files, directories = verify_backup(
            backup,
            expected_zot_version=EXPECTED_VERSION,
            expected_binary_sha256=EXPECTED_BINARY_SHA256,
        )
        self.assertEqual(manifest["backup_mode"], "cold")
        self.assertEqual(manifest["source_classification"], "synthetic Task 012 data")
        self.assertEqual(list(files), sorted(files))
        self.assertEqual(list(directories), sorted(directories))

    def test_symbolic_link_source_entry_is_rejected(self) -> None:
        (self.source / "link").symlink_to("blob")
        with self.assertRaisesRegex(BackupError, "symbolic link"):
            create_backup(self.source, self.root / "backup", BINARY)

    def test_fifo_source_entry_is_rejected(self) -> None:
        os.mkfifo(self.source / "pipe")
        with self.assertRaisesRegex(BackupError, "unsupported filesystem"):
            create_backup(self.source, self.root / "backup", BINARY)

    def test_socket_source_entry_is_rejected(self) -> None:
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            endpoint.bind(str(self.source / "socket"))
            with self.assertRaisesRegex(BackupError, "unsupported filesystem"):
                create_backup(self.source, self.root / "backup", BINARY)
        finally:
            endpoint.close()

    def test_existing_backup_destination_is_rejected(self) -> None:
        destination = self.root / "backup"
        destination.mkdir()
        with self.assertRaisesRegex(BackupError, "must not already exist"):
            create_backup(self.source, destination, BINARY)

    def test_unknown_schema_and_wrong_zot_metadata_are_rejected(self) -> None:
        for field, value, message in (
            ("schema_version", 999, "unknown"),
            ("zot_version", "v0.0.0", "version"),
            ("zot_binary_sha256", "0" * 64, "binary"),
        ):
            with self.subTest(field=field):
                backup = self.root / f"backup-{field}"
                create_backup(self.source, backup, BINARY)
                manifest_path = backup / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                manifest[field] = value
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(BackupError, message):
                    verify_backup(
                        backup,
                        expected_zot_version=EXPECTED_VERSION,
                        expected_binary_sha256=EXPECTED_BINARY_SHA256,
                    )

    def test_duplicate_and_unsafe_manifest_paths_are_rejected(self) -> None:
        for name in ("duplicate", "absolute", "traversal"):
            with self.subTest(name=name):
                backup = self.root / f"backup-{name}"
                create_backup(self.source, backup, BINARY)
                path = backup / "manifest.json"
                manifest = json.loads(path.read_text())
                if name == "duplicate":
                    manifest["files"].append(dict(manifest["files"][0]))
                elif name == "absolute":
                    manifest["files"][0]["path"] = "/absolute"
                else:
                    manifest["files"][0]["path"] = "../escape"
                path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaises(BackupError):
                    verify_backup(
                        backup,
                        expected_zot_version=EXPECTED_VERSION,
                        expected_binary_sha256=EXPECTED_BINARY_SHA256,
                    )

    def test_hard_link_archive_alias_is_rejected(self) -> None:
        backup = self._backup()
        payload = backup / "payload.tar"
        members = []
        with tarfile.open(payload, mode="r:") as archive:
            for member in archive:
                stream = archive.extractfile(member) if member.isreg() else None
                members.append((member, stream.read() if stream is not None else None))
        alias = tarfile.TarInfo("hard-link-alias")
        alias.type = tarfile.LNKTYPE
        alias.linkname = next(member.name for member, _ in members if member.isreg())
        members.append((alias, None))
        with tarfile.open(payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for member, content in members:
                archive.addfile(member, io.BytesIO(content) if content is not None else None)
        payload_hash = hashlib.sha256(payload.read_bytes()).hexdigest()
        (backup / "payload.tar.sha256").write_text(
            f"{payload_hash}  payload.tar\n", encoding="ascii"
        )
        with self.assertRaisesRegex(BackupError, "unsupported archive member"):
            verify_backup(
                backup,
                expected_zot_version=EXPECTED_VERSION,
                expected_binary_sha256=EXPECTED_BINARY_SHA256,
            )


if __name__ == "__main__":
    unittest.main()
