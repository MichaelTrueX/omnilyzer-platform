"""File: services/identity/tests/test_keycloak_offhost_receive.py
Purpose: Verify authenticated offhost receiver rejects tampering and preserves
    all plaintext only in a stream, with synthetic data and keys.
Related: services/identity/ops/{keycloak_offhost_receive,keycloak_offhost_backup}.py.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1] / "ops"


def module(name):
    """Import complete owning production module without invoking its CLI."""
    source = BASE / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, source)
    instance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(instance)
    return instance


RECEIVER = module("keycloak_offhost_receive")
EXPORT = module("keycloak_offhost_backup")


def make_plain_archive(root):
    """Synthetic-only stand-in for a protected PostgreSQL recovery package."""
    content = {
        "keycloak.pgcustom": b"PGDMP" + b"synthetic data" * 2200,
        "keycloak.env": b"TEST_PASSWORD=synthetic-not-production\n",
        "sumlaude-bff-client.env": b"TEST_CLIENT=synthetic-not-production\n",
        "omnilyzer-keycloak.service": b"[Service]\nUser=synthetic\n",
    }
    content["sha256sum.txt"] = (
        hashlib.sha256(content["keycloak.pgcustom"]).hexdigest() +
        "  keycloak.pgcustom\n").encode()
    checks = {}
    for name, body in content.items():
        (root / name).write_bytes(body)
        checks[name] = {"sha256": hashlib.sha256(body).hexdigest(),
                        "bytes": len(body)}
    payload = io.BytesIO()
    with mock.patch.object(EXPORT, "BACKUP_ROOT", root):
        EXPORT.create_tar_stream(payload, checks)
    return payload.getvalue(), checks


class KeycloakOffhostReceiverTests(unittest.TestCase):
    """Prove no raw Keycloak backup is persisted or accepted without integrity."""

    def test_fixed_remote_endpoint_and_pinned_client_key(self):
        self.assertEqual(RECEIVER.LAPTOP_HOST, "small-laptop")
        self.assertEqual(RECEIVER.REMOTE_IP, "46.62.147.181")
        self.assertEqual(RECEIVER.REMOTE_PORT, 2222)
        self.assertEqual(RECEIVER.EXPECTED_PUBLIC_KEY_SHA256,
                         EXPORT.RECEIVER_FINGERPRINT_SHA256)
        self.assertEqual(RECEIVER.EXPECTED_FILES, EXPORT.FILES)

    def test_synthetic_tar_validates_without_disk(self):
        with tempfile.TemporaryDirectory() as temp:
            payload, checks = make_plain_archive(Path(temp))
            result = RECEIVER.verify_tar_stream(io.BytesIO(payload))
            self.assertEqual(result, checks["keycloak.pgcustom"]["sha256"])

    def test_rejects_plaintext_or_corrupt_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload, _ = make_plain_archive(root)
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
                parts = [(member, archive.extractfile(member).read())
                         for member in archive]
            corrupted = io.BytesIO()
            with tarfile.open(fileobj=corrupted, mode="w:") as tar:
                for member, data in parts:
                    if member.name == "keycloak.env":
                        data = data.replace(b"synthetic", b"changed__")
                    tar.addfile(member, io.BytesIO(data))
            with self.assertRaisesRegex(RuntimeError,
                                        "authenticated Keycloak content digest mismatch"):
                RECEIVER.verify_tar_stream(io.BytesIO(corrupted.getvalue()))

    def test_rejects_archive_member_path_traversal(self):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w:") as archive:
            item = tarfile.TarInfo("../../outside-file")
            item.size = 4
            archive.addfile(item, io.BytesIO(b"test"))
        with self.assertRaisesRegex(RuntimeError, "archive member invalid"):
            RECEIVER.verify_tar_stream(io.BytesIO(content.getvalue()))

    def test_denies_network_or_partial_download_if_preflight_bad(self):
        with mock.patch.object(RECEIVER, "preflight",
                               return_value=["wrong laptop identity"]), \
             mock.patch.object(RECEIVER.subprocess, "run") as command:
            with self.assertRaisesRegex(RuntimeError, "wrong laptop identity"):
                RECEIVER.verify_remote_stream("a" * 64)
            command.assert_not_called()

    def test_age_authenticated_encrypted_roundtrip_with_synthetic_only(self):
        age = Path("/home/trust/.cache/omnilyzer-identity-offhost/extracted/usr/bin/age")
        agekeygen = age.with_name("age-keygen")
        if not age.is_file() or not agekeygen.is_file():
            self.skipTest("verified Ubuntu user-local age binary unavailable in CI")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plaintext, checks = make_plain_archive(root)
            key = root / "identity"
            subprocess.run([str(agekeygen), "-o", str(key)],
                           check=True, capture_output=True, timeout=10)
            recipient = next(
                line.partition(": ")[2] for line in key.read_text().splitlines()
                if line.startswith("# public key: "))
            encrypted = root / "archive.age"
            subprocess.run([str(age), "-r", recipient, "-o", str(encrypted)],
                           input=plaintext, check=True, capture_output=True, timeout=12)
            with mock.patch.multiple(RECEIVER, AGE_BIN=age, IDENTITY=key):
                result = RECEIVER.verify_age_file(encrypted)
            self.assertEqual(result, checks["keycloak.pgcustom"]["sha256"])

    def test_does_not_copy_plaintext_out_or_change_product_runtime(self):
        source = (BASE / "keycloak_offhost_receive.py").read_text()
        self.assertIn('"StrictHostKeyChecking=yes"', source)
        self.assertIn('"BatchMode=yes"', source)
        self.assertIn('mode="r|"', source)
        self.assertIn('"BatchMode=yes"', source)
        self.assertNotIn("DEST_FILE", source)
        self.assertNotIn("shutil.copyfileobj", source)
        self.assertNotIn("scp", source)
        for forbidden in ("tar -xf", "tar xzf", "systemctl restart",
                          "pg_restore", "nginx -s reload", "sudo -n",
                          "CREATE DATABASE", "cloudflare.request"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
