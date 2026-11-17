"""File: services/identity/tests/test_keycloak_offhost_backup.py
Purpose: Offline security and actual age/SSH-key crypto tests for encrypted
    Keycloak disaster-recovery handoff.
Related: services/identity/ops/keycloak_offhost_backup.py,
    services/identity/ops/keycloak_prod_recovery.py and SECURITY.md.

Every test uses synthetic data. Never decrypt a production backup in CI.
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

SRC = Path(__file__).resolve().parents[1] / "ops/keycloak_offhost_backup.py"
SPEC = importlib.util.spec_from_file_location("keycloak_offhost_backup", SRC)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def synthetic_files(root):
    """Create a safely synthetic local PG snapshot and credential placeholders."""
    contents = {
        "keycloak.pgcustom": b"PGDMP" + b"A" * 17000,
        "keycloak.env": b"KC_DB_PASSWORD=synthetic-not-real\n",
        "sumlaude-bff-client.env": b"OIDC_CLIENT_SECRET=synthetic-not-real\n",
        "omnilyzer-keycloak.service": b"[Service]\nUser=synthetic\n",
    }
    contents["sha256sum.txt"] = (
        hashlib.sha256(contents["keycloak.pgcustom"]).hexdigest() +
        "  keycloak.pgcustom\n").encode()
    checks = {}
    for name, data in contents.items():
        (root / name).write_bytes(data)
        checks[name] = {"sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data)}
    return checks


class OffhostBackupTests(unittest.TestCase):
    """Require verified original source and approved exact public recipient."""

    def test_exact_source_inventory_and_recipient_fingerprint(self):
        self.assertEqual(set(MOD.FILES),
                         {"keycloak.pgcustom", "keycloak.env",
                          "sumlaude-bff-client.env", "omnilyzer-keycloak.service",
                          "sha256sum.txt"})
        self.assertEqual(MOD.RECEIVER_FINGERPRINT_SHA256,
                         "d6955c0bbc8a74847aa464196ac516275561ce6a7306674c9a8dd39d5150a492")
        self.assertEqual(MOD.HOST, "truexmainserver")
        self.assertEqual(MOD.AGE_VERSION, "1.1.1-1ubuntu0.24.04.3")

    def test_tar_stream_manifest_lists_hashes_and_no_path_traversal(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            checks = synthetic_files(root)
            output = io.BytesIO()
            with mock.patch.object(MOD, "BACKUP_ROOT", root):
                MOD.create_tar_stream(output, checks)
            output.seek(0)
            with tarfile.open(fileobj=output, mode="r:") as archive:
                names = archive.getnames()
                self.assertEqual(names, list(MOD.FILES) + ["manifest.json"])
                for info in archive:
                    self.assertFalse(info.issym())
                    self.assertEqual(info.uid, 0)
                    self.assertEqual(info.mode, 0o600)
                manifest = json.loads(archive.extractfile("manifest.json").read())
                self.assertEqual(manifest["recovery_files"], checks)
                self.assertEqual(manifest["format"], "omnilyzer-keycloak-offhost-v1")
                for filename in MOD.FILES:
                    body = archive.extractfile(filename).read()
                    self.assertEqual(hashlib.sha256(body).hexdigest(),
                                     checks[filename]["sha256"])

    def test_preflight_aborts_without_packaging_sensitive_material(self):
        with mock.patch.object(MOD, "preflight", return_value=["unsafe recipient"]), \
             mock.patch.object(MOD, "ensure_signed_age") as package, \
             mock.patch.object(MOD, "encrypt_to_root") as encrypt:
            with self.assertRaisesRegex(RuntimeError, "unsafe recipient"):
                MOD.export_once()
            package.assert_not_called()
            encrypt.assert_not_called()

    def test_private_file_metadata_rejects_links_and_relaxed_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "keycloak.env"
            real.write_text("synthetic")
            real.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "ownership/type/mode"):
                MOD.file_metadata(real, root_required=False)
            real.chmod(0o600)
            link = root / "link"
            link.symlink_to(real)
            with self.assertRaisesRegex(RuntimeError, "ownership/type/mode"):
                MOD.file_metadata(link, root_required=False)

    def test_ciphertext_wont_overwrite_existing_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "archive.tar.age"
            destination.write_text("EXISTING ARCHIVE MUST REMAIN")
            destination.chmod(0o600)
            with mock.patch.object(MOD, "CIPHERTEXT_ROOT", destination):
                with self.assertRaises(FileExistsError):
                    MOD.encrypt_to_root({})
            self.assertEqual(destination.read_text(), "EXISTING ARCHIVE MUST REMAIN")

    def test_synthetic_age_encryption_decryption_roundtrip_when_available(self):
        """Use the official CLI on the operator laptop, with disposable test keys."""
        age = Path("/home/trust/.cache/omnilyzer-identity-offhost/extracted/usr/bin/age")
        agekeygen = age.with_name("age-keygen")
        if not (age.is_file() and agekeygen.is_file()):
            self.skipTest("no pinned nonroot Ubuntu age binary on CI runner")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checks = synthetic_files(root)
            identity = root / "identity.txt"
            result = subprocess.run([str(agekeygen), "-o", str(identity)],
                                    capture_output=True, text=True, check=True, timeout=10)
            pub = next(line.split(": ", 1)[1] for line in
                       identity.read_text().splitlines() if line.startswith("# public key: "))
            recipient = root / "recipient.txt"
            recipient.write_text(pub + "\n")
            cipher = root / "encrypted.age"
            with mock.patch.multiple(MOD, BACKUP_ROOT=root, RECIPIENT=recipient,
                                     CIPHERTEXT_ROOT=cipher, AGE_BIN=age):
                size, digest = MOD.encrypt_to_root(checks)
                self.assertEqual(digest, MOD.file_digest(cipher))
                self.assertGreater(size, 1024)
            restored = subprocess.run([str(age), "-d", "-i", str(identity),
                                       str(cipher)], check=True, capture_output=True,
                                      timeout=15).stdout
            with tarfile.open(fileobj=io.BytesIO(restored), mode="r:") as archive:
                manifest = json.load(archive.extractfile("manifest.json"))
                self.assertEqual(manifest["recovery_files"], checks)

    def test_source_does_not_modify_existing_services_or_send_raw_data(self):
        source = SRC.read_text()
        for forbidden in ("systemctl restart", "systemctl stop", "kc.sh start",
                          "cloudflare.request", "pg_dump", "CREATE DATABASE",
                          "DROP DATABASE", "tar czf", "gpg --symmetric"):
            self.assertNotIn(forbidden, source)
        self.assertIn('"/usr/bin/apt-get", "install"', source)
        self.assertIn('["/usr/bin/systemctl", "show"', source)
        self.assertIn('mode="w|"', source)


if __name__ == "__main__":
    unittest.main()
