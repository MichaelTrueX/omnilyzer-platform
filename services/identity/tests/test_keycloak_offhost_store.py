"""File: services/identity/tests/test_keycloak_offhost_store.py
Purpose: Guard the key-separated ciphertext storage flow and pinned SSH
    relay without accessing production identity data or live networks.
Related: services/identity/ops/keycloak_offhost_store.py.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "ops/keycloak_offhost_store.py"
SPEC = importlib.util.spec_from_file_location("m01_offhost_store", SOURCE)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class EncryptedKeySeparatedStorageTests(unittest.TestCase):
    """Prove narrow SSH host identity and fail-closed ciphertext-only transfer."""

    def test_exact_storage_host_and_pinned_ssh_key(self):
        self.assertEqual(MOD.HOST, "michael-laptop")
        self.assertEqual(MOD.USER, "michael")
        self.assertEqual(MOD.JUMP_HOST, "192.168.68.116")
        self.assertEqual(MOD.JUMP_KNOWN_HOSTS_SHA256,
                         "abf7bed721e19089ac3913addee134caa1f782d30ddbb5dda542b0568f74e2cd")
        self.assertEqual(MOD.PROD_HOST, "46.62.147.181")
        self.assertEqual(MOD.PROD_PORT, 2222)

    def test_relay_is_ciphertext_only_with_strict_host_verification(self):
        args = MOD.relay_command()
        self.assertEqual(args[0], "/usr/bin/ssh")
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("BatchMode=yes", args)
        self.assertIn("IdentitiesOnly=yes", args)
        self.assertIn("StrictHostKeyChecking=yes", args[-1])
        self.assertIn("BatchMode=yes", args[-1])
        self.assertIn("/usr/bin/cat -- " + MOD.PROD_FILE, args[-1])
        self.assertNotIn("age -d", args[-1])
        self.assertNotIn("pg_dump", args[-1])

    def test_invalid_source_or_destination_aborts_before_ssh(self):
        with mock.patch.object(MOD, "preflight", return_value=["wrong host"]), \
             mock.patch.object(MOD.subprocess, "run") as process:
            with self.assertRaisesRegex(RuntimeError, "wrong host"):
                MOD.store("a" * 64)
            process.assert_not_called()

    def test_accepted_ciphertext_digest_only(self):
        with mock.patch.object(MOD, "preflight", return_value=[]):
            for invalid in ("", "0" * 63, "not_a_hash", "A" * 64):
                with self.assertRaisesRegex(RuntimeError, "SHA256 required"):
                    MOD.store(invalid)

    def test_private_stored_ciphertext_file_creation_and_no_overwrites(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "store"
            ciphertext = b"age-encryption.org/v1\n" + b"x" * 2300
            digest = hashlib.sha256(ciphertext).hexdigest()

            def run_fake(args, *, stdout=None, **kwargs):
                self.assertEqual(args, MOD.relay_command())
                stdout.write(ciphertext)
                return mock.Mock(returncode=0)

            with mock.patch.multiple(MOD, ROOT=root, TARGET=root / MOD.CIPHERTEXT,
                                     preflight=lambda: []), \
                 mock.patch.object(MOD.subprocess, "run", side_effect=run_fake):
                MOD.store(digest)
                self.assertEqual((root / MOD.CIPHERTEXT).read_bytes(), ciphertext)
                self.assertEqual((root / MOD.CIPHERTEXT).stat().st_mode & 0o777,
                                 0o600)

    def test_no_local_decryption_or_other_service_mutation(self):
        source = SOURCE.read_text()
        for forbidden in ("age -d", "age-keygen", "sudo", "pg_restore",
                          "systemctl", "CREATE DATABASE", "DROP DATABASE",
                          "KC_BOOTSTRAP_ADMIN_PASSWORD", "scp -3"):
            self.assertNotIn(forbidden, source)
        self.assertIn("os.replace(temporary, TARGET)", source)


if __name__ == "__main__":
    unittest.main()
