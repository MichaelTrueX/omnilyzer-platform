#!/usr/bin/env python3
# File: release/tests/test_analytics_private_handoff.py
# Purpose: Verify that private Analytics source and OCI transit public GitHub
#          Actions artifacts ONLY as authenticated GPG-encrypted ciphertext.
# Related: release/analytics_private_handoff.py,
#          release/analytics_handoff_recipient.asc,
#          .github/workflows/platform-release.yml.
# Security: Test-only keys are temporary; no production decryption key or
#          repository source files are ever read by these tests.
"""Real GPG encryption, safe extraction, tampering, and missing-key tests."""

from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from release.analytics_private_handoff import (
    EnvelopeDenied, RECIPIENT, RECIPIENT_FINGERPRINT, decrypt, encrypt,
)


@unittest.skipUnless(subprocess.run(["sh", "-c", "command -v gpg >/dev/null"],
                                       check=False).returncode == 0,
                     "the pinned Ubuntu runner includes GnuPG")
class AnalyticsPrivateHandoffTests(unittest.TestCase):
    """Exercise the real GPG CLI, not an encryption mock."""

    @classmethod
    def setUpClass(cls) -> None:
        """Build one isolated, disposable and unencrypted-password test key."""
        cls.context = tempfile.TemporaryDirectory(prefix="analytics-test-gpg-")
        cls.root = Path(cls.context.name)
        home = cls.root / "gpg"
        home.mkdir(mode=0o700)
        cls.environment = dict(os.environ, GNUPGHOME=str(home))
        subprocess.run(
            ["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback",
             "--passphrase", "", "--quick-generate-key",
             "Analytics Handoff TEST ONLY", "default", "default", "1d"],
            env=cls.environment, check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=60,
        )
        raw = subprocess.run(["gpg", "--with-colons", "--list-keys"],
                             env=cls.environment, capture_output=True,
                             check=True).stdout.decode()
        cls.fingerprint = next(line.split(":")[9] for line in raw.splitlines()
                               if line.startswith("fpr:"))
        cls.public = cls.root / "test-recipient.asc"
        cls.public.write_bytes(subprocess.run(
            ["gpg", "--armor", "--export", cls.fingerprint],
            env=cls.environment, capture_output=True, check=True).stdout)
        cls.private_key = subprocess.run(
            ["gpg", "--armor", "--export-secret-keys", cls.fingerprint],
            env=cls.environment, capture_output=True, check=True).stdout.decode()

    @classmethod
    def tearDownClass(cls) -> None:
        """Destroy the test private key and all test artifacts."""
        cls.context.cleanup()

    def _source(self, root: Path) -> Path:
        """Create a nonproduction handoff with all four required identity files."""
        source = root / "source"
        (source / "candidate").mkdir(parents=True)
        (source / "candidate/source.tar").write_bytes(b"PRIVATE_TEST_SOURCE_XYZ")
        (source / "candidate/analytics.oci.tar").write_bytes(b"PRIVATE_TEST_OCI_ABC")
        (source / "analytics-source-claim.json").write_text('{"source":"synthetic"}')
        (source / "oci-grype.json").write_text('{"matches":[]}')
        return source

    def _encrypt(self, source: Path, encrypted: Path) -> None:
        """Use a test-only recipient rather than the protected release key."""
        encrypt(source, encrypted, public_key=self.public,
                fingerprint=self.fingerprint)

    def test_public_production_key_has_exact_reviewed_fingerprint(self) -> None:
        """The repository exposes only a public recipient with a pinned ID."""
        result = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--show-keys", str(RECIPIENT)],
            capture_output=True, check=True,
        ).stdout.decode()
        self.assertIn(RECIPIENT_FINGERPRINT, result)
        self.assertIn("BEGIN PGP PUBLIC KEY BLOCK", RECIPIENT.read_text())
        self.assertNotIn("PRIVATE KEY", RECIPIENT.read_text())

    def test_real_encrypted_round_trip_never_exposes_source_in_artifact(self) -> None:
        """Only ciphertext crosses the public artifact boundary."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._source(root)
            encrypted = root / "transport.gpg"
            self._encrypt(source, encrypted)
            raw = encrypted.read_bytes()
            self.assertNotIn(b"PRIVATE_TEST_SOURCE_XYZ", raw)
            self.assertNotIn(b"PRIVATE_TEST_OCI_ABC", raw)
            output = root / "output"
            decrypt(encrypted, output, private_key=self.private_key)
            self.assertEqual((output / "candidate/source.tar").read_bytes(),
                             b"PRIVATE_TEST_SOURCE_XYZ")
            self.assertEqual((output / "candidate/analytics.oci.tar").read_bytes(),
                             b"PRIVATE_TEST_OCI_ABC")

    def test_missing_wrong_key_or_tampered_ciphertext_fails_closed(self) -> None:
        """No release identity survives missing keys or GPG authentication failure."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            encrypted = root / "transport.gpg"
            self._encrypt(self._source(root), encrypted)
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(EnvelopeDenied):
                    decrypt(encrypted, root / "absent")
            raw = bytearray(encrypted.read_bytes())
            raw[-8] ^= 0x20
            encrypted.write_bytes(raw)
            with self.assertRaises(EnvelopeDenied):
                decrypt(encrypted, root / "tampered", private_key=self.private_key)
            self.assertFalse((root / "tampered").exists())

    def test_reject_symlinks_and_existing_ciphertext(self) -> None:
        """Reject path-substitution and accidental artifact replacement."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._source(root)
            encrypted = root / "transport.gpg"
            (source / "candidate/link").symlink_to("source.tar")
            with self.assertRaises(EnvelopeDenied):
                self._encrypt(source, encrypted)
            (source / "candidate/link").unlink()
            encrypted.write_bytes(b"already occupied")
            with self.assertRaises(EnvelopeDenied):
                self._encrypt(source, encrypted)

    def test_decrypted_archive_cannot_escape_destination(self) -> None:
        """Even attacker-encrypted tar traversal is rejected before extraction."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = root / "malicious.tar"
            with tarfile.open(payload, "w") as archive:
                content = b"not authorized"
                member = tarfile.TarInfo("../outside")
                member.size = len(content)
                archive.addfile(member, BytesIO(content))
            encrypted = root / "malicious.gpg"
            subprocess.run([
                "gpg", "--batch", "--yes", "--trust-model", "always",
                "--recipient", self.fingerprint, "--encrypt", "--output",
                str(encrypted), str(payload),
            ], check=True, env=self.environment, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            with self.assertRaises(EnvelopeDenied):
                decrypt(encrypted, root / "untrusted", private_key=self.private_key)
            self.assertFalse((root / "outside").exists())
            self.assertFalse((root / "untrusted").exists())


if __name__ == "__main__":
    unittest.main()
