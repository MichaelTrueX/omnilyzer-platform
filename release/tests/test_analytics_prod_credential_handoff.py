#!/usr/bin/env python3
"""File: release/tests/test_analytics_prod_credential_handoff.py

Purpose: Negative and successful boundary tests for the short-lived encrypted
         Analytics PROD registry credential handoff, without minting real JWTs.
Related: release/analytics_prod_credential_handoff.py,
         release/private_zot_auth_probe.py,
         .github/workflows/platform-promote.yml.

Sections: exact workflow owner/ref, recipient, no output/JWT logs, one-shot
          artifact name, missing-token refusal and encrypted file custody.
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

m = importlib.import_module("release.analytics_prod_credential_handoff")


class TestProdCredentialHandoff(unittest.TestCase):
    """Only the existing protected workflow may create a sealed handoff."""

    def setUp(self):
        """Use a private ephemeral runner directory without real credentials."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.output = self.parent / "m05-analytics-prod-registry-token.age"
        self.env = {
            "GITHUB_ACTOR": "MichaelTrueX",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_TEMP": str(self.parent),
        }

    def execute(self):
        """Exercise true handoff source and bounded subprocess with fixture token."""
        def encrypted(argv, *, input, **kwargs):
            self.assertEqual(input, b"fixture.jwt.signature")
            self.assertIn(m.RECIPIENT, argv)
            self.assertNotIn(input.decode(), str(argv))
            self.output.write_bytes(b"age-encryption.org/v1\nsynthetic encrypted test fixture")
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(m, "_workflow_context_preflight"), \
             mock.patch.object(m, "_oidc_token", return_value="fixture.jwt.signature"), \
             mock.patch.object(m, "_claims_preflight"), \
             mock.patch.object(m.subprocess, "run", side_effect=encrypted):
            m.mint_encrypt(self.env, self.output)

    def test_accept_once(self):
        """Correct source identity produces one private encrypted handoff."""
        self.execute()
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_reject_replay(self):
        """A preexisting artifact cannot be overwritten or duplicated."""
        self.execute()
        with self.assertRaises(m.ProbeUnavailableError):
            self.execute()

    def test_wrong_actor(self):
        """Only the real Product Owner may request a PROD registry token."""
        self.env["GITHUB_ACTOR"] = "not-the-owner"
        with self.assertRaises(m.ProbeUnavailableError):
            self.execute()

    def test_wrong_ref(self):
        """Never issue PROD OCI auth from unprotected branch refs."""
        self.env["GITHUB_REF"] = "refs/heads/feature/unreviewed"
        with self.assertRaises(m.ProbeUnavailableError):
            self.execute()

    def test_wrong_environment(self):
        """Only the exact GitHub-hosted OIDC authority can mint tokens."""
        self.env["RUNNER_ENVIRONMENT"] = "self-hosted"
        with self.assertRaises(m.ProbeUnavailableError):
            self.execute()

    def test_wrong_artifact_name(self):
        """Reject dynamic user-controlled credential output filenames."""
        with self.assertRaises(m.ProbeUnavailableError):
            m.mint_encrypt(self.env, self.parent / "some-token.txt")

    def test_wrong_path(self):
        """Artifact output must be in GitHub's current private RUNNER_TEMP."""
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(m.ProbeUnavailableError):
                m.mint_encrypt(self.env, Path(other) / self.output.name)

    def test_no_forged_token(self):
        """OIDC issuance failure stops the operation before age runs."""
        with mock.patch.object(m, "_workflow_context_preflight"), \
             mock.patch.object(m, "_oidc_token",
                               side_effect=m.ProbeUnavailableError("OIDC rejected")), \
             mock.patch.object(m.subprocess, "run") as encrypt:
            with self.assertRaises(m.ProbeUnavailableError):
                m.mint_encrypt(self.env, self.output)
        encrypt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
