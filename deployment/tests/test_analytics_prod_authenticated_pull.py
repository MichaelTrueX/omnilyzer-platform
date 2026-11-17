#!/usr/bin/env python3
"""File: deployment/tests/test_analytics_prod_authenticated_pull.py

Purpose: Focused fail-closed tests for the existing signed 0.16.0 OCI
         authenticated rootless PROD pull, without live registry credentials.
Related: deployment/analytics_prod_authenticated_pull.py,
         deployment/private_registry_pull.py.

Sections: exact identity, SHA custody, Sigstore gate, short-lived OIDC input,
          0600 volatile auth cleanup and immutable postpull digest.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "analytics_prod_authenticated_pull.py"
SPEC = importlib.util.spec_from_file_location("analytics_prod_authenticated_pull", SOURCE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def jwt(*, issuer: str = m.ISSUER, audience: str = m.AUDIENCE,
        workflow: str = m.WORKFLOW, lifetime: int = 290) -> bytes:
    """Construct an untrusted JWT fixture; never claim a test token is signed."""
    payload = {
        "iss": issuer,
        "aud": audience,
        "repository": "MichaelTrueX/omnilyzer-platform",
        "workflow_ref": workflow,
        "exp": 1_800_000_000 + lifetime,
    }
    encode = lambda val: base64.urlsafe_b64encode(json.dumps(val).encode()).rstrip(b"=")
    return encode({"alg": "RS256"}) + b"." + encode(payload) + b".fixture"


class TestProdAuthenticatedPull(unittest.TestCase):
    """Keep rootless Docker admission distinct from container start and ingress."""

    def test_reject_wrong_host_principal(self):
        """Never execute Docker through trusthansen or the old DEV UID991."""
        with mock.patch.object(m.os, "getuid", return_value=991), \
             mock.patch.object(m.os, "geteuid", return_value=991):
            with self.assertRaises(m.PullHold):
                m.check_identity()

    def test_reject_symlinked_trusted_file(self):
        """Do not trust a digest-matching symlink to executable source."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "a"
            source.write_bytes(b"reviewed")
            link = root / "b"
            link.symlink_to(source)
            with self.assertRaises(m.PullHold):
                m.owned_sha256(link, uid=os.getuid(), gid=os.getgid(),
                               mode=0o600, limit=2000)

    def test_accept_exact_regular_file(self):
        """The original inode is hashed without loading an entire binary."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "digest"
            path.write_bytes(b"reviewed")
            path.chmod(0o400)
            got = m.owned_sha256(path, uid=os.getuid(), gid=os.getgid(),
                                  mode=0o400, limit=1000)
            self.assertEqual(got, hashlib.sha256(b"reviewed").hexdigest())

    def test_signature_mismatch_halts_before_cosign(self):
        """A wrong bundle hash must deny the next release phase."""
        with mock.patch.object(m, "owned_sha256", return_value="0"*64), \
             mock.patch.object(m.subprocess, "run") as called:
            with self.assertRaisesRegex(m.PullHold, "bundle changed"):
                m.signature_preflight()
        called.assert_not_called()

    def test_signature_verifier_failure(self):
        """A nonzero cryptographic verifier is not papered over."""
        with mock.patch.object(m, "owned_sha256",
                               side_effect=[m.BUNDLE_SHA, m.COSIGN_SHA]), \
             mock.patch.object(m.subprocess, "run",
                               return_value=mock.Mock(returncode=1, stdout=b"", stderr=b"")):
            with self.assertRaisesRegex(m.PullHold, "not verified"):
                m.signature_preflight()

    def test_signature_exact_identity_and_digest(self):
        """The only allowed signer is original protected Task013 main."""
        with mock.patch.object(m, "owned_sha256",
                               side_effect=[m.BUNDLE_SHA, m.COSIGN_SHA]), \
             mock.patch.object(m.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stdout=b"", stderr=b"Verified OK")) as run:
            m.signature_preflight()
        command = run.call_args.args[0]
        self.assertIn(m.SIGNER, command)
        self.assertIn(m.ISSUER, command)
        self.assertIn(m.IMAGE_DIGEST.removeprefix("sha256:"), command)
        self.assertNotIn("--insecure-ignore-tlog", command)

    def read_token(self, data: bytes) -> str:
        """Read one fixture token using only the real stdin parsing function."""
        with mock.patch.object(m.time, "time", return_value=1_800_000_000), \
             mock.patch.object(m.sys, "stdin", mock.Mock(buffer=io.BytesIO(data))):
            return m.read_oidc_stdin()

    def test_oidc_contract(self):
        """Expected fresh Task014 token is admitted only as an untrusted prefilter."""
        token = jwt()
        self.assertEqual(self.read_token(token), token.decode("ascii"))

    def test_reject_old_oidc(self):
        """Expired/near-expiry GitHub tokens cannot begin a cold pull."""
        with self.assertRaises(m.PullHold):
            self.read_token(jwt(lifetime=20))

    def test_reject_wrong_workflow(self):
        """An unreviewed workflow cannot issue a token for PROD admission."""
        with self.assertRaises(m.PullHold):
            self.read_token(jwt(workflow="MichaelTrueX/omnilyzer-platform/.github/workflows/unreviewed.yml@refs/heads/main"))

    def test_reject_wrong_issuer(self):
        """A non-GitHub identity is not accepted."""
        with self.assertRaises(m.PullHold):
            self.read_token(jwt(issuer="https://evil.example"))

    def test_reject_oversize_token(self):
        """Unlimited or malformed stdin is never accepted."""
        with self.assertRaises(m.PullHold):
            self.read_token(b"x" * (m.MAX_TOKEN + 1))

    def test_volatile_auth_file_and_cleanup(self):
        """Credential exists only in mode0600 temp Docker config."""
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root)
            m.write_volatile_auth(workspace, "short-test-only-jwt")
            config = workspace / "config.json"
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            content = json.loads(config.read_text())
            value = base64.b64decode(content["auths"][m.ZOT]["auth"])
            self.assertEqual(value, b"oidc:short-test-only-jwt")
            self.assertNotIn("short-test-only-jwt", str(content))

    def test_pull_confirms_original_config_and_registry_digest(self):
        """A digest-pinned pull can only finish after local Docker readback."""
        with tempfile.TemporaryDirectory() as runtime:
            with mock.patch.object(m, "RUNTIME", Path(runtime)), \
                 mock.patch.object(m, "preflight"), \
                 mock.patch.object(m, "read_oidc_stdin", return_value="fixture-jwt"), \
                 mock.patch.object(m, "docker",
                                   side_effect=[b"{}", b"", json.dumps([m.IMAGE]).encode()+b"|"+m.CONFIG_DIGEST.encode()]) as docker:
                m.pull_only()
        self.assertEqual(docker.call_count, 3)
        self.assertEqual(docker.call_args_list[1].args[0],
                         ("pull", "--quiet", m.IMAGE))

    def test_pull_rejects_wrong_docker_image_config(self):
        """A different config digest cannot be promoted as signed0.16."""
        with tempfile.TemporaryDirectory() as runtime:
            with mock.patch.object(m, "RUNTIME", Path(runtime)), \
                 mock.patch.object(m, "preflight"), \
                 mock.patch.object(m, "read_oidc_stdin", return_value="fixture-jwt"), \
                 mock.patch.object(m, "docker",
                                   side_effect=[b"{}", b"", json.dumps([m.IMAGE]).encode()+b"|sha256:"+b"0"*64]):
                with self.assertRaises(m.PullHold):
                    m.pull_only()


if __name__ == "__main__":
    unittest.main()
