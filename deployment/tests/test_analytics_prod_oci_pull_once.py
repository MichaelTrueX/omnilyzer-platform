#!/usr/bin/env python3
"""File: deployment/tests/test_analytics_prod_oci_pull_once.py

Purpose: Focused offline regression tests for the OWNER-ATTENDED, single
         command, original signed Analytics 0.16.0 PROD pull wrapper.
Related: deployment/analytics_prod_oci_pull_once.py,
         release/analytics_prod_credential_handoff.py,
         deployment/analytics_prod_authenticated_pull.py.

Sections: exact owner and signed host preflight; one workflow dispatch; fresh
          successful credential job; ciphertext-only artifact; remote signed
          rootless pull with no automatic retry; immutable Docker readback.
All tests are synthetic and NEVER call GitHub, SSH, Docker, decrypt a real
token or change any server.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "analytics_prod_oci_pull_once.py"
SPEC = importlib.util.spec_from_file_location("analytics_prod_oci_pull_once", SOURCE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class TestOneOwnerAction(unittest.TestCase):
    """Require the exact signed source and reject unsafe/surprise effects."""

    def test_fixed_rootless_prod_and_digest(self):
        """Never use a mutable image tag or a privileged Docker socket."""
        self.assertEqual(m.PROD_PORT, "2222")
        self.assertIn("@sha256:", m.IMAGE)
        self.assertTrue(m.PROD_RECEIVER.endswith("_v3.py"))
        self.assertTrue(m.IMAGE_ID.startswith("sha256:"))
        self.assertIn("StrictHostKeyChecking=yes", m.SSH_OPTS)
        self.assertIn("BatchMode=yes", m.SSH_OPTS)

    def test_owner_rejects_other_machine(self):
        """No unattended invocation from DEV or PROD."""
        with mock.patch.object(m.socket, "gethostname", return_value="omnilyzerdev"):
            with self.assertRaisesRegex(m.ReleaseHold, "michael-laptop"):
                m.check_owner()

    def test_original_root_source_preflight(self):
        """Read-only remote check requires original source hash and signature."""
        with mock.patch.object(m, "execute",
                               return_value="ANALYTICS_PROD_SIGNED_REGISTRY_PULL_READONLY_PASS") as run:
            m.remote_preflight()
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "ssh")
        self.assertIn("sudo -n /usr/bin/sha256sum", argv[-1])
        self.assertIn(m.PROD_RECEIVER_SHA, argv[-1])
        self.assertIn("--preflight", argv[-1])
        self.assertNotIn("--pull-only", argv[-1])

    def test_remote_preflight_missing_receipt(self):
        """Do not dispatch before a verified PROD preflight."""
        with mock.patch.object(m, "execute", return_value=""):
            with self.assertRaisesRegex(m.ReleaseHold, "preflight"):
                m.remote_preflight()

    def test_dispatch_only_credential_job(self):
        """Original Task014 DEV deployment input is never requested."""
        old = [{"databaseId": 123}]
        new = [dict(databaseId=124, headSha="a"*40, event="workflow_dispatch",
                    createdAt=dt.datetime.now(dt.timezone.utc).isoformat())]
        with mock.patch.object(m, "protected_main_sha", return_value="a"*40), \
             mock.patch.object(m, "workflow_runs", side_effect=[old, new]), \
             mock.patch.object(m, "execute") as run:
            self.assertEqual(m.dispatch_once(), 124)
        argv = run.call_args.args[0]
        self.assertIn("auth_probe=true", argv)
        self.assertIn("target_stage=prod", argv)
        self.assertIn("product_id=analytics", argv)
        self.assertNotIn("analytics_successor=true", argv)

    def test_wait_one_credential_success(self):
        """Original gate/deploy/probe must all be SKIPPED."""
        data = {"status": "completed", "conclusion": "success", "jobs": [
            {"name": "prod_analytics_registry_credential", "conclusion": "success"},
            {"name": "gate", "conclusion": "skipped"},
            {"name": "deploy_dev", "conclusion": "skipped"},
            {"name": "private_zot_readonly_probe", "conclusion": "skipped"},
        ]}
        with mock.patch.object(m, "execute", return_value=json.dumps(data)):
            m.wait_success(321)

    def test_reject_executed_original_dev_deploy(self):
        """Any actual Task014 deploy must stop the owner wrapper."""
        data = {"status": "completed", "conclusion": "success", "jobs": [
            {"name": "prod_analytics_registry_credential", "conclusion": "success"},
            {"name": "gate", "conclusion": "skipped"},
            {"name": "deploy_dev", "conclusion": "success"},
            {"name": "private_zot_readonly_probe", "conclusion": "skipped"},
        ]}
        with mock.patch.object(m, "execute", return_value=json.dumps(data)):
            with self.assertRaises(m.ReleaseHold):
                m.wait_success(321)

    def test_artifact_no_extra_files(self):
        """Only ciphertext with the exact fixed artifact filename may transfer."""
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            file = folder / "m05-analytics-prod-registry-token.age"
            file.write_bytes(b"age-encryption.org/v1\n" + b"x"*64)
            with mock.patch.object(m, "execute"):
                self.assertEqual(m.encrypted_artifact(12345, folder), file)
                (folder / "plaintext.jwt").write_bytes(b"bad")
                with self.assertRaises(m.ReleaseHold):
                    m.encrypted_artifact(12345, folder)

    def test_remote_no_secret_or_container_start(self):
        """Only ciphertext goes through SCP, then exact UID990 signed pull."""
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "m05-analytics-prod-registry-token.age"
            artifact.write_bytes(b"age-encryption.org/v1\n" + b"x"*30)
            with mock.patch.object(m, "execute",
                                   side_effect=["", "", m.EXPECTED_MARKER]) as run:
                m.remote_pull(987654, artifact)
        self.assertEqual(run.call_count, 3)
        scp_argv = run.call_args_list[1].args[0]
        self.assertEqual(scp_argv[0], "scp")
        self.assertIn("m05-analytics-prod-registry-token.age", scp_argv[-2])
        shell = run.call_args_list[2].kwargs["input_text"]
        self.assertIn("set -Eeuo pipefail", shell)
        self.assertIn(m.AGE_IDENTITY, shell)
        self.assertIn(m.PROD_RECEIVER, shell)
        self.assertIn("--pull-only", shell)
        self.assertIn("sudo -n /usr/sbin/runuser -u omnilyzer-analytics", shell)
        self.assertNotIn("docker run", shell)
        self.assertNotIn("docker compose", shell)
        self.assertNotIn("nginx", shell)

    def test_remote_rejects_missing_signed_receipt(self):
        """Do not silently promote a failed/partial image pull."""
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "test.age"
            artifact.write_bytes(b"age")
            with mock.patch.object(m, "execute", side_effect=["", "", ""]):
                with self.assertRaisesRegex(m.ReleaseHold, "receipt"):
                    m.remote_pull(987654, artifact)

    def test_docker_postpull_digest_strict(self):
        """Only original signed image/config pair qualifies."""
        data = json.dumps([m.IMAGE]) + "|" + m.IMAGE_ID + "\n"
        with mock.patch.object(m, "execute", return_value=data):
            m.verify_postpull()
        with mock.patch.object(m, "execute",
                               return_value=json.dumps([m.IMAGE]) + "|sha256:"+"0"*64):
            with self.assertRaisesRegex(m.ReleaseHold, "config digest"):
                m.verify_postpull()

    def test_main_preflight_never_dispatches(self):
        """Help and --preflight cannot mint a real OIDC token."""
        with mock.patch.object(m, "check_owner"), \
             mock.patch.object(m, "remote_preflight"), \
             mock.patch.object(m, "dispatch_once") as dispatch, \
             mock.patch.object(m.sys, "argv", ["tool", "--preflight"]):
            self.assertEqual(m.main(), 0)
        dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
