"""File: deployment/tests/test_analytics_private_registry.py

Purpose: Exercise the original rootless Docker/Zot security path against exact
         signed Analytics 0.15.0 with synthetic sealed tokens and a fake command
         runner; no live Zot, Docker, secret or production connection.
Related: deployment/analytics_private_registry.py,
         deployment/analytics_executor.py,
         deployment/private_registry_fd.py,
         deployment/private_registry_pull.py,
         deployment/tests/test_private_registry_pull.py.

Sections: isolated volatile secret config, original rootless invocation,
          post-preflight short-lived credential pull, fail-closed adversarial
          cases and complete cleanup.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from deployment.analytics_private_registry import (
    AnalyticsPrivateRegistryError, AnalyticsPrivateZotPullAdapter,
)
from deployment.analytics_signed_release_consumer import PINNED_IMAGE
from deployment.analytics_execution import AnalyticsExecutorRequest
from deployment.private_registry_fd import create_sealed_credential
from deployment.private_registry_pull import scoped_private_zot_request
from deployment.tests.test_analytics_execution import EXPECTED, fixture
from deployment.tests.test_identity import NOW
from deployment.policy import canonical_bytes
from deployment.docker_runtime import CommandResult

REQUEST = canonical_bytes(fixture())
TOKEN = "synthetic-original-signed-JWT-for-tests-only"


class SyntheticRunner:
    """Inspect the original Docker command and volatile config, never execute."""

    def __init__(self, *, outcome=None):
        self.calls = []
        self.workspaces = []
        self.outcome = CommandResult(0, "", "") if outcome is None else outcome

    def run(self, argv, *, cwd, environment, timeout):
        """Capture nonsecret envelope, assert config/permission and fake result."""
        workspace = Path(environment["HOME"])
        config = workspace / "config.json"
        assert config.is_file()
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
        assert argv[0] == "/usr/bin/docker"
        assert argv[1] == "--config" and argv[2] == str(workspace)
        assert argv[3:5] == (
            "--host", "unix:///run/omnilyzer/deployment/rootless-docker/docker.sock",
        )
        assert argv[-1] == PINNED_IMAGE
        assert TOKEN not in str(argv)
        assert TOKEN not in str(environment)
        assert set(environment) == {"PATH", "LANG", "ANALYTICS_IMAGE", "HOME"}
        assert environment["ANALYTICS_IMAGE"] == PINNED_IMAGE
        assert timeout in (30.0, 180.0)
        self.calls.append((argv, dict(environment), timeout))
        self.workspaces.append(workspace)
        return self.outcome


def make_fd(*, expires_at=NOW + 270, canonical_request=REQUEST):
    """Return original kernel-sealed exact digest and bound-request descriptor."""
    return create_sealed_credential(
        TOKEN, expires_at=expires_at, image=PINNED_IMAGE,
        canonical_request=canonical_request, now=NOW, product_id="analytics",
    )


class RootlessAnalyticsZotTests(unittest.TestCase):
    """No Docker I/O is possible until the original rootless preflight passes."""

    def setUp(self):
        self.workdir = tempfile.TemporaryDirectory(prefix="m05-14-analytics-zot-")
        root = Path(self.workdir.name)
        root.chmod(0o700)
        self.addCleanup(self.workdir.cleanup)
        self.runner = SyntheticRunner()
        self.adapter = AnalyticsPrivateZotPullAdapter(
            self.runner, reviewed_installed_source=EXPECTED,
        )
        self.patches = [
            patch("deployment.analytics_private_registry.time.time", return_value=NOW),
            patch("deployment.analytics_private_registry._private_runtime_directory",
                  return_value=root),
            patch("deployment.analytics_private_registry._require_rootless_socket",
                  return_value=None),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_manifest_then_scoped_private_pull_and_volatile_cleanup(self):
        """Exact original 30s manifest + 180s pull; secret never in argv or env."""
        fd = make_fd()
        try:
            self.assertIsNone(self.adapter.preflight_analytics(REQUEST, fd))
            request = AnalyticsExecutorRequest.from_dict(fixture(), **EXPECTED)
            with scoped_private_zot_request(fd, REQUEST):
                self.assertIsNone(self.adapter.pull_analytics(request))
            self.assertEqual(len(self.runner.calls), 2)
            self.assertEqual(
                self.runner.calls[0][0][-3:-1], ("manifest", "inspect"),
            )
            self.assertIn("pull", self.runner.calls[1][0])
            self.assertEqual(
                [call[2] for call in self.runner.calls], [30.0, 180.0],
            )
            self.assertTrue(all(not path.exists() for path in self.runner.workspaces))
            self.assertEqual(list(Path(self.workdir.name).iterdir()), [])
        finally:
            os.close(fd)

    def test_privileged_executor_uses_same_fd_for_real_adapter_manifest_and_pull(self):
        """The original executor phase order reuses one secure Docker auth scope."""
        from deployment.analytics_executor import AnalyticsPrivilegedExecutor
        from deployment.executor import parse_canonical_response
        from deployment.tests.test_executor import Replay

        class ExactPrivateFirstInstall:
            """Synthetic product runtime, delegates only original scoped pull."""

            def __init__(self, adapter):
                self.adapter = adapter
                self.calls = 0

            def deploy_analytics(self, request):
                """Run the exact authenticated pull; no Compose or DB change."""
                self.calls += 1
                self.adapter.pull_analytics(request)

            def rollback_first_analytics(self, request):
                """No container started by this narrow fake pull operation."""
                return None

        events = []
        replay = Replay(events)
        operation = ExactPrivateFirstInstall(self.adapter)
        executor = AnalyticsPrivilegedExecutor(
            replay_guard=replay, private_registry_preflight=self.adapter,
            operation=operation, reviewed_installed_source=EXPECTED,
        )
        fd = make_fd()
        try:
            with patch("deployment.analytics_executor.time.time", return_value=NOW):
                response = executor.execute_private(REQUEST, credential_fd=fd)
            self.assertEqual(
                parse_canonical_response(response).executor_request_sha256,
                hashlib.sha256(REQUEST).hexdigest(),
            )
            self.assertEqual(len(self.runner.calls), 2)
            self.assertEqual(operation.calls, 1)
            self.assertEqual(events, ["begin_execution", "finish_execution"])
            self.assertTrue(all(not path.exists() for path in self.runner.workspaces))
        finally:
            os.close(fd)

    def test_missing_scope_never_pulls_or_uses_original_canary(self):
        """No unsigned executor deployment can start a private image pull."""
        fd = make_fd()
        try:
            request = AnalyticsExecutorRequest.from_dict(fixture(), **EXPECTED)
            with self.assertRaises(AnalyticsPrivateRegistryError):
                self.adapter.pull_analytics(request)
            with scoped_private_zot_request(fd, b"mismatched-request"):
                with self.assertRaises(AnalyticsPrivateRegistryError):
                    self.adapter.pull_analytics(request)
            self.assertEqual(self.runner.calls, [])
        finally:
            os.close(fd)

    def test_rootless_absent_denies_before_creating_config(self):
        """No fallback to host rootful Docker socket, even with valid signer."""
        fd = make_fd()
        try:
            with patch(
                "deployment.analytics_private_registry._require_rootless_socket",
                side_effect=OSError("synthetic rootless socket missing"),
            ):
                with self.assertRaises(AnalyticsPrivateRegistryError):
                    self.adapter.preflight_analytics(REQUEST, fd)
            self.assertEqual(self.runner.calls, [])
            self.assertEqual(list(Path(self.workdir.name).iterdir()), [])
        finally:
            os.close(fd)

    def test_short_credential_ttl_and_tampered_request_denied(self):
        """Bound pull windows are original and immutable, never relaxed."""
        for expires, altered in (
            (NOW + 224, REQUEST),
            (NOW + 270, REQUEST + b" "),
            (NOW + 270, canonical_bytes({**fixture(), "stage": "prod"})),
        ):
            fd = make_fd(expires_at=expires)
            try:
                with self.subTest(ttl=expires - NOW), self.assertRaises(
                    AnalyticsPrivateRegistryError
                ):
                    self.adapter.preflight_analytics(altered, fd)
            finally:
                os.close(fd)
        self.assertEqual(self.runner.calls, [])

    def test_nonzero_docker_result_is_redacted_and_temp_config_removed(self):
        """Never print Docker stdout/stderr, registry token or auth information."""
        self.runner.outcome = CommandResult(
            1, "synthetic sensitive output", "401 invalid synthetic password",
        )
        fd = make_fd()
        try:
            with self.assertRaises(AnalyticsPrivateRegistryError) as captured:
                self.adapter.preflight_analytics(REQUEST, fd)
            self.assertNotIn(TOKEN, str(captured.exception))
            self.assertNotIn("401", str(captured.exception))
            self.assertEqual(len(self.runner.calls), 1)
            self.assertTrue(all(not path.exists() for path in self.runner.workspaces))
        finally:
            os.close(fd)

    def test_invalid_product_source_or_runner_never_constructs_authority(self):
        """No caller-selected image, source hash, repo or dynamic command."""
        with self.assertRaises(TypeError):
            AnalyticsPrivateZotPullAdapter(
                self.runner,
                reviewed_installed_source={
                    **EXPECTED, "reviewed_compose_sha256": "malformed",
                },
            )
        with self.assertRaises(TypeError):
            AnalyticsPrivateZotPullAdapter(
                object(), reviewed_installed_source=EXPECTED,
            )
        with self.assertRaises(AttributeError):
            self.adapter._runner = lambda *_: None


if __name__ == "__main__":
    unittest.main()
