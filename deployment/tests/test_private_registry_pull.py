"""File: deployment/tests/test_private_registry_pull.py

Purpose: Exercise an isolated authenticated Docker pull using disposable
private directories and synthetic sealed Zot tokens; never contact Docker or
the real OCI registry. Related: deployment/private_registry_pull.py,
deployment/private_registry_fd.py, deployment/docker_runtime.py.

Sections: authorization gates, exact subprocess boundary, cleanup on error.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from deployment.docker_runtime import CommandResult, DOCKER_CLI, DOCKER_HOST
from deployment.execution import ExecutorRequest
from deployment.private_registry_fd import create_sealed_credential
from deployment.private_registry_pull import (
    PrivateRegistryPullError, PRIVATE_PULL_TIMEOUT_SECONDS,
    MIN_POST_PREFLIGHT_VALIDITY_SECONDS, execute_private_zot_read,
    require_private_zot_pull_budget,
)
from deployment.tests.test_execution import valid_request

NOW = 1_800_000_000
TOKEN = "synthetic.test.JWT-never-a-real-secret"
REQUEST = ExecutorRequest.from_dict(valid_request()).canonical_bytes()
IMAGE = ExecutorRequest.from_dict(valid_request()).exact_image_reference


class MemoryCommandRunner:
    """An inert runner which reads temporary auth config during one mock call."""

    def __init__(self, *, status: int = 0) -> None:
        self.status = status
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.config_path: Path | None = None

    def run(self, argv: tuple[str, ...], *, cwd: Path,
            environment: dict[str, str], timeout: float) -> CommandResult:
        """Assert token is disk-isolated, never exposed in process args or env."""
        self.calls.append((" ".join(argv[5:]), argv))
        assert argv[:2] == (DOCKER_CLI, "--config")
        assert argv[3:5] == ("--host", DOCKER_HOST)
        assert all(TOKEN not in argument for argument in argv)
        assert all(TOKEN not in str(x) for x in environment.values())
        assert set(environment) == {"PATH", "LANG", "CANARY_IMAGE", "HOME"}
        assert environment["CANARY_IMAGE"] == IMAGE
        assert environment["HOME"] == str(Path(argv[2]))
        assert timeout > 0
        self.config_path = Path(argv[2]) / "config.json"
        info = self.config_path.stat()
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert (info.st_uid, info.st_gid) == (os.geteuid(), os.getegid())
        parent = self.config_path.parent.stat()
        assert stat.S_IMODE(parent.st_mode) == 0o700
        data = json.loads(self.config_path.read_text())
        assert set(data) == {"auths"}
        assert set(data["auths"]) == {"oci-dev.omnilyzer.ai"}
        assert set(data["auths"]["oci-dev.omnilyzer.ai"]) == {"auth"}
        decoded = base64.b64decode(
            data["auths"]["oci-dev.omnilyzer.ai"]["auth"],
            validate=True,
        ).decode("ascii")
        assert decoded == "oidc:" + TOKEN
        return CommandResult(self.status, "", "")


class PrivateRegistryPullTests(unittest.TestCase):
    """Prove exact image authorization and error cleanup without daemon I/O."""

    def setUp(self) -> None:
        """Allocate one fresh local test directory without real runtime changes."""
        self.workspace = tempfile.TemporaryDirectory(prefix="task014-registry-read-")
        self.addCleanup(self.workspace.cleanup)
        self.location = Path(self.workspace.name)
        self.location.chmod(0o700)
        self.mock_dir = patch("deployment.private_registry_pull.VOLATILE_DOCKER_DIRECTORY",
                              self.location)
        self.mock_socket = patch("deployment.private_registry_pull._require_rootless_socket",
                                 lambda: None)
        self.mock_clock = patch("deployment.private_registry_pull.time.time", return_value=NOW)
        self.mock_dir.start()
        self.mock_socket.start()
        self.mock_clock.start()
        self.addCleanup(self.mock_dir.stop)
        self.addCleanup(self.mock_socket.stop)
        self.addCleanup(self.mock_clock.stop)

    def sealed(self, *, expires_at: int = NOW + 270,
               request: bytes = REQUEST, image: str = IMAGE) -> int:
        """Create an offline sealed memfd; cleanup is always registered."""
        descriptor = create_sealed_credential(
            TOKEN, expires_at=expires_at, image=image,
            canonical_request=request, now=NOW
        )
        self.addCleanup(os.close, descriptor)
        return descriptor

    def test_manifest_probe_binds_only_one_digest(self) -> None:
        """Perform a read-only manifest lookup without a lasting auth config."""
        runner = MemoryCommandRunner()
        execute_private_zot_read(
            runner, credential_fd=self.sealed(),
            canonical_request=REQUEST, image=IMAGE, operation="manifest",
        )
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0][1][-3:],
                         ("manifest", "inspect", IMAGE))
        self.assertFalse(runner.config_path.exists())
        self.assertEqual(list(self.location.iterdir()), [])

    def test_pull_uses_only_exact_digest_and_cleans_credentials(self) -> None:
        """Docker pull uses the authenticated temporary config and then deletes it."""
        runner = MemoryCommandRunner()
        execute_private_zot_read(
            runner, credential_fd=self.sealed(),
            canonical_request=REQUEST, image=IMAGE, operation="pull",
        )
        self.assertEqual(runner.calls[0][1][-3:], ("pull", "--quiet", IMAGE))
        self.assertFalse(runner.config_path.exists())
        self.assertEqual(list(self.location.iterdir()), [])

    def test_pull_lifetime_reserves_exact_bounded_window(self) -> None:
        """A 180s pull is allowed only with its full expiry safety reserve."""
        self.assertEqual(PRIVATE_PULL_TIMEOUT_SECONDS, 180.0)
        self.assertEqual(MIN_POST_PREFLIGHT_VALIDITY_SECONDS, 225)
        live = self.sealed(expires_at=NOW + 270)
        require_private_zot_pull_budget(live, REQUEST, IMAGE)
        too_short = self.sealed(expires_at=NOW + 224)
        with self.assertRaises(PrivateRegistryPullError):
            require_private_zot_pull_budget(too_short, REQUEST, IMAGE)

    def test_failed_subprocess_removes_token_config(self) -> None:
        """A denied/failed Docker pull does not retain token bytes on disk."""
        runner = MemoryCommandRunner(status=1)
        with self.assertRaises(PrivateRegistryPullError) as caught:
            execute_private_zot_read(
                runner, credential_fd=self.sealed(),
                canonical_request=REQUEST, image=IMAGE, operation="pull",
            )
        self.assertEqual(str(caught.exception), "private Zot pull is unavailable")
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertFalse(runner.config_path.exists())
        self.assertEqual(list(self.location.iterdir()), [])

    def test_no_runner_call_for_expired_or_wrong_binding(self) -> None:
        """Expired, near-expiry and cross-request JWTs fail before Docker I/O."""
        cases = (
            dict(expires_at=NOW + 44, request=REQUEST, image=IMAGE,
                 actual_request=REQUEST, actual_image=IMAGE),
            dict(expires_at=NOW + 60, request=REQUEST, image=IMAGE,
                 actual_request=b'{"another":"request"}\n', actual_image=IMAGE),
            dict(expires_at=NOW + 60, request=REQUEST, image=IMAGE,
                 actual_request=REQUEST, actual_image=IMAGE[:-1] + "0"),
        )
        for case in cases:
            with self.subTest(case=case):
                runner = MemoryCommandRunner()
                fd = self.sealed(
                    expires_at=case["expires_at"], request=case["request"],
                    image=case["image"],
                )
                with self.assertRaises(PrivateRegistryPullError):
                    execute_private_zot_read(
                        runner, credential_fd=fd,
                        canonical_request=case["actual_request"],
                        image=case["actual_image"], operation="pull",
                    )
                self.assertEqual(runner.calls, [])
                self.assertEqual(list(self.location.iterdir()), [])

    def test_invalid_mode_or_directory_metadata_rejected(self) -> None:
        """No public/world-readable parent may hold ephemeral credentials."""
        self.location.chmod(0o755)
        runner = MemoryCommandRunner()
        with self.assertRaises(PrivateRegistryPullError):
            execute_private_zot_read(
                runner, credential_fd=self.sealed(),
                canonical_request=REQUEST, image=IMAGE, operation="manifest",
            )
        self.assertEqual(runner.calls, [])
        self.assertEqual(list(self.location.iterdir()), [])

    def test_unknown_operations_and_unsealed_files_rejected(self) -> None:
        """Arbitrary Docker commands and missing authority must never execute."""
        for operation in ("", "push", "rmi", "delete", None, 1):
            runner = MemoryCommandRunner()
            with self.subTest(operation=operation):
                with self.assertRaises(PrivateRegistryPullError):
                    execute_private_zot_read(
                        runner, credential_fd=self.sealed(),
                        canonical_request=REQUEST, image=IMAGE, operation=operation,
                    )
                self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
