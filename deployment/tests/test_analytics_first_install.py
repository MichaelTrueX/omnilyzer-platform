"""File: deployment/tests/test_analytics_first_install.py

Purpose: Negative-first Task014 Analytics exact first-install operation tests.
         Exercise original kernel-sealed FD and private rootless Docker command
         construction using a strictly simulated rootless command runner.
Related: deployment/analytics_first_install.py,
         deployment/analytics_executor.py,
         deployment/analytics_private_registry.py,
         deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/tests/test_analytics_private_registry.py.

Sections: immutable Compose+rootless image slot, secret UID mapping review,
          first-install readiness, all failures stop-only rollback, original
          executor replay integration, no canary/public/DB modifications.

These tests intentionally do NOT access a Docker daemon, actual PostgreSQL,
real secrets, live signed registry or root-owned deployment host. The fake
runner returns projected Docker metadata, never actual install acceptance.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from deployment.analytics_first_install import (
    AnalyticsFirstInstallError, AnalyticsFirstInstallOperation,
    _require_mapped_secret_groups,
)
from deployment.analytics_execution import AnalyticsExecutorRequest
from deployment.analytics_private_registry import AnalyticsPrivateZotPullAdapter
from deployment.analytics_signed_release_consumer import PINNED_IMAGE
from deployment.docker_runtime import CommandResult, DOCKER_PREFIX
from deployment.executor import parse_canonical_response
from deployment.private_registry_fd import create_sealed_credential
from deployment.private_registry_pull import scoped_private_zot_request
from deployment.tests.test_analytics_execution import EXPECTED, fixture
from deployment.tests.test_identity import NOW
from deployment.tests.test_executor import Replay
from deployment.policy import canonical_bytes

REQUEST = canonical_bytes(fixture())
CONTAINER = "a" * 64
IMAGE = PINNED_IMAGE
ROOTLESS = DOCKER_PREFIX
SLOT = "analytics-blue"
NETWORK = "omnilyzer-analytics-backend-dev"
TOKEN = "SYNTHETIC_CREDENTIAL_DO_NOT_USE"


class SyntheticRootlessDocker:
    """A closed fake of the original nonsecret rootless Docker CLI runner."""

    def __init__(self, *, failure: str | None = None):
        """Select one exact simulated failure without modifying any host."""
        self.calls: list[tuple[str, ...]] = []
        self.failure = failure
        self.state = "absent"
        self.started = False

    def run(self, argv, *, cwd, environment, timeout):
        """Reject arbitrary CLI/env; simulate Docker metadata and exit codes."""
        assert type(argv) is tuple and argv[0] == "/usr/bin/docker"
        assert set(environment) == {
            "PATH", "LANG", "ANALYTICS_BLUE_IMAGE", "ANALYTICS_GREEN_IMAGE",
        } or set(environment) == {
            "PATH", "LANG", "ANALYTICS_IMAGE", "HOME",
        }
        assert TOKEN not in str(argv) and TOKEN not in str(environment)
        assert cwd.name == "dev" and cwd.parent.name == "runtime"
        assert float(timeout) in (5., 30., 45., 180.)
        if environment.get("ANALYTICS_IMAGE") == IMAGE:
            # The original signed-Zot pull uses a temporarily bound Docker
            # config path rather than the global uncredentialed Docker config.
            assert argv[1] == "--config" and argv[3:5] == ROOTLESS[3:5]
            config = Path(argv[2]) / "config.json"
            assert config.is_file() and config.stat().st_mode & 0o777 == 0o600
            assert argv[-1] == IMAGE and argv[5] in ("manifest", "pull")
            self.calls.append(tuple(argv[5:]))
            return CommandResult(0, "", "")
        assert argv[:len(ROOTLESS)] == ROOTLESS
        args = argv[len(ROOTLESS):]
        self.calls.append(args)

        if args[:2] == ("network", "inspect"):
            return CommandResult(0, json.dumps(NETWORK) + "\n", "")
        if args[:2] == ("image", "inspect"):
            return CommandResult(
                0, json.dumps([IMAGE if self.failure != "bad-digest"
                               else "oci-dev.omnilyzer.ai/other@sha256:"+"b"*64]) + "\n", "",
            )
        if args[:2] == ("container", "inspect"):
            query = args[3]
            results = {
                "{{json .Config.Image}}": IMAGE,
                "{{json .Config.User}}": "10001:10001",
                "{{json .HostConfig.ReadonlyRootfs}}": True,
                "{{json .HostConfig.Privileged}}": False,
                "{{json .HostConfig.CapDrop}}": ["ALL"],
                "{{json .HostConfig.SecurityOpt}}": ["no-new-privileges:true"],
                "{{json .HostConfig.PortBindings}}": {
                    "3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3141"}],
                },
                "{{json .NetworkSettings.Networks}}": {NETWORK: {"IPAddress":"10.5.5.5"}},
                "{{json .State.Health.Status}}": (
                    "unhealthy" if self.failure == "unhealthy" else "healthy"
                ),
            }
            if self.failure == "public-bind":
                results["{{json .HostConfig.PortBindings}}"] = {
                    "3000/tcp": [{"HostIp":"0.0.0.0","HostPort":"3141"}],
                }
            if self.failure == "capability-leak":
                results["{{json .HostConfig.CapDrop}}"] = []
            return CommandResult(0, json.dumps(results[query])+"\n", "")
        if args[0] == "compose":
            assert args[:8] == (
                "compose", "--project-name", "omnilyzer-analytics-dev",
                "--file", args[4], "--profile", "blue",
                args[7],
            )
            assert args[4].endswith("analytics.compose.review.yaml")
            operation = args[7]
            if operation == "config":
                return CommandResult(0, "", "")
            if operation == "ps":
                if "-q" in args:
                    return CommandResult(0, (CONTAINER+"\n") if self.started else "", "")
                if "--all" in args:
                    return CommandResult(0, '[]\n' if self.failure != "occupied" else
                                         '[{"Name":"other"}]\n', "")
                if "--status" in args:
                    return CommandResult(0, '[]\n' if self.state == "stopped"
                                         else '[{"State":"running"}]\n', "")
            if operation == "up":
                self.started = True
                self.state = "running"
                if self.failure == "up-error":
                    return CommandResult(1, "", "synthetic error")
                return CommandResult(0, "", "")
            if operation == "stop":
                if self.failure == "stop-error":
                    return CommandResult(1, "", "synthetic error")
                self.state = "stopped"
                return CommandResult(0, "", "")
            if operation == "exec":
                return CommandResult(0, "FAIL\n" if self.failure == "not-ready"
                                     else "READY\n", "")
        if args[:2] == ("manifest", "inspect") or "pull" in args:
            # Original Zot helper's private Docker command.
            assert environment["HOME"].startswith("/tmp/")
            return CommandResult(0, "", "")
        raise AssertionError("unreviewed rootless Docker command")


class ExactFirstInstallTests(unittest.TestCase):
    """No host mutation before signed source/secret/slot checks."""

    def setUp(self):
        """Use original short-lived FD and mocked rootless/secret metadata."""
        self.workspace = tempfile.TemporaryDirectory(prefix="m05-14-first-install-")
        self.addCleanup(self.workspace.cleanup)
        self.runner = SyntheticRootlessDocker()
        self.reviews = [
            patch("deployment.analytics_first_install._require_rootless_socket"),
            patch("deployment.analytics_private_registry._require_rootless_socket"),
            patch("deployment.analytics_first_install.review_private_secret_paths",
                  return_value=("COLLECTOR_DATABASE_URL","DATABASE_URL",
                                "JWT_REFRESH_SECRET","JWT_SECRET")),
            patch("deployment.analytics_first_install._require_mapped_secret_groups"),
            patch("deployment.analytics_private_registry._private_runtime_directory",
                  return_value=Path(self.workspace.name)),
            patch("deployment.analytics_private_registry.time.time",return_value=NOW),
            patch("deployment.private_registry_fd.time.time",return_value=NOW),
        ]
        for item in self.reviews:
            item.start()
            self.addCleanup(item.stop)
        self.registry = AnalyticsPrivateZotPullAdapter(
            self.runner, reviewed_installed_source=EXPECTED,
        )
        self.operation = AnalyticsFirstInstallOperation(
            runner=self.runner, private_registry=self.registry,
            reviewed_installed_source=EXPECTED,
        )
        self.request = AnalyticsExecutorRequest.from_dict(fixture(), **EXPECTED)
        self.fd = create_sealed_credential(
            TOKEN, expires_at=NOW + 270, image=IMAGE,
            canonical_request=REQUEST, product_id="analytics", now=NOW,
        )
        self.addCleanup(os.close, self.fd)

    def deploy(self):
        """Invoke one synthetic original executor-local credential scope."""
        with scoped_private_zot_request(self.fd, REQUEST):
            return self.operation.deploy_analytics(self.request)

    def test_success_private_blue_only_no_public_or_canary(self):
        """One exact signed digest, local readyz and no rollback after success."""
        self.assertIsNone(self.deploy())
        args = self.runner.calls
        self.assertTrue(any(a[:2] == ("network","inspect") for a in args))
        self.assertTrue(any(a[:2] == ("image","inspect") for a in args))
        self.assertTrue(any(a[0] == "compose" and a[7] == "config" for a in args))
        self.assertTrue(any(a[0] == "compose" and a[7] == "up" for a in args))
        self.assertTrue(any(a[0] == "compose" and a[7] == "exec" for a in args))
        self.assertFalse(any(a[0] == "compose" and a[7] == "stop" for a in args))
        self.assertTrue(all(
            "canary" not in " ".join(a) and "--volumes" not in a
            and "down" not in a and "green" not in a
            for a in args
        ))
        self.assertEqual(self.runner.state, "running")

    def test_preflight_requires_uid991_directory_and_uid503216_secret_files(self):
        """Require root:991 mode0710 parent and mapped-UID0600 source files."""
        from deployment.rootless_docker_authority import RootlessDockerAuthority
        with patch("deployment.analytics_first_install.review_private_secret_paths",
                   return_value=("COLLECTOR_DATABASE_URL","DATABASE_URL",
                                 "JWT_REFRESH_SECRET","JWT_SECRET")) as reviewer:
            self.assertIsNone(self.deploy())
        authority = RootlessDockerAuthority()
        reviewer.assert_called_once_with(
            directory=Path("/var/lib/omnilyzer/deployment/analytics/dev/secrets"),
            owner_uid=authority.subuid_start + 10001 - 1,
            directory_owner_uid=0,
            directory_group_gid=authority.executor_gid,
        )

    def test_missing_secret_mapping_or_changed_compose_fails_before_docker(self):
        """Rootless mapped UID requirement is non-optional and exact."""
        with patch(
            "deployment.analytics_first_install.review_private_secret_paths",
            side_effect=PermissionError,
        ):
            with self.assertRaises(AnalyticsFirstInstallError):
                self.deploy()
        self.assertEqual(self.runner.calls, [])
        with patch("deployment.analytics_first_install._require_mapped_secret_groups",
                   side_effect=PermissionError):
            with self.assertRaises(AnalyticsFirstInstallError):
                self.deploy()
        self.assertEqual(self.runner.calls, [])
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".yaml") as changed:
            changed.write(b"unreviewed compose")
            changed.flush()
            with patch("deployment.analytics_first_install.COMPOSE_FILE",
                       Path(changed.name)):
                with self.assertRaises(AnalyticsFirstInstallError):
                    self.deploy()
        self.assertEqual(self.runner.calls, [])

    def test_existing_blue_container_fails_without_pull_or_mutation(self):
        """First-install cannot replace or reuse a previously created slot."""
        self.runner.failure = "occupied"
        with self.assertRaises(AnalyticsFirstInstallError):
            self.deploy()
        self.assertFalse(any(a[0] == "compose" and a[7] == "up"
                             for a in self.runner.calls))
        self.assertFalse(any("pull" in a for a in self.runner.calls))
        self.assertFalse(any(a[0] == "compose" and a[7] == "stop"
                             for a in self.runner.calls))

    def test_bad_image_digest_denies_before_start(self):
        """Only signed local RepoDigests can enter the Compose up phase."""
        self.runner.failure = "bad-digest"
        with self.assertRaises(AnalyticsFirstInstallError):
            self.deploy()
        self.assertFalse(any(a[0] == "compose" and a[7] == "up"
                             for a in self.runner.calls))

    def test_failure_after_start_always_stops_only_blue(self):
        """Up failure, public port, failed readyz and unhealthy stop safely."""
        for failure in ("up-error", "public-bind", "capability-leak", "not-ready", "unhealthy"):
            with self.subTest(failure=failure):
                self.runner = SyntheticRootlessDocker(failure=failure)
                self.registry = AnalyticsPrivateZotPullAdapter(
                    self.runner, reviewed_installed_source=EXPECTED,
                )
                self.operation = AnalyticsFirstInstallOperation(
                    runner=self.runner, private_registry=self.registry,
                    reviewed_installed_source=EXPECTED,
                )
                with self.assertRaises(AnalyticsFirstInstallError):
                    self.deploy()
                assert self.runner.state == "stopped"
                stop = [a for a in self.runner.calls
                        if a[0] == "compose" and a[7] == "stop"]
                self.assertEqual(len(stop), 1)
                self.assertEqual(stop[0][-1], "analytics-blue")
                self.assertFalse(any("down" in a or "--volumes" in a or "rm" in a
                                     for a in self.runner.calls))

    def test_failed_rollback_does_not_report_success(self):
        """A failed stop never becomes a successful/healthy deploy response."""
        class PartialStartAndBrokenStop(SyntheticRootlessDocker):
            """Simulate partial Docker up followed by failed stop command."""

            def run(self, argv, *, cwd, environment, timeout):
                """Original executor captures this ordinary class method."""
                if "up" in argv:
                    self.started = True
                    self.state = "running"
                    self.calls.append(argv[len(ROOTLESS):])
                    return CommandResult(1, "", "synthetic partial start")
                return super().run(
                    argv, cwd=cwd, environment=environment, timeout=timeout,
                )

        self.runner = PartialStartAndBrokenStop(failure="stop-error")
        self.registry = AnalyticsPrivateZotPullAdapter(
            self.runner, reviewed_installed_source=EXPECTED,
        )
        self.operation = AnalyticsFirstInstallOperation(
            runner=self.runner, private_registry=self.registry,
            reviewed_installed_source=EXPECTED,
        )
        captured = io.StringIO()
        with redirect_stderr(captured), self.assertRaises(AnalyticsFirstInstallError):
            self.deploy()
        self.assertIn("rollback=unconfirmed",captured.getvalue())
        self.assertNotIn(TOKEN,captured.getvalue())

    def test_original_executor_replay_then_private_first_install(self):
        """Real original sealed FD, executor replay transitions and fake Docker."""
        from deployment.analytics_executor import AnalyticsPrivilegedExecutor
        replay = Replay([])
        executor = AnalyticsPrivilegedExecutor(
            replay_guard=replay, private_registry_preflight=self.registry,
            operation=self.operation, reviewed_installed_source=EXPECTED,
        )
        with patch("deployment.analytics_executor.time.time",return_value=NOW):
            response = executor.execute_private(REQUEST, credential_fd=self.fd)
        self.assertEqual(
            parse_canonical_response(response).executor_request_sha256,
            hashlib.sha256(REQUEST).hexdigest(),
        )
        self.assertEqual(len(replay.begin_calls),1)
        self.assertEqual(len(replay.finish_calls),1)
        self.assertEqual(self.runner.state,"running")

    def test_executor_replay_finish_failure_stops_healthy_first_slot(self):
        """Unconfirmed durable finish must deactivate an otherwise-ready slot."""
        from deployment.analytics_executor import AnalyticsPrivilegedExecutor
        from deployment.executor import ExecutorUnavailableError
        replay = Replay([], finish_error=OSError("synthetic SQLite disk failure"))
        executor = AnalyticsPrivilegedExecutor(
            replay_guard=replay, private_registry_preflight=self.registry,
            operation=self.operation, reviewed_installed_source=EXPECTED,
        )
        with patch("deployment.analytics_executor.time.time", return_value=NOW):
            with self.assertRaises(ExecutorUnavailableError):
                executor.execute_private(REQUEST, credential_fd=self.fd)
        self.assertEqual(len(replay.begin_calls), 1)
        self.assertEqual(len(replay.finish_calls), 1)
        self.assertEqual(self.runner.state, "stopped")
        stop = [a for a in self.runner.calls
                if a[0] == "compose" and a[7] == "stop"]
        self.assertEqual(len(stop), 1)
        self.assertFalse(any("down" in a or "--volumes" in a
                             for a in self.runner.calls))

    def test_rollback_can_only_stop_its_own_completed_request(self):
        """No arbitrary request may stop another product's first-slot state."""
        self.assertIsNone(self.deploy())
        from dataclasses import replace
        altered = replace(self.request, oidc_jti="different-valid-jti")
        with self.assertRaises(AnalyticsFirstInstallError):
            self.operation.rollback_first_analytics(altered)
        self.assertEqual(self.runner.state, "running")
        self.assertIsNone(self.operation.rollback_first_analytics(self.request))
        self.assertEqual(self.runner.state, "stopped")
        # A subsequent rollback is idempotent and must not repeat Docker stop.
        self.assertIsNone(self.operation.rollback_first_analytics(self.request))
        self.assertEqual(len([
            a for a in self.runner.calls if a[0] == "compose" and a[7] == "stop"
        ]), 1)

    def test_wrong_product_runtime_reference_or_source_prevents_start(self):
        """No arbitrary launch via constructed but wrongly bound objects."""
        from dataclasses import replace
        wrong = replace(self.request, ingress_reference={
            **self.request.ingress_reference, "public_origin": "https://example.com",
        })
        with scoped_private_zot_request(self.fd,REQUEST):
            with self.assertRaises(AnalyticsFirstInstallError):
                self.operation.deploy_analytics(wrong)
        self.assertEqual(self.runner.calls, [])


if __name__ == "__main__":
    unittest.main()
