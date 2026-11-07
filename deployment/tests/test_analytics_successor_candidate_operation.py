"""File: deployment/tests/test_analytics_successor_candidate_operation.py

Purpose: Independently qualify first-successor rootless green startup and
         stop-only rollback with real sealed FD + disposable Ed25519 owner
         approval, synthetic Docker CLI and a protected V2 source fixture.
Related: deployment/analytics_first_install.py,
         deployment/analytics_executor_service_config.py,
         deployment/analytics_private_registry.py,
         deployment/runtime/dev/analytics.compose.successor-ports.yaml,
         deployment/tests/test_analytics_unix_boundary.py.

Sections: closed simulated Docker runtime; real request/credential setup;
          positive private candidate, negative authority and failure rollback.

The tests make NO real Docker pull, service change, network/RootlessKit route,
database mutation, release signing, privileged installation or production
deployment. Candidate startup is NOT enabled in the installed schema-2 handler.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment.analytics_execution import parse_analytics_successor_request
from deployment.analytics_first_install import (
    AnalyticsFirstInstallError, AnalyticsSuccessorCandidateOperation,
    _SUCCESSOR_COMPOSE_OVERLAY,
)
from deployment.analytics_private_registry import AnalyticsPrivateZotPullAdapter
from deployment.docker_runtime import CommandResult, DOCKER_PREFIX
from deployment.private_registry_fd import create_sealed_credential
from deployment.private_registry_pull import scoped_private_zot_request
from deployment.tests.test_analytics_execution import (
    AnalyticsSuccessorRequestTests, EXPECTED,
)
from deployment.tests.test_analytics_private_registry import (
    first_successor_empty_active_state, make_full_successor_fd,
)
from deployment.tests.test_analytics_unix_boundary import signed_owner_fixture
from deployment.tests.test_identity import NOW
from deployment.policy import canonical_bytes


# Section 1: require precisely the existing reviewed Task014 Docker command
# syntax, a completely private Compose overlay and no arbitrary Docker verbs.
CID = "b" * 64
TOKEN = "SYNTHETIC_TASK14B_ZOT_ONLY"
NETWORK = "omnilyzer-analytics-backend-dev"
NETWORK_ID = "f" * 64


class SyntheticGreenRunner:
    """Trace exact rootless commands while never connecting to a daemon."""

    def __init__(self, image: str, failure: str | None = None):
        """Select one synthetic failure and original immutable OCI identity."""
        self.image = image
        self.failure = failure
        self.created = False
        self.running = False
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv, *, cwd, environment, timeout):
        """Reject unauthorized command/env and project bounded Docker replies."""
        assert type(argv) is tuple and argv[0] == "/usr/bin/docker"
        assert type(timeout) is float and 0 < timeout <= 500.0
        assert TOKEN not in str(argv) and TOKEN not in str(environment)
        assert cwd.name == "dev" and cwd.parent.name == "runtime"
        if "ANALYTICS_IMAGE" in environment:
            assert set(environment) == {
                "PATH", "LANG", "ANALYTICS_IMAGE", "HOME",
            }
            assert argv[1] == "--config"
            assert argv[3:5] == DOCKER_PREFIX[3:5]
            assert argv[-3:] == ("pull", "--quiet", self.image)
            assert (Path(argv[2]) / "config.json").is_file()
            assert (Path(argv[2]) / "config.json").stat().st_mode & 0o777 == 0o600
            self.calls.append(("sealed-zot-pull", self.image))
            return CommandResult(0, "", "")

        assert argv[:len(DOCKER_PREFIX)] == DOCKER_PREFIX
        assert set(environment) == {
            "PATH", "LANG", "ANALYTICS_BLUE_IMAGE", "ANALYTICS_GREEN_IMAGE",
        }
        assert environment["ANALYTICS_GREEN_IMAGE"] == self.image
        assert timeout <= 45.0
        parts = argv[len(DOCKER_PREFIX):]
        self.calls.append(parts)
        if parts[:2] == ("network", "inspect"):
            assert parts[-1] == NETWORK
            data = {
                "{{json .Name}}": NETWORK,
                "{{json .Id}}": (
                    "d" * 64 if self.failure == "wrong-network" else NETWORK_ID
                ),
                "{{json .Internal}}": self.failure != "public-network",
            }
            assert parts[3] in data
            return CommandResult(0, json.dumps(data[parts[3]]), "")
        if parts[:2] == ("image", "inspect"):
            assert parts[-1] == self.image
            digest = (
                "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:" + "f" * 64
                if self.failure == "wrong-repodigest" else self.image
            )
            return CommandResult(0, json.dumps([digest]), "")
        if parts[:2] == ("container", "stop"):
            assert parts == ("container", "stop", "--time", "15", CID)
            if self.failure == "stop-error":
                return CommandResult(1, "", "synthetic stop denial")
            self.running = False
            return CommandResult(0, CID + "\n", "")
        if parts[:2] == ("container", "inspect"):
            assert parts[-1] == CID
            wanted = parts[3]
            metadata = {
                "{{json .Config.Image}}": self.image,
                "{{json .Config.User}}": "10001:10001",
                "{{json .HostConfig.ReadonlyRootfs}}": True,
                "{{json .HostConfig.Privileged}}": False,
                "{{json .HostConfig.CapDrop}}": ["ALL"],
                "{{json .HostConfig.SecurityOpt}}": [
                    "no-new-privileges:true",
                ],
                "{{json .HostConfig.PortBindings}}": (
                    {"3000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3142"}]}
                    if self.failure == "public-port" else {}
                ),
                "{{json .NetworkSettings.Networks}}": {
                    NETWORK: {
                        "IPAddress": (
                            "172.20.0.3" if self.failure == "shared-IP"
                            else "172.20.0.4"
                        ),
                        "NetworkID": NETWORK_ID,
                        "Gateway": "",
                    },
                },
                "{{json .State.Health.Status}}": (
                    "unhealthy" if self.failure == "unhealthy" else "healthy"
                ),
                "{{json .State.Running}}": self.running,
            }
            assert wanted in metadata
            return CommandResult(0, json.dumps(metadata[wanted]), "")
        prefix = (
            "compose", "--project-name", "omnilyzer-analytics-dev",
            "--file", str(_SUCCESSOR_COMPOSE_OVERLAY.with_name(
                "analytics.compose.review.yaml"
            )),
            "--file", str(_SUCCESSOR_COMPOSE_OVERLAY),
            "--profile", "green",
        )
        assert parts[:len(prefix)] == prefix
        command = parts[len(prefix):]
        if command[:1] == ("config",):
            assert command == ("config", "--quiet")
            return CommandResult(0, "", "")
        if command[:1] == ("ps",):
            if "--all" in command and "--format" in command:
                return CommandResult(
                    0,
                    '[{"Name":"unapproved-green"}]'
                    if self.failure == "occupied" else "[]",
                    "",
                )
            if "--all" in command and "-q" in command:
                # Simulate the service being replaced by an unrelated container
                # using the same image digest after startup but before rollback.
                selected = (
                    "f" * 64 if self.failure == "replaced-same-image"
                    else CID
                )
                return CommandResult(0, selected if self.created else "", "")
            if "-q" in command:
                return CommandResult(0, CID if self.running else "", "")
            if "--status" in command:
                return CommandResult(
                    0, "[]" if not self.running else '[{"State":"running"}]',
                    "",
                )
            raise AssertionError("unreviewed ps query")
        if command[:1] == ("up",):
            assert command == (
                "up", "--detach", "--no-deps", "--no-recreate",
                "--no-build", "--pull", "never", "analytics-green",
            )
            self.created = True
            self.running = True
            if self.failure == "up-error":
                return CommandResult(1, "", "synthetic partial startup")
            return CommandResult(0, "", "")
        if command[:1] == ("exec",):
            assert command[:4] == ("exec", "--no-TTY", "analytics-green", "node")
            return CommandResult(
                0, "FAIL" if self.failure == "not-ready" else "READY\n", "",
            )
        if command[:1] == ("stop",):
            assert command == (
                "stop", "--timeout", "15", "analytics-green",
            )
            if self.failure == "stop-error":
                return CommandResult(1, "", "synthetic stop denial")
            self.running = False
            return CommandResult(0, "", "")
        raise AssertionError("unreviewed Docker operation")


# Section 2: every positive candidate must possess the real Task014
# canonical schema-3 request, a disposable authentic SSH Ed25519 owner signer,
# and a sealed scope bound to that exact successor request and OCI digest.
class AnalyticsSuccessorCandidateStageTests(unittest.TestCase):
    """First successor startup is not a route switch or public release."""

    def setUp(self):
        """Bind read-only Linux trust fixtures and a nonmutating Docker runner."""
        data, context = AnalyticsSuccessorRequestTests().candidate()
        self.request = parse_analytics_successor_request(
            canonical_bytes(data), **context,
        )
        self.raw = self.request.canonical_bytes()
        self.selected = context["selected"]
        self.runner = SyntheticGreenRunner(self.request.exact_image_reference)
        self.temp = tempfile.TemporaryDirectory(
            prefix="m05-14-green-candidate-",
        )
        self.addCleanup(self.temp.cleanup)
        # Section: future mutating image-pull tests must pass the complete
        # kernel-sealed three-JWT schema-2 FD, not the legacy read-only
        # one-token successor probe. Real JWT signatures are verified by
        # UID991's separate cryptographic admission, not this Docker fake.
        self.fd = make_full_successor_fd(
            self.raw, self.request.exact_image_reference,
        )
        self.addCleanup(os.close, self.fd)
        self.scope = ExitStack()
        self.addCleanup(self.scope.close)
        self.scope.enter_context(signed_owner_fixture(self.selected))
        self.scope.enter_context(
            patch("deployment.analytics_first_install.os.getuid",
                  return_value=991),
        )
        self.scope.enter_context(
            patch("deployment.analytics_first_install.os.geteuid",
                  return_value=991),
        )
        self.scope.enter_context(
            patch("deployment.analytics_first_install.os.getgid",
                  return_value=991),
        )
        self.scope.enter_context(
            patch("deployment.analytics_first_install.os.getegid",
                  return_value=991),
        )
        self.scope.enter_context(
            patch(
                "deployment.analytics_executor_service_config._SUCCESSOR_INSTALLED_ROOT",
                Path(__file__).resolve().parents[2],
            ),
        )
        self.scope.enter_context(
            patch("deployment.analytics_executor_service_config.load_analytics_executor_service_config",
                  return_value=(EXPECTED, {
                      "expected_executor_uid": 991,
                      "expected_executor_gid": 991,
                  })),
        )
        for package in (
            "deployment.analytics_first_install",
            "deployment.analytics_private_registry",
        ):
            self.scope.enter_context(
                patch(package + "._require_rootless_socket"),
            )
        self.scope.enter_context(
            patch("deployment.analytics_first_install.review_private_secret_paths",
                  return_value=(
                      "COLLECTOR_DATABASE_URL", "DATABASE_URL",
                      "JWT_REFRESH_SECRET", "JWT_SECRET",
                  )),
        )
        self.scope.enter_context(
            patch("deployment.analytics_first_install._require_mapped_secret_groups"),
        )
        self.scope.enter_context(
            patch("deployment.analytics_private_registry._private_runtime_directory",
                  return_value=Path(self.temp.name)),
        )
        self.scope.enter_context(
            patch("deployment.analytics_private_registry.time.time",
                  return_value=NOW),
        )
        self.scope.enter_context(
            patch("deployment.private_registry_fd.time.time",
                  return_value=NOW),
        )
        self.inspector = self.scope.enter_context(
            patch(
                "deployment.analytics_active_state_review.inspect_analytics_active_state",
                return_value=first_successor_empty_active_state(),
            ),
        )
        self.absent = self.scope.enter_context(
            patch(
                "deployment.analytics_active_state_review.verify_empty_analytics_successor_slot",
                return_value=None,
            ),
        )
        self.registry = AnalyticsPrivateZotPullAdapter(
            self.runner, reviewed_installed_source=EXPECTED,
        )
        self.operation = AnalyticsSuccessorCandidateOperation(
            runner=self.runner, private_registry=self.registry,
            reviewed_installed_source=EXPECTED,
        )

    def stage(self):
        """Call only the future handler's exact transient Zot capability."""
        with scoped_private_zot_request(self.fd, self.raw):
            return self.operation.stage_first_successor_green(self.request)

    def test_signed_green_starts_without_any_route_or_database_mutation(self):
        """Pull immutable OCI, check overlay, hardened runtime and readyz."""
        self.assertEqual(self.stage(), CID)
        self.assertTrue(self.runner.running)
        self.assertGreaterEqual(self.inspector.call_count, 3)
        self.assertGreaterEqual(self.absent.call_count, 2)
        self.assertIn(
            ("sealed-zot-pull", self.request.exact_image_reference),
            self.runner.calls,
        )
        local_checks = [
            entry[-1] for entry in self.runner.calls
            if entry and entry[0] == "compose" and "exec" in entry
        ]
        self.assertEqual(len(local_checks), 2)
        self.assertIn("/readyz", local_checks[0])
        self.assertIn("/livez", local_checks[1])
        self.assertEqual(
            len([a for a in self.runner.calls
                 if a and a[0] == "compose" and "up" in a]), 1,
        )
        self.assertFalse(any(
            "down" in a or "rm" in a or "--force-recreate" in a
            or "analytics-blue" in a or "canary" in a or "ports" in a
            for a in self.runner.calls
        ))
        self.assertFalse(any(
            a and a[0] == "compose" and "stop" in a
            for a in self.runner.calls
        ))
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_only_exact_signed_request_can_be_stopped(self):
        """Executor finalization rollback is bound to request and container."""
        self.assertEqual(self.stage(), CID)
        altered = replace(self.request, oidc_jti="unrelated-jti")
        with self.assertRaises(AnalyticsFirstInstallError):
            self.operation.rollback_staged_successor(altered, CID)
        self.assertTrue(self.runner.running)
        with self.assertRaises(AnalyticsFirstInstallError):
            self.operation.rollback_staged_successor(self.request, "f" * 64)
        self.assertTrue(self.runner.running)
        self.assertIsNone(
            self.operation.rollback_staged_successor(self.request, CID),
        )
        self.assertFalse(self.runner.running)

    def test_completed_rollback_stops_exact_id_not_compose_service_name(self):
        """A completed rollback cannot follow a mutable Compose name at stop."""
        self.assertEqual(self.stage(), CID)
        self.assertIsNone(
            self.operation.rollback_staged_successor(self.request, CID),
        )
        self.assertIn(("container", "stop", "--time", "15", CID),
                      self.runner.calls)
        self.assertFalse(any(
            a and a[0] == "compose" and "stop" in a
            for a in self.runner.calls
        ))

    def test_completed_rollback_failed_exact_stop_is_not_reported_success(self):
        """A failed exact-ID stop cannot consume completed rollback authority."""
        self.assertEqual(self.stage(), CID)
        self.runner.failure = "stop-error"
        with self.assertRaises(AnalyticsFirstInstallError):
            self.operation.rollback_staged_successor(self.request, CID)
        self.assertTrue(self.runner.running)
        self.assertFalse(any(
            a and a[0] == "compose" and "stop" in a
            for a in self.runner.calls
        ))

    def test_rollback_rejects_replaced_same_image_container_without_stop(self):
        """A new container ID is not the approved staged release identity."""
        self.assertEqual(self.stage(), CID)
        self.runner.failure = "replaced-same-image"
        with self.assertRaises(AnalyticsFirstInstallError):
            self.operation.rollback_staged_successor(self.request, CID)
        self.assertTrue(self.runner.running)
        self.assertFalse(any(
            a and a[0] == "compose" and "stop" in a
            for a in self.runner.calls
        ))

    def test_untrusted_principal_or_v1_generation_denied_before_docker(self):
        """Incorrect UID/GID and absent root-approved V2 never start anything."""
        with (
            patch("deployment.analytics_first_install.os.geteuid",
                  return_value=1000),
            self.assertRaises(AnalyticsFirstInstallError),
        ):
            self.stage()
        self.assertEqual(self.runner.calls, [])
        with (
            patch(
                "deployment.analytics_executor_service_config.load_analytics_executor_service_config",
                side_effect=PermissionError("no protected V2 source"),
            ),
            self.assertRaises(AnalyticsFirstInstallError),
        ):
            self.stage()
        self.assertEqual(self.runner.calls, [])

    def test_no_scoped_fd_or_other_release_identity_denies_before_pull(self):
        """Caller-created dataclass is insufficient without scoped Zot FD."""
        with self.assertRaises(AnalyticsFirstInstallError):
            self.operation.stage_first_successor_green(self.request)
        self.assertFalse(any(
            a[0] == "sealed-zot-pull" for a in self.runner.calls
        ))
        altered = replace(self.request, exact_image_reference="analytics:latest")
        with (
            scoped_private_zot_request(self.fd, self.raw),
            self.assertRaises(AnalyticsFirstInstallError),
        ):
            self.operation.stage_first_successor_green(altered)
        self.assertFalse(self.runner.created)

    def test_legacy_single_token_fd_cannot_stage_green(self):
        """Historical successor probe token is never an image-pull grant."""
        old = create_sealed_credential(
            TOKEN, expires_at=NOW + 270,
            image=self.request.exact_image_reference,
            canonical_request=self.raw,
            product_id="analytics-successor", now=NOW,
        )
        try:
            with (
                scoped_private_zot_request(old, self.raw),
                self.assertRaises(AnalyticsFirstInstallError),
            ):
                self.operation.stage_first_successor_green(self.request)
            self.assertFalse(self.runner.created)
            self.assertFalse(any(
                "up" in call or "sealed-zot-pull" in call
                for call in self.runner.calls
            ))
        finally:
            os.close(old)

    def test_existing_green_denies_without_pulling_or_overwriting(self):
        """A stopped or unknown candidate is not adopted by --no-recreate."""
        self.runner.failure = "occupied"
        with self.assertRaises(AnalyticsFirstInstallError):
            self.stage()
        self.assertFalse(self.runner.created)
        self.assertFalse(any(
            a[0] == "sealed-zot-pull" for a in self.runner.calls
        ))

    def test_real_owner_signature_is_mandatory_before_first_docker_read(self):
        """Neither a valid dataclass nor a sealed FD substitutes for owner trust."""
        from deployment import analytics_executor as executor
        with (
            patch.object(
                executor, "_OWNER_APPROVAL_FILE",
                Path(self.temp.name) / "missing-owner-approval.json",
            ),
            self.assertRaises(AnalyticsFirstInstallError),
        ):
            self.stage()
        self.assertEqual(self.runner.calls, [])

    def test_expired_global_budget_stops_partial_green_with_cleanup_reserve(self):
        """After up, 570s stage timeout still leaves independent stop budget."""
        object.__setattr__(
            self.operation, "_clock",
            lambda: 600.0 if self.runner.created else 0.0,
        )
        with self.assertRaises(AnalyticsFirstInstallError):
            self.stage()
        self.assertTrue(self.runner.created)
        self.assertFalse(self.runner.running)
        self.assertEqual(
            len([a for a in self.runner.calls
                 if a and a[0] == "compose" and "stop" in a]), 1,
        )
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_invalid_rollback_id_type_is_denied_without_docker(self):
        """Type confusion cannot emit raw TypeError or stop another service."""
        self.assertEqual(self.stage(), CID)
        before = len(self.runner.calls)
        for invalid in (None, 1, True, {}, [], "invalid"):
            with self.subTest(value=invalid):
                with self.assertRaises(AnalyticsFirstInstallError):
                    self.operation.rollback_staged_successor(self.request, invalid)
                self.assertTrue(self.runner.running)
        self.assertEqual(len(self.runner.calls), before)

    def test_network_must_be_same_internal_bridge_and_distinct_private_ip(self):
        """No public replacement network or wrong Docker bridge may host green."""
        for failure in ("wrong-network", "public-network", "shared-IP"):
            with self.subTest(failure=failure):
                self.runner = SyntheticGreenRunner(
                    self.request.exact_image_reference, failure=failure,
                )
                self.registry = AnalyticsPrivateZotPullAdapter(
                    self.runner, reviewed_installed_source=EXPECTED,
                )
                self.operation = AnalyticsSuccessorCandidateOperation(
                    runner=self.runner, private_registry=self.registry,
                    reviewed_installed_source=EXPECTED,
                )
                with self.assertRaises(AnalyticsFirstInstallError):
                    self.stage()
                if failure != "shared-IP":
                    self.assertFalse(self.runner.created)
                else:
                    self.assertTrue(self.runner.created)
                    self.assertFalse(self.runner.running)

    def test_mismatched_installed_source_root_rejected_before_docker(self):
        """Even a valid signed config cannot authorize using dev worktree YAML."""
        from deployment import analytics_executor_service_config as config
        with (
            patch.object(config, "_SUCCESSOR_INSTALLED_ROOT",
                         Path("/opt/unreviewed-deployment")),
            self.assertRaises(AnalyticsFirstInstallError),
        ):
            self.stage()
        self.assertEqual(self.runner.calls, [])

    def test_wrong_local_digest_rejected_before_candidate_start(self):
        """A mismatched local RepoDigest does not become runtime authority."""
        self.runner.failure = "wrong-repodigest"
        with self.assertRaises(AnalyticsFirstInstallError):
            self.stage()
        self.assertFalse(self.runner.created)
        self.assertFalse(self.runner.running)

    def test_partial_up_and_public_bind_and_unhealthy_are_stopped(self):
        """Every untrusted candidate failure is stop-only, never Compose down."""
        for failure in ("up-error", "public-port", "unhealthy", "not-ready"):
            with self.subTest(failure=failure):
                self.runner = SyntheticGreenRunner(
                    self.request.exact_image_reference, failure=failure,
                )
                self.registry = AnalyticsPrivateZotPullAdapter(
                    self.runner, reviewed_installed_source=EXPECTED,
                )
                self.operation = AnalyticsSuccessorCandidateOperation(
                    runner=self.runner, private_registry=self.registry,
                    reviewed_installed_source=EXPECTED,
                )
                with self.assertRaises(AnalyticsFirstInstallError):
                    self.stage()
                self.assertTrue(self.runner.created)
                self.assertFalse(self.runner.running)
                self.assertEqual(
                    len([a for a in self.runner.calls
                         if a and a[0] == "compose" and "stop" in a]),
                    1,
                )
                self.assertFalse(any(
                    "down" in a or "rm" in a or "analytics-blue" in a
                    for a in self.runner.calls
                ))


if __name__ == "__main__":
    unittest.main()
