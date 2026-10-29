"""File: deployment/tests/test_analytics_broker_service.py

Purpose: Validate the one-root-owned Analytics broker opt-in using Task014
         original C32H service configuration, exact code identity and the
         existing canary HTTP ingress without a second service.
Related: deployment/analytics_broker_service.py,
         deployment/analytics_broker_router.py,
         deployment/broker_service_bootstrap.py,
         deployment/analytics_executor_service_config.py,
         deployment/tests/test_analytics_broker_router.py.

Sections: exact real class composition, original root config missing/present,
          malformed root config denial, file-descriptor cleanup and strict
          canary-only service fallback.

All root-owned filesystem metadata is simulated; no host privilege, HTTP
socket, credential, Docker/PG mutation or live registry is required.
"""
from __future__ import annotations

import os
import stat
import unittest
from unittest.mock import patch

from deployment import analytics_broker_service as broker_service
from deployment import broker_service_config_loader as original_loader
from deployment.analytics_broker_router import AnalyticsDEVPromotionRouter
from deployment.analytics_executor_service_config import (
    ANALYTICS_INSTALLED_FILES,
)
from deployment.blob_verifier import CosignReleaseBlobVerifier
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.jwks import GitHubJWKSCache
from deployment.oidc_verifier import GitHubOIDCVerifier
from deployment.registry_promotion_composition import compose_inert_dev_promotion_handler
from deployment.replay_sqlite import PRODUCTION_REPLAY_DATABASE, SQLiteReplayGuard
from deployment.tests.test_analytics_execution import EXPECTED
from deployment.tests.test_broker_service_config import configuration_values
from deployment.unix_transport import UnixExecutorTransport
from deployment.policy import canonical_bytes


def approved_configuration() -> DevBrokerServiceConfiguration:
    """Construct the original closed C32H config matching signed source."""
    return DevBrokerServiceConfiguration(**configuration_values(
        reviewed_commit=EXPECTED["reviewed_installed_commit"],
    ))


class OriginalBrokerCompositionTests(unittest.TestCase):
    """No dynamic canary route or second shared identity store is introduced."""

    def test_real_original_broker_and_analytics_share_security_collaborators(self):
        """Actual original inert classes compose without any filesystem I/O."""
        config = approved_configuration()
        cache = GitHubJWKSCache()
        verifier = GitHubOIDCVerifier(
            expected_workflow_sha=config.expected_workflow_sha, jwks_cache=cache,
        )
        blob = CosignReleaseBlobVerifier(**config.blob_verifier_kwargs())
        ids = config.installation_contract().broker_composition_kwargs()
        replay = SQLiteReplayGuard(
            PRODUCTION_REPLAY_DATABASE,
            expected_directory_uid=ids["expected_replay_directory_uid"],
            expected_directory_gid=ids["expected_replay_directory_gid"],
            expected_broker_uid=ids["expected_broker_uid"],
            expected_executor_uid=ids["expected_executor_uid"],
        )
        original = compose_inert_dev_promotion_handler(
            configuration=config, verifier=verifier, replay_guard=replay,
            transport=UnixExecutorTransport(
                expected_executor_uid=ids["expected_executor_uid"],
                expected_executor_gid=ids["expected_executor_gid"],
                expected_socket_group_gid=ids["expected_socket_group_gid"],
            ), blob_signatures=blob, jwks_cache=cache,
            private_registry_transport=True,
        )
        selected = broker_service.compose_approved_analytics_broker_router(
            configuration=config, canary_handler=original,
            verifier=verifier, replay_guard=replay,
            blob_signatures=blob, jwks_cache=cache,
            reviewed_installed_source=EXPECTED,
        )
        self.assertIs(type(selected), AnalyticsDEVPromotionRouter)
        self.assertIs(
            object.__getattribute__(selected, "_canary").__self__, original,
        )
        analytics = object.__getattribute__(selected, "_analytics").__self__
        self.assertIs(
            object.__getattribute__(analytics, "_replay").__self__, replay,
        )
        self.assertIs(
            object.__getattribute__(analytics, "_verify").__self__, verifier,
        )
        self.assertIs(
            object.__getattribute__(analytics, "_transport").__self__.__class__,
            __import__("deployment.analytics_unix_boundary",
                       fromlist=["AnalyticsUnixExecutorTransport"]).AnalyticsUnixExecutorTransport,
        )

    def test_wrong_original_broker_source_cannot_construct_analytics_router(self):
        """A public mapping, fake JWKS, or wrong executable source is no grant."""
        with self.assertRaises(TypeError):
            broker_service.compose_approved_analytics_broker_router(
                configuration=approved_configuration(),
                canary_handler=object(), verifier=object(),
                replay_guard=object(), blob_signatures=object(),
                jwks_cache=object(), reviewed_installed_source=EXPECTED,
            )


class OriginalRootOwnedOptInTests(unittest.TestCase):
    """Exact protected root and broker GID must precede product routing."""

    def setUp(self):
        """Build original virtual UID/GID and one 0640 root-owned config inode."""
        self.cfg = approved_configuration()
        self.raw = canonical_bytes({
            "schema_version": 1, "product_id": "analytics", "stage": "dev",
            **EXPECTED,
            "source_sha256": {name: "a" * 64
                              for name in ANALYTICS_INSTALLED_FILES},
        })
        self.file_stat = os.stat_result((
            stat.S_IFREG | 0o640, 123, 456, 1, 0,
            self.cfg.broker_gid, len(self.raw), 1, 2, 3,
        ))
        self.directory_stat = (
            stat.S_IFDIR | 0o750, 321, 654, 2, 0,
            self.cfg.broker_gid, 0, 1, 2,
        )
        identities = self.cfg.installation_contract().broker_required_group_gids
        self.identity = (
            self.cfg.broker_uid, self.cfg.broker_uid, self.cfg.broker_gid,
            self.cfg.broker_gid, list(identities),
        )

    def preflight(self, *, absent=False, wrong_owner=False):
        """Patch descriptor I/O only; no live root path is opened."""
        from contextlib import ExitStack
        st = self.file_stat
        if wrong_owner:
            parts = list(st)
            parts[4] = self.cfg.broker_uid
            st = os.stat_result(parts)
        stack = ExitStack()
        patches = (
            (original_loader, "_process_identity", self.identity),
            (original_loader, "_required_flags", (0, 0)),
            (original_loader, "_open_directories", ([], 77)),
            (original_loader, "_revalidate_directories", self.directory_stat),
            (original_loader, "_close_owned", (False, None)),
            (original_loader, "_claim_descriptor", 55),
            (original_loader, "_bounded_read", self.raw),
        )
        for module, name, value in patches:
            stack.enter_context(patch.object(module, name, return_value=value))
        def validated_fake_file(info):
            """Keep original 0640 root-owner policy without fake ns timestamps."""
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o640
                    or info.st_nlink != 1):
                raise OSError("invalid synthetic owner or mode")
            return (*tuple(info)[:7], 100, 200)

        stack.enter_context(patch.object(
            original_loader, "_configuration_file", side_effect=validated_fake_file,
        ))
        stack.enter_context(patch.object(
            broker_service.os, "stat",
            side_effect=(FileNotFoundError(2, "not found") if absent else None),
            return_value=None if absent else st,
        ))
        stack.enter_context(patch.object(
            broker_service.os, "open", return_value=55,
        ))
        stack.enter_context(patch.object(
            broker_service.os, "fstat", return_value=st,
        ))
        verify = stack.enter_context(patch.object(
            broker_service, "_verify_source_bytes", return_value=None,
        ))
        return stack, verify

    def test_missing_root_product_conf_returns_original_canary_only(self):
        """Missing config is not a permission to start or admit Analytics."""
        stack, verified = self.preflight(absent=True)
        with stack:
            self.assertIsNone(
                broker_service.load_analytics_broker_installed_source(self.cfg),
            )
        verified.assert_not_called()

    def test_present_root_owned_sha_bound_conf_yields_only_four_hashes(self):
        """Exact source proof checks 16 Python modules, Compose and profiles."""
        stack, verified = self.preflight()
        with stack:
            result = broker_service.load_analytics_broker_installed_source(self.cfg)
        self.assertEqual(result, EXPECTED)
        verified.assert_called_once()
        names = tuple(name for name, _digest in verified.call_args.args[0])
        self.assertEqual(names[:len(ANALYTICS_INSTALLED_FILES)], ANALYTICS_INSTALLED_FILES)
        self.assertEqual(names[-3:], (
            "deployment/products/analytics-dev.json",
            "deployment/products/analytics-runtime-dev.json",
            "deployment/runtime/dev/analytics.compose.review.yaml",
        ))

    def test_wrong_owner_or_wrong_platform_commit_fails_closed(self):
        """A present wrong file must never silently become canary-only."""
        stack, verified = self.preflight(wrong_owner=True)
        with stack, self.assertRaises(broker_service.AnalyticsBrokerSourceError):
            broker_service.load_analytics_broker_installed_source(self.cfg)
        verified.assert_not_called()
        stack, verified = self.preflight()
        with stack, patch.object(
            broker_service, "parse_analytics_executor_service_config",
            return_value={
                **EXPECTED, "reviewed_installed_commit": "b" * 40,
                "source_sha256": tuple(),
            },
        ), self.assertRaises(broker_service.AnalyticsBrokerSourceError):
            broker_service.load_analytics_broker_installed_source(self.cfg)
        verified.assert_not_called()

    def test_source_verifier_failure_is_no_broker_grant(self):
        """No signed source means zero credential processing or listener."""
        stack, _verified = self.preflight()
        with stack, patch.object(
            broker_service, "_verify_source_bytes",
            side_effect=PermissionError("host files changed"),
        ), self.assertRaises(broker_service.AnalyticsBrokerSourceError):
            broker_service.load_analytics_broker_installed_source(self.cfg)


class ApprovedReplacementServiceTests(unittest.TestCase):
    """Actual original classes behind fake source, no network or systemd."""

    def test_optional_root_approved_service_reuses_canary_port_and_identity(self):
        """One original canary+Analytics router and original replay/JWKS cache."""
        from deployment.broker_loopback_listener import BrokerStopController
        from deployment.replay_sqlite import SQLiteReplayGuard
        from deployment import broker_service_bootstrap as original
        selected = []
        config = approved_configuration()

        class RecordingOriginalListener:
            """Never bind; only inspect existing loopback controller args."""

            def __init__(self, handler):
                selected.append(("listener", handler))

            def serve_until_stopped(self, stop_controller):
                """Record original stop handling without opening port3031."""
                self.assert_no_call = stop_controller
                selected.append(("serve", stop_controller))

        stopper = BrokerStopController()
        with (
            patch.object(original, "_load_configuration", return_value=config),
            patch.object(
                broker_service, "load_analytics_broker_installed_source",
                return_value=dict(EXPECTED),
            ) as source,
            patch.object(SQLiteReplayGuard, "validate", return_value=None),
            patch.object(
                original, "_DevBrokerLoopbackListener",
                RecordingOriginalListener,
            ),
        ):
            self.assertIsNone(
                broker_service.run_approved_analytics_broker_service(
                    stop_controller=stopper,
                )
            )
        source.assert_called_once_with(config)
        self.assertEqual([v[0] for v in selected], ["listener", "serve"])
        router = selected[0][1]
        self.assertIs(type(router), AnalyticsDEVPromotionRouter)
        self.assertIs(selected[1][1], stopper)

    def test_missing_or_bad_root_owned_source_never_builds_listener(self):
        """A configured Analytics replacement service never downgrades to canary."""
        from deployment.broker_loopback_listener import BrokerStopController
        from deployment import broker_service_bootstrap as original
        stopper = BrokerStopController()
        for fail in (None, {}, broker_service.AnalyticsBrokerSourceError("deny")):
            mocked = (
                {"side_effect": fail}
                if isinstance(fail, Exception) else {"return_value": fail}
            )
            with (
                patch.object(original, "_load_configuration",
                             return_value=approved_configuration()),
                patch.object(
                    broker_service, "load_analytics_broker_installed_source",
                    **mocked,
                ),
                patch.object(
                    original, "_DevBrokerLoopbackListener",
                    side_effect=AssertionError("unverified source cannot listen"),
                ),
                self.subTest(case=type(fail).__name__),
                self.assertRaises(broker_service.AnalyticsBrokerSourceError),
            ):
                broker_service.run_approved_analytics_broker_service(
                    stop_controller=stopper,
                )

    def test_no_accidental_process_start_or_unreviewed_stop_controller(self):
        """A review helper cannot install a service or substitute a handler."""
        with self.assertRaises(broker_service.AnalyticsBrokerSourceError):
            broker_service.run_approved_analytics_broker_service(
                stop_controller=object(),
            )

    def test_dropin_only_substitutes_existing_service_not_new_port(self):
        """The future systemd override is inert and has one exact ExecStart."""
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        content = (
            root / "deployment/systemd/dev/analytics-broker-enabled.conf"
        ).read_text()
        self.assertIn(
            "ConditionPathExists=/etc/omnilyzer/deployment/broker/analytics.json",
            content,
        )
        self.assertIn("[Service]\nExecStart=\nExecStart=/opt/omnilyzer/deployment/venv/bin/python -m deployment.analytics_broker_service_entrypoint", content)
        self.assertNotIn("ListenStream=", content)
        self.assertNotIn("3032", content)
        self.assertEqual(content.count("ExecStart="), 2)
        self.assertEqual(content.count("ConditionPathExists="), 1)

    def test_entrypoint_reuses_original_graceful_stop_and_handles_failure(self):
        """Original SIGTERM/SIGINT stop, restore and nonzero error status."""
        from deployment import analytics_broker_service_entrypoint as entry
        from deployment.broker_loopback_listener import BrokerStopController
        state = {}

        def original_signal(signum, handler):
            """Capture only request_stop, no actual OS signal registration."""
            old = state.get(signum, f"original-{signum}")
            state[signum] = handler
            return old

        def check_stop(*, stop_controller):
            """Original lifecycle only, no extra port or background worker."""
            self.assertIs(type(stop_controller), BrokerStopController)
            state[15](15, None)
            self.assertTrue(stop_controller.is_stopping())

        with patch.object(entry.signal, "signal", side_effect=original_signal), patch.object(
            entry, "run_approved_analytics_broker_service", side_effect=check_stop,
        ):
            self.assertEqual(entry.main(), 0)
        with patch.object(entry.signal, "signal", side_effect=original_signal), patch.object(
            entry, "run_approved_analytics_broker_service",
            side_effect=broker_service.AnalyticsBrokerSourceError("denied"),
        ):
            self.assertEqual(entry.main(), 1)


if __name__ == "__main__":
    unittest.main()
