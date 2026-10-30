"""File: deployment/tests/test_analytics_executor_composition.py

Purpose: Verify one exact Analytics-only original Task014 executor composition
         and unchanged installed canary source/route with no host activation.

Related: deployment/analytics_executor_composition.py,
         deployment/analytics_unix_boundary.py,
         deployment/analytics_private_registry.py,
         deployment/analytics_first_install.py,
         deployment/application_source_set.py,
         deployment/executor_composition.py,
         deployment/tests/test_analytics_unix_boundary.py.

Sections: inert source-constrained graph; immutable collaborators and precise
          original shared SQLite replay path; wrong roots/route; actual one-shot
          Linux socket test remains in test_analytics_unix_boundary.py.

NO external Docker, registry, PostgreSQL, systemd activation or real secrets.
"""
from __future__ import annotations

import os
import socket
import unittest
from unittest.mock import patch

from deployment.analytics_executor_composition import AnalyticsExecutorComposition
from deployment.analytics_unix_boundary import (
    ANALYTICS_EXECUTOR_SOCKET_PATH,
    AnalyticsUnixExecutorListener,
    AnalyticsUnixExecutorConnectionHandler,
)
from deployment.analytics_executor import AnalyticsPrivilegedExecutor
from deployment.analytics_first_install import AnalyticsFirstInstallOperation
from deployment.analytics_private_registry import AnalyticsPrivateZotPullAdapter
from deployment.application_source_set import DevApplicationSourceSet
from deployment.executor_listener import PRODUCTION_EXECUTOR_SOCKET_PATH
from deployment.replay_sqlite import PRODUCTION_REPLAY_DATABASE
from deployment.tests.test_analytics_execution import EXPECTED


def composition(listener: object, *, source: dict[str, str] | None = None):
    """Bind original Task014 numeric host roles, distinct broker/executor UIDs."""
    return AnalyticsExecutorComposition(
        listener=listener, reviewed_installed_source=EXPECTED if source is None else source,
        expected_replay_directory_uid=991, expected_replay_directory_gid=991,
        expected_broker_uid=990, expected_broker_gid=990,
        expected_executor_uid=991, expected_executor_gid=991,
        expected_socket_owner_uid=991, expected_socket_group_gid=993,
    )


class AnalyticsExecutorCompositionTests(unittest.TestCase):
    """Task014 production canary remains untouched by this inert composition."""

    def test_original_executable_graph_is_product_only_and_inert(self):
        """Capture actual class types and original replay with zero host I/O."""
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)

        # No subprocess, network or host secrets may be accessed in constructor.
        with (
            patch("deployment.analytics_first_install._require_rootless_socket",
                  side_effect=AssertionError("docker in constructor")),
            patch("deployment.analytics_private_registry._require_rootless_socket",
                  side_effect=AssertionError("registry in constructor")),
            patch("deployment.analytics_first_install.review_private_secret_paths",
                  side_effect=AssertionError("secrets in constructor")),
            patch("deployment.replay_sqlite.sqlite3.connect",
                  side_effect=AssertionError("SQLite in constructor")),
        ):
            composed = composition(listener)
        serve = object.__getattribute__(composed, "_serve_once")
        secured = serve.__self__
        self.assertIs(type(secured), AnalyticsUnixExecutorListener)
        config = object.__getattribute__(secured, "_configuration")
        self.assertEqual(config[26], ANALYTICS_EXECUTOR_SOCKET_PATH)
        self.assertNotEqual(config[26], PRODUCTION_EXECUTOR_SOCKET_PATH)
        handler = config[1].__self__
        self.assertIs(type(handler), AnalyticsUnixExecutorConnectionHandler)
        backend = object.__getattribute__(handler, "_configuration")[0].__self__
        self.assertIs(type(backend), AnalyticsPrivilegedExecutor)
        deploy = object.__getattribute__(backend, "_deploy").__self__
        self.assertIs(type(deploy), AnalyticsFirstInstallOperation)
        private = object.__getattribute__(backend, "_preflight").__self__
        self.assertIs(type(private), AnalyticsPrivateZotPullAdapter)
        self.assertIs(
            object.__getattribute__(deploy, "_pull").__self__, private,
        )
        begin = object.__getattribute__(backend, "_replay")[0]
        self.assertEqual(
            object.__getattribute__(begin.__self__, "_path"),
            PRODUCTION_REPLAY_DATABASE,
        )

    def test_source_identity_is_strict_and_canary_cannot_substitute(self):
        """Prevent non-reviewed source/profile/hash and source path injection."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        bad = (
            {**EXPECTED, "reviewed_compose_sha256": "a" * 63},
            {**EXPECTED, "extra": "a" * 64},
            {**EXPECTED, "reviewed_installed_commit": "0" * 40},
        )
        for source in bad:
            with self.subTest(source=source), self.assertRaises(TypeError):
                composition(sock, source=source)

    def test_exact_original_fd_path_remains_uninstalled(self):
        """Review-only Python source cannot bypass protected source allowlist."""
        reviewed = {item.repository_path for item in DevApplicationSourceSet().files}
        for path in (
            "deployment/analytics_executor.py",
            "deployment/analytics_executor_composition.py",
            "deployment/analytics_unix_boundary.py",
            "deployment/analytics_first_install.py",
            "deployment/analytics_promotion_broker.py",
            "deployment/analytics_private_registry.py",
        ):
            self.assertNotIn(path, reviewed)
        self.assertIn("deployment/executor_composition.py", reviewed)
        self.assertIn("deployment/unix_transport.py", reviewed)

    def test_original_socket_path_remains_canary_only(self):
        """No canary alias or chosen product socket can enter composition."""
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        original = composition(listener)
        with self.assertRaises(AttributeError):
            original._serve_once = lambda: None
        with self.assertRaises(AttributeError):
            del original._serve_once
        self.assertEqual(
            object.__getattribute__(
                object.__getattribute__(original, "_serve_once").__self__,
                "_configuration",
            )[26], ANALYTICS_EXECUTOR_SOCKET_PATH,
        )

    def test_bogus_listener_rejected_without_fallback(self):
        """The original kernel-bound listener requires a real closed API."""
        with self.assertRaises(TypeError):
            composition(object())


if __name__ == "__main__":
    unittest.main()
