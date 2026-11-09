"""File: deployment/tests/test_analytics_executor_socket_visibility.py

Purpose: Focused source-only regression for Task014's positive UID991 executor
         mount isolation and the immutable Analytics read-only socket observer.
Related: deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service,
         deployment/analytics_active_state_review.py, Issue #281.
Safety: Static checks only. Never invokes systemd, Docker, sockets, OIDC,
        replay, signing, application routes or the private registry.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


# Section 1: locate only the checked-out first-party existing source files.
DEPLOYMENT = Path(__file__).resolve().parents[1]
SERVICE = DEPLOYMENT / "systemd/dev/omnilyzer-deployment-analytics-executor.service"
OBSERVER = DEPLOYMENT / "analytics_active_state_review.py"


def exact_constant(name: str) -> str:
    """Read a fixed socket address from the original first-party Python AST."""
    tree = ast.parse(OBSERVER.read_text(encoding="utf-8"))
    matches = (
        stmt.value.value
        for stmt in tree.body
        if isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and stmt.targets[0].id == name
        and isinstance(stmt.value, ast.Constant)
        and type(stmt.value.value) is str
    )
    result = list(matches)
    if len(result) != 1:
        raise AssertionError("missing exact original socket constant")
    return result[0]


# Section 2: preserve original isolation and expose only the required sockets.
class AnalyticsExecutorSocketVisibilityTests(unittest.TestCase):
    """Reject a source change that hides or overexposes rootless UID991 APIs."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read only the exact, already version-controlled executor unit."""
        cls.lines = SERVICE.read_text(encoding="utf-8").splitlines()
        cls.properties = [line.strip() for line in cls.lines
                          if line.strip() and not line.lstrip().startswith("#")]

    def test_protected_home_remains_hidden_without_weak_readonly_mode(self) -> None:
        """ProtectHome tmpfs hides user homes while supporting fixed bind paths."""
        self.assertEqual(
            [line for line in self.properties if line.startswith("ProtectHome=")],
            ["ProtectHome=tmpfs"],
        )
        for critical in (
            "User=omnilyzer-executor",
            "Group=omnilyzer-executor",
            "SupplementaryGroups=omnilyzer-replay",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectSystem=strict",
            "RestrictNamespaces=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "Restart=no",
        ):
            self.assertIn(critical, self.properties)

    def test_exact_only_fixed_uid991_socket_bind_targets(self) -> None:
        """No /run/user tree, wildcard directory or caller selected IPC scope."""
        docker = exact_constant("_DOCKER")
        rootless = exact_constant("_ROOTLESS")
        self.assertEqual(docker, "/run/user/991/docker.sock")
        self.assertEqual(rootless, "/run/user/991/dockerd-rootless/api.sock")
        binds = [
            line.removeprefix("BindReadOnlyPaths=")
            for line in self.properties
            if line.startswith("BindReadOnlyPaths=")
        ]
        self.assertCountEqual(binds, [
            docker + ":/run/omnilyzer/deployment/rootless-docker/docker.sock",
            docker + ":" + docker,
            rootless + ":" + rootless,
        ])
        self.assertFalse(any(
            "/run/user/991:" in item
            or "/run/user:" in item
            or "BindPaths=" in item
            for item in self.properties
        ))

    def test_no_change_to_signed_replay_or_original_executor_entrypoint(self) -> None:
        """Stay inside existing product-specific Task014 without new routes."""
        for critical in (
            "Requires=omnilyzer-deployment-analytics-executor.socket",
            "WorkingDirectory=/opt/omnilyzer/deployment/analytics-app",
            "ExecStart=/opt/omnilyzer/deployment/venv/bin/python -m deployment.analytics_executor_service_entrypoint",
            "ReadWritePaths=/var/lib/omnilyzer/deployment",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        ):
            self.assertIn(critical, self.properties)


if __name__ == "__main__":
    unittest.main()
