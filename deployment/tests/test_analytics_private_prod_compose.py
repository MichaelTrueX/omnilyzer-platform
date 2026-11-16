"""File: deployment/tests/test_analytics_private_prod_compose.py

Purpose: Enforce the first private Analytics PROD runtime boundary without
         starting Docker, touching secrets or requiring production privileges.
Related: deployment/runtime/prod/analytics.compose.private.yaml,
         deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/analytics_prod_rootless_bootstrap.py,
         docs/operations/dev-prod-direct-delivery.md.

Sections: canonical source binding, private runtime/security, database socket
          and product isolation, first-slot-only safety, no live mutation.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest

COMPOSE = (
    Path(__file__).resolve().parents[1]
    / "runtime/prod/analytics.compose.private.yaml"
)


class AnalyticsPrivateProdComposeTests(unittest.TestCase):
    """Check source-level invariants; actual Compose parsing is separate."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load only the committed inert first-slot runtime source."""
        cls.source = COMPOSE.read_text(encoding="utf-8")

    def test_release_requires_external_signed_digest(self) -> None:
        """Do not hard-code a tag, synthetic image or DEV image identity."""
        self.assertIn(
            "${ANALYTICS_PROD_IMAGE:?original signed 0.16.0 OCI digest required}",
            self.source,
        )
        self.assertNotIn("latest", self.source)
        self.assertNotIn("image: node:", self.source)

    def test_loopback_only_first_blue_slot(self) -> None:
        """No public listener, concurrent green or second server."""
        self.assertIn('name: omnilyzer-analytics-prod', self.source)
        self.assertIn('profiles: ["blue"]', self.source)
        self.assertEqual(self.source.count("127.0.0.1:3141:3000"), 1)
        self.assertNotIn("0.0.0.0:3141", self.source)
        self.assertNotIn("3142:3000", self.source)
        self.assertNotIn("analytics-green:", self.source)
        self.assertNotIn("server_name:", self.source)

    def test_rootless_hardening_and_production_memory_cap(self) -> None:
        """Retain accepted DEV rootless controls and bound no-swap PROD memory."""
        for phrase in (
            'user: "10001:10001"', "read_only: true", "cap_drop:",
            "- ALL", "no-new-privileges:true", "pids_limit: 192",
            'cpus: "1.00"', "mem_limit: 768m",
            'restart: "no"', 'NODE_OPTIONS: "--max-old-space-size=512"',
            'max-size: 10m', "max-file:",
        ):
            self.assertIn(phrase, self.source)

    def test_existing_pg_socket_not_new_tcp_listener(self) -> None:
        """Reuse host PG16 locally; separate role/HBA acceptance is still required."""
        for phrase in (
            "source: /var/run/postgresql",
            "target: /var/run/postgresql",
            "read_only: true",
            "create_host_path: false",
        ):
            self.assertIn(phrase, self.source)
        self.assertNotIn("5432:5432", self.source)
        self.assertNotIn("host.docker.internal", self.source)

    def test_prod_only_secret_names_and_network(self) -> None:
        """Four mapped files and a separate pre-existing network are mandatory."""
        for name in (
            "COLLECTOR_DATABASE_URL", "DATABASE_URL",
            "JWT_REFRESH_SECRET", "JWT_SECRET",
        ):
            self.assertIn(
                "/var/lib/omnilyzer/analytics/prod/secrets/" + name,
                self.source,
            )
        self.assertIn("name: omnilyzer-analytics-backend-prod", self.source)
        self.assertIn("external: true", self.source)
        self.assertNotIn("/analytics/dev/", self.source)
        self.assertNotIn("omnilyzer-analytics-backend-dev", self.source)

    def test_no_broad_runtime_configuration_or_credentials(self) -> None:
        """No insecure shortcuts, baked credentials or rootless socket exports."""
        denied = (
            "privileged: true", "network_mode: host", "pid: host",
            "user: root", "build:", "docker.sock", "password:",
            "POSTGRES_PASSWORD:", "container_name:", "staging",
        )
        for phrase in denied:
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, self.source)
        self.assertEqual(
            len(re.findall(r"^    - source: PROD_", self.source, re.M)), 4
        )


if __name__ == "__main__":
    unittest.main()
