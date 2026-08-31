"""Static configuration and repository-boundary evidence for Task 010."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


SPIKE = Path(__file__).resolve().parents[1]
REPOSITORY = SPIKE.parents[1]
COMPOSE_PATH = SPIKE / "compose.yaml"
PROMETHEUS_PATH = SPIKE / "prometheus" / "prometheus.yml"


class ConfigurationPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        result = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_PATH), "config", "--format", "json"],
            cwd=REPOSITORY, text=True, capture_output=True, check=True,
        )
        cls.compose = json.loads(result.stdout)
        cls.compose_text = COMPOSE_PATH.read_text(encoding="utf-8")
        cls.prometheus_text = PROMETHEUS_PATH.read_text(encoding="utf-8")

    def test_prometheus_image_is_version_and_digest_pinned(self) -> None:
        image = self.compose["services"]["prometheus"]["image"]
        self.assertEqual(image, "prom/prometheus:v3.14.0@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0")
        self.assertNotIn("latest", image)

    def test_targets_have_no_host_ports_and_only_private_network(self) -> None:
        for name in ("target-alpha", "target-beta", "target-flaky"):
            service = self.compose["services"][name]
            self.assertFalse(service.get("ports"))
            self.assertEqual(set(service["networks"]), {"metrics-internal"})
        self.assertTrue(self.compose["networks"]["metrics-internal"]["internal"])

    def test_prometheus_api_is_loopback_only(self) -> None:
        ports = self.compose["services"]["prometheus"]["ports"]
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["host_ip"], "127.0.0.1")

    def test_scrape_bounds_are_explicit_and_ordered(self) -> None:
        self.assertIn("scrape_interval: 1s", self.prometheus_text)
        self.assertIn("scrape_timeout: 500ms", self.prometheus_text)
        self.assertLess(0.5, 1.0)

    def test_exact_three_private_targets(self) -> None:
        for target in ("target-alpha:8000", "target-beta:8000", "target-flaky:8000"):
            self.assertIn(target, self.prometheus_text)
        self.assertEqual(self.prometheus_text.count(":8000"), 3)

    def test_no_remote_write_or_unneeded_admin_lifecycle_flags(self) -> None:
        combined = self.compose_text + self.prometheus_text
        for forbidden in ("remote_write", "web.enable-admin-api", "web.enable-lifecycle"):
            self.assertNotIn(forbidden, combined)

    def test_no_credentials_or_real_endpoints(self) -> None:
        combined = self.compose_text + self.prometheus_text
        for forbidden in ("password", "api_key", "bearer_token", "omnilyzer.ai", "cloudsmith"):
            self.assertNotIn(forbidden.lower(), combined.lower())

    def test_no_out_of_scope_monitoring_components(self) -> None:
        services = set(self.compose["services"])
        self.assertFalse(services & {"grafana", "loki", "tempo", "jaeger", "alloy", "alertmanager", "thanos", "mimir", "victoriametrics"})

    def test_containers_are_hardened(self) -> None:
        for service in self.compose["services"].values():
            self.assertTrue(service["read_only"])
            self.assertIn("ALL", service["cap_drop"])
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertNotEqual(service["user"], "0")

    def test_fixture_dependency_is_exact_and_hash_verified(self) -> None:
        requirements = (SPIKE / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("prometheus-client==0.26.0", requirements)
        self.assertIn("sha256:fa93d06737aa02bacd05794768508bb97d2fbee28cb3bca04eaae92f0ca953d6", requirements)

    def test_target_image_context_is_allowlisted(self) -> None:
        dockerignore = (SPIKE / ".dockerignore").read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            dockerignore,
            [
                "# Limit the synthetic image build context to its four reviewed inputs.",
                "*", "!Dockerfile.target", "!requirements.txt", "!target_app.py",
                "!target_probe.py",
            ],
        )

    def test_no_changes_outside_allowed_task010_scope_except_spike_index(self) -> None:
        result = subprocess.run(
            ["git", "status", "--short"], cwd=REPOSITORY, text=True, capture_output=True, check=True
        )
        paths = [line[3:] for line in result.stdout.splitlines() if line]
        self.assertTrue(all(path == "spikes/README.md" or path.startswith("spikes/prometheus-metrics/") for path in paths), paths)


if __name__ == "__main__":
    unittest.main()
