"""File: deployment/tests/test_analytics_private_prod_compose.py

Purpose: Verify the complete first-private PROD Analytics Compose contract.
Related: deployment/runtime/prod/analytics.compose.private.yaml,
         deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/analytics_prod_rootless_bootstrap.py,
         docs/operations/dev-prod-direct-delivery.md.

All tests parse inert source with the repository's existing PyYAML dependency.
They never launch Docker, read secrets, open sockets, or authorize a release.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

import yaml

COMPOSE = (
    Path(__file__).resolve().parents[1]
    / "runtime/prod/analytics.compose.private.yaml"
)
SECRET_NAMES = (
    "COLLECTOR_DATABASE_URL", "DATABASE_URL",
    "JWT_REFRESH_SECRET", "JWT_SECRET",
)
SIGNED_VARIABLE = (
    "${ANALYTICS_PROD_IMAGE:?original signed 0.16.0 OCI digest required}"
)


class AnalyticsPrivateProdComposeTests(unittest.TestCase):
    """Check the actual parsed model, not just text fragments or comments."""

    @classmethod
    def setUpClass(cls) -> None:
        """Parse the canonical production-only YAML, resolving its anchor."""
        cls.config = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))

    def assert_private_prod_contract(self, config: object) -> None:
        """Enforce one isolated app, bounded host access and exact secret use."""
        self.assertIs(type(config), dict)
        self.assertEqual(config["name"], "omnilyzer-analytics-prod")
        self.assertEqual(set(config["services"]), {"analytics-blue"})
        self.assertEqual(
            set(config), {
                "name", "x-private-analytics", "services", "networks", "secrets"
            },
        )

        # Section 1: only a separately supplied, verified immutable OCI.
        service = config["services"]["analytics-blue"]
        self.assertEqual(service["image"], SIGNED_VARIABLE)
        self.assertEqual(service["profiles"], ["blue"])
        self.assertEqual(service["ports"], ["127.0.0.1:3141:3000"])
        for unsafe in (
            "privileged", "build", "network_mode", "pid", "userns_mode",
            "devices", "volumes_from", "extra_hosts", "entrypoint", "dns",
            "container_name", "env_file", "extends",
        ):
            self.assertNotIn(unsafe, service)

        # Section 2: reuse the existing accepted unprivileged Docker profile.
        self.assertEqual(service["user"], "10001:10001")
        self.assertIs(service["read_only"], True)
        self.assertEqual(service["cap_drop"], ["ALL"])
        self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
        self.assertEqual(service["pids_limit"], 192)
        self.assertEqual(service["cpus"], "1.00")
        self.assertEqual(service["mem_limit"], "768m")
        self.assertEqual(service["restart"], "no")
        self.assertEqual(
            service["environment"],
            {
                "NODE_ENV": "production",
                "NEXT_TELEMETRY_DISABLED": "1",
                "NODE_OPTIONS": "--max-old-space-size=512",
            },
        )
        self.assertEqual(
            service["tmpfs"],
            ["/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777"],
        )
        self.assertEqual(
            service["logging"],
            {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
        )

        # Section 3: private readiness and four separate env-file mounts.
        self.assertEqual(service["command"], [
            "node", *[
                f"--env-file=/run/secrets/{name}"
                for name in SECRET_NAMES
            ],
            "node_modules/next/dist/bin/next", "start",
            "-H", "0.0.0.0", "-p", "3000",
        ])
        self.assertEqual(
            sorted((item["source"], item["target"]) for item in service["secrets"]),
            sorted((f"PROD_{name}", name) for name in SECRET_NAMES),
        )
        health = service["healthcheck"]
        self.assertEqual(health["test"][:3], ["CMD", "node", "-e"])
        self.assertIn("127.0.0.1:3000/readyz", health["test"][3])
        self.assertEqual(service["networks"], ["analytics_backend"])

        # Section 4: no extra database server or TCP exposure. Read-only
        # Unix-socket usage still needs explicit PostgreSQL SCRAM/RLS approval.
        self.assertEqual(service["volumes"], [{
            "type": "bind",
            "source": "/var/run/postgresql",
            "target": "/var/run/postgresql",
            "read_only": True,
            "bind": {"create_host_path": False},
        }])
        self.assertEqual(
            config["networks"],
            {"analytics_backend": {
                "external": True, "name": "omnilyzer-analytics-backend-prod"
            }},
        )
        self.assertEqual(set(config["secrets"]), {
            f"PROD_{name}" for name in SECRET_NAMES
        })
        for name in SECRET_NAMES:
            self.assertEqual(
                config["secrets"][f"PROD_{name}"]["file"],
                f"/var/lib/omnilyzer/analytics/prod/secrets/{name}",
            )

    def test_actual_production_runtime_contract(self) -> None:
        """Parse and verify the complete one-slot read-only PROD model."""
        self.assert_private_prod_contract(self.config)

    def test_reject_public_port_and_additional_service(self) -> None:
        """Detect accidental public ingress or an unreviewed green release."""
        for change in ("public_port", "second_service", "extra_port", "inherited_port"):
            with self.subTest(change=change):
                config = deepcopy(self.config)
                if change == "public_port":
                    config["services"]["analytics-blue"]["ports"] = [
                        "0.0.0.0:3141:3000"
                    ]
                elif change == "second_service":
                    config["services"]["analytics-green"] = deepcopy(
                        config["services"]["analytics-blue"]
                    )
                elif change == "extra_port":
                    config["services"]["analytics-blue"]["ports"].append(
                        "127.0.0.1:3142:3000"
                    )
                else:
                    config["services"]["analytics-blue"]["extends"] = {
                        "file": "./unexpected-public-service.yaml",
                        "service": "public-base",
                    }
                with self.assertRaises(AssertionError):
                    self.assert_private_prod_contract(config)

    def test_reject_secret_or_privilege_expansion(self) -> None:
        """Detect root execution, expanded container powers and source drift."""
        for change in ("root", "privileged", "unbounded_ram", "dev_secret"):
            with self.subTest(change=change):
                config = deepcopy(self.config)
                service = config["services"]["analytics-blue"]
                if change == "root":
                    service["user"] = "0:0"
                elif change == "privileged":
                    service["privileged"] = True
                elif change == "unbounded_ram":
                    service.pop("mem_limit")
                else:
                    config["secrets"]["PROD_DATABASE_URL"]["file"] = (
                        "/var/lib/omnilyzer/deployment/analytics/dev/secrets/DATABASE_URL"
                    )
                with self.assertRaises((AssertionError, KeyError)):
                    self.assert_private_prod_contract(config)


if __name__ == "__main__":
    unittest.main()
