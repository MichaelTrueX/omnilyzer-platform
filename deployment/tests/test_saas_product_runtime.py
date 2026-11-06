"""File: deployment/tests/test_saas_product_runtime.py

Purpose: Independent fail-closed profile checks for M05 Task014 Analytics DEV.
Related: deployment/saas_product_runtime.py,
deployment/products/analytics-runtime-dev.json, M01 PR225 source admission.
Tests do not touch Docker, network, registry, protected broker or any host.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from deployment.policy import DeploymentPolicyError
from deployment.saas_product_runtime import (
    SaaSRuntimeProfile, load_review_profile,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "deployment/products/analytics-runtime-dev.json"


class TestSaaSRuntimeProfile(unittest.TestCase):
    """Protect product boundaries without producing signed release authority."""

    def setUp(self) -> None:
        """Load the exact committed DEV runtime descriptor."""
        self.original = json.loads(PROFILE.read_text())
        self.profile = SaaSRuntimeProfile.from_dict(self.original)

    def reject(self, operation) -> None:
        """Verify an adversarial descriptor mutation is not accepted."""
        value = copy.deepcopy(self.original)
        operation(value)
        with self.assertRaises(DeploymentPolicyError):
            SaaSRuntimeProfile.from_dict(value)

    def test_approved(self) -> None:
        """Approve only the reviewed isolated Analytics profile."""
        self.assertEqual(self.profile.to_dict(), self.original)
        self.assertEqual(self.profile.container_port, 3000)
        self.assertEqual(self.profile.ready_path, "/readyz")
        self.assertRegex(self.profile.sha256(), r"^[0-9a-f]{64}$")

    def test_canary_is_not_analytics(self) -> None:
        """Canary image repository must never stand in for Analytics."""
        self.reject(lambda x: x.update(oci_repository="omnilyzer/task013-release-canary"))

    def test_future_modules_denied(self) -> None:
        """A future cybersecurity module needs reviewed policy, not a wildcard."""
        self.reject(lambda x: x.update(product_id="cybersecurity"))

    def test_wrong_stage_denied(self) -> None:
        """Do not allow production activation from a DEV descriptor."""
        self.reject(lambda x: x.update(stage="prod"))

    def test_extra_claim_denied(self) -> None:
        """Extra metadata cannot silently add an approval claim."""
        self.reject(lambda x: x.update(approved=True))

    def test_incorrect_port_denied(self) -> None:
        """Disallow host port 3451 and arbitrary product ports."""
        self.reject(lambda x: x.update(container_port=3451))

    def test_boolean_port_denied(self) -> None:
        """Reject bool masquerading as int under Python comparison rules."""
        self.reject(lambda x: x.update(container_port=True))

    def test_admin_probe_denied(self) -> None:
        """Never call an authenticated admin metric endpoint for readiness."""
        self.reject(lambda x: x["health"].update(ready="/api/v1/admin/system-health"))

    def test_missing_liveness_denied(self) -> None:
        """Require complete readiness and liveness contracts."""
        self.reject(lambda x: x["health"].pop("live"))

    def test_collector_secret_reference_required(self) -> None:
        """Collector DB identity cannot be silently replaced by app DB."""
        self.reject(lambda x: x["runtime_secret_names"].remove("COLLECTOR_DATABASE_URL"))

    def test_literal_secret_denied(self) -> None:
        """Never store actual secret values in a reviewed profile."""
        self.reject(lambda x: x.update(JWT_SECRET="unsafe"))

    def test_secret_order_is_closed(self) -> None:
        """No duplicate or reordered names that change a canonical contract."""
        self.reject(lambda x: x["runtime_secret_names"].reverse())

    def test_shared_mysql_denied(self) -> None:
        """Do not allow a separate product to use a shared legacy DB."""
        self.reject(lambda x: x.update(database="mysql"))

    def test_public_ingress_denied(self) -> None:
        """Task014 DEV must remain a private ingress."""
        self.reject(lambda x: x.update(ingress="public-cloudflare"))

    def test_unsafe_data_rollback_denied(self) -> None:
        """Rollback does not authorize restoring a stale customer DB snapshot."""
        self.reject(lambda x: x.update(rollback="delete-database"))

    def test_extra_health_field_denied(self) -> None:
        """Avoid undocumented executable health probes."""
        self.reject(lambda x: x["health"].update(command="curl $(env)"))

    def test_duplicate_json_denied(self) -> None:
        """Reject duplicate security-sensitive JSON keys."""
        raw = PROFILE.read_bytes().replace(b'"product_id": "analytics",',
                b'"product_id": "analytics", "product_id": "cybersecurity",')
        with self.assertRaises(DeploymentPolicyError):
            SaaSRuntimeProfile.from_json_bytes(raw)

    def test_oversized_json_denied(self) -> None:
        """Bound untrusted config before JSON parsing."""
        with self.assertRaises(DeploymentPolicyError):
            SaaSRuntimeProfile.from_json_bytes(b"x" * 4097)

    def test_symlink_rejected(self) -> None:
        """No mutable symlink to another runtime profile is accepted."""
        with tempfile.TemporaryDirectory(prefix="m05-runtime-") as td:
            link = Path(td) / "profile.json"
            link.symlink_to(PROFILE)
            with self.assertRaises(DeploymentPolicyError):
                load_review_profile(link)


if __name__ == "__main__":
    unittest.main()
