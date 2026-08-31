"""Unit evidence for the bounded application metric fixture."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest


SPIKE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SPIKE))
os.environ.setdefault("SERVICE", "unit-api")
os.environ.setdefault("PRODUCT", "unit-product")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("APP_VERSION", "1.0.0")
os.environ.setdefault("PLATFORM_VERSION", "1.8.0")

from prometheus_client import generate_latest  # noqa: E402
import target_app  # noqa: E402


class MetricContractTests(unittest.TestCase):
    def fixture(self) -> target_app.MetricsFixture:
        return target_app.MetricsFixture(
            service="unit-api", product="unit-product", environment="test",
            app_version="1.0.0", platform_version="1.8.0", initial_export_failures=1,
        )

    def test_ten_thousand_raw_user_ids_share_one_route_label_set(self) -> None:
        fixture = self.fixture()
        for item in range(10_000):
            fixture.observe("GET", f"/api/users/{item}?query=secret-{item}", 200, 0.001)
        families = list(fixture.registry.collect())
        counter = next(item for item in families if item.name == "omnilyzer_http_requests")
        totals = [sample for sample in counter.samples if sample.name.endswith("_total")]
        self.assertEqual(len(totals), 1)
        self.assertEqual(totals[0].labels["route"], "/api/users/{id}")
        self.assertEqual(totals[0].value, 10_000)

    def test_unique_unmatched_paths_collapse(self) -> None:
        fixture = self.fixture()
        for item in range(1_000):
            fixture.observe("GET", f"/unexpected/customer-{item}", 404, 0.001)
        counter = next(
            item for item in fixture.registry.collect() if item.name == "omnilyzer_http_requests"
        )
        totals = [sample for sample in counter.samples if sample.name.endswith("_total")]
        self.assertEqual([(sample.labels["route"], sample.value) for sample in totals], [("unmatched", 1_000)])

    def test_long_uuid_and_query_values_never_become_routes(self) -> None:
        self.assertEqual(target_app.normalized_route("/api/users/123e4567-e89b-12d3-a456-426614174000?token=secret"), "/api/users/{id}")
        self.assertEqual(target_app.normalized_route("/unexpected/" + "x" * 4096), "unmatched")

    def test_arbitrary_methods_collapse(self) -> None:
        self.assertEqual(target_app.bounded_method("BREW"), "OTHER")
        self.assertEqual(target_app.bounded_method("get"), "GET")

    def test_status_is_bounded(self) -> None:
        self.assertEqual(target_app.status_class(200), "2xx")
        self.assertEqual(target_app.status_class(599), "5xx")
        self.assertEqual(target_app.status_class(999), "other")

    def test_request_dimensions_are_exactly_closed_contract(self) -> None:
        self.assertEqual(
            target_app.REQUEST_LABELS,
            ("service", "product", "environment", "method", "route", "status_class"),
        )
        self.assertFalse(target_app.FORBIDDEN_REQUEST_LABELS & set(target_app.REQUEST_LABELS))

    def test_metric_names_match_adr_0007_contract(self) -> None:
        names = {family.name for family in self.fixture().registry.collect()}
        self.assertTrue({
            "omnilyzer_http_requests", "omnilyzer_http_request_duration_seconds",
            "omnilyzer_build_info", "omnilyzer_telemetry_export_failures",
        } <= names)

    def test_sensitive_values_absent_from_exposition(self) -> None:
        fixture = self.fixture()
        secrets = ("workspace-secret", "user-secret", "token-secret", "request-secret")
        fixture.observe("GET", f"/api/users/{secrets[1]}?token={secrets[2]}", 200, 0.001)
        output = generate_latest(fixture.registry).decode()
        for secret in secrets:
            self.assertNotIn(secret, output)

    def test_build_transition_replaces_current_gauge_only(self) -> None:
        fixture = self.fixture()
        fixture.transition_build("1.1.0", "1.8.1")
        build = next(item for item in fixture.registry.collect() if item.name == "omnilyzer_build_info")
        self.assertEqual(len(build.samples), 1)
        self.assertEqual(build.samples[0].labels["app_version"], "1.1.0")

    def test_build_identity_is_not_a_request_dimension(self) -> None:
        self.assertNotIn("app_version", target_app.REQUEST_LABELS)
        self.assertNotIn("git_commit", target_app.REQUEST_LABELS)
        self.assertNotIn("oci_digest", target_app.REQUEST_LABELS)
        self.assertNotIn("deployment_timestamp", target_app.REQUEST_LABELS)


if __name__ == "__main__":
    unittest.main()
