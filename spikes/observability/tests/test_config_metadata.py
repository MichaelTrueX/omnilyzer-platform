"""Configuration and application/build metadata contract evidence."""

from __future__ import annotations

import unittest

from contract.config import ObservabilityConfig
from contract.metadata import installed_version, load_build_metadata
from contract.runtime import get_runtime, initialize_safely, set_runtime


class ConfigurationTests(unittest.TestCase):
    """Validate strict configuration and availability-preserving fallback."""

    def test_valid_configuration_is_bounded(self) -> None:
        config = ObservabilityConfig.from_mapping(
            {
                "OBSERVABILITY_ENABLED": "true",
                "OBSERVABILITY_SERVICE": "valoria-api",
                "OBSERVABILITY_PRODUCT": "valoria",
                "OBSERVABILITY_ENVIRONMENT": "test",
                "OBSERVABILITY_TRUST_INCOMING_REQUEST_ID": "true",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:4318/v1/traces",
                "OTEL_EXPORT_TIMEOUT_MILLIS": "200",
                "OTEL_BSP_SCHEDULE_DELAY_MILLIS": "25",
                "OTEL_BSP_MAX_QUEUE_SIZE": "128",
                "OTEL_BSP_MAX_EXPORT_BATCH_SIZE": "16",
            }
        )
        self.assertTrue(config.enabled)
        self.assertTrue(config.trust_incoming_request_id)
        self.assertEqual(config.max_queue_size, 128)
        self.assertLessEqual(config.max_export_batch_size, config.max_queue_size)

    def test_malformed_telemetry_configuration_is_rejected(self) -> None:
        malformed = (
            {"OBSERVABILITY_ENABLED": "yes"},
            {"OBSERVABILITY_TRUST_INCOMING_REQUEST_ID": "yes"},
            {"OBSERVABILITY_ENABLED": "true"},
            {
                "OBSERVABILITY_ENABLED": "true",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://user:secret@127.0.0.1:4318/v1/traces",
            },
            {
                "OBSERVABILITY_ENABLED": "true",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://collector.internal/v1/traces",
            },
            {
                "OBSERVABILITY_ENABLED": "true",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:4318/wrong",
            },
            {"OBSERVABILITY_SERVICE": "UNBOUNDED OR INVALID"},
            {"OBSERVABILITY_ENVIRONMENT": "customer-controlled"},
            {"OTEL_BSP_MAX_QUEUE_SIZE": "1000000"},
            {"OTEL_BSP_MAX_EXPORT_BATCH_SIZE": "0"},
        )
        for values in malformed:
            with self.subTest(values=values), self.assertRaises(ValueError):
                ObservabilityConfig.from_mapping(values)

    def test_malformed_configuration_disables_telemetry_without_crashing_app(self) -> None:
        previous = get_runtime()
        runtime = initialize_safely({"OBSERVABILITY_ENABLED": "invalid"})
        try:
            self.assertFalse(runtime.config.enabled)
            self.assertIsNone(runtime.provider)
        finally:
            set_runtime(previous)


class MetadataTests(unittest.TestCase):
    """Validate package-derived versions and deployment-time injection."""

    def values(self) -> dict[str, str]:
        return {
            "APPLICATION_DISTRIBUTION": "synthetic-application",
            "PLATFORM_DISTRIBUTION": "synthetic-platform",
            "GIT_COMMIT": "c" * 40,
            "OCI_DIGEST": "sha256:" + "d" * 64,
            "DEPLOYMENT_TIMESTAMP": "2026-08-30T13:14:15Z",
            "OBSERVABILITY_SERVICE": "valoria-api",
            "OBSERVABILITY_PRODUCT": "valoria",
            "OBSERVABILITY_ENVIRONMENT": "prod",
        }

    def test_installed_distribution_metadata_is_available(self) -> None:
        self.assertEqual(installed_version("Django"), "6.1")
        self.assertEqual(installed_version("omnilyzer-observability-spike"), "0.0.0")

    def test_complete_metadata_and_bounded_build_info_are_separate(self) -> None:
        versions = {
            "synthetic-application": "2.4.1",
            "synthetic-platform": "1.8.0",
        }
        metadata = load_build_metadata(self.values(), resolver=versions.__getitem__)
        complete = metadata.as_dict()
        self.assertEqual(complete["git_commit"], "c" * 40)
        self.assertEqual(complete["oci_digest"], "sha256:" + "d" * 64)
        self.assertEqual(complete["deployment_timestamp"], "2026-08-30T13:14:15Z")
        labels = metadata.build_info_labels()
        self.assertEqual(labels["app_version"], "2.4.1")
        self.assertEqual(labels["platform_version"], "1.8.0")
        for high_churn in ("git_commit", "oci_digest", "deployment_timestamp"):
            self.assertNotIn(high_churn, labels)

    def test_malformed_deployment_metadata_fails_closed(self) -> None:
        cases = (
            ("GIT_COMMIT", "short"),
            ("OCI_DIGEST", "sha256:bad"),
            ("DEPLOYMENT_TIMESTAMP", "not-a-timestamp"),
        )
        for key, value in cases:
            values = self.values()
            values[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                load_build_metadata(values, resolver=lambda _: "1.0.0")
