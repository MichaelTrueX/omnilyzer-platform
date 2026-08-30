"""Mandatory telemetry outage and bounded-resource acceptance evidence."""

from __future__ import annotations

import socket
from io import StringIO
import logging
import time
import tracemalloc
from unittest.mock import patch

from django.test import TestCase, override_settings

from contract.runtime import set_runtime
from contract.telemetry import QueueFullWarningFilter, build_runtime

from .helpers import (
    BlockingExporter,
    METADATA,
    Receiver,
    RaisingExporter,
    config,
    installed_runtime,
    muted_logger,
)


class TelemetryFailureIsolationTests(TestCase):
    """Prove trace export is never a synchronous application dependency."""

    def test_background_exporter_exception_never_reaches_callers(self) -> None:
        exporter = RaisingExporter()
        runtime = build_runtime(config(enabled=True, queue=32, batch=8), METADATA, exporter=exporter)
        with installed_runtime(runtime):
            responses = [self.client.get(f"/api/work/{item}") for item in range(40)]
            runtime.provider.force_flush(timeout_millis=500)
            metrics = runtime.metrics.render().decode("utf-8")
        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertGreater(exporter.calls, 0)
        self.assertEqual(exporter.shutdown_calls, 1)
        self.assertIn("omnilyzer_telemetry_export_failures_total", metrics)
        self.assertIn('reason="exception"', metrics)

    def test_unreachable_otlp_target_has_bounded_latency_memory_and_shutdown(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            unused_port = probe.getsockname()[1]
        endpoint = f"http://127.0.0.1:{unused_port}/v1/traces"
        runtime = build_runtime(
            config(enabled=True, endpoint=endpoint, timeout=100, queue=32, batch=8),
            METADATA,
        )
        previous = set_runtime(runtime)
        latencies: list[float] = []
        tracemalloc.start()
        try:
            with muted_logger("opentelemetry.exporter.otlp.proto.http.trace_exporter"):
                for item in range(100):
                    started = time.perf_counter()
                    response = self.client.get(f"/api/work/{item}")
                    latencies.append(time.perf_counter() - started)
                    self.assertEqual(response.status_code, 200)
                runtime.provider.force_flush(timeout_millis=750)
                current, peak = tracemalloc.get_traced_memory()
                shutdown_started = time.perf_counter()
                runtime.shutdown()
                shutdown_seconds = time.perf_counter() - shutdown_started
        finally:
            tracemalloc.stop()
            set_runtime(previous)
        p95 = sorted(latencies)[int(len(latencies) * 0.95) - 1]
        self.assertLess(p95, 0.05)
        self.assertLess(max(latencies), 0.25)
        self.assertLess(peak - current, 8 * 1024 * 1024)
        self.assertLess(shutdown_seconds, 1.0)
        self.assertIn(
            "omnilyzer_telemetry_export_failures_total",
            runtime.metrics.render().decode("utf-8"),
        )

    def test_rejecting_otlp_receiver_has_bounded_retry_count(self) -> None:
        with Receiver(post_status=503) as receiver:
            runtime = build_runtime(
                config(
                    enabled=True,
                    endpoint=receiver.otlp_endpoint,
                    timeout=100,
                    queue=64,
                    batch=8,
                ),
                METADATA,
            )
            with installed_runtime(runtime), muted_logger(
                "opentelemetry.exporter.otlp.proto.http.trace_exporter"
            ):
                for item in range(32):
                    self.assertEqual(self.client.get(f"/api/work/{item}").status_code, 200)
                runtime.provider.force_flush(timeout_millis=750)
        self.assertGreater(receiver.posts, 0)
        self.assertLessEqual(receiver.posts, 16)

    def test_queue_saturation_warnings_are_narrowly_rate_limited(self) -> None:
        upstream_logger = logging.getLogger("opentelemetry.sdk._shared_internal")
        prior_handlers = upstream_logger.handlers[:]
        prior_filters = upstream_logger.filters[:]
        prior_level = upstream_logger.level
        prior_propagate = upstream_logger.propagate
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        upstream_logger.handlers = [handler]
        upstream_logger.filters = [QueueFullWarningFilter(interval_seconds=60)]
        upstream_logger.setLevel(logging.WARNING)
        upstream_logger.propagate = False

        exporter = BlockingExporter()
        runtime = build_runtime(
            config(enabled=True, timeout=100, queue=16, batch=8, delay=10),
            METADATA,
            exporter=exporter,
        )
        previous = set_runtime(runtime)
        latencies: list[float] = []
        try:
            for item in range(8):
                self.assertEqual(self.client.get(f"/api/work/{item}").status_code, 200)
            self.assertTrue(exporter.started.wait(timeout=1))
            for item in range(600):
                started = time.perf_counter()
                self.assertEqual(self.client.get(f"/api/work/{item}").status_code, 200)
                latencies.append(time.perf_counter() - started)
            upstream_logger.warning("unrelated OpenTelemetry warning remains visible")
            upstream_logger.error("unrelated OpenTelemetry error remains visible")
        finally:
            exporter.release.set()
            runtime.provider.force_flush(timeout_millis=750)
            runtime.shutdown()
            set_runtime(previous)
            upstream_logger.handlers = prior_handlers
            upstream_logger.filters = prior_filters
            upstream_logger.setLevel(prior_level)
            upstream_logger.propagate = prior_propagate

        messages = stream.getvalue().splitlines()
        queue_warnings = [
            message for message in messages if message == "Queue full, dropping Span."
        ]
        self.assertEqual(len(queue_warnings), 1)
        self.assertIn("unrelated OpenTelemetry warning remains visible", messages)
        self.assertIn("unrelated OpenTelemetry error remains visible", messages)
        self.assertLess(max(latencies), 0.25)
        self.assertGreater(exporter.calls, 0)
        self.assertIn(
            'reason="rejected"', runtime.metrics.render().decode("utf-8")
        )

    def test_queue_warning_filter_preserves_first_periodic_and_unrelated_records(self) -> None:
        warning_filter = QueueFullWarningFilter(interval_seconds=60)
        queue_record = logging.LogRecord(
            "opentelemetry.sdk._shared_internal",
            logging.WARNING,
            __file__,
            1,
            "Queue full, dropping %s.",
            ("Span",),
            None,
        )
        unrelated = logging.LogRecord(
            "opentelemetry.sdk._shared_internal",
            logging.ERROR,
            __file__,
            1,
            "unrelated error",
            (),
            None,
        )
        with patch("contract.telemetry.time.monotonic", side_effect=(0.0, 1.0, 61.0)):
            self.assertTrue(warning_filter.filter(queue_record))
            self.assertFalse(warning_filter.filter(queue_record))
            self.assertTrue(warning_filter.filter(queue_record))
        self.assertTrue(warning_filter.filter(unrelated))

    def test_controlled_otlp_receiver_accepts_vendor_neutral_payloads(self) -> None:
        with Receiver(post_status=200) as receiver:
            runtime = build_runtime(
                config(enabled=True, endpoint=receiver.otlp_endpoint), METADATA
            )
            with installed_runtime(runtime):
                for item in range(10):
                    self.assertEqual(self.client.get(f"/api/work/{item}").status_code, 200)
                self.assertTrue(runtime.provider.force_flush(timeout_millis=750))
        self.assertGreater(receiver.posts, 0)
        self.assertGreater(receiver.bytes, 0)

    def test_outage_does_not_expose_exporter_details_or_change_security_results(self) -> None:
        exporter = RaisingExporter()
        runtime = build_runtime(config(enabled=True), METADATA, exporter=exporter)
        with installed_runtime(runtime), override_settings(
            REQUIRED_READINESS_CHECK=lambda: True
        ):
            work = self.client.get("/api/work/1")
            ready = self.client.get("/readyz")
            unauthorized = self.client.get("/api/secure")
        self.assertEqual(work.status_code, 200)
        self.assertEqual(ready.status_code, 200)
        self.assertEqual(unauthorized.status_code, 401)
        combined = work.content + ready.content + unauthorized.content
        for leaked in (b"otlp", b"exporter", b"traceback", b"connection", b"4318"):
            self.assertNotIn(leaked, combined.lower())
