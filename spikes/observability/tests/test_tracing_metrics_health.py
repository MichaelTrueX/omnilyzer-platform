"""Tracing portability, metrics cardinality, health, and security evidence."""

from __future__ import annotations

from io import StringIO
import json
import logging
import unittest

from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from contract.metrics import FORBIDDEN_REQUEST_LABELS, REQUEST_LABELS
from contract.middleware import ObservabilityMiddleware
from contract.structured_logging import JsonFormatter
from contract.telemetry import build_runtime

from .helpers import METADATA, Receiver, RaisingExporter, config, installed_runtime


class TracingAndMetricsTests(TestCase):
    """Validate trace propagation and bounded metric dimensions."""

    def setUp(self) -> None:
        self.exporter = InMemorySpanExporter()
        self.runtime = build_runtime(config(enabled=True), METADATA, exporter=self.exporter)
        self.runtime_context = installed_runtime(self.runtime)
        self.runtime_context.__enter__()
        self.addCleanup(self.runtime_context.__exit__, None, None, None)

    def flush(self):
        self.assertTrue(self.runtime.provider.force_flush(timeout_millis=500))
        return self.exporter.get_finished_spans()

    def test_django_request_and_database_spans_are_correlated(self) -> None:
        response = self.client.get(
            "/api/work/123456",
            headers={
                "X-Workspace-ID": "workspace-sensitive-1",
                "Authorization": "Bearer trace-secret-2",
                "Cookie": "sessionid=trace-session-3",
            },
        )
        self.assertEqual(response.status_code, 200)
        spans = self.flush()
        server = next(span for span in spans if span.name == "http.server.request")
        database = next(span for span in spans if span.name == "database.required_operation")
        self.assertEqual(database.parent.span_id, server.context.span_id)
        self.assertEqual(server.attributes["http.route"], "/api/work/{item_id}")
        self.assertEqual(database.attributes, {"db.system.name": "sqlite"})
        serialized = json.dumps(
            [{"name": span.name, "attributes": dict(span.attributes)} for span in spans],
            sort_keys=True,
        )
        for sensitive in (
            "workspace-sensitive-1", "trace-secret-2", "trace-session-3",
            "123456", "workspace_id", "user_id", "email", "authorization",
            "request.body", "session_id", "access_token", "refresh_token",
        ):
            self.assertNotIn(sensitive, serialized.lower())

    def test_incoming_w3c_trace_context_is_honored(self) -> None:
        trace_id = "1" * 32
        parent_span_id = "2" * 16
        response = self.client.get(
            "/api/work/7",
            headers={"traceparent": f"00-{trace_id}-{parent_span_id}-01"},
        )
        self.assertEqual(response.status_code, 200)
        server = next(
            span for span in self.flush() if span.name == "http.server.request"
        )
        self.assertEqual(f"{server.context.trace_id:032x}", trace_id)
        self.assertEqual(f"{server.parent.span_id:016x}", parent_span_id)

    def test_outbound_http_propagates_trace_context(self) -> None:
        with Receiver() as receiver, override_settings(
            SYNTHETIC_OUTBOUND_URL=receiver.downstream_endpoint
        ):
            response = self.client.get("/api/outbound")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(receiver.traceparents), 1)
        self.assertRegex(
            receiver.traceparents[0],
            r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$",
        )
        spans = self.flush()
        self.assertIn("http.synthetic_downstream", {span.name for span in spans})

    def test_request_metrics_use_normalized_routes_and_bounded_labels(self) -> None:
        for item in (1, 2, 999999999):
            self.assertEqual(self.client.get(f"/api/work/{item}").status_code, 200)
        self.assertEqual(self.client.get("/api/secure").status_code, 401)
        rendered = self.runtime.metrics.render().decode("utf-8")
        self.assertIn('route="/api/work/{item_id}"', rendered)
        for raw in ("/api/work/1", "/api/work/2", "/api/work/999999999"):
            self.assertNotIn(raw, rendered)
        self.assertEqual(FORBIDDEN_REQUEST_LABELS.intersection(REQUEST_LABELS), set())
        request_samples = [
            sample
            for metric in self.runtime.metrics.registry.collect()
            if metric.name in {
                "omnilyzer_http_requests",
                "omnilyzer_http_request_duration_seconds",
            }
            for sample in metric.samples
        ]
        self.assertTrue(request_samples)
        self.assertTrue(
            any(
                sample.labels.get("route") == "/api/secure"
                and sample.labels.get("status_class") == "4xx"
                for sample in request_samples
            )
        )
        for sample in request_samples:
            self.assertTrue(set(REQUEST_LABELS).issubset(sample.labels))
            self.assertTrue(set(sample.labels).issubset({*REQUEST_LABELS, "le"}))
            self.assertFalse(FORBIDDEN_REQUEST_LABELS.intersection(sample.labels))

    def test_build_info_is_one_bounded_series_without_deployment_churn_labels(self) -> None:
        samples = [
            sample
            for metric in self.runtime.metrics.registry.collect()
            if metric.name == "omnilyzer_build_info"
            for sample in metric.samples
        ]
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].value, 1)
        self.assertEqual(
            set(samples[0].labels),
            {"service", "product", "environment", "app_version", "platform_version"},
        )
        for prohibited in ("git_commit", "oci_digest", "deployment_timestamp"):
            self.assertNotIn(prohibited, samples[0].labels)


class HealthAndSecurityBoundaryTests(TestCase):
    """Prove minimal health semantics and non-interference with security decisions."""

    def test_liveness_is_minimal_and_dependency_free(self) -> None:
        with override_settings(REQUIRED_READINESS_CHECK=lambda: False):
            response = self.client.get("/livez")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "alive"})
        self.assertEqual(set(response.json()), {"status"})

    def test_readiness_reflects_required_dependency_only(self) -> None:
        with override_settings(REQUIRED_READINESS_CHECK=lambda: True):
            self.assertEqual(self.client.get("/readyz").json(), {"status": "ready"})
        with override_settings(REQUIRED_READINESS_CHECK=lambda: False):
            response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"status": "unready"})
        rendered = response.content.decode("utf-8")
        for prohibited in (
            "password", "hostname", "127.0.0.1", "traceback", "otlp", "database",
        ):
            self.assertNotIn(prohibited, rendered.lower())

    def test_observability_failure_is_not_a_readiness_dependency(self) -> None:
        exporter = RaisingExporter()
        runtime = build_runtime(config(enabled=True), METADATA, exporter=exporter)
        with installed_runtime(runtime), override_settings(
            REQUIRED_READINESS_CHECK=lambda: True
        ):
            for _ in range(10):
                self.assertEqual(self.client.get("/readyz").status_code, 200)
            self.assertTrue(runtime.provider.force_flush(timeout_millis=500))
        self.assertGreater(exporter.calls, 0)

    def test_telemetry_does_not_bypass_auth_authorization_csrf_cors_or_cookies(self) -> None:
        exporter = RaisingExporter()
        runtime = build_runtime(config(enabled=True), METADATA, exporter=exporter)
        with installed_runtime(runtime):
            self.assertEqual(self.client.get("/api/secure").status_code, 401)
            forbidden = self.client.get(
                "/api/secure",
                headers={"Authorization": "Bearer synthetic-valid-token"},
            )
            self.assertEqual(forbidden.status_code, 403)
            authorized = self.client.get(
                "/api/secure",
                headers={
                    "Authorization": "Bearer synthetic-valid-token",
                    "X-Workspace-ID": "00000000-0000-4000-8000-000000000001",
                },
            )
            self.assertEqual(authorized.status_code, 200)
            self.assertNotIn("Access-Control-Allow-Origin", authorized)
            self.assertFalse(authorized.cookies)
            csrf_client = Client(enforce_csrf_checks=True)
            csrf_response = csrf_client.post(
                "/api/secure",
                headers={
                    "Authorization": "Bearer synthetic-valid-token",
                    "X-Workspace-ID": "00000000-0000-4000-8000-000000000001",
                },
            )
            self.assertEqual(csrf_response.status_code, 403)
        self.assertNotIn("access_token", runtime.metadata.as_dict())

    def test_middleware_preserves_security_context_and_csp_response(self) -> None:
        request = RequestFactory().get(
            "/synthetic",
            headers={
                "Authorization": "Bearer synthetic-valid-token",
                "X-Workspace-ID": "00000000-0000-4000-8000-000000000001",
                "Cookie": "__Host-session=opaque",
            },
        )
        request.workspace_context = object()
        original_context = request.workspace_context

        def security_boundary(observed_request):
            self.assertEqual(
                observed_request.headers["Authorization"],
                "Bearer synthetic-valid-token",
            )
            self.assertEqual(
                observed_request.headers["X-Workspace-ID"],
                "00000000-0000-4000-8000-000000000001",
            )
            self.assertIs(observed_request.workspace_context, original_context)
            response = HttpResponse("ok")
            response["Content-Security-Policy"] = "default-src 'self'"
            return response

        response = ObservabilityMiddleware(security_boundary)(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Security-Policy"], "default-src 'self'")
        self.assertNotIn("Access-Control-Allow-Origin", response)
        self.assertFalse(response.cookies)

    def test_sensitive_headers_and_body_are_absent_from_request_logs(self) -> None:
        stream = StringIO()
        logger = logging.getLogger("omnilyzer.observability")
        prior_handlers, prior_propagate = logger.handlers[:], logger.propagate
        handler = logging.StreamHandler(stream)
        handler.setFormatter(
            JsonFormatter(
                service=METADATA.service,
                product=METADATA.product,
                environment=METADATA.environment,
            )
        )
        logger.handlers = [handler]
        logger.propagate = False
        try:
            response = Client(enforce_csrf_checks=True).post(
                "/api/secure",
                data=json.dumps({"password": "body-secret-1"}),
                content_type="application/json",
                headers={
                    "Authorization": "Bearer header-secret-2",
                    "Cookie": "sessionid=cookie-secret-3",
                    "X-CSRFToken": "csrf-secret-4",
                },
            )
        finally:
            logger.handlers = prior_handlers
            logger.propagate = prior_propagate
        self.assertEqual(response.status_code, 403)
        rendered = stream.getvalue()
        for secret in (
            "body-secret-1", "header-secret-2", "cookie-secret-3", "csrf-secret-4",
        ):
            self.assertNotIn(secret, rendered)
