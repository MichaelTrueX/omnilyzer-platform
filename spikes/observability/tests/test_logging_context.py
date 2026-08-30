"""Structured logging, request correlation, and concurrency evidence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import StringIO
import json
import logging
import re
from threading import Barrier
import unittest

from django.test import Client, TestCase
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from contract.context import REQUEST_ID_PATTERN, current_request_id
from contract.structured_logging import JsonFormatter, event
from contract.telemetry import build_runtime

from .helpers import METADATA, config, installed_runtime


class StructuredLoggingTests(unittest.TestCase):
    """Prove stable JSON fields and representative secret exclusion."""

    def setUp(self) -> None:
        self.stream = StringIO()
        self.logger = logging.getLogger(f"task009-test-{id(self)}")
        self.logger.handlers = []
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(self.stream)
        handler.setFormatter(
            JsonFormatter(
                service=METADATA.service,
                product=METADATA.product,
                environment=METADATA.environment,
            )
        )
        self.logger.addHandler(handler)

    def record(self) -> dict:
        return json.loads(self.stream.getvalue())

    def test_structured_log_contract(self) -> None:
        event(self.logger, "application.test", fields={"operation": "validate", "count": 2})
        record = self.record()
        self.assertEqual(
            set(record),
            {
                "timestamp", "level", "service", "product", "environment",
                "event", "request_id", "trace_id", "fields",
            },
        )
        self.assertRegex(record["timestamp"], r"^\d{4}-\d{2}-\d{2}T.*Z$")
        self.assertEqual(record["event"], "application.test")
        self.assertEqual(record["fields"], {"count": 2, "operation": "validate"})

    def test_representative_secrets_are_redacted(self) -> None:
        secrets = {
            "password": "password-secret-91",
            "access_token": "access-secret-92",
            "refresh-token": "refresh-secret-93",
            "Authorization": "Bearer auth-secret-94",
            "session_cookie": "__Host-omnilyzer=session-secret-95",
            "csrf_token": "csrf-secret-96",
            "api_key": "api-secret-97",
            "secret": "generic-secret-98",
            "request_body": {"customer_document": "private-document-99"},
        }
        event(self.logger, "security.redaction_test", fields=secrets)
        rendered = self.stream.getvalue()
        for secret in (
            "password-secret-91", "access-secret-92", "refresh-secret-93",
            "auth-secret-94", "session-secret-95", "csrf-secret-96",
            "api-secret-97", "generic-secret-98", "private-document-99",
        ):
            self.assertNotIn(secret, rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_credentials_embedded_in_message_like_fields_are_redacted(self) -> None:
        event(
            self.logger,
            "security.string_redaction_test",
            fields={
                "diagnostic": (
                    "Authorization: Bearer abc.def.ghi password=visible-no csrf_token=csrf-no "
                    "sessionid=session-no"
                )
            },
        )
        rendered = self.stream.getvalue()
        for secret in ("abc.def.ghi", "visible-no", "csrf-no", "session-no"):
            self.assertNotIn(secret, rendered)


class RequestCorrelationTests(TestCase):
    """Exercise the request ID contract over real Django middleware calls."""

    def setUp(self) -> None:
        self.exporter = InMemorySpanExporter()
        self.runtime = build_runtime(config(enabled=True), METADATA, exporter=self.exporter)
        self.runtime_context = installed_runtime(self.runtime)
        self.runtime_context.__enter__()
        self.addCleanup(self.runtime_context.__exit__, None, None, None)

    def test_generated_request_id_is_canonical_and_returned(self) -> None:
        response = self.client.get("/api/work/1")
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(REQUEST_ID_PATTERN.fullmatch(response["X-Request-ID"]))
        self.assertIsNone(current_request_id())

    def test_default_mode_replaces_even_valid_external_request_id(self) -> None:
        request_id = "0123456789abcdef0123456789abcdef"
        response = self.client.get("/api/work/2", headers={"X-Request-ID": request_id})
        self.assertNotEqual(response["X-Request-ID"], request_id)
        self.assertIsNotNone(REQUEST_ID_PATTERN.fullmatch(response["X-Request-ID"]))

    def trusted_runtime(self):
        """Build an isolated runtime representing a sanitizing trusted ingress."""

        return build_runtime(
            config(enabled=True, trust_incoming_request_id=True),
            METADATA,
            exporter=InMemorySpanExporter(),
        )

    def test_trusted_ingress_accepts_exact_valid_request_id(self) -> None:
        valid = "0123456789abcdef0123456789abcdef"
        with installed_runtime(self.trusted_runtime()):
            self.assertEqual(
                self.client.get("/api/work/2", headers={"X-Request-ID": valid})[
                    "X-Request-ID"
                ],
                valid,
            )

    def test_trusted_ingress_replaces_malformed_request_id(self) -> None:
        with installed_runtime(self.trusted_runtime()):
            for supplied in ("UPPERCASE", "../unsafe", "a" * 33):
                with self.subTest(supplied=supplied):
                    observed = self.client.get(
                        "/api/work/3", headers={"X-Request-ID": supplied}
                    )["X-Request-ID"]
                    self.assertNotEqual(observed, supplied)
                    self.assertIsNotNone(REQUEST_ID_PATTERN.fullmatch(observed))

    def test_trusted_ingress_replaces_oversized_request_id(self) -> None:
        supplied = "a" * 4096
        with installed_runtime(self.trusted_runtime()):
            observed = self.client.get(
                "/api/work/3", headers={"X-Request-ID": supplied}
            )["X-Request-ID"]
        self.assertNotEqual(observed, supplied)
        self.assertIsNotNone(REQUEST_ID_PATTERN.fullmatch(observed))

    def test_concurrent_requests_do_not_inherit_context(self) -> None:
        barrier = Barrier(8)
        request_ids = [f"{value:032x}" for value in range(1, 9)]

        def invoke(pair: tuple[int, str]) -> tuple[str, int]:
            item, request_id = pair
            barrier.wait(timeout=2)
            response = Client().get(
                f"/api/work/{item}", headers={"X-Request-ID": request_id}
            )
            return response["X-Request-ID"], response.status_code

        with installed_runtime(self.trusted_runtime()), ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(invoke, enumerate(request_ids, start=1)))
        self.assertEqual([result[0] for result in results], request_ids)
        self.assertTrue(all(result[1] == 200 for result in results))
        self.assertIsNone(current_request_id())

    def test_trace_id_is_correlated_in_structured_request_log(self) -> None:
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
        self.addCleanup(setattr, logger, "handlers", prior_handlers)
        self.addCleanup(setattr, logger, "propagate", prior_propagate)

        response = self.client.get("/api/work/9")
        self.assertEqual(response.status_code, 200)
        self.runtime.provider.force_flush(timeout_millis=500)
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        request_record = next(item for item in records if item["event"] == "http.request_completed")
        self.assertRegex(request_record["trace_id"], r"^[0-9a-f]{32}$")
        server_span = next(
            span for span in self.exporter.get_finished_spans()
            if span.name == "http.server.request"
        )
        self.assertEqual(request_record["trace_id"], f"{server_span.context.trace_id:032x}")
