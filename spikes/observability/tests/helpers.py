"""Synthetic receivers and runtime fixtures for Task 009 tests."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import logging
from threading import Event, Thread
from typing import Iterator

from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from contract.config import ObservabilityConfig
from contract.metadata import BuildMetadata
from contract.runtime import get_runtime, set_runtime
from contract.telemetry import TelemetryRuntime, build_runtime


METADATA = BuildMetadata(
    service="task009-service",
    product="synthetic-product",
    environment="test",
    app_version="2.4.1",
    platform_version="1.8.0",
    git_commit="a" * 40,
    deployment_timestamp="2026-08-30T12:00:00Z",
    oci_digest="sha256:" + "b" * 64,
)


def config(
    *,
    enabled: bool,
    endpoint: str | None = None,
    timeout: int = 100,
    queue: int = 64,
    batch: int = 8,
    delay: int = 10,
    trust_incoming_request_id: bool = False,
    trust_incoming_trace_context: bool = False,
) -> ObservabilityConfig:
    """Create a fully bounded test configuration."""

    return ObservabilityConfig(
        enabled=enabled,
        service=METADATA.service,
        product=METADATA.product,
        environment=METADATA.environment,
        trust_incoming_request_id=trust_incoming_request_id,
        trust_incoming_trace_context=trust_incoming_trace_context,
        otlp_endpoint=endpoint,
        export_timeout_millis=timeout,
        schedule_delay_millis=delay,
        max_queue_size=queue,
        max_export_batch_size=batch,
    )


@contextmanager
def installed_runtime(runtime: TelemetryRuntime) -> Iterator[TelemetryRuntime]:
    """Temporarily install and reliably stop one test runtime."""

    previous = set_runtime(runtime)
    try:
        yield runtime
    finally:
        runtime.shutdown()
        set_runtime(previous)


class RaisingExporter(SpanExporter):
    """Exporter that proves background exceptions cannot cross into requests."""

    def __init__(self) -> None:
        self.calls = 0
        self.shutdown_calls = 0

    def export(self, spans):
        self.calls += 1
        raise RuntimeError("synthetic exporter failure")

    def shutdown(self) -> None:
        self.shutdown_calls += 1


class BlockingExporter(SpanExporter):
    """Hold background export so tests can deterministically saturate the queue."""

    def __init__(self) -> None:
        self.started = Event()
        self.release = Event()
        self.calls = 0

    def export(self, spans):
        self.calls += 1
        self.started.set()
        self.release.wait(timeout=5)
        return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        self.release.set()


class Receiver:
    """Loopback OTLP/downstream receiver with bounded request recording."""

    def __init__(self, post_status: int = 200) -> None:
        self.post_status = post_status
        self.posts = 0
        self.bytes = 0
        self.traceparents: list[str] = []
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - standard-library hook
                length = int(self.headers.get("Content-Length", "0"))
                receiver.bytes += len(self.rfile.read(length))
                receiver.posts += 1
                self.send_response(receiver.post_status)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802 - standard-library hook
                traceparent = self.headers.get("traceparent")
                if traceparent:
                    receiver.traceparents.append(traceparent)
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def otlp_endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/traces"

    @property
    def downstream_endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/downstream"

    def __enter__(self) -> "Receiver":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


@contextmanager
def muted_logger(name: str) -> Iterator[None]:
    """Suppress expected third-party exporter diagnostics during failure tests."""

    logger = logging.getLogger(name)
    prior = logger.disabled
    logger.disabled = True
    try:
        yield
    finally:
        logger.disabled = prior
