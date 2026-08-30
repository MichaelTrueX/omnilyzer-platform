"""Vendor-neutral OpenTelemetry runtime with bounded asynchronous export."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from threading import Lock
import time
from typing import Sequence

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import NoOpTracerProvider, Tracer

from .config import ObservabilityConfig
from .metadata import BuildMetadata
from .metrics import MetricsContract
from .structured_logging import event


_LOGGER = logging.getLogger("omnilyzer.observability")
_OTEL_INTERNAL_LOGGER_NAME = "opentelemetry.sdk._shared_internal"
_QUEUE_FULL_MESSAGE = "Queue full, dropping %s."


class QueueFullWarningFilter(logging.Filter):
    """Rate-limit only the pinned SDK's per-span queue-full warning."""

    def __init__(self, interval_seconds: float = 60.0) -> None:
        super().__init__()
        self._interval_seconds = interval_seconds
        self._lock = Lock()
        self._last_allowed: float | None = None

    def filter(self, record: logging.LogRecord) -> bool:
        """Keep the first and periodic queue warning; preserve every other record."""

        if not (
            record.name == _OTEL_INTERNAL_LOGGER_NAME
            and record.levelno == logging.WARNING
            and record.msg == _QUEUE_FULL_MESSAGE
            and record.args == ("Span",)
        ):
            return True
        now = time.monotonic()
        with self._lock:
            if (
                self._last_allowed is None
                or now - self._last_allowed >= self._interval_seconds
            ):
                self._last_allowed = now
                return True
            return False


def install_queue_full_warning_filter() -> QueueFullWarningFilter:
    """Install one narrow process-wide filter on the exact noisy SDK logger."""

    logger = logging.getLogger(_OTEL_INTERNAL_LOGGER_NAME)
    for existing in logger.filters:
        if isinstance(existing, QueueFullWarningFilter):
            return existing
    warning_filter = QueueFullWarningFilter()
    logger.addFilter(warning_filter)
    return warning_filter


class DiagnosingExporter(SpanExporter):
    """Convert exporter exceptions into bounded async diagnostics, never request errors."""

    def __init__(self, delegate: SpanExporter, metrics: MetricsContract) -> None:
        self._delegate = delegate
        self._metrics = metrics
        self._log_lock = Lock()
        self._last_log = 0.0

    def _diagnose(self, reason: str) -> None:
        self._metrics.observe_export_failure(reason)
        now = time.monotonic()
        with self._log_lock:
            if now - self._last_log >= 1.0:
                event(
                    _LOGGER,
                    "telemetry.export_failed",
                    level=logging.WARNING,
                    fields={"reason": reason},
                )
                self._last_log = now

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            result = self._delegate.export(spans)
        except Exception:
            self._diagnose("exception")
            return SpanExportResult.FAILURE
        if result is not SpanExportResult.SUCCESS:
            self._diagnose("rejected")
        return result

    def shutdown(self) -> None:
        try:
            self._delegate.shutdown()
        except Exception:
            self._diagnose("exception")

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        try:
            return bool(self._delegate.force_flush(timeout_millis))
        except Exception:
            self._diagnose("exception")
            return False


@dataclass(slots=True)
class TelemetryRuntime:
    """Runtime handles kept outside product domain code."""

    config: ObservabilityConfig
    metadata: BuildMetadata
    metrics: MetricsContract
    tracer: Tracer
    provider: TracerProvider | None

    def shutdown(self) -> None:
        """Flush and stop bounded background export work."""

        if self.provider is not None:
            self.provider.shutdown()


def build_runtime(
    config: ObservabilityConfig,
    metadata: BuildMetadata,
    *,
    exporter: SpanExporter | None = None,
) -> TelemetryRuntime:
    """Build disabled or OTLP-capable tracing without setting a process-global provider."""

    install_queue_full_warning_filter()
    metrics = MetricsContract(metadata)
    if not config.enabled:
        provider = NoOpTracerProvider()
        return TelemetryRuntime(config, metadata, metrics, provider.get_tracer("omnilyzer.contract"), None)
    delegate = exporter or OTLPSpanExporter(
        endpoint=config.otlp_endpoint,
        timeout=config.export_timeout_millis / 1000,
    )
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": config.service,
                "service.namespace": config.product,
                "deployment.environment.name": config.environment,
            }
        )
    )
    provider.add_span_processor(
        BatchSpanProcessor(
            DiagnosingExporter(delegate, metrics),
            max_queue_size=config.max_queue_size,
            schedule_delay_millis=config.schedule_delay_millis,
            max_export_batch_size=config.max_export_batch_size,
            export_timeout_millis=config.export_timeout_millis,
        )
    )
    return TelemetryRuntime(
        config,
        metadata,
        metrics,
        provider.get_tracer("omnilyzer.contract", "0.0.0"),
        provider,
    )
