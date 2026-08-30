"""Prometheus-compatible metrics with a closed, low-cardinality label contract."""

from __future__ import annotations

import re

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from .metadata import BuildMetadata


REQUEST_LABELS = ("service", "product", "environment", "method", "route", "status_class")
FORBIDDEN_REQUEST_LABELS = {
    "workspace_id", "user_id", "email", "session_id", "request_id", "trace_id",
    "ip_address", "authorization", "query", "url", "object_id", "git_commit",
    "oci_digest", "deployment_timestamp", "app_version", "platform_version",
}
_ROUTE_PARAMETER = re.compile(r"<(?:[a-z_][a-z0-9_]*:)?([a-z_][a-z0-9_]*)>", re.IGNORECASE)
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def normalized_route(route: str | None) -> str:
    """Convert a reviewed Django route template to a bounded metric label."""

    if not route:
        return "unmatched"
    normalized = _ROUTE_PARAMETER.sub(r"{\1}", route.strip("/"))
    if not normalized or len(normalized) > 160:
        return "unmatched"
    return "/" + normalized


def bounded_method(method: str) -> str:
    """Collapse unexpected methods into one bounded value."""

    canonical = method.upper()
    return canonical if canonical in _METHODS else "OTHER"


def status_class(status_code: int) -> str:
    """Return one of the fixed HTTP outcome classes."""

    if 100 <= status_code <= 599:
        return f"{status_code // 100}xx"
    return "other"


class MetricsContract:
    """Own an isolated registry and the mandatory application instruments."""

    def __init__(self, metadata: BuildMetadata) -> None:
        if FORBIDDEN_REQUEST_LABELS.intersection(REQUEST_LABELS):
            raise RuntimeError("request metric contract contains a forbidden label")
        self.registry = CollectorRegistry(auto_describe=True)
        constant = {
            "service": metadata.service,
            "product": metadata.product,
            "environment": metadata.environment,
        }
        self._constant = constant
        self.requests = Counter(
            "omnilyzer_http_requests_total",
            "Completed HTTP requests by normalized route and bounded outcome.",
            REQUEST_LABELS,
            registry=self.registry,
        )
        self.duration = Histogram(
            "omnilyzer_http_request_duration_seconds",
            "HTTP request duration using fixed platform buckets.",
            REQUEST_LABELS,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            registry=self.registry,
        )
        self.export_failures = Counter(
            "omnilyzer_telemetry_export_failures_total",
            "Asynchronous trace export failures by bounded category.",
            ("service", "product", "environment", "reason"),
            registry=self.registry,
        )
        self.build_info = Gauge(
            "omnilyzer_build_info",
            "One bounded build identity series for the running deployment.",
            ("service", "product", "environment", "app_version", "platform_version"),
            registry=self.registry,
        )
        self.build_info.labels(**metadata.build_info_labels()).set(1)

    def observe_request(self, method: str, route: str | None, code: int, seconds: float) -> None:
        """Record one request using only the closed label dimensions."""

        labels = {
            **self._constant,
            "method": bounded_method(method),
            "route": normalized_route(route),
            "status_class": status_class(code),
        }
        self.requests.labels(**labels).inc()
        self.duration.labels(**labels).observe(max(seconds, 0.0))

    def observe_export_failure(self, reason: str) -> None:
        """Record a failure using one of two bounded diagnostic reasons."""

        if reason not in {"exception", "rejected"}:
            reason = "exception"
        self.export_failures.labels(**self._constant, reason=reason).inc()

    def render(self) -> bytes:
        """Render the registry in Prometheus text exposition format."""

        return generate_latest(self.registry)
