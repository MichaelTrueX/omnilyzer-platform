#!/usr/bin/env python3
"""Synthetic internal HTTP target implementing the accepted Task 009 metric contract."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
from threading import RLock
import time
from urllib.parse import parse_qs, urlsplit

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest


REQUEST_LABELS = ("service", "product", "environment", "method", "route", "status_class")
FORBIDDEN_REQUEST_LABELS = {
    "workspace_id", "user_id", "email", "session_id", "request_id", "trace_id",
    "ip_address", "authorization", "query", "url", "path", "customer_id",
    "object_id", "document_id", "order_id", "git_commit", "oci_digest",
    "deployment_timestamp", "app_version", "platform_version",
}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
ROUTES = (
    (re.compile(r"^/api/users/[^/]+$"), "/api/users/{id}"),
    (re.compile(r"^/api/orders/[^/]+$"), "/api/orders/{id}"),
    (re.compile(r"^/api/documents/[^/]+$"), "/api/documents/{id}"),
)
FIXED_ROUTES = {"/api/secure", "/livez", "/readyz", "/metrics"}
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


def normalized_route(raw_target: str) -> str:
    """Map caller-controlled paths to a finite framework-template vocabulary."""

    path = urlsplit(raw_target).path
    if path in FIXED_ROUTES:
        return path
    for pattern, template in ROUTES:
        if pattern.fullmatch(path):
            return template
    return "unmatched"


def bounded_method(method: str) -> str:
    """Collapse arbitrary HTTP methods into one bounded fallback."""

    canonical = method.upper()
    return canonical if canonical in METHODS else "OTHER"


def status_class(status: int) -> str:
    """Return a bounded HTTP status classification."""

    return f"{status // 100}xx" if 100 <= status <= 599 else "other"


class MetricsFixture:
    """Own one isolated registry matching the accepted product metric names and labels."""

    def __init__(
        self,
        *,
        service: str,
        product: str,
        environment: str,
        app_version: str,
        platform_version: str,
        initial_export_failures: int,
    ) -> None:
        if FORBIDDEN_REQUEST_LABELS.intersection(REQUEST_LABELS):
            raise RuntimeError("request metric labels contain a prohibited dimension")
        self.registry = CollectorRegistry(auto_describe=True)
        self.identity = {
            "service": service,
            "product": product,
            "environment": environment,
        }
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
            buckets=BUCKETS,
            registry=self.registry,
        )
        self.export_failures = Counter(
            "omnilyzer_telemetry_export_failures_total",
            "Asynchronous telemetry export failures by bounded category.",
            ("service", "product", "environment", "reason"),
            registry=self.registry,
        )
        self.build_info = Gauge(
            "omnilyzer_build_info",
            "One bounded build identity series for the running deployment.",
            ("service", "product", "environment", "app_version", "platform_version"),
            registry=self.registry,
        )
        self.app_version = app_version
        self.platform_version = platform_version
        self._set_build_info(app_version, platform_version)
        if initial_export_failures:
            self.export_failures.labels(**self.identity, reason="rejected").inc(
                initial_export_failures
            )

    def _set_build_info(self, app_version: str, platform_version: str) -> None:
        self.build_info.labels(
            **self.identity,
            app_version=app_version,
            platform_version=platform_version,
        ).set(1)

    def transition_build(self, app_version: str, platform_version: str) -> None:
        """Replace the current build-info identity without touching request metrics."""

        self.build_info.remove(
            *self.identity.values(), self.app_version, self.platform_version
        )
        self.app_version = app_version
        self.platform_version = platform_version
        self._set_build_info(app_version, platform_version)

    def observe(self, method: str, raw_target: str, status: int, seconds: float) -> None:
        """Record one request through the closed cardinality contract."""

        labels = {
            **self.identity,
            "method": bounded_method(method),
            "route": normalized_route(raw_target),
            "status_class": status_class(status),
        }
        self.requests.labels(**labels).inc()
        self.duration.labels(**labels).observe(max(0.0, seconds))


class TargetState:
    """Mutable synthetic controls kept outside metric labels."""

    def __init__(self) -> None:
        self.lock = RLock()
        self.metrics_mode = "normal"
        self.metrics = MetricsFixture(
            service=os.environ["SERVICE"],
            product=os.environ["PRODUCT"],
            environment=os.environ["ENVIRONMENT"],
            app_version=os.environ["APP_VERSION"],
            platform_version=os.environ["PLATFORM_VERSION"],
            initial_export_failures=int(os.environ.get("INITIAL_EXPORT_FAILURES", "0")),
        )


STATE = TargetState()


class Handler(BaseHTTPRequestHandler):
    """Serve synthetic domain, health, control, and internal metric requests."""

    protocol_version = "HTTP/1.1"
    server_version = "Task010SyntheticTarget"
    sys_version = ""

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, status: int, payload: dict[str, object]) -> None:
        self._write(status, json.dumps(payload, sort_keys=True).encode(), "application/json")

    def _control(self, path: str, query: dict[str, list[str]]) -> bool:
        if path == "/__mode" and self.command == "POST":
            mode = query.get("value", [""])[0]
            if mode not in {"normal", "slow", "malformed"}:
                self._json(400, {"status": "invalid"})
                return True
            with STATE.lock:
                STATE.metrics_mode = mode
            self._json(200, {"mode": mode})
            return True
        if path == "/__deployment" and self.command == "POST":
            app_version = query.get("app_version", [""])[0]
            platform_version = query.get("platform_version", [""])[0]
            if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", app_version) or not re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+", platform_version
            ):
                self._json(400, {"status": "invalid"})
                return True
            with STATE.lock:
                STATE.metrics.transition_build(app_version, platform_version)
            self._json(200, {"status": "updated"})
            return True
        return False

    def _handle(self) -> None:
        started = time.perf_counter()
        split = urlsplit(self.path)
        query = parse_qs(split.query, keep_blank_values=True)
        if self._control(split.path, query):
            return

        if split.path == "/metrics":
            with STATE.lock:
                mode = STATE.metrics_mode
            if mode == "slow":
                time.sleep(2)
            if mode == "malformed":
                self._write(200, b"not valid prometheus text {{{\n", "text/plain")
                return
            with STATE.lock:
                body = generate_latest(STATE.metrics.registry)
            status = 200
            self._write(status, body, "text/plain; version=0.0.4; charset=utf-8")
        elif split.path == "/livez":
            status = 200
            self._json(status, {"status": "alive"})
        elif split.path == "/readyz":
            status = 200
            self._json(status, {"status": "ready"})
        elif split.path == "/api/secure":
            if self.headers.get("Authorization") != "Bearer synthetic-valid-token":
                status = 401
            elif self.headers.get("X-Workspace-ID") != "00000000-0000-4000-8000-000000000001":
                status = 403
            else:
                status = 200
            self._json(status, {"status": "authorized" if status == 200 else "denied"})
        elif normalized_route(split.path) != "unmatched":
            status = 200
            self._json(status, {"status": "ok"})
        else:
            status = 404
            self._json(status, {"status": "not_found"})

        elapsed = time.perf_counter() - started
        with STATE.lock:
            STATE.metrics.observe(self.command, self.path, status, elapsed)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle
    do_BREW = _handle

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    """Serve only on the container network interface."""

    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
