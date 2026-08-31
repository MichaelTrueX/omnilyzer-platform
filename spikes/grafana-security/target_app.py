#!/usr/bin/env python3
"""Dependency-free synthetic application exposing the accepted metrics contract."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock
import time


IDENTITIES = (
    ("valoria-api", "valoria", "dev", "2.4.1", "1.8.0"),
    ("chronicle-api", "chronicle", "staging", "1.3.0", "1.8.0"),
    ("platform-api", "platform", "test", "0.9.0", "1.8.0"),
)
BUCKETS = ("0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "+Inf")
LOCK = Lock()
REQUEST_COUNT = 10


def _labels(**values: str) -> str:
    return ",".join(f'{name}="{value}"' for name, value in values.items())


def metrics_text() -> bytes:
    """Return deterministic Prometheus exposition with bounded synthetic labels."""

    with LOCK:
        current = REQUEST_COUNT
    lines = [
        "# HELP omnilyzer_http_requests_total Completed requests by bounded dimensions.",
        "# TYPE omnilyzer_http_requests_total counter",
    ]
    for index, (service, product, environment, _app, _platform) in enumerate(IDENTITIES):
        labels = _labels(
            service=service,
            product=product,
            environment=environment,
            method="GET",
            route="/api/users/{id}",
            status_class="2xx",
        )
        lines.append(f"omnilyzer_http_requests_total{{{labels}}} {current + index}")
    lines.extend([
        "# HELP omnilyzer_http_request_duration_seconds Request duration in seconds.",
        "# TYPE omnilyzer_http_request_duration_seconds histogram",
    ])
    service, product, environment, _app, _platform = IDENTITIES[0]
    base = dict(service=service, product=product, environment=environment, method="GET", route="/api/users/{id}", status_class="2xx")
    for bucket in BUCKETS:
        lines.append(f"omnilyzer_http_request_duration_seconds_bucket{{{_labels(**base, le=bucket)}}} {current}")
    lines.append(f"omnilyzer_http_request_duration_seconds_sum{{{_labels(**base)}}} 0.25")
    lines.append(f"omnilyzer_http_request_duration_seconds_count{{{_labels(**base)}}} {current}")
    lines.extend([
        "# HELP omnilyzer_build_info Bounded current deployment identity.",
        "# TYPE omnilyzer_build_info gauge",
    ])
    for service, product, environment, app_version, platform_version in IDENTITIES:
        lines.append(
            f"omnilyzer_build_info{{{_labels(service=service, product=product, environment=environment, app_version=app_version, platform_version=platform_version)}}} 1"
        )
    lines.extend([
        "# HELP omnilyzer_telemetry_export_failures_total Bounded telemetry export diagnostics.",
        "# TYPE omnilyzer_telemetry_export_failures_total counter",
        f"omnilyzer_telemetry_export_failures_total{{{_labels(service='valoria-api', product='valoria', environment='dev', reason='rejected')}}} 2",
        "",
    ])
    return "\n".join(lines).encode()


class Handler(BaseHTTPRequestHandler):
    """Serve only synthetic domain, health, and metrics endpoints."""

    server_version = "Task011SyntheticApp"
    sys_version = ""

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        global REQUEST_COUNT
        if self.path == "/metrics":
            self._write(200, metrics_text(), "text/plain; version=0.0.4; charset=utf-8")
            return
        if self.path == "/livez":
            self._write(200, b'{"status":"alive"}', "application/json")
            return
        if self.path == "/readyz":
            self._write(200, b'{"status":"ready"}', "application/json")
            return
        if self.path.startswith("/api/users/"):
            with LOCK:
                REQUEST_COUNT += 1
            body = json.dumps({"status": "ok"}, separators=(",", ":")).encode()
            self._write(200, body, "application/json")
            return
        self._write(404, b'{"status":"not_found"}', "application/json")

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    server.daemon_threads = True
    server.serve_forever()

