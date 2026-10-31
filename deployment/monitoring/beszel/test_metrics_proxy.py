#!/usr/bin/env python3
# File: deployment/monitoring/beszel/test_metrics_proxy.py
# Purpose: Validate the metrics-only Docker proxy and its negative security cases.
# Related: metrics_proxy.py, beszel-omnilyzer-proxy.service and beszel-omnilyzer-agent.service.
"""Standard-library tests for Docker API minimization and fail-closed routing."""

import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

import metrics_proxy as proxy

FAKE_ID = "1a" * 32
FAKE_CONTAINER = {
    "Id": FAKE_ID,
    "Names": ["/sumlaude-api"],
    "State": "running",
    "Status": "Up 11 hours (private-status-leak)",
    "Image": "registry.local/very-private-image:secret",
    "Labels": {"secret": "private-label"},
    "Command": "./private-script.sh --password=oops",
    "Mounts": [{"Source": "/secrets/private-file"}],
    "Ports": [{"IP": "127.0.0.1", "PublicPort": 45000}],
    "Health": {"Status": "healthy"},
}
FAKE_STATS = {
    "read": "2026-10-31T09:00:00Z",
    "cpu_stats": {"cpu_usage": {"total_usage": 5000}, "system_cpu_usage": 100000, "online_cpus": 4, "secret": "SECRET"},
    "memory_stats": {"usage": 123000, "stats": {"inactive_file": 1000, "cache": 2000, "other": "SECRET"}},
    "networks": {"veth-secret": {"rx_bytes": 400, "tx_bytes": 500, "private": "SECRET"}},
    "secret": "SECRET",
}
BACKEND_RESPONSES = {
    "/version": {"Version": "29.8.1", "ApiVersion": "1.51", "Secret": "SECRET"},
    "/info": {"OperatingSystem": "Linux", "KernelVersion": "6.8", "NCPU": 8, "MemTotal": 10000, "Env": "SECRET"},
    "/containers/json": [FAKE_CONTAINER],
    f"/containers/{FAKE_ID}/stats?stream=0&one-shot=1": FAKE_STATS,
}


class UnixHTTPConnection(http.client.HTTPConnection):
    """Exercise the proxy using its real Unix stream without TCP exposure."""
    def __init__(self, socket_path):
        super().__init__("localhost", timeout=3)
        self.socket_path = socket_path

    def connect(self):
        """Connect to the private test server Unix socket."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(self.socket_path)


class ProxyTests(unittest.TestCase):
    """Confirm only safe and expected Beszel API messages can leave proxy."""

    def setUp(self):
        """Start one throwaway local Unix socket without touching real Docker."""
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "proxy.sock")
        self.calls = []
        self.patcher = mock.patch.object(proxy, "docker_get", side_effect=self.mock_docker_get)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.server = proxy.UnixMetricsServer(self.path, "/does-not-exist.sock")
        self.addCleanup(self.server.server_close)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        """Stop worker and ensure no background thread survives the test."""
        self.server.shutdown()
        self.worker.join(timeout=3)
        self.assertFalse(self.worker.is_alive())

    def mock_docker_get(self, _socket_path, api_path):
        """Allow only explicitly enumerated fake Docker API responses."""
        self.calls.append(api_path)
        if api_path not in BACKEND_RESPONSES:
            raise AssertionError("Unexpected upstream Docker request: " + api_path)
        return BACKEND_RESPONSES[api_path]

    def call(self, method, path):
        """Call the actual proxy HTTP handler and return its filtered JSON."""
        conn = UnixHTTPConnection(self.path)
        try:
            conn.request(method, path)
            response = conn.getresponse()
            body = response.read()
            return response.status, json.loads(body) if body else None
        finally:
            conn.close()

    def test_read_only_minimal_version_and_info(self):
        """Expose only version number and safe system totals."""
        code, data = self.call("GET", "/version")
        self.assertEqual(code, 200)
        self.assertEqual(data, {"Version": "29.8.1"})
        code, data = self.call("GET", "/info")
        self.assertEqual(code, 200)
        self.assertEqual(set(data), {"OperatingSystem", "KernelVersion", "NCPU", "MemTotal"})
        self.assertNotIn("SECRET", json.dumps(data))

    def test_list_excludes_sensitive_metadata(self):
        """Hide labels, image coordinates, port/IP, mount and CLI arguments."""
        code, data = self.call("GET", "/containers/json")
        self.assertEqual(code, 200)
        self.assertEqual(data[0]["Id"], FAKE_ID)
        self.assertEqual(data[0]["Names"], ["/sumlaude-api"])
        self.assertEqual(data[0]["Status"], "Up")
        for private in ("SECRET", "private-label", "very-private", "private-file", "45000", "oops", "private-status-leak"):
            self.assertNotIn(private, json.dumps(data))

    def test_stats_counters_only(self):
        """Expose CPU, memory and network bytes without interface identities."""
        code, data = self.call("GET", f"/containers/{FAKE_ID[:12]}/stats?stream=0&one-shot=1")
        self.assertEqual(code, 200)
        self.assertEqual(data["cpu_stats"]["cpu_usage"]["total_usage"], 5000)
        self.assertEqual(data["memory_stats"]["usage"], 123000)
        self.assertEqual(data["networks"], {"if0": {"rx_bytes": 400, "tx_bytes": 500}})
        self.assertNotIn("SECRET", json.dumps(data))
        self.assertNotIn("veth-secret", json.dumps(data))
        self.assertEqual(self.calls, ["/containers/json", f"/containers/{FAKE_ID}/stats?stream=0&one-shot=1"])

    def test_denies_every_mutation_and_private_endpoint(self):
        """Never forward create, stop, exec, logs, inspect, image or volume API."""
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
            status, _ = self.call(method, "/containers/create")
            self.assertEqual(status, 405)
        for path in (
            "/containers/create", f"/containers/{FAKE_ID}/json", f"/containers/{FAKE_ID}/logs",
            "/images/json", "/secrets", "/containers/json?all=1",
            f"/containers/{FAKE_ID[:12]}/stats?stream=1&one-shot=1",
            f"/containers/{FAKE_ID[:12]}/stats?stream=0&one-shot=0",
            f"/containers/{'2b'*12}/stats?stream=0&one-shot=1",
            "/containers/%2E%2E/secret", "/containers/../secret", "/containers/json?filters=secret",
        ):
            status, _ = self.call("GET", path)
            self.assertEqual(status, 404, path)
        self.assertEqual(self.calls.count("/containers/json"), 1)

    def test_fails_closed_on_invalid_list_and_backend_failure(self):
        """Never emit raw data if Docker schema is invalid or unreachable."""
        with mock.patch.object(proxy, "docker_get", return_value=[{"Id": "BAD", "Labels": {"secret": "LEAK"}}]):
            status, data = self.call("GET", "/containers/json")
            self.assertEqual(status, 404)
            self.assertNotIn("LEAK", json.dumps(data))
        with mock.patch.object(proxy, "docker_get", side_effect=OSError("SECRET")):
            status, data = self.call("GET", "/containers/json")
            self.assertEqual(status, 502)
            self.assertNotIn("SECRET", json.dumps(data))

    def test_rejects_ambiguous_ids_and_unbounded_payload(self):
        """Reject id prefixes and oversized container inventory."""
        self.assertEqual(self.call("GET", f"/containers/{FAKE_ID[:11]}/stats?stream=0&one-shot=1")[0], 404)
        self.assertEqual(self.call("GET", f"/containers/{FAKE_ID[:12]}/stats?stream=0&one-shot=2")[0], 404)
        with mock.patch.object(proxy, "docker_get", return_value=[FAKE_CONTAINER] * (proxy.MAX_CONTAINER_COUNT + 1)):
            self.assertEqual(self.call("GET", "/containers/json")[0], 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
