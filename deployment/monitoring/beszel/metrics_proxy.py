#!/usr/bin/env python3
# File: /opt/omnilyzer-beszel-monitor/metrics_proxy.py
# Purpose: Expose a tiny read-only Docker metrics subset to the isolated Beszel agent.
# Related: /run/user/991/docker.sock (owner-only Docker source);
#          /run/user/991/beszel-metrics.sock (restricted consumer socket);
#          beszel-omnilyzer-proxy.service, beszel-omnilyzer-agent.service.
# Security: No TCP listener, no write-capable Docker API, no logs, no inspect,
#           no exec, no arbitrary paths, no labels/env/mounts/secrets in output.
"""Narrow Docker metrics protocol adapter, using Python standard library only."""

from __future__ import annotations

import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
from urllib.parse import parse_qsl, urlsplit

# Section: Explicitly permitted Docker API paths and response limits.
CONTAINER_STATS = re.compile(r"\A/containers/([a-f0-9]{12,64})/stats\Z")
DOCKER_ID = re.compile(r"\A[a-f0-9]{64}\Z")
MAX_REPLY_BYTES = 3 * 1024 * 1024
MAX_CONTAINER_COUNT = 128
UPSTREAM_TIMEOUT = 8


class DockerUnixConnection(http.client.HTTPConnection):
    """Use the preexisting engine-owned Unix socket for fixed GET requests."""

    def __init__(self, socket_path: str):
        super().__init__("localhost", timeout=UPSTREAM_TIMEOUT)
        self.socket_path = socket_path

    def connect(self):
        """Connect to Docker without opening a network listener or TCP port."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(UPSTREAM_TIMEOUT)
        self.sock.connect(self.socket_path)


def docker_get(socket_path: str, path: str):
    """Fetch a fixed Docker GET endpoint with strict body and timeout limits."""
    conn = DockerUnixConnection(socket_path)
    try:
        conn.request("GET", path, headers={"Accept": "application/json", "Connection": "close"})
        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError("Docker returned non-200 HTTP status")
        raw = response.read(MAX_REPLY_BYTES + 1)
        if len(raw) > MAX_REPLY_BYTES:
            raise ValueError("Docker metrics response exceeds size limit")
        return json.loads(raw)
    finally:
        conn.close()


def positive_int(value):
    """Pass through a non-negative integer counter, never arbitrary JSON."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return 0
    return value


def sanitize_list(raw):
    """Remove labels, env, mounts, commands, images, IPs and other metadata."""
    if not isinstance(raw, list) or len(raw) > MAX_CONTAINER_COUNT:
        raise ValueError("Invalid Docker container list")
    result = []
    for item in raw:
        if not isinstance(item, dict) or not DOCKER_ID.fullmatch(str(item.get("Id", ""))):
            raise ValueError("Invalid Docker container identifier")
        names = item.get("Names")
        if not isinstance(names, list) or not names or not isinstance(names[0], str):
            raise ValueError("Docker container has no usable name")
        first_name = names[0]
        if not first_name.startswith("/") or len(first_name) > 120:
            raise ValueError("Invalid Docker container name")
        state = item.get("State", "")
        if state not in ("running", "paused", "restarting", "exited", "created", "dead"):
            state = "unknown"
        # Never relay Docker's unstructured status text into the dashboard.
        # Beszel accepts these synthetic status words for basic state display.
        status = {
            "running": "Up", "paused": "Paused", "restarting": "Restarting",
            "exited": "Exited", "created": "Created", "dead": "Dead",
        }.get(state, "Unknown")
        health = item.get("Health", {})
        if not isinstance(health, dict):
            health = {}
        health_status = health.get("Status", "")
        if health_status not in ("healthy", "unhealthy", "starting", "none"):
            health_status = ""
        result.append({
            "Id": item["Id"],
            "Names": [first_name],
            "State": state,
            "Status": status,
            "Health": {"Status": health_status},
            "Image": "redacted",
            "Ports": [],
        })
    return result


def sanitize_stats(raw):
    """Return only counters necessary for Beszel CPU, RAM and network graphs."""
    if not isinstance(raw, dict):
        raise ValueError("Invalid Docker resource statistics")
    cpu = raw.get("cpu_stats", {})
    mem = raw.get("memory_stats", {})
    if not isinstance(cpu, dict) or not isinstance(mem, dict):
        raise ValueError("Invalid CPU or memory structure")
    usage = cpu.get("cpu_usage", {})
    mem_fields = mem.get("stats", {})
    if not isinstance(usage, dict) or not isinstance(mem_fields, dict):
        raise ValueError("Invalid CPU usage or memory cache")
    networks = raw.get("networks", {})
    if not isinstance(networks, dict):
        networks = {}
    networks_sanitized = {}
    for index, entry in enumerate(networks.values()):
        if not isinstance(entry, dict) or index >= 32:
            continue
        networks_sanitized[f"if{index}"] = {
            "rx_bytes": positive_int(entry.get("rx_bytes")),
            "tx_bytes": positive_int(entry.get("tx_bytes")),
        }
    return {
        "read": raw.get("read") if isinstance(raw.get("read"), str) else "",
        "cpu_stats": {
            "cpu_usage": {"total_usage": positive_int(usage.get("total_usage"))},
            "system_cpu_usage": positive_int(cpu.get("system_cpu_usage")),
            "online_cpus": positive_int(cpu.get("online_cpus")),
        },
        "memory_stats": {
            "usage": positive_int(mem.get("usage")),
            "stats": {
                "cache": positive_int(mem_fields.get("cache")),
                "inactive_file": positive_int(mem_fields.get("inactive_file")),
            },
        },
        "networks": networks_sanitized,
    }


def sanitize_info(raw):
    """Provide only the minimal host metadata consumed by Beszel."""
    if not isinstance(raw, dict):
        raise ValueError("Invalid Docker info payload")
    return {
        "OperatingSystem": str(raw.get("OperatingSystem", ""))[:100],
        "KernelVersion": str(raw.get("KernelVersion", ""))[:100],
        "NCPU": positive_int(raw.get("NCPU")),
        "MemTotal": positive_int(raw.get("MemTotal")),
    }


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """Reject every HTTP operation except the exact Beszel metrics reads."""

    protocol_version = "HTTP/1.1"
    server_version = "BeszelMetricsProxy"
    sys_version = ""

    def log_message(self, format_string, *args):
        """Do not log untrusted request contents or Docker metadata."""
        return

    def respond(self, status: int, payload):
        """Send a bounded JSON reply and close the local client connection."""
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(body) > MAX_REPLY_BYTES:
            status, body = 502, b'{"error":"response too large"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        # A client that disconnects early must not produce a traceback
        # containing untrusted HTTP input or flood service logs.
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.close_connection = True

    def do_GET(self):
        """Route only version, list, info and running-container counters."""
        try:
            raw_target = self.path
            if not raw_target.isascii() or "%" in raw_target or "\\" in raw_target:
                self.respond(404, {"error": "not found"})
                return
            url = urlsplit(raw_target)
            if url.scheme or url.netloc or url.fragment:
                self.respond(404, {"error": "not found"})
                return
            path = url.path
            query = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
            if path == "/version" and not query:
                obj = docker_get(self.server.docker_socket, "/version")
                self.respond(200, {"Version": str(obj.get("Version", ""))[:40]})
                return
            if path == "/info" and not query:
                self.respond(200, sanitize_info(docker_get(self.server.docker_socket, "/info")))
                return
            if path == "/containers/json" and not query:
                self.respond(200, sanitize_list(docker_get(self.server.docker_socket, "/containers/json")))
                return
            match = CONTAINER_STATS.fullmatch(path)
            if match and sorted(query) == [("one-shot", "1"), ("stream", "0")]:
                container_prefix = match.group(1)
                known = sanitize_list(docker_get(self.server.docker_socket, "/containers/json"))
                eligible = [x["Id"] for x in known if x["Id"].startswith(container_prefix)]
                if len(eligible) != 1:
                    self.respond(404, {"error": "not found"})
                    return
                docker_path = f"/containers/{eligible[0]}/stats?stream=0&one-shot=1"
                self.respond(200, sanitize_stats(docker_get(self.server.docker_socket, docker_path)))
                return
            self.respond(404, {"error": "not found"})
        except (ValueError, TypeError):
            self.respond(404, {"error": "bad metrics request"})
        except (OSError, RuntimeError, json.JSONDecodeError):
            self.respond(502, {"error": "metrics backend unavailable"})

    def do_POST(self):
        """Explicitly reject writes to Docker, including create and exec."""
        self.respond(405, {"error": "method not allowed"})

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST

    def do_HEAD(self):
        """Deny HEAD without a response body, as HTTP requires."""
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True


class UnixMetricsServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Accept metrics requests only on an owner-private Unix socket."""

    daemon_threads = True
    request_queue_size = 16
    allow_reuse_address = False

    def __init__(self, path: str, docker_socket: str):
        self.docker_socket = docker_socket
        super().__init__(path, ProxyHandler)


def verify_socket_path(path: Path, *, require_existing: bool):
    """Reject paths outside the private user runtime directory and symlinks."""
    expected_parent = Path(f"/run/user/{os.getuid()}")
    expected_name = "docker.sock" if require_existing else "beszel-metrics.sock"
    if path.parent != expected_parent or path.name != expected_name:
        raise RuntimeError("Unexpected engine or proxy socket path")
    st = expected_parent.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError("Runtime directory is not private")
    if require_existing:
        socket_stat = path.lstat()
        if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != os.getuid():
            raise RuntimeError("Docker socket type or ownership invalid")


def main():
    """Create a restricted Unix endpoint for Beszel; never bind a TCP port."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-socket", required=True)
    parser.add_argument("--listen-socket", required=True)
    args = parser.parse_args()
    if os.getuid() == 0:
        raise RuntimeError("Refusing to run Docker metrics proxy as root")
    docker_socket = Path(args.docker_socket)
    listen_socket = Path(args.listen_socket)
    verify_socket_path(docker_socket, require_existing=True)
    verify_socket_path(listen_socket, require_existing=False)
    if listen_socket == docker_socket:
        raise RuntimeError("Refusing to replace Docker engine socket")
    if listen_socket.exists() or listen_socket.is_symlink():
        # Section: Recover an abandoned socket without deleting another service.
        existing = listen_socket.lstat()
        if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid():
            raise RuntimeError("Refusing to overwrite non-owned or non-socket path")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(1)
        try:
            probe.connect(str(listen_socket))
        except ConnectionRefusedError:
            listen_socket.unlink()  # Exact path, owner-only parent, stale socket.
        else:
            raise RuntimeError("A Docker metrics proxy is already listening")
        finally:
            probe.close()
    os.umask(0o077)
    try:
        with UnixMetricsServer(str(listen_socket), str(docker_socket)) as server:
            os.chmod(listen_socket, 0o600)
            print("BESZEL_METRICS_PROXY_READY", flush=True)
            server.serve_forever(poll_interval=0.5)
    finally:
        if listen_socket.is_socket() and listen_socket.stat().st_uid == os.getuid():
            listen_socket.unlink()


if __name__ == "__main__":
    main()
