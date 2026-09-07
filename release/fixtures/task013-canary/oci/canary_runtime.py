"""Bounded standard-library HTTP runtime for Task 014 deployment validation."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
from typing import Mapping
from urllib.parse import urlsplit

from migration import DEFINITION_PATH, MARKER_PATH, MigrationError, validate_marker


VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
CONFIG_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
MAX_RESPONSE_BYTES = 1024


class CanaryConfigurationError(ValueError):
    pass


class CanaryApplication:
    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        marker_path: Path = MARKER_PATH,
        definition_path: Path = DEFINITION_PATH,
    ) -> None:
        self.environ = dict(os.environ if environ is None else environ)
        self.marker_path = marker_path
        self.definition_path = definition_path
        self.release_version = self.environ.get("CANARY_RELEASE_VERSION", "")
        self.source_sha = self.environ.get("CANARY_SOURCE_SHA", "")
        if VERSION_RE.fullmatch(self.release_version) is None:
            raise CanaryConfigurationError("embedded release version is invalid")
        if (SOURCE_SHA_RE.fullmatch(self.source_sha) is None
                or self.source_sha == "0" * 40):
            raise CanaryConfigurationError("embedded source SHA is invalid")

    def _dependency_ready(self) -> bool:
        required = self.environ.get("CANARY_DEPENDENCY_REQUIRED", "false")
        if required == "false":
            return True
        if required != "true":
            return False
        host = self.environ.get("CANARY_DEPENDENCY_HOST", "")
        port = self.environ.get("CANARY_DEPENDENCY_PORT", "")
        if HOST_RE.fullmatch(host) is None or not port.isascii() or not port.isdecimal():
            return False
        number = int(port)
        if not 1 <= number <= 65535:
            return False
        try:
            with socket.create_connection((host, number), timeout=1):
                return True
        except OSError:
            return False

    def readiness(self) -> tuple[bool, dict[str, bool]]:
        config_id = self.environ.get("CANARY_RUNTIME_CONFIG_ID", "")
        checks = {
            "runtime_configuration": CONFIG_ID_RE.fullmatch(config_id) is not None,
            "migration": False,
            "dependency": self._dependency_ready(),
        }
        try:
            checks["migration"] = validate_marker(self.marker_path, self.definition_path)
        except (MigrationError, OSError):
            checks["migration"] = False
        return all(checks.values()), checks

    def response(self, target: str) -> tuple[int, dict[str, object]]:
        parsed = urlsplit(target)
        if parsed.query or parsed.fragment:
            return 404, {"error": "not_found"}
        if parsed.path == "/livez":
            return 200, {"live": True}
        if parsed.path == "/readyz":
            ready, checks = self.readiness()
            return (200 if ready else 503), {"checks": checks, "ready": ready}
        if parsed.path == "/metadata":
            return 200, {
                "canary": True,
                "release_version": self.release_version,
                "source_sha": self.source_sha,
            }
        return 404, {"error": "not_found"}


def handler(application: CanaryApplication) -> type[BaseHTTPRequestHandler]:
    class CanaryHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            status, value = application.response(self.path)
            payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            if len(payload) > MAX_RESPONSE_BYTES:
                raise RuntimeError("canary response exceeded its fixed bound")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    return CanaryHandler


def main() -> None:
    application = CanaryApplication()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), handler(application))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
