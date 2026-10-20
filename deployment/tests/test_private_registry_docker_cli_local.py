"""File: deployment/tests/test_private_registry_docker_cli_local.py

Purpose: Reproduce real Docker 29.x manifest authentication against a *mock*
OCI registry with disposable loopback TLS and synthetic credentials, testing
both the unverified registrytoken path and Docker's existing proven username
'oidc'/JWT-password login path. No external Zot or Docker daemon is contacted.
Links: deployment/private_registry_pull.py, deployment/docker_runtime.py,
deployment/tests/test_private_registry_pull.py.

Sections: mock OCI Bearer challenge, Basic-to-Bearer token exchange, disposable
TLS and Docker CLI acceptance. No GitHub OIDC request, OCI pull, containers,
live registry permission changes, service or replay/state modifications.
"""

from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from deployment.private_registry_pull import _command, _write_config

_TEST_IDENTITY = "synthetic-gh-oidc-jwt-for-local-test"
_TEST_REGISTRY_TOKEN = "synthetic-oci-registry-bearer-from-local-test"
_TEST_BASIC = "Basic " + base64.b64encode(
    ("oidc:" + _TEST_IDENTITY).encode("ascii")
).decode("ascii")
_CONFIG = json.dumps({
    "architecture": "amd64", "os": "linux", "config": {},
    "rootfs": {"type": "layers", "diff_ids": []}, "history": [],
}, sort_keys=True, separators=(",", ":")).encode("ascii")
_CONFIG_DIGEST = "sha256:" + hashlib.sha256(_CONFIG).hexdigest()
_MANIFEST = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
               "digest": _CONFIG_DIGEST, "size": len(_CONFIG)},
    "layers": [],
}, sort_keys=True, separators=(",", ":")).encode("ascii")
_DIGEST = "sha256:" + hashlib.sha256(_MANIFEST).hexdigest()


# Section 1: a private synthetic OCI v2 Bearer token service.
class _LocalOCI(BaseHTTPRequestHandler):
    """Serve metadata only, record bool auth success, never log credentials."""

    def log_message(self, _fmt: str, *args: object) -> None:
        """Suppress access logs containing requests or bearer tokens."""
        return

    def _challenge(self, *, scope: str = "") -> None:
        """Require OCI Bearer and give Docker a local synthetic token service."""
        # The challenge must never echo a peer-controlled HTTP Host header.
        # Only this test's kernel-assigned loopback socket determines realm.
        host, port = self.server.server_address
        assert host == "127.0.0.1" and type(port) is int and 1 <= port <= 65535
        realm = f"https://127.0.0.1:{port}/token"
        if scope == "":
            header = f'Bearer realm="{realm}",service="test-local-oci"'
        elif scope == "repository:test/private-canary:pull":
            header = (
                f'Bearer realm="{realm}",service="test-local-oci",'
                'scope="repository:test/private-canary:pull"'
            )
        else:
            raise AssertionError("unsupported local registry scope")
        self.send_response(401)
        self.send_header("WWW-Authenticate", header)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _get(self, head: bool = False) -> None:
        """Authenticate a Basic exchange or a scoped Bearer manifest request."""
        path = urlsplit(self.path).path
        authorization = self.headers.get("Authorization")
        basic_correct = authorization == _TEST_BASIC
        bearer_correct = authorization == "Bearer " + _TEST_REGISTRY_TOKEN
        self.server.events.append((self.command, path, basic_correct, bearer_correct))

        if path == "/token":
            if not basic_correct:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="local-oci"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            response = json.dumps({
                "token": _TEST_REGISTRY_TOKEN,
                "access_token": _TEST_REGISTRY_TOKEN,
                "expires_in": 300,
                "issued_at": "2026-10-19T10:00:00Z",
            }).encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            if not head:
                self.wfile.write(response)
            return

        if path == "/v2/":
            if not bearer_correct:
                self._challenge()
                return
            self.send_response(200)
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/v2/test/private-canary/manifests/" + _DIGEST:
            if not bearer_correct:
                self._challenge(scope="repository:test/private-canary:pull")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            self.send_header("Docker-Content-Digest", _DIGEST)
            self.send_header("Content-Length", str(len(_MANIFEST)))
            self.end_headers()
            if not head:
                self.wfile.write(_MANIFEST)
            return

        if path == "/v2/test/private-canary/blobs/" + _CONFIG_DIGEST:
            if not bearer_correct:
                self._challenge(scope="repository:test/private-canary:pull")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.oci.image.config.v1+json")
            self.send_header("Docker-Content-Digest", _CONFIG_DIGEST)
            self.send_header("Content-Length", str(len(_CONFIG)))
            self.end_headers()
            if not head:
                self.wfile.write(_CONFIG)
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle OCI registry and synthetic token GET requests."""
        self._get()

    def do_HEAD(self) -> None:
        """Handle only OCI manifest metadata requests."""
        self._get(head=True)


# Section 2: the real CLI must follow the OCI challenge and authenticate.
class DockerCLIPrivateAuthAcceptance(unittest.TestCase):
    """Observe Docker CLI only against throwaway 127.0.0.1 TLS."""

    def test_oidc_password_docker_config_exchanges_for_bearer(self) -> None:
        """Temporary Basic OIDC auth works; no token leaks to argv or stdout."""
        docker, openssl = shutil.which("docker"), shutil.which("openssl")
        if docker is None or openssl is None:
            self.skipTest("Docker CLI or disposable TLS generator unavailable")
        with tempfile.TemporaryDirectory(prefix="task014-oci-local-") as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            cert, key = parent / "local-cert.pem", parent / "local-key.pem"
            p = subprocess.run(
                [openssl, "req", "-newkey", "rsa:2048", "-x509", "-nodes",
                 "-days", "1", "-subj", "/CN=127.0.0.1",
                 "-keyout", str(key), "-out", str(cert)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=9, check=False,
            )
            self.assertEqual(p.returncode, 0)

            server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalOCI)
            server.events = []
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # The disposable server must not allow obsolete TLSv1/1.1 either.
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(cert), str(key))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host = f"127.0.0.1:{server.server_address[1]}"
                image = host + "/test/private-canary@" + _DIGEST
                # Exercise the exact production Docker auth/command builders.
                # Only the local host and Docker executable are substituted.
                with (
                    patch("deployment.private_registry_pull.ZOT_HOST", host),
                    patch("deployment.private_registry_pull.DOCKER_CLI", docker),
                ):
                    _write_config(parent, _TEST_IDENTITY)
                    argv = _command(parent, image, "manifest")
                config = parent / "config.json"
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                self.assertEqual(
                    json.loads(config.read_text())["auths"][host]["auth"],
                    _TEST_BASIC.split(" ", 1)[1],
                )
                # Only this disposable self-signed loopback cert needs
                # --insecure; the *production* command lacks the flag.
                self.assertNotIn("--insecure", argv)
                self.assertEqual(argv[-3:], ("manifest", "inspect", image))
                local_args = (*argv[:-1], "--insecure", image)
                r = subprocess.run(
                    local_args,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=15, check=False,
                    env={"HOME": str(parent), "PATH": "/usr/bin:/bin",
                         "LANG": "C.UTF-8"},
                )
                self.assertNotIn(_TEST_IDENTITY.encode(), r.stdout)
                self.assertNotIn(_TEST_IDENTITY.encode(), r.stderr)
                self.assertNotIn(_TEST_REGISTRY_TOKEN.encode(), r.stdout)
                self.assertNotIn(_TEST_REGISTRY_TOKEN.encode(), r.stderr)
                observed = list(server.events)
                exchanged = any(path == "/token" and basic for _,path,basic,_ in observed)
                authorized = any(
                    path == "/v2/test/private-canary/manifests/" + _DIGEST and bearer
                    for _,path,_,bearer in observed
                )
                diagnostic = {
                    "returncode": r.returncode,
                    "events": observed,
                    "stderr": r.stderr.decode("utf-8", "replace")[:260],
                }
                self.assertTrue(exchanged, "DOCKER_DID_NOT_EXCHANGE_BASIC " + str(diagnostic))
                self.assertTrue(authorized, "NO_SCOPED_MANIFEST_BEARER " + str(diagnostic))
                self.assertEqual(r.returncode, 0, "MANIFEST_READ_FAILED " + str(diagnostic))
                self.assertEqual(json.loads(r.stdout)["schemaVersion"], 2)
            finally:
                server.shutdown()
                thread.join(timeout=3)
                server.server_close()
        self.assertFalse(parent.exists())


if __name__ == "__main__":
    unittest.main()
