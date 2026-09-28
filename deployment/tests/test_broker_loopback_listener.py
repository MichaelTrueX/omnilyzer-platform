"""C32R strict one-connection listener tests; all sockets are fake."""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

import deployment.broker_loopback_listener as listener_module
from deployment.application_source_set import DevApplicationSourceSet
from deployment.broker_https_ingress import (
    BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT, FORGEJO_OIDC_HEADER,
    IngressResponse, PROMOTION_PATH, ZOT_OIDC_HEADER,
)
from deployment.broker_loopback_listener import (
    ACCEPT_TIMEOUT_SECONDS, LISTEN_BACKLOG, MAX_HEADER_BYTES,
    READ_TIMEOUT_SECONDS, WRITE_TIMEOUT_SECONDS,
    BrokerLoopbackListenerError, DevBrokerLoopbackListener,
)


ROOT = Path(__file__).resolve().parents[2]
BODY = b'{"opaque":"canonical-validation-belongs-to-C32P"}\n'
TOKENS = ("deploy.jwt.sig", "zot.jwt.sig", "forgejo.jwt.sig")


def wire(*, method=b"POST", path=PROMOTION_PATH.encode(), version=b"HTTP/1.0",
         body=BODY, extra=(), content_length=None, connection=b"close"):
    fields = [
        (b"Host", b"deploy-dev.omnilyzer.ai"),
        (b"Authorization", b"Bearer " + TOKENS[0].encode()),
        (ZOT_OIDC_HEADER.encode(), TOKENS[1].encode()),
        (FORGEJO_OIDC_HEADER.encode(), TOKENS[2].encode()),
        (b"Content-Type", b"application/json"),
        (b"Content-Length", str(len(body)).encode() if content_length is None else content_length),
        (b"Connection", connection),
    ]
    fields.extend(extra)
    return (method + b" " + path + b" " + version + b"\r\n"
            + b"".join(name + b": " + value + b"\r\n" for name, value in fields)
            + b"\r\n" + body)


class FakeConnection:
    def __init__(self, chunks, *, short_writes=False, close_error=False):
        self.family = socket.AF_INET
        self.type = socket.SOCK_STREAM
        self.chunks = list(chunks)
        self.short_writes = short_writes
        self.close_error = close_error
        self.sent = bytearray()
        self.read_sizes = []
        self.timeouts = []
        self.closed = False
        self.inheritable = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, size):
        self.read_sizes.append(size)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def send(self, data):
        count = min(len(data), 3) if self.short_writes else len(data)
        self.sent.extend(data[:count])
        return count

    def set_inheritable(self, value):
        self.inheritable = value

    def get_inheritable(self):
        return self.inheritable

    def close(self):
        self.closed = True
        if self.close_error:
            raise OSError("private close detail")


class FakeServer:
    def __init__(self, connection, *, peer=("127.0.0.1", 44902), close_error=False):
        self.family = socket.AF_INET
        self.type = socket.SOCK_STREAM
        self.connection = connection
        self.peer = peer
        self.close_error = close_error
        self.calls = []
        self.closed = False
        self.inheritable = False

    def set_inheritable(self, value):
        self.inheritable = value

    def get_inheritable(self):
        return self.inheritable

    def setsockopt(self, *args):
        self.calls.append(("setsockopt", args))

    def bind(self, address):
        self.calls.append(("bind", address))

    def getsockname(self):
        return (BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT)

    def listen(self, backlog):
        self.calls.append(("listen", backlog))

    def settimeout(self, value):
        self.calls.append(("timeout", value))

    def accept(self):
        self.calls.append(("accept",))
        return self.connection, self.peer

    def close(self):
        self.closed = True
        if self.close_error:
            raise OSError("private server close detail")


class Handler:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def handle(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return b"opaque"


def fixture(raw=None, *, chunks=None, handler=None, peer=("127.0.0.1", 44902),
            short_writes=False, close_error=False, server_close_error=False,
            wall_clock=None, monotonic=None):
    if raw is None:
        raw = wire()
    connection = FakeConnection([raw] if chunks is None else chunks,
                                short_writes=short_writes, close_error=close_error)
    server = FakeServer(connection, peer=peer, close_error=server_close_error)
    calls = []

    def factory(family, kind):
        calls.append((family, kind))
        return server

    handler = handler or Handler()
    listener = DevBrokerLoopbackListener(
        handler, socket_factory=factory,
        wall_clock=wall_clock or (lambda: 123.75),
        monotonic=monotonic or (lambda: 1.0),
    )
    return listener, server, connection, handler, calls


class BrokerLoopbackListenerTests(unittest.TestCase):
    def test_inert_construction_exact_bind_and_cleanup(self):
        listener, server, connection, handler, calls = fixture()
        self.assertEqual(calls, [])
        self.assertEqual(server.calls, [])
        self.assertEqual(listener.serve_once(), 202)
        self.assertEqual(calls, [(socket.AF_INET, socket.SOCK_STREAM)])
        self.assertEqual(server.calls[:3], [
            ("setsockopt", (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)),
            ("bind", ("127.0.0.1", 3031)), ("listen", LISTEN_BACKLOG),
        ])
        self.assertEqual(LISTEN_BACKLOG, 2)
        self.assertIn(("timeout", ACCEPT_TIMEOUT_SECONDS), server.calls)
        self.assertTrue(server.closed)
        self.assertTrue(connection.closed)
        self.assertEqual(handler.calls[0]["received_at"], 123)
        self.assertEqual(handler.calls[0]["promotion_request"], BODY)
        self.assertEqual((handler.calls[0]["compact_token"],
                          handler.calls[0]["zot_token"],
                          handler.calls[0]["forgejo_token"]), TOKENS)

    def test_fragmentation_short_writes_and_separate_timeouts(self):
        raw = wire()
        parts = [raw[:1], raw[1:12], raw[12:50], raw[50:-4], raw[-4:]]
        listener, _, connection, _, _ = fixture(chunks=parts, short_writes=True)
        self.assertEqual(listener.serve_once(), 202)
        self.assertTrue(all(1 <= size <= 4096 for size in connection.read_sizes))
        self.assertIn(None, connection.timeouts)  # framing timeout removed for handler
        self.assertIn(READ_TIMEOUT_SECONDS, connection.timeouts)
        self.assertIn(WRITE_TIMEOUT_SECONDS, connection.timeouts)
        response = bytes(connection.sent)
        self.assertTrue(response.startswith(b"HTTP/1.0 202 Accepted\r\n"))
        self.assertIn(b"Content-Length: 22\r\n", response)
        self.assertIn(b"Cache-Control: no-store\r\nConnection: close\r\n", response)
        self.assertTrue(response.endswith(b'{"status":"accepted"}\n'))
        for forbidden in (b"Server:", b"Date:", b"Set-Cookie:", b"Location:",
                          b"Access-Control-Allow-Origin:", b"WWW-Authenticate:"):
            self.assertNotIn(forbidden, response)

    def test_clock_sampled_after_complete_request(self):
        connection = None

        def clock():
            self.assertEqual(connection.chunks, [])
            return 123.99

        listener, _, connection, handler, _ = fixture(
            chunks=[wire()[:-3], wire()[-3:]], wall_clock=clock)
        self.assertEqual(listener.serve_once(), 202)
        self.assertEqual(handler.calls[0]["received_at"], 123)

    def test_wrong_peer_fails_closed_and_closes(self):
        listener, server, connection, handler, _ = fixture(peer=("10.0.0.1", 12345))
        with self.assertRaises(BrokerLoopbackListenerError):
            listener.serve_once()
        self.assertTrue(server.closed and connection.closed)
        self.assertEqual(handler.calls, [])
        self.assertEqual(connection.sent, b"")

    def test_wrong_socket_kind_and_reentrant_serve_rejected(self):
        listener, server, connection, handler, _ = fixture()
        server.family = socket.AF_UNIX
        with self.assertRaises(BrokerLoopbackListenerError):
            listener.serve_once()
        self.assertTrue(server.closed)
        self.assertFalse(connection.closed)  # no accept occurred

        class Reentrant:
            def __init__(self):
                self.listener = None
                self.rejected = False

            def handle(self, **kwargs):
                with self_assert.assertRaises(BrokerLoopbackListenerError):
                    self.listener.serve_once()
                self.rejected = True
                return b"opaque"

        self_assert = self
        reentrant = Reentrant()
        listener, server, connection, _, calls = fixture(handler=reentrant)
        reentrant.listener = listener
        self.assertEqual(listener.serve_once(), 202)
        self.assertTrue(reentrant.rejected)
        self.assertEqual(len(calls), 1)
        self.assertTrue(server.closed and connection.closed)

    def test_malformed_framing_returns_fixed_403_without_handler(self):
        mutations = (
            wire(method=b"GET"), wire(method=b"post"),
            wire(version=b"HTTP/1.1"), wire(version=b"HTTP/2"),
            wire(path=b"/task014/dev/promote?x=1"),
            wire(path=b"http://127.0.0.1:3031/task014/dev/promote"),
            wire().replace(b"\r\n", b"\n", 1),
            wire(extra=((b"Upgrade", b"websocket"),)),
            wire(extra=((b"Transfer-Encoding", b"chunked"),)),
            wire(extra=((b"TE", b"trailers"),)),
            wire(extra=((b"Keep-Alive", b"timeout=5"),)),
            wire(extra=((b"Connection", b"close"),)),
            wire(connection=b"keep-alive"),
            wire(content_length=b"0003"),
            wire(content_length=b"4097"),
            wire(body=BODY[:-1], content_length=str(len(BODY)).encode()),
            wire() + b"NEXT",  # already-buffered pipelining
            wire().replace(b"Authorization: ", b"Authorization : "),
            wire().replace(b"Host: ", b" Host: "),
            wire().replace(b"Host: ", b"Host:\t"),
            wire().replace(b"\r\nAuthorization", b"\r\n\tAuthorization"),
        )
        for raw in mutations:
            with self.subTest(raw=raw[:60]):
                listener, server, connection, handler, _ = fixture(raw)
                self.assertEqual(listener.serve_once(), 403)
                self.assertEqual(handler.calls, [])
                self.assertTrue(server.closed and connection.closed)
                self.assertNotIn(TOKENS[0].encode(), connection.sent)
                self.assertTrue(connection.sent.endswith(b'{"status":"rejected"}\n'))

    def test_duplicate_credentials_reach_c32q_and_are_rejected(self):
        for name, value in ((b"Authorization", b"Bearer duplicate.jwt.sig"),
                            (ZOT_OIDC_HEADER.encode(), b"duplicate.jwt.sig"),
                            (FORGEJO_OIDC_HEADER.encode(), b"duplicate.jwt.sig")):
            listener, _, connection, handler, _ = fixture(
                wire(extra=((name, value),)))
            self.assertEqual(listener.serve_once(), 403)
            self.assertEqual(handler.calls, [])
            self.assertNotIn(b"duplicate.jwt.sig", connection.sent)

    def test_raw_semantic_header_order_and_body_cross_dispatch(self):
        seen = []

        def dispatch(handler, **kwargs):
            seen.append(kwargs)
            return IngressResponse(202, b'{"status":"accepted"}\n')

        listener, _, _, _, _ = fixture()
        with patch.object(listener_module, "dispatch_inert_dev_promotion_ingress", dispatch):
            self.assertEqual(listener.serve_once(), 202)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["method"], "POST")
        self.assertEqual(seen[0]["path"], PROMOTION_PATH)
        self.assertEqual(seen[0]["body"], BODY)
        self.assertEqual(seen[0]["received_at"], 123)
        self.assertEqual([name for name, _ in seen[0]["headers"]], [
            "Host", "Authorization", ZOT_OIDC_HEADER, FORGEJO_OIDC_HEADER,
            "Content-Type", "Content-Length",
        ])

    def test_header_and_body_bounds(self):
        self.assertEqual(MAX_HEADER_BYTES, 3 * 16 * 1024 + 1024)
        maximum = b"x" * (16 * 1024)
        valid = wire().replace(b"deploy.jwt.sig", maximum).replace(
            b"zot.jwt.sig", maximum).replace(b"forgejo.jwt.sig", maximum)
        listener, _, connection, handler, _ = fixture(valid)
        self.assertEqual(listener.serve_once(), 202)
        self.assertEqual(len(handler.calls[0]["compact_token"]), 16 * 1024)
        self.assertTrue(connection.closed)
        oversized_token = wire().replace(b"zot.jwt.sig", b"x" * (16 * 1024 + 1))
        listener, _, _, handler, _ = fixture(oversized_token)
        self.assertEqual(listener.serve_once(), 403)
        self.assertEqual(handler.calls, [])
        oversized_header = wire().replace(b"deploy.jwt.sig", b"x" * (16 * 1024 + 8))
        listener, _, _, handler, _ = fixture(oversized_header)
        self.assertEqual(listener.serve_once(), 403)
        self.assertEqual(handler.calls, [])
        for raw in (b"A" * (MAX_HEADER_BYTES + 1),
                    wire(extra=((b"X-Extra", b"a" * MAX_HEADER_BYTES),)),
                    wire(extra=tuple((b"X-Extra", b"x") for _ in range(3))),
                    wire(body=b"x" * 4097)):
            listener, _, connection, handler, _ = fixture(raw)
            self.assertEqual(listener.serve_once(), 403)
            self.assertEqual(handler.calls, [])
            self.assertTrue(connection.closed)

    def test_timeout_handler_error_and_cleanup_failure(self):
        listener, _, connection, handler, _ = fixture(chunks=[TimeoutError()])
        self.assertEqual(listener.serve_once(), 503)
        self.assertEqual(handler.calls, [])
        self.assertTrue(connection.closed)
        samples = iter((2.0, 1.0))
        listener, _, connection, handler, _ = fixture(monotonic=lambda: next(samples))
        with self.assertRaises(BrokerLoopbackListenerError):
            listener.serve_once()
        self.assertEqual(handler.calls, [])
        self.assertTrue(connection.closed)
        listener, _, connection, handler, _ = fixture(wall_clock=lambda: True)
        self.assertEqual(listener.serve_once(), 503)
        self.assertEqual(handler.calls, [])
        self.assertTrue(connection.closed)
        listener, _, connection, _, _ = fixture()
        connection.send = lambda data: (_ for _ in ()).throw(TimeoutError())
        with self.assertRaises(BrokerLoopbackListenerError):
            listener.serve_once()
        self.assertTrue(connection.closed)
        listener, _, connection, _, _ = fixture(handler=Handler(RuntimeError("secret")))
        self.assertEqual(listener.serve_once(), 503)
        self.assertNotIn(b"secret", connection.sent)
        listener, _, connection, _, _ = fixture(close_error=True)
        with self.assertRaisesRegex(BrokerLoopbackListenerError,
                                    "^deployment listener is unavailable$"):
            listener.serve_once()
        self.assertTrue(connection.closed)
        listener, server, connection, _, _ = fixture(server_close_error=True)
        with self.assertRaises(BrokerLoopbackListenerError):
            listener.serve_once()
        self.assertTrue(server.closed and connection.closed)

    def test_nginx_review_and_nonlive_repository_contract(self):
        config = (ROOT / "deployment/ingress/dev-broker-https.nginx.review.conf").read_text()
        for required in ("proxy_http_version 1.0;", "proxy_set_header Connection close;",
                         "proxy_pass_request_headers off;",
                         "proxy_pass http://127.0.0.1:3031;",
                         'if ($http_authorization ~ ",") { return 400; }',
                         'if ($http_x_omnilyzer_zot_oidc ~ ",") { return 400; }',
                         'if ($http_x_omnilyzer_forgejo_oidc ~ ",") { return 400; }'):
            self.assertIn(required, config)
        self.assertNotIn("ssl_certificate /", config)
        self.assertIn("review-only", config)
        documentation = (ROOT / "deployment/README.md").read_text()
        self.assertIn("1.23.0", documentation)
        self.assertIn("real duplicate-header probe", documentation)
        source = (ROOT / "deployment/broker_loopback_listener.py").read_text()
        imports = {node.module for node in ast.walk(ast.parse(source))
                   if isinstance(node, ast.ImportFrom)}
        self.assertNotIn("http.server", imports)
        for forbidden in ("SO_REUSEPORT", "getaddrinfo", "__main__", "logging."):
            self.assertNotIn(forbidden, source)
        self.assertEqual(tuple(inspect.signature(DevBrokerLoopbackListener).parameters),
                         ("handler", "socket_factory", "wall_clock", "monotonic"))
        environment = json.loads((ROOT / "deployment/environments/dev.json").read_text())
        self.assertIs(environment["activation"]["deployment_enabled"], False)
        selected = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(selected), 41)
        self.assertIn("deployment/broker_loopback_listener.py", selected)


if __name__ == "__main__":
    unittest.main()
