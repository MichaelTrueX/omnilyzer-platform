"""Hostile tests for the inert bounded Unix executor connection handler."""

from __future__ import annotations

import ast
import inspect
import math
import os
from pathlib import Path
import socket
import struct
import unittest
from unittest.mock import patch

from deployment.broker import MAX_EXECUTOR_RESPONSE_BYTES
from deployment.execution import MAX_CANONICAL_REQUEST_BYTES
import deployment.executor_server as server_module
from deployment.executor_server import (
    EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE,
    ExecutorConnectionUnavailableError,
    UnixExecutorConnectionHandler,
)
from deployment.unix_transport import MAX_TIMEOUT_MS


ROOT = Path(__file__).resolve().parents[2]
PEER = struct.Struct("=iII")
REQUEST = b"exact-canonical-executor-request"
REQUEST_FRAME = len(REQUEST).to_bytes(4, "big") + REQUEST
REQUEST_HASH = "a" * 64
RESPONSE = (
    b'{"executor_request_sha256":"' + REQUEST_HASH.encode("ascii")
    + b'","schema_version":1,"status":"succeeded"}\n'
)
RESPONSE_FRAME = len(RESPONSE).to_bytes(4, "big") + RESPONSE


class Executor:
    def __init__(self, response: object = RESPONSE) -> None:
        self.response = response
        self.calls: list[bytes] = []
        self.on_execute: object = None

    def execute(self, canonical_request: bytes) -> bytes:
        self.calls.append(canonical_request)
        if self.on_execute is not None:
            self.on_execute()  # type: ignore[operator]
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response  # type: ignore[return-value]


class Clock:
    def __init__(self, values: list[object] | None = None, step: float = 0.001) -> None:
        self.values = list(values or [])
        self.current = 100.0
        self.step = step
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        if self.values:
            return self.values.pop(0)
        value = self.current
        self.current += self.step
        return value


class FakeConnection:
    def __init__(
        self, request: bytes = REQUEST_FRAME, *, peer: object | None = None,
        domain: object = int(socket.AF_UNIX), kind: object = int(socket.SOCK_STREAM),
        inheritable: object = False, send_chunk: int | None = None,
    ) -> None:
        self.receives = bytearray(request)
        self.peer = PEER.pack(os.getpid(), os.getuid(), os.getgid()) if peer is None else peer
        self.domain = domain
        self.kind = kind
        self.inheritable = inheritable
        self.send_chunk = send_chunk
        self.sent = bytearray()
        self.recv_sizes: list[int] = []
        self.timeouts: list[float] = []
        self.shutdowns: list[int] = []
        self.closed = False
        self.close_calls = 0
        self.eof_observed = False
        self.failures: dict[str, BaseException] = {}
        self.interrupts: dict[str, int] = {}

    def _before(self, name: str) -> None:
        remaining = self.interrupts.get(name, 0)
        if remaining:
            self.interrupts[name] = remaining - 1
            raise InterruptedError(f"{name}-eintr-marker")
        error = self.failures.get(name)
        if error is not None:
            raise error

    def get_inheritable(self) -> object:
        self._before("get_inheritable")
        return self.inheritable

    def getsockopt(self, level: int, option: int, size: int | None = None) -> object:
        self._before("getsockopt")
        if level != socket.SOL_SOCKET:
            raise AssertionError("unexpected socket level")
        if option == socket.SO_DOMAIN:
            return self.domain
        if option == socket.SO_TYPE:
            return self.kind
        if option == socket.SO_PEERCRED:
            return self.peer
        raise AssertionError("unexpected socket option")

    def settimeout(self, value: float) -> None:
        self._before("settimeout")
        self.timeouts.append(value)

    def recv(self, size: int) -> bytes:
        self._before("recv")
        self.recv_sizes.append(size)
        if not self.receives:
            self.eof_observed = True
            return b""
        result = bytes(self.receives[:size])
        del self.receives[:size]
        return result

    def send(self, value: object) -> int:
        self._before("send")
        raw = bytes(value)
        count = len(raw) if self.send_chunk is None else min(self.send_chunk, len(raw))
        self.sent.extend(raw[:count])
        return count

    def shutdown(self, direction: int) -> None:
        self._before("shutdown")
        self.shutdowns.append(direction)

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        self._before("close")


def handler(
    executor: object, *, clock: Clock | None = None, timeout_ms: int = 1000,
) -> UnixExecutorConnectionHandler:
    with patch.object(server_module.time, "monotonic", clock or Clock()):
        return UnixExecutorConnectionHandler(
            executor=executor,
            expected_broker_uid=os.getuid(),
            expected_broker_gid=os.getgid(),
            timeout_ms=timeout_ms,
        )


class ConstructorTests(unittest.TestCase):
    def test_public_api_is_closed_and_construction_is_inert(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(UnixExecutorConnectionHandler).parameters),
            ("executor", "expected_broker_uid", "expected_broker_gid", "timeout_ms"),
        )
        self.assertEqual(
            tuple(inspect.signature(UnixExecutorConnectionHandler.handle).parameters),
            ("self", "connection"),
        )
        with (
            patch.object(server_module.socket, "socket", side_effect=AssertionError("socket")),
            patch.object(server_module, "parse_canonical_response", side_effect=AssertionError("parse")),
        ):
            instance = UnixExecutorConnectionHandler(
                executor=Executor(), expected_broker_uid=1,
                expected_broker_gid=2, timeout_ms=3000,
            )
        self.assertIsInstance(instance, UnixExecutorConnectionHandler)
        self.assertEqual(MAX_TIMEOUT_MS, 3000)

    def test_only_handle_is_public_and_configuration_is_immutable(self) -> None:
        instance = handler(Executor())
        public = {
            name for name, value in vars(UnixExecutorConnectionHandler).items()
            if not name.startswith("_") and callable(value)
        }
        self.assertEqual(public, {"handle"})
        with self.assertRaises(AttributeError):
            instance._configuration = ()  # type: ignore[misc]

    def test_valid_identity_and_and_timeout_boundaries_construct(self) -> None:
        for identity in (0, server_module.MAX_IDENTITY_VALUE):
            for timeout_ms in (1, MAX_TIMEOUT_MS):
                with self.subTest(identity=identity, timeout_ms=timeout_ms):
                    self.assertIsInstance(
                        UnixExecutorConnectionHandler(
                            executor=Executor(), expected_broker_uid=identity,
                            expected_broker_gid=identity, timeout_ms=timeout_ms,
                        ),
                        UnixExecutorConnectionHandler,
                    )

    def test_invalid_executor_shapes_reject_without_invocation(self) -> None:
        class Missing:
            pass

        class Property:
            @property
            def execute(self) -> object:
                raise AssertionError("property invoked")

        class Static:
            @staticmethod
            def execute(canonical_request: bytes) -> bytes:
                return RESPONSE

        class Class:
            @classmethod
            def execute(cls, canonical_request: bytes) -> bytes:
                return RESPONSE

        class Default:
            def execute(self, canonical_request: bytes = b"x") -> bytes:
                return RESPONSE

        class Variadic:
            def execute(self, canonical_request: bytes, *args: object) -> bytes:
                return RESPONSE

        class Async:
            async def execute(self, canonical_request: bytes) -> bytes:
                return RESPONSE

        for value in (None, object(), Missing(), Property(), Static(), Class(), Default(), Variadic(), Async()):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                UnixExecutorConnectionHandler(
                    executor=value, expected_broker_uid=1, expected_broker_gid=2,
                )


def _install_constructor_value_tests() -> None:
    invalid = (
        ("bool", True), ("float", 1.0), ("negative", -1),
        ("reserved", 2**32 - 1), ("overflow", 2**32), ("str", "1"),
        ("none", None), ("subclass", type("IntChild", (int,), {})(1)),
    )
    for field in ("expected_broker_uid", "expected_broker_gid"):
        for label, value in invalid:
            def test(
                self: unittest.TestCase, field: str = field, value: object = value,
            ) -> None:
                arguments: dict[str, object] = {
                    "executor": Executor(), "expected_broker_uid": 1,
                    "expected_broker_gid": 2, "timeout_ms": 1000,
                }
                arguments[field] = value
                with self.assertRaises(TypeError):
                    UnixExecutorConnectionHandler(**arguments)  # type: ignore[arg-type]
            setattr(ConstructorTests, f"test_{field}_{label}_rejects", test)
    for label, value in (
        ("zero", 0), ("negative", -1), ("above", 3001), ("bool", True),
        ("float", 1.0), ("subclass", type("TimeoutChild", (int,), {})(1)),
    ):
        def test(self: unittest.TestCase, value: object = value) -> None:
            with self.assertRaises(TypeError):
                UnixExecutorConnectionHandler(
                    executor=Executor(), expected_broker_uid=1,
                    expected_broker_gid=2, timeout_ms=value,  # type: ignore[arg-type]
                )
        setattr(ConstructorTests, f"test_timeout_{label}_rejects", test)


class PeerAuthenticationTests(unittest.TestCase):
    def rejected(self, connection: FakeConnection) -> Executor:
        executor = Executor()
        with self.assertRaisesRegex(
            ExecutorConnectionUnavailableError,
            f"^{EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE}$",
        ):
            handler(executor).handle(connection)
        self.assertEqual(executor.calls, [])
        self.assertEqual(connection.recv_sizes, [])
        self.assertEqual(connection.close_calls, 1)
        return executor

    def test_exact_peer_credentials_are_accepted(self) -> None:
        connection = FakeConnection()
        executor = Executor()
        self.assertIsNone(handler(executor).handle(connection))
        self.assertEqual(executor.calls, [REQUEST])

    def test_wrong_uid_and_gid_reject_before_receive(self) -> None:
        for label, peer in (
            ("uid", PEER.pack(os.getpid(), os.getuid() + 1, os.getgid())),
            ("gid", PEER.pack(os.getpid(), os.getuid(), os.getgid() + 1)),
        ):
            with self.subTest(label=label):
                self.rejected(FakeConnection(peer=peer))

    def test_nonpositive_pid_rejects(self) -> None:
        for pid in (0, -1):
            with self.subTest(pid=pid):
                self.rejected(FakeConnection(peer=PEER.pack(pid, os.getuid(), os.getgid())))

    def test_malformed_peer_credentials_reject(self) -> None:
        for peer in (b"", b"x", b"x" * (PEER.size - 1), b"x" * (PEER.size + 1), bytearray(b"x" * PEER.size)):
            with self.subTest(peer=repr(peer)):
                self.rejected(FakeConnection(peer=peer))

    def test_wrong_domain_type_and_inheritable_reject(self) -> None:
        cases = (
            FakeConnection(domain=int(socket.AF_INET)),
            FakeConnection(domain=type("IntChild", (int,), {})(socket.AF_UNIX)),
            FakeConnection(kind=int(socket.SOCK_DGRAM)),
            FakeConnection(kind=type("IntChild", (int,), {})(socket.SOCK_STREAM)),
            FakeConnection(inheritable=True),
            FakeConnection(inheritable=0),
        )
        for connection in cases:
            with self.subTest(connection=connection):
                self.rejected(connection)

    def test_missing_linux_socket_controls_reject(self) -> None:
        executor = Executor()
        connection = FakeConnection()
        with patch.object(server_module.socket, "SO_PEERCRED", None):
            instance = UnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), timeout_ms=1000,
            )
        with self.assertRaises(ExecutorConnectionUnavailableError):
            instance.handle(connection)
        self.assertEqual(executor.calls, [])
        self.assertEqual(connection.close_calls, 1)


class RequestFramingTests(unittest.TestCase):
    def exchange(self, frame: bytes) -> tuple[Executor, FakeConnection, BaseException | None]:
        executor = Executor()
        connection = FakeConnection(frame)
        try:
            handler(executor).handle(connection)
            return executor, connection, None
        except BaseException as error:
            return executor, connection, error

    def test_partial_prefix_and_body_reads_reassemble_exact_original(self) -> None:
        class Fragmented(FakeConnection):
            def recv(self, size: int) -> bytes:
                return super().recv(min(size, 1))

        executor = Executor()
        connection = Fragmented()
        self.assertIsNone(handler(executor).handle(connection))
        self.assertEqual(executor.calls, [REQUEST])
        self.assertGreater(len(connection.recv_sizes), len(REQUEST))

    def test_zero_oversized_truncated_and_trailing_frames_reject(self) -> None:
        cases = (
            b"", b"\x00", b"\x00\x00\x00", b"\x00\x00\x00\x00",
            (MAX_CANONICAL_REQUEST_BYTES + 1).to_bytes(4, "big"),
            (4).to_bytes(4, "big") + b"abc",
            REQUEST_FRAME + b"x",
            REQUEST_FRAME + (1).to_bytes(4, "big") + b"x",
        )
        for frame in cases:
            with self.subTest(frame=frame[:8]):
                executor, connection, error = self.exchange(frame)
                self.assertIsInstance(error, ExecutorConnectionUnavailableError)
                self.assertEqual(executor.calls, [])
                self.assertEqual(connection.close_calls, 1)

    def test_executor_is_not_called_until_exact_eof(self) -> None:
        class MissingEOF(FakeConnection):
            def recv(self, size: int) -> bytes:
                if not self.receives:
                    raise socket.timeout("missing-eof-secret")
                return super().recv(size)

        executor = Executor()
        connection = MissingEOF()
        with self.assertRaises(ExecutorConnectionUnavailableError):
            handler(executor).handle(connection)
        self.assertEqual(executor.calls, [])
        self.assertEqual(connection.close_calls, 1)

    def test_maximum_request_is_forwarded_once_without_rewriting(self) -> None:
        request = b"x" * MAX_CANONICAL_REQUEST_BYTES
        executor = Executor()
        connection = FakeConnection(len(request).to_bytes(4, "big") + request)
        handler(executor).handle(connection)
        self.assertEqual(executor.calls, [request])
        self.assertIs(type(executor.calls[0]), bytes)


class ResponseTests(unittest.TestCase):
    def test_exact_canonical_response_is_partially_sent_unchanged(self) -> None:
        executor = Executor()
        connection = FakeConnection(send_chunk=1)
        self.assertIsNone(handler(executor).handle(connection))
        self.assertEqual(executor.calls, [REQUEST])
        self.assertEqual(bytes(connection.sent), RESPONSE_FRAME)
        self.assertEqual(connection.shutdowns, [socket.SHUT_WR])
        self.assertEqual(connection.close_calls, 1)

    def test_invalid_executor_responses_send_nothing_and_do_not_retry(self) -> None:
        class BytesChild(bytes):
            pass

        malformed = (
            b"", "response", bytearray(RESPONSE), memoryview(RESPONSE),
            BytesChild(RESPONSE), b"{}\n", RESPONSE.rstrip(b"\n"),
            RESPONSE + b" ", b"x" * (MAX_EXECUTOR_RESPONSE_BYTES + 1),
        )
        for value in malformed:
            with self.subTest(value=type(value).__name__):
                executor = Executor(value)
                connection = FakeConnection()
                with self.assertRaises(ExecutorConnectionUnavailableError):
                    handler(executor).handle(connection)
                self.assertEqual(executor.calls, [REQUEST])
                self.assertEqual(connection.sent, b"")
                self.assertEqual(connection.close_calls, 1)

    def test_executor_failure_sends_nothing_and_never_retries(self) -> None:
        executor = Executor(RuntimeError("executor-secret"))
        connection = FakeConnection()
        with self.assertRaisesRegex(
            ExecutorConnectionUnavailableError,
            f"^{EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE}$",
        ) as caught:
            handler(executor).handle(connection)
        self.assertNotIn("executor-secret", repr(caught.exception))
        self.assertEqual(executor.calls, [REQUEST])
        self.assertEqual(connection.sent, b"")
        self.assertEqual(connection.close_calls, 1)

    def test_client_disconnect_send_shutdown_and_close_fail_closed(self) -> None:
        for operation, error in (
            ("send", BrokenPipeError("client-disconnect-secret")),
            ("shutdown", OSError("shutdown-secret")),
            ("close", OSError("close-secret")),
        ):
            executor = Executor()
            connection = FakeConnection()
            connection.failures[operation] = error
            with self.subTest(operation=operation), self.assertRaisesRegex(
                ExecutorConnectionUnavailableError,
                f"^{EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE}$",
            ) as caught:
                handler(executor).handle(connection)
            self.assertNotIn("secret", repr(caught.exception))
            self.assertEqual(executor.calls, [REQUEST])
            self.assertEqual(connection.close_calls, 1)


class DeadlineTests(unittest.TestCase):
    def test_executor_runtime_is_outside_request_and_send_deadlines(self) -> None:
        clock = Clock(step=0.001)
        executor = Executor()
        executor.on_execute = lambda: setattr(clock, "current", clock.current + 301.0)
        connection = FakeConnection()
        self.assertIsNone(handler(executor, clock=clock).handle(connection))
        request_timeouts = [value for value in connection.timeouts if value < 1.0]
        self.assertTrue(request_timeouts)
        self.assertTrue(any(
            later > earlier
            for earlier, later in zip(connection.timeouts, connection.timeouts[1:])
        ))

    def test_receive_and_send_deadline_expiry_fail_closed(self) -> None:
        for phase in ("recv", "send"):
            clock = Clock(step=0.001)

            class Expiring(FakeConnection):
                def recv(self, size: int) -> bytes:
                    result = super().recv(size)
                    if phase == "recv" and len(self.recv_sizes) == 1:
                        clock.current += 2.0
                    return result

                def send(self, value: object) -> int:
                    result = super().send(value)
                    if phase == "send" and len(self.sent) > 0:
                        clock.current += 2.0
                    return result

            executor = Executor()
            connection = Expiring()
            with self.subTest(phase=phase), self.assertRaises(
                ExecutorConnectionUnavailableError,
            ):
                handler(executor, clock=clock).handle(connection)
            self.assertEqual(len(executor.calls), 0 if phase == "recv" else 1)
            self.assertEqual(connection.close_calls, 1)

    def test_eintr_retries_same_deadline_without_executor_retry(self) -> None:
        executor = Executor()
        connection = FakeConnection(send_chunk=3)
        connection.interrupts = {"getsockopt": 1, "recv": 2, "send": 2, "shutdown": 1}
        self.assertIsNone(handler(executor).handle(connection))
        self.assertEqual(executor.calls, [REQUEST])
        self.assertEqual(bytes(connection.sent), RESPONSE_FRAME)
        self.assertEqual(connection.shutdowns, [socket.SHUT_WR])
        increases = [
            index for index, (before, after) in enumerate(
                zip(connection.timeouts, connection.timeouts[1:])
            ) if after > before
        ]
        self.assertEqual(len(increases), 1)
        split = increases[0] + 1
        for phase in (connection.timeouts[:split], connection.timeouts[split:]):
            self.assertTrue(all(a > b for a, b in zip(phase, phase[1:])))

    def test_malformed_nonfinite_failed_and_backward_clocks_fail_closed(self) -> None:
        values = (
            [True], ["1"], [None], [math.nan], [math.inf], [-math.inf], [-1.0],
            [10.0, 10.1, 10.05],
        )
        for samples in values:
            executor = Executor()
            connection = FakeConnection()
            with self.subTest(samples=samples), self.assertRaisesRegex(
                ExecutorConnectionUnavailableError,
                f"^{EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE}$",
            ):
                handler(executor, clock=Clock(values=list(samples))).handle(connection)
            self.assertEqual(connection.close_calls, 1)

        class FailedClock:
            def __call__(self) -> object:
                raise OSError("clock-secret")

        executor = Executor()
        connection = FakeConnection()
        with self.assertRaises(ExecutorConnectionUnavailableError):
            handler(executor, clock=FailedClock()).handle(connection)  # type: ignore[arg-type]
        self.assertEqual(connection.close_calls, 1)

    def test_response_phase_clock_failures_and_overflow_fail_closed(self) -> None:
        cases = (
            ("bool", [True]), ("string", ["1"]), ("none", [None]),
            ("nan", [math.nan]), ("infinity", [math.inf]),
            ("negative", [-1.0]), ("rollback", [99.0]),
            ("overflow", [float.fromhex("0x1.fffffffffffffp+1023")]),
        )
        for label, samples in cases:
            clock = Clock()
            executor = Executor()
            executor.on_execute = lambda samples=samples: setattr(
                clock, "values", list(samples),
            )
            connection = FakeConnection()
            with self.subTest(label=label), self.assertRaisesRegex(
                ExecutorConnectionUnavailableError,
                f"^{EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE}$",
            ):
                handler(executor, clock=clock).handle(connection)
            self.assertEqual(executor.calls, [REQUEST])
            self.assertEqual(connection.sent, b"")
            self.assertEqual(connection.close_calls, 1)


class MutationReentrancyAndCleanupTests(unittest.TestCase):
    def test_close_is_captured_once_even_for_a_hostile_descriptor(self) -> None:
        class ChangingClose(FakeConnection):
            def __init__(self) -> None:
                super().__init__()
                self.close_lookups = 0

            @property
            def close(self) -> object:
                self.close_lookups += 1

                def captured_close() -> None:
                    self.close_calls += 1
                    self.closed = True

                if self.close_lookups > 1:
                    raise AssertionError("close descriptor read twice")
                return captured_close

        executor = Executor()
        connection = ChangingClose()
        self.assertIsNone(handler(executor).handle(connection))
        self.assertEqual(connection.close_lookups, 1)
        self.assertEqual(connection.close_calls, 1)

    def test_module_and_executor_mutation_cannot_redirect_captured_execution(self) -> None:
        executor = Executor()
        instance = handler(executor)

        def mutate() -> None:
            server_module.parse_canonical_response = lambda value: object()  # type: ignore[assignment]
            Executor.execute = lambda self, canonical_request: b"redirected"  # type: ignore[assignment]
            with self.assertRaises(AttributeError):
                instance._configuration = ()  # type: ignore[misc]

        executor.on_execute = mutate
        connection = FakeConnection()
        try:
            self.assertIsNone(instance.handle(connection))
            self.assertEqual(bytes(connection.sent), RESPONSE_FRAME)
            self.assertEqual(executor.calls, [REQUEST])
        finally:
            # Restore the module/class bindings for following tests; the handler's
            # captured operations were deliberately proven independent of them.
            server_module.parse_canonical_response = _ORIGINAL_PARSE
            Executor.execute = _ORIGINAL_EXECUTE

    def test_reentrant_handle_closes_nested_connection_without_double_execution(self) -> None:
        executor = Executor()
        instance = handler(executor)
        nested = FakeConnection()

        def reenter() -> None:
            with self.assertRaises(ExecutorConnectionUnavailableError):
                instance.handle(nested)

        executor.on_execute = reenter
        outer = FakeConnection()
        self.assertIsNone(instance.handle(outer))
        self.assertEqual(executor.calls, [REQUEST])
        self.assertEqual(nested.close_calls, 1)
        self.assertEqual(outer.close_calls, 1)

    def test_control_flow_exceptions_preserve_identity_and_close(self) -> None:
        for phase in ("recv", "execute", "send", "shutdown", "close"):
            for error_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
                error = error_type(f"{phase}-control-marker")
                executor = Executor(error if phase == "execute" else RESPONSE)
                connection = FakeConnection()
                if phase != "execute":
                    connection.failures[phase] = error
                with self.subTest(phase=phase, error_type=error_type.__name__), self.assertRaises(
                    error_type,
                ) as caught:
                    handler(executor).handle(connection)
                self.assertIs(caught.exception, error)
                self.assertEqual(connection.close_calls, 1)

    def test_every_operational_failure_is_redacted_and_closed(self) -> None:
        marker = "token-request-response-peer-path-dependency-docker-secret"
        for operation in (
            "get_inheritable", "getsockopt", "settimeout", "recv", "send",
            "shutdown", "close",
        ):
            executor = Executor()
            connection = FakeConnection()
            connection.failures[operation] = OSError(f"{operation}-{marker}")
            with self.subTest(operation=operation), self.assertRaisesRegex(
                ExecutorConnectionUnavailableError,
                f"^{EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE}$",
            ) as caught:
                handler(executor).handle(connection)
            self.assertNotIn(marker, repr(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(connection.close_calls, 1)


class SocketpairIntegrationTests(unittest.TestCase):
    def test_real_unix_stream_socketpair_happy_path_and_peer_identity(self) -> None:
        client, connection = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.sendall(REQUEST_FRAME)
            client.shutdown(socket.SHUT_WR)
            executor = Executor()
            self.assertIsNone(handler(executor).handle(connection))
            received = bytearray()
            while True:
                piece = client.recv(4096)
                if not piece:
                    break
                received.extend(piece)
            self.assertEqual(bytes(received), RESPONSE_FRAME)
            self.assertEqual(executor.calls, [REQUEST])
            self.assertEqual(connection.fileno(), -1)
        finally:
            client.close()
            connection.close()


class StaticAuthorityTests(unittest.TestCase):
    def test_module_has_no_listener_filesystem_runtime_or_external_authority(self) -> None:
        path = ROOT / "deployment/executor_server.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(calls & {
            "bind", "listen", "accept", "connect", "socket", "open", "system",
            "popen", "fork", "exec", "sleep", "start",
        })
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertFalse(imports & {
            "subprocess", "pathlib", "os", "http", "ssl", "requests", "docker",
        })
        self.assertNotIn("PRODUCTION_EXECUTOR_SOCKET_PATH", source)
        self.assertNotIn("/run/omnilyzer", source)

    def test_tests_use_socketpair_and_never_bind_a_filesystem_socket(self) -> None:
        source = (ROOT / "deployment/tests/test_executor_server.py").read_text()
        tree = ast.parse(source)
        calls = {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertIn("socketpair", calls)
        self.assertFalse(calls & {"bind", "listen", "accept"})
        production_path = "/run/" + "omnilyzer/deployment/executor.sock"
        self.assertNotIn(production_path, source)


_ORIGINAL_PARSE = server_module.parse_canonical_response
_ORIGINAL_EXECUTE = Executor.execute
_install_constructor_value_tests()


if __name__ == "__main__":
    unittest.main()
