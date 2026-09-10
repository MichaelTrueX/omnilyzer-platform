"""Hostile public tests for the inert bounded Unix executor transport."""

from __future__ import annotations

import ast
import inspect
import math
import os
from pathlib import Path
import socket
import stat
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from deployment.broker import BrokerUnavailableError, RestrictedDeploymentBroker
from deployment.execution import ExecutorRequest, MAX_CANONICAL_REQUEST_BYTES
from deployment.tests.test_broker import Replay, Verifier
from deployment.tests.test_execution import valid_request
from deployment.tests.test_identity import NOW
import deployment.unix_transport as unix_transport
from deployment.unix_transport import (
    ExecutorTransportUnavailableError,
    MAX_TIMEOUT_MS,
    PRODUCTION_EXECUTOR_SOCKET_PATH,
    RESPONSE_TIMEOUT_MS,
    TRANSPORT_UNAVAILABLE_MESSAGE,
    UnixExecutorTransport,
)


ROOT = Path(__file__).resolve().parents[2]
PEER = struct.Struct("=iII")
REQUEST = b"exact-canonical-request"
RESPONSE = b"bounded-response"


def receive_exact(connection: socket.socket, size: int) -> bytes:
    pieces: list[bytes] = []
    remaining = size
    while remaining:
        piece = connection.recv(remaining)
        if not piece:
            break
        pieces.append(piece)
        remaining -= len(piece)
    return b"".join(pieces)


class OneShotServer:
    def __init__(
        self, path: str, *, response: bytes = RESPONSE, chunks: tuple[int, ...] = (),
        declared_length: int | None = None, trailing: bytes = b"",
        receive_request: bool = True,
    ) -> None:
        self.path = path
        self.response = response
        self.chunks = chunks
        self.declared_length = len(response) if declared_length is None else declared_length
        self.trailing = trailing
        self.receive_request = receive_request
        self.request_header = b""
        self.request = b""
        self.write_eof = False
        self.error: BaseException | None = None
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        os.chmod(path, 0o660)
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            connection, _ = self.listener.accept()
            with connection:
                if self.receive_request:
                    self.request_header = receive_exact(connection, 4)
                    if len(self.request_header) == 4:
                        length = int.from_bytes(self.request_header, "big")
                        self.request = receive_exact(connection, length)
                    self.write_eof = connection.recv(1) == b""
                frame = self.declared_length.to_bytes(4, "big") + self.response + self.trailing
                if self.chunks:
                    offset = 0
                    for size in self.chunks:
                        connection.sendall(frame[offset:offset + size])
                        offset += size
                    if offset < len(frame):
                        connection.sendall(frame[offset:])
                else:
                    connection.sendall(frame)
        except BaseException as exc:  # surfaced by finish(), never hidden
            self.error = exc
        finally:
            self.listener.close()

    def finish(self) -> None:
        self.thread.join(5)
        if self.thread.is_alive():
            raise AssertionError("test server did not finish")
        if self.error is not None:
            raise self.error


def constructed(path: str, **overrides: object) -> UnixExecutorTransport:
    values = {
        "expected_executor_uid": os.getuid(),
        "expected_executor_gid": os.getgid(),
        "expected_socket_group_gid": os.getgid(),
        "timeout_ms": 1000,
    }
    values.update(overrides)
    with patch.object(unix_transport, "PRODUCTION_EXECUTOR_SOCKET_PATH", path):
        return UnixExecutorTransport(**values)  # type: ignore[arg-type]


def metadata(
    *, mode: int = stat.S_IFSOCK | 0o660, inode: int = 101, device: int = 202,
    links: int = 1, uid: int | None = None, gid: int | None = None,
) -> os.stat_result:
    return os.stat_result((
        mode, inode, device, links,
        os.getuid() if uid is None else uid,
        os.getgid() if gid is None else gid,
        0, 0, 0, 0,
    ))


class FakeSocket:
    def __init__(
        self, *, peer: bytes | None = None, response: bytes | None = None,
        failures: dict[str, BaseException] | None = None,
    ) -> None:
        self.peer = peer if peer is not None else PEER.pack(os.getpid(), os.getuid(), os.getgid())
        frame = len(RESPONSE).to_bytes(4, "big") + RESPONSE
        self.receives = bytearray(frame if response is None else response)
        self.failures = failures or {}
        self.inheritable = True
        self.closed = False
        self.close_calls = 0
        self.connected: list[object] = []
        self.sent: list[bytes] = []
        self.shutdowns: list[int] = []
        self.timeouts: list[float] = []
        self.recv_sizes: list[int] = []

    def _fail(self, name: str) -> None:
        error = self.failures.get(name)
        if error is not None:
            raise error

    def set_inheritable(self, value: bool) -> None:
        self._fail("set_inheritable")
        self.inheritable = value

    def get_inheritable(self) -> bool:
        self._fail("get_inheritable")
        return self.inheritable

    def getsockopt(self, level: int, option: int, size: int | None = None) -> object:
        self._fail("getsockopt")
        if option == socket.SO_DOMAIN:
            return int(socket.AF_UNIX)
        if option == socket.SO_TYPE:
            return int(socket.SOCK_STREAM)
        if option == socket.SO_PEERCRED:
            return self.peer
        raise AssertionError("unexpected socket option")

    def settimeout(self, value: float) -> None:
        self._fail("settimeout")
        self.timeouts.append(value)

    def connect(self, path: str) -> None:
        self._fail("connect")
        self.connected.append(path)

    def sendall(self, value: bytes) -> None:
        self._fail("sendall")
        self.sent.append(value)

    def shutdown(self, direction: int) -> None:
        self._fail("shutdown")
        self.shutdowns.append(direction)

    def recv(self, size: int) -> bytes:
        self._fail("recv")
        self.recv_sizes.append(size)
        if not self.receives:
            return b""
        result = bytes(self.receives[:size])
        del self.receives[:size]
        return result

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        self._fail("close")


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


def fake_transport(
    fake: FakeSocket, *, stats: list[object] | None = None,
    clock: Clock | None = None, factory_error: BaseException | None = None,
    deadline_factory: object | None = None,
) -> tuple[UnixExecutorTransport, list[tuple[int, int]]]:
    path = "/tmp/task014-test/executor.sock"
    results = list(stats or [metadata(), metadata()])
    factory_calls: list[tuple[int, int]] = []

    def lstat(_path: str) -> object:
        if not results:
            raise AssertionError("unexpected lstat")
        return results.pop(0)

    def factory(family: int, kind: int) -> FakeSocket:
        factory_calls.append((family, kind))
        if factory_error is not None:
            raise factory_error
        return fake

    with (
        patch.object(unix_transport, "PRODUCTION_EXECUTOR_SOCKET_PATH", path),
        patch.object(unix_transport.os, "lstat", lstat),
        patch.object(unix_transport.socket, "socket", factory),
        patch.object(unix_transport.time, "monotonic", clock or Clock()),
        patch.object(
            unix_transport, "_Deadline",
            unix_transport._Deadline if deadline_factory is None else deadline_factory,
        ),
    ):
        result = UnixExecutorTransport(
            expected_executor_uid=os.getuid(),
            expected_executor_gid=os.getgid(),
            expected_socket_group_gid=os.getgid(),
            timeout_ms=1000,
        )
    return result, factory_calls


class UnixTransportConstructorTests(unittest.TestCase):
    def test_exact_public_signatures(self) -> None:
        self.assertEqual(MAX_TIMEOUT_MS, 3000)
        self.assertEqual(RESPONSE_TIMEOUT_MS, 600_000)
        self.assertEqual(
            tuple(inspect.signature(UnixExecutorTransport).parameters),
            ("expected_executor_uid", "expected_executor_gid", "expected_socket_group_gid", "timeout_ms"),
        )
        self.assertEqual(
            tuple(inspect.signature(UnixExecutorTransport.send).parameters),
            ("self", "canonical_request"),
        )

    def test_only_send_is_public(self) -> None:
        public = {name for name, value in vars(UnixExecutorTransport).items()
                  if not name.startswith("_") and callable(value)}
        self.assertEqual(public, {"send"})

    def test_import_and_construction_do_not_touch_filesystem_or_socket(self) -> None:
        with (
            patch.object(unix_transport.os, "lstat", side_effect=AssertionError("lstat")),
            patch.object(unix_transport.socket, "socket", side_effect=AssertionError("socket")),
        ):
            transport = UnixExecutorTransport(
                expected_executor_uid=1, expected_executor_gid=2,
                expected_socket_group_gid=3,
            )
        self.assertIsInstance(transport, UnixExecutorTransport)

    def test_fixed_path_and_operations_are_captured_at_construction(self) -> None:
        fake = FakeSocket()
        transport, _ = fake_transport(fake)
        with (
            patch.object(unix_transport, "PRODUCTION_EXECUTOR_SOCKET_PATH", "/tmp/redirect.sock"),
            patch.object(unix_transport.os, "lstat", side_effect=AssertionError("redirect")),
            patch.object(unix_transport.socket, "socket", side_effect=AssertionError("redirect")),
            patch.object(unix_transport.os, "stat_result", object),
            patch.object(unix_transport.math, "isfinite", side_effect=AssertionError("redirect")),
        ):
            self.assertEqual(transport.send(REQUEST), RESPONSE)
        self.assertEqual(fake.connected, ["/tmp/task014-test/executor.sock"])

    def test_environment_cannot_redirect_path(self) -> None:
        fake = FakeSocket()
        transport, _ = fake_transport(fake)
        with patch.dict(os.environ, {
            "HOME": "/attacker", "EXECUTOR_SOCKET": "/attacker/socket",
            "HTTP_PROXY": "http://attacker.invalid",
        }):
            self.assertEqual(transport.send(REQUEST), RESPONSE)
        self.assertEqual(fake.connected, ["/tmp/task014-test/executor.sock"])

    def test_configuration_is_not_normally_replaceable(self) -> None:
        transport, _ = fake_transport(FakeSocket())
        with self.assertRaises(AttributeError):
            transport._configuration = ()  # type: ignore[misc]

    def test_production_path_contract(self) -> None:
        self.assertEqual(PRODUCTION_EXECUTOR_SOCKET_PATH, "/run/omnilyzer/deployment/executor.sock")
        self.assertLessEqual(len(os.fsencode(PRODUCTION_EXECUTOR_SOCKET_PATH)), 107)

    def test_valid_identity_and_timeout_boundaries_pass_construction(self) -> None:
        for identity in (0, unix_transport.MAX_IDENTITY_VALUE):
            for timeout_ms in (1, MAX_TIMEOUT_MS):
                with self.subTest(identity=identity, timeout_ms=timeout_ms):
                    self.assertIsInstance(
                        UnixExecutorTransport(
                            expected_executor_uid=identity,
                            expected_executor_gid=identity,
                            expected_socket_group_gid=identity,
                            timeout_ms=timeout_ms,
                        ),
                        UnixExecutorTransport,
                    )

    def test_path_policy_rejects_noncanonical_and_non_string_constants(self) -> None:
        class StringChild(str):
            pass
        invalid = (
            "relative/executor.sock", "//run/executor.sock",
            "/run/./executor.sock", "/run/../executor.sock",
            "/run//executor.sock", "/run/executor.sock\x00suffix",
            "\x00abstract", "/" + "x" * 108,
            Path("/run/executor.sock"), StringChild("/run/executor.sock"),
        )
        for value in invalid:
            with self.subTest(value=repr(value)), patch.object(
                unix_transport, "PRODUCTION_EXECUTOR_SOCKET_PATH", value,
            ), self.assertRaises(TypeError):
                UnixExecutorTransport(
                    expected_executor_uid=1, expected_executor_gid=2,
                    expected_socket_group_gid=3,
                )


class UnixTransportRequestTests(unittest.TestCase):
    def test_exact_request_bytes_are_framed_without_change(self) -> None:
        fake = FakeSocket()
        transport, calls = fake_transport(fake)
        self.assertEqual(transport.send(REQUEST), RESPONSE)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], socket.AF_UNIX)
        self.assertTrue(calls[0][1] & socket.SOCK_STREAM)
        self.assertEqual(fake.sent, [len(REQUEST).to_bytes(4, "big"), REQUEST])
        self.assertIs(fake.sent[1], REQUEST)
        self.assertEqual(fake.shutdowns, [socket.SHUT_WR])
        self.assertTrue(fake.closed)

    def test_maximum_request_passes(self) -> None:
        request = b"x" * MAX_CANONICAL_REQUEST_BYTES
        fake = FakeSocket()
        transport, _ = fake_transport(fake)
        self.assertEqual(transport.send(request), RESPONSE)
        self.assertIs(fake.sent[1], request)

    def test_invalid_request_does_not_touch_filesystem_or_socket(self) -> None:
        with (
            patch.object(unix_transport.os, "lstat", side_effect=AssertionError("lstat")),
            patch.object(unix_transport.socket, "socket", side_effect=AssertionError("socket")),
        ):
            transport = UnixExecutorTransport(
                expected_executor_uid=1, expected_executor_gid=2,
                expected_socket_group_gid=3,
            )
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(b"")


class UnixTransportMetadataTests(unittest.TestCase):
    def assert_metadata_rejected(self, first: object, second: object | None = None) -> FakeSocket:
        fake = FakeSocket()
        stats = [first] if second is None else [first, second]
        transport, _ = fake_transport(fake, stats=stats)
        with self.assertRaisesRegex(
            ExecutorTransportUnavailableError, f"^{TRANSPORT_UNAVAILABLE_MESSAGE}$",
        ):
            transport.send(REQUEST)
        return fake

    def test_post_connect_inode_replacement_rejects_before_send(self) -> None:
        fake = self.assert_metadata_rejected(metadata(), metadata(inode=102))
        self.assertEqual(fake.sent, [])
        self.assertEqual(len(fake.connected), 1)

    def test_post_connect_device_replacement_rejects_before_send(self) -> None:
        fake = self.assert_metadata_rejected(metadata(), metadata(device=203))
        self.assertEqual(fake.sent, [])

    def test_post_connect_mode_drift_rejects_before_send(self) -> None:
        fake = self.assert_metadata_rejected(
            metadata(), metadata(mode=stat.S_IFSOCK | 0o600),
        )
        self.assertEqual(fake.sent, [])

    def test_post_connect_owner_drift_rejects_before_send(self) -> None:
        fake = self.assert_metadata_rejected(
            metadata(), metadata(uid=os.getuid() + 1),
        )
        self.assertEqual(fake.sent, [])

    def test_post_connect_group_drift_rejects_before_send(self) -> None:
        fake = self.assert_metadata_rejected(
            metadata(), metadata(gid=os.getgid() + 1),
        )
        self.assertEqual(fake.sent, [])

    def test_post_connect_link_count_drift_rejects_before_send(self) -> None:
        fake = self.assert_metadata_rejected(metadata(), metadata(links=2))
        self.assertEqual(fake.sent, [])

    def test_stat_result_subclass_is_rejected(self) -> None:
        class HostileStat(tuple):
            def __getattribute__(self, name: str) -> object:
                raise AssertionError("hostile stat attribute")
        fake = self.assert_metadata_rejected(HostileStat(metadata()))
        self.assertEqual(fake.connected, [])

    def test_actual_symlink_regular_directory_fifo_and_hardlink_reject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular"
            regular.write_bytes(b"not-a-socket")
            symlink = root / "symlink.sock"
            symlink.symlink_to(regular)
            fifo = root / "fifo.sock"
            os.mkfifo(fifo, 0o660)
            listener_path = root / "listener.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(listener_path))
            os.chmod(listener_path, 0o660)
            hardlink = root / "listener-hardlink.sock"
            os.link(listener_path, hardlink)
            try:
                for label, path in (
                    ("symlink", symlink), ("regular", regular),
                    ("directory", root), ("fifo", fifo),
                    ("hardlink", listener_path),
                ):
                    with self.subTest(label=label):
                        transport = constructed(str(path))
                        with self.assertRaises(ExecutorTransportUnavailableError):
                            transport.send(REQUEST)
            finally:
                listener.close()

    def test_actual_wrong_socket_mode_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "executor.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            os.chmod(path, 0o600)
            try:
                with self.assertRaises(ExecutorTransportUnavailableError):
                    constructed(path).send(REQUEST)
            finally:
                listener.close()


class UnixTransportPeerTests(unittest.TestCase):
    def assert_peer_rejected(self, peer: object) -> FakeSocket:
        fake = FakeSocket(peer=peer)  # type: ignore[arg-type]
        transport, _ = fake_transport(fake)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(fake.sent, [])
        return fake

    def test_real_format_peer_credentials_pass(self) -> None:
        fake = FakeSocket(peer=PEER.pack(os.getpid(), os.getuid(), os.getgid()))
        transport, _ = fake_transport(fake)
        self.assertEqual(transport.send(REQUEST), RESPONSE)

    def test_peer_check_occurs_before_second_lstat_and_send(self) -> None:
        fake = self.assert_peer_rejected(PEER.pack(0, os.getuid(), os.getgid()))
        self.assertEqual(fake.sent, [])

    def test_missing_peercred_constant_fails_before_connect_data(self) -> None:
        fake = FakeSocket()
        with patch.object(unix_transport.socket, "SO_PEERCRED", None):
            transport, _ = fake_transport(fake)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(fake.sent, [])

    def test_deceptive_socket_identity_reports_fail_closed(self) -> None:
        cases = (
            ("domain", type("IntChild", (int,), {})(socket.AF_UNIX)),
            ("domain", int(socket.AF_INET)),
            ("type", type("IntChild", (int,), {})(socket.SOCK_STREAM)),
            ("type", int(socket.SOCK_DGRAM)),
            ("inheritable", 0),
        )
        for field, value in cases:
            class DeceptiveSocket(FakeSocket):
                def get_inheritable(self) -> object:
                    if field == "inheritable":
                        return value
                    return super().get_inheritable()

                def getsockopt(
                    self, level: int, option: int, size: int | None = None,
                ) -> object:
                    if field == "domain" and option == socket.SO_DOMAIN:
                        return value
                    if field == "type" and option == socket.SO_TYPE:
                        return value
                    return super().getsockopt(level, option, size)

            with self.subTest(field=field, value=value):
                fake = DeceptiveSocket()
                transport, _ = fake_transport(fake)
                with self.assertRaises(ExecutorTransportUnavailableError):
                    transport.send(REQUEST)
                self.assertEqual(fake.sent, [])
                self.assertEqual(fake.close_calls, 1)


class UnixTransportFramingTests(unittest.TestCase):
    def exchange(self, framed_response: bytes) -> tuple[bytes | None, FakeSocket, BaseException | None]:
        fake = FakeSocket(response=framed_response)
        transport, _ = fake_transport(fake)
        try:
            result = transport.send(REQUEST)
            return result, fake, None
        except BaseException as exc:
            return None, fake, exc

    def test_empty_response_passes(self) -> None:
        result, fake, error = self.exchange(b"\x00\x00\x00\x00")
        self.assertIsNone(error)
        self.assertEqual(result, b"")
        self.assertTrue(fake.closed)

    def test_maximum_response_passes(self) -> None:
        body = b"r" * unix_transport.MAX_EXECUTOR_RESPONSE_BYTES
        result, fake, error = self.exchange(len(body).to_bytes(4, "big") + body)
        self.assertIsNone(error)
        self.assertEqual(result, body)
        self.assertIs(type(result), bytes)
        self.assertLessEqual(max(fake.recv_sizes), unix_transport.MAX_EXECUTOR_RESPONSE_BYTES)

    def test_partial_header_and_body_are_reassembled(self) -> None:
        class Fragmented(FakeSocket):
            def recv(self, size: int) -> bytes:
                return super().recv(min(size, 1))
        fake = Fragmented()
        transport, _ = fake_transport(fake)
        self.assertEqual(transport.send(REQUEST), RESPONSE)
        self.assertGreater(len(fake.recv_sizes), len(RESPONSE))

    def test_second_frame_is_trailing_data(self) -> None:
        frame = len(RESPONSE).to_bytes(4, "big") + RESPONSE
        result, _, error = self.exchange(frame + b"\x00\x00\x00\x00")
        self.assertIsNone(result)
        self.assertIsInstance(error, ExecutorTransportUnavailableError)

    def test_oversized_declaration_reads_no_body(self) -> None:
        declared = unix_transport.MAX_EXECUTOR_RESPONSE_BYTES + 1
        result, fake, error = self.exchange(declared.to_bytes(4, "big") + b"secret")
        self.assertIsNone(result)
        self.assertIsInstance(error, ExecutorTransportUnavailableError)
        self.assertEqual(fake.recv_sizes[-1], 4)

    def test_largest_unsigned_declaration_rejects(self) -> None:
        result, _, error = self.exchange((2**32 - 1).to_bytes(4, "big"))
        self.assertIsNone(result)
        self.assertIsInstance(error, ExecutorTransportUnavailableError)

    def test_hostile_recv_return_larger_than_requested_rejects(self) -> None:
        class Oversupplying(FakeSocket):
            def recv(self, size: int) -> bytes:
                self.recv_sizes.append(size)
                return b"x" * (size + 1)
        fake = Oversupplying()
        transport, _ = fake_transport(fake)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertTrue(fake.closed)

    def test_bytes_subclass_eof_rejects_without_virtual_equality(self) -> None:
        class BytesChild(bytes):
            def __eq__(self, other: object) -> bool:
                raise AssertionError("hostile equality")
        class HostileEOF(FakeSocket):
            def recv(self, size: int) -> bytes:
                if not self.receives:
                    return BytesChild(b"")
                return super().recv(size)
        fake = HostileEOF()
        transport, _ = fake_transport(fake)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertTrue(fake.closed)


class UnixTransportDeadlineTests(unittest.TestCase):
    def test_each_phase_decreases_and_response_deadline_is_never_restarted(self) -> None:
        clock = Clock(step=0.01)
        fake = FakeSocket()
        transport, _ = fake_transport(fake, clock=clock)
        self.assertEqual(transport.send(REQUEST), RESPONSE)
        request_timeouts = [value for value in fake.timeouts if value < 3.0]
        response_timeouts = [value for value in fake.timeouts if value > 500.0]
        self.assertEqual(len(request_timeouts), 5)
        self.assertEqual(len(response_timeouts), 3)
        self.assertTrue(all(a > b for a, b in zip(request_timeouts, request_timeouts[1:])))
        self.assertTrue(all(a > b for a, b in zip(response_timeouts, response_timeouts[1:])))
        self.assertEqual(fake.timeouts, request_timeouts + response_timeouts)

    def test_shutdown_is_exact_transition_and_response_uses_one_new_deadline(self) -> None:
        created: list[RecordingDeadline] = []

        class RecordingDeadline:
            def __init__(self, _clock: object, timeout_ms: int) -> None:
                self.timeout_ms = timeout_ms
                self.calls = 0
                created.append(self)
                if len(created) == 2:
                    self.assert_shutdown()

            def assert_shutdown(self) -> None:
                self_test.assertEqual(fake.shutdowns, [socket.SHUT_WR])

            def remaining(self) -> float:
                self.calls += 1
                return self.timeout_ms / 1000.0 - self.calls / 1000.0

        self_test = self
        fake = FakeSocket()
        transport, _ = fake_transport(fake, deadline_factory=RecordingDeadline)
        self.assertEqual(transport.send(REQUEST), RESPONSE)
        self.assertEqual([item.timeout_ms for item in created], [1000, RESPONSE_TIMEOUT_MS])
        self.assertEqual(created[0].calls, 8)
        self.assertEqual(created[1].calls, 5)
        self.assertEqual(len([value for value in fake.timeouts if value > 500]), 3)

    def test_shutdown_failure_never_constructs_response_deadline(self) -> None:
        calls: list[int] = []

        def deadline_factory(clock: object, timeout_ms: int) -> object:
            calls.append(timeout_ms)
            return unix_transport._Deadline(clock, timeout_ms)  # type: ignore[arg-type]

        fake = FakeSocket(failures={"shutdown": OSError("shutdown-marker")})
        transport, factory_calls = fake_transport(fake, deadline_factory=deadline_factory)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(calls, [1000])
        self.assertEqual(len(factory_calls), 1)
        self.assertEqual(fake.sent, [len(REQUEST).to_bytes(4, "big"), REQUEST])

    def test_response_after_request_deadline_but_within_fixed_budget_succeeds(self) -> None:
        clock = Clock(step=0.001)

        class DelayedResponse(FakeSocket):
            def __init__(self) -> None:
                super().__init__()
                self.delayed = False

            def recv(self, size: int) -> bytes:
                if not self.delayed:
                    self.delayed = True
                    clock.current += 4.0
                return super().recv(size)

        fake = DelayedResponse()
        transport, _ = fake_transport(fake, clock=clock)
        self.assertEqual(transport.send(REQUEST), RESPONSE)
        self.assertTrue(any(value > 599.0 for value in fake.timeouts))

    def test_shutdown_that_exceeds_request_deadline_is_rejected(self) -> None:
        clock = Clock(step=0.001)

        class DelayedShutdown(FakeSocket):
            def shutdown(self, direction: int) -> None:
                super().shutdown(direction)
                clock.current += 2.0

        fake = DelayedShutdown()
        transport, calls = fake_transport(fake, clock=clock)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(len(calls), 1)
        self.assertEqual(fake.recv_sizes, [])
        self.assertEqual(fake.close_calls, 1)

    def test_response_deadline_constant_is_captured_and_not_caller_mutable(self) -> None:
        calls: list[int] = []

        def deadline_factory(clock: object, timeout_ms: int) -> object:
            calls.append(timeout_ms)
            return unix_transport._Deadline(clock, timeout_ms)  # type: ignore[arg-type]

        fake = FakeSocket()
        transport, _ = fake_transport(fake, deadline_factory=deadline_factory)
        with patch.object(unix_transport, "RESPONSE_TIMEOUT_MS", 1):
            self.assertEqual(transport.send(REQUEST), RESPONSE)
        self.assertEqual(calls, [1000, 600_000])

    def test_response_deadline_construction_failure_closes_without_resend(self) -> None:
        calls: list[int] = []

        def deadline_factory(clock: object, timeout_ms: int) -> object:
            calls.append(timeout_ms)
            if len(calls) == 2:
                raise OSError("response-deadline-secret")
            return unix_transport._Deadline(clock, timeout_ms)  # type: ignore[arg-type]

        fake = FakeSocket()
        transport, factory_calls = fake_transport(fake, deadline_factory=deadline_factory)
        with self.assertRaisesRegex(
            ExecutorTransportUnavailableError, f"^{TRANSPORT_UNAVAILABLE_MESSAGE}$",
        ) as caught:
            transport.send(REQUEST)
        self.assertNotIn("response-deadline-secret", repr(caught.exception))
        self.assertEqual(calls, [1000, RESPONSE_TIMEOUT_MS])
        self.assertEqual(len(factory_calls), 1)
        self.assertEqual(fake.sent, [len(REQUEST).to_bytes(4, "big"), REQUEST])
        self.assertEqual(fake.close_calls, 1)

    def test_malformed_response_clock_samples_fail_after_request_delivery(self) -> None:
        malformed = (True, "1", None, math.nan, math.inf, -math.inf, -1.0)
        for value in malformed:
            clock = Clock()

            class MalformedAfterShutdown(FakeSocket):
                def shutdown(self, direction: int) -> None:
                    super().shutdown(direction)
                    clock.values = [101.0, value]

            with self.subTest(value=repr(value)):
                fake = MalformedAfterShutdown()
                transport, calls = fake_transport(fake, clock=clock)
                with self.assertRaises(ExecutorTransportUnavailableError):
                    transport.send(REQUEST)
                self.assertEqual(len(calls), 1)
                self.assertEqual(len(fake.sent), 2)
                self.assertEqual(fake.close_calls, 1)

    def test_response_clock_rollback_fails_closed(self) -> None:
        clock = Clock()

        class RollbackAfterShutdown(FakeSocket):
            def shutdown(self, direction: int) -> None:
                super().shutdown(direction)
                clock.values = [200.0, 201.0, 200.5]

        fake = RollbackAfterShutdown()
        transport, _ = fake_transport(fake, clock=clock)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(fake.close_calls, 1)

    def test_clock_rollback_at_request_response_transition_fails_closed(self) -> None:
        clock = Clock()

        class RollbackAtShutdown(FakeSocket):
            def shutdown(self, direction: int) -> None:
                super().shutdown(direction)
                clock.values = [101.0, 100.0]

        fake = RollbackAtShutdown()
        transport, _ = fake_transport(fake, clock=clock)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(fake.recv_sizes, [])
        self.assertEqual(fake.close_calls, 1)

    def test_non_advancing_response_deadline_overflow_fails_closed(self) -> None:
        clock = Clock()

        class OverflowAfterShutdown(FakeSocket):
            def shutdown(self, direction: int) -> None:
                super().shutdown(direction)
                clock.values = [101.0, float.fromhex("0x1.fffffffffffffp+1023")]

        fake = OverflowAfterShutdown()
        transport, _ = fake_transport(fake, clock=clock)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(fake.recv_sizes, [])
        self.assertEqual(fake.close_calls, 1)

    def test_response_header_body_eof_and_cleanup_expiry_fail_closed(self) -> None:
        for phase in ("header", "body", "eof", "cleanup"):
            clock = Clock(step=0.001)

            class Expiring(FakeSocket):
                def __init__(self) -> None:
                    super().__init__()
                    self.response_reads = 0

                def recv(self, size: int) -> bytes:
                    self.response_reads += 1
                    result = super().recv(size)
                    target = {"header": 1, "body": 2, "eof": 3}.get(phase)
                    if self.response_reads == target:
                        clock.current += 601.0
                    return result

                def close(self) -> None:
                    super().close()
                    if phase == "cleanup":
                        clock.current += 601.0

            with self.subTest(phase=phase):
                fake = Expiring()
                transport, calls = fake_transport(fake, clock=clock)
                with self.assertRaises(ExecutorTransportUnavailableError):
                    transport.send(REQUEST)
                self.assertEqual(len(calls), 1)
                self.assertEqual(fake.close_calls, 1)

    def test_partial_response_body_timeout_fails_closed(self) -> None:
        class PartialBodyTimeout(FakeSocket):
            def __init__(self) -> None:
                super().__init__()
                self.response_reads = 0

            def recv(self, size: int) -> bytes:
                self.response_reads += 1
                if self.response_reads == 2:
                    return super().recv(1)
                if self.response_reads == 3:
                    raise socket.timeout("partial-body-timeout-secret")
                return super().recv(size)

        fake = PartialBodyTimeout()
        transport, calls = fake_transport(fake)
        with self.assertRaisesRegex(
            ExecutorTransportUnavailableError, f"^{TRANSPORT_UNAVAILABLE_MESSAGE}$",
        ) as caught:
            transport.send(REQUEST)
        self.assertNotIn("partial-body-timeout-secret", repr(caught.exception))
        self.assertEqual(len(calls), 1)
        self.assertEqual(fake.close_calls, 1)

    def test_deadline_expiry_closes_without_retry(self) -> None:
        clock = Clock(step=0.6)
        fake = FakeSocket()
        transport, calls = fake_transport(fake, clock=clock)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertLessEqual(len(calls), 1)
        if calls:
            self.assertTrue(fake.closed)

    def test_monotonic_rollback_fails_closed(self) -> None:
        clock = Clock(values=[10.0, 10.1, 10.2, 10.15])
        fake = FakeSocket()
        transport, _ = fake_transport(fake, clock=clock)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertTrue(fake.closed)

    def test_stalled_connect_header_body_and_eof_fail_without_retry(self) -> None:
        for phase in ("connect", "header", "body", "eof"):
            class Stalled(FakeSocket):
                def __init__(self) -> None:
                    super().__init__()
                    self.recv_calls = 0

                def connect(self, path: str) -> None:
                    if phase == "connect":
                        raise socket.timeout("stalled-connect-marker")
                    super().connect(path)

                def recv(self, size: int) -> bytes:
                    self.recv_calls += 1
                    target = {"header": 1, "body": 2, "eof": 3}.get(phase)
                    if self.recv_calls == target:
                        raise socket.timeout(f"stalled-{phase}-marker")
                    return super().recv(size)

            with self.subTest(phase=phase):
                fake = Stalled()
                transport, calls = fake_transport(fake)
                with self.assertRaisesRegex(
                    ExecutorTransportUnavailableError,
                    f"^{TRANSPORT_UNAVAILABLE_MESSAGE}$",
                ):
                    transport.send(REQUEST)
                self.assertEqual(len(calls), 1)
                self.assertEqual(len(fake.connected), 0 if phase == "connect" else 1)
                self.assertEqual(fake.close_calls, 1)

    def test_connect_delay_that_exhausts_request_budget_is_not_restarted(self) -> None:
        clock = Clock(step=0.001)

        class DelayedConnect(FakeSocket):
            def connect(self, path: str) -> None:
                super().connect(path)
                clock.current += 2.0

        fake = DelayedConnect()
        transport, calls = fake_transport(fake, clock=clock)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(len(calls), 1)
        self.assertEqual(fake.sent, [])
        self.assertEqual(fake.close_calls, 1)


class UnixTransportFailureTests(unittest.TestCase):
    def test_socket_factory_failure_is_generic_and_not_retried(self) -> None:
        marker = "factory-secret-path-uid-errno"
        fake = FakeSocket()
        transport, calls = fake_transport(fake, factory_error=OSError(marker))
        with self.assertRaises(ExecutorTransportUnavailableError) as caught:
            transport.send(REQUEST)
        self.assertEqual(str(caught.exception), TRANSPORT_UNAVAILABLE_MESSAGE)
        self.assertNotIn(marker, str(caught.exception))
        self.assertEqual(len(calls), 1)

    def test_close_failure_rejects_completed_response(self) -> None:
        fake = FakeSocket(failures={"close": OSError("close-secret")})
        transport, _ = fake_transport(fake)
        with self.assertRaisesRegex(
            ExecutorTransportUnavailableError, f"^{TRANSPORT_UNAVAILABLE_MESSAGE}$",
        ):
            transport.send(REQUEST)
        self.assertTrue(fake.closed)

    def test_shutdown_failure_closes_and_does_not_resend(self) -> None:
        fake = FakeSocket(failures={"shutdown": OSError("shutdown-secret")})
        transport, _ = fake_transport(fake)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(fake.sent, [len(REQUEST).to_bytes(4, "big"), REQUEST])
        self.assertTrue(fake.closed)

    def test_partial_send_failure_is_not_retried(self) -> None:
        class SecondSendFails(FakeSocket):
            def sendall(self, value: bytes) -> None:
                self.sent.append(value)
                if len(self.sent) == 2:
                    raise OSError("partial-body-secret")
        fake = SecondSendFails()
        transport, _ = fake_transport(fake)
        with self.assertRaises(ExecutorTransportUnavailableError):
            transport.send(REQUEST)
        self.assertEqual(len(fake.sent), 2)
        self.assertEqual(len(fake.connected), 1)

    def test_control_flow_exception_is_preserved_and_socket_closed(self) -> None:
        fake = FakeSocket(failures={"recv": KeyboardInterrupt()})
        transport, _ = fake_transport(fake)
        with self.assertRaises(KeyboardInterrupt):
            transport.send(REQUEST)
        self.assertTrue(fake.closed)

    def test_all_required_control_flow_exceptions_are_preserved(self) -> None:
        for phase in ("connect", "recv"):
            for error_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
                with self.subTest(phase=phase, error_type=error_type.__name__):
                    error = error_type("control-marker")
                    fake = FakeSocket(failures={phase: error})
                    transport, _ = fake_transport(fake)
                    with self.assertRaises(error_type) as caught:
                        transport.send(REQUEST)
                    self.assertIs(caught.exception, error)
                    self.assertEqual(fake.close_calls, 1)

    def test_generic_failure_has_no_exception_chain_or_sensitive_marker(self) -> None:
        marker = "socket-path-uid-gid-pid-errno-request-response-timing-secret"
        fake = FakeSocket(failures={"recv": OSError(marker)})
        transport, _ = fake_transport(fake)
        with self.assertRaises(ExecutorTransportUnavailableError) as caught:
            transport.send(REQUEST)
        self.assertEqual(str(caught.exception), TRANSPORT_UNAVAILABLE_MESSAGE)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(marker, repr(caught.exception))
        self.assertEqual(fake.close_calls, 1)

    def test_pre_and_post_lstat_failures_are_generic_and_not_retried(self) -> None:
        for failure_index in (0, 1):
            calls = 0

            def lstat(_path: str) -> os.stat_result:
                nonlocal calls
                calls += 1
                if calls - 1 == failure_index:
                    raise OSError("lstat-sensitive-marker")
                return metadata()

            fake = FakeSocket()
            path = "/tmp/task014-test/executor.sock"
            with (
                patch.object(unix_transport, "PRODUCTION_EXECUTOR_SOCKET_PATH", path),
                patch.object(unix_transport.os, "lstat", lstat),
                patch.object(unix_transport.socket, "socket", lambda *_: fake),
                patch.object(unix_transport.time, "monotonic", Clock()),
            ):
                transport = UnixExecutorTransport(
                    expected_executor_uid=os.getuid(),
                    expected_executor_gid=os.getgid(),
                    expected_socket_group_gid=os.getgid(),
                    timeout_ms=1000,
                )
            with self.subTest(failure_index=failure_index), self.assertRaisesRegex(
                ExecutorTransportUnavailableError,
                f"^{TRANSPORT_UNAVAILABLE_MESSAGE}$",
            ):
                transport.send(REQUEST)
            self.assertEqual(calls, failure_index + 1)
            self.assertEqual(fake.close_calls, failure_index)


class UnixTransportLinuxIntegrationTests(unittest.TestCase):
    def run_server_exchange(
        self, *, response: bytes = RESPONSE, chunks: tuple[int, ...] = (),
        declared_length: int | None = None, trailing: bytes = b"",
    ) -> tuple[bytes | None, OneShotServer, BaseException | None]:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "executor.sock")
            server = OneShotServer(
                path, response=response, chunks=chunks,
                declared_length=declared_length, trailing=trailing,
            )
            transport = constructed(path)
            try:
                result = transport.send(REQUEST)
                error = None
            except BaseException as exc:
                result = None
                error = exc
            server.finish()
            return result, server, error

    @unittest.skipUnless(
        hasattr(socket, "SO_PEERCRED") and hasattr(socket, "SO_DOMAIN"),
        "Linux peer credentials are required",
    )
    def test_real_socket_exact_frame_peer_and_write_eof(self) -> None:
        result, server, error = self.run_server_exchange()
        self.assertIsNone(error)
        self.assertEqual(result, RESPONSE)
        self.assertEqual(server.request_header, len(REQUEST).to_bytes(4, "big"))
        self.assertEqual(server.request, REQUEST)
        self.assertTrue(server.write_eof)

    def test_real_socket_empty_response(self) -> None:
        result, _, error = self.run_server_exchange(response=b"")
        self.assertIsNone(error)
        self.assertEqual(result, b"")

    def test_real_socket_fragmented_header_and_body(self) -> None:
        result, _, error = self.run_server_exchange(chunks=(1, 1, 1, 1, 2, 3))
        self.assertIsNone(error)
        self.assertEqual(result, RESPONSE)

    def test_real_socket_truncated_header_rejects(self) -> None:
        result, _, error = self.run_server_exchange(response=b"", declared_length=1)
        self.assertIsNone(result)
        self.assertIsInstance(error, ExecutorTransportUnavailableError)

    def test_real_socket_trailing_byte_rejects(self) -> None:
        result, _, error = self.run_server_exchange(trailing=b"x")
        self.assertIsNone(result)
        self.assertIsInstance(error, ExecutorTransportUnavailableError)

    def test_real_socket_path_is_removed_with_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "executor.sock")
            server = OneShotServer(path)
            transport = constructed(path)
            self.assertEqual(transport.send(REQUEST), RESPONSE)
            server.finish()
        self.assertFalse(Path(path).exists())

    def test_one_instance_supports_concurrent_independent_connections(self) -> None:
        count = 6
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "executor.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            os.chmod(path, 0o660)
            listener.listen(count)
            received: list[bytes] = []
            lock = threading.Lock()
            errors: list[BaseException] = []

            def serve_one(connection: socket.socket) -> None:
                try:
                    with connection:
                        header = receive_exact(connection, 4)
                        body = receive_exact(connection, int.from_bytes(header, "big"))
                        connection.recv(1)
                        with lock:
                            received.append(body)
                        reply = b"response:" + body[-1:]
                        connection.sendall(len(reply).to_bytes(4, "big") + reply)
                except BaseException as exc:
                    with lock:
                        errors.append(exc)

            def accept_all() -> None:
                workers = []
                try:
                    for _ in range(count):
                        connection, _ = listener.accept()
                        worker = threading.Thread(target=serve_one, args=(connection,))
                        worker.start()
                        workers.append(worker)
                    for worker in workers:
                        worker.join(5)
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    listener.close()

            server = threading.Thread(target=accept_all)
            server.start()
            transport = constructed(path)
            requests = [b"request-" + bytes([65 + index]) for index in range(count)]
            results: list[bytes | None] = [None] * count

            def call(index: int) -> None:
                results[index] = transport.send(requests[index])

            callers = [threading.Thread(target=call, args=(index,)) for index in range(count)]
            for caller in callers:
                caller.start()
            for caller in callers:
                caller.join(5)
            server.join(5)
            self.assertFalse(any(caller.is_alive() for caller in callers))
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [])
            self.assertCountEqual(received, requests)
            self.assertEqual(
                results,
                [b"response:" + request[-1:] for request in requests],
            )


class UnixTransportBrokerIntegrationTests(unittest.TestCase):
    def test_broker_replay_precedes_exact_socket_transmission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "executor.sock")
            server = OneShotServer(path)
            transport = constructed(path)
            replay = Replay()
            broker = RestrictedDeploymentBroker(
                verifier=Verifier(), replay_guard=replay, transport=transport,
            )
            canonical = ExecutorRequest.from_dict(valid_request()).canonical_bytes()
            result = broker.authorize_and_forward(
                compact_token="bounded.synthetic.token",
                canonical_request=canonical,
                received_at=NOW,
            )
            server.finish()
            self.assertEqual(result, RESPONSE)
            self.assertEqual(len(replay.calls), 1)
            self.assertEqual(server.request, canonical)
            self.assertNotIn(b"bounded.synthetic.token", server.request)
            self.assertNotIn(replay.calls[0]["request_hash"].encode(), server.request)
            # The protected ExecutorRequest schema itself contains oidc_jti;
            # the transport adds no second identity or metadata envelope.
            self.assertEqual(
                server.request_header + server.request,
                len(canonical).to_bytes(4, "big") + canonical,
            )

    def test_malformed_response_is_broker_unavailable_without_replay_reset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "executor.sock")
            server = OneShotServer(path, trailing=b"smuggled")
            transport = constructed(path)
            replay = Replay()
            broker = RestrictedDeploymentBroker(
                verifier=Verifier(), replay_guard=replay, transport=transport,
            )
            with self.assertRaises(BrokerUnavailableError):
                broker.authorize_and_forward(
                    compact_token="bounded.synthetic.token",
                    canonical_request=ExecutorRequest.from_dict(valid_request()).canonical_bytes(),
                    received_at=NOW,
                )
            server.finish()
            self.assertEqual(len(replay.calls), 1)
            self.assertFalse(hasattr(replay, "reset"))


class UnixTransportStaticAuthorityTests(unittest.TestCase):
    def test_module_has_no_listener_or_operational_imports(self) -> None:
        tree = ast.parse((ROOT / "deployment/unix_transport.py").read_text())
        calls = {node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {"bind", "listen", "accept", "system", "popen", "fork", "exec"})
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertFalse(imports & {"subprocess", "http", "ssl", "requests", "docker"})

    def test_module_does_not_read_environment(self) -> None:
        source = (ROOT / "deployment/unix_transport.py").read_text()
        self.assertNotIn("environ", source)
        self.assertNotIn("getenv", source)

    def test_no_production_listener_exists(self) -> None:
        tree = ast.parse((ROOT / "deployment/tests/test_unix_transport.py").read_text())
        unsafe = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"bind", "connect"}
            and any(isinstance(argument, ast.Name)
                    and argument.id == "PRODUCTION_EXECUTOR_SOCKET_PATH"
                    for argument in node.args)
        ]
        self.assertEqual(unsafe, [])

    def test_no_retry_polling_heartbeat_or_background_execution_is_added(self) -> None:
        source = (ROOT / "deployment/unix_transport.py").read_text()
        tree = ast.parse(source)
        names = {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
        } | {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        self.assertFalse(names & {
            "Thread", "ThreadPoolExecutor", "asyncio", "create_task", "sleep",
            "poll", "heartbeat", "reconnect", "retry",
        })
        send_calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"connect", "sendall", "shutdown"}
        ]
        self.assertEqual(
            [node.func.attr for node in send_calls],
            ["connect", "sendall", "sendall", "shutdown"],
        )


def _install_constructor_boundary_tests() -> None:
    bad_values = (
        ("bool", True), ("float", 1.0), ("negative", -1),
        ("reserved_max", 2**32 - 1), ("overflow", 2**32),
        ("str", "1"), ("none", None),
    )
    fields = ("expected_executor_uid", "expected_executor_gid", "expected_socket_group_gid")
    for field in fields:
        for label, bad in bad_values:
            def test(self: unittest.TestCase, field: str = field, bad: object = bad) -> None:
                values: dict[str, object] = {
                    "expected_executor_uid": 1, "expected_executor_gid": 2,
                    "expected_socket_group_gid": 3, "timeout_ms": 1000,
                }
                values[field] = bad
                with self.assertRaises(TypeError):
                    UnixExecutorTransport(**values)  # type: ignore[arg-type]
            setattr(UnixTransportConstructorTests, f"test_{field}_{label}_rejects", test)
    for label, bad in (
        ("zero", 0), ("negative", -1), ("above_max", MAX_TIMEOUT_MS + 1),
        ("bool", True), ("float", 1.0), ("subclass", type("IntChild", (int,), {})(1)),
    ):
        def test(self: unittest.TestCase, bad: object = bad) -> None:
            with self.assertRaises(TypeError):
                UnixExecutorTransport(
                    expected_executor_uid=1, expected_executor_gid=2,
                    expected_socket_group_gid=3, timeout_ms=bad,  # type: ignore[arg-type]
                )
        setattr(UnixTransportConstructorTests, f"test_timeout_{label}_rejects", test)


def _install_request_rejection_tests() -> None:
    class BytesChild(bytes):
        pass
    class Coercible:
        def __bytes__(self) -> bytes:
            raise AssertionError("must not coerce")
        def __len__(self) -> int:
            raise AssertionError("must not inspect")
    cases: tuple[tuple[str, object], ...] = (
        ("empty", b""), ("over_limit", b"x" * (MAX_CANONICAL_REQUEST_BYTES + 1)),
        ("bytes_subclass", BytesChild(b"x")), ("bytearray", bytearray(b"x")),
        ("memoryview", memoryview(b"x")), ("string", "x"),
        ("mapping", {"request": "x"}), ("request_object", ExecutorRequest.from_dict(valid_request())),
        ("coercible", Coercible()), ("none", None),
    )
    for label, bad in cases:
        def test(self: unittest.TestCase, bad: object = bad) -> None:
            fake = FakeSocket()
            transport, calls = fake_transport(fake)
            with self.assertRaisesRegex(
                ExecutorTransportUnavailableError, f"^{TRANSPORT_UNAVAILABLE_MESSAGE}$",
            ):
                transport.send(bad)  # type: ignore[arg-type]
            self.assertEqual(calls, [])
        setattr(UnixTransportRequestTests, f"test_{label}_rejects_before_io", test)


def _install_metadata_rejection_tests() -> None:
    cases = (
        ("regular", metadata(mode=stat.S_IFREG | 0o660)),
        ("directory", metadata(mode=stat.S_IFDIR | 0o660)),
        ("fifo", metadata(mode=stat.S_IFIFO | 0o660)),
        ("mode_600", metadata(mode=stat.S_IFSOCK | 0o600)),
        ("mode_666", metadata(mode=stat.S_IFSOCK | 0o666)),
        ("wrong_uid", metadata(uid=os.getuid() + 1)),
        ("wrong_gid", metadata(gid=os.getgid() + 1)),
        ("zero_links", metadata(links=0)),
        ("two_links", metadata(links=2)),
        ("negative_inode", metadata(inode=-1)),
        ("negative_device", metadata(device=-1)),
        ("non_stat", object()),
    )
    for label, bad in cases:
        def test(self: UnixTransportMetadataTests, bad: object = bad) -> None:
            fake = self.assert_metadata_rejected(bad)
            self.assertEqual(fake.connected, [])
            self.assertEqual(fake.sent, [])
        setattr(UnixTransportMetadataTests, f"test_{label}_rejects", test)


def _install_peer_rejection_tests() -> None:
    cases: tuple[tuple[str, object], ...] = (
        ("zero_pid", PEER.pack(0, os.getuid(), os.getgid())),
        ("negative_pid", PEER.pack(-1, os.getuid(), os.getgid())),
        ("wrong_uid", PEER.pack(os.getpid(), os.getuid() + 1, os.getgid())),
        ("wrong_gid", PEER.pack(os.getpid(), os.getuid(), os.getgid() + 1)),
        ("short", b"x"), ("long", b"x" * (PEER.size + 1)),
        ("bytearray", bytearray(PEER.pack(os.getpid(), os.getuid(), os.getgid()))),
        ("memoryview", memoryview(PEER.pack(os.getpid(), os.getuid(), os.getgid()))),
    )
    for label, bad in cases:
        def test(self: UnixTransportPeerTests, bad: object = bad) -> None:
            fake = self.assert_peer_rejected(bad)
            self.assertTrue(fake.closed)
        setattr(UnixTransportPeerTests, f"test_{label}_rejects", test)


def _install_framing_rejection_tests() -> None:
    cases = (
        ("empty_header", b""), ("one_header_byte", b"\x00"),
        ("three_header_bytes", b"\x00\x00\x00"),
        ("body_one_short", (4).to_bytes(4, "big") + b"abc"),
        ("body_empty", (1).to_bytes(4, "big")),
        ("one_above_limit", (unix_transport.MAX_EXECUTOR_RESPONSE_BYTES + 1).to_bytes(4, "big")),
        ("trailing_one", (1).to_bytes(4, "big") + b"a" + b"b"),
    )
    for label, framed in cases:
        def test(self: UnixTransportFramingTests, framed: bytes = framed) -> None:
            result, fake, error = self.exchange(framed)
            self.assertIsNone(result)
            self.assertIsInstance(error, ExecutorTransportUnavailableError)
            self.assertTrue(fake.closed)
        setattr(UnixTransportFramingTests, f"test_{label}_rejects", test)


def _install_clock_rejection_tests() -> None:
    cases: tuple[tuple[str, object], ...] = (
        ("bool", True), ("string", "1"), ("none", None),
        ("nan", math.nan), ("positive_infinity", math.inf),
        ("negative_infinity", -math.inf), ("negative", -1.0),
        ("float_subclass", type("FloatChild", (float,), {})(1.0)),
        ("int_subclass", type("IntChild", (int,), {})(1)),
    )
    for label, value in cases:
        def test(self: unittest.TestCase, value: object = value) -> None:
            fake = FakeSocket()
            transport, calls = fake_transport(fake, clock=Clock(values=[value]))
            with self.assertRaisesRegex(
                ExecutorTransportUnavailableError, f"^{TRANSPORT_UNAVAILABLE_MESSAGE}$",
            ):
                transport.send(REQUEST)
            self.assertEqual(calls, [])
        setattr(UnixTransportDeadlineTests, f"test_monotonic_{label}_rejects", test)


def _install_socket_failure_tests() -> None:
    operations = (
        "set_inheritable", "get_inheritable", "getsockopt", "settimeout",
        "connect", "sendall", "shutdown", "recv", "close",
    )
    for operation in operations:
        def test(self: unittest.TestCase, operation: str = operation) -> None:
            marker = f"{operation}-path-uid-gid-pid-errno-request-response-secret"
            fake = FakeSocket(failures={operation: OSError(marker)})
            transport, calls = fake_transport(fake)
            with self.assertRaises(ExecutorTransportUnavailableError) as caught:
                transport.send(REQUEST)
            self.assertEqual(str(caught.exception), TRANSPORT_UNAVAILABLE_MESSAGE)
            self.assertNotIn(marker, str(caught.exception))
            self.assertEqual(len(calls), 1)
            self.assertTrue(fake.closed)
        setattr(UnixTransportFailureTests, f"test_{operation}_failure_is_generic", test)


_install_constructor_boundary_tests()
_install_request_rejection_tests()
_install_metadata_rejection_tests()
_install_peer_rejection_tests()
_install_framing_rejection_tests()
_install_clock_rejection_tests()
_install_socket_failure_tests()


if __name__ == "__main__":
    unittest.main()
