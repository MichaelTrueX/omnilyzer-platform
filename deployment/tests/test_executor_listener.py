"""Hostile tests for the inert single-accept executor listener boundary."""

from __future__ import annotations

import ast
import importlib
import inspect
import math
import os
from pathlib import Path
import socket
import stat
import threading
import unittest
from unittest.mock import patch

import deployment.executor_listener as listener_module
from deployment.executor_listener import (
    EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE,
    MAX_ACCEPT_TIMEOUT_MS,
    PRODUCTION_EXECUTOR_SOCKET_PATH,
    ExecutorListenerUnavailableError,
    UnixExecutorListener,
)


ROOT = Path(__file__).resolve().parents[2]
PATH = "/run/omnilyzer/deployment/executor.sock"
ANCESTORS = ("/", "/run", "/run/omnilyzer", "/run/omnilyzer/deployment")


def metadata(
    mode: int, inode: int, device: int = 7, links: int = 1,
    uid: int | None = None, gid: int | None = None,
) -> os.stat_result:
    return os.stat_result((
        mode, inode, device, links,
        os.getuid() if uid is None else uid,
        os.getgid() if gid is None else gid,
        0, 0, 0, 0,
    ))


class Clock:
    def __init__(self, values: list[object] | None = None, step: float = 0.0001) -> None:
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


class FakeFilesystem:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.values = {
            ancestor: metadata(stat.S_IFDIR | 0o755, index + 10)
            for index, ancestor in enumerate(ANCESTORS)
        }
        # Linux pathname socket nodes and descriptor sockfs objects use
        # distinct device/inode namespaces; both identities are stabilized.
        self.values[PATH] = metadata(stat.S_IFSOCK | 0o660, 199, device=2049)
        self.on_call: object = None
        self.proc_calls: list[str] = []

    def lstat(self, path: str) -> object:
        self.calls.append(path)
        if self.on_call is not None:
            self.on_call(path, len(self.calls))  # type: ignore[operator]
        return self.values[path]

    def fstat(self, descriptor: int) -> object:
        if descriptor != 41:
            raise OSError("fstat-injected-marker")
        return metadata(stat.S_IFSOCK | 0o777, 99)

    def read_proc_unix(self, path: str) -> object:
        self.proc_calls.append(path)
        return (
            b"Num RefCount Protocol Flags Type St Inode Path\n"
            b"0000000000000000: 00000002 00000000 00010000 0001 01 99 "
            + PATH.encode("ascii") + b"\n"
        )


class FakeListener:
    def __init__(self, accepted: object) -> None:
        self.accepted = accepted
        self.domain: object = int(socket.AF_UNIX)
        self.kind: object = int(socket.SOCK_STREAM)
        self.accepting: object = 1
        self.inheritable: object = False
        self.name: object = PATH
        self.descriptor: object = 41
        self.timeout: object = None
        self.timeouts: list[object] = []
        self.accept_calls = 0
        self.events: list[str] = []
        self.failures: dict[str, BaseException] = {}
        self.on_accept: object = None

    def _before(self, name: str) -> None:
        self.events.append(name)
        error = self.failures.get(name)
        if error is not None:
            raise error

    def get_inheritable(self) -> object:
        self._before("get_inheritable")
        return self.inheritable

    def getsockopt(self, level: int, option: int) -> object:
        self._before("getsockopt")
        if level != socket.SOL_SOCKET:
            raise AssertionError("unexpected-level")
        if option == socket.SO_DOMAIN:
            return self.domain
        if option == socket.SO_TYPE:
            return self.kind
        if option == socket.SO_ACCEPTCONN:
            return self.accepting
        raise AssertionError("unexpected-option")

    def getsockname(self) -> object:
        self._before("getsockname")
        return self.name

    def fileno(self) -> object:
        self._before("fileno")
        return self.descriptor

    def gettimeout(self) -> object:
        self._before("gettimeout")
        return self.timeout

    def settimeout(self, value: object) -> None:
        self._before("settimeout")
        self.timeouts.append(value)
        self.timeout = value

    def accept(self) -> object:
        self._before("accept")
        self.accept_calls += 1
        if self.on_accept is not None:
            self.on_accept()  # type: ignore[operator]
        return self.accepted


class Handler:
    def __init__(self, *, close: bool = True, result: object = None) -> None:
        self.close = close
        self.result = result
        self.calls: list[object] = []
        self.error: BaseException | None = None
        self.on_handle: object = None

    def handle(self, connection: object) -> None:
        self.calls.append(connection)
        if self.on_handle is not None:
            self.on_handle()  # type: ignore[operator]
        if self.close:
            connection.close()  # type: ignore[attr-defined]
        if self.error is not None:
            raise self.error
        return self.result  # type: ignore[return-value]


class Closeable:
    def __init__(self) -> None:
        self.close_calls = 0
        self.error: BaseException | None = None

    def close(self) -> None:
        self.close_calls += 1
        if self.error is not None:
            raise self.error


def make_listener(
    raw_listener: FakeListener, handler: Handler, *, filesystem: FakeFilesystem | None = None,
    clock: Clock | None = None, timeout_ms: int = 1000,
) -> tuple[UnixExecutorListener, FakeFilesystem, Clock]:
    filesystem = filesystem or FakeFilesystem()
    clock = clock or Clock()
    with (
        patch.object(listener_module.os, "lstat", filesystem.lstat),
        patch.object(listener_module.os, "fstat", filesystem.fstat),
        patch.object(listener_module.time, "monotonic", clock),
        patch.object(listener_module, "_read_proc_unix", filesystem.read_proc_unix),
    ):
        instance = UnixExecutorListener(
            listener=raw_listener, handler=handler,
            expected_socket_owner_uid=os.getuid(),
            expected_socket_group_gid=os.getgid(),
            accept_timeout_ms=timeout_ms,
        )
    return instance, filesystem, clock


def socket_pair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)


class ConstructorTests(unittest.TestCase):
    def test_import_and_construction_are_inert_and_api_is_closed(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(peer.close)
        self.addCleanup(server.close)
        raw = FakeListener((server, ""))
        fs = FakeFilesystem()
        with (
            patch.object(listener_module.os, "lstat", side_effect=AssertionError("lstat")),
            patch.object(listener_module.os, "fstat", side_effect=AssertionError("fstat")),
            patch.object(listener_module.time, "monotonic", side_effect=AssertionError("clock")),
        ):
            instance = UnixExecutorListener(
                listener=raw, handler=Handler(), expected_socket_owner_uid=1,
                expected_socket_group_gid=2, accept_timeout_ms=3000,
            )
        self.assertIsInstance(instance, UnixExecutorListener)
        self.assertEqual(raw.events, [])
        self.assertEqual(fs.calls, [])
        self.assertEqual(
            tuple(inspect.signature(UnixExecutorListener).parameters),
            ("listener", "handler", "expected_socket_owner_uid", "expected_socket_group_gid", "accept_timeout_ms"),
        )
        self.assertEqual(
            tuple(inspect.signature(UnixExecutorListener.serve_once).parameters), ("self",),
        )
        self.assertEqual(
            {name for name, value in vars(UnixExecutorListener).items()
             if not name.startswith("_") and callable(value)},
            {"serve_once"},
        )

    def test_module_import_has_no_operational_top_level_calls(self) -> None:
        tree = ast.parse((ROOT / "deployment/executor_listener.py").read_text())
        forbidden = {"bind", "listen", "accept", "unlink", "chmod", "chown", "fork", "Popen", "run"}
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                name = getattr(node.value.func, "attr", getattr(node.value.func, "id", ""))
                self.assertNotIn(name, forbidden)
        self.assertIs(importlib.import_module("deployment.executor_listener"), listener_module)

    def test_configuration_is_immutable_and_path_is_not_configurable(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(peer.close)
        self.addCleanup(server.close)
        raw = FakeListener((server, ""))
        instance, _, _ = make_listener(raw, Handler())
        with self.assertRaises(AttributeError):
            instance._configuration = ()  # type: ignore[misc]
        self.assertEqual(PRODUCTION_EXECUTOR_SOCKET_PATH, PATH)
        self.assertNotIn("path", inspect.signature(UnixExecutorListener).parameters)

    def test_module_mutation_cannot_redirect_captured_path_or_operations(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        handler = Handler()
        instance, _, _ = make_listener(raw, handler)
        with (
            patch.object(listener_module, "PRODUCTION_EXECUTOR_SOCKET_PATH", "/injected"),
            patch.object(listener_module, "_validate_listener", side_effect=AssertionError("redirect")),
            patch.object(listener_module, "_timeout_value", side_effect=AssertionError("redirect")),
        ):
            self.assertIsNone(instance.serve_once())
        self.assertEqual(handler.calls, [accepted])

    def test_valid_configuration_boundaries(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(server.close)
        self.addCleanup(peer.close)
        for identity in (0, listener_module.MAX_IDENTITY_VALUE):
            for timeout in (1, MAX_ACCEPT_TIMEOUT_MS):
                self.assertIsInstance(
                    UnixExecutorListener(
                        listener=FakeListener((server, "")), handler=Handler(),
                        expected_socket_owner_uid=identity,
                        expected_socket_group_gid=identity,
                        accept_timeout_ms=timeout,
                    ),
                    UnixExecutorListener,
                )

    def test_invalid_configuration_and_hostile_collaborators_reject(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(server.close)
        self.addCleanup(peer.close)
        int_child = type("IntChild", (int,), {})(1)
        for field, values in (
            ("expected_socket_owner_uid", (True, -1, 2**32 - 1, 1.0, int_child)),
            ("expected_socket_group_gid", (False, -1, 2**32, "1", int_child)),
            ("accept_timeout_ms", (True, 0, -1, 3001, 1.0, int_child)),
        ):
            for value in values:
                arguments: dict[str, object] = {
                    "listener": FakeListener((server, "")), "handler": Handler(),
                    "expected_socket_owner_uid": 1, "expected_socket_group_gid": 2,
                    "accept_timeout_ms": 1000,
                }
                arguments[field] = value
                with self.subTest(field=field, value=repr(value)), self.assertRaises(TypeError):
                    UnixExecutorListener(**arguments)  # type: ignore[arg-type]

        class PropertyListener(FakeListener):
            @property
            def accept(self) -> object:  # type: ignore[override]
                raise AssertionError("property-marker")

        class StaticHandler:
            @staticmethod
            def handle(connection: object) -> None:
                return None

        with self.assertRaises(TypeError):
            UnixExecutorListener(
                listener=PropertyListener((server, "")), handler=Handler(),
                expected_socket_owner_uid=1, expected_socket_group_gid=2,
            )

        class Dynamic:
            def __getattr__(self, name: str) -> object:
                raise AssertionError("dynamic-marker")

        with self.assertRaises(TypeError):
            UnixExecutorListener(
                listener=Dynamic(), handler=Handler(),
                expected_socket_owner_uid=1, expected_socket_group_gid=2,
            )
        with self.assertRaises(TypeError):
            UnixExecutorListener(
                listener=FakeListener((server, "")), handler=StaticHandler(),
                expected_socket_owner_uid=1, expected_socket_group_gid=2,
            )


class ValidationTests(unittest.TestCase):
    def rejected(
        self, raw: FakeListener, *, filesystem: FakeFilesystem | None = None,
        marker: str | None = None,
    ) -> None:
        handler = Handler()
        instance, _, _ = make_listener(raw, handler, filesystem=filesystem)
        with self.assertRaisesRegex(
            ExecutorListenerUnavailableError,
            f"^{EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE}$",
        ) as caught:
            instance.serve_once()
        self.assertEqual(raw.accept_calls, 0)
        self.assertEqual(handler.calls, [])
        if marker is not None:
            self.assertNotIn(marker, str(caught.exception))

    def test_descriptor_rejections_happen_before_accept(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(server.close)
        self.addCleanup(peer.close)
        mutations = (
            ("domain", int(socket.AF_INET)),
            ("domain", type("IntChild", (int,), {})(socket.AF_UNIX)),
            ("kind", int(socket.SOCK_DGRAM)),
            ("kind", type("IntChild", (int,), {})(socket.SOCK_STREAM)),
            ("accepting", 0), ("accepting", True),
            ("inheritable", True), ("inheritable", 0),
            ("name", "/injected/socket"), ("name", type("StrChild", (str,), {})(PATH)),
            ("descriptor", -1), ("descriptor", True),
        )
        for field, value in mutations:
            raw = FakeListener((server, ""))
            setattr(raw, field, value)
            with self.subTest(field=field, value=repr(value)):
                self.rejected(raw)

    def test_missing_linux_controls_fail_closed(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(server.close)
        self.addCleanup(peer.close)
        raw = FakeListener((server, ""))
        with patch.object(listener_module.socket, "SO_DOMAIN", None):
            instance, _, _ = make_listener(raw, Handler())
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        self.assertEqual(raw.accept_calls, 0)

    def test_leaf_type_mode_owner_group_links_and_identity_reject(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(server.close)
        self.addCleanup(peer.close)
        cases = (
            metadata(stat.S_IFLNK | 0o777, 99),
            metadata(stat.S_IFREG | 0o660, 99),
            metadata(stat.S_IFSOCK | 0o600, 99),
            metadata(stat.S_IFSOCK | 0o660, 99, uid=os.getuid() + 1),
            metadata(stat.S_IFSOCK | 0o660, 99, gid=os.getgid() + 1),
            metadata(stat.S_IFSOCK | 0o660, 99, links=2),
        )
        for value in cases:
            fs = FakeFilesystem()
            fs.values[PATH] = value
            with self.subTest(value=tuple(value)[:6]):
                self.rejected(FakeListener((server, "")), filesystem=fs)

    def test_non_socket_descriptor_and_hostile_metadata_reject(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(server.close)
        self.addCleanup(peer.close)
        fs = FakeFilesystem()
        fs.fstat = lambda descriptor: metadata(stat.S_IFREG | 0o660, 99)  # type: ignore[method-assign]
        self.rejected(FakeListener((server, "")), filesystem=fs)
        fs = FakeFilesystem()
        fs.values[PATH] = tuple(fs.values[PATH])  # type: ignore[assignment]
        self.rejected(FakeListener((server, "")), filesystem=fs)

    def test_proc_binding_must_be_unique_and_match_descriptor_inode(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(server.close)
        self.addCleanup(peer.close)
        rows = (
            b"Num RefCount Protocol Flags Type St Inode Path\n",
            b"Num RefCount Protocol Flags Type St Inode Path\n"
            b"0: 2 0 00010000 0001 01 100 /run/omnilyzer/deployment/executor.sock\n",
            b"Num RefCount Protocol Flags Type St Inode Path\n"
            b"0: 2 0 00010000 0001 01 99 /run/omnilyzer/deployment/executor.sock\n"
            b"1: 2 0 00010000 0001 01 100 /run/omnilyzer/deployment/executor.sock\n",
            b"\xff\n",
        )
        for value in rows:
            fs = FakeFilesystem()
            fs.read_proc_unix = lambda path, value=value: value  # type: ignore[method-assign]
            with self.subTest(value=value):
                self.rejected(FakeListener((server, "")), filesystem=fs)

    def test_connected_proc_row_does_not_conflict_with_unique_listener(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        fs = FakeFilesystem()
        original = fs.read_proc_unix
        fs.read_proc_unix = lambda path: (  # type: ignore[method-assign]
            original(path)
            + b"1: 3 0 00000000 0001 03 101 /run/omnilyzer/deployment/executor.sock\n"
        )
        handler = Handler()
        instance, _, _ = make_listener(FakeListener((accepted, "")), handler, filesystem=fs)
        self.assertIsNone(instance.serve_once())
        self.assertEqual(handler.calls, [accepted])

    def test_ancestor_symlink_or_replacement_fails_closed(self) -> None:
        server, peer = socket_pair()
        self.addCleanup(server.close)
        self.addCleanup(peer.close)
        fs = FakeFilesystem()
        fs.values["/run/omnilyzer"] = metadata(stat.S_IFLNK | 0o777, 12)
        self.rejected(FakeListener((server, "")), filesystem=fs)

        accepted, peer2 = socket_pair()
        self.addCleanup(peer2.close)
        raw = FakeListener((accepted, ""))
        fs = FakeFilesystem()
        def mutate(path: str, call: int) -> None:
            if call == 6:
                fs.values["/run"] = metadata(stat.S_IFDIR | 0o755, 777)
        fs.on_call = mutate
        handler = Handler()
        instance, _, _ = make_listener(raw, handler, filesystem=fs)
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        self.assertEqual(raw.accept_calls, 1)
        self.assertEqual(handler.calls, [])
        self.assertEqual(accepted.fileno(), -1)

    def test_validation_order_is_before_accept_and_repeated_after(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        handler = Handler()
        instance, fs, _ = make_listener(raw, handler)
        self.assertIsNone(instance.serve_once())
        self.assertEqual(raw.accept_calls, 1)
        self.assertEqual(fs.calls, list(ANCESTORS) + [PATH] + list(ANCESTORS) + [PATH])
        self.assertLess(raw.events.index("getsockname"), raw.events.index("accept"))
        self.assertGreater(raw.events.index("getsockname", raw.events.index("accept")), raw.events.index("accept"))


class AcceptAndHandoffTests(unittest.TestCase):
    def test_exact_connection_is_dispatched_once_and_owned_by_handler(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        handler = Handler()
        instance, _, _ = make_listener(raw, handler)
        self.assertIsNone(instance.serve_once())
        self.assertEqual(raw.accept_calls, 1)
        self.assertEqual(handler.calls, [accepted])
        self.assertEqual(accepted.fileno(), -1)
        self.assertEqual(raw.timeout, None)
        self.assertEqual(len(raw.timeouts), 2)
        self.assertGreater(raw.timeouts[0], 0)
        self.assertLessEqual(raw.timeouts[0], 1.0)
        self.assertIsNone(raw.timeouts[1])

    def test_malformed_accept_results_fail_and_do_not_retry(self) -> None:
        tuple_child = type("TupleChild", (tuple,), {})((object(), ""))
        cases: tuple[object, ...] = (
            None, (), (object(),), (object(), "", "extra"), [object(), ""], tuple_child,
        )
        for result in cases:
            raw = FakeListener(result)
            handler = Handler()
            instance, _, _ = make_listener(raw, handler)
            with self.subTest(result=repr(result)), self.assertRaises(ExecutorListenerUnavailableError):
                instance.serve_once()
            self.assertEqual(raw.accept_calls, 1)
            self.assertEqual(handler.calls, [])

    def test_malformed_accepted_address_closes_before_dispatch(self) -> None:
        for address in (object(), b"", "injected-address", type("StrChild", (str,), {})("")):
            accepted, peer = socket_pair()
            self.addCleanup(peer.close)
            raw = FakeListener((accepted, address))
            handler = Handler()
            instance, _, _ = make_listener(raw, handler)
            with self.subTest(address=repr(address)), self.assertRaises(ExecutorListenerUnavailableError):
                instance.serve_once()
            self.assertEqual(handler.calls, [])
            self.assertEqual(accepted.fileno(), -1)

    def test_malformed_container_with_real_socket_is_closed(self) -> None:
        tuple_child_type = type("TupleChildWithSocket", (tuple,), {})
        containers = (lambda value: [value, ""], lambda value: tuple_child_type((value, "")))
        for container in containers:
            accepted, peer = socket_pair()
            self.addCleanup(peer.close)
            raw = FakeListener(container(accepted))
            instance, _, _ = make_listener(raw, Handler())
            with self.assertRaises(ExecutorListenerUnavailableError):
                instance.serve_once()
            self.assertEqual(accepted.fileno(), -1)

    def test_exact_wrong_arity_tuple_and_socket_subclass_are_closed(self) -> None:
        factories = (
            lambda value: (value,),
            lambda value: (value, "", "extra"),
        )
        for factory in factories:
            accepted, peer = socket_pair()
            self.addCleanup(peer.close)
            instance, _, _ = make_listener(FakeListener(factory(accepted)), Handler())
            with self.assertRaises(ExecutorListenerUnavailableError):
                instance.serve_once()
            self.assertEqual(accepted.fileno(), -1)

        class SocketChild(socket.socket):
            pass

        accepted = SocketChild(socket.AF_UNIX, socket.SOCK_STREAM)
        instance, _, _ = make_listener(FakeListener((accepted, "")), Handler())
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        self.assertEqual(accepted.fileno(), -1)

    def test_late_deadline_failure_after_accept_closes_connection(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        clock = Clock()
        raw.on_accept = lambda: setattr(clock, "current", clock.current + 2.0)
        handler = Handler()
        instance, _, _ = make_listener(raw, handler, clock=clock)
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        self.assertEqual(handler.calls, [])
        self.assertEqual(accepted.fileno(), -1)

    def test_non_socket_accepted_object_is_closed_once_before_dispatch(self) -> None:
        connection = Closeable()
        raw = FakeListener((connection, "marker-address"))
        handler = Handler()
        instance, _, _ = make_listener(raw, handler)
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        self.assertEqual(connection.close_calls, 1)
        self.assertEqual(handler.calls, [])
        self.assertEqual(raw.accept_calls, 1)

    def test_predispatch_close_failure_is_redacted(self) -> None:
        connection = Closeable()
        connection.error = OSError("close-injected-marker")
        raw = FakeListener((connection, ""))
        instance, _, _ = make_listener(raw, Handler())
        with self.assertRaisesRegex(
            ExecutorListenerUnavailableError,
            f"^{EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE}$",
        ):
            instance.serve_once()
        self.assertEqual(connection.close_calls, 1)

    def test_post_accept_path_change_closes_without_dispatch(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        fs = FakeFilesystem()
        def replace(path: str, call: int) -> None:
            if call == 6:
                fs.values[PATH] = metadata(stat.S_IFSOCK | 0o660, 101)
        fs.on_call = replace
        handler = Handler()
        instance, _, _ = make_listener(raw, handler, filesystem=fs)
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        self.assertEqual(handler.calls, [])
        self.assertEqual(raw.accept_calls, 1)
        self.assertEqual(accepted.fileno(), -1)

    def test_handler_non_none_or_failure_is_generic_without_retry_or_double_close(self) -> None:
        for result, error in ((object(), None), (None, OSError("handler-injected-marker"))):
            accepted, peer = socket_pair()
            self.addCleanup(peer.close)
            raw = FakeListener((accepted, ""))
            handler = Handler(result=result)
            handler.error = error
            instance, _, _ = make_listener(raw, handler)
            with self.subTest(error=error), self.assertRaisesRegex(
                ExecutorListenerUnavailableError,
                f"^{EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE}$",
            ) as caught:
                instance.serve_once()
            self.assertNotIn("injected", str(caught.exception))
            self.assertEqual(raw.accept_calls, 1)
            self.assertEqual(handler.calls, [accepted])
            self.assertEqual(accepted.fileno(), -1)

    def test_listener_does_not_close_a_dispatched_connection(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(accepted.close)
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        handler = Handler(close=False)
        instance, _, _ = make_listener(raw, handler)
        self.assertIsNone(instance.serve_once())
        self.assertGreaterEqual(accepted.fileno(), 0)
        self.assertEqual(handler.calls, [accepted])

    def test_accept_deadline_does_not_span_handler_execution(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        clock = Clock()
        handler = Handler()
        handler.on_handle = lambda: setattr(clock, "current", clock.current + 600.0)
        instance, _, _ = make_listener(raw, handler, clock=clock)
        self.assertIsNone(instance.serve_once())
        self.assertEqual(handler.calls, [accepted])
        self.assertEqual(raw.timeout, None)


class DeadlineCleanupAndControlTests(unittest.TestCase):
    def test_accept_is_once_and_deadline_never_restarts_or_retries_eintr(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(accepted.close)
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        raw.failures["accept"] = InterruptedError("eintr-marker")
        clock = Clock(step=0.001)
        instance, _, _ = make_listener(raw, Handler(), clock=clock)
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        self.assertEqual(raw.accept_calls, 0)
        self.assertEqual(sum(event == "accept" for event in raw.events), 1)
        positive = [value for value in raw.timeouts if type(value) is float]
        self.assertEqual(len(positive), 1)
        self.assertLessEqual(positive[0], 1.0)

    def test_clock_invalid_nonfinite_rollback_and_expiry_fail_closed(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(accepted.close)
        self.addCleanup(peer.close)
        clocks = (
            Clock(["bad"]), Clock([math.nan]), Clock([math.inf]), Clock([-1.0]),
            Clock([100.0, 99.0]), Clock(step=2.0),
        )
        for clock in clocks:
            raw = FakeListener((accepted, ""))
            instance, _, _ = make_listener(raw, Handler(), clock=clock)
            with self.subTest(clock=clock), self.assertRaises(ExecutorListenerUnavailableError):
                instance.serve_once()
            self.assertEqual(raw.accept_calls, 0)

    def test_timeout_restored_on_success_and_failure(self) -> None:
        for failure in (None, OSError("accept-marker")):
            accepted, peer = socket_pair()
            self.addCleanup(accepted.close)
            self.addCleanup(peer.close)
            raw = FakeListener((accepted, ""))
            raw.timeout = 2.5
            if failure is not None:
                raw.failures["accept"] = failure
            instance, _, _ = make_listener(raw, Handler())
            if failure is None:
                self.assertIsNone(instance.serve_once())
            else:
                with self.assertRaises(ExecutorListenerUnavailableError):
                    instance.serve_once()
            self.assertEqual(raw.timeout, 2.5)
            self.assertEqual(raw.timeouts[-1], 2.5)

    def test_timeout_restore_failure_is_generic(self) -> None:
        class RestoreFailListener(FakeListener):
            def __init__(self, accepted: object) -> None:
                super().__init__(accepted)
                self.set_calls = 0

            def settimeout(self, value: object) -> None:
                self.set_calls += 1
                if self.set_calls == 2:
                    raise OSError("restore-injected-marker")
                super().settimeout(value)

        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = RestoreFailListener((accepted, ""))
        instance, _, _ = make_listener(raw, Handler())
        with self.assertRaisesRegex(
            ExecutorListenerUnavailableError,
            f"^{EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE}$",
        ):
            instance.serve_once()
        self.assertEqual(raw.set_calls, 3)
        self.assertEqual(accepted.fileno(), -1)

    def test_timeout_restore_verification_failure_prevents_dispatch(self) -> None:
        class RestoreMismatchListener(FakeListener):
            def __init__(self, accepted: object) -> None:
                super().__init__(accepted)
                self.get_calls = 0

            def gettimeout(self) -> object:
                self.get_calls += 1
                if self.get_calls == 2:
                    return 2.0
                return super().gettimeout()

        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = RestoreMismatchListener((accepted, ""))
        handler = Handler()
        instance, _, _ = make_listener(raw, handler)
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        self.assertEqual(handler.calls, [])
        self.assertEqual(accepted.fileno(), -1)

    def test_reentrant_call_rejects_and_outer_call_accepts_only_once(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        handler = Handler()
        instance, _, _ = make_listener(raw, handler)
        nested: list[BaseException] = []
        def reenter() -> None:
            try:
                instance.serve_once()
            except BaseException as error:
                nested.append(error)
        raw.on_accept = reenter
        self.assertIsNone(instance.serve_once())
        self.assertEqual(raw.accept_calls, 1)
        self.assertEqual(len(nested), 1)
        self.assertIsInstance(nested[0], ExecutorListenerUnavailableError)

    def test_concurrent_calls_cannot_both_proceed(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        entered = threading.Event()
        release = threading.Event()
        def block_accept() -> None:
            entered.set()
            if not release.wait(5):
                raise AssertionError("coordination-timeout")
        raw.on_accept = block_accept
        instance, _, _ = make_listener(raw, Handler())
        outcomes: list[BaseException | None] = []
        def first() -> None:
            try:
                instance.serve_once()
                outcomes.append(None)
            except BaseException as error:
                outcomes.append(error)
        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(entered.wait(5))
        with self.assertRaises(ExecutorListenerUnavailableError):
            instance.serve_once()
        release.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes, [None])
        self.assertEqual(raw.accept_calls, 1)

    def test_collaborator_method_replacement_does_not_redirect_inflight(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(peer.close)
        raw = FakeListener((accepted, ""))
        original = Handler()
        replacement = Handler()
        instance, _, _ = make_listener(raw, original)
        raw.on_accept = lambda: setattr(original, "handle", replacement.handle)
        self.assertIsNone(instance.serve_once())
        self.assertEqual(original.calls, [accepted])
        self.assertEqual(replacement.calls, [])

    def test_control_flow_exceptions_are_preserved_after_cleanup(self) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            accepted, peer = socket_pair()
            self.addCleanup(peer.close)
            raw = FakeListener((accepted, ""))
            handler = Handler()
            handler.error = exception_type("control-marker")
            instance, _, _ = make_listener(raw, handler)
            with self.subTest(exception_type=exception_type), self.assertRaises(exception_type):
                instance.serve_once()
            self.assertEqual(raw.timeout, None)
            self.assertEqual(accepted.fileno(), -1)

    def test_other_baseexception_and_clock_exception_are_normalized(self) -> None:
        class HostileBase(BaseException):
            pass

        for source in ("handler", "clock"):
            accepted, peer = socket_pair()
            self.addCleanup(accepted.close)
            self.addCleanup(peer.close)
            raw = FakeListener((accepted, ""))
            handler = Handler()
            clock = Clock()
            if source == "handler":
                handler.error = HostileBase("base-injected-marker")
            else:
                clock = Clock([HostileBase("clock-injected-marker")])

                def raising_clock() -> object:
                    value = clock.values.pop(0)
                    raise value  # type: ignore[misc]

                with patch.object(listener_module.time, "monotonic", raising_clock):
                    instance = UnixExecutorListener(
                        listener=raw, handler=handler,
                        expected_socket_owner_uid=os.getuid(),
                        expected_socket_group_gid=os.getgid(),
                    )
            if source == "handler":
                instance, _, _ = make_listener(raw, handler, clock=clock)
            with self.subTest(source=source), self.assertRaisesRegex(
                ExecutorListenerUnavailableError,
                f"^{EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE}$",
            ):
                instance.serve_once()

    def test_all_operational_details_are_redacted(self) -> None:
        accepted, peer = socket_pair()
        self.addCleanup(accepted.close)
        self.addCleanup(peer.close)
        markers = (
            PATH, "uid=123", "gid=456", "inode=99", "payload-secret",
            "dependency-injected-marker", "accepted-address",
        )
        raw = FakeListener((accepted, ""))
        raw.failures["getsockname"] = OSError(" ".join(markers))
        instance, _, _ = make_listener(raw, Handler())
        with self.assertRaises(ExecutorListenerUnavailableError) as caught:
            instance.serve_once()
        self.assertEqual(str(caught.exception), EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE)
        for marker in markers:
            self.assertNotIn(marker, str(caught.exception))


class ScopeTests(unittest.TestCase):
    def test_no_operational_api_or_forbidden_call_is_present(self) -> None:
        source = (ROOT / "deployment/executor_listener.py").read_text()
        tree = ast.parse(source)
        public = set(listener_module.__all__)
        forbidden_public = {"bind", "listen", "unlink", "chmod", "chown", "fork", "shutdown", "run", "start", "stop"}
        self.assertTrue(public.isdisjoint(forbidden_public))
        forbidden_attributes = {"bind", "listen", "unlink", "chmod", "chown", "fork", "Popen", "system"}
        used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertTrue(used.isdisjoint(forbidden_attributes))
        self.assertNotIn("subprocess", source)
        self.assertNotIn("docker", source.lower())
        self.assertNotIn("registry", source.lower())

    def test_c7_handler_boundary_remains_unchanged_and_authoritative(self) -> None:
        source = (ROOT / "deployment/executor_listener.py").read_text()
        for forbidden in ("recv(", "send(", "SO_PEERCRED", "parse_canonical", "execute("):
            self.assertNotIn(forbidden, source)
        self.assertEqual(
            tuple(inspect.signature(listener_module._handler_operation).parameters),
            ("handler",),
        )


if __name__ == "__main__":
    unittest.main()
