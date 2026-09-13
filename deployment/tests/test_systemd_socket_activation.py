"""deployment/tests/test_systemd_socket_activation.py — inert C16 handoff tests.

These unittest/mock tests prove the closed systemd FD 3 acquisition contract
without systemd, a real inherited descriptor, a real listener, or host action.
"""

from __future__ import annotations

import ast
from contextlib import ExitStack
import importlib
import inspect
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import deployment.systemd_socket_activation as activation
from deployment.systemd_socket_activation import (
    ExecutorSocketActivationError,
    acquire_systemd_executor_listener,
)


SOURCE = Path(activation.__file__)
VARIABLES = ("LISTEN_PID", "LISTEN_PIDFDID", "LISTEN_FDS", "LISTEN_FDNAMES")
GENERIC_ERROR = "executor socket activation is unavailable"


class Text(str):
    """Represent a non-exact environment string supplied by a test double."""


class FakeListener:
    """Record inherited-listener operations without owning a real descriptor."""

    def __init__(
        self, *, descriptor: object = 3, inheritable: object = False,
        set_error: BaseException | None = None,
        get_error: BaseException | None = None,
        fileno_error: BaseException | None = None,
    ) -> None:
        self.descriptor = descriptor
        self.inheritable = inheritable
        self.set_error = set_error
        self.get_error = get_error
        self.fileno_error = fileno_error
        self.set_calls: list[object] = []
        self.get_calls = 0
        self.fileno_calls = 0
        self.close_calls = 0

    def set_inheritable(self, value: object) -> None:
        self.set_calls.append(value)
        if self.set_error is not None:
            raise self.set_error

    def get_inheritable(self) -> object:
        self.get_calls += 1
        if self.get_error is not None:
            raise self.get_error
        return self.inheritable

    def fileno(self) -> object:
        self.fileno_calls += 1
        if self.fileno_error is not None:
            raise self.fileno_error
        return self.descriptor

    def close(self) -> None:
        self.close_calls += 1


def environment(**changes: object) -> dict[str, object]:
    """Return valid mocked activation state with selected overrides."""

    values: dict[str, object] = {
        "LISTEN_PID": "4242",
        "LISTEN_FDS": "1",
        "LISTEN_FDNAMES": "omnilyzer-executor",
    }
    values.update(changes)
    return values


def assert_consumed(test: unittest.TestCase, values: dict[str, object]) -> None:
    """Assert all activation variables were removed from the mocked process."""

    for name in VARIABLES:
        test.assertNotIn(name, values)


class ImportAndSurfaceTests(unittest.TestCase):
    """Prove import inertness and the exact closed public API."""

    def test_reload_is_inert_and_does_not_consume_environment(self) -> None:
        values = environment(LISTEN_PIDFDID="77777")
        original = dict(values)
        blockers = (
            patch.object(activation._os, "environ", values),
            patch.object(activation._os, "getenv", side_effect=AssertionError("getenv")),
            patch.object(activation._os, "getpid", side_effect=AssertionError("getpid")),
            patch.object(activation._os, "fstat", side_effect=AssertionError("fstat")),
            patch.object(activation._os, "close", side_effect=AssertionError("close")),
            patch.object(activation._socket, "socket", side_effect=AssertionError("socket")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
        )
        if hasattr(activation._os, "pidfd_open"):
            blockers += (
                patch.object(
                    activation._os, "pidfd_open",
                    side_effect=AssertionError("pidfd_open"),
                ),
            )
        with ExitStack() as stack:
            for blocker in blockers:
                stack.enter_context(blocker)
            importlib.reload(activation)
        self.assertEqual(values, original)

    def test_exact_public_surface_and_zero_argument_function(self) -> None:
        self.assertEqual(activation.__all__, (
            "ExecutorSocketActivationError",
            "acquire_systemd_executor_listener",
        ))
        self.assertEqual(
            tuple(inspect.signature(acquire_systemd_executor_listener).parameters),
            (),
        )
        public_callables = {
            name for name, value in vars(activation).items()
            if not name.startswith("_") and callable(value)
        }
        self.assertEqual(public_callables, {
            "ExecutorSocketActivationError",
            "acquire_systemd_executor_listener",
        })
        for name in (
            "install", "activate", "bind", "listen", "connect", "accept",
            "run", "systemctl", "service", "socket_unit", "reset", "retry",
        ):
            self.assertFalse(hasattr(activation, name))


class AcquisitionTests(unittest.TestCase):
    """Exercise success and every closed fail-closed acquisition boundary."""

    def test_basic_success_claims_only_fd3_and_consumes_environment(self) -> None:
        values = environment()
        listener = FakeListener()
        factory = Mock(return_value=listener)
        with (
            patch.object(activation._os, "environ", values),
            patch.object(activation._os, "getpid", return_value=4242),
            patch.object(activation._socket, "socket", factory),
        ):
            returned = acquire_systemd_executor_listener()
        self.assertIs(returned, listener)
        factory.assert_called_once_with(fileno=3)
        self.assertEqual(listener.set_calls, [False])
        self.assertEqual(listener.get_calls, 1)
        self.assertEqual(listener.fileno_calls, 1)
        self.assertEqual(listener.close_calls, 0)
        assert_consumed(self, values)

    def test_success_with_pidfd_identity_closes_temporary_fd(self) -> None:
        values = environment(LISTEN_PIDFDID="77777")
        listener = FakeListener()
        factory = Mock(return_value=listener)
        with (
            patch.object(activation._os, "environ", values),
            patch.object(activation._os, "getpid", return_value=4242),
            patch.object(activation._os, "pidfd_open", return_value=91) as opened,
            patch.object(
                activation._os, "fstat",
                return_value=SimpleNamespace(st_ino=77777),
            ) as inspected,
            patch.object(activation._os, "close") as closed,
            patch.object(activation._socket, "socket", factory),
        ):
            returned = acquire_systemd_executor_listener()
        self.assertIs(returned, listener)
        opened.assert_called_once_with(4242, 0)
        inspected.assert_called_once_with(91)
        closed.assert_called_once_with(91)
        factory.assert_called_once_with(fileno=3)
        assert_consumed(self, values)

    def test_pid_binding_failures_never_claim_a_socket(self) -> None:
        invalid = (
            None, "", "0", "-4242", "+4242", "04242", " 4242",
            "4242 ", "4242\n", "4243", "4_242", Text("4242"), 4242,
        )
        for value in invalid:
            values = environment()
            if value is None:
                values.pop("LISTEN_PID")
            else:
                values["LISTEN_PID"] = value
            factory = Mock()
            with self.subTest(value=repr(value)):
                with (
                    patch.object(activation._os, "environ", values),
                    patch.object(activation._os, "getpid", return_value=4242),
                    patch.object(activation._socket, "socket", factory),
                ):
                    with self.assertRaisesRegex(
                        ExecutorSocketActivationError, f"^{GENERIC_ERROR}$",
                    ):
                        acquire_systemd_executor_listener()
            factory.assert_not_called()
            assert_consumed(self, values)

    def test_fd_count_failures_never_claim_a_socket(self) -> None:
        invalid = (
            None, "", "0", "2", "01", "+1", "-1", " 1", "1 ",
            "1\n", Text("1"), 1,
        )
        for value in invalid:
            values = environment()
            if value is None:
                values.pop("LISTEN_FDS")
            else:
                values["LISTEN_FDS"] = value
            factory = Mock()
            with self.subTest(value=repr(value)):
                with (
                    patch.object(activation._os, "environ", values),
                    patch.object(activation._os, "getpid", return_value=4242),
                    patch.object(activation._socket, "socket", factory),
                ):
                    with self.assertRaises(ExecutorSocketActivationError):
                        acquire_systemd_executor_listener()
            factory.assert_not_called()
            assert_consumed(self, values)

    def test_fd_name_failures_never_claim_a_socket(self) -> None:
        invalid = (
            None, "", "executor", "omnilyzer", "Omnilyzer-executor",
            "omnilyzer_executor", "omnilyzer-executor:",
            ":omnilyzer-executor", "omnilyzer-executor:other",
            " omnilyzer-executor", "omnilyzer-executor ",
            "omnilyzer-executor\n", Text("omnilyzer-executor"), 1,
        )
        for value in invalid:
            values = environment()
            if value is None:
                values.pop("LISTEN_FDNAMES")
            else:
                values["LISTEN_FDNAMES"] = value
            factory = Mock()
            with self.subTest(value=repr(value)):
                with (
                    patch.object(activation._os, "environ", values),
                    patch.object(activation._os, "getpid", return_value=4242),
                    patch.object(activation._socket, "socket", factory),
                ):
                    with self.assertRaises(ExecutorSocketActivationError):
                        acquire_systemd_executor_listener()
            factory.assert_not_called()
            assert_consumed(self, values)

    def test_pidfd_identity_value_failures_do_not_open_pidfd(self) -> None:
        invalid = (
            "", "0", "-1", "+77777", "077777", " 77777", "77777 ",
            "77777\n", Text("77777"), 77777,
        )
        for value in invalid:
            values = environment(LISTEN_PIDFDID=value)
            factory = Mock()
            with self.subTest(value=repr(value)):
                with (
                    patch.object(activation._os, "environ", values),
                    patch.object(activation._os, "getpid", return_value=4242),
                    patch.object(activation._os, "pidfd_open") as opened,
                    patch.object(activation._socket, "socket", factory),
                ):
                    with self.assertRaises(ExecutorSocketActivationError):
                        acquire_systemd_executor_listener()
            opened.assert_not_called()
            factory.assert_not_called()
            assert_consumed(self, values)

    def test_pidfd_mismatch_and_malformed_inode_always_close_pidfd(self) -> None:
        for inode in (77778, 0, -1, True, "77777", object()):
            values = environment(LISTEN_PIDFDID="77777")
            factory = Mock()
            with self.subTest(inode=repr(inode)):
                with (
                    patch.object(activation._os, "environ", values),
                    patch.object(activation._os, "getpid", return_value=4242),
                    patch.object(activation._os, "pidfd_open", return_value=91),
                    patch.object(
                        activation._os, "fstat",
                        return_value=SimpleNamespace(st_ino=inode),
                    ),
                    patch.object(activation._os, "close") as closed,
                    patch.object(activation._socket, "socket", factory),
                ):
                    with self.assertRaises(ExecutorSocketActivationError):
                        acquire_systemd_executor_listener()
            closed.assert_called_once_with(91)
            factory.assert_not_called()
            assert_consumed(self, values)

    def test_pidfd_open_unavailable_or_failing_fails_closed(self) -> None:
        for pidfd_open in (None, Mock(side_effect=OSError("private pidfd detail"))):
            values = environment(LISTEN_PIDFDID="77777")
            factory = Mock()
            with self.subTest(pidfd_open=repr(pidfd_open)):
                with (
                    patch.object(activation._os, "environ", values),
                    patch.object(activation._os, "getpid", return_value=4242),
                    patch.object(activation._os, "pidfd_open", pidfd_open),
                    patch.object(activation._socket, "socket", factory),
                ):
                    with self.assertRaisesRegex(
                        ExecutorSocketActivationError, f"^{GENERIC_ERROR}$",
                    ) as caught:
                        acquire_systemd_executor_listener()
            self.assertNotIn("private", str(caught.exception))
            factory.assert_not_called()
            assert_consumed(self, values)

    def test_pidfd_fstat_failure_closes_pidfd_once(self) -> None:
        values = environment(LISTEN_PIDFDID="77777")
        factory = Mock()
        with (
            patch.object(activation._os, "environ", values),
            patch.object(activation._os, "getpid", return_value=4242),
            patch.object(activation._os, "pidfd_open", return_value=91),
            patch.object(activation._os, "fstat", side_effect=OSError("private")),
            patch.object(activation._os, "close") as closed,
            patch.object(activation._socket, "socket", factory),
        ):
            with self.assertRaisesRegex(
                ExecutorSocketActivationError, f"^{GENERIC_ERROR}$",
            ):
                acquire_systemd_executor_listener()
        closed.assert_called_once_with(91)
        factory.assert_not_called()
        assert_consumed(self, values)

    def test_pidfd_close_failure_is_generic_without_retry(self) -> None:
        values = environment(LISTEN_PIDFDID="77777")
        factory = Mock()
        with (
            patch.object(activation._os, "environ", values),
            patch.object(activation._os, "getpid", return_value=4242),
            patch.object(activation._os, "pidfd_open", return_value=91),
            patch.object(
                activation._os, "fstat",
                return_value=SimpleNamespace(st_ino=77777),
            ),
            patch.object(
                activation._os, "close", side_effect=OSError("private close"),
            ) as closed,
            patch.object(activation._socket, "socket", factory),
        ):
            with self.assertRaisesRegex(
                ExecutorSocketActivationError, f"^{GENERIC_ERROR}$",
            ):
                acquire_systemd_executor_listener()
        closed.assert_called_once_with(91)
        factory.assert_not_called()
        assert_consumed(self, values)

    def test_socket_wrap_failure_is_generic_and_does_not_close_a_listener(self) -> None:
        values = environment()
        factory = Mock(side_effect=OSError("private wrapper detail"))
        with (
            patch.object(activation._os, "environ", values),
            patch.object(activation._os, "getpid", return_value=4242),
            patch.object(activation._socket, "socket", factory),
        ):
            with self.assertRaisesRegex(
                ExecutorSocketActivationError, f"^{GENERIC_ERROR}$",
            ) as caught:
                acquire_systemd_executor_listener()
        self.assertNotIn("private", str(caught.exception))
        factory.assert_called_once_with(fileno=3)
        assert_consumed(self, values)

    def test_post_wrap_failures_close_listener_exactly_once(self) -> None:
        listeners = (
            FakeListener(set_error=OSError("set detail")),
            FakeListener(get_error=OSError("get detail")),
            FakeListener(inheritable=True),
            FakeListener(fileno_error=OSError("fileno detail")),
            FakeListener(descriptor=4),
            FakeListener(descriptor=True),
        )
        for listener in listeners:
            values = environment()
            factory = Mock(return_value=listener)
            with self.subTest(listener=listener):
                with (
                    patch.object(activation._os, "environ", values),
                    patch.object(activation._os, "getpid", return_value=4242),
                    patch.object(activation._socket, "socket", factory),
                ):
                    with self.assertRaisesRegex(
                        ExecutorSocketActivationError, f"^{GENERIC_ERROR}$",
                    ):
                        acquire_systemd_executor_listener()
            factory.assert_called_once_with(fileno=3)
            self.assertEqual(listener.close_calls, 1)
            assert_consumed(self, values)

    def test_activation_is_one_shot_without_retry_or_reset(self) -> None:
        values = environment()
        listener = FakeListener()
        factory = Mock(return_value=listener)
        with (
            patch.object(activation._os, "environ", values),
            patch.object(activation._os, "getpid", return_value=4242),
            patch.object(activation._socket, "socket", factory),
        ):
            self.assertIs(acquire_systemd_executor_listener(), listener)
            with self.assertRaises(ExecutorSocketActivationError):
                acquire_systemd_executor_listener()
        factory.assert_called_once_with(fileno=3)
        assert_consumed(self, values)

    def test_control_flow_exception_is_preserved_after_environment_consumption(self) -> None:
        values = environment()
        with (
            patch.object(activation._os, "environ", values),
            patch.object(activation._os, "getpid", side_effect=KeyboardInterrupt),
            patch.object(activation._socket, "socket") as factory,
        ):
            with self.assertRaises(KeyboardInterrupt):
                acquire_systemd_executor_listener()
        factory.assert_not_called()
        assert_consumed(self, values)


class StructuralBoundaryTests(unittest.TestCase):
    """Prove C16 contains only the narrow inherited-descriptor handoff."""

    def test_fixed_descriptor_without_duplication_or_socket_lifecycle(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertEqual(activation._SYSTEMD_LISTEN_FDS_START, 3)
        self.assertIn("socket", calls)
        self.assertTrue(calls.isdisjoint({
            "fromfd", "dup", "dup2", "dup3", "bind", "listen", "connect",
            "accept", "stat", "lstat", "getsockname", "getsockopt",
        }))
        self.assertEqual(source.count("_os.fstat("), 1)
        self.assertNotIn("AF_UNIX", source)
        self.assertNotIn("SOCK_STREAM", source)
        self.assertNotIn("/run/omnilyzer/deployment/executor.sock", source)
        self.assertNotIn("/proc/self/net/unix", source)

    def test_no_host_action_or_hidden_service_bootstrap(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imported_modules.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertTrue(imported_modules.isdisjoint({
            "subprocess", "pwd", "grp", "sqlite3",
            "deployment.executor_composition", "deployment.executor_listener",
            "deployment.installation_contract",
        }))
        source = SOURCE.read_text(encoding="utf-8").lower()
        for forbidden in (
            "systemctl", "systemd-run", "systemd-socket-activate", "docker",
            "github", "oidc", "devexecutorcomposition(",
            "unixexecutorlistener(", "devhostinstallationcontract(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
