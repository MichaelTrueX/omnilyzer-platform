"""Tests for the closed C20 DEV executor service process entrypoint."""

from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import importlib
import inspect
import io
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import Mock, patch

import deployment.executor_service_bootstrap as bootstrap
import deployment.executor_service_entrypoint as entrypoint


MODULE_NAME = "deployment.executor_service_entrypoint"
SOURCE_PATH = Path(entrypoint.__file__)


class EntrypointTestCase(unittest.TestCase):
    """Provide output capture and isolated ``__main__`` execution helpers."""

    def call_main(self, delegate):
        """Call ``main`` with one fake C19 delegate and capture all output."""

        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.object(entrypoint, "_run_dev_executor_service_once", delegate), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            result = entrypoint.main()
        return result, stdout.getvalue(), stderr.getvalue()

    def run_as_main(self, argv, delegate):
        """Execute a fresh module as ``__main__`` with a patched C19 source."""

        stdout = io.StringIO()
        stderr = io.StringIO()
        loaded = sys.modules.pop(MODULE_NAME, None)
        try:
            with patch.object(
                bootstrap, "run_dev_executor_service_once", delegate
            ), patch.object(sys, "argv", argv), redirect_stdout(stdout), \
                    redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_module(MODULE_NAME, run_name="__main__")
        finally:
            if loaded is not None:
                sys.modules[MODULE_NAME] = loaded
        return caught.exception, stdout.getvalue(), stderr.getvalue()


class ImportAndSurfaceTests(EntrypointTestCase):
    """Prove import inertness and the exact public surface."""

    def test_import_is_inert_and_ignores_argv(self) -> None:
        delegate = Mock(side_effect=AssertionError("C19 called"))
        stdout = io.StringIO()
        stderr = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(
                bootstrap, "run_dev_executor_service_once", delegate
            ))
            stack.enter_context(patch.object(
                builtins, "open", side_effect=AssertionError("filesystem")
            ))
            stack.enter_context(patch.object(sys, "argv", ["module", "--debug"]))
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            importlib.reload(entrypoint)
        delegate.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        importlib.reload(entrypoint)

    def test_exact_public_api_and_zero_argument_main(self) -> None:
        self.assertEqual(entrypoint.__all__, ("main",))
        self.assertEqual(tuple(inspect.signature(entrypoint.main).parameters), ())
        forbidden = {
            "configuration", "path", "listener", "clock", "image", "digest",
            "uid", "gid", "socket", "environment", "retry", "timeout",
            "service", "runner", "logger", "argv", "exit_code",
        }
        self.assertTrue(forbidden.isdisjoint(entrypoint.__all__))

    def test_private_exact_builtin_integer_exit_codes(self) -> None:
        expected = (
            ("_SUCCESS_EXIT_CODE", 0),
            ("_FAILURE_EXIT_CODE", 1),
            ("_USAGE_EXIT_CODE", 2),
        )
        for name, value in expected:
            with self.subTest(name=name):
                actual = getattr(entrypoint, name)
                self.assertIs(type(actual), int)
                self.assertEqual(actual, value)
                self.assertNotIn(name, entrypoint.__all__)


class MainOutcomeTests(EntrypointTestCase):
    """Verify exact one-attempt result and exception mapping."""

    def test_exact_none_succeeds_once_without_output(self) -> None:
        delegate = Mock(return_value=None)
        result, stdout, stderr = self.call_main(delegate)
        delegate.assert_called_once_with()
        self.assertIs(type(result), int)
        self.assertEqual(result, 0)
        self.assertEqual((stdout, stderr), ("", ""))

    def test_every_non_none_result_fails_closed_once_without_output(self) -> None:
        for unexpected in (False, 0, "", object(), (), []):
            with self.subTest(value=repr(unexpected)):
                delegate = Mock(return_value=unexpected)
                result, stdout, stderr = self.call_main(delegate)
                delegate.assert_called_once_with()
                self.assertIs(type(result), int)
                self.assertEqual(result, 1)
                self.assertEqual((stdout, stderr), ("", ""))

    def test_ordinary_exceptions_fail_once_without_leaking(self) -> None:
        errors = (
            RuntimeError("LISTEN_PID=999 fd=3"),
            ValueError("uid=1234"),
            Exception("docker-secret-marker"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                delegate = Mock(side_effect=error)
                result, stdout, stderr = self.call_main(delegate)
                delegate.assert_called_once_with()
                self.assertIs(type(result), int)
                self.assertEqual(result, 1)
                self.assertEqual((stdout, stderr), ("", ""))

    def test_control_flow_exceptions_propagate_unchanged(self) -> None:
        errors = (
            KeyboardInterrupt("keyboard-marker"),
            SystemExit(77),
            GeneratorExit("generator-marker"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                delegate = Mock(side_effect=error)
                with patch.object(
                    entrypoint, "_run_dev_executor_service_once", delegate
                ):
                    with self.assertRaises(type(error)) as caught:
                        entrypoint.main()
                delegate.assert_called_once_with()
                self.assertIs(caught.exception, error)
                if isinstance(error, SystemExit):
                    self.assertEqual(caught.exception.code, 77)


class ModuleExecutionTests(EntrypointTestCase):
    """Verify deterministic module-process semantics without a subprocess."""

    def test_module_success(self) -> None:
        delegate = Mock(return_value=None)
        exited, stdout, stderr = self.run_as_main([MODULE_NAME], delegate)
        self.assertEqual(exited.code, 0)
        delegate.assert_called_once_with()
        self.assertEqual((stdout, stderr), ("", ""))

    def test_module_ordinary_failure(self) -> None:
        delegate = Mock(side_effect=RuntimeError("process-secret-marker"))
        exited, stdout, stderr = self.run_as_main([MODULE_NAME], delegate)
        self.assertEqual(exited.code, 1)
        delegate.assert_called_once_with()
        self.assertEqual((stdout, stderr), ("", ""))

    def test_extra_arguments_exit_two_before_c19(self) -> None:
        for argv in (
            [MODULE_NAME, "--debug"],
            [MODULE_NAME, "unexpected", "another"],
        ):
            with self.subTest(argv=argv):
                delegate = Mock(side_effect=AssertionError("C19 called"))
                exited, stdout, stderr = self.run_as_main(argv, delegate)
                self.assertEqual(exited.code, 2)
                delegate.assert_not_called()
                self.assertEqual((stdout, stderr), ("", ""))

    def test_module_preserves_delegate_system_exit(self) -> None:
        delegate = Mock(side_effect=SystemExit(77))
        exited, stdout, stderr = self.run_as_main([MODULE_NAME], delegate)
        self.assertEqual(exited.code, 77)
        delegate.assert_called_once_with()
        self.assertEqual((stdout, stderr), ("", ""))


class StaticBoundaryTests(unittest.TestCase):
    """Prove the production source contains no broader authority."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_only_sys_and_c19_are_direct_dependencies(self) -> None:
        imports = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module)
        self.assertEqual(imports, [
            "__future__", "sys", "executor_service_bootstrap",
        ])
        imported_names = {
            alias.name
            for node in ast.walk(self.tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "executor_service_bootstrap"
            for alias in node.names
        }
        self.assertEqual(imported_names, {"run_dev_executor_service_once"})

    def test_no_output_or_operational_authority_and_no_loops(self) -> None:
        forbidden_tokens = {
            "print", "logging", "warnings", "traceback", "pprint", "stdout",
            "stderr", "open", "pathlib", "socket", "subprocess", "docker",
            "systemd", "environ", "getenv", "getuid", "geteuid", "getgid",
            "getegid", "getgroups", "signal", "atexit", "thread", "asyncio",
            "multiprocessing", "fork", "sleep", "retry", "argparse",
        }
        names = {
            node.id.lower() for node in ast.walk(self.tree)
            if isinstance(node, ast.Name)
        }
        attributes = {
            node.attr.lower() for node in ast.walk(self.tree)
            if isinstance(node, ast.Attribute)
        }
        self.assertTrue(forbidden_tokens.isdisjoint(names | attributes))
        self.assertFalse(any(isinstance(node, (ast.For, ast.While, ast.AsyncFor))
                             for node in ast.walk(self.tree)))

    def test_exact_single_module_guard_and_execution_shape(self) -> None:
        guards = [
            node for node in self.tree.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and ast.unparse(node.test) == "__name__ == '__main__'"
        ]
        self.assertEqual(len(guards), 1)
        guard = guards[0]
        self.assertEqual(len(guard.body), 2)
        self.assertIsInstance(guard.body[0], ast.If)
        self.assertEqual(ast.unparse(guard.body[0].test), "len(_sys.argv) != 1")
        self.assertEqual(
            ast.unparse(guard.body[0].body[0]),
            "raise SystemExit(_USAGE_EXIT_CODE)",
        )
        self.assertEqual(ast.unparse(guard.body[1]), "raise SystemExit(main())")
        self.assertEqual(
            sum(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "main"
                for node in ast.walk(guard)
            ),
            1,
        )
        self.assertNotIn("sys.exit", self.source)


if __name__ == "__main__":
    unittest.main()
