"""Tests for the inert one-attempt DEV executor service bootstrap."""

from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack
import datetime
import importlib
import inspect
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import Mock, patch

import deployment.executor_composition as composition_module
import deployment.executor_service_bootstrap as bootstrap
import deployment.executor_service_config_loader as loader_module
import deployment.systemd_socket_activation as activation_module


CANARY_IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:"
    "628af866084f08763b31a44c8a484c5ae4c64db6697f4c4ceaad91bbf54ba72a"
)
HASHES = (
    "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
)
_DEFAULT = object()


def configuration():
    """Create one exact current C17 configuration using the live module alias."""

    return bootstrap._DevExecutorServiceConfiguration(
        schema_version=1,
        stage="dev",
        broker_uid=1001,
        broker_gid=1002,
        executor_uid=2001,
        executor_gid=2002,
        replay_group_gid=2003,
        socket_group_gid=2004,
        canary_image=CANARY_IMAGE,
        reviewed_commit="a" * 40,
        runtime_configuration_sha256=(
            "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f"
        ),
        ingress_file_sha256=HASHES,
    )


class FakeListener:
    """Record the sole allowed lifecycle operation on an acquired listener."""

    def __init__(self, events=None, *, close_result=None, close_error=None):
        self.events = events
        self.close_result = close_result
        self.close_error = close_error
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        if self.events is not None:
            self.events.append("close")
        if self.close_error is not None:
            raise self.close_error
        return self.close_result


class FakeComposition:
    """Record one serve operation without invoking any deployment boundary."""

    def __init__(self, events=None, *, serve_result=None, serve_error=None):
        self.events = events
        self.serve_result = serve_result
        self.serve_error = serve_error
        self.serve_calls = 0

    def serve_once(self):
        self.serve_calls += 1
        if self.events is not None:
            self.events.append("serve")
        if self.serve_error is not None:
            raise self.serve_error
        return self.serve_result


class BootstrapTestCase(unittest.TestCase):
    def assert_bootstrap_error(self, action) -> None:
        with self.assertRaises(bootstrap.ExecutorServiceBootstrapError) as caught:
            action()
        self.assertEqual(
            str(caught.exception),
            "DEV executor service bootstrap is unavailable",
        )

    def run_with(
        self, *, config=_DEFAULT, projection=_DEFAULT, listener=_DEFAULT,
        composition=_DEFAULT,
        load_error=None, projection_error=None, acquire_error=None,
        construct_error=None,
    ):
        config = configuration() if config is _DEFAULT else config
        listener = FakeListener() if listener is _DEFAULT else listener
        composition = FakeComposition() if composition is _DEFAULT else composition
        projected = (
            config.executor_composition_kwargs()
            if projection is _DEFAULT
            and type(config) is bootstrap._DevExecutorServiceConfiguration
            else projection
        )
        load = Mock(side_effect=load_error) if load_error is not None else Mock(return_value=config)
        acquire = (
            Mock(side_effect=acquire_error)
            if acquire_error is not None else Mock(return_value=listener)
        )
        constructor = (
            Mock(side_effect=construct_error)
            if construct_error is not None else Mock(return_value=composition)
        )
        if type(config) is bootstrap._DevExecutorServiceConfiguration:
            project = (
                Mock(side_effect=projection_error)
                if projection_error is not None else Mock(return_value=projected)
            )
            project_patch = patch.object(
                bootstrap._DevExecutorServiceConfiguration,
                "executor_composition_kwargs",
                autospec=True,
                side_effect=lambda _self: project(),
            )
        else:
            project = Mock()
            project_patch = ExitStack()
        stack = ExitStack()
        stack.enter_context(patch.object(bootstrap, "_load_configuration", load))
        stack.enter_context(patch.object(bootstrap, "_acquire_listener", acquire))
        stack.enter_context(patch.object(bootstrap, "_DevExecutorComposition", constructor))
        stack.enter_context(project_patch)
        return stack, load, project, acquire, constructor, listener, composition, projected


class ImportAndSurfaceTests(BootstrapTestCase):
    def test_import_is_inert(self) -> None:
        sentinels = []
        clock_source = Mock()
        clock_source.now.side_effect = AssertionError("clock")
        with ExitStack() as stack:
            for target, name in (
                (builtins, "open"), (os, "open"), (os, "read"), (os, "stat"),
                (os, "getenv"), (os, "getuid"), (os, "getgid"),
                (socket, "socket"), (socket, "create_connection"),
                (subprocess, "Popen"),
            ):
                sentinels.append(
                    stack.enter_context(
                        patch.object(target, name, side_effect=AssertionError(name)),
                    )
                )
            sentinels.extend((
                clock_source.now,
                stack.enter_context(patch.object(datetime, "datetime", clock_source)),
                stack.enter_context(patch.object(
                    loader_module, "load_dev_executor_service_configuration",
                    side_effect=AssertionError("load"),
                )),
                stack.enter_context(patch.object(
                    activation_module, "acquire_systemd_executor_listener",
                    side_effect=AssertionError("acquire"),
                )),
                stack.enter_context(patch.object(
                    composition_module, "DevExecutorComposition",
                    side_effect=AssertionError("construct"),
                )),
            ))
            importlib.reload(bootstrap)
            self.assertTrue(
                all(
                    not hasattr(item, "call_count") or item.call_count == 0
                    for item in sentinels
                )
            )
        importlib.reload(bootstrap)

    def test_exact_public_api_and_zero_arguments(self) -> None:
        self.assertEqual(bootstrap.__all__, (
            "ExecutorServiceBootstrapError",
            "run_dev_executor_service_once",
        ))
        self.assertEqual(
            tuple(inspect.signature(bootstrap.run_dev_executor_service_once).parameters),
            (),
        )
        forbidden = {
            "main", "bootstrap", "install", "start", "stop", "restart",
            "run_forever", "serve_forever", "load", "acquire", "close",
            "clock", "configure", "activate", "deploy",
        }
        self.assertTrue(forbidden.isdisjoint(bootstrap.__all__))


class SuccessAndClockTests(BootstrapTestCase):
    def test_successful_exact_order_identity_kwargs_and_counts(self) -> None:
        events = []
        config = configuration()
        projection = config.executor_composition_kwargs()
        listener = FakeListener(events)
        composed = FakeComposition(events)

        def load():
            events.append("load")
            return config

        def project(_self):
            events.append("projection")
            return projection

        def acquire():
            events.append("acquire")
            return listener

        captured = {}
        def construct(**kwargs):
            events.append("construct")
            captured.update(kwargs)
            return composed

        with patch.object(bootstrap, "_load_configuration", side_effect=load) as load_mock, \
                patch.object(
                    bootstrap._DevExecutorServiceConfiguration,
                    "executor_composition_kwargs", autospec=True,
                    side_effect=project,
                ) as project_mock, \
                patch.object(bootstrap, "_acquire_listener", side_effect=acquire) as acquire_mock, \
                patch.object(bootstrap, "_DevExecutorComposition", side_effect=construct) as ctor:
            self.assertIsNone(bootstrap.run_dev_executor_service_once())

        self.assertEqual(events, ["load", "projection", "acquire", "construct", "serve", "close"])
        self.assertEqual(load_mock.call_count, 1)
        self.assertEqual(project_mock.call_count, 1)
        self.assertEqual(acquire_mock.call_count, 1)
        self.assertEqual(ctor.call_count, 1)
        self.assertEqual(composed.serve_calls, 1)
        self.assertEqual(listener.close_calls, 1)
        self.assertIs(captured.pop("listener"), listener)
        self.assertIs(captured.pop("clock"), bootstrap._utc_audit_clock)
        self.assertEqual(captured, projection)

    def test_fixed_clock_is_exact_utc_second_precision(self) -> None:
        instants = (
            (datetime.datetime(2026, 9, 13, 5, 42, 17, 987654, tzinfo=datetime.timezone.utc),
             "2026-09-13T05:42:17Z"),
            (datetime.datetime(2030, 1, 2, 23, 4, 5, 1, tzinfo=datetime.timezone.utc),
             "2030-01-02T23:04:05Z"),
        )
        for instant, expected in instants:
            with self.subTest(instant=instant):
                fake_datetime = Mock()
                fake_datetime.now.return_value = instant
                with patch.object(bootstrap._datetime, "datetime", fake_datetime):
                    result = bootstrap._utc_audit_clock()
                fake_datetime.now.assert_called_once_with(datetime.timezone.utc)
                self.assertIs(type(result), str)
                self.assertEqual(result, expected)
                self.assertNotIn("+", result)
                self.assertNotIn(".", result)

    def test_bootstrap_passes_clock_without_sampling_it(self) -> None:
        stack, *_items = self.run_with()
        clock = Mock(side_effect=AssertionError("clock sampled"))
        with stack, patch.object(bootstrap, "_utc_audit_clock", clock):
            self.assertIsNone(bootstrap.run_dev_executor_service_once())
        clock.assert_not_called()


class ConfigurationBoundaryTests(BootstrapTestCase):
    def test_requires_exact_c17_type_before_acquisition(self) -> None:
        class ConfigurationSubclass(bootstrap._DevExecutorServiceConfiguration):
            pass

        for value in (None, object(), object.__new__(ConfigurationSubclass)):
            with self.subTest(value_type=type(value).__name__):
                stack, load, _project, acquire, constructor, listener, *_ = self.run_with(
                    config=value,
                )
                with stack:
                    self.assert_bootstrap_error(bootstrap.run_dev_executor_service_once)
                self.assertEqual(load.call_count, 1)
                acquire.assert_not_called()
                constructor.assert_not_called()
                self.assertEqual(listener.close_calls, 0)

    def test_projection_must_be_exact_dict_without_reserved_keys(self) -> None:
        class DictSubclass(dict):
            pass

        for value in (None, object(), DictSubclass(), {"listener": object()}, {"clock": object()}):
            with self.subTest(value_type=type(value).__name__):
                stack, load, project, acquire, constructor, listener, *_ = self.run_with(
                    projection=value,
                )
                with stack:
                    self.assert_bootstrap_error(bootstrap.run_dev_executor_service_once)
                self.assertEqual(load.call_count, 1)
                self.assertEqual(project.call_count, 1)
                acquire.assert_not_called()
                constructor.assert_not_called()
                self.assertEqual(listener.close_calls, 0)


class FailureAndCleanupTests(BootstrapTestCase):
    def test_failures_before_listener_do_not_close_or_continue(self) -> None:
        cases = ("load", "projection", "acquire")
        for stage in cases:
            with self.subTest(stage=stage):
                options = {f"{stage}_error": RuntimeError(f"{stage}-marker")}
                stack, load, project, acquire, constructor, listener, *_ = self.run_with(**options)
                with stack:
                    self.assert_bootstrap_error(bootstrap.run_dev_executor_service_once)
                self.assertEqual(load.call_count, 1)
                expected_projection = 0 if stage == "load" else 1
                expected_acquire = 1 if stage == "acquire" else 0
                self.assertEqual(project.call_count, expected_projection)
                self.assertEqual(acquire.call_count, expected_acquire)
                constructor.assert_not_called()
                self.assertEqual(listener.close_calls, 0)

    def test_constructor_failure_closes_once_without_serve_or_retry(self) -> None:
        stack, load, project, acquire, constructor, listener, composed, *_ = self.run_with(
            construct_error=RuntimeError("constructor marker"),
        )
        with stack:
            self.assert_bootstrap_error(bootstrap.run_dev_executor_service_once)
        self.assertEqual((load.call_count, project.call_count, acquire.call_count,
                          constructor.call_count, composed.serve_calls, listener.close_calls),
                         (1, 1, 1, 1, 0, 1))

    def test_serve_failure_closes_once_without_retry(self) -> None:
        composed = FakeComposition(serve_error=RuntimeError("serve marker"))
        stack, load, project, acquire, constructor, listener, *_ = self.run_with(
            composition=composed,
        )
        with stack:
            self.assert_bootstrap_error(bootstrap.run_dev_executor_service_once)
        self.assertEqual((load.call_count, project.call_count, acquire.call_count,
                          constructor.call_count, composed.serve_calls, listener.close_calls),
                         (1, 1, 1, 1, 1, 1))

    def test_non_none_serve_result_fails_closed_after_one_close(self) -> None:
        composed = FakeComposition(serve_result=object())
        stack, *_prefix, listener, _composed, _projection = self.run_with(
            composition=composed,
        )
        with stack:
            self.assert_bootstrap_error(bootstrap.run_dev_executor_service_once)
        self.assertEqual(composed.serve_calls, 1)
        self.assertEqual(listener.close_calls, 1)

    def test_close_failure_or_non_none_return_is_not_retried(self) -> None:
        listeners = (
            FakeListener(close_error=OSError("close marker")),
            FakeListener(close_result=object()),
        )
        for listener in listeners:
            with self.subTest(close_error=listener.close_error is not None):
                stack, *_ = self.run_with(listener=listener)
                with stack:
                    self.assert_bootstrap_error(bootstrap.run_dev_executor_service_once)
                self.assertEqual(listener.close_calls, 1)

    def test_control_flow_before_listener_is_preserved(self) -> None:
        for stage in ("load", "projection", "acquire"):
            for exception in (KeyboardInterrupt(), SystemExit(), GeneratorExit()):
                with self.subTest(stage=stage, exception=type(exception).__name__):
                    options = {f"{stage}_error": exception}
                    stack, _load, _project, _acquire, constructor, listener, *_ = self.run_with(
                        **options,
                    )
                    with stack, self.assertRaises(type(exception)):
                        bootstrap.run_dev_executor_service_once()
                    constructor.assert_not_called()
                    self.assertEqual(listener.close_calls, 0)

    def test_control_flow_after_listener_is_preserved_and_closed(self) -> None:
        for stage in ("construct", "serve"):
            for exception in (KeyboardInterrupt(), SystemExit(), GeneratorExit()):
                with self.subTest(stage=stage, exception=type(exception).__name__):
                    options = (
                        {"construct_error": exception}
                        if stage == "construct"
                        else {"composition": FakeComposition(serve_error=exception)}
                    )
                    stack, *_prefix, listener, _composition, _projection = self.run_with(
                        **options,
                    )
                    with stack, self.assertRaises(type(exception)):
                        bootstrap.run_dev_executor_service_once()
                    self.assertEqual(listener.close_calls, 1)

    def test_cleanup_failure_does_not_replace_active_control(self) -> None:
        original = KeyboardInterrupt("original-control")
        listener = FakeListener(close_error=OSError("cleanup-marker"))
        composed = FakeComposition(serve_error=original)
        stack, *_ = self.run_with(listener=listener, composition=composed)
        with stack, self.assertRaisesRegex(KeyboardInterrupt, "original-control"):
            bootstrap.run_dev_executor_service_once()
        self.assertEqual(listener.close_calls, 1)

    def test_close_control_flow_propagates_after_normal_serve(self) -> None:
        for exception in (KeyboardInterrupt(), SystemExit(), GeneratorExit()):
            with self.subTest(exception=type(exception).__name__):
                listener = FakeListener(close_error=exception)
                stack, *_ = self.run_with(listener=listener)
                with stack, self.assertRaises(type(exception)):
                    bootstrap.run_dev_executor_service_once()
                self.assertEqual(listener.close_calls, 1)

    def test_ordinary_error_hygiene_at_every_stage(self) -> None:
        markers = {
            "load": "config-secret-marker",
            "acquire": "LISTEN_PID=999 fd=3",
            "construct": "uid=1234 docker-marker",
        }
        for stage, marker in markers.items():
            with self.subTest(stage=stage):
                options = {f"{stage}_error": RuntimeError(marker)}
                stack, *_ = self.run_with(**options)
                with stack:
                    self.assert_bootstrap_error(bootstrap.run_dev_executor_service_once)


class StructuralSeparationTests(BootstrapTestCase):
    def test_no_loop_cli_or_lower_level_authority(self) -> None:
        source_path = Path(bootstrap.__file__)
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, (ast.For, ast.While, ast.AsyncFor))
                             for node in ast.walk(tree)))
        self.assertNotIn("if __name__", source)
        for marker in (
            "argparse", "sys.argv", "sys.exit", "click", "typer",
            "serve_forever", "run_forever", "backoff", "sleep",
        ):
            self.assertNotIn(marker, source)

        imported = {
            alias.name for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        forbidden = {
            "FilesystemDeploymentStateStore", "SQLiteReplayGuard",
            "FilesystemAuditSink", "SubprocessCommandRunner",
            "DockerComposeCandidateHttpClient", "DockerRuntimeAdapter",
            "DevDeploymentOperation", "RestrictedPrivilegedExecutor",
            "UnixExecutorConnectionHandler", "UnixExecutorListener",
            "socket", "subprocess", "os",
        }
        self.assertTrue(imported.isdisjoint(forbidden))

        calls = {
            node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(tree) if isinstance(node, ast.Call)
            if isinstance(node.func, (ast.Attribute, ast.Name))
        }
        forbidden_calls = {
            "open", "stat", "fromfd", "create_connection", "bind", "listen",
            "accept", "connect", "systemctl", "systemd-run", "docker", "Popen",
        }
        self.assertTrue(calls.isdisjoint(forbidden_calls))


if __name__ == "__main__":
    unittest.main()
