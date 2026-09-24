"""deployment/tests/test_executor_composition.py — tests for inert C15 wiring.

These tests prove that the closed DEV executor composition uses the reviewed
components, including C14's concrete probe, and fixed production paths without
activating any external side effect during import or construction.
"""

from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack
import importlib
import inspect
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

import deployment.executor_composition as composition_module
from deployment.audit import AUDIT_PATH, FilesystemAuditSink
from deployment.deployment_operation import DevDeploymentOperation
from deployment.docker_runtime import (
    DockerComposeCandidateHttpClient,
    DockerRuntimeAdapter,
    RuntimeOperationError,
    SubprocessCommandRunner,
)
from deployment.executor import RestrictedPrivilegedExecutor
from deployment.executor_composition import DevExecutorComposition
from deployment.executor_listener import (
    PRODUCTION_EXECUTOR_SOCKET_PATH,
    UnixExecutorListener,
)
from deployment.executor_server import UnixExecutorConnectionHandler
from deployment.replay_sqlite import PRODUCTION_REPLAY_DATABASE, SQLiteReplayGuard
from deployment.state_store import (
    PRODUCTION_DEV_STATE_PATH,
    FilesystemDeploymentStateStore,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "deployment/executor_composition.py"
CANARY_IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:"
    "628af866084f08763b31a44c8a484c5ae4c64db6697f4c4ceaad91bbf54ba72a"
)
REVIEWED_COMMIT = "4" * 40
RUNTIME_HASH = "d" * 64
INGRESS_HASHES = ("1" * 64, "2" * 64, "3" * 64)


def audit_clock() -> str:
    """Return one deterministic value without performing external work."""

    return "2026-09-13T00:00:00Z"


class ExistingListener:
    """Model an already-provisioned listener and fail on every operation."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def _called(self, name: str) -> object:
        self.calls.append(name)
        raise AssertionError(f"listener operation called during composition: {name}")

    def get_inheritable(self) -> object:
        return self._called("get_inheritable")

    def getsockopt(self, level: int, option: int) -> object:
        return self._called("getsockopt")

    def getsockname(self) -> object:
        return self._called("getsockname")

    def fileno(self) -> object:
        return self._called("fileno")

    def gettimeout(self) -> object:
        return self._called("gettimeout")

    def settimeout(self, value: object) -> None:
        self._called("settimeout")

    def accept(self) -> object:
        return self._called("accept")


def configuration(**changes: object) -> dict[str, object]:
    """Return one valid closed composition configuration with selected changes."""

    values: dict[str, object] = {
        "listener": ExistingListener(),
        "clock": audit_clock,
        "canary_image": CANARY_IMAGE,
        "reviewed_commit": REVIEWED_COMMIT,
        "runtime_configuration_sha256": RUNTIME_HASH,
        "ingress_file_sha256": INGRESS_HASHES,
        "expected_state_owner_uid": 1001,
        "expected_state_group_gid": 1002,
        "expected_replay_directory_uid": 1003,
        "expected_replay_directory_gid": 1004,
        "expected_broker_uid": 1005,
        "expected_broker_gid": 1006,
        "expected_socket_owner_uid": 1007,
        "expected_socket_group_gid": 1008,
    }
    values.update(changes)
    return values


class ImportInertnessTests(unittest.TestCase):
    """Prove module loading contains no activation behavior or authority imports."""

    def test_reload_performs_no_external_operation(self) -> None:
        blockers = (
            patch.object(builtins, "open", side_effect=AssertionError("filesystem open")),
            patch.object(os, "open", side_effect=AssertionError("filesystem open")),
            patch.object(os, "mkdir", side_effect=AssertionError("filesystem mkdir")),
            patch.object(os, "makedirs", side_effect=AssertionError("filesystem makedirs")),
            patch.object(os, "stat", side_effect=AssertionError("filesystem stat")),
            patch.object(os, "lstat", side_effect=AssertionError("filesystem lstat")),
            patch.object(os, "scandir", side_effect=AssertionError("filesystem scan")),
            patch.object(socket, "socket", side_effect=AssertionError("socket creation")),
            patch.object(socket, "create_connection", side_effect=AssertionError("network")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
        )
        entered = []
        try:
            for blocker in blockers:
                entered.append(blocker)
                blocker.start()
            importlib.reload(composition_module)
        finally:
            for blocker in reversed(entered):
                blocker.stop()

    def test_no_external_authorization_or_trigger_module_is_imported(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imported = {
            ("." * node.level) + node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertTrue(imported.isdisjoint({
            ".broker", ".identity", ".jwks", ".oidc_verifier", ".promotion",
        }))
        lowered = SOURCE.read_text(encoding="utf-8").lower()
        for authority in ("github", "oidc", "workflow", "environment"):
            self.assertNotIn(authority, lowered)


class ConstructionTests(unittest.TestCase):
    """Prove construction is inert, closed, and connected in reviewed order."""

    def test_construction_calls_no_operational_boundary(self) -> None:
        listener = ExistingListener()

        def load(store: object) -> object:
            raise AssertionError("state load")

        def save(store: object, state: object) -> None:
            raise AssertionError("state save")

        def initialize(guard: object) -> None:
            raise AssertionError("replay initialize")

        def begin_execution(
            guard: object, jti: str, *, request_hash: str,
            run_id: int, run_attempt: int,
        ) -> None:
            raise AssertionError("replay mutation")

        def finish_execution(
            guard: object, jti: str, *, request_hash: str,
            run_id: int, run_attempt: int,
        ) -> None:
            raise AssertionError("replay mutation")

        def append(sink: object, event: object) -> None:
            raise AssertionError("audit append")

        def run(
            runner: object, argv: tuple[str, ...], *, cwd: Path,
            environment: object, timeout: float,
        ) -> object:
            raise AssertionError("command execution")

        def get(
            client: object, slot: str, path: str, *, timeout: float,
            max_bytes: int,
        ) -> tuple[int, bytes]:
            raise AssertionError("candidate probe")

        blockers = (
            patch.object(FilesystemDeploymentStateStore, "load", load),
            patch.object(FilesystemDeploymentStateStore, "save", save),
            patch.object(SQLiteReplayGuard, "initialize", initialize),
            patch.object(SQLiteReplayGuard, "begin_execution", begin_execution),
            patch.object(SQLiteReplayGuard, "finish_execution", finish_execution),
            patch.object(FilesystemAuditSink, "append", append),
            patch.object(SubprocessCommandRunner, "run", run),
            patch.object(DockerComposeCandidateHttpClient, "get", get),
            patch.object(socket, "socket", side_effect=AssertionError("socket creation")),
            patch.object(
                socket, "create_connection",
                side_effect=AssertionError("socket connection"),
            ),
            patch.object(os, "open", side_effect=AssertionError("production path open")),
            patch.object(os, "stat", side_effect=AssertionError("production path stat")),
            patch.object(os, "lstat", side_effect=AssertionError("production path lstat")),
            patch.object(os, "scandir", side_effect=AssertionError("production path scan")),
            patch.object(builtins, "open", side_effect=AssertionError("path open")),
            patch.object(Path, "mkdir", side_effect=AssertionError("path mkdir")),
            patch.object(Path, "exists", side_effect=AssertionError("path exists")),
            patch.object(Path, "is_file", side_effect=AssertionError("path is_file")),
            patch.object(Path, "is_dir", side_effect=AssertionError("path is_dir")),
            patch.object(Path, "stat", side_effect=AssertionError("path stat")),
            patch.object(Path, "iterdir", side_effect=AssertionError("path iterdir")),
            patch.object(Path, "read_bytes", side_effect=AssertionError("path read")),
            patch.object(Path, "write_bytes", side_effect=AssertionError("path write")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
        )
        with ExitStack() as stack:
            for blocker in blockers:
                stack.enter_context(blocker)
            composed = DevExecutorComposition(**configuration(listener=listener))

        self.assertIsInstance(composed, DevExecutorComposition)
        self.assertEqual(listener.calls, [])

    def test_graph_uses_actual_reviewed_components_in_order(self) -> None:
        created: dict[str, object] = {}
        order: list[str] = []

        def record(name: str, constructor: object):
            def construct(*args: object, **kwargs: object) -> object:
                instance = constructor(*args, **kwargs)  # type: ignore[operator]
                order.append(name)
                created[name] = instance
                created[f"{name}_args"] = args
                created[f"{name}_kwargs"] = kwargs
                return instance
            return construct

        replacements = {
            "_FilesystemDeploymentStateStore": record("state", FilesystemDeploymentStateStore),
            "_SQLiteReplayGuard": record("replay", SQLiteReplayGuard),
            "_FilesystemAuditSink": record("audit", FilesystemAuditSink),
            "_SubprocessCommandRunner": record("runner", SubprocessCommandRunner),
            "_DockerComposeCandidateHttpClient": record(
                "candidate", DockerComposeCandidateHttpClient,
            ),
            "_DockerRuntimeAdapter": record("runtime", DockerRuntimeAdapter),
            "_DevDeploymentOperation": record("operation", DevDeploymentOperation),
            "_RestrictedPrivilegedExecutor": record("executor", RestrictedPrivilegedExecutor),
            "_UnixExecutorConnectionHandler": record("handler", UnixExecutorConnectionHandler),
            "_UnixExecutorListener": record("listener", UnixExecutorListener),
        }
        with patch.multiple(composition_module, **replacements):
            composed = composition_module.DevExecutorComposition(**configuration())

        expected_types = {
            "state": FilesystemDeploymentStateStore,
            "replay": SQLiteReplayGuard,
            "audit": FilesystemAuditSink,
            "runner": SubprocessCommandRunner,
            "candidate": DockerComposeCandidateHttpClient,
            "runtime": DockerRuntimeAdapter,
            "operation": DevDeploymentOperation,
            "executor": RestrictedPrivilegedExecutor,
            "handler": UnixExecutorConnectionHandler,
            "listener": UnixExecutorListener,
        }
        for name, expected_type in expected_types.items():
            self.assertIsInstance(created[name], expected_type)
        self.assertEqual(order, [
            "state", "replay", "audit", "runner", "candidate", "runtime",
            "operation", "executor", "handler", "listener",
        ])
        self.assertEqual(created["state_args"], ())
        self.assertEqual(set(created["state_kwargs"]), {  # type: ignore[arg-type]
            "expected_owner_uid", "expected_group_gid",
        })
        self.assertEqual(created["replay_args"], (PRODUCTION_REPLAY_DATABASE,))
        self.assertEqual(set(created["replay_kwargs"]), {  # type: ignore[arg-type]
            "expected_directory_uid", "expected_directory_gid",
        })
        self.assertEqual(created["audit_args"], ())
        self.assertEqual(created["audit_kwargs"], {})
        self.assertEqual(order.count("runner"), 1)
        self.assertIs(created["candidate_args"][0], created["runner"])  # type: ignore[index]
        self.assertIs(created["runtime_args"][0], created["runner"])  # type: ignore[index]
        self.assertIs(created["runtime_args"][1], created["candidate"])  # type: ignore[index]
        self.assertIs(created["candidate_kwargs"]["canary_image"], CANARY_IMAGE)  # type: ignore[index]
        self.assertIs(created["runtime_kwargs"]["canary_image"], CANARY_IMAGE)  # type: ignore[index]
        self.assertIs(created["operation_kwargs"]["runtime"], created["runtime"])  # type: ignore[index]
        self.assertIs(created["operation_kwargs"]["state_store"], created["state"])  # type: ignore[index]
        self.assertIs(created["operation_kwargs"]["audit_sink"], created["audit"])  # type: ignore[index]
        self.assertIs(created["executor_kwargs"]["replay_guard"], created["replay"])  # type: ignore[index]
        self.assertIs(created["executor_kwargs"]["operation"], created["operation"])  # type: ignore[index]
        self.assertIs(created["handler_kwargs"]["executor"], created["executor"])  # type: ignore[index]
        self.assertIs(created["listener_kwargs"]["handler"], created["handler"])  # type: ignore[index]
        self.assertNotIn("path", created["listener_kwargs"])  # type: ignore[operator]
        self.assertIs(composed._serve_once.__self__, created["listener"])

    def test_constructor_surface_closes_candidate_and_runner_injection(self) -> None:
        parameters = inspect.signature(DevExecutorComposition).parameters
        self.assertEqual(tuple(parameters), (
            "listener", "clock", "canary_image", "reviewed_commit",
            "runtime_configuration_sha256", "ingress_file_sha256",
            "expected_state_owner_uid", "expected_state_group_gid",
            "expected_replay_directory_uid", "expected_replay_directory_gid",
            "expected_broker_uid", "expected_broker_gid",
            "expected_socket_owner_uid", "expected_socket_group_gid",
        ))
        for name in (
            "candidate_http_client", "runner", "command_runner", "http",
            "http_client", "candidate_probe", "probe_client", "probe_factory",
            "runtime_factory", "docker_client", "compose_client",
        ):
            self.assertNotIn(name, parameters)

    def test_candidate_client_injection_and_old_validator_are_absent(self) -> None:
        with self.assertRaises(TypeError):
            DevExecutorComposition(
                **configuration(), candidate_http_client=object(),
            )
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        function_names = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertNotIn("CandidateHttpClient", imported_names)
        self.assertNotIn("_validate_candidate_http_client", function_names)
        self.assertIn("DockerComposeCandidateHttpClient", imported_names)

    def test_invalid_image_fails_before_any_operation(self) -> None:
        listener = ExistingListener()

        def run(
            runner: object, argv: tuple[str, ...], *, cwd: Path,
            environment: object, timeout: float,
        ) -> object:
            raise AssertionError("command execution")

        def get(
            client: object, slot: str, path: str, *, timeout: float,
            max_bytes: int,
        ) -> tuple[int, bytes]:
            raise AssertionError("candidate probe")

        with (
            patch.object(SubprocessCommandRunner, "run", run),
            patch.object(DockerComposeCandidateHttpClient, "get", get),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
            patch.object(builtins, "open", side_effect=AssertionError("filesystem")),
        ):
            with self.assertRaises(RuntimeOperationError):
                DevExecutorComposition(**configuration(
                    listener=listener, canary_image="latest",
                ))
        self.assertEqual(listener.calls, [])

    def test_fixed_paths_have_no_composition_override(self) -> None:
        parameters = inspect.signature(DevExecutorComposition).parameters
        for name in ("state_path", "replay_path", "audit_path", "socket_path"):
            self.assertNotIn(name, parameters)
        self.assertEqual(PRODUCTION_DEV_STATE_PATH, "/var/lib/omnilyzer/deployment/dev/state.json")
        self.assertEqual(
            str(PRODUCTION_REPLAY_DATABASE),
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
        )
        self.assertEqual(str(AUDIT_PATH), "/var/lib/omnilyzer/deployment/audit/events.jsonl")
        self.assertEqual(
            PRODUCTION_EXECUTOR_SOCKET_PATH,
            "/run/omnilyzer/deployment/executor.sock",
        )

    def test_invalid_values_fail_closed(self) -> None:
        invalid = (
            ("expected_state_owner_uid", "1001"),
            ("expected_state_group_gid", True),
            ("expected_replay_directory_uid", -1),
            ("expected_replay_directory_gid", False),
            ("expected_broker_uid", 1.0),
            ("expected_broker_gid", True),
            ("expected_socket_owner_uid", object()),
            ("expected_socket_group_gid", True),
            ("canary_image", "latest"),
            ("reviewed_commit", "not-a-commit"),
            ("runtime_configuration_sha256", "not-a-hash"),
            ("ingress_file_sha256", ("1" * 64, "2" * 64)),
            ("ingress_file_sha256", ("1" * 64, "bad", "3" * 64)),
            ("ingress_file_sha256", ["1" * 64, "2" * 64, "3" * 64]),
            ("listener", object()),
            ("clock", object()),
        )
        for name, value in invalid:
            with self.subTest(name=name), self.assertRaises((TypeError, ValueError)):
                DevExecutorComposition(**configuration(**{name: value}))

    def test_public_instance_surface_is_only_serve_once(self) -> None:
        composed = DevExecutorComposition(**configuration())
        public = {name for name in dir(composed) if not name.startswith("_")}
        self.assertEqual(public, {"serve_once"})
        for forbidden in (
            "run", "execute", "deploy", "load", "save", "append", "accept",
            "bind", "listen", "connect", "initialize", "pull_exact_image",
        ):
            self.assertFalse(hasattr(composed, forbidden))
        with self.assertRaises(AttributeError):
            composed._serve_once = lambda: None  # type: ignore[method-assign]


class DelegationTests(unittest.TestCase):
    """Prove the sole public action delegates once without retry or coercion."""

    def test_serve_once_delegates_exactly_once_and_returns_none(self) -> None:
        class RecordingListener:
            def __init__(self, **kwargs: object) -> None:
                self.calls = 0

            def serve_once(self) -> None:
                self.calls += 1

        with patch.object(composition_module, "_UnixExecutorListener", RecordingListener):
            composed = composition_module.DevExecutorComposition(**configuration())
        listener = composed._serve_once.__self__
        self.assertIsNone(composed.serve_once())
        self.assertEqual(listener.calls, 1)

    def test_serve_once_preserves_failure_without_retry(self) -> None:
        marker = RuntimeError("listener failed closed")

        class FailingListener:
            def __init__(self, **kwargs: object) -> None:
                self.calls = 0

            def serve_once(self) -> None:
                self.calls += 1
                raise marker

        with patch.object(composition_module, "_UnixExecutorListener", FailingListener):
            composed = composition_module.DevExecutorComposition(**configuration())
        listener = composed._serve_once.__self__
        with self.assertRaises(RuntimeError) as caught:
            composed.serve_once()
        self.assertIs(caught.exception, marker)
        self.assertEqual(listener.calls, 1)

    def test_serve_once_rejects_non_none_result(self) -> None:
        class InvalidListener:
            def __init__(self, **kwargs: object) -> None:
                self.calls = 0

            def serve_once(self) -> None:
                self.calls += 1
                return "unexpected"  # type: ignore[return-value]

        with patch.object(composition_module, "_UnixExecutorListener", InvalidListener):
            composed = composition_module.DevExecutorComposition(**configuration())
        listener = composed._serve_once.__self__
        with self.assertRaises(TypeError):
            composed.serve_once()
        self.assertEqual(listener.calls, 1)


if __name__ == "__main__":
    unittest.main()
