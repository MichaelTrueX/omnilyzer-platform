"""Adversarial tests for the inert restricted privileged executor core."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ast
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import deployment.executor as executor_module

from deployment.broker import MAX_EXECUTOR_RESPONSE_BYTES
from deployment.execution import (
    MAX_CANONICAL_REQUEST_BYTES,
    ExecutorRequest,
    PrivilegedExecutor,
)
from deployment.executor import (
    EXECUTOR_REJECTED_MESSAGE,
    EXECUTOR_UNAVAILABLE_MESSAGE,
    ExecutorRejectedError,
    ExecutorResponse,
    ExecutorUnavailableError,
    RestrictedPrivilegedExecutor,
    parse_canonical_response,
)
from deployment.identity import ReplayError, ReplayUnavailableError
from deployment.replay_sqlite import DIRECTORY_MODE, SQLiteReplayGuard
from deployment.tests.fixtures import executor_request_value


ROOT = Path(__file__).resolve().parents[2]


def request_bytes(updates: dict[str, object] | None = None) -> bytes:
    value = executor_request_value()
    if updates:
        value.update(updates)
    return ExecutorRequest.from_dict(value).canonical_bytes()


class Replay:
    def __init__(self, events: list[object], begin_error=None, finish_error=None):
        self.events = events
        self.begin_error = begin_error
        self.finish_error = finish_error
        self.begin_calls: list[tuple[object, dict[str, object]]] = []
        self.finish_calls: list[tuple[object, dict[str, object]]] = []

    def begin_execution(self, jti, *, request_hash, run_id, run_attempt):
        binding = {
            "request_hash": request_hash, "run_id": run_id,
            "run_attempt": run_attempt,
        }
        self.events.append("begin_execution")
        self.begin_calls.append((jti, binding))
        if self.begin_error is not None:
            raise self.begin_error

    def finish_execution(self, jti, *, request_hash, run_id, run_attempt):
        binding = {
            "request_hash": request_hash, "run_id": run_id,
            "run_attempt": run_attempt,
        }
        self.events.append("finish_execution")
        self.finish_calls.append((jti, binding))
        if self.finish_error is not None:
            raise self.finish_error


class Operation:
    def __init__(self, events: list[object], result=None, error=None):
        self.events = events
        self.result = result
        self.error = error
        self.requests: list[ExecutorRequest] = []

    def deploy(self, request):
        self.events.append("deploy")
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.result


class ExecutorCoreTests(unittest.TestCase):
    def make(self, *, replay=None, operation=None):
        events: list[object] = []
        replay = replay or Replay(events)
        operation = operation or Operation(events)
        return RestrictedPrivilegedExecutor(
            replay_guard=replay, operation=operation,
        ), replay, operation, events

    def assert_rejected(self, call) -> None:
        with self.assertRaises(ExecutorRejectedError) as captured:
            call()
        self.assertEqual(type(captured.exception), ExecutorRejectedError)
        self.assertEqual(str(captured.exception), EXECUTOR_REJECTED_MESSAGE)
        self.assertIsNone(captured.exception.__cause__)

    def assert_unavailable(self, call) -> None:
        with self.assertRaises(ExecutorUnavailableError) as captured:
            call()
        self.assertEqual(type(captured.exception), ExecutorUnavailableError)
        self.assertEqual(str(captured.exception), EXECUTOR_UNAVAILABLE_MESSAGE)
        self.assertIsNone(captured.exception.__cause__)

    def test_import_and_construction_are_inert_and_forbidden_modules_absent(self) -> None:
        tree = ast.parse((ROOT / "deployment/executor.py").read_text())
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        forbidden = {
            "socket", "subprocess", "docker", "deployment.docker_runtime",
            "deployment.controller", "deployment.unix_transport", "deployment.audit",
        }
        self.assertTrue(forbidden.isdisjoint(imported))
        events: list[object] = []
        with (
            patch("pathlib.Path.open") as open_file,
            patch("socket.socket") as socket,
            patch("subprocess.Popen") as popen,
            patch("threading.Thread.start") as thread_start,
        ):
            module_name = "deployment._executor_inert_probe"
            spec = importlib.util.spec_from_file_location(
                module_name, ROOT / "deployment/executor.py",
            )
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
                module.RestrictedPrivilegedExecutor(
                    replay_guard=Replay(events), operation=Operation(events),
                )
            finally:
                sys.modules.pop(module_name, None)
        self.assertEqual(events, [])
        open_file.assert_not_called()
        socket.assert_not_called()
        popen.assert_not_called()
        thread_start.assert_not_called()

    def test_constructor_requires_ordinary_instance_bound_methods(self) -> None:
        touched: list[str] = []

        class Descriptor:
            def __get__(self, instance, owner):
                touched.append("descriptor")
                raise AssertionError("must not run")

        class BadReplay:
            begin_execution = Descriptor()
            finish_execution = Descriptor()

        class StaticReplay:
            begin_execution = staticmethod(lambda *args, **kwargs: None)
            finish_execution = staticmethod(lambda *args, **kwargs: None)

        class ClassOperation:
            @classmethod
            def deploy(cls, request):
                return None

        for replay, operation in (
            (None, Operation([])),
            (BadReplay(), Operation([])),
            (StaticReplay(), Operation([])),
            (Replay([]), None),
            (Replay([]), ClassOperation()),
        ):
            with self.subTest(replay=type(replay), operation=type(operation)):
                with self.assertRaises(TypeError):
                    RestrictedPrivilegedExecutor(
                        replay_guard=replay, operation=operation,
                    )
        self.assertEqual(touched, [])

    def test_constructor_rejects_incompatible_method_signatures(self) -> None:
        class MissingReplayArgument:
            def begin_execution(self):
                return None

            def finish_execution(self, jti, *, request_hash, run_id, run_attempt):
                return None

        class VariadicReplay:
            def begin_execution(self, jti, *, request_hash, run_id, run_attempt, **extra):
                return None

            def finish_execution(self, jti, *, request_hash, run_id, run_attempt):
                return None

        class DefaultOperation:
            def deploy(self, request=None):
                return None

        class WrongOperation:
            def deploy(self):
                return None

        class AsyncOperation:
            async def deploy(self, request):
                return None

        for replay, operation in (
            (MissingReplayArgument(), Operation([])),
            (VariadicReplay(), Operation([])),
            (Replay([]), DefaultOperation()),
            (Replay([]), WrongOperation()),
            (Replay([]), AsyncOperation()),
        ):
            with self.subTest(replay=type(replay), operation=type(operation)):
                with self.assertRaises(TypeError):
                    RestrictedPrivilegedExecutor(
                        replay_guard=replay, operation=operation,
                    )

    def test_collaborators_are_immutable(self) -> None:
        executor, _, _, _ = self.make()
        with self.assertRaises(AttributeError):
            executor._operations = ()

    def test_public_api_has_only_constructor_bound_collaborators_and_request_bytes(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(RestrictedPrivilegedExecutor).parameters),
            ("replay_guard", "operation"),
        )
        self.assertTrue(all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for parameter in inspect.signature(RestrictedPrivilegedExecutor).parameters.values()
        ))
        self.assertEqual(
            tuple(inspect.signature(RestrictedPrivilegedExecutor.execute).parameters),
            ("self", "canonical_request"),
        )
        public = {
            name for name in dir(RestrictedPrivilegedExecutor)
            if not name.startswith("_")
        }
        self.assertEqual(public, {"execute"})

    def test_input_boundary_rejects_before_collaborators(self) -> None:
        executor, replay, operation, events = self.make()

        class BytesSubclass(bytes):
            pass

        for value in (
            "{}\n", bytearray(b"{}\n"), memoryview(b"{}\n"),
            BytesSubclass(b"{}\n"), b"", b"x" * (MAX_CANONICAL_REQUEST_BYTES + 1),
        ):
            with self.subTest(value_type=type(value), size=len(value)):
                self.assert_rejected(lambda value=value: executor.execute(value))
        self.assertEqual(events, [])
        self.assertEqual(replay.begin_calls, [])
        self.assertEqual(operation.requests, [])

    def test_malformed_noncanonical_and_policy_invalid_rejected_before_calls(self) -> None:
        executor, replay, operation, events = self.make()
        policy_invalid = executor_request_value()
        policy_invalid["stage"] = "prod"
        cases = (
            b"not-json\n",
            json.dumps(executor_request_value()).encode() + b"\n",
            json.dumps(policy_invalid, sort_keys=True, separators=(",", ":")).encode() + b"\n",
        )
        for raw in cases:
            with self.subTest(raw=raw[:20]):
                self.assert_rejected(lambda raw=raw: executor.execute(raw))
        self.assertEqual(events, [])
        self.assertEqual(replay.begin_calls, [])
        self.assertEqual(operation.requests, [])

    def test_success_hashes_original_bytes_and_has_exact_order_and_binding(self) -> None:
        executor, replay, operation, events = self.make()
        raw = request_bytes()
        expected_hash = hashlib.sha256(raw).hexdigest()
        response = executor.execute(raw)
        parsed = parse_canonical_response(response)
        request = ExecutorRequest.from_dict(executor_request_value())
        binding = {
            "request_hash": expected_hash,
            "run_id": request.github_run_id,
            "run_attempt": request.github_run_attempt,
        }
        self.assertEqual(events, ["begin_execution", "deploy", "finish_execution"])
        self.assertEqual(replay.begin_calls, [(request.oidc_jti, binding)])
        self.assertEqual(replay.finish_calls, [(request.oidc_jti, binding)])
        self.assertEqual(len(operation.requests), 1)
        self.assertEqual(type(operation.requests[0]), ExecutorRequest)
        self.assertEqual(parsed.executor_request_sha256, expected_hash)

    def test_replay_snapshot_revalidates_exact_builtins_and_bounds(self) -> None:
        raw = request_bytes()
        for field, value in (
            ("oidc_jti", "../host-path"),
            ("github_run_id", True),
            ("github_run_id", 2**63),
            ("github_run_attempt", 1.0),
            ("github_run_attempt", 2**63),
        ):
            request = ExecutorRequest.from_dict(executor_request_value())
            object.__setattr__(request, field, value)
            executor, replay, operation, events = self.make()
            with self.subTest(field=field, value=value), patch(
                "deployment.executor.parse_canonical_request", return_value=request,
            ):
                self.assert_unavailable(lambda: executor.execute(raw))
                self.assertEqual(events, [])
                self.assertEqual(replay.begin_calls, [])
                self.assertEqual(operation.requests, [])

    def test_operation_failure_or_non_none_is_unavailable_without_finish_or_retry(self) -> None:
        marker = "secret-operation-marker"
        for operation in (Operation([], result=False), Operation([], error=RuntimeError(marker))):
            events: list[object] = []
            operation.events = events
            replay = Replay(events)
            executor, _, _, _ = self.make(replay=replay, operation=operation)
            with self.subTest(result=operation.result, error=operation.error):
                self.assert_unavailable(lambda: executor.execute(request_bytes()))
                self.assertEqual(events, ["begin_execution", "deploy"])
                self.assertEqual(len(operation.requests), 1)
                self.assertEqual(replay.finish_calls, [])

    def test_begin_errors_classify_and_prevent_operation(self) -> None:
        cases = (
            (ReplayError("sensitive-jti"), ExecutorRejectedError),
            (ReplayUnavailableError("secret-sql"), ExecutorUnavailableError),
            (RuntimeError("secret-dependency"), ExecutorUnavailableError),
        )
        for error, expected in cases:
            events: list[object] = []
            replay = Replay(events, begin_error=error)
            operation = Operation(events)
            executor, _, _, _ = self.make(replay=replay, operation=operation)
            with self.subTest(error=type(error)):
                assertion = self.assert_rejected if expected is ExecutorRejectedError else self.assert_unavailable
                assertion(lambda: executor.execute(request_bytes()))
                self.assertEqual(events, ["begin_execution"])
                self.assertEqual(operation.requests, [])
                self.assertEqual(replay.finish_calls, [])

    def test_finish_failures_are_unavailable_and_never_rerun_deploy(self) -> None:
        for error in (ReplayError("secret"), ReplayUnavailableError("path"), RuntimeError("host")):
            events: list[object] = []
            replay = Replay(events, finish_error=error)
            operation = Operation(events)
            executor, _, _, _ = self.make(replay=replay, operation=operation)
            with self.subTest(error=type(error)):
                self.assert_unavailable(lambda: executor.execute(request_bytes()))
                self.assertEqual(events, ["begin_execution", "deploy", "finish_execution"])
                self.assertEqual(len(operation.requests), 1)
                self.assertEqual(len(replay.finish_calls), 1)

    def test_non_none_replay_results_are_contract_failures(self) -> None:
        class BadBegin(Replay):
            def begin_execution(self, jti, *, request_hash, run_id, run_attempt):
                super().begin_execution(
                    jti, request_hash=request_hash, run_id=run_id,
                    run_attempt=run_attempt,
                )
                return True

        class BadFinish(Replay):
            def finish_execution(self, jti, *, request_hash, run_id, run_attempt):
                super().finish_execution(
                    jti, request_hash=request_hash, run_id=run_id,
                    run_attempt=run_attempt,
                )
                return 0

        for replay, expected_events in (
            (BadBegin([]), ["begin_execution"]),
            (BadFinish([]), ["begin_execution", "deploy", "finish_execution"]),
        ):
            events = replay.events
            operation = Operation(events)
            executor, _, _, _ = self.make(replay=replay, operation=operation)
            self.assert_unavailable(lambda: executor.execute(request_bytes()))
            self.assertEqual(events, expected_events)

    def test_control_flow_exceptions_propagate_without_finish(self) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit):
            events: list[object] = []
            operation = Operation(events, error=exception_type())
            replay = Replay(events)
            executor, _, _, _ = self.make(replay=replay, operation=operation)
            with self.subTest(exception_type=exception_type):
                with self.assertRaises(exception_type):
                    executor.execute(request_bytes())
                self.assertEqual(events, ["begin_execution", "deploy"])
                self.assertEqual(replay.finish_calls, [])

    def test_all_normalized_errors_are_generic_and_redacted(self) -> None:
        raw = request_bytes()
        sensitive = (
            raw.decode().strip(), "bearer-token", "secret-jti", "run-3415",
            "/var/lib/private", "SELECT *", "docker stderr", "host.internal",
        )
        events: list[object] = []
        executor = RestrictedPrivilegedExecutor(
            replay_guard=Replay(events),
            operation=Operation(events, error=RuntimeError(" ".join(sensitive))),
        )
        with self.assertRaises(ExecutorUnavailableError) as captured:
            executor.execute(raw)
        self.assertEqual(str(captured.exception), EXECUTOR_UNAVAILABLE_MESSAGE)
        for marker in sensitive:
            self.assertNotIn(marker, str(captured.exception))

    def test_request_mutation_cannot_change_finish_binding_or_response(self) -> None:
        events: list[object] = []
        replay = Replay(events)
        original = ExecutorRequest.from_dict(executor_request_value())
        raw = original.canonical_bytes()
        expected_hash = hashlib.sha256(raw).hexdigest()

        class Mutator:
            def deploy(self, request):
                events.append("deploy")
                object.__setattr__(request, "oidc_jti", "mutated-jti")
                object.__setattr__(request, "github_run_id", 9)
                object.__setattr__(request, "github_run_attempt", 9)

        executor = RestrictedPrivilegedExecutor(replay_guard=replay, operation=Mutator())
        response = parse_canonical_response(executor.execute(raw))
        self.assertEqual(replay.finish_calls, replay.begin_calls)
        self.assertEqual(replay.finish_calls[0][0], original.oidc_jti)
        self.assertEqual(response.executor_request_sha256, expected_hash)

    def test_inflight_replacement_cannot_redirect_later_phases(self) -> None:
        events: list[object] = []
        original_replay = Replay(events)
        redirected_replay = Replay(events)
        redirected_operation = Operation(events)

        class Replacer:
            executor = None

            def deploy(self, request):
                events.append("deploy")
                object.__setattr__(
                    self.executor, "_operations",
                    (
                        redirected_replay.begin_execution,
                        redirected_operation.deploy,
                        redirected_replay.finish_execution,
                        lambda request_hash: b"redirected\n",
                    ),
                )

        operation = Replacer()
        executor = RestrictedPrivilegedExecutor(
            replay_guard=original_replay, operation=operation,
        )
        operation.executor = executor
        executor.execute(request_bytes())
        self.assertEqual(events, ["begin_execution", "deploy", "finish_execution"])
        self.assertEqual(len(original_replay.finish_calls), 1)
        self.assertEqual(redirected_replay.begin_calls, [])
        self.assertEqual(redirected_replay.finish_calls, [])
        self.assertEqual(redirected_operation.requests, [])

    def test_combined_replacement_and_reentrancy_cannot_execute_redirected_operation(self) -> None:
        events: list[object] = []
        original_replay = Replay(events)
        evil_replay = Replay(events)
        evil_operation = Operation(events)
        holder: dict[str, RestrictedPrivilegedExecutor] = {}

        class ReplacingReentrantOperation:
            def deploy(self, request):
                events.append("deploy")
                object.__setattr__(
                    holder["executor"], "_operations",
                    (
                        evil_replay.begin_execution,
                        evil_operation.deploy,
                        evil_replay.finish_execution,
                        lambda request_hash: b"evil\n",
                    ),
                )
                with self_test.assertRaises(ExecutorUnavailableError):
                    holder["executor"].execute(request_bytes())

        self_test = self
        holder["executor"] = RestrictedPrivilegedExecutor(
            replay_guard=original_replay,
            operation=ReplacingReentrantOperation(),
        )
        holder["executor"].execute(request_bytes())
        self.assertEqual(events, ["begin_execution", "deploy", "finish_execution"])
        self.assertEqual(evil_replay.begin_calls, [])
        self.assertEqual(evil_replay.finish_calls, [])
        self.assertEqual(evil_operation.requests, [])

    def test_cross_thread_replacement_and_reentry_cannot_execute_redirected_operation(self) -> None:
        events: list[object] = []
        original_replay = Replay(events)
        evil_replay = Replay(events)
        evil_operation = Operation(events)
        replaced = threading.Event()
        nested_done = threading.Event()
        holder: dict[str, RestrictedPrivilegedExecutor] = {}

        class ReplacingOperation:
            def deploy(self, request):
                events.append("deploy")
                object.__setattr__(
                    holder["executor"], "_operations",
                    (
                        evil_replay.begin_execution,
                        evil_operation.deploy,
                        evil_replay.finish_execution,
                        lambda request_hash: b"evil\n",
                    ),
                )
                replaced.set()
                if not nested_done.wait(timeout=5):
                    raise RuntimeError("nested execution did not finish")

        holder["executor"] = RestrictedPrivilegedExecutor(
            replay_guard=original_replay, operation=ReplacingOperation(),
        )

        def nested_execute():
            if not replaced.wait(timeout=5):
                raise RuntimeError("operation did not replace collaborators")
            try:
                holder["executor"].execute(request_bytes())
            finally:
                nested_done.set()

        with ThreadPoolExecutor(max_workers=2) as pool:
            nested = pool.submit(nested_execute)
            outer = pool.submit(holder["executor"].execute, request_bytes())
            with self.assertRaises(ExecutorUnavailableError):
                nested.result(timeout=5)
            outer.result(timeout=5)
        self.assertEqual(events, ["begin_execution", "deploy", "finish_execution"])
        self.assertEqual(evil_replay.begin_calls, [])
        self.assertEqual(evil_replay.finish_calls, [])
        self.assertEqual(evil_operation.requests, [])

    def test_deploy_cannot_redirect_captured_response_builder(self) -> None:
        events: list[object] = []
        original_response_type = executor_module.ExecutorResponse

        class EvilResponse:
            def __init__(self, request_hash):
                pass

            def canonical_bytes(self):
                return b"ATTACKER RESPONSE"

        class MutatingOperation(Operation):
            def deploy(self, request):
                events.append("deploy")
                executor_module.ExecutorResponse = EvilResponse

        replay = Replay(events)
        executor = RestrictedPrivilegedExecutor(
            replay_guard=replay, operation=MutatingOperation(events),
        )
        try:
            response = executor.execute(request_bytes())
        finally:
            executor_module.ExecutorResponse = original_response_type
        self.assertEqual(parse_canonical_response(response).status, "succeeded")
        self.assertNotEqual(response, b"ATTACKER RESPONSE")

    def test_reentrancy_during_begin_or_deploy_cannot_execute_twice(self) -> None:
        for phase in ("begin", "deploy"):
            events: list[object] = []
            holder: dict[str, RestrictedPrivilegedExecutor] = {}

            class ReentrantReplay(Replay):
                def begin_execution(self, jti, *, request_hash, run_id, run_attempt):
                    result = super().begin_execution(
                        jti, request_hash=request_hash, run_id=run_id,
                        run_attempt=run_attempt,
                    )
                    if phase == "begin":
                        with self_test.assertRaises(ExecutorUnavailableError):
                            holder["executor"].execute(request_bytes())
                    return result

            class ReentrantOperation(Operation):
                def deploy(self, request):
                    if phase == "deploy":
                        with self_test.assertRaises(ExecutorUnavailableError):
                            holder["executor"].execute(request_bytes())
                    return super().deploy(request)

            self_test = self
            replay = ReentrantReplay(events)
            operation = ReentrantOperation(events)
            holder["executor"] = RestrictedPrivilegedExecutor(
                replay_guard=replay, operation=operation,
            )
            holder["executor"].execute(request_bytes())
            self.assertEqual(len(operation.requests), 1)
            self.assertEqual(len(replay.begin_calls), 1)
            self.assertEqual(len(replay.finish_calls), 1)

    def test_hash_provider_failures_and_malformed_results_are_redacted(self) -> None:
        class Digest:
            def __init__(self, value):
                self.value = value

            def hexdigest(self):
                if isinstance(self.value, BaseException):
                    raise self.value
                return self.value

        providers = (
            lambda raw: (_ for _ in ()).throw(RuntimeError("hash-secret")),
            lambda raw: Digest("A" * 64),
            lambda raw: Digest(b"a" * 64),
            lambda raw: Digest("a" * 63),
            lambda raw: Digest(RuntimeError("digest-secret")),
        )
        for provider in providers:
            executor, replay, operation, events = self.make()
            with self.subTest(provider=provider), patch(
                "deployment.executor.hashlib.sha256", provider,
            ):
                self.assert_unavailable(lambda: executor.execute(request_bytes()))
                self.assertEqual(events, [])
                self.assertEqual(replay.begin_calls, [])
                self.assertEqual(operation.requests, [])

    def test_protocol_shape_is_compatible(self) -> None:
        def accepts_executor(value: PrivilegedExecutor) -> bytes:
            return value.execute(request_bytes())

        executor, _, _, _ = self.make()
        self.assertEqual(parse_canonical_response(accepts_executor(executor)).status, "succeeded")


class ExecutorResponseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = "a" * 64
        self.value = {
            "executor_request_sha256": self.digest,
            "schema_version": 1,
            "status": "succeeded",
        }
        self.canonical = ExecutorResponse.from_dict(self.value).canonical_bytes()

    def test_response_is_closed_canonical_bounded_and_deterministic(self) -> None:
        expected = (
            b'{"executor_request_sha256":"' + self.digest.encode()
            + b'","schema_version":1,"status":"succeeded"}\n'
        )
        self.assertEqual(self.canonical, expected)
        self.assertEqual(ExecutorResponse(self.digest).canonical_bytes(), self.canonical)
        self.assertLessEqual(len(self.canonical), MAX_EXECUTOR_RESPONSE_BYTES)
        self.assertEqual(parse_canonical_response(self.canonical), ExecutorResponse(self.digest))
        self.assertEqual(self.canonical.count(b"\n"), 1)
        self.assertTrue(self.canonical.endswith(b"\n"))

    def test_parser_rejects_closed_field_type_hash_and_representation_tricks(self) -> None:
        invalid_values = []
        for key in self.value:
            changed = dict(self.value)
            del changed[key]
            invalid_values.append(changed)
        invalid_values.extend((
            {**self.value, "extra": 1},
            {**self.value, "schema_version": True},
            {**self.value, "schema_version": 1.0},
            {**self.value, "schema_version": 2},
            {**self.value, "status": "failed"},
            {**self.value, "executor_request_sha256": "A" * 64},
            {**self.value, "executor_request_sha256": "a" * 63},
            {**self.value, "executor_request_sha256": "a" * 65},
            {**self.value, "executor_request_sha256": "g" * 64},
        ))
        for value in invalid_values:
            with self.subTest(value=value):
                raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                with self.assertRaises(ValueError):
                    parse_canonical_response(raw)

        duplicate = self.canonical.replace(
            b'{"executor_request_sha256":',
            b'{"status":"succeeded","executor_request_sha256":',
        )
        cases = (
            duplicate,
            self.canonical[:-1],
            self.canonical + b"\n",
            json.dumps(self.value).encode() + b"\n",
            b"x" * (MAX_EXECUTOR_RESPONSE_BYTES + 1),
            "not-bytes",
            bytearray(self.canonical),
            memoryview(self.canonical),
            type("BytesSubclass", (bytes,), {})(self.canonical),
        )
        for raw in cases:
            with self.subTest(raw_type=type(raw)):
                with self.assertRaises(ValueError):
                    parse_canonical_response(raw)

    def test_model_rejects_subclasses_and_coercible_values(self) -> None:
        class IntSubclass(int):
            pass

        class StrSubclass(str):
            pass

        class DictSubclass(dict):
            pass

        class ResponseSubclass(ExecutorResponse):
            pass

        for value in (
            DictSubclass(self.value),
            {**self.value, "schema_version": IntSubclass(1)},
            {**self.value, "status": StrSubclass("succeeded")},
            {**self.value, "executor_request_sha256": StrSubclass(self.digest)},
        ):
            with self.assertRaises(ValueError):
                ExecutorResponse.from_dict(value)
        with self.assertRaises(ValueError):
            ResponseSubclass(self.digest).canonical_bytes()
        with self.assertRaises(ValueError):
            ResponseSubclass.from_dict(self.value)

    def test_json_schema_and_python_policy_agree_on_representable_cases(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is unavailable")
        schema = json.loads(
            (ROOT / "deployment/schemas/executor-response.schema.json").read_text()
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.value, schema)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        for update in (
            {"status": "failed"},
            {"schema_version": 2},
            {"executor_request_sha256": "A" * 64},
            {"extra": True},
        ):
            value = dict(self.value)
            value.update(update)
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(value, schema)
            with self.assertRaises(ValueError):
                ExecutorResponse.from_dict(value)


class SQLiteExecutorIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="task014-executor-")
        self.directory = Path(self.temporary.name)
        self.directory.chmod(DIRECTORY_MODE)
        self.path = self.directory / "replay.sqlite3"
        self.now = 1_778_000_000
        self.guard = SQLiteReplayGuard(
            self.path,
            expected_directory_uid=os.getuid(),
            expected_directory_gid=os.getgid(),
            current_time=lambda: self.now,
        )
        self.guard.initialize()
        self.raw = request_bytes()
        self.request = ExecutorRequest.from_dict(executor_request_value())
        self.request_hash = hashlib.sha256(self.raw).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def consume(self) -> None:
        self.guard.consume(
            self.request.oidc_jti,
            expires_at=self.request.oidc_expires_at,
            request_hash=self.request_hash,
            run_id=self.request.github_run_id,
            run_attempt=self.request.github_run_attempt,
        )

    def status(self) -> str:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT status FROM consumptions WHERE jti = ?",
                (self.request.oidc_jti,),
            ).fetchone()
        assert row is not None
        return row[0]

    def test_real_replay_moves_consumed_to_finished_and_rejects_second_execution(self) -> None:
        self.consume()
        events: list[object] = []
        operation = Operation(events)
        executor = RestrictedPrivilegedExecutor(
            replay_guard=self.guard, operation=operation,
        )
        executor.execute(self.raw)
        self.assertEqual(self.status(), "finished")
        self.assertEqual(len(operation.requests), 1)
        with self.assertRaises(ExecutorRejectedError):
            executor.execute(self.raw)
        self.assertEqual(len(operation.requests), 1)
        self.assertEqual(self.status(), "finished")

    def test_real_replay_operation_failure_remains_executing_without_reset(self) -> None:
        self.consume()
        events: list[object] = []
        operation = Operation(events, error=RuntimeError("secret"))
        executor = RestrictedPrivilegedExecutor(
            replay_guard=self.guard, operation=operation,
        )
        with self.assertRaises(ExecutorUnavailableError):
            executor.execute(self.raw)
        self.assertEqual(self.status(), "executing")
        with self.assertRaises(ExecutorRejectedError):
            executor.execute(self.raw)
        self.assertEqual(len(operation.requests), 1)
        self.assertEqual(self.status(), "executing")

    def test_two_executors_contend_on_one_real_replay_and_run_operation_once(self) -> None:
        self.consume()
        entered = threading.Event()
        release = threading.Event()
        calls: list[ExecutorRequest] = []

        class BlockingOperation:
            def deploy(self, request):
                calls.append(request)
                entered.set()
                release.wait(timeout=5)

        first_executor = RestrictedPrivilegedExecutor(
            replay_guard=self.guard, operation=BlockingOperation(),
        )
        second_executor = RestrictedPrivilegedExecutor(
            replay_guard=self.guard, operation=BlockingOperation(),
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(first_executor.execute, self.raw)
            self.assertTrue(entered.wait(timeout=5))
            second = pool.submit(second_executor.execute, self.raw)
            with self.assertRaises(ExecutorRejectedError):
                second.result(timeout=5)
            release.set()
            first.result(timeout=5)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.status(), "finished")


if __name__ == "__main__":
    unittest.main()
