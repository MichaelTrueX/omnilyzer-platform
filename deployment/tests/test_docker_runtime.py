from __future__ import annotations

import ast
import builtins
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from deployment.controller import DeploymentPlan
import deployment.docker_runtime as runtime_module
from deployment.docker_runtime import (
    COMMAND_TIMEOUT_SECONDS, COMPOSE_FILE, HTTP_TIMEOUT_SECONDS, IMAGE_PREFIX,
    MAX_HTTP_RESPONSE, MIGRATION_CHECKSUM, MIGRATION_IDENTITY, PROJECT,
    RUNTIME_CONFIG_BYTES, WORKING_DIRECTORY, CandidateHttpClient, CommandResult,
    DockerComposeCandidateHttpClient, DockerRuntimeAdapter, RuntimeOperationError,
    SubprocessCommandRunner, candidate_slot, validate_canary_image,
    validate_runtime_configuration,
)
from deployment.policy import DeploymentPolicyError


IMAGE = IMAGE_PREFIX + "sha256:" + "6" * 64
OTHER_IMAGE = IMAGE_PREFIX + "sha256:" + "7" * 64
SOURCE = "9d29fa1a4010e6e72676580c36a94c1e97e8794b"
EXPECTED_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "CANARY_IMAGE": IMAGE,
}


class FakeRunner:
    def __init__(self) -> None:
        self.calls = []
        self.results: list[object] = []
        self.error: BaseException | None = None

    def run(self, argv, *, cwd, environment, timeout):
        self.calls.append((argv, cwd, dict(environment), timeout))
        if self.error is not None:
            raise self.error
        if self.results:
            return self.results.pop(0)
        return CommandResult(0, "", "")


class FakeHttp:
    def __init__(self) -> None:
        self.values = {
            "/livez": (200, b'{"live":true}\n'),
            "/readyz": (200, b'{"checks":{},"ready":true}\n'),
            "/metadata": (200, json.dumps({"canary": True, "release_version": "0.14.2", "source_sha": SOURCE}).encode()),
        }
        self.calls = []

    def get(self, slot, path, *, timeout, max_bytes):
        self.calls.append((slot, path, timeout, max_bytes))
        return self.values[path]


def plan(active=None, candidate="blue"):
    return DeploymentPlan("promotion", "dev", "0.14.2", SOURCE, IMAGE, active, candidate, ())


def probe_result(status: object = 200, body_hex: object = "") -> CommandResult:
    """Return one canonical candidate-probe envelope for a fake runner."""

    return CommandResult(
        0,
        json.dumps(
            {"body_hex": body_hex, "status": status},
            sort_keys=True, separators=(",", ":"),
        ) + "\n",
        "",
    )


class Text(str):
    """Represent a non-exact string rejected by closed probe selection."""


class FloatValue(float):
    """Represent a non-exact float rejected by timeout validation."""


class IntegerValue(int):
    """Represent a non-exact integer rejected by response-bound validation."""


class DockerComposeCandidateHttpClientTests(unittest.TestCase):
    """Hostile tests for the closed same-container candidate probe."""

    def setUp(self) -> None:
        self.runner = FakeRunner()
        self.client = DockerComposeCandidateHttpClient(
            self.runner, canary_image=IMAGE,
        )

    def get(self, slot: object = "blue", path: object = "/livez") -> tuple[int, bytes]:
        """Invoke the client with the exact reviewed timeout and response bound."""

        return self.client.get(  # type: ignore[arg-type]
            slot, path, timeout=HTTP_TIMEOUT_SECONDS, max_bytes=MAX_HTTP_RESPONSE,
        )

    def test_constructor_is_inert_and_uses_no_host_network_or_subprocess(self) -> None:
        runner = FakeRunner()
        with (
            patch.object(builtins, "open", side_effect=AssertionError("filesystem")),
            patch.object(os, "open", side_effect=AssertionError("filesystem")),
            patch.object(socket, "socket", side_effect=AssertionError("host socket")),
            patch.object(socket, "create_connection", side_effect=AssertionError("host network")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
        ):
            client = DockerComposeCandidateHttpClient(runner, canary_image=IMAGE)
        self.assertIsInstance(client, DockerComposeCandidateHttpClient)
        self.assertEqual(runner.calls, [])

    def test_constructor_requires_exact_image_and_ordinary_runner(self) -> None:
        for image in (IMAGE + " ", OTHER_IMAGE.replace("7", "A"), Text(IMAGE)):
            with self.subTest(image_type=type(image).__name__), self.assertRaises(
                (TypeError, RuntimeOperationError),
            ):
                DockerComposeCandidateHttpClient(self.runner, canary_image=image)
        with self.assertRaises(TypeError):
            DockerComposeCandidateHttpClient(object(), canary_image=IMAGE)  # type: ignore[arg-type]
        self.assertEqual(self.runner.calls, [])

    def test_get_has_exact_protocol_and_c11_compatible_shape(self) -> None:
        expected = ("self", "slot", "path", "timeout", "max_bytes")
        signature = inspect.signature(DockerComposeCandidateHttpClient.get)
        protocol = inspect.signature(CandidateHttpClient.get)
        self.assertEqual(tuple(signature.parameters), expected)
        self.assertEqual(tuple(protocol.parameters), expected)
        self.assertEqual(
            [parameter.kind for parameter in signature.parameters.values()],
            [
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
                inspect.Parameter.KEYWORD_ONLY,
            ],
        )
        self.assertTrue(all(
            parameter.default is inspect.Parameter.empty
            for parameter in signature.parameters.values()
        ))

    def test_only_exact_blue_and_green_slots_are_selected(self) -> None:
        for slot, service in (("blue", "canary-blue"), ("green", "canary-green")):
            self.runner.results = [probe_result()]
            self.get(slot=slot)
            self.assertEqual(self.runner.calls[-1][0][8], service)
        invalid = (
            "Blue", "GREEN", "canary-blue", "blue:8080", "blue/", " blue",
            "blue ", "", "database", Text("blue"), None, 1,
        )
        for slot in invalid:
            self.runner.calls.clear()
            with self.subTest(slot=repr(slot)), self.assertRaises(RuntimeOperationError):
                self.get(slot=slot)
            self.assertEqual(self.runner.calls, [])

    def test_only_three_exact_paths_are_selected(self) -> None:
        for path in ("/livez", "/readyz", "/metadata"):
            self.runner.results = [probe_result()]
            self.get(path=path)
            self.assertEqual(self.runner.calls[-1][0][-1], path)
        invalid = (
            "/", "/health", "/livez/", "/livez?x=1", "//livez",
            "http://127.0.0.1:8080/livez", "https://example/livez",
            "/livez#fragment", " /livez", "/livez ", Text("/livez"), None, 1,
        )
        for path in invalid:
            self.runner.calls.clear()
            with self.subTest(path=repr(path)), self.assertRaises(RuntimeOperationError):
                self.get(path=path)
            self.assertEqual(self.runner.calls, [])

    def test_exact_compose_exec_command_for_every_slot_and_path(self) -> None:
        for slot, service in (("blue", "canary-blue"), ("green", "canary-green")):
            for path in ("/livez", "/readyz", "/metadata"):
                self.runner.results = [probe_result()]
                self.get(slot=slot, path=path)
                argv = self.runner.calls[-1][0]
                self.assertEqual(argv, (
                    "docker", "compose", "--project-name", PROJECT,
                    "--file", str(COMPOSE_FILE), "exec", "--no-TTY", service,
                    "/usr/bin/python", "-c",
                    runtime_module._CANDIDATE_PROBE_SCRIPT, path,
                ))
                self.assertNotIn("sh", argv)
                self.assertNotIn("bash", argv)
                self.assertNotIn("docker exec", " ".join(argv))

    def test_helper_uses_only_same_container_numeric_loopback(self) -> None:
        script = runtime_module._CANDIDATE_PROBE_SCRIPT
        tree = ast.parse(script)
        constants = {
            node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
        }
        self.assertIn("127.0.0.1", constants)
        self.assertIn(8080, constants)
        self.assertIn(4097, constants)
        self.assertTrue({"/livez", "/readyz", "/metadata"}.issubset(constants))
        lowered = script.lower()
        for forbidden in (
            "3020", "3021", "3022", "localhost", "canary-dev.omnilyzer.ai",
            "urllib.request", "requests", "curl", "wget", "proxy",
        ):
            self.assertNotIn(forbidden, lowered)
        self.assertIn('connection.request(\n            "GET"', script)

    def test_runner_receives_only_exact_minimal_environment_and_bounds(self) -> None:
        self.runner.results = [probe_result()]
        self.get()
        _argv, cwd, environment, timeout = self.runner.calls[0]
        self.assertEqual(cwd, WORKING_DIRECTORY)
        self.assertEqual(environment, EXPECTED_ENVIRONMENT)
        self.assertEqual(set(environment), {"PATH", "LANG", "CANARY_IMAGE"})
        self.assertEqual(timeout, HTTP_TIMEOUT_SECONDS)
        self.assertFalse(any("proxy" in name.lower() for name in environment))
        self.assertNotIn("HOME", environment)

    def test_valid_statuses_and_exact_body_bytes_are_preserved(self) -> None:
        for status, body in ((200, b'\x00{\xff}\n'), (503, b'{"ready":false}\n')):
            self.runner.results = [probe_result(status, body.hex())]
            returned_status, returned_body = self.get(path="/readyz")
            self.assertEqual(returned_status, status)
            self.assertIs(type(returned_body), bytes)
            self.assertEqual(returned_body, body)

    def test_malformed_envelopes_fail_closed_without_retry(self) -> None:
        malformed: tuple[object, ...] = (
            CommandResult(0, "not-json\n", ""),
            CommandResult(0, '{"body_hex":"","extra":1,"status":200}\n', ""),
            CommandResult(0, '{"body_hex":""}\n', ""),
            probe_result(True, ""),
            probe_result("200", ""),
            probe_result(-1, ""),
            probe_result(600, ""),
            probe_result(200, "AA"),
            probe_result(200, "a"),
            probe_result(200, "gg"),
            probe_result(200, "00" * (MAX_HTTP_RESPONSE + 1)),
            CommandResult(0, "x" * (MAX_HTTP_RESPONSE * 3), ""),
            CommandResult(0, '{"body_hex":"","body_hex":"","status":200}\n', ""),
            CommandResult(0, '{ "body_hex":"","status":200}\n', ""),
            CommandResult(0, '{"body_hex":"","status":200}\nextra', ""),
            CommandResult(1, "", ""),
            CommandResult(True, '{"body_hex":"","status":200}\n', ""),
            CommandResult(0, '{"body_hex":"","status":200}\n', "warning"),
            CommandResult(0, b"wrong", ""),  # type: ignore[arg-type]
            CommandResult(0, "", b"wrong"),  # type: ignore[arg-type]
            object(),
        )
        for result in malformed:
            self.runner.calls.clear()
            self.runner.results = [result]
            with self.subTest(result=repr(result)), self.assertRaisesRegex(
                RuntimeOperationError, "^candidate probe failed$",
            ):
                self.get()
            self.assertEqual(len(self.runner.calls), 1)

    def test_runner_failure_is_generic_and_never_retried(self) -> None:
        marker = OSError("sensitive runner detail")
        self.runner.error = marker
        with self.assertRaisesRegex(
            RuntimeOperationError, "^candidate probe failed$",
        ) as caught:
            self.get()
        self.assertEqual(len(self.runner.calls), 1)
        self.assertNotIn("sensitive", str(caught.exception))

    def test_timeout_and_response_bound_must_be_exact_builtins(self) -> None:
        invalid_timeouts = (
            True, 3, "3.0", float("nan"), float("inf"), -1.0, 0.0, 3.1,
            FloatValue(HTTP_TIMEOUT_SECONDS), object(),
        )
        for timeout in invalid_timeouts:
            with self.subTest(timeout=repr(timeout)), self.assertRaises(RuntimeOperationError):
                self.client.get(  # type: ignore[arg-type]
                    "blue", "/livez", timeout=timeout, max_bytes=MAX_HTTP_RESPONSE,
                )
        invalid_bounds = (
            True, "4096", -1, 0, MAX_HTTP_RESPONSE + 1,
            float(MAX_HTTP_RESPONSE), IntegerValue(MAX_HTTP_RESPONSE), object(),
        )
        for bound in invalid_bounds:
            with self.subTest(bound=repr(bound)), self.assertRaises(RuntimeOperationError):
                self.client.get(  # type: ignore[arg-type]
                    "blue", "/livez", timeout=HTTP_TIMEOUT_SECONDS, max_bytes=bound,
                )
        self.assertEqual(self.runner.calls, [])

    def test_get_uses_no_host_socket_with_fake_runner(self) -> None:
        self.runner.results = [probe_result(200, b'{"live":true}\n'.hex())]
        with (
            patch.object(socket, "socket", side_effect=AssertionError("host socket")),
            patch.object(socket, "create_connection", side_effect=AssertionError("host network")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")),
        ):
            self.assertEqual(self.get(), (200, b'{"live":true}\n'))
        self.assertEqual(len(self.runner.calls), 1)

    def test_public_surface_is_only_get_and_configuration_is_immutable(self) -> None:
        public = {name for name in dir(self.client) if not name.startswith("_")}
        self.assertEqual(public, {"get"})
        for forbidden in (
            "run", "exec", "probe", "connect", "request", "fetch", "send",
            "shell", "command", "container", "inspect", "health", "metadata",
            "start", "stop", "restart", "docker", "compose",
        ):
            self.assertFalse(hasattr(self.client, forbidden))
        with self.assertRaises(AttributeError):
            self.client._configuration = ()  # type: ignore[misc]

    def test_concrete_client_integrates_with_runtime_adapter_using_fakes(self) -> None:
        self.runner.results = [probe_result(200, b'{"live":true}\n'.hex())]
        adapter = DockerRuntimeAdapter(
            self.runner, self.client, canary_image=IMAGE,
        )
        self.assertTrue(adapter.check_liveness("dev", "blue"))
        self.assertEqual(len(self.runner.calls), 1)


class DockerRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.runner = FakeRunner()
        self.http = FakeHttp()
        self.migration = Path(self.temp.name) / "migration"
        self.migration.mkdir()
        self.adapter = DockerRuntimeAdapter(
            self.runner, self.http, canary_image=IMAGE,
        )
        self.adapter._nginx_runtime_directory = Path(self.temp.name)
        self.adapter._migration_directory = self.migration

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_image_contract_rejects_tags_origins_repositories_and_whitespace(self) -> None:
        bad = [
            IMAGE_PREFIX.removesuffix("@") + ":0.14.2", IMAGE + " ", " " + IMAGE,
            IMAGE + "," + IMAGE, "docker.io/omnilyzer/task013-release-canary@sha256:" + "6" * 64,
            "oci-dev.omnilyzer.ai/omnilyzer/other@sha256:" + "6" * 64,
            IMAGE_PREFIX + "sha256:" + "A" * 64,
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(RuntimeOperationError):
                validate_canary_image(value)
        self.assertEqual(validate_canary_image(IMAGE), IMAGE)

    def test_constructor_binds_only_an_exact_authorized_digest(self) -> None:
        accepted = DockerRuntimeAdapter(
            self.runner, self.http, canary_image=IMAGE,
        )
        self.assertEqual(accepted._canary_image, IMAGE)
        rejected = (
            IMAGE_PREFIX.removesuffix("@") + ":0.14.2",
            "docker.io/omnilyzer/task013-release-canary@sha256:" + "6" * 64,
            "oci-dev.omnilyzer.ai/omnilyzer/other@sha256:" + "6" * 64,
        )
        for image in rejected:
            with self.subTest(image=image), self.assertRaises(RuntimeOperationError):
                DockerRuntimeAdapter(self.runner, self.http, canary_image=image)

    def test_runtime_configuration_is_closed_and_canonical(self) -> None:
        validate_runtime_configuration(RUNTIME_CONFIG_BYTES)
        for raw in (RUNTIME_CONFIG_BYTES.rstrip(), RUNTIME_CONFIG_BYTES.replace(b"false", b"true"), RUNTIME_CONFIG_BYTES + b" "):
            with self.assertRaises(RuntimeOperationError):
                validate_runtime_configuration(raw)

    def test_pull_argv_is_exact_and_bounded(self) -> None:
        self.adapter.pull_exact_image(IMAGE)
        argv, _, environment, timeout = self.runner.calls[0]
        self.assertEqual(argv, ("docker", "pull", IMAGE))
        self.assertEqual(environment, EXPECTED_ENVIRONMENT)
        self.assertEqual(timeout, COMMAND_TIMEOUT_SECONDS)

    def test_image_operations_reject_another_valid_digest(self) -> None:
        operations = (
            lambda: self.adapter.pull_exact_image(OTHER_IMAGE),
            lambda: self.adapter.verify_local_repo_digest(OTHER_IMAGE),
            lambda: self.adapter.start_candidate(DeploymentPlan(
                "promotion", "dev", "0.14.2", SOURCE, OTHER_IMAGE, None, "blue", (),
            )),
            lambda: self.adapter.execute_migration(
                stage="dev", exact_image_reference=OTHER_IMAGE,
                identity=MIGRATION_IDENTITY, checksum=MIGRATION_CHECKSUM,
            ),
        )
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaisesRegex(
                RuntimeOperationError, "differs from the adapter",
            ):
                operation()
        self.assertEqual(self.runner.calls, [])

    def test_subprocess_runner_bounds_output_and_time_without_shell(self) -> None:
        runner = SubprocessCommandRunner()
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        result = runner.run(
            (sys.executable, "-c", "print('ok')"), cwd=Path(self.temp.name),
            environment=environment, timeout=1.0,
        )
        self.assertEqual((result.returncode, result.stdout), (0, "ok\n"))
        with self.assertRaisesRegex(RuntimeOperationError, "output exceeded"):
            runner.run(
                (sys.executable, "-c", "print('x'*20000)"), cwd=Path(self.temp.name),
                environment=environment, timeout=1.0,
            )
        with self.assertRaisesRegex(RuntimeOperationError, "bounded runtime command failed"):
            runner.run(
                (sys.executable, "-c", "import time; time.sleep(2)"), cwd=Path(self.temp.name),
                environment=environment, timeout=0.01,
            )
        source = Path(__file__).resolve().parents[1].joinpath("docker_runtime.py").read_text()
        self.assertNotIn("shell=True", source)

    def test_local_repo_digest_must_be_single_exact_value(self) -> None:
        self.runner.results = [CommandResult(0, json.dumps([IMAGE]), "")]
        self.adapter.verify_local_repo_digest(IMAGE)
        for output in ("not-json", json.dumps([]), json.dumps([IMAGE, IMAGE]), json.dumps([IMAGE.replace("6", "7")])):
            self.runner.results = [CommandResult(0, output, "")]
            with self.subTest(output=output), self.assertRaises(RuntimeOperationError):
                self.adapter.verify_local_repo_digest(IMAGE)

    def test_closed_candidate_selection(self) -> None:
        self.assertEqual(candidate_slot(None), "blue")
        self.assertEqual(candidate_slot("blue"), "green")
        self.assertEqual(candidate_slot("green"), "blue")
        with self.assertRaises(DeploymentPolicyError):
            candidate_slot("database")

    def test_start_only_inactive_candidate_and_never_builds(self) -> None:
        self.runner.results = [CommandResult(0, json.dumps([IMAGE]), ""), CommandResult(0, "", "")]
        self.adapter.start_candidate(plan())
        argv = self.runner.calls[-1][0]
        self.assertEqual(argv[-5:], ("up", "--detach", "--no-deps", "--force-recreate", "canary-blue"))
        self.assertEqual(self.runner.calls[-1][2], EXPECTED_ENVIRONMENT)
        self.assertNotIn("build", argv)
        with self.assertRaises(RuntimeOperationError):
            self.adapter.start_candidate(plan(active="blue", candidate="blue"))

    def test_migration_is_explicit_hardened_and_rw_only_there(self) -> None:
        self.adapter.execute_migration(
            stage="dev", exact_image_reference=IMAGE,
            identity=MIGRATION_IDENTITY, checksum=MIGRATION_CHECKSUM,
        )
        argv = self.runner.calls[0][0]
        self.assertEqual(argv[:3], ("docker", "run", "--rm"))
        self.assertIn("/app/migration.py", argv)
        mount = next(item for item in argv if "dst=/run/omnilyzer-canary" in item)
        self.assertNotIn("readonly", mount)
        self.assertNotIn(",ro", mount)
        with self.assertRaises(RuntimeOperationError):
            self.adapter.execute_migration(
                stage="dev", exact_image_reference=IMAGE,
                identity="other", checksum=MIGRATION_CHECKSUM,
            )

    def test_health_and_metadata_are_closed_bounded_and_exact(self) -> None:
        self.assertTrue(self.adapter.check_liveness("dev", "blue"))
        self.assertTrue(self.adapter.check_readiness("dev", "blue"))
        self.assertTrue(self.adapter.validate_application(plan()))
        self.http.values["/metadata"] = (200, b'{"canary":true,"release_version":"0.14.1","source_sha":"' + SOURCE.encode() + b'"}')
        self.assertFalse(self.adapter.validate_application(plan()))
        self.http.values["/livez"] = (200, b"x" * 4097)
        with self.assertRaises(RuntimeOperationError):
            self.adapter.check_liveness("dev", "blue")

    def test_switch_fragments_are_canonical_and_arbitrary_upstream_is_impossible(self) -> None:
        blue = self.adapter._active_fragment("blue")
        green = self.adapter._active_fragment("green")
        self.assertIn(b"canary-blue:8080", blue)
        self.assertIn(b"canary-green:8080", green)
        with self.assertRaises(DeploymentPolicyError):
            self.adapter._active_fragment("blue:9000")

    def test_validate_nginx_and_normal_switch_bind_every_compose_call(self) -> None:
        self.assertTrue(self.adapter.validate_nginx("dev"))
        self.assertEqual(len(self.runner.calls), 1)
        self.assertIn("-t", self.runner.calls[0][0])
        self.assertEqual(self.runner.calls[0][2], EXPECTED_ENVIRONMENT)

        self.runner.calls.clear()
        self.adapter.switch_traffic("dev", "green")
        self.assertEqual(len(self.runner.calls), 2)
        self.assertIn("-t", self.runner.calls[0][0])
        self.assertEqual(self.runner.calls[1][0][-3:], ("nginx", "-s", "reload"))
        for _, _, environment, _ in self.runner.calls:
            self.assertEqual(environment, EXPECTED_ENVIRONMENT)

    def test_restore_traffic_is_closed_and_supports_no_active_maintenance(self) -> None:
        class Text(str):
            pass

        target = Path(self.temp.name) / "active.conf"
        target.write_bytes(self.adapter._active_fragment("green"))
        self.adapter.restore_traffic("dev", "blue")
        self.assertEqual(target.read_bytes(), self.adapter._active_fragment("blue"))
        self.adapter.restore_traffic("dev", None)
        self.assertFalse(target.exists())
        for stage, slot in (
            ("prod", "blue"), ("dev", "database"),
            (Text("dev"), "blue"), ("dev", Text("blue")),
        ):
            with self.subTest(stage=stage, slot=slot), self.assertRaises(RuntimeOperationError):
                self.adapter.restore_traffic(stage, slot)

    def test_syntax_failure_restores_previous_routing(self) -> None:
        target = Path(self.temp.name) / "active.conf"
        old = self.adapter._active_fragment("blue")
        target.write_bytes(old)
        self.runner.results = [CommandResult(1, "", "syntax"), CommandResult(0, "", ""), CommandResult(0, "", "")]
        with self.assertRaises(RuntimeOperationError):
            self.adapter.switch_traffic("dev", "green")
        self.assertEqual(target.read_bytes(), old)
        self.assertEqual(len(self.runner.calls), 3)
        self.assertIn("-t", self.runner.calls[0][0])
        self.assertIn("-t", self.runner.calls[1][0])
        self.assertEqual(self.runner.calls[2][0][-3:], ("nginx", "-s", "reload"))
        for _, _, environment, _ in self.runner.calls:
            self.assertEqual(environment, EXPECTED_ENVIRONMENT)

    def test_reload_failure_restores_previous_routing(self) -> None:
        target = Path(self.temp.name) / "active.conf"
        old = self.adapter._active_fragment("blue")
        target.write_bytes(old)
        self.runner.results = [
            CommandResult(0, "", ""), CommandResult(1, "", "reload"),
            CommandResult(0, "", ""), CommandResult(0, "", ""),
        ]
        with self.assertRaises(RuntimeOperationError):
            self.adapter.switch_traffic("dev", "green")
        self.assertEqual(target.read_bytes(), old)
        self.assertEqual(len(self.runner.calls), 4)
        self.assertIn("-t", self.runner.calls[0][0])
        self.assertEqual(self.runner.calls[1][0][-3:], ("nginx", "-s", "reload"))
        self.assertIn("-t", self.runner.calls[2][0])
        self.assertEqual(self.runner.calls[3][0][-3:], ("nginx", "-s", "reload"))
        for _, _, environment, _ in self.runner.calls:
            self.assertEqual(environment, EXPECTED_ENVIRONMENT)
        self.assertNotIn("host-nginx", " ".join(" ".join(call[0]) for call in self.runner.calls))


if __name__ == "__main__":
    unittest.main()
