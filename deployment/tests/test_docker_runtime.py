from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

from deployment.controller import DeploymentPlan
from deployment.docker_runtime import (
    COMMAND_TIMEOUT_SECONDS, IMAGE_PREFIX, MIGRATION_CHECKSUM, MIGRATION_IDENTITY,
    CommandResult, DockerRuntimeAdapter, RuntimeOperationError, candidate_slot,
    RUNTIME_CONFIG_BYTES, SubprocessCommandRunner, validate_canary_image,
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
        self.results: list[CommandResult] = []

    def run(self, argv, *, cwd, environment, timeout):
        self.calls.append((argv, cwd, dict(environment), timeout))
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
