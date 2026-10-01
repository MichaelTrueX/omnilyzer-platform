"""deployment/tests/test_dev_live_activation_policy.py - C33W policy tests.

Purpose:
- prove the dedicated DEV live authority is exact and closed;
- prove the historical environment/controller source remains unchanged;
- prove the GitHub gate routes DEV through C33W only;
- exercise the exact CLI entrypoint used by the workflow.

Links:
- deployment/dev_live_activation_policy.py validates the dedicated authority.
- deployment/dev-live-activation.json contains the reviewed DEV live authority.
- .github/workflows/platform-promote.yml selects the C33W validator for DEV.
"""

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment import application_source_set
from deployment.dev_live_activation_policy import (
    DEV_ACTIVATION_VERIFIED_AT,
    DEV_INGRESS_FILE_SHA256,
    DEV_RUNTIME_CONFIGURATION_SHA256,
    DEV_RUNTIME_REVIEWED_COMMIT,
    expected_dev_runtime_references,
    main as activation_main,
    validate_live_dev_environment,
)
from deployment.policy import DeploymentPolicyError
from deployment.tests.fixtures import request


ROOT = Path(__file__).resolve().parents[2]


class DevLiveActivationPolicyTests(unittest.TestCase):
    """Exercise exact repository-side DEV live authority."""

    def _live_path(self) -> Path:
        """Return the dedicated C33W authority path."""

        return ROOT / "deployment/dev-live-activation.json"

    def test_dedicated_dev_authority_is_exact(self) -> None:
        """Require exact activation, successor references, and reviewed timestamp."""

        value = json.loads(self._live_path().read_text(encoding="utf-8"))
        validated = validate_live_dev_environment(value)
        self.assertEqual(
            validated["activation"],
            {
                "deployment_enabled": True,
                "verified_at": DEV_ACTIVATION_VERIFIED_AT,
            },
        )
        self.assertEqual(validated["runtime"], expected_dev_runtime_references())
        self.assertEqual(
            validated["runtime"]["configuration_reference"]["reviewed_commit"],
            DEV_RUNTIME_REVIEWED_COMMIT,
        )
        self.assertEqual(
            validated["runtime"]["configuration_reference"]["sha256"],
            DEV_RUNTIME_CONFIGURATION_SHA256,
        )
        self.assertEqual(
            tuple(
                item["sha256"]
                for item in validated["runtime"]["ingress_reference"]["files"]
            ),
            DEV_INGRESS_FILE_SHA256,
        )

    def test_live_authority_rejects_partial_or_forged_values(self) -> None:
        """Fail closed on activation rollback or successor-reference substitution."""

        base = json.loads(self._live_path().read_text(encoding="utf-8"))
        forged_values = []

        value = json.loads(json.dumps(base))
        value["activation"]["deployment_enabled"] = False
        forged_values.append(value)

        value = json.loads(json.dumps(base))
        value["activation"]["verified_at"] = None
        forged_values.append(value)

        value = json.loads(json.dumps(base))
        value["runtime"]["configuration_reference"]["sha256"] = "0" * 64
        forged_values.append(value)

        value = json.loads(json.dumps(base))
        value["runtime"]["ingress_reference"]["files"][0]["sha256"] = "0" * 64
        forged_values.append(value)

        value = json.loads(json.dumps(base))
        value["stage"] = "staging"
        forged_values.append(value)

        for index, value in enumerate(forged_values):
            with self.subTest(index=index), self.assertRaises(DeploymentPolicyError):
                validate_live_dev_environment(value)

    def test_historical_environment_and_host_source_set_remain_closed(self) -> None:
        """Keep historical Phase-1 files and installed host source bytes unchanged."""

        historical = json.loads(
            (ROOT / "deployment/environments/dev.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            historical["activation"],
            {"deployment_enabled": False, "verified_at": None},
        )
        self.assertTrue(all(value is None for value in historical["runtime"].values()))

        paths = tuple(
            item.repository_path
            for item in application_source_set.DevApplicationSourceSet().files
        )
        self.assertIn("deployment/controller.py", paths)
        self.assertNotIn("deployment/dev_live_activation_policy.py", paths)
        self.assertNotIn("deployment/dev_live_activation_contract.py", paths)
        self.assertNotIn("deployment/dev-live-activation.json", paths)

        controller = ROOT / "deployment/controller.py"
        self.assertEqual(
            hashlib.sha256(controller.read_bytes()).hexdigest(),
            "f2c06d37b6b9fbe264c16677f699663594f62e503e0fe0072ec3eca3ce7b207f",
        )

    def test_workflow_routes_dev_only_through_c33w_authority(self) -> None:
        """Require one DEV live-validator call and preserve historical later-stage gate."""

        workflow = (
            ROOT / ".github/workflows/platform-promote.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            workflow.count("python3 -m deployment.dev_live_activation_policy"),
            1,
        )
        self.assertEqual(workflow.count("python3 -m deployment.controller"), 1)
        self.assertIn(
            '--environment "deployment/dev-live-activation.json"',
            workflow,
        )
        self.assertIn(
            '--environment "deployment/environments/$TARGET_STAGE.json"',
            workflow,
        )
        self.assertIn('if [ "$TARGET_STAGE" = "dev" ]; then', workflow)

    def test_cli_accepts_exact_dev_request_and_emits_live_authority(self) -> None:
        """Exercise the exact entrypoint used by the GitHub gate."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_bytes(request("dev").canonical_bytes())
            output = io.StringIO()
            with patch(
                "sys.argv",
                [
                    "dev_live_activation_policy",
                    "--request",
                    str(request_path),
                    "--environment",
                    str(self._live_path()),
                ],
            ), redirect_stdout(output):
                self.assertEqual(activation_main(), 0)

        result = json.loads(output.getvalue())
        self.assertIs(result["deployment_enabled"], True)
        self.assertEqual(result["stage"], "dev")
        self.assertEqual(result["status"], "dev-live-authorized")
        self.assertEqual(result["verified_at"], DEV_ACTIVATION_VERIFIED_AT)
        self.assertEqual(result["request_sha256"], request("dev").sha256())

    def test_policy_module_has_no_host_mutation_surface(self) -> None:
        """Keep the workflow-side policy parser validation-only."""

        source = (
            ROOT / "deployment/dev_live_activation_policy.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "subprocess.",
            "/usr/bin/systemctl",
            "socket.socket(",
            "docker run",
            "tailscale serve",
            "os.replace(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
