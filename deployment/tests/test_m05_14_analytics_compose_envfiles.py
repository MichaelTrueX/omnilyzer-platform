"""File: deployment/tests/test_m05_14_analytics_compose_envfiles.py

Purpose: Isolated functional proof that the existing Analytics Compose template
         passes four distinct, correctly named synthetic env-file secrets to
         Node under the application UID, and rejects a missing secret.
Related: deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/analytics_dev_release_review.py,
         deployment/products/analytics-runtime-dev.json.

This is a disposable NO-NETWORK test, not Task014 signature verification,
privileged executor authorization, deployment or rootless-host qualification.
It never reads real credentials or uses production resources.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from deployment.analytics_dev_release_review import REQUIRED_SECRET_NAMES


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "deployment/runtime/dev/analytics.compose.review.yaml"
LOCAL_TEST_IMAGE = "omnilyzer-analytics-pr52-security:local"
SUCCESS = "M05_ANALYTICS_ENVFILE_UID10001_PASS"


class AnalyticsEnvfileRuntimeTests(unittest.TestCase):
    """Validate actual Node env-file behavior with disposable Compose mounts."""

    def test_runtime_command_uses_exactly_four_matching_env_files(self) -> None:
        """Catch static command/secret drift even without a Docker daemon."""
        import yaml

        config = yaml.safe_load(COMPOSE_FILE.read_text())
        self.assertEqual(config["name"], "omnilyzer-analytics-dev")
        for slot in ("blue", "green"):
            service = config["services"]["analytics-" + slot]
            self.assertEqual(service["user"], "10001:10001")
            command = service["command"]
            self.assertEqual(command[0], "node")
            self.assertEqual(
                command[1:5],
                [f"--env-file=/run/secrets/{name}" for name in REQUIRED_SECRET_NAMES],
            )
            self.assertEqual(
                sorted(item["target"] for item in service["secrets"]),
                sorted(REQUIRED_SECRET_NAMES),
            )
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertEqual(service["ports"][0].split(":")[0], "127.0.0.1")

    @unittest.skipUnless(
        os.environ.get("M05_REAL_ANALYTICS_COMPOSE_TEST") == "1",
        "explicit opt-in required for disposable Docker containers",
    )
    def test_actual_node_loads_exact_secrets_and_denies_missing_file(self) -> None:
        """Verify real Node environment loading and UID permissions, not signatures."""
        if shutil.which("docker") is None:
            self.skipTest("Docker is unavailable")
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is unavailable")

        def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
            """Run bounded, no-network test-only Docker commands."""
            result = subprocess.run(
                cmd, text=True, capture_output=True, timeout=60, check=False,
            )
            if check and result.returncode:
                raise AssertionError(
                    f"Disposable Docker command failed with code {result.returncode}: "
                    + result.stderr[-500:]
                )
            return result

        image = run(["docker", "image", "inspect", LOCAL_TEST_IMAGE], check=False)
        if image.returncode:
            self.skipTest("local PR52 security-test OCI image not cached")
        with tempfile.TemporaryDirectory(prefix="m05-14-envfile-") as folder:
            directory = Path(folder)
            secrets = directory / "secrets"
            secrets.mkdir(mode=0o755)
            expected = {name: "SYNTHETIC_TEST_" + str(i) for i, name
                        in enumerate(REQUIRED_SECRET_NAMES, 1)}
            for name, value in expected.items():
                secret = secrets / name
                secret.write_text(f"{name}={value}\n", encoding="utf-8")
                secret.chmod(0o600)

            raw = yaml.safe_load(COMPOSE_FILE.read_text())
            service = raw["services"]["analytics-blue"].copy()
            for field in ("profiles", "ports", "networks", "healthcheck"):
                service.pop(field, None)
            service["network_mode"] = "none"
            service["restart"] = "no"
            service["image"] = LOCAL_TEST_IMAGE
            service["environment"] = {"NODE_ENV": "test"}
            check_script = (
                "const names=" + json.dumps(list(REQUIRED_SECRET_NAMES)) + ";"
                "const expected=Object.fromEntries(names.map((n,i)=>"
                "[n,'SYNTHETIC_TEST_'+(i+1)]));"
                "if(names.some(n=>process.env[n]!==expected[n]))process.exit(51);"
                f"console.log('{SUCCESS}')"
            )
            service["command"] = [
                "node", *[f"--env-file=/run/secrets/{name}"
                         for name in REQUIRED_SECRET_NAMES],
                "-e", check_script,
            ]
            raw["name"] = "m05-14-envfile-" + directory.name[-7:].lower()
            raw["services"] = {"analytics-blue": service}
            raw.pop("networks", None)
            for item in raw["secrets"].values():
                item["file"] = str(secrets / Path(item["file"]).name)
            temporary_compose = directory / "compose.yaml"
            temporary_compose.write_text(
                yaml.safe_dump(raw, sort_keys=False), encoding="utf-8",
            )
            base = ["docker", "compose", "-f", str(temporary_compose)]
            try:
                # Local rootful Docker may be used only as a *functional* test.
                # UID mapping on the approved rootless host is a separate gate.
                for name in REQUIRED_SECRET_NAMES:
                    run([
                        "docker", "run", "--rm", "--pull", "never",
                        "--network", "none", "--user", "0:0", "--mount",
                        f"type=bind,src={secrets / name},dst=/proof",
                        LOCAL_TEST_IMAGE, "chown", "10001:10001", "/proof",
                    ])
                success = run([*base, "run", "--rm", "--no-deps", "-T",
                               "analytics-blue"])
                self.assertIn(SUCCESS, success.stdout)
                # Removing the essential JWT file must fail, never fall back.
                (secrets / "JWT_SECRET").unlink()
                denied = run([*base, "run", "--rm", "--no-deps", "-T",
                              "analytics-blue"], check=False)
                self.assertNotEqual(denied.returncode, 0)
                self.assertNotIn(SUCCESS, denied.stdout)
            finally:
                run([*base, "down", "--remove-orphans", "--volumes"], check=False)


if __name__ == "__main__":
    unittest.main()
