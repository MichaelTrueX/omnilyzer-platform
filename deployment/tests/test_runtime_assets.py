from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest

import yaml

from deployment.policy import canonical_bytes


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "deployment/runtime/dev"
TEST_IMAGE = "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:" + "a" * 64
NGINX_IMAGE = "cgr.dev/chainguard/nginx@sha256:af16298b4fd38b12be52aa913c158b530b83d85d567752f611508593d542b20a"
INGRESS_HASHES = {
    "compose.yaml": "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "host-nginx.conf": "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "nginx/nginx.conf": "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
}
PROTECTED = {
    ".github/workflows/platform-release.yml": "53485cfafd1d1b8cdf0b1cb80c34bab12be12bfc07d7f7e6629a8c489be53471",
    ".github/workflows/platform-promote.yml": "3846ae1e48c945dacb563da8967e588b3fbb6fffa2580276f816496396b3c134",
    "deployment/environments/dev.json": "4b1cf03bdcd1fa7d8fd848862137a4dca7dc834b1cc45fa1d7cffd2756722ae8",
    "deployment/environments/staging.json": "7fde448d38022e4e435218c1fe6049c629ee091031845fce93156dcc787a7358",
    "deployment/environments/prod.json": "a08cd3d718ffa0531071ed7ad0aeafc19b4edeb0a82e74bd87a6044bbabebcce",
    "release/vulnerability-policy.json": "475ad38ef4ae8d89dcf7d4e03eeb76701085fdcd4ebdb8ae9aa41a7bce2cde8f",
}


class RuntimeAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = (RUNTIME / "compose.yaml").read_text()
        cls.compose = yaml.safe_load(cls.raw.replace("${CANARY_IMAGE:?exact digest required}", TEST_IMAGE))

    def test_project_and_exact_services(self) -> None:
        self.assertEqual(self.compose["name"], "omnilyzer-task014-dev")
        self.assertEqual(set(self.compose["services"]), {"canary-blue", "canary-green", "deployment-nginx"})

    def test_no_build_and_required_exact_image_expression(self) -> None:
        self.assertNotIn("build:", self.raw)
        self.assertIn("image: ${CANARY_IMAGE:?exact digest required}", self.raw)
        self.assertNotIn("${CANARY_IMAGE:-", self.raw)
        self.assertEqual(self.raw.count("${CANARY_IMAGE"), 1)
        self.assertNotIn("sha256:" + "0" * 64, self.raw)
        self.assertNotIn("cgr.dev/chainguard/nginx:latest", self.raw)

    def test_audit_documentation_defers_complete_oidc_projection_to_pr_c(self) -> None:
        runtime_documentation = (RUNTIME / "README.md").read_text()
        deployment_documentation = (ROOT / "deployment/README.md").read_text()
        for documentation in (runtime_documentation, deployment_documentation):
            self.assertIn("filesystem audit sink", documentation)
            self.assertIn("current `AuditEvent` does not persist", documentation)
            self.assertIn("PR C", documentation)
            self.assertIn("OIDC JTI", documentation)

    def test_real_compose_required_variable_contract_without_runtime_mutation(self) -> None:
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("Docker Compose is not locally available")
        argv = [docker, "compose", "--file", str(RUNTIME / "compose.yaml"), "config", "--quiet"]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        missing = subprocess.run(
            argv, cwd=ROOT, env=environment, shell=False,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
        )
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn(b"exact digest required", missing.stderr)
        environment["CANARY_IMAGE"] = TEST_IMAGE
        present = subprocess.run(
            argv, cwd=ROOT, env=environment, shell=False,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
        )
        self.assertEqual(present.returncode, 0, present.stderr.decode("utf-8", "replace"))

    def test_nginx_qualification_evidence_is_recorded(self) -> None:
        evidence = (RUNTIME / "README.md").read_text()
        self.assertIn("sha256:b91cf888522ed0cc1b6bddadfa8320ac2a131a1003b103ae340217a421f12fcc", evidence)
        self.assertIn("blocked_findings=[]", evidence)
        self.assertIn("Grype **0.118.0**", evidence)
        self.assertIn("https://token.actions.githubusercontent.com", evidence)
        self.assertIn("https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main", evidence)
        self.assertIn("Chainguard Free", evidence)
        self.assertIn("No mirroring is implemented", evidence)

    def test_application_security_and_resources(self) -> None:
        for name in ("canary-blue", "canary-green"):
            service = self.compose["services"][name]
            self.assertEqual(service["image"], TEST_IMAGE)
            self.assertEqual(service["user"], "10001:10001")
            self.assertIs(service["read_only"], True)
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
            self.assertNotIn("ports", service)
            self.assertEqual(service["networks"], ["task014_frontend"])
            self.assertEqual(service["pids_limit"], 128)
            self.assertEqual(service["cpus"], "0.50")
            self.assertEqual(service["mem_limit"], "128m")
            self.assertEqual(service["restart"], "unless-stopped")
            self.assertEqual(service["logging"]["options"], {"max-size": "10m", "max-file": "3"})
            self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777", service["tmpfs"])
            self.assertIn("/run/omnilyzer-canary:ro", service["volumes"][0])
            self.assertIn("/livez", " ".join(service["healthcheck"]["test"]))
            self.assertNotIn("/readyz", " ".join(service["healthcheck"]["test"]))

    def test_network_and_nginx_boundary(self) -> None:
        self.assertEqual(self.compose["networks"], {"task014_frontend": {"internal": True}})
        self.assertNotIn("backend", self.raw)
        nginx = self.compose["services"]["deployment-nginx"]
        self.assertEqual(nginx["image"], NGINX_IMAGE)
        self.assertEqual(nginx["user"], "65532:65532")
        self.assertIs(nginx["read_only"], True)
        self.assertEqual(nginx["cap_drop"], ["ALL"])
        self.assertEqual(nginx["ports"], ["127.0.0.1:3020:8080"])
        self.assertIn("/nginx-runtime:/etc/nginx/runtime:ro", nginx["volumes"][1])
        self.assertNotIn("docker.sock", self.raw)

    def test_no_active_nginx_is_safe_and_directory_include_is_optional(self) -> None:
        config = (RUNTIME / "nginx/nginx.conf").read_text()
        self.assertIn("return 503", config)
        self.assertIn("include /etc/nginx/runtime/*.conf", config)
        self.assertNotIn("canary-blue", config)
        self.assertNotIn("canary-green", config)

    def test_runtime_configuration_is_exact_canonical_and_secret_free(self) -> None:
        path = RUNTIME / "canary-runtime.json"
        raw = path.read_bytes()
        value = json.loads(raw)
        self.assertEqual(value, {
            "CANARY_DEPENDENCY_REQUIRED": "false",
            "CANARY_RUNTIME_CONFIG_ID": "task014-dev",
            "schema_version": 1,
        })
        self.assertEqual(raw, canonical_bytes(value))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f")
        self.assertNotRegex(raw.decode().lower(), r"token|password|secret|credential")

    def test_migration_contract_matches_released_source(self) -> None:
        definition = ROOT / "release/fixtures/task013-canary/oci/migration-definition.json"
        self.assertEqual(hashlib.sha256(definition.read_bytes()).hexdigest(), "b25e7d2d55bce3e233f58f9607e715daebc2a1a69c37603adbb569604ef76421")
        self.assertEqual(json.loads(definition.read_text())["migration_identity"], "task014-executable-canary-v1")
        self.assertNotIn("migration.py", self.raw)

    def test_ingress_file_set_is_exact(self) -> None:
        from deployment.execution import INGRESS_PATHS
        self.assertEqual(INGRESS_PATHS, (
            "deployment/runtime/dev/compose.yaml",
            "deployment/runtime/dev/host-nginx.conf",
            "deployment/runtime/dev/nginx/nginx.conf",
        ))
        for relative, expected in INGRESS_HASHES.items():
            self.assertEqual(hashlib.sha256((RUNTIME / relative).read_bytes()).hexdigest(), expected)

    def test_protected_non_live_files_remain_at_base_hashes(self) -> None:
        for relative, expected in PROTECTED.items():
            with self.subTest(relative=relative):
                raw = (ROOT / relative).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
        for stage in ("dev", "staging", "prod"):
            value = json.loads((ROOT / f"deployment/environments/{stage}.json").read_text())
            self.assertIs(value["activation"]["deployment_enabled"], False)
            self.assertEqual(value["runtime"], {
                "configuration_reference": None, "secrets_reference": None, "ingress_reference": None,
            })

    def test_non_live_boundaries(self) -> None:
        promote = (ROOT / ".github/workflows/platform-promote.yml").read_text()
        workflow = yaml.safe_load(promote)
        self.assertEqual(workflow["permissions"], {})
        self.assertEqual(len(workflow["jobs"]), 1)
        self.assertEqual(next(iter(workflow["jobs"].values()))["permissions"], {"contents": "read"})
        self.assertNotIn("id-token", promote)
        self.assertNotIn("environment:", promote)
        production = "\n".join(
            path.read_text() for path in (ROOT / "deployment").glob("*.py")
        )
        self.assertNotIn("spikes.", production)


if __name__ == "__main__":
    unittest.main()
