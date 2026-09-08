from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest

import yaml
from jsonschema import Draft202012Validator

from deployment.audit import AuditEvent
from deployment.controller import validate_environment
from deployment.policy import APPROVED_OCI_ORIGIN, APPROVED_OCI_REPOSITORIES
from deployment.runtime import CONTAINER_SECURITY_CONTRACT, HEALTH_CONTRACT, NETWORK_PATH
from deployment.tests.fixtures import request, state
from deployment.tests.test_audit import value as audit_value
from deployment.tests.test_execution import valid_request as executor_request_value


ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT_ROOT = ROOT / "deployment"
WORKFLOW_PATH = ROOT / ".github/workflows/platform-promote.yml"
PLATFORM_RELEASE_SHA256 = "53485cfafd1d1b8cdf0b1cb80c34bab12be12bfc07d7f7e6629a8c489be53471"
TASK008_PROTECTED = {
    ".github/workflows/task008-publish.yml": "0d6bd4a5715e6366250c427c959401e13b1f63b79786717a99b3816fd87a74b8",
    ".github/workflows/task008-consume.yml": "2712a221da0e4c4502fc2bc7dea6096cc015d8e0527a95a37f476c3fe3c7d5d1",
    ".github/workflows/task008-zot-publish.yml": "b0af8b0e017627972624d62c9e434037649200c3c56feae4495ca27469920a2d",
    ".github/workflows/task008-zot-consume.yml": "1d8618b15685f973c0af677f7557833c2e16b3b992571ea186f344532748adf9",
    "spikes/supply-chain/control/consume.trigger": "a92b0248b8baacfaf54e8d59caaca7d5e6b9a0a25ee140c81ea973b4ae25142f",
    "spikes/supply-chain/control/consumer-permissions.trigger": "c59b7e04d4f60d49b58122149dfb0ea9b4203f0716b69af28eb10f6dd8419005",
    "spikes/supply-chain/control/publish.trigger": "a92b0248b8baacfaf54e8d59caaca7d5e6b9a0a25ee140c81ea973b4ae25142f",
    "spikes/supply-chain/control/publisher-permissions.trigger": "ae9900404c8864cf4d8433eaeceafcf31cdbbbbe839d3b1883a64cbf081904ba",
    "spikes/supply-chain/control/rollback-retention.trigger": "8a14bd154b0ffe943349113d01a2bcb5251502ff92306bafe03f9c10bb252044",
    "spikes/supply-chain/control/tamper-negative.trigger": "9e54949c2b2fc014c56181d4da6d8e223766b4f5029155a18c65bed5cf5d8e4a",
    "spikes/supply-chain/control/zot-consume.trigger": "7bdacb65a7a6102e8d2068e2c98f49daf7ebd61d21ffa6c9ecf925a22d3b3027",
    "spikes/supply-chain/control/zot-publish.trigger": "bab946ff93488e2d95589a70b4fa6d5678e1ec5307b0b719424854e0c374cc1e",
}


class EnvironmentPolicyTests(unittest.TestCase):
    def test_all_stage_environments_are_valid_and_disabled(self) -> None:
        for stage in ("dev", "staging", "prod"):
            with self.subTest(stage=stage):
                value = json.loads((DEPLOYMENT_ROOT / "environments" / f"{stage}.json").read_text())
                environment = validate_environment(value)
                self.assertEqual(environment["activation"], {
                    "deployment_enabled": False,
                    "verified_at": None,
                })
                self.assertTrue(all(item is None for item in environment["runtime"].values()))

    def test_stage_order_and_production_approval_are_declarative(self) -> None:
        expected = {"dev": None, "staging": "dev", "prod": "staging"}
        for stage, prior in expected.items():
            value = json.loads((DEPLOYMENT_ROOT / "environments" / f"{stage}.json").read_text())
            self.assertEqual(value["promotion_policy"]["required_prior_stage"], prior)
            self.assertIs(
                value["promotion_policy"]["production_approval_required"], stage == "prod",
            )
            self.assertEqual(value["promotion_policy"]["source_registry_origin"], APPROVED_OCI_ORIGIN)
            self.assertEqual(
                value["promotion_policy"]["approved_repositories"],
                list(APPROVED_OCI_REPOSITORIES),
            )


class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.raw)

    def test_workflow_is_manual_with_closed_global_permissions(self) -> None:
        self.assertEqual(self.workflow["permissions"], {})
        self.assertIn("workflow_dispatch", self.raw)
        self.assertNotIn("push:", self.raw)
        self.assertNotIn("schedule:", self.raw)

    def test_only_gate_job_exists_without_oidc_or_environment(self) -> None:
        self.assertEqual(set(self.workflow["jobs"]), {"gate"})
        gate = self.workflow["jobs"]["gate"]
        self.assertEqual(gate["permissions"], {"contents": "read"})
        self.assertNotIn("id-token", gate["permissions"])
        self.assertNotIn("environment", gate)
        self.assertNotIn("continue-on-error", gate)

    def test_checkout_is_pinned_and_drops_credentials(self) -> None:
        uses = re.findall(r"uses:\s*([^\s#]+)", self.raw)
        self.assertTrue(uses)
        for value in uses:
            self.assertRegex(value, r"^[^@]+@[0-9a-f]{40}$")
        self.assertEqual(self.raw.count("persist-credentials: false"), len(uses))

    def test_phase1_workflow_has_no_live_or_oidc_authority(self) -> None:
        forbidden = (
            "id-token: write", "docker login", "docker push", "ssh ", "kubectl ",
            "environment: task014-", "secrets.", "curl ", "wget ",
        )
        lowered = self.raw.lower()
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, lowered)


class SourceBoundaryTests(unittest.TestCase):
    def test_production_code_has_no_build_or_publication_commands(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(DEPLOYMENT_ROOT.glob("*.py"))
        ).lower()
        forbidden = (
            "docker build", "docker buildx build", "npm pack", "python -m build",
            "hatch build", "docker push", "oras push", "package upload",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_production_code_does_not_import_spike_runtime(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(DEPLOYMENT_ROOT.glob("*.py"))
        )
        self.assertNotRegex(source, r"(?m)^\s*(?:from|import)\s+spikes(?:\.|\s|$)")

    def test_schemas_are_closed_draft_2020_12_documents(self) -> None:
        schemas = sorted((DEPLOYMENT_ROOT / "schemas").glob("*.schema.json"))
        self.assertEqual(len(schemas), 4)
        for path in schemas:
            with self.subTest(path=path.name):
                schema = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(set(schema["required"]), set(schema["properties"]))

    def test_reference_documents_validate_against_all_schemas(self) -> None:
        documents = {
            "promotion-request.schema.json": request().to_dict(),
            "deployment-state.schema.json": state(candidate=True).to_dict(),
            "audit-event.schema.json": AuditEvent.from_dict(audit_value()).to_dict(),
            "executor-request.schema.json": executor_request_value(),
        }
        for filename, document in documents.items():
            with self.subTest(filename=filename):
                schema = json.loads((DEPLOYMENT_ROOT / "schemas" / filename).read_text())
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(document)

    def test_state_schema_rejects_partial_identity_and_migration_state(self) -> None:
        schema = json.loads(
            (DEPLOYMENT_ROOT / "schemas/deployment-state.schema.json").read_text(),
        )
        validator = Draft202012Validator(schema)
        partial = state().to_dict()
        partial["active_digest"] = None
        inconsistent_migration = state().to_dict()
        inconsistent_migration["migration_state"]["identity"] = "unexpected"
        self.assertTrue(list(validator.iter_errors(partial)))
        self.assertTrue(list(validator.iter_errors(inconsistent_migration)))

    def test_runtime_contract_preserves_adr_health_security_and_network_model(self) -> None:
        self.assertEqual(HEALTH_CONTRACT.liveness_path, "/livez")
        self.assertTrue(HEALTH_CONTRACT.liveness_process_only)
        self.assertEqual(HEALTH_CONTRACT.readiness_path, "/readyz")
        self.assertTrue(HEALTH_CONTRACT.readiness_requires_runtime_configuration)
        self.assertTrue(HEALTH_CONTRACT.readiness_requires_database_connectivity)
        self.assertTrue(HEALTH_CONTRACT.readiness_requires_migration_state)
        self.assertTrue(CONTAINER_SECURITY_CONTRACT.non_root_uid_gid)
        self.assertTrue(CONTAINER_SECURITY_CONTRACT.read_only_root_filesystem)
        self.assertEqual(CONTAINER_SECURITY_CONTRACT.dropped_capabilities, ("ALL",))
        self.assertTrue(CONTAINER_SECURITY_CONTRACT.no_new_privileges)
        self.assertTrue(CONTAINER_SECURITY_CONTRACT.writable_tmpfs_only)
        self.assertFalse(CONTAINER_SECURITY_CONTRACT.docker_socket_mounted)
        self.assertTrue(CONTAINER_SECURITY_CONTRACT.runtime_secrets_outside_image)
        self.assertFalse(CONTAINER_SECURITY_CONTRACT.application_host_published)
        self.assertFalse(CONTAINER_SECURITY_CONTRACT.database_host_published)
        self.assertEqual(NETWORK_PATH, (
            "ingress", "nginx", "frontend_network", "application",
            "backend_network", "postgresql",
        ))

    def test_platform_release_and_task008_files_are_unchanged(self) -> None:
        expected = {".github/workflows/platform-release.yml": PLATFORM_RELEASE_SHA256}
        expected.update(TASK008_PROTECTED)
        for relative, digest in expected.items():
            with self.subTest(relative=relative):
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(actual, digest)


if __name__ == "__main__":
    unittest.main()
