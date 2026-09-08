"""Closed executor request, privilege boundary, and non-live regression tests."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
from pathlib import Path
import unittest

from deployment.execution import (
    ALLOWED_OPERATIONS,
    DEV_LOOPBACK_ADDRESS,
    DEV_LOOPBACK_PORT,
    DEV_PUBLIC_ORIGIN,
    DEV_OCI_REPOSITORY,
    DeploymentBroker,
    ExecutorRequest,
    ExecutorRequestError,
    ExecutorTransport,
    INGRESS_PATHS,
    NO_SECRETS_REASON,
    PrivilegedExecutor,
    RUNTIME_CONFIGURATION_PATH,
    bind_request_to_identity,
    parse_canonical_request,
)
from deployment.identity import (
    DEV_REPOSITORY_ID,
    DEV_WORKFLOW_REF,
    authorize_verified_github_oidc,
)
from deployment.tests.test_identity import NOW, WORKFLOW_SHA, valid_claims


ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "6" * 64
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
REVIEWED_COMMIT = "1" * 40


def runtime_reference() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "repository-blob-sha256",
        "repository_id": DEV_REPOSITORY_ID,
        "reviewed_commit": REVIEWED_COMMIT,
        "path": RUNTIME_CONFIGURATION_PATH,
        "sha256": SHA_A,
    }


def secrets_reference() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "none",
        "required": [],
        "reason": NO_SECRETS_REASON,
    }


def ingress_reference() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "repository-file-set-sha256",
        "repository_id": DEV_REPOSITORY_ID,
        "reviewed_commit": REVIEWED_COMMIT,
        "files": [
            {"path": path, "sha256": f"{index + 1:x}" * 64}
            for index, path in enumerate(INGRESS_PATHS)
        ],
        "loopback_address": DEV_LOOPBACK_ADDRESS,
        "loopback_port": DEV_LOOPBACK_PORT,
        "public_origin": DEV_PUBLIC_ORIGIN,
    }


def valid_request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "operation": "deploy",
        "stage": "dev",
        "release_version": "0.14.2",
        "source_sha": WORKFLOW_SHA,
        "oci_origin": "https://oci-dev.omnilyzer.ai",
        "oci_repository": DEV_OCI_REPOSITORY,
        "manifest_digest": DIGEST,
        "exact_image_reference": f"oci-dev.omnilyzer.ai/{DEV_OCI_REPOSITORY}@{DIGEST}",
        "release_manifest_sha256": SHA_A,
        "provenance_sha256": SHA_B,
        "originating_release_run_id": 34139853319,
        "promotion_request_sha256": SHA_C,
        "requested_by_actor_id": 130741173,
        "github_repository_id": DEV_REPOSITORY_ID,
        "github_workflow_ref": DEV_WORKFLOW_REF,
        "github_workflow_sha": WORKFLOW_SHA,
        "github_run_id": 34150000000,
        "github_run_attempt": 1,
        "oidc_jti": "a95bf7cc-7c30-4c90-b85b-f001144c1c6e",
        "oidc_issued_at": NOW - 10,
        "oidc_expires_at": NOW + 290,
        "runtime_configuration_reference": runtime_reference(),
        "secrets_reference": secrets_reference(),
        "ingress_reference": ingress_reference(),
    }


class ExecutorRequestTests(unittest.TestCase):
    def reject(self, key: str, value: object) -> None:
        request = valid_request()
        request[key] = value
        with self.assertRaises(ExecutorRequestError):
            ExecutorRequest.from_dict(request)

    def test_valid_canonical_request_passes(self) -> None:
        request = ExecutorRequest.from_dict(valid_request())
        self.assertEqual(request.operation, "deploy")
        self.assertEqual(request.exact_image_reference, valid_request()["exact_image_reference"])
        self.assertEqual(parse_canonical_request(request.canonical_bytes()), request)

    def test_unknown_field_rejected(self) -> None:
        request = valid_request()
        request["command"] = "docker"
        with self.assertRaises(ExecutorRequestError):
            ExecutorRequest.from_dict(request)

    def test_missing_field_rejected(self) -> None:
        request = valid_request()
        del request["stage"]
        with self.assertRaises(ExecutorRequestError):
            ExecutorRequest.from_dict(request)

    def test_mutable_tag_rejected(self) -> None:
        self.reject(
            "exact_image_reference",
            "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary:0.14.2",
        )

    def test_wrong_origin_rejected(self) -> None:
        self.reject("oci_origin", "https://registry.example.invalid")

    def test_wrong_repository_rejected(self) -> None:
        self.reject("oci_repository", "omnilyzer/other")

    def test_digest_reference_mismatch_rejected(self) -> None:
        self.reject(
            "exact_image_reference",
            f"oci-dev.omnilyzer.ai/{DEV_OCI_REPOSITORY}@sha256:{'7' * 64}",
        )

    def test_wrong_stage_rejected(self) -> None:
        self.reject("stage", "staging")

    def test_unsupported_operation_rejected(self) -> None:
        for operation in ("dry-run", "rollback", "shell", "pull", "compose"):
            with self.subTest(operation=operation):
                self.reject("operation", operation)

    def test_only_deploy_operation_is_allowed(self) -> None:
        self.assertEqual(ALLOWED_OPERATIONS, ("deploy",))

    def test_malformed_promotion_request_hash_rejected(self) -> None:
        self.reject("promotion_request_sha256", "A" * 64)

    def test_malformed_evidence_hashes_rejected(self) -> None:
        for key in ("release_manifest_sha256", "provenance_sha256"):
            with self.subTest(key=key):
                self.reject(key, "bad")

    def test_wrong_github_repository_id_rejected(self) -> None:
        self.reject("github_repository_id", 1)

    def test_wrong_workflow_rejected(self) -> None:
        self.reject("github_workflow_ref", DEV_WORKFLOW_REF.replace("promote", "release"))

    def test_malformed_configuration_reference_rejected(self) -> None:
        mutations = (
            ("kind", "path"),
            ("repository_id", 1),
            ("reviewed_commit", "../main"),
            ("path", "../../canary-runtime.json"),
            ("sha256", "A" * 64),
        )
        for key, value in mutations:
            request = valid_request()
            reference = request["runtime_configuration_reference"]
            assert isinstance(reference, dict)
            reference[key] = value
            with self.subTest(key=key), self.assertRaises(ExecutorRequestError):
                ExecutorRequest.from_dict(request)

    def test_fake_or_non_none_secret_reference_rejected(self) -> None:
        for reference in (
            {"schema_version": 1, "kind": "host-file", "required": ["DB"], "reason": "needed"},
            {"schema_version": 1, "kind": "none", "required": ["FAKE"], "reason": NO_SECRETS_REASON},
            {"schema_version": 1, "kind": "none", "required": [], "reason": "placeholder"},
        ):
            with self.subTest(reference=reference):
                self.reject("secrets_reference", reference)

    def test_unsorted_ingress_files_rejected(self) -> None:
        request = valid_request()
        ingress = request["ingress_reference"]
        assert isinstance(ingress, dict) and isinstance(ingress["files"], list)
        ingress["files"].reverse()
        with self.assertRaises(ExecutorRequestError):
            ExecutorRequest.from_dict(request)

    def test_duplicate_ingress_files_rejected(self) -> None:
        request = valid_request()
        ingress = request["ingress_reference"]
        assert isinstance(ingress, dict) and isinstance(ingress["files"], list)
        ingress["files"][1] = copy.deepcopy(ingress["files"][0])
        with self.assertRaises(ExecutorRequestError):
            ExecutorRequest.from_dict(request)

    def test_ingress_file_allowlist_rejects_arbitrary_path(self) -> None:
        request = valid_request()
        ingress = request["ingress_reference"]
        assert isinstance(ingress, dict) and isinstance(ingress["files"], list)
        ingress["files"][0]["path"] = "/etc/shadow"
        with self.assertRaises(ExecutorRequestError):
            ExecutorRequest.from_dict(request)

    def test_invalid_loopback_address_and_port_rejected(self) -> None:
        for key, value in (
            ("loopback_address", "0.0.0.0"),
            ("loopback_address", "127.0.0.2"),
            ("loopback_address", "not-an-address"),
            ("loopback_port", 3021),
            ("loopback_port", True),
        ):
            request = valid_request()
            ingress = request["ingress_reference"]
            assert isinstance(ingress, dict)
            ingress[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ExecutorRequestError):
                ExecutorRequest.from_dict(request)

    def test_canonical_serialization_is_deterministic_ascii_and_newline_terminated(self) -> None:
        first = ExecutorRequest.from_dict(valid_request()).canonical_bytes()
        reordered = dict(reversed(tuple(valid_request().items())))
        second = ExecutorRequest.from_dict(reordered).canonical_bytes()
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertEqual(first.decode("ascii"), first.decode("utf-8"))
        self.assertNotIn(b" ", first)

    def test_request_sha_is_deterministic_and_hashes_canonical_bytes(self) -> None:
        request = ExecutorRequest.from_dict(valid_request())
        expected = hashlib.sha256(request.canonical_bytes()).hexdigest()
        self.assertEqual(request.sha256(), expected)
        self.assertEqual(request.sha256(), ExecutorRequest.from_dict(valid_request()).sha256())

    def test_executor_revalidation_catches_broker_side_mutation(self) -> None:
        canonical = ExecutorRequest.from_dict(valid_request()).canonical_bytes()
        value = json.loads(canonical)
        value["oci_repository"] = "attacker/image"
        with self.assertRaises(ExecutorRequestError):
            ExecutorRequest.from_dict(value)

    def test_executor_parser_rejects_noncanonical_or_duplicate_json(self) -> None:
        canonical = ExecutorRequest.from_dict(valid_request()).canonical_bytes()
        with self.assertRaises(ExecutorRequestError):
            parse_canonical_request(b" " + canonical)
        duplicate = canonical.replace(b'{"exact_image_reference"', b'{"stage":"dev","exact_image_reference"', 1)
        with self.assertRaises(ExecutorRequestError):
            parse_canonical_request(duplicate)

    def test_request_must_bind_authorized_oidc_identity(self) -> None:
        identity = authorize_verified_github_oidc(valid_claims(), received_at=NOW)
        request = ExecutorRequest.from_dict(valid_request())
        bind_request_to_identity(request, identity)
        changed = valid_request()
        changed["github_run_attempt"] = 2
        with self.assertRaises(ExecutorRequestError):
            bind_request_to_identity(ExecutorRequest.from_dict(changed), identity)

    def test_boolean_integer_fields_rejected(self) -> None:
        for key in (
            "originating_release_run_id", "requested_by_actor_id", "github_repository_id",
            "github_run_id", "github_run_attempt", "oidc_issued_at", "oidc_expires_at",
        ):
            with self.subTest(key=key):
                self.reject(key, True)

    def test_nested_unknown_fields_rejected(self) -> None:
        for name in ("runtime_configuration_reference", "secrets_reference", "ingress_reference"):
            request = valid_request()
            reference = request[name]
            assert isinstance(reference, dict)
            reference["unknown"] = "value"
            with self.subTest(name=name), self.assertRaises(ExecutorRequestError):
                ExecutorRequest.from_dict(request)


class PrivilegeBoundaryTests(unittest.TestCase):
    def test_executor_request_schema_is_closed_and_complete(self) -> None:
        schema = json.loads(
            (ROOT / "deployment/schemas/executor-request.schema.json").read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertEqual(schema["properties"]["operation"], {"const": "deploy"})
        for name in ("runtime_reference", "no_secrets_reference", "ingress_reference"):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])

    def test_broker_interface_separates_verified_claims_replay_and_transport(self) -> None:
        parameters = inspect.signature(DeploymentBroker.authorize_and_forward).parameters
        self.assertIn("cryptographically_verified_claims", parameters)
        self.assertIn("replay_guard", parameters)
        self.assertIn("transport", parameters)

    def test_executor_interface_accepts_only_canonical_bytes(self) -> None:
        parameters = inspect.signature(PrivilegedExecutor.execute).parameters
        self.assertEqual(tuple(parameters), ("self", "canonical_request"))

    def test_transport_interface_has_no_command_or_path_api(self) -> None:
        parameters = inspect.signature(ExecutorTransport.send).parameters
        self.assertEqual(tuple(parameters), ("self", "canonical_request"))

    def test_contract_modules_have_no_network_crypto_process_or_docker_dependency(self) -> None:
        prohibited = {
            "aiohttp", "cryptography", "django", "docker", "fastapi", "flask",
            "http", "jwt", "requests", "socket", "subprocess",
        }
        for relative in ("deployment/identity.py", "deployment/execution.py"):
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".")[0])
            with self.subTest(relative=relative):
                self.assertFalse(imports & prohibited, imports & prohibited)

    def test_production_contracts_do_not_import_spikes(self) -> None:
        for relative in ("deployment/identity.py", "deployment/execution.py"):
            self.assertNotIn("spikes", (ROOT / relative).read_text(encoding="utf-8"))


class NonLiveRegressionTests(unittest.TestCase):
    PROTECTED_HASHES = {
        ".github/workflows/platform-promote.yml": "3846ae1e48c945dacb563da8967e588b3fbb6fffa2580276f816496396b3c134",
        "deployment/environments/dev.json": "4b1cf03bdcd1fa7d8fd848862137a4dca7dc834b1cc45fa1d7cffd2756722ae8",
        "deployment/environments/staging.json": "7fde448d38022e4e435218c1fe6049c629ee091031845fce93156dcc787a7358",
        "deployment/environments/prod.json": "a08cd3d718ffa0531071ed7ad0aeafc19b4edeb0a82e74bd87a6044bbabebcce",
        "release/vulnerability-policy.json": "475ad38ef4ae8d89dcf7d4e03eeb76701085fdcd4ebdb8ae9aa41a7bce2cde8f",
        ".github/workflows/platform-release.yml": "53485cfafd1d1b8cdf0b1cb80c34bab12be12bfc07d7f7e6629a8c489be53471",
    }

    def test_protected_live_files_are_byte_identical(self) -> None:
        for relative, expected in self.PROTECTED_HASHES.items():
            observed = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            with self.subTest(relative=relative):
                self.assertEqual(observed, expected)

    def test_platform_promote_remains_phase1_validation_only(self) -> None:
        raw = (ROOT / ".github/workflows/platform-promote.yml").read_text(encoding="utf-8")
        self.assertIn("Phase 1 validates immutable promotion requests only", raw)
        self.assertEqual(raw.count("  gate:\n"), 1)
        self.assertNotIn("id-token: write", raw)
        self.assertNotIn("environment:", raw)
        self.assertNotIn("docker ", raw.lower())

    def test_all_environments_remain_disabled_with_null_runtime_references(self) -> None:
        for stage in ("dev", "staging", "prod"):
            value = json.loads((ROOT / f"deployment/environments/{stage}.json").read_text())
            with self.subTest(stage=stage):
                self.assertEqual(value["activation"], {"deployment_enabled": False, "verified_at": None})
                self.assertEqual(
                    value["runtime"],
                    {"configuration_reference": None, "secrets_reference": None, "ingress_reference": None},
                )

    def test_no_persistent_credential_material_in_new_contract_files(self) -> None:
        markers = ("BEGIN PRIVATE KEY", "ssh-rsa ", "ghp_", "password=")
        raw = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in ("deployment/identity.py", "deployment/execution.py")
        )
        self.assertFalse(any(marker in raw for marker in markers))


if __name__ == "__main__":
    unittest.main()
