"""Closed execution-identity projection and audit binding tests."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from deployment.audit import (
    AUDIT_EXECUTION_IDENTITY_SCHEMA_VERSION,
    AUDIT_SCHEMA_VERSION,
    EXECUTION_IDENTITY_FIELDS,
    AuditEvent,
    AuditExecutionIdentity,
    ChainedAuditRecord,
    FilesystemAuditSink,
    MAX_EVENT_BYTES,
)
from deployment.execution import ExecutorRequest, MAX_IDENTIFIER
from deployment.identity import DEV_REPOSITORY_ID, DEV_WORKFLOW_REF
from deployment.policy import DeploymentPolicyError, canonical_bytes
from deployment.tests.fixtures import (
    DIGEST,
    PROMOTION_REQUEST_SHA256,
    SOURCE_SHA,
    VERSION,
    WORKFLOW_SHA,
    executor_request,
    executor_request_value,
    execution_identity,
)
from deployment.tests.test_audit import value as audit_value


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "deployment/schemas/audit-event.schema.json"


def projected() -> AuditExecutionIdentity:
    return AuditExecutionIdentity.from_executor_request(executor_request())


def valid_event() -> AuditEvent:
    return AuditEvent.from_dict(audit_value())


def request_with(**changes: object) -> ExecutorRequest:
    raw = executor_request_value()
    raw.update(changes)
    if "manifest_digest" in changes:
        raw["exact_image_reference"] = (
            f"oci-dev.omnilyzer.ai/{raw['oci_repository']}@{raw['manifest_digest']}"
        )
    return ExecutorRequest.from_dict(raw)


class AuditExecutionIdentityProjectionTests(unittest.TestCase):
    def test_projection_contains_exact_closed_fields(self) -> None:
        identity = projected()
        self.assertEqual(set(identity.to_dict()), EXECUTION_IDENTITY_FIELDS)
        self.assertEqual(identity.schema_version, AUDIT_EXECUTION_IDENTITY_SCHEMA_VERSION)

    def test_projection_copies_every_execution_field(self) -> None:
        request = executor_request()
        identity = AuditExecutionIdentity.from_executor_request(request)
        expected = {
            "requested_by_actor_id": request.requested_by_actor_id,
            "github_repository_id": request.github_repository_id,
            "github_workflow_ref": request.github_workflow_ref,
            "github_workflow_sha": request.github_workflow_sha,
            "github_run_id": request.github_run_id,
            "github_run_attempt": request.github_run_attempt,
            "oidc_jti": request.oidc_jti,
            "oidc_issued_at": request.oidc_issued_at,
            "oidc_expires_at": request.oidc_expires_at,
            "promotion_request_sha256": request.promotion_request_sha256,
        }
        for field, expected_value in expected.items():
            self.assertEqual(getattr(identity, field), expected_value, field)

    def test_executor_request_hash_is_derived_exactly(self) -> None:
        request = executor_request()
        identity = AuditExecutionIdentity.from_executor_request(request)
        self.assertEqual(identity.executor_request_sha256, request.sha256())
        self.assertEqual(
            identity.executor_request_sha256,
            hashlib.sha256(request.canonical_bytes()).hexdigest(),
        )

    def test_promotion_request_hash_is_preserved(self) -> None:
        self.assertEqual(projected().promotion_request_sha256, PROMOTION_REQUEST_SHA256)

    def test_projection_rejects_non_executor_request(self) -> None:
        for candidate in (None, {}, executor_request_value(), object()):
            with self.subTest(candidate=type(candidate).__name__):
                with self.assertRaises(DeploymentPolicyError):
                    AuditExecutionIdentity.from_executor_request(candidate)  # type: ignore[arg-type]

    def test_projection_revalidates_directly_constructed_request(self) -> None:
        forged = replace(executor_request(), requested_by_actor_id=True)
        with self.assertRaises(DeploymentPolicyError):
            AuditExecutionIdentity.from_executor_request(forged)

    def test_projection_rejects_mutated_nested_request(self) -> None:
        forged = replace(
            executor_request(),
            runtime_configuration_reference=replace(
                executor_request().runtime_configuration_reference,
                sha256="A" * 64,
            ),
        )
        with self.assertRaises(DeploymentPolicyError):
            AuditExecutionIdentity.from_executor_request(forged)

    def test_projection_ignores_shadowed_request_serialization_methods(self) -> None:
        request = replace(executor_request(), requested_by_actor_id=True)
        object.__setattr__(request, "canonical_bytes", lambda: executor_request().canonical_bytes())
        object.__setattr__(request, "to_dict", lambda: executor_request().to_dict())
        with self.assertRaises(DeploymentPolicyError):
            AuditExecutionIdentity.from_executor_request(request)

    def test_projection_ignores_shadowed_nested_serialization_method(self) -> None:
        valid = executor_request()
        forged_secrets = replace(valid.secrets_reference, reason="forged")
        object.__setattr__(forged_secrets, "to_dict", lambda: valid.secrets_reference.to_dict())
        request = replace(valid, secrets_reference=forged_secrets)
        with self.assertRaises(DeploymentPolicyError):
            AuditExecutionIdentity.from_executor_request(request)

    def test_projection_has_no_override_parameters(self) -> None:
        with self.assertRaises(TypeError):
            AuditExecutionIdentity.from_executor_request(  # type: ignore[call-arg]
                executor_request(), executor_request_sha256="0" * 64,
            )

    def test_identity_is_immutable(self) -> None:
        with self.assertRaises((AttributeError, TypeError)):
            projected().github_run_id = 1  # type: ignore[misc]


class AuditExecutionIdentityValidationTests(unittest.TestCase):
    def reject(self, field: str, invalid: object) -> None:
        raw = execution_identity()
        raw[field] = invalid
        with self.assertRaises(DeploymentPolicyError):
            AuditExecutionIdentity.from_dict(raw)

    def test_valid_identity_round_trip(self) -> None:
        identity = projected()
        self.assertEqual(AuditExecutionIdentity.from_dict(identity.to_dict()), identity)

    def test_hostile_integer_subclass_is_rejected(self) -> None:
        class HostileInteger(int):
            def __le__(self, other: object) -> bool:
                return True

            def __ge__(self, other: object) -> bool:
                return True

        self.reject("github_run_id", HostileInteger(-9))

    def test_hostile_deepcopy_cannot_normalize_integer_subclass(self) -> None:
        class HostileInteger(int):
            def __deepcopy__(self, memo: object) -> int:
                return 1

        self.reject("github_run_id", HostileInteger(-9))

    def test_unknown_nested_field_rejected(self) -> None:
        raw = execution_identity()
        raw["token"] = "not-stored"
        with self.assertRaises(DeploymentPolicyError):
            AuditExecutionIdentity.from_dict(raw)

    def test_non_object_identity_rejected(self) -> None:
        for candidate in (None, [], "identity", 1):
            with self.subTest(candidate=candidate):
                with self.assertRaises(DeploymentPolicyError):
                    AuditExecutionIdentity.from_dict(candidate)

    def test_wrong_identity_schema_versions_rejected(self) -> None:
        for version in (0, 2, True, "1"):
            with self.subTest(version=version):
                self.reject("schema_version", version)

    def test_identifier_zero_negative_and_overflow_rejected(self) -> None:
        for field in (
            "requested_by_actor_id", "github_repository_id", "github_run_id",
            "github_run_attempt",
        ):
            for invalid in (0, -1, MAX_IDENTIFIER + 1):
                with self.subTest(field=field, invalid=invalid):
                    self.reject(field, invalid)

    def test_wrong_repository_id_rejected(self) -> None:
        self.reject("github_repository_id", DEV_REPOSITORY_ID + 1)

    def test_wrong_workflow_ref_rejected(self) -> None:
        self.reject("github_workflow_ref", DEV_WORKFLOW_REF + "/other")

    def test_workflow_sha_variants_rejected(self) -> None:
        for invalid in ("A" * 40, "a" * 39, "a" * 41, "g" * 40, "0" * 40):
            with self.subTest(invalid=invalid):
                self.reject("github_workflow_sha", invalid)

    def test_jti_variants_rejected(self) -> None:
        for invalid in (
            "", "a" * 129, "unsafe/value", "unsafe value", "unsafe..value",
            ".leading", "unicodé", "line\nbreak",
        ):
            with self.subTest(invalid=invalid):
                self.reject("oidc_jti", invalid)

    def test_timestamp_boundaries_rejected(self) -> None:
        for field in ("oidc_issued_at", "oidc_expires_at"):
            for invalid in (-1, MAX_IDENTIFIER + 1):
                with self.subTest(field=field, invalid=invalid):
                    self.reject(field, invalid)

    def test_expiry_must_be_after_issuance(self) -> None:
        issued = execution_identity()["oidc_issued_at"]
        for expiry in (issued, int(issued) - 1):
            with self.subTest(expiry=expiry):
                self.reject("oidc_expires_at", expiry)

    def test_token_lifetime_is_bounded(self) -> None:
        issued = int(execution_identity()["oidc_issued_at"])
        self.reject("oidc_expires_at", issued + 301)

    def test_sha256_variants_rejected(self) -> None:
        for field in ("promotion_request_sha256", "executor_request_sha256"):
            for invalid in ("A" * 64, "a" * 63, "a" * 65, "g" * 64, ""):
                with self.subTest(field=field, invalid=invalid):
                    self.reject(field, invalid)


def _add_missing_field_test(field: str) -> None:
    def test(self: unittest.TestCase) -> None:
        raw = execution_identity()
        del raw[field]
        with self.assertRaises(DeploymentPolicyError):
            AuditExecutionIdentity.from_dict(raw)
    setattr(
        AuditExecutionIdentityValidationTests,
        f"test_missing_identity_field_{field}",
        test,
    )


for _field in sorted(EXECUTION_IDENTITY_FIELDS):
    _add_missing_field_test(_field)


def _add_integer_type_test(field: str, invalid: object, label: str) -> None:
    def test(self: AuditExecutionIdentityValidationTests) -> None:
        self.reject(field, invalid)
    setattr(
        AuditExecutionIdentityValidationTests,
        f"test_{label}_rejected_for_{field}",
        test,
    )


for _integer_field in (
    "schema_version", "requested_by_actor_id", "github_repository_id",
    "github_run_id", "github_run_attempt", "oidc_issued_at", "oidc_expires_at",
):
    _add_integer_type_test(_integer_field, True, "bool")
    _add_integer_type_test(_integer_field, 1.0, "float")
    _add_integer_type_test(_integer_field, "1", "string")


class AuditEventRequestBindingTests(unittest.TestCase):
    def test_request_bound_factory_derives_artifact_and_identity(self) -> None:
        request = executor_request()
        event = AuditEvent.for_executor_request(
            request,
            event_id="request-bound",
            event_type="promotion_started",
            previous_digest=None,
            active_slot="blue",
            candidate_slot="green",
            migration_identity=None,
            result="started",
            timestamp="2026-09-09T12:00:00Z",
        )
        self.assertEqual(
            (event.stage, event.release_version, event.source_sha, event.oci_repository, event.digest),
            (request.stage, request.release_version, request.source_sha,
             request.oci_repository, request.manifest_digest),
        )
        self.assertEqual(event.execution_identity, projected())
        event.require_executor_request(request)

    def test_request_bound_factory_revalidates_forged_request(self) -> None:
        forged = replace(executor_request(), github_run_id=True)
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.for_executor_request(
                forged, event_id="forged", event_type="promotion_started",
                previous_digest=None, active_slot="blue", candidate_slot="green",
                migration_identity=None, result="started", timestamp="2026-09-09T12:00:00Z",
            )

    def test_valid_event_binds_to_exact_request(self) -> None:
        valid_event().require_executor_request(executor_request())

    def test_binding_rejects_non_request(self) -> None:
        with self.assertRaises(DeploymentPolicyError):
            valid_event().require_executor_request({})  # type: ignore[arg-type]

    def test_binding_rejects_each_artifact_mismatch(self) -> None:
        alternatives = (
            request_with(release_version="0.13.5"),
            request_with(source_sha="5" * 40),
            request_with(manifest_digest="sha256:" + "7" * 64),
        )
        for request in alternatives:
            with self.subTest(request=request):
                with self.assertRaises(DeploymentPolicyError):
                    valid_event().require_executor_request(request)

    def test_binding_rejects_other_valid_stage_event(self) -> None:
        raw = audit_value()
        raw["stage"] = "staging"
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(raw).require_executor_request(executor_request())

    def test_binding_rejects_each_variable_identity_mismatch(self) -> None:
        alternatives = (
            request_with(requested_by_actor_id=130741174),
            request_with(github_workflow_sha="5" * 40),
            request_with(github_run_id=34150000001),
            request_with(github_run_attempt=2),
            request_with(oidc_jti="another-safe-jti"),
            request_with(oidc_issued_at=1_778_000_001, oidc_expires_at=1_778_000_300),
            request_with(oidc_expires_at=1_778_000_299),
            request_with(promotion_request_sha256="d" * 64),
        )
        for request in alternatives:
            with self.subTest(request=request):
                with self.assertRaises(DeploymentPolicyError):
                    valid_event().require_executor_request(request)

    def test_binding_rejects_forged_event_dataclass(self) -> None:
        forged = replace(
            valid_event(),
            execution_identity=replace(projected(), executor_request_sha256="0" * 64),
        )
        with self.assertRaises(DeploymentPolicyError):
            forged.require_executor_request(executor_request())

    def test_binding_revalidates_every_forged_identity_component(self) -> None:
        alternatives = {
            "schema_version": 2,
            "requested_by_actor_id": 130741174,
            "github_repository_id": DEV_REPOSITORY_ID + 1,
            "github_workflow_ref": DEV_WORKFLOW_REF + "/other",
            "github_workflow_sha": "5" * 40,
            "github_run_id": 34150000001,
            "github_run_attempt": 2,
            "oidc_jti": "different-safe-jti",
            "oidc_issued_at": 1_778_000_001,
            "oidc_expires_at": 1_778_000_299,
            "promotion_request_sha256": "d" * 64,
            "executor_request_sha256": "e" * 64,
        }
        for field, replacement_value in alternatives.items():
            forged_identity = replace(projected(), **{field: replacement_value})
            forged = replace(valid_event(), execution_identity=forged_identity)
            with self.subTest(field=field):
                with self.assertRaises(DeploymentPolicyError):
                    forged.require_executor_request(executor_request())

    def test_binding_rejects_valid_looking_hostile_string_subclass(self) -> None:
        class EqualString(str):
            def __eq__(self, other: object) -> bool:
                return True

            def __hash__(self) -> int:
                return str.__hash__(self)

        forged_identity = replace(projected(), oidc_jti=EqualString("different-safe-jti"))
        forged = replace(valid_event(), execution_identity=forged_identity)
        with self.assertRaises(DeploymentPolicyError):
            forged.require_executor_request(executor_request())


class AuditSchemaAndPersistenceTests(unittest.TestCase):
    def test_audit_schema_two_is_exact(self) -> None:
        self.assertEqual(AUDIT_SCHEMA_VERSION, 2)
        self.assertEqual(valid_event().schema_version, 2)

    def test_audit_schema_one_is_rejected(self) -> None:
        raw = audit_value()
        raw["schema_version"] = 1
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(raw)

    def test_old_actor_field_is_rejected(self) -> None:
        raw = audit_value()
        raw["actor"] = "github:task014"
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(raw)

    def test_missing_execution_identity_is_rejected(self) -> None:
        raw = audit_value()
        del raw["execution_identity"]
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(raw)

    def test_canonical_serialization_is_ascii_sorted_compact_and_newline_terminated(self) -> None:
        encoded = valid_event().canonical_bytes()
        self.assertTrue(encoded.isascii())
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertNotIn(b" ", encoded)
        self.assertEqual(encoded, canonical_bytes(valid_event().to_dict()))

    def test_event_remains_within_byte_bound(self) -> None:
        self.assertLessEqual(len(valid_event().canonical_bytes()), MAX_EVENT_BYTES)

    def test_oversized_otherwise_valid_event_is_rejected(self) -> None:
        raw = audit_value()
        raw["release_version"] = "1" * MAX_EVENT_BYTES + ".1.1"
        schema = json.loads(SCHEMA_PATH.read_text())
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(raw)))
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(raw)

    def test_no_sensitive_request_material_is_persisted(self) -> None:
        encoded = valid_event().canonical_bytes().decode("ascii")
        for forbidden in (
            "compact_token", "bearer", "claims", "credential", "http_headers",
            "canonical_request_bytes", "response", "subprocess_output", "secret=",
        ):
            self.assertNotIn(forbidden, encoded.lower())
        self.assertEqual(set(json.loads(encoded)["execution_identity"]), EXECUTION_IDENTITY_FIELDS)

    def test_sink_revalidates_directly_constructed_identity(self) -> None:
        forged = replace(
            valid_event(),
            execution_identity=replace(projected(), requested_by_actor_id=True),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            with self.assertRaises(DeploymentPolicyError):
                FilesystemAuditSink(path).append(forged)
            self.assertFalse(path.exists())

    def test_sink_rejects_hostile_integer_subclass_without_persistence(self) -> None:
        class HostileInteger(int):
            def __le__(self, other: object) -> bool:
                return True

            def __ge__(self, other: object) -> bool:
                return True

        forged = replace(
            valid_event(),
            execution_identity=replace(projected(), github_run_id=HostileInteger(-9)),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            with self.assertRaises(DeploymentPolicyError):
                FilesystemAuditSink(path).append(forged)
            self.assertFalse(path.exists())

    def test_sink_rejects_hostile_string_subclasses_for_closed_fields(self) -> None:
        class HostileString(str):
            def __eq__(self, other: object) -> bool:
                return True

            def __hash__(self) -> int:
                return str.__hash__(self)

        for field in (
            "event_type", "result", "stage", "oci_repository", "active_slot",
            "candidate_slot",
        ):
            forged = replace(valid_event(), **{field: HostileString("evil")})
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "events.jsonl"
                with self.assertRaises(DeploymentPolicyError):
                    FilesystemAuditSink(path).append(forged)
                self.assertFalse(path.exists())

    def test_sink_and_binding_reject_audit_event_subclass_override(self) -> None:
        class ForgedAuditEvent(AuditEvent):
            def to_dict(self) -> dict[str, object]:
                return valid_event().to_dict()

        forged = ForgedAuditEvent(**vars(valid_event()))
        with self.assertRaises(DeploymentPolicyError):
            forged.require_executor_request(executor_request())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            with self.assertRaises(DeploymentPolicyError):
                FilesystemAuditSink(path).append(forged)
            self.assertFalse(path.exists())

    def test_sink_and_binding_ignore_shadowed_base_event_to_dict(self) -> None:
        forged = replace(valid_event(), schema_version=1)
        object.__setattr__(forged, "to_dict", lambda: valid_event().to_dict())
        with self.assertRaises(DeploymentPolicyError):
            forged.require_executor_request(executor_request())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            with self.assertRaises(DeploymentPolicyError):
                FilesystemAuditSink(path).append(forged)
            self.assertFalse(path.exists())

    def test_python_remains_authoritative_for_integral_float(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text())
        document = valid_event().to_dict()
        document["execution_identity"]["github_run_id"] = 1.0
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(document)))
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(document)

    def test_sink_revalidates_directly_constructed_artifact(self) -> None:
        forged = replace(valid_event(), digest="sha256:bad")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            with self.assertRaises(DeploymentPolicyError):
                FilesystemAuditSink(path).append(forged)
            self.assertFalse(path.exists())

    def test_sink_revalidates_schema_timestamp_and_lifecycle_fields(self) -> None:
        for changes in (
            {"schema_version": 1},
            {"timestamp": "2026-09-09T25:00:00Z"},
            {"event_type": "arbitrary"},
            {"result": "unknown"},
            {"event_type": "migration_started", "migration_identity": None},
            {"event_type": "rollback_started", "previous_digest": None},
        ):
            forged = replace(valid_event(), **changes)
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "events.jsonl"
                with self.assertRaises(DeploymentPolicyError):
                    FilesystemAuditSink(path).append(forged)
                self.assertFalse(path.exists())

    def test_sink_revalidates_secret_marker_and_event_size(self) -> None:
        forged = replace(
            valid_event(), migration_identity="token=" + "x" * MAX_EVENT_BYTES,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            with self.assertRaises(DeploymentPolicyError):
                FilesystemAuditSink(path).append(forged)
            self.assertFalse(path.exists())

    def test_old_schema_history_fails_without_rewrite(self) -> None:
        old = audit_value()
        old["schema_version"] = 1
        old.pop("execution_identity")
        old["actor"] = "github:task014"
        line = canonical_bytes({"event": old, "previous_event_sha256": None})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(line)
            before = path.read_bytes()
            with self.assertRaises(DeploymentPolicyError):
                FilesystemAuditSink(path).append(valid_event())
            self.assertEqual(path.read_bytes(), before)

    def test_malformed_historical_identity_fails_without_rewrite(self) -> None:
        raw = audit_value()
        raw["execution_identity"].pop("oidc_jti")  # type: ignore[union-attr]
        line = canonical_bytes({"event": raw, "previous_event_sha256": None})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(line)
            before = path.read_bytes()
            with self.assertRaises(DeploymentPolicyError):
                FilesystemAuditSink(path).append(valid_event())
            self.assertEqual(path.read_bytes(), before)

    def test_each_identity_change_changes_chain_hash(self) -> None:
        baseline = ChainedAuditRecord(valid_event(), None).sha256()
        for field, replacement in (
            ("schema_version", 2),
            ("requested_by_actor_id", 130741174),
            ("github_repository_id", DEV_REPOSITORY_ID + 1),
            ("github_workflow_ref", DEV_WORKFLOW_REF + "/other"),
            ("github_workflow_sha", "5" * 40),
            ("github_run_id", 34150000001),
            ("github_run_attempt", 2),
            ("oidc_jti", "different-safe-jti"),
            ("oidc_issued_at", 1_778_000_001),
            ("oidc_expires_at", 1_778_000_299),
            ("promotion_request_sha256", "d" * 64),
            ("executor_request_sha256", "e" * 64),
        ):
            changed_identity = replace(projected(), **{field: replacement})
            changed = replace(valid_event(), execution_identity=changed_identity)
            with self.subTest(field=field):
                self.assertNotEqual(ChainedAuditRecord(changed, None).sha256(), baseline)

    def test_python_and_json_schema_agree_on_closed_valid_document(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text())
        Draft202012Validator.check_schema(schema)
        document = valid_event().to_dict()
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(document)))
        self.assertEqual(AuditEvent.from_dict(document).to_dict(), document)

    def test_python_and_json_schema_reject_unknown_nested_property(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text())
        document = valid_event().to_dict()
        document["execution_identity"]["jwt"] = "forbidden"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(document)))
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(document)

    def test_python_and_json_schema_agree_on_structural_rejections(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text())
        validator = Draft202012Validator(schema)
        cases = (
            ("schema_version", 1),
            ("event_id", "event\n"),
            ("release_version", "01.2.3"),
            ("source_sha", "A" * 40),
            ("digest", "sha256:" + "A" * 64),
            ("timestamp", "2026-09-09T25:00:00Z"),
        )
        for field, invalid in cases:
            document = valid_event().to_dict()
            document[field] = invalid
            with self.subTest(field=field):
                self.assertTrue(list(validator.iter_errors(document)))
                with self.assertRaises(DeploymentPolicyError):
                    AuditEvent.from_dict(document)

    def test_production_audit_path_is_not_used(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            FilesystemAuditSink(path).append(valid_event())
            self.assertTrue(path.is_file())
            self.assertNotIn("/var/log/omnilyzer", str(path))


if __name__ == "__main__":
    unittest.main()
