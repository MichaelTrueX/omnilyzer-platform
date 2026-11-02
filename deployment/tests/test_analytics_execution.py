"""File: deployment/tests/test_analytics_execution.py

Purpose: Fail-closed original Task014 Analytics DEV executor request shape
         regression, without installing it, granting broker permission or
         accepting caller-supplied signature attestations as authorization.

Related: deployment/analytics_execution.py, deployment/execution.py (original
         canary-only request), deployment/identity.py,
         deployment/analytics_signed_release_consumer.py,
         deployment/products/analytics-dev.json,
         deployment/products/analytics-runtime-dev.json,
         deployment/runtime/dev/analytics.compose.review.yaml.

Sections: canonical first-install fixture, immutable release/source binding,
          exact four private secret references, root-controlled Compose hashes,
          original OIDC/replay identity binding, first-install rollback denial,
          old canary separation, malformed/adversarial JSON.

All inputs are synthetic. A parsed object is never a deployment permission.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from deployment.analytics_execution import (
    AnalyticsExecutorRequest, AnalyticsRequestError,
    ANALYTICS_COMPOSE_PATH, ANALYTICS_FIRST_PORT, ANALYTICS_NETWORK,
    ANALYTICS_REQUEST_SCHEMA, ANALYTICS_ROLLBACK_MODE,
    ANALYTICS_SECRETS_DIRECTORY, bind_analytics_request_to_identity,
    bind_analytics_request_to_verified_evidence, parse_analytics_request,
)
from deployment.analytics_signed_release_consumer import (
    PINNED_DIGEST, PINNED_IMAGE, PINNED_PLATFORM_COMMIT,
    PINNED_RUN_ID, PINNED_VERSION,
)
from deployment.analytics_signed_source_pin import SOURCE_COMMIT
from deployment.execution import (
    ExecutorRequestError, parse_canonical_request,
)
from deployment.identity import (
    DEV_REPOSITORY_ID, DEV_WORKFLOW_REF,
    authorize_verified_github_oidc,
)
from deployment.policy import (
    APPROVED_OCI_ORIGIN, APPROVED_OCI_REPOSITORIES,
    canonical_bytes,
)
from deployment.saas_product_contract import (
    REQUIRED_ANALYTICS_SECRET_NAMES, load_reviewed_profile,
)
from deployment.saas_product_runtime import load_review_profile
from deployment.tests.test_identity import NOW, WORKFLOW_SHA, valid_claims

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SHA = "f" * 40
COMPOSE_SHA = hashlib.sha256(
    (ROOT / ANALYTICS_COMPOSE_PATH).read_bytes(),
).hexdigest()
PRODUCT_SHA = load_reviewed_profile(
    ROOT / "deployment/products/analytics-dev.json",
).sha256()
RUNTIME_SHA = load_review_profile(
    ROOT / "deployment/products/analytics-runtime-dev.json",
).sha256()
EXPECTED = {
    "reviewed_installed_commit": INSTALL_SHA,
    "reviewed_compose_sha256": COMPOSE_SHA,
    "reviewed_product_profile_sha256": PRODUCT_SHA,
    "reviewed_runtime_profile_sha256": RUNTIME_SHA,
}


def fixture() -> dict[str, object]:
    """Create the minimum safe first-install request shape from test identity."""
    identity = authorize_verified_github_oidc(
        valid_claims(), received_at=NOW, expected_workflow_sha=WORKFLOW_SHA,
    )
    return {
        "schema_version": ANALYTICS_REQUEST_SCHEMA,
        "product_id": "analytics",
        "operation": "deploy",
        "stage": "dev",
        "release_version": PINNED_VERSION,
        "source_sha": PINNED_PLATFORM_COMMIT,
        "product_source_sha": SOURCE_COMMIT,
        "source_claim_sha256": "e" * 64,
        "oci_origin": APPROVED_OCI_ORIGIN,
        "oci_repository": "omnilyzer/analytics",
        "manifest_digest": PINNED_DIGEST,
        "exact_image_reference": PINNED_IMAGE,
        "release_manifest_sha256": "a" * 64,
        "provenance_sha256": "b" * 64,
        "originating_release_run_id": PINNED_RUN_ID,
        "promotion_request_sha256": "c" * 64,
        "requested_by_actor_id": identity.actor_id,
        "github_repository_id": identity.repository_id,
        "github_workflow_ref": identity.workflow_ref,
        "github_workflow_sha": identity.workflow_sha,
        "github_run_id": identity.run_id,
        "github_run_attempt": identity.run_attempt,
        "oidc_jti": identity.jti,
        "oidc_issued_at": identity.issued_at,
        "oidc_expires_at": identity.expires_at,
        "runtime_configuration_reference": {
            "kind": "reviewed-repository-product-profile-set",
            "repository_id": DEV_REPOSITORY_ID,
            "reviewed_commit": INSTALL_SHA,
            "compose_path": ANALYTICS_COMPOSE_PATH,
            "compose_sha256": COMPOSE_SHA,
            "product_profile_sha256": PRODUCT_SHA,
            "runtime_profile_sha256": RUNTIME_SHA,
        },
        "secrets_reference": {
            "kind": "private-host-files-name-only",
            "directory": ANALYTICS_SECRETS_DIRECTORY,
            "required": list(REQUIRED_ANALYTICS_SECRET_NAMES),
            "container_uid": 10001,
            "file_mode": "0600",
            "rootless_required": True,
        },
        "ingress_reference": {
            "kind": "private-no-public-ingress",
            "slot": "blue",
            "loopback_address": "127.0.0.1",
            "loopback_port": ANALYTICS_FIRST_PORT,
            "backend_network": ANALYTICS_NETWORK,
            "public_origin": None,
            "active_slot": None,
        },
        "rollback_reference": {
            "kind": ANALYTICS_ROLLBACK_MODE,
            "previous_digest": None,
            "previous_slot": None,
            "preserve_database_writes": True,
        },
    }


class AnalyticsFirstInstallRequestTests(unittest.TestCase):
    """Assert no request shape can become a general canary/PROD grant."""

    def reject(self, mutation: dict[str, object]) -> None:
        """Reject a mutated top-level request with reviewed local authorities."""
        with self.assertRaises(AnalyticsRequestError):
            AnalyticsExecutorRequest.from_dict({**fixture(), **mutation}, **EXPECTED)

    def reject_nested(self, key: str, changes: dict[str, object]) -> None:
        """Reject nested secret/ingress/runtime substitutions and extras."""
        data = fixture()
        value = dict(data[key])
        value.update(changes)
        data[key] = value
        with self.assertRaises(AnalyticsRequestError):
            AnalyticsExecutorRequest.from_dict(data, **EXPECTED)

    def test_exact_analytics_first_install_request_is_only_inert_shape(self):
        """Canonical request roundtrips without installing runtime authority."""
        value = fixture()
        request = AnalyticsExecutorRequest.from_dict(value, **EXPECTED)
        self.assertEqual(request.to_dict(), value)
        self.assertEqual(request.canonical_bytes(), canonical_bytes(value))
        self.assertEqual(request.sha256(), hashlib.sha256(canonical_bytes(value)).hexdigest())
        self.assertEqual(parse_analytics_request(canonical_bytes(value), **EXPECTED), request)
        self.assertEqual(request.secrets_reference["required"], list(REQUIRED_ANALYTICS_SECRET_NAMES))
        self.assertIsNone(request.ingress_reference["public_origin"])
        self.assertIsNone(request.rollback_reference["previous_digest"])
        with self.assertRaises(ExecutorRequestError):
            parse_canonical_request(canonical_bytes(value))
        self.assertEqual(APPROVED_OCI_REPOSITORIES, ("omnilyzer/task013-release-canary",))

    def test_source_release_and_replay_hash_substitutions_denied(self):
        """Only exact original signed 0.15.0, platform and external source."""
        for key, wrong in {
            "schema_version": 1,
            "product_id": "canary",
            "operation": "rollback",
            "stage": "prod",
            "release_version": "0.15.1",
            "source_sha": "d" * 40,
            "product_source_sha": "d" * 40,
            "oci_origin": "https://attacker.invalid",
            "oci_repository": "omnilyzer/task013-release-canary",
            "manifest_digest": "sha256:" + "d" * 64,
            "exact_image_reference": PINNED_IMAGE.replace("analytics", "other"),
            "originating_release_run_id": PINNED_RUN_ID + 1,
            "source_claim_sha256": "0" * 64,
            "release_manifest_sha256": "x" * 64,
            "provenance_sha256": "0" * 64,
            "promotion_request_sha256": "x" * 64,
            "requested_by_actor_id": -1,
            "github_repository_id": DEV_REPOSITORY_ID + 1,
            "github_workflow_ref": "attacker/promote",
            "oidc_jti": "../bad",
            "github_run_id": 0,
            "github_run_attempt": 0,
            "oidc_issued_at": False,
            "oidc_expires_at": NOW + 10000,
        }.items():
            with self.subTest(key=key):
                self.reject({key: wrong})
        self.reject({"public_origin": "https://example.invalid"})
        value = fixture()
        value.pop("manifest_digest")
        with self.assertRaises(AnalyticsRequestError):
            AnalyticsExecutorRequest.from_dict(value, **EXPECTED)

    def test_no_cookie_secret_values_or_canary_no_secrets(self):
        """Four name-only private references: no caller-selected secret bytes."""
        for changes in (
            {"required": ["DATABASE_URL"]},
            {"required": list(reversed(REQUIRED_ANALYTICS_SECRET_NAMES))},
            {"required": list(REQUIRED_ANALYTICS_SECRET_NAMES) + ["ADMIN_SECRET"]},
            {"required": []},
            {"kind": "none"},
            {"directory": "/tmp/my-secrets"},
            {"file_mode": "0644"},
            {"container_uid": 0},
            {"container_uid": 10001.0},
            {"rootless_required": False},
            {"rootless_required": 1},
            {"JWT_SECRET": "literal"},
            {"cookie": "session"},
        ):
            with self.subTest(changes=changes):
                self.reject_nested("secrets_reference", changes)
        self.reject({"secrets_reference": {
            "schema_version": 1, "kind": "none", "required": [],
            "reason": "task014-synthetic-canary-has-no-runtime-secrets",
        }})

    def test_root_controlled_profile_compose_and_network_denied(self):
        """Review digest and product runtime cannot be chosen by promotion."""
        for changes in (
            {"kind": "unknown"},
            {"repository_id": 1},
            {"repository_id": float(DEV_REPOSITORY_ID)},
            {"reviewed_commit": "c" * 40},
            {"compose_path": "deployment/runtime/dev/compose.yaml"},
            {"compose_sha256": "c" * 64},
            {"product_profile_sha256": "d" * 64},
            {"runtime_profile_sha256": "e" * 64},
        ):
            with self.subTest(changes=changes):
                self.reject_nested("runtime_configuration_reference", changes)
        for key, wrong in (
            ("reviewed_installed_commit", "d" * 40),
            ("reviewed_compose_sha256", "d" * 64),
            ("reviewed_product_profile_sha256", "e" * 64),
            ("reviewed_runtime_profile_sha256", "e" * 64),
        ):
            with self.subTest(key=key), self.assertRaises(AnalyticsRequestError):
                AnalyticsExecutorRequest.from_dict(
                    fixture(), **{**EXPECTED, key: wrong},
                )

    def test_first_slot_is_private_and_first_rollback_cannot_forge_previous(self):
        """Forbid public ingress, active green slot or invented rollback image."""
        for changes in (
            {"kind": "public"},
            {"slot": "green"},
            {"loopback_address": "0.0.0.0"},
            {"loopback_port": 3142},
            {"loopback_port": 3141.0},
            {"backend_network": "bridge"},
            {"public_origin": "https://analytics.omnilyzer.ai"},
            {"active_slot": "green"},
        ):
            with self.subTest(changes=changes):
                self.reject_nested("ingress_reference", changes)
        for changes in (
            {"kind": "restore-database"},
            {"previous_digest": PINNED_DIGEST},
            {"previous_slot": "green"},
            {"preserve_database_writes": False},
            {"preserve_database_writes": 1},
        ):
            with self.subTest(changes=changes):
                self.reject_nested("rollback_reference", changes)

    def test_original_authorized_github_oidc_identity_is_strict(self):
        """Do not trust a client-supplied actor, run, workflow or replay nonce."""
        identity = authorize_verified_github_oidc(
            valid_claims(), received_at=NOW, expected_workflow_sha=WORKFLOW_SHA,
        )
        valid = AnalyticsExecutorRequest.from_dict(fixture(), **EXPECTED)
        self.assertIsNone(bind_analytics_request_to_identity(valid, identity))
        for key, wrong in {
            "requested_by_actor_id": 1,
            "github_workflow_sha": "d" * 40,
            "github_run_id": identity.run_id + 1,
            "github_run_attempt": identity.run_attempt + 1,
            "oidc_jti": "another-valid-nonce",
            "oidc_issued_at": identity.issued_at + 1,
            "oidc_expires_at": identity.expires_at - 1,
        }.items():
            with self.subTest(key=key), self.assertRaises(AnalyticsRequestError):
                request = AnalyticsExecutorRequest.from_dict(
                    {**fixture(), key: wrong}, **EXPECTED,
                )
                bind_analytics_request_to_identity(request, identity)

    def test_signed_evidence_hashes_must_match_before_future_broker_dispatch(self):
        """Reject synthetic signed-review hash substitutions, not grant deploy."""
        from dataclasses import replace
        from deployment.analytics_signed_release_consumer import (
            AnalyticsSignedEvidenceReview,
        )
        from deployment.analytics_signed_source_pin import (
            AnalyticsSourceReviewReceipt, SOURCE_TREE,
        )
        source = AnalyticsSourceReviewReceipt(
            source_commit=SOURCE_COMMIT,
            source_tree=SOURCE_TREE,
            oci_manifest_digest=PINNED_DIGEST,
            claim_sha256="e" * 64,
            product_profile_sha256=PRODUCT_SHA,
            runtime_profile_sha256=RUNTIME_SHA,
        )
        review = AnalyticsSignedEvidenceReview(
            release_version=PINNED_VERSION,
            image=PINNED_IMAGE,
            release_run_id=PINNED_RUN_ID,
            manifest_sha256="a" * 64,
            provenance_sha256="b" * 64,
            source=source,
        )
        req = AnalyticsExecutorRequest.from_dict(fixture(), **EXPECTED)
        self.assertIsNone(bind_analytics_request_to_verified_evidence(req, review))
        for mutation in (
            {"release_version": "0.15.1"},
            {"image": PINNED_IMAGE.replace("analytics", "other")},
            {"manifest_sha256": "c" * 64},
            {"provenance_sha256": "c" * 64},
            {"release_run_id": PINNED_RUN_ID + 1},
            {"deployment_authorized": True},
            {"source": replace(source, claim_sha256="c" * 64)},
            {"source": replace(source, runtime_profile_sha256="c" * 64)},
            {"source": replace(source, product_profile_sha256="c" * 64)},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(AnalyticsRequestError):
                bind_analytics_request_to_verified_evidence(req, replace(review, **mutation))

    def test_canonical_rejects_duplicate_json_ambiguous_fields_and_oversize(self):
        """No last-wins JSON, pretty text, non-ASCII, excess or appended bytes."""
        raw = canonical_bytes(fixture())
        self.assertEqual(parse_analytics_request(raw, **EXPECTED).release_version, PINNED_VERSION)
        for broken in (
            raw + b"\n",
            json.dumps(fixture(), indent=2).encode("ascii"),
            raw.replace(b'"product_id":"analytics"', b'"product_id":"analytics","product_id":"canary"'),
            raw.replace(b'"container_uid":10001', b'"container_uid":10001,"container_uid":0'),
            raw.replace(b'"secret', b'"s\xc3\xa9cret', 1),
            b"x" * 16385,
            b"{}\n",
        ):
            with self.subTest(size=len(broken)), self.assertRaises(AnalyticsRequestError):
                parse_analytics_request(broken, **EXPECTED)

    def test_caller_mutation_after_validation_cannot_change_original_input(self):
        """Request graph must be copied, not retain original dictionary/list."""
        data = fixture()
        request = AnalyticsExecutorRequest.from_dict(data, **EXPECTED)
        secrets = dict(data["secrets_reference"])
        secrets["required"].clear()
        data["secrets_reference"] = secrets
        self.assertEqual(
            request.secrets_reference["required"],
            list(REQUIRED_ANALYTICS_SECRET_NAMES),
        )
        self.assertEqual(parse_analytics_request(request.canonical_bytes(), **EXPECTED), request)


if __name__ == "__main__":
    unittest.main()
