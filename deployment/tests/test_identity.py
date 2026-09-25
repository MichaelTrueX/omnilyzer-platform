"""Non-live tests for already-verified GitHub OIDC authorization and replay."""

from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor

from deployment.identity import (
    DEV_AUDIENCE,
    DEV_ENVIRONMENT,
    DEV_EVENT_NAME,
    DEV_ISSUER,
    DEV_REF,
    DEV_REPOSITORY,
    DEV_REPOSITORY_ID,
    DEV_REPOSITORY_OWNER_ID,
    DEV_RUNNER_ENVIRONMENT,
    DEV_WORKFLOW_REF,
    InMemoryReplayGuard,
    OIDCAuthorizationError,
    ReplayError,
    ReplayGuard,
    ReplayUnavailableError,
    authorize_verified_github_oidc,
)


NOW = 2_000_000_000
WORKFLOW_SHA = "9d29fa1a4010e6e72676580c36a94c1e97e8794b"
REQUEST_HASH = "a" * 64


def valid_claims() -> dict[str, object]:
    return {
        "iss": DEV_ISSUER,
        "aud": DEV_AUDIENCE,
        "repository": DEV_REPOSITORY,
        "repository_id": str(DEV_REPOSITORY_ID),
        "repository_owner_id": str(DEV_REPOSITORY_OWNER_ID),
        "workflow_ref": DEV_WORKFLOW_REF,
        "workflow_sha": WORKFLOW_SHA,
        "ref": DEV_REF,
        "environment": DEV_ENVIRONMENT,
        "event_name": DEV_EVENT_NAME,
        "runner_environment": DEV_RUNNER_ENVIRONMENT,
        "run_id": "34150000000",
        "run_attempt": "1",
        "actor_id": "130741173",
        "iat": NOW - 10,
        "nbf": NOW - 15,
        "exp": NOW + 290,
        "jti": "a95bf7cc-7c30-4c90-b85b-f001144c1c6e",
    }


class VerifiedOIDCAuthorizationTests(unittest.TestCase):
    def test_reviewed_workflow_revision_is_mandatory_and_exact(self) -> None:
        claims = valid_claims()
        self.assertEqual(authorize_verified_github_oidc(
            claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA,
        ).workflow_sha, WORKFLOW_SHA)
        with self.assertRaises(TypeError):
            authorize_verified_github_oidc(claims, received_at=NOW)
        class StringSubclass(str):
            pass
        for authority in (None, True, "", "0" * 40, WORKFLOW_SHA.upper(),
                          "a" * 39, "a" * 41, "g" * 40,
                          StringSubclass(WORKFLOW_SHA)):
            with self.subTest(authority=authority), self.assertRaises(OIDCAuthorizationError):
                authorize_verified_github_oidc(
                    claims, received_at=NOW, expected_workflow_sha=authority,
                )
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(
                claims, received_at=NOW, expected_workflow_sha="f" * 40,
            )
        altered = valid_claims()
        altered["workflow_sha"] = "f" * 40
        self.assertEqual(altered["workflow_ref"], claims["workflow_ref"])
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(
                altered, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA,
            )

    def reject(self, key: str, value: object) -> None:
        claims = valid_claims()
        claims[key] = value
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_exact_valid_dev_claim_set_passes(self) -> None:
        identity = authorize_verified_github_oidc(valid_claims(), received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)
        self.assertEqual(identity.repository_id, DEV_REPOSITORY_ID)
        self.assertEqual(identity.workflow_sha, WORKFLOW_SHA)
        self.assertEqual(identity.jti, valid_claims()["jti"])

    def test_wrong_issuer_rejected(self) -> None:
        self.reject("iss", "https://issuer.invalid")

    def test_wrong_audience_rejected(self) -> None:
        self.reject("aud", "https://oci-dev.omnilyzer.ai")

    def test_wrong_repository_rejected(self) -> None:
        self.reject("repository", "attacker/omnilyzer-platform")

    def test_wrong_repository_id_rejected(self) -> None:
        self.reject("repository_id", "1")

    def test_wrong_owner_id_rejected(self) -> None:
        self.reject("repository_owner_id", "1")

    def test_wrong_workflow_rejected(self) -> None:
        self.reject("workflow_ref", DEV_WORKFLOW_REF.replace("platform-promote", "evil"))

    def test_wrong_workflow_sha_rejected(self) -> None:
        self.reject("workflow_sha", "not-a-sha")

    def test_wrong_ref_rejected(self) -> None:
        self.reject("ref", "refs/heads/feature/attacker")

    def test_wrong_environment_rejected(self) -> None:
        self.reject("environment", "task014-prod")

    def test_wrong_event_rejected(self) -> None:
        self.reject("event_name", "pull_request")

    def test_self_hosted_runner_rejected(self) -> None:
        self.reject("runner_environment", "self-hosted")

    def test_malformed_run_id_rejected(self) -> None:
        self.reject("run_id", "run-1")

    def test_malformed_run_attempt_rejected(self) -> None:
        self.reject("run_attempt", "0")

    def test_malformed_actor_id_rejected(self) -> None:
        self.reject("actor_id", "octocat")

    def test_missing_jti_rejected(self) -> None:
        claims = valid_claims()
        del claims["jti"]
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_control_character_and_path_jti_rejected(self) -> None:
        for value in ("bad\njti", "../jti", "jti/child", "", "a" * 129):
            with self.subTest(value=value):
                self.reject("jti", value)

    def test_expired_token_rejected(self) -> None:
        claims = valid_claims()
        claims.update(iat=NOW - 50, nbf=NOW - 60, exp=NOW - 31)
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_excessive_lifetime_rejected(self) -> None:
        claims = valid_claims()
        claims["exp"] = claims["iat"] + 301  # type: ignore[operator]
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_iat_too_old_rejected(self) -> None:
        claims = valid_claims()
        claims.update(iat=NOW - 61, nbf=NOW - 70, exp=NOW + 100)
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_nbf_too_far_in_future_rejected(self) -> None:
        claims = valid_claims()
        claims["nbf"] = NOW + 31
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_thirty_second_clock_skew_boundary_is_permitted(self) -> None:
        claims = valid_claims()
        claims.update(iat=NOW + 30, nbf=NOW + 30, exp=NOW + 300)
        self.assertEqual(
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA).issued_at,
            NOW + 30,
        )
        claims.update(iat=NOW + 31, nbf=NOW + 31, exp=NOW + 301)
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_boolean_integer_values_rejected(self) -> None:
        for key in ("repository_id", "repository_owner_id", "run_id", "run_attempt", "actor_id"):
            with self.subTest(key=key):
                self.reject(key, True)
        for key in ("iat", "nbf", "exp"):
            with self.subTest(key=key):
                self.reject(key, True)
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(valid_claims(), received_at=True, expected_workflow_sha=WORKFLOW_SHA)

    def test_malformed_timestamp_ordering_rejected(self) -> None:
        for updates in (
            {"exp": NOW - 10},
            {"nbf": NOW + 291, "exp": NOW + 290},
            {"iat": -1},
            {"iat": "2000000000"},
        ):
            claims = valid_claims()
            claims.update(updates)
            with self.subTest(updates=updates), self.assertRaises(OIDCAuthorizationError):
                authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_additional_irrelevant_claims_neither_grant_nor_block_authority(self) -> None:
        claims = valid_claims()
        claims.update(actor="renamable-login", arbitrary_unreviewed_claim="ignored")
        self.assertEqual(
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA).actor_id,
            130741173,
        )
        claims["repository_id"] = "1"
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)

    def test_missing_each_authorizing_claim_rejected(self) -> None:
        for key in tuple(valid_claims()):
            claims = valid_claims()
            del claims[key]
            with self.subTest(key=key), self.assertRaises(OIDCAuthorizationError):
                authorize_verified_github_oidc(claims, received_at=NOW, expected_workflow_sha=WORKFLOW_SHA)


class ReplayContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = NOW
        self.guard = InMemoryReplayGuard(lambda: self.now)

    def consume(self, jti: str = "jti-1", expires_at: int = NOW + 100) -> None:
        self.guard.consume(
            jti, expires_at=expires_at, request_hash=REQUEST_HASH,
            run_id=34150000000, run_attempt=1,
        )

    def test_replay_guard_protocol_has_closed_consume_contract(self) -> None:
        self.assertTrue(hasattr(ReplayGuard, "consume"))

    def test_first_jti_consume_passes(self) -> None:
        self.consume()

    def test_duplicate_jti_rejected(self) -> None:
        self.consume()
        with self.assertRaises(ReplayError):
            self.consume()

    def test_different_jti_passes(self) -> None:
        self.consume("jti-1")
        self.consume("jti-2")

    def test_replay_storage_failure_fails_closed(self) -> None:
        guard = InMemoryReplayGuard(lambda: (_ for _ in ()).throw(RuntimeError("clock failed")))
        with self.assertRaises(ReplayUnavailableError):
            guard.consume(
                "jti-1", expires_at=NOW + 10, request_hash=REQUEST_HASH,
                run_id=1, run_attempt=1,
            )
        bounded = InMemoryReplayGuard(lambda: NOW, maximum_entries=1)
        bounded.consume("jti-1", expires_at=NOW + 10, request_hash=REQUEST_HASH, run_id=1, run_attempt=1)
        with self.assertRaises(ReplayUnavailableError):
            bounded.consume("jti-2", expires_at=NOW + 10, request_hash=REQUEST_HASH, run_id=1, run_attempt=1)

    def test_replay_expiry_semantics_are_deterministic(self) -> None:
        self.consume(expires_at=NOW + 10)
        self.now = NOW + 40
        with self.assertRaises(ReplayError):
            self.consume(expires_at=NOW + 100)
        self.now = NOW + 41
        self.consume(expires_at=NOW + 100)

    def test_concurrent_duplicate_consumption_has_one_winner(self) -> None:
        def attempt() -> str:
            try:
                self.consume()
                return "accepted"
            except ReplayError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda _: attempt(), range(16)))
        self.assertEqual(outcomes.count("accepted"), 1)
        self.assertEqual(outcomes.count("rejected"), 15)


if __name__ == "__main__":
    unittest.main()
