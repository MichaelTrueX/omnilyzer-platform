"""File: deployment/tests/test_analytics_review_composition.py

Purpose: Protect read-only Task014 OIDC/registry/signature composition
         for original Analytics 0.15.0 and root-approved successors. Reject
         invalid identity, owner approval, signer/OCI evidence, and mutable
         collaborators before any privileged deployment exists.

Related: deployment/analytics_registry_review_composition.py,
         deployment/registry_promotion_composition.py (original unchanged),
         deployment/analytics_signed_release_consumer.py,
         deployment/registry_oidc_credentials.py,
         deployment/broker.py, deployment/oci_verifier.py,
         deployment/tests/test_broker_integration.py,
         deployment/tests/test_registry_oidc_credentials.py.

All positive signed-release results are SYNTHETIC and injected only for
unit testing the original OIDC registry identity ordering. No network,
real credentials, Docker, replay, installer, broker dispatch or production.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment.analytics_signed_release_consumer import (
    AnalyticsSignedEvidenceReview, PINNED_IMAGE, PINNED_RUN_ID,
    PINNED_VERSION,
)
from deployment.analytics_signed_source_pin import (
    AnalyticsSourceReviewReceipt, SOURCE_COMMIT, SOURCE_TREE,
)
from deployment.broker import BrokerRejectedError, BrokerUnavailableError
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.jwks import OIDCVerificationError, OIDCVerificationUnavailable
from deployment.registry_oidc_credentials import VerifiedRegistryCredentials
from deployment.analytics_registry_review_composition import (
    InertAnalyticsSignedReleaseReviewHandler,
)
from deployment.registry_promotion_composition import compose_inert_dev_promotion_handler
from deployment.tests.test_broker import Replay, Transport, Verifier
from deployment.tests.test_broker_integration import (
    FORGEJO_TOKEN, KEY, TOKEN, ZOT_TOKEN,
)
from deployment.tests.test_broker_service_config import configuration_values
from deployment.tests.test_identity import NOW, WORKFLOW_SHA
from deployment.tests.test_registry_oidc_credentials import StaticCache


def review_receipt() -> AnalyticsSignedEvidenceReview:
    """SYNTHETIC shape-only result, explicitly not proof of signed release."""
    return AnalyticsSignedEvidenceReview(
        PINNED_VERSION, PINNED_IMAGE, PINNED_RUN_ID,
        "a" * 64, "b" * 64,
        AnalyticsSourceReviewReceipt(
            SOURCE_COMMIT, SOURCE_TREE, PINNED_IMAGE.rsplit("@", 1)[-1],
            "c" * 64, "d" * 64, "e" * 64,
        ),
    )


def handler(*, verifier: object | None = None,
            blob_signatures: object | None = None,
            owner_files: tuple[Path, Path] | None = None) -> InertAnalyticsSignedReleaseReviewHandler:
    """Compose actual original OIDC registry verifier with synthetic tokens."""
    from deployment.tests.test_release_consumer import BlobSignatures

    return InertAnalyticsSignedReleaseReviewHandler(
        configuration=DevBrokerServiceConfiguration(**configuration_values(
            expected_workflow_sha=WORKFLOW_SHA,
        )),
        verifier=Verifier() if verifier is None else verifier,
        blob_signatures=BlobSignatures() if blob_signatures is None else blob_signatures,
        jwks_cache=StaticCache(KEY.public_key()),
        owner_approval_file=None if owner_files is None else owner_files[0],
        owner_signature_file=None if owner_files is None else owner_files[1],
    )


class OriginalAnalyticsReadonlyCompositionTests(unittest.TestCase):
    """Only valid original OIDC + registry credentials reach signed consumer."""

    def test_original_installed_canary_source_set_remains_strictly_unchanged(self):
        """New review files have NO installed broker or privileged authority."""
        from deployment.application_source_set import DevApplicationSourceSet

        paths = {item.repository_path for item in DevApplicationSourceSet().files}
        self.assertIn("deployment/registry_promotion_composition.py", paths)
        for new_file in (
            "deployment/analytics_execution.py",
            "deployment/analytics_broker_router.py",
            "deployment/analytics_broker_service.py",
            "deployment/analytics_broker_service_entrypoint.py",
            "deployment/analytics_executor.py",
            "deployment/analytics_executor_composition.py",
            "deployment/analytics_executor_service_bootstrap.py",
            "deployment/analytics_executor_service_config.py",
            "deployment/analytics_executor_service_entrypoint.py",
            "deployment/analytics_first_install.py",
            "deployment/analytics_unix_boundary.py",
            "deployment/analytics_private_registry.py",
            "deployment/analytics_signed_release_consumer.py",
            "deployment/analytics_registry_review_composition.py",
            "deployment/runtime/dev/analytics.compose.review.yaml",
            "release/products/analytics-source.json",
            "deployment/systemd/dev/omnilyzer-deployment-analytics-executor.socket",
            "deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service",
        ):
            with self.subTest(file=new_file):
                self.assertNotIn(new_file, paths)

    def test_original_oidc_registry_pair_reaches_only_readonly_review(self):
        """No replay consumption, executor dispatch or privileged request."""
        obj = handler()
        calls = []
        expected = review_receipt()

        def fake_review(zot, forgejo, signer, oci, *, received_at,
                        zot_factory, forgejo_factory):
            """Inspect original validated credential context, not JWT values."""
            self.assertIs(zot, forgejo)
            self.assertIs(type(zot), VerifiedRegistryCredentials)
            self.assertEqual(received_at, NOW)
            self.assertTrue(callable(signer.verify))
            self.assertEqual(oci._authority[4], "omnilyzer/analytics")
            self.assertTrue(callable(zot_factory))
            self.assertTrue(callable(forgejo_factory))
            calls.append("original-signer-review")
            return expected

        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            side_effect=fake_review,
        ) as mocked:
            observed = obj.review(
                compact_token=TOKEN, zot_token=ZOT_TOKEN,
                forgejo_token=FORGEJO_TOKEN, received_at=NOW,
            )
        self.assertEqual(observed, expected)
        self.assertFalse(observed.deployment_authorized)
        self.assertEqual(calls, ["original-signer-review"])
        mocked.assert_called_once()

    def test_reject_malformed_triple_tokens_before_any_credential_review(self):
        """Reject non-ASCII, missing, oversized or wrong-type token envelopes."""
        obj = handler()
        samples = (
            {"compact_token": ""},
            {"zot_token": ""},
            {"forgejo_token": ""},
            {"compact_token": "ü"},
            {"forgejo_token": "ü"},
            {"zot_token": True},
            {"zot_token": "a" * 20000},
            {"received_at": -1},
            {"received_at": True},
        )
        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
        ) as mocked:
            for changes in samples:
                with self.subTest(changes=changes), self.assertRaises(BrokerRejectedError):
                    obj.review(**{
                        "compact_token": TOKEN, "zot_token": ZOT_TOKEN,
                        "forgejo_token": FORGEJO_TOKEN, "received_at": NOW,
                        **changes,
                    })
        mocked.assert_not_called()

    def test_original_oidc_denial_prevents_registry_lookup(self):
        """OIDC rejection is not transformed into a deploy-ready receipt."""
        for error, expected in (
            (OIDCVerificationError("test"), BrokerRejectedError),
            (OIDCVerificationUnavailable("test"), BrokerUnavailableError),
        ):
            obj = handler(verifier=Verifier(error=error))
            with patch(
                "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            ) as mocked, self.assertRaises(expected):
                obj.review(
                    compact_token=TOKEN, zot_token=ZOT_TOKEN,
                    forgejo_token=FORGEJO_TOKEN, received_at=NOW,
                )
            mocked.assert_not_called()

    def test_registry_wrong_audience_or_token_rejected_before_signatures(self):
        """Only original bound registry JWTs for same authorized workflow."""
        obj = handler()
        for mutation in (
            {"zot_token": FORGEJO_TOKEN},
            {"forgejo_token": ZOT_TOKEN},
            {"zot_token": "not-a-valid.jwt"},
            {"forgejo_token": "not-a-valid.jwt"},
        ):
            with self.subTest(mutation=mutation), patch(
                "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            ) as mocked, self.assertRaises((BrokerRejectedError, BrokerUnavailableError)):
                obj.review(**{
                    "compact_token": TOKEN, "zot_token": ZOT_TOKEN,
                    "forgejo_token": FORGEJO_TOKEN, "received_at": NOW,
                    **mutation,
                })
                mocked.assert_not_called()

    def test_signature_failure_or_false_release_review_denied(self):
        """Even after original three JWTs, bad verifier never yields a receipt."""
        obj = handler()
        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            side_effect=ValueError("untrusted synthetic signature"),
        ), self.assertRaises(BrokerUnavailableError) as exc:
            obj.review(
                compact_token=TOKEN, zot_token=ZOT_TOKEN,
                forgejo_token=FORGEJO_TOKEN, received_at=NOW,
            )
        self.assertNotIn("untrusted synthetic signature", str(exc.exception))

        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            return_value=replace(review_receipt(), deployment_authorized=True),
        ), self.assertRaises(BrokerUnavailableError):
            obj.review(
                compact_token=TOKEN, zot_token=ZOT_TOKEN,
                forgejo_token=FORGEJO_TOKEN, received_at=NOW,
            )

    def test_verifier_capture_immutable_and_original_canary_handler_unchanged(self):
        """No later replacement of signer or registry connection method."""
        class MutableVerifier(Verifier):
            """Original broker test verifier, mutable only before capture."""

        verifier = MutableVerifier()
        obj = handler(verifier=verifier)
        verifier.verify = lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("untrusted replaced verifier")
        )
        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            return_value=review_receipt(),
        ):
            self.assertEqual(
                obj.review(
                    compact_token=TOKEN, zot_token=ZOT_TOKEN,
                    forgejo_token=FORGEJO_TOKEN, received_at=NOW,
                ).release_version,
                PINNED_VERSION,
            )
        with self.assertRaises(AttributeError):
            obj._workflow = "f" * 40

        # Original canary constructor and its closed request remain unchanged.
        from deployment.tests.test_release_consumer import BlobSignatures
        canary = compose_inert_dev_promotion_handler(
            configuration=DevBrokerServiceConfiguration(**configuration_values()),
            verifier=Verifier(), replay_guard=Replay(), transport=Transport(),
            blob_signatures=BlobSignatures(),
            jwks_cache=StaticCache(KEY.public_key()),
        )
        self.assertTrue(callable(canary.handle))


class SuccessorAnalyticsReadonlyCompositionTests(unittest.TestCase):
    """The original registry/OIDC composition can review an owner successor.

    Root-key and Sigstore/Cosign results are synthetic here. These tests
    confirm ordering and untrusted-data rejection, not live release trust.
    """

    def args(self):
        return {
            "compact_token": TOKEN, "zot_token": ZOT_TOKEN,
            "forgejo_token": FORGEJO_TOKEN, "received_at": NOW,
        }

    def synthetic_review(self):
        from deployment.tests.test_analytics_signed_release_consumer import (
            synthetic_successor, SyntheticBlobSignatureVerifier,
            SyntheticSuccessorOCISignatureVerifier, SCANNERS,
        )
        from deployment.analytics_signed_release_consumer import (
            verify_owner_selected_analytics_signed_evidence,
        )
        selected, owner, evidence, scanners, digest = synthetic_successor()
        small = {name: data for name, data in evidence.items()
                 if name not in SCANNERS}
        reviewed = verify_owner_selected_analytics_signed_evidence(
            small, scanners, SyntheticBlobSignatureVerifier(),
            SyntheticSuccessorOCISignatureVerifier(digest),
            received_at=1700000000, selected=selected, owner_approval=owner,
        )
        return selected, owner, reviewed

    def test_missing_independent_root_trust_never_reaches_registry(self):
        obj = handler()
        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
        ) as remote:
            with self.assertRaises(BrokerUnavailableError):
                obj.review_successor(**self.args())
            remote.assert_not_called()

    def test_real_oidc_and_registry_bound_to_owner_source_review(self):
        selected, owner, reviewed = self.synthetic_review()
        files = (Path("/root/approved-owner.json"), Path("/root/approved-owner.json.sig"))
        obj = handler(owner_files=files)
        with (
            patch("deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source",
                  return_value=(selected, owner)) as owner_check,
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
                  return_value=reviewed) as signatures,
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release") as original,
        ):
            result = obj.review_successor(**self.args())
            self.assertEqual(result, (reviewed, selected, owner))
            owner_check.assert_called_once_with(*files)
            signatures.assert_called_once()
            original.assert_not_called()
            call = signatures.call_args
            self.assertIs(type(call.args[0]), VerifiedRegistryCredentials)
            self.assertIs(call.args[0], call.args[1])
            self.assertEqual(call.kwargs["approval_file"], files[0])
            self.assertEqual(call.kwargs["signature_file"], files[1])
            self.assertEqual(call.kwargs["received_at"], NOW)
        self.assertFalse(result[0].deployment_authorized)

    def test_historical_review_does_not_read_successor_owner_files(self):
        """The original signed 0.15.0 path remains independent of new keys."""
        obj = handler(owner_files=(
            Path("/root/not-configured-owner.json"),
            Path("/root/not-configured-owner.sig"),
        ))
        with (
            patch("deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source") as root,
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                  return_value=review_receipt()) as original,
        ):
            observed = obj.review(**self.args())
            self.assertEqual(observed, review_receipt())
            root.assert_not_called()
            original.assert_called_once()

    def test_bad_signature_and_bad_release_cannot_get_successor_review(self):
        from dataclasses import replace
        selected, owner, reviewed = self.synthetic_review()
        files = (Path("/root/owner.json"), Path("/root/owner.sig"))
        obj = handler(owner_files=files)
        for bad in (
            (selected, replace(owner, owner_signature_verified=False)),
            (selected, replace(owner, source_commit="a" * 40)),
            ("untrusted", owner),
        ):
            with self.subTest(bad=bad), patch(
                "deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source",
                return_value=bad,
            ), patch(
                "deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
            ) as registry:
                with self.assertRaises(BrokerUnavailableError):
                    obj.review_successor(**self.args())
                registry.assert_not_called()

        for changed in (
            replace(reviewed, release_version="9.9.9"),
            replace(reviewed, image=PINNED_IMAGE),
            replace(reviewed, deployment_authorized=True),
            replace(reviewed, source=replace(
                reviewed.source, source_tree="a" * 40,
            )),
        ):
            with self.subTest(changed=changed), patch(
                "deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source",
                return_value=(selected, owner),
            ), patch(
                "deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
                return_value=changed,
            ):
                with self.assertRaises(BrokerUnavailableError):
                    obj.review_successor(**self.args())

    def test_oidc_failure_stops_before_owner_root_or_private_registry(self):
        from deployment.jwks import OIDCVerificationError
        obj = handler(
            verifier=Verifier(error=OIDCVerificationError("synthetic bad audience")),
            owner_files=(Path("/root/owner.json"), Path("/root/owner.sig")),
        )
        with (
            patch("deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source") as root,
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release") as remote,
        ):
            with self.assertRaises(BrokerRejectedError):
                obj.review_successor(**self.args())
            root.assert_not_called()
            remote.assert_not_called()


if __name__ == "__main__":
    unittest.main()
