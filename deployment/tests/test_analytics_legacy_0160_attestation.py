"""Source-only fail-closed tests: exact owner-root historical0.16.0 bridge."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment.analytics_route_journal import (
    LEGACY_REQUEST, LEGACY_RUN, LEGACY_FINAL_SHA, LEGACY_IMAGE,
    LEGACY_GREEN, LEGACY_VERSION, LEGACY_SOURCE, LEGACY_PLATFORM_SOURCE,
    Legacy0160AuthorityUnavailable, verify_root_legacy_certificate,
    read_root_legacy_certificate,
)
from deployment.analytics_route_journal import AnalyticsRouteJournal
from deployment.executor import ExecutorUnavailableError
from deployment.analytics_executor import _review_root_attested_legacy_0160_restart
from deployment.policy import canonical_bytes


def legacy_intent():
    return {
        "schema_version": 1, "phase": "switched", "generation": 2,
        "request_sha256": LEGACY_REQUEST,
        "previous_slot": "blue",
        "previous_image": "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
                          + "6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1",
        "previous_container_id": "227318fc3e8f4a9e2c6b6a6a269f4a2de4052c785ac05014d77a30c93fc4fb47",
        "previous_ip": "172.20.0.3", "next_slot": "green",
        "next_image": LEGACY_IMAGE, "next_container_id": LEGACY_GREEN,
        "next_ip": "172.20.0.4",
    }


def certificate(intent=None):
    if intent is None:
        intent = legacy_intent()
    return {
        "schema_version": 1, "kind": "owner_root_attested_legacy_0160_oat",
        "original_run_id": LEGACY_RUN, "request_sha256": LEGACY_REQUEST,
        "current_journal_sha256": hashlib.sha256(canonical_bytes(intent)).hexdigest(),
        "final_release_receipt_sha256": LEGACY_FINAL_SHA,
        "oat_before_sha256": "a" * 64,
        "oat_restored_sha256": "b" * 64,
        "oat_returned_sha256": "c" * 64,
        "oat_result_sha256": "d" * 64,
        "image": LEGACY_IMAGE, "container_id": LEGACY_GREEN,
        "owner_approved_product_source": LEGACY_SOURCE,
        "owner_approved_platform_source": LEGACY_PLATFORM_SOURCE,
        "slot": "green", "generation": 2,
    }


def parse(doc, intent=None, **metadata):
    if intent is None:
        intent = legacy_intent()
    return verify_root_legacy_certificate(
        canonical_bytes(doc), intent=intent,
        file_uid=metadata.get("uid", 0),
        file_gid=metadata.get("gid", 991),
        file_mode=metadata.get("mode", 0o440),
        file_nlink=metadata.get("links", 1),
    )


class LegacyRootCertificateTests(unittest.TestCase):
    def test_exact_positive_root_pinned_historical_ownership(self):
        original = legacy_intent()
        self.assertEqual(parse(certificate(original)), certificate(original))

    def test_mode_owner_link_and_wrong_journal_hard_hold(self):
        base = certificate()
        for metadata in ({"uid":991}, {"gid":992}, {"mode":0o600},
                         {"mode":0o640}, {"links":2}):
            with self.subTest(metadata=metadata), self.assertRaises(Legacy0160AuthorityUnavailable):
                parse(base, **metadata)
        for changed in (
            {"phase":"restored"}, {"generation":1},
            {"request_sha256":"f"*64}, {"next_image":"invalid"},
            {"next_slot":"blue"}, {"next_container_id":"e"*64},
        ):
            intent={**legacy_intent(),**changed}
            with self.subTest(changed=changed), self.assertRaises(Legacy0160AuthorityUnavailable):
                parse(base, intent)

    def test_forged_completion_receipt_and_duplicate_json_hard_hold(self):
        base = certificate()
        for changed in (
            {"original_run_id":44890393889},
            {"final_release_receipt_sha256":"e"*64},
            {"owner_approved_product_source":"f"*40},
            {"owner_approved_platform_source":"f"*40},
            {"oat_returned_sha256":"0"*64},
            {"oat_returned_sha256":"a"*64},
            {"request_sha256":"f"*64},
            {"kind":"ordinary_signed_release_finished"},
            {"image":"mutable/latest"}, {"container_id":"e"*64},
            {"generation":1}, {"schema_version":True},
            {"current_journal_sha256":"f"*64},
            {"unreviewed_go":True},
        ):
            with self.subTest(changed=changed), self.assertRaises(Legacy0160AuthorityUnavailable):
                parse({**base, **changed})
        payload=canonical_bytes(base).replace(
            b'"kind":', b'"kind":"wrong", "kind":', 1)
        with self.assertRaises(Legacy0160AuthorityUnavailable):
            verify_root_legacy_certificate(
                payload, intent=legacy_intent(),
                file_uid=0,file_gid=991,file_mode=0o440,file_nlink=1)

    def test_connected_uid1005_cannot_claim_root_certificate(self):
        journal=AnalyticsRouteJournal(
            "/var/lib/omnilyzer/deployment/analytics-route",
            expected_uid=991,expected_gid=991,
        )
        with self.assertRaises(Legacy0160AuthorityUnavailable):
            read_root_legacy_certificate(journal,legacy_intent())


class LegacyRestartBindingTests(unittest.TestCase):
    def setUp(self):
        self.intent=legacy_intent()
        self.journal=AnalyticsRouteJournal(
            "/var/lib/omnilyzer/deployment/analytics-route",
            expected_uid=991,expected_gid=991,
        )
        self.identities={
            "expected_replay_directory_uid":0,
            "expected_replay_directory_gid":992,
            "expected_broker_uid":990,"expected_executor_uid":991,
        }

    def review(self, *, state=None, image=None, attested=True, root_claims=None):
        seen=SimpleNamespace(
            active_slot="green",
            active_image=LEGACY_IMAGE if image is None else image,
            active_container_id=LEGACY_GREEN,
        )
        with (
            patch("deployment.analytics_executor.os.getuid",return_value=991),
            patch("deployment.analytics_executor.os.geteuid",return_value=991),
            patch("deployment.analytics_executor.os.getgid",return_value=991),
            patch("deployment.analytics_executor.os.getegid",return_value=991),
            patch("deployment.analytics_executor._read_analytics_execution_status",return_value=state),
            patch("deployment.analytics_route_journal.read_root_legacy_certificate",
                  return_value=(
                      {**certificate(self.intent), **(root_claims or {})}
                      if attested else None
                  )),
            patch("deployment.analytics_active_state_review.inspect_committed_analytics_route",
                  return_value=seen),
            patch.object(AnalyticsRouteJournal,"read",return_value=self.intent),
        ):
            return _review_root_attested_legacy_0160_restart(
                journal=self.journal,intent=self.intent,identities=self.identities,
            )

    def test_no_old_jti_row_but_root_signed_release_attestation_permits_readonly(self):
        self.assertIsNone(self.review(state=None))

    def test_inflight_replay_changed_historical_source_or_image_always_hold(self):
        for state in ("consumed","executing"):
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.review(state=state)
        for changed in (
            {"owner_approved_product_source":"f"*40},
            {"owner_approved_platform_source":"f"*40},
            {"final_release_receipt_sha256":"f"*64},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.review(root_claims=changed)
        with self.assertRaises(ValueError):
            self.review(image="wrong")

    def test_no_root_attestation_does_not_silently_adopt_signed_active_image(self):
        # A missing/invalid root certificate must not be substituted by a
        # healthy Docker route or valid owner signature.
        with self.assertRaises(ValueError):
            self.review(attested=False)

if __name__=="__main__":
    unittest.main()
