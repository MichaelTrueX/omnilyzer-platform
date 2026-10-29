# File: release/tests/test_analytics_source_admission.py
# Purpose: Verify pinned PR36 source admission, security denials, and explicit
#          refusal to reinterpret untrusted Analytics as Task 014 canary release.
# Links: release/analytics_source_admission.py;
#        release/products/analytics-source.json; deployment/policy.py.
import copy
import json
import os
from pathlib import Path
import unittest

from deployment.policy import DeploymentPolicyError, validate_repository
from release.analytics_source_admission import (
    AnalyticsAdmissionError, BINDING, verify_source, _safe_path
)

class AnalyticsSourceAdmissionTests(unittest.TestCase):
    """Security regression on the existing release boundary, not a mock signer."""

    @classmethod
    def setUpClass(cls):
        """Load the checked-in exact source authority and optional DEV checkout."""
        cls.binding = json.loads(BINDING.read_text(encoding='utf-8'))
        env = os.environ.get('OMNILYZER_ANALYTICS_CHECKOUT')
        cls.checkout = Path(env) if env else None

    def test_review_only_source_authority(self):
        """Source admission must never issue a signed release or deployment."""
        self.assertEqual(self.binding['authorization'],
                         'review-only-not-a-signed-release')
        self.assertEqual(self.binding['runtime']['auth'],
                         'json-bearer-localstorage')
        self.assertEqual(self.binding['runtime']['http_ready_path'], '/readyz')

    def test_task014_still_rejects_unreleased_analytics_image(self):
        """Preserve existing canary-only promotion policy as a required gate."""
        with self.assertRaises(DeploymentPolicyError):
            validate_repository('omnilyzer/analytics')

    def test_reject_source_path_traversal_and_absolute_paths(self):
        """Ensure Git object lookups cannot inspect unrelated host paths."""
        for value in ('../etc/passwd', '/etc/passwd', './prisma/schema.prisma',
                      'x//y', 'x/../y', 'x\\y', ''):
            with self.subTest(value=value), self.assertRaises(AnalyticsAdmissionError):
                _safe_path(value)

    def test_source_is_exact_verified_pr36(self):
        """On DEV, check all pinned committed blobs, including M05 exact sources."""
        if self.checkout is None:
            self.skipTest('requires explicit separately checked out Analytics PR36')
        receipt = verify_source(self.checkout, self.binding)
        self.assertEqual(receipt['source_commit'], self.binding['source_commit'])
        self.assertEqual(receipt['source_files_verified'], 51)
        self.assertFalse(receipt['release_authorized'])
        self.assertFalse(receipt['deployment_authorized'])

    def test_reject_wrong_commit(self):
        """A mutable branch or guessed source is not software provenance."""
        if self.checkout is None:
            self.skipTest('requires explicit Analytics source checkout')
        bad = copy.deepcopy(self.binding)
        bad['source_commit'] = '0' * 40
        with self.assertRaises(AnalyticsAdmissionError):
            verify_source(self.checkout,bad)

    def test_reject_changed_manifest_hash(self):
        """A valid-looking but unreviewed manifest is rejected before source admission."""
        if self.checkout is None:
            self.skipTest('requires explicit Analytics source checkout')
        bad = copy.deepcopy(self.binding)
        bad['source_manifest_sha256'] = 'f' * 64
        with self.assertRaisesRegex(AnalyticsAdmissionError,'manifest hash'):
            verify_source(self.checkout,bad)

    def test_reject_changed_auth_code_hash(self):
        """Token and session code cannot drift without a new reviewed binding."""
        if self.checkout is None:
            self.skipTest('requires explicit Analytics source checkout')
        bad = copy.deepcopy(self.binding)
        bad['source_critical_files']['lib/server-api-auth.ts'] = 'a' * 64
        with self.assertRaisesRegex(AnalyticsAdmissionError,'critical source hash'):
            verify_source(self.checkout,bad)

    def test_reject_changed_oci_build_recipe(self):
        """OCI package contents cannot be revised behind a pinned signed source."""
        if self.checkout is None:
            self.skipTest('requires explicit Analytics OCI source checkout')
        bad = copy.deepcopy(self.binding)
        bad['source_critical_files']['Dockerfile.analytics'] = 'b' * 64
        with self.assertRaisesRegex(AnalyticsAdmissionError,'critical source hash'):
            verify_source(self.checkout,bad)

    def test_reject_missing_oci_build_recipe(self):
        """Both runtime Docker build and ignore policy are required."""
        if self.checkout is None:
            self.skipTest('requires explicit Analytics OCI source checkout')
        bad = copy.deepcopy(self.binding)
        del bad['source_critical_files']['.dockerignore']
        with self.assertRaises(AnalyticsAdmissionError):
            verify_source(self.checkout,bad)

    def test_reject_marketing_root_as_operational_readiness(self):
        """Task014 readiness must use dual-DB /readyz, never public root /."""
        bad = copy.deepcopy(self.binding)
        bad["runtime"]["http_ready_path"] = "/"
        with self.assertRaisesRegex(AnalyticsAdmissionError, "runtime contract"):
            verify_source(self.checkout or Path.cwd(), bad)

    def test_reject_cookie_or_keycloak_contract(self):
        """Refuse silent token-transport, session or infrastructure migration."""
        for value in ('http-only-cookie', 'keycloak-bff', 'redis-sessions'):
            with self.subTest(value=value):
                bad=copy.deepcopy(self.binding)
                bad['runtime']['auth']=value
                with self.assertRaises(AnalyticsAdmissionError):
                    verify_source(self.checkout or Path.cwd(),bad)

    def test_reject_unknown_authorization_and_extra_fields(self):
        """The review-only envelope may not be repurposed as an OIDC token."""
        bad=copy.deepcopy(self.binding)
        bad['authorization']='production-approved'
        with self.assertRaises(AnalyticsAdmissionError):
            verify_source(self.checkout or Path.cwd(),bad)
        bad=copy.deepcopy(self.binding)
        bad['oidc_jwt']='synthetic'
        with self.assertRaises(AnalyticsAdmissionError):
            verify_source(self.checkout or Path.cwd(),bad)

if __name__ == '__main__':
    unittest.main()
