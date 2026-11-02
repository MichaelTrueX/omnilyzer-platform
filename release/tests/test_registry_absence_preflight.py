# File: release/tests/test_registry_absence_preflight.py
# Purpose: Prevent a registry collision or permission-masked 404 from allowing
#          the one-time Task 013 immutable publication to begin.
# Related: release/registry_absence_preflight.py,
#          .github/workflows/platform-release.yml,
#          release/tests/test_workflow_policy.py.
# Security: Mocked offline response sequences only; never issue real requests.

"""Authenticated, fail-closed registry version absence regression tests."""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from unittest.mock import Mock, patch

from release.registry_absence_preflight import (
    FORGEJO, ZOT, NoRedirect, PreflightError, _checked_package_list,
    _status, check_absence,
)

FAKE_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature"


def missing_sequence() -> list[tuple[int, bytes]]:
    """Return exactly one successful authenticated listing and four absences."""
    return [(200, b"[]"), (404, b""), (200, b"[]"),
            (404, b""), (200, b"[]"), (404, b""), (200, b"[]"),
            (200, b""), (404, b"")]


class RegistryAbsenceTests(unittest.TestCase):
    """Prove every version check precedes publication and fails closed."""

    def test_exact_four_destinations_absent(self) -> None:
        """Authenticated PyPI/npm/generic and OCI absence is the only PASS."""
        results = missing_sequence()
        with patch("release.registry_absence_preflight._status", side_effect=results) as request:
            check_absence("0.14.5", FAKE_JWT, FAKE_JWT)
        self.assertEqual(request.call_count, 9)
        urls = [c.args[2] for c in request.call_args_list]
        self.assertEqual(urls[0], "/api/v1/packages/omnilyzer?type=pypi&limit=1")
        self.assertIn("/api/v1/packages/omnilyzer/pypi/omnilyzer-release-canary/0.14.5", urls)
        self.assertIn("/api/v1/packages/omnilyzer/npm/%40omnilyzer%2Frelease-canary/0.14.5", urls)
        self.assertIn("/api/v1/packages/omnilyzer/generic/task013-release-evidence/0.14.5", urls)
        self.assertEqual(urls[-2:], ["/v2/", "/v2/omnilyzer/task013-release-canary/manifests/0.14.5"])
        self.assertEqual(request.call_args_list[-1].kwargs["method"], "HEAD")

    def test_analytics_exact_generic_and_oci_absence(self) -> None:
        """Analytics checks ONLY its own immutable Generic evidence and OCI tag."""
        results = [(200, b"[]"), (404, b""), (200, b"[]"),
                   (200, b""), (404, b"")]
        with patch("release.registry_absence_preflight._status", side_effect=results) as request:
            check_absence("0.14.5", FAKE_JWT, FAKE_JWT, product="analytics")
        paths = [call.args[2] for call in request.call_args_list]
        self.assertEqual(paths, [
            "/api/v1/packages/omnilyzer?type=pypi&limit=1",
            "/api/v1/packages/omnilyzer/generic/analytics-release-evidence/0.14.5",
            "/api/v1/packages/omnilyzer?type=generic&limit=50&page=1",
            "/v2/", "/v2/omnilyzer/analytics/manifests/0.14.5",
        ])
        self.assertEqual(request.call_args_list[-1].kwargs["method"], "HEAD")

    def test_analytics_rejects_occupied_evidence_and_oci(self) -> None:
        """Never publish over either occupied Analytics destination."""
        for index, expected in ((1, "GENERIC_VERSION_OCCUPIED"), (4, "OCI_TAG_OCCUPIED")):
            with self.subTest(index=index):
                responses = [(200,b"[]"),(404,b""),(200,b"[]"),(200,b""),(404,b"")]
                responses[index] = (200,b"{}")
                with patch("release.registry_absence_preflight._status", side_effect=responses):
                    with self.assertRaisesRegex(PreflightError, expected):
                        check_absence("0.14.5", FAKE_JWT, FAKE_JWT, product="analytics")
        with patch("release.registry_absence_preflight._status") as request:
            with self.assertRaisesRegex(PreflightError, "UNKNOWN_PRODUCT"):
                check_absence("0.14.5", FAKE_JWT, FAKE_JWT, product="any")
            request.assert_not_called()

    def test_denied_forgejo_auth_never_probes_destinations(self) -> None:
        """A masked unauthorized response cannot be treated as absent."""
        for status in (401, 403, 404, 429, 500):
            with self.subTest(status=status):
                with patch("release.registry_absence_preflight._status", return_value=(status,b"")) as request:
                    with self.assertRaisesRegex(PreflightError,"FORGEJO_AUTH_HTTP"):
                        check_absence("0.14.5", FAKE_JWT, FAKE_JWT)
                    request.assert_called_once()

    def test_existing_exact_pypi_npm_generic_version_is_a_blocker(self) -> None:
        """Never overwrite any package version, even if only one exists."""
        for n, kind in ((1,"PYPI"),(3,"NPM"),(5,"GENERIC")):
            with self.subTest(kind=kind):
                calls=missing_sequence()
                calls[n]=(200,b"{}")
                with patch("release.registry_absence_preflight._status", side_effect=calls):
                    with self.assertRaisesRegex(PreflightError,kind+"_VERSION_OCCUPIED"):
                        check_absence("0.14.5",FAKE_JWT,FAKE_JWT)

    def test_existing_listed_version_is_blocker_even_when_exact_returns_404(self) -> None:
        """A URL-escaping ambiguity may not mask an existing npm version."""
        calls=missing_sequence()
        calls[4]=(200,json.dumps([{"type":"npm","name":"@omnilyzer/release-canary","version":"0.14.5"}]).encode())
        with patch("release.registry_absence_preflight._status",side_effect=calls):
            with self.assertRaisesRegex(PreflightError,"NPM_VERSION_OCCUPIED"):
                check_absence("0.14.5",FAKE_JWT,FAKE_JWT)

    def test_existing_oci_tag_is_blocker(self) -> None:
        """A previously published OCI tag must never be overwritten."""
        calls=missing_sequence()
        calls[-1]=(200,b"")
        with patch("release.registry_absence_preflight._status",side_effect=calls):
            with self.assertRaisesRegex(PreflightError,"OCI_TAG_OCCUPIED"):
                check_absence("0.14.5",FAKE_JWT,FAKE_JWT)

    def test_zot_authorization_failure_never_counts_as_absence(self) -> None:
        """OCI status 401/403/404 on the auth baseline stops before HEAD."""
        for status in (401,403,404):
            calls=missing_sequence()
            calls[-2]=(status,b"")
            with patch("release.registry_absence_preflight._status",side_effect=calls) as request:
                with self.assertRaisesRegex(PreflightError,"ZOT_AUTH_HTTP"):
                    check_absence("0.14.5",FAKE_JWT,FAKE_JWT)
                self.assertEqual(request.call_count,8)

    def test_invalid_version_jwt_json_are_rejected(self) -> None:
        """Bad inputs or malformed registry JSON cannot permit publication."""
        for version in ("0.14.5/../", "0.14.5\n", "0.14.4.x", "00.14.5"):
            with self.subTest(version=version),self.assertRaises(ValueError):
                check_absence(version,FAKE_JWT,FAKE_JWT)
        with self.assertRaisesRegex(PreflightError,"JWT_FORMAT"):
            check_absence("0.14.5","notjwt",FAKE_JWT)
        for payload in (b"{}",b"null",b"not-json",b'[{"name":"x"}]'):
            with self.subTest(payload=payload),self.assertRaises(PreflightError):
                _checked_package_list(payload)

    def test_redirect_denied_and_outgoing_methods_are_read_only(self) -> None:
        """Neither cross-origin redirects nor HTTP writes may execute."""
        with self.assertRaisesRegex(PreflightError,"REDIRECT_DENIED"):
            NoRedirect().redirect_request(None,None,302,"Redirect",{},"https://wrong.invalid")
        opener=Mock()
        with self.assertRaisesRegex(PreflightError,"READ_ONLY_METHOD_REQUIRED"):
            _status(opener,FORGEJO,"/api/v1/packages/omnilyzer",FAKE_JWT,method="POST")
        opener.open.assert_not_called()
        with self.assertRaisesRegex(PreflightError,"UNTRUSTED_DESTINATION"):
            _status(opener,"https://evil.invalid","/v2/",FAKE_JWT)
        opener.open.assert_not_called()

    def test_http_error_is_sanitized_and_bounded(self) -> None:
        """HTTP error body or JWT may not escape the preflight result."""
        opener=Mock()
        error=urllib.error.HTTPError(FORGEJO+"/v2/",401,"contains secret",{},io.BytesIO(FAKE_JWT.encode()))
        opener.open.side_effect=error
        status,body=_status(opener,FORGEJO,"/api/v1/packages/omnilyzer",FAKE_JWT)
        self.assertEqual((status,body),(401,b""))
        self.assertNotIn(FAKE_JWT,repr((status,body)))


if __name__ == "__main__":
    unittest.main()
