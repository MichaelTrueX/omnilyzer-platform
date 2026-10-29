"""File: release/tests/test_analytics_forgejo_evidence.py
Purpose: Test fail-closed Analytics-only Forgejo evidence without network.
Links: release/analytics_forgejo_evidence.py, release/analytics_release_source_binding.py.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from release.analytics_forgejo_evidence import archive_evidence, publish

DIGEST = 'sha256:' + 'a' * 64
VERSION = '1.2.3'


def fixture(directory):
    """Section: Create synthetic unsigned test evidence; never production credentials."""
    claim = {'oci_repository': 'omnilyzer/analytics', 'oci_manifest_digest': DIGEST}
    scanners = ('oci-sbom.cdx.json', 'oci-grype.json', 'grype-db-status.json',
                'vulnerability-policy.json')
    scanner_data = {name: b'{}' for name in scanners}
    scanner_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in scanner_data.items()}
    provenance = {'subjects': {'oci_manifest_digest': DIGEST,
                   'scanner_sha256': scanner_hashes, 'security_exceptions': 0},
                  'external_source': claim}
    provenance_raw = json.dumps(provenance).encode()
    manifest = {'oci': {'repository': 'omnilyzer/analytics', 'manifest_digest': DIGEST},
                'provenance': {'sha256': hashlib.sha256(provenance_raw).hexdigest()},
                'external_source': claim,
                'signing': {'oci_signature': 'omnilyzer/analytics@' + DIGEST}}
    bundle = json.dumps({'mediaType': 'application/vnd.dev.sigstore.bundle.v0.3+json',
                         'verificationMaterial': {}, 'messageSignature': {}}).encode()
    data = {'analytics-source-claim.json': json.dumps(claim).encode(),
            'oci-publication.json': json.dumps({'schema_version': 1,
                'registry': 'https://oci-dev.omnilyzer.ai', 'repository': 'omnilyzer/analytics',
                'tag': VERSION, 'manifest_digest': DIGEST}).encode(),
            'release-manifest.json': json.dumps(manifest).encode(),
            'release-provenance.json': provenance_raw,
            'release-manifest.sigstore.json': bundle,
            'release-provenance.sigstore.json': bundle}
    data.update(scanner_data)
    for name, value in data.items():
        (directory / name).write_bytes(value)


class AnalyticsForgejoEvidenceTests(unittest.TestCase):
    """Section: Validate digest, destination, file integrity and registry readback."""
    def test_deterministic_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            self.assertEqual(archive_evidence(directory, DIGEST, VERSION),
                             archive_evidence(directory, DIGEST, VERSION))

    def test_invalid_digest_version_and_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            for digest, version in [('sha256:' + 'b' * 64, VERSION), (DIGEST, 'latest')]:
                with self.assertRaises(ValueError):
                    archive_evidence(directory, digest, version)
            (directory / 'unexpected').write_text('no')
            with self.assertRaises(ValueError):
                archive_evidence(directory, DIGEST, VERSION)

    def test_mismatched_external_source_denied(self):
        """Section: reject missing or altered source binding in signed evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            manifest_path = directory / 'release-manifest.json'
            manifest = json.loads(manifest_path.read_bytes())
            manifest['external_source']['oci_repository'] = 'omnilyzer/other'
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                archive_evidence(directory, DIGEST, VERSION)

    def test_tampered_scan_denied(self):
        """Section: reject modified Grype evidence after source-bound signing."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            (directory / 'oci-grype.json').write_bytes(b'{"tampered": true}')
            with self.assertRaises(ValueError):
                archive_evidence(directory, DIGEST, VERSION)

    def test_invalid_signature_bundle_denied(self):
        """Section: reject missing or malformed Sigstore bundle structures."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            (directory / 'release-manifest.sigstore.json').write_bytes(b'fixture-only')
            with self.assertRaises(Exception):
                archive_evidence(directory, DIGEST, VERSION)

    def test_publish_readback_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            token = directory / 'token'
            with patch('release.analytics_forgejo_evidence._token', return_value='test'), \
                 patch('release.analytics_forgejo_evidence._request', side_effect=[(201, b''), (200, b'wrong')]):
                with self.assertRaises(RuntimeError):
                    publish(directory, token, DIGEST, VERSION)


if __name__ == '__main__':
    unittest.main()
