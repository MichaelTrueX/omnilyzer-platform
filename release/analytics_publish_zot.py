#!/usr/bin/env python3
"""File: release/analytics_publish_zot.py
Purpose: Publish immutable verified Analytics OCI layers through the ORIGINAL
Task013 Zot HTTPS/OIDC client with tag and digest roundtrip verification.
Links: release/publish_zot.py, release/analytics_release_source_binding.py,
release/analytics_oci_archive.py, .github/workflows/platform-release.yml.
Sections: preflight and publication; command entrypoint.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from release.publish_zot import Client, _load_token
from release.analytics_release_source_binding import prepare_source_claim
from deployment.policy import canonical_bytes

REPOSITORY = 'omnilyzer/analytics'
ORIGIN = 'https://oci-dev.omnilyzer.ai'


def publish(checkout: Path, context: Path, archive_path: Path, token_file: Path,
            output: Path, version: str, platform_root: Path) -> None:
    """Verify source before consuming short-lived OIDC; publish by immutable digest."""
    if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is None or output.exists() or output.is_symlink():
        raise ValueError('invalid Analytics version or publication target')
    claim = prepare_source_claim(checkout, context, archive_path, platform_root=platform_root)
    if claim['oci_repository'] != REPOSITORY:
        raise ValueError('unexpected OCI target')
    expected = claim['oci_manifest_digest']
    with tarfile.open(archive_path, 'r:') as tar:
        manifest = tar.extractfile(tar.getmember('blobs/sha256/' + expected[7:])).read()
        if hashlib.sha256(manifest).hexdigest() != expected[7:]:
            raise ValueError('manifest hash differs from reviewed OCI subject')
        descriptor = json.loads(manifest)
        blobs = {}
        for item in (descriptor['config'], *descriptor['layers']):
            digest = item['digest']
            data = tar.extractfile(tar.getmember('blobs/sha256/' + digest[7:])).read()
            if hashlib.sha256(data).hexdigest() != digest[7:] or len(data) != item['size']:
                raise ValueError('OCI content digest mismatch')
            blobs[digest] = data
    client = Client(ORIGIN, _load_token(token_file), REPOSITORY)
    if client.request('GET', '/v2/')[0] != 200:
        raise RuntimeError('Zot OIDC authentication denied')
    path = '/v2/' + REPOSITORY + '/manifests/' + version
    status, _, _ = client.request('HEAD', path,
        headers={'Accept': 'application/vnd.oci.image.manifest.v1+json'})
    if status != 404:
        raise RuntimeError('immutable Zot version occupied or unknown')
    for digest, data in blobs.items():
        client.upload_blob(digest, data)
    status, headers, _ = client.request('PUT', path, data=manifest,
        headers={'Content-Type': 'application/vnd.oci.image.manifest.v1+json'})
    if status != 201 or headers.get('Docker-Content-Digest', expected) != expected:
        raise RuntimeError('Zot returned mismatched published OCI digest')
    for reference in (version, expected):
        status, _, data = client.request('GET', '/v2/' + REPOSITORY + '/manifests/' + reference,
            headers={'Accept': 'application/vnd.oci.image.manifest.v1+json'})
        if status != 200 or hashlib.sha256(data).hexdigest() != expected[7:]:
            raise RuntimeError('authenticated OCI publication readback mismatch')
    output.write_bytes(canonical_bytes({'schema_version': 1, 'registry': ORIGIN,
        'repository': REPOSITORY, 'tag': version, 'manifest_digest': expected}))


def main() -> int:
    """Run as an isolated protected Task013 publish step."""
    parser = argparse.ArgumentParser()
    for name in ('analytics-checkout', 'immutable-context', 'oci-archive', 'token-file', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--version', required=True)
    a = parser.parse_args()
    publish(a.analytics_checkout, a.immutable_context, a.oci_archive,
            a.token_file, a.output, a.version, Path.cwd())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
