#!/usr/bin/env python3
"""File: release/analytics_forgejo_evidence.py
Purpose: Publish ONLY verified Analytics signed release evidence to the existing
Forgejo Generic package API, without inventing Python/npm distributions.
Links: release/publish_forgejo.py, release/analytics_release_source_binding.py,
release/registry_absence_preflight.py, release/tests/test_analytics_forgejo_evidence.py.
Security: immutable version, strict evidence allowlist, no redirects, authenticated
readback and byte comparison; requires caller's protected signer verification.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import re
import tarfile
import gzip
from pathlib import Path
from release.publish_forgejo import _request, _token
from release.analytics_release_source_binding import _canonical_json, verify_analytics_zot_receipt

ORIGIN = 'https://registry-dev.omnilyzer.ai'
OWNER = 'omnilyzer'
PACKAGE = 'analytics-release-evidence'
FILES = frozenset({'release-manifest.json', 'release-provenance.json',
                   'release-manifest.sigstore.json', 'release-provenance.sigstore.json',
                   'analytics-source-claim.json', 'oci-publication.json'})


def archive_evidence(directory: Path, expected_digest: str, version: str) -> bytes:
    """Section: Validate six regular evidence files and deterministic archive."""
    if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is None:
        raise ValueError('invalid immutable release version')
    if not directory.is_dir() or directory.is_symlink() or {p.name for p in directory.iterdir()} != FILES:
        raise ValueError('Analytics evidence file allowlist mismatch')
    for name in FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('Analytics evidence input is unsafe')
    claim = _canonical_json((directory / 'analytics-source-claim.json').read_bytes(), 'source claim')
    if claim.get('oci_manifest_digest') != expected_digest or claim.get('oci_repository') != 'omnilyzer/analytics':
        raise ValueError('Analytics source digest mismatch')
    receipt = verify_analytics_zot_receipt((directory / 'oci-publication.json').read_bytes(), claim)
    if receipt['tag'] != version:
        raise ValueError('Analytics published version mismatch')
    manifest = _canonical_json((directory / 'release-manifest.json').read_bytes(), 'release manifest')
    provenance = _canonical_json((directory / 'release-provenance.json').read_bytes(), 'release provenance')
    if (manifest.get('oci', {}).get('manifest_digest') != expected_digest
            or manifest.get('oci', {}).get('repository') != 'omnilyzer/analytics'
            or provenance.get('subjects', {}).get('oci_manifest_digest') != expected_digest):
        raise ValueError('Analytics signed subject mismatch')
    if manifest.get('provenance', {}).get('sha256') != hashlib.sha256((directory / 'release-provenance.json').read_bytes()).hexdigest():
        raise ValueError('Analytics provenance hash mismatch')
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name in sorted(FILES):
            data = (directory / name).read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 946684800
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            tar.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename='', fileobj=compressed, mode='wb', mtime=0) as stream:
        stream.write(buffer.getvalue())
    return compressed.getvalue()


def publish(directory: Path, token_file: Path, expected_digest: str, version: str) -> None:
    """Section: Publish immutable Forgejo Generic package and verify byte readback."""
    archive = archive_evidence(directory, expected_digest, version)
    token = _token(token_file)
    path = f'/api/packages/{OWNER}/generic/{PACKAGE}/{version}/release-evidence.tar.gz'
    status, _ = _request(ORIGIN, token, 'PUT', path, archive, 'application/gzip')
    if status != 201:
        raise RuntimeError(f'Analytics evidence publication denied: HTTP {status}')
    status, returned = _request(ORIGIN, token, 'GET', path)
    if status != 200 or returned != archive:
        raise RuntimeError('Analytics evidence registry readback mismatch')


def main() -> int:
    """Section: CLI for protected original Task013 release job."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--token-file', required=True, type=Path)
    parser.add_argument('--oci-digest', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    publish(args.evidence, args.token_file, args.oci_digest, args.version)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
