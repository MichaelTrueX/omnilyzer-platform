#!/usr/bin/env python3
"""File: release/analytics_release_evidence.py
Purpose: Produce the Analytics-only Task013 manifest/provenance for the existing
protected Cosign OIDC signer. No synthetic Python or npm packages.
Links: release/analytics_release_source_binding.py, release/vulnerability_policy.py,
release/analytics_forgejo_evidence.py, .github/workflows/platform-release.yml.
Sections: exact signed subject validation, scanner policy gate, evidence creation, CLI.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import re
from pathlib import Path
from release.analytics_release_source_binding import _canonical_json, verify_analytics_zot_receipt, REQUIRED_SOURCE_CLAIM
from release.provenance import release_execution
from release.vulnerability_policy import validate_policy, validate_database_status, evaluate
from deployment.policy import canonical_bytes


def _hash(path: Path) -> str:
    """Hash one non-symlinked regular scanner artifact."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('unsafe scanner evidence')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create(source_claim: Path, publication: Path, scan_dir: Path, output: Path,
           *, version: str, execution: dict) -> None:
    """Build exact OCI-only release evidence after authenticated Zot publication."""
    if output.exists() or output.is_symlink() or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is None:
        raise ValueError('unsafe Analytics release output or version')
    claim = _canonical_json(source_claim.read_bytes(), 'Analytics claim')
    if (set(claim) != REQUIRED_SOURCE_CLAIM or claim.get('product_id') != 'analytics'
            or claim.get('schema_version') != 1
            or claim.get('source_repository') != 'MichaelTrueX/omnilyzer'
            or claim.get('source_commit') != '4cdda7faeba57abb3388f9be5c450fe6afb1140d'
            or claim.get('source_files_verified') != 78
            or claim.get('readiness_path') != '/readyz'):
        raise ValueError('Analytics source claim missing required fields')
    receipt = verify_analytics_zot_receipt(publication.read_bytes(), claim)
    if receipt['tag'] != version:
        raise ValueError('Zot version does not match Analytics release')
    checked = release_execution(repository=execution['repository'], repository_id=str(execution['repository_id']),
        workflow_ref=execution['workflow_ref'], workflow_sha=execution['workflow_sha'],
        run_id=str(execution['run_id']), run_attempt=str(execution['run_attempt']),
        event_name=execution['event_name'], source_commit=execution['source_commit'])
    if checked['source_commit'] != claim['platform_source_commit']:
        raise ValueError('signed workflow and Analytics source admission differ')
    names = ('oci-sbom.cdx.json', 'oci-grype.json', 'grype-db-status.json', 'vulnerability-policy.json')
    if any(not (scan_dir / name).is_file() for name in names):
        raise ValueError('missing actual Analytics scanner output')
    policy = validate_policy(_canonical_json((scan_dir / 'vulnerability-policy.json').read_bytes(), 'policy'), dt.date.today())
    if policy['exceptions']:
        raise ValueError('Analytics release security exceptions forbidden')
    status = validate_database_status(_canonical_json((scan_dir / 'grype-db-status.json').read_bytes(), 'database'))
    if status['valid'] is not True:
        raise ValueError('Analytics Grype database invalid')
    result = evaluate(scan_dir / 'vulnerability-policy.json', {'oci': scan_dir / 'oci-grype.json'}, dt.date.today())
    if result.get('decision') != 'PASS' or result.get('blocked_findings'):
        raise ValueError('Analytics release Critical/High policy denied')
    artifact_hashes = {name: _hash(scan_dir / name) for name in names}
    provenance = {
        'schema_version': 1, 'statement_type': 'https://omnilyzer.ai/analytics-release-provenance/v1',
        'product_id': 'analytics', 'version': version, 'source_commit': checked['source_commit'],
        'execution': checked, 'external_source': claim,
        'subjects': {'oci_repository': 'omnilyzer/analytics',
                     'oci_manifest_digest': receipt['manifest_digest'],
                     'oci_archive_sha256': claim['oci_archive_sha256'],
                     'scanner_sha256': artifact_hashes, 'security_exceptions': 0},
    }
    provenance_bytes = canonical_bytes(provenance)
    manifest = {
        'schema_version': 1, 'product_id': 'analytics', 'version': version,
        'source_commit': checked['source_commit'], 'external_source': claim,
        'oci': {'registry': receipt['registry'], 'repository': receipt['repository'],
                'manifest_digest': receipt['manifest_digest'],
                'deployment_identity': receipt['repository'] + '@' + receipt['manifest_digest']},
        'provenance': {'filename': 'release-provenance.json',
                       'sha256': hashlib.sha256(provenance_bytes).hexdigest()},
        'signing': {'method': 'keyless Sigstore/Fulcio/Rekor with GitHub OIDC',
                    'release_manifest_bundle': 'release-manifest.sigstore.json',
                    'provenance_bundle': 'release-provenance.sigstore.json',
                    'oci_signature': receipt['repository'] + '@' + receipt['manifest_digest']},
    }
    output.mkdir(mode=0o700)
    (output / 'release-provenance.json').write_bytes(provenance_bytes)
    (output / 'release-manifest.json').write_bytes(canonical_bytes(manifest))
    (output / 'analytics-source-claim.json').write_bytes(canonical_bytes(claim))
    (output / 'oci-publication.json').write_bytes(canonical_bytes(receipt))
    # Preserve the actual scanned SBOM, Grype report, DB status and policy
    # whose exact hashes were committed in the signed provenance subject.
    for name in names:
        (output / name).write_bytes((scan_dir / name).read_bytes())


def main() -> int:
    """Accept protected workflow identity as explicit environment-bound CLI fields."""
    parser = argparse.ArgumentParser()
    for name in ('source-claim', 'publication', 'scan-dir', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('version', 'repository', 'repository-id', 'workflow-ref', 'workflow-sha',
                 'run-id', 'run-attempt', 'event-name', 'source-commit'):
        parser.add_argument('--' + name, required=True)
    a = parser.parse_args()
    execution = {key: getattr(a, key) for key in ('repository', 'repository_id', 'workflow_ref',
                  'workflow_sha', 'run_id', 'run_attempt', 'event_name', 'source_commit')}
    create(a.source_claim, a.publication, a.scan_dir, a.output,
           version=a.version, execution=execution)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
