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
from release.analytics_release_source_binding import (
    _canonical_json, verify_analytics_zot_receipt, REQUIRED_SOURCE_CLAIM,
)
from deployment.promotion import (
    ANALYTICS_LEGACY_SOURCE_SHA, SIGNED_SUCCESSOR_SOURCE_FIELDS,
    SIGNED_HASH_FIELDS, SIGNED_SUCCESSOR_HASH_FIELDS, SIGNED_GIT_FIELDS,
)
from deployment.policy import canonical_bytes, validate_sha256, validate_source_sha
from release.analytics_owner_source_selection import review_ci_owner_signed_claim
from release.analytics_task013_build_candidate import protected_ci_owner_inputs
from release.provenance import release_execution
from release.vulnerability_policy import validate_policy, validate_database_status, evaluate


def _hash(path: Path) -> str:
    """Hash one non-symlinked regular scanner artifact."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('unsafe scanner evidence')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create(source_claim: Path, publication: Path, scan_dir: Path, output: Path,
           *, version: str, execution: dict,
           owner_context: dict[str, str] | None = None,
           owner_payload: dict[str, str] | None = None,
           owner_signature_base64: str | None = None,
           protected_owner_signers: bytes | None = None) -> None:
    """Build exact OCI-only release evidence after authenticated Zot publication."""
    if output.exists() or output.is_symlink() or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is None:
        raise ValueError('unsafe Analytics release output or version')
    claim = _canonical_json(source_claim.read_bytes(), 'Analytics claim')
    # Section: the original 0.15.0 claim stays exact and immutable.
    # Successors bind the full Git-tree source and owner's distinct signed
    # approval SHA in schema 2, without reusing the historical 78-file pin.
    schema = claim.get('schema_version')
    fields = (
        REQUIRED_SOURCE_CLAIM if schema == 1
        else SIGNED_SUCCESSOR_SOURCE_FIELDS if schema == 2
        else frozenset()
    )
    if (type(schema) is not int or schema not in (1, 2)
            or set(claim) != fields
            or claim.get('product_id') != 'analytics'
            or claim.get('source_repository') != 'MichaelTrueX/omnilyzer'
            or claim.get('oci_repository') != 'omnilyzer/analytics'
            or claim.get('readiness_path') != '/readyz'):
        raise ValueError('Analytics source claim missing required fields')
    if schema == 1:
        if (claim['source_commit'] != ANALYTICS_LEGACY_SOURCE_SHA
                or type(claim['source_files_verified']) is not int
                or claim['source_files_verified'] != 78):
            raise ValueError('legacy source review cannot change')
    else:
        if (claim['source_commit'] == ANALYTICS_LEGACY_SOURCE_SHA
                or claim['release_version'] != version
                or type(claim['release_version']) is not str
                or type(claim['full_git_tree_file_count']) is not int
                or not 8 <= claim['full_git_tree_file_count'] <= 10000):
            raise ValueError('successor release/version/Git tree mismatch')
    for name in SIGNED_HASH_FIELDS if schema == 1 else SIGNED_SUCCESSOR_HASH_FIELDS:
        validate_sha256(claim[name], name)
    for name in SIGNED_GIT_FIELDS:
        validate_source_sha(claim[name])
    # Section: original release signer must independently verify the SAME
    # owner Ed25519 approval that protected source and Zot jobs checked.
    # A replayable claim SHA alone cannot enter the protected signing job.
    owner_inputs = (
        owner_context, owner_payload,
        owner_signature_base64, protected_owner_signers,
    )
    if schema == 2:
        if not all(value is not None for value in owner_inputs):
            raise ValueError('missing successor owner signing approval')
        checked_owner = review_ci_owner_signed_claim(
            claim, owner_context, owner_payload,
            signature_base64=owner_signature_base64,
            protected_signers=protected_owner_signers,
        )
        if (
            checked_owner.approval_sha256 != claim["owner_approval_sha256"]
            or checked_owner.owner_signature_verified is not True
            or checked_owner.release_authorized is not False
            or checked_owner.deployment_authorized is not False
        ):
            raise ValueError('unverified owner source claim')
    elif any(value is not None for value in owner_inputs):
        raise ValueError('successor signature cannot downgrade into original source')
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
    parser.add_argument('--successor', action='store_true',
                        help='Require independently protected Ed25519 owner approval before signing')
    a = parser.parse_args()
    execution = {key: getattr(a, key) for key in ('repository', 'repository_id', 'workflow_ref',
                  'workflow_sha', 'run_id', 'run_attempt', 'event_name', 'source_commit')}
    kwargs = protected_ci_owner_inputs() if a.successor else {}
    create(a.source_claim, a.publication, a.scan_dir, a.output,
           version=a.version, execution=execution, **kwargs)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
