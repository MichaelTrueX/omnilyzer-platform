<!-- File: docs/operations/m05-13-task013-analytics-release-20261029.md -->
<!-- Purpose: Document complete reviewed Task013 Analytics source-to-signature code path and release acceptance. -->
<!-- Links: .github/workflows/platform-release.yml; release/analytics_publish_zot.py; -->
<!-- release/analytics_release_evidence.py; release/analytics_forgejo_evidence.py; -->
<!-- docs/operations/m05-13-task013-analytics-signing-gate-20261029.md. -->

# M05-13 — Analytics Task013 protected release integration

## Scope and source

Target: `MichaelTrueX/omnilyzer-platform` PR #248 stacked on PR #244.
Analytics Git source: `MichaelTrueX/omnilyzer` PR #52,
`4cdda7faeba57abb3388f9be5c450fe6afb1140d`.
No change to the canary release gate, packages, publishers, Task014 broker,
production service, or release consumers. The new Analytics release publishes
only a new OCI image and a Forgejo **Generic** evidence archive; it never
fabricates a Python wheel, npm package, or release authorization for Task014.

## Signed release path

1. The existing `analytics-source-admission` job requires the exact protected
   `main` SHA, builds from a reviewed immutable Git-only TAR using pinned
   Buildx/BuildKit, independently checks every OCI blob, runs real pinned
   Syft/Grype and enforces zero Critical/High and zero exceptions.
2. A transport artifact contains the reviewed TAR, OCI, full source claim,
   actual SBOM/Grype/DB-status and the exact security policy; **no OIDC in the
   build job**.
3. `analytics-publish-zot` requires the completed scanner job and the existing
   `task013-dev-release` environment. Before OIDC it independently rebuilds
   the source/OCI claim. The original two-registry absence preflight rejects
   any occupied Analytics version. The original Zot HTTPS/OIDC client publishes
   only the exact verified `omnilyzer/analytics` digest and checks version and
   digest roundtrip bytes.
4. `analytics-publish-forgejo` depends on both earlier jobs and the same
   protected environment. The Analytics-only evidence adapter verifies the
   published OCI receipt against source, immutable release version, actual
   scanner hashes and policy. It signs **both** manifest and provenance using
   the already pinned Cosign v3.1.2 keyless GitHub OIDC implementation, verifies
   both bundles against the exact protected `main` workflow identity, signs
   `oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:<digest>`, and verifies its
   OCI signature before requesting Forgejo OIDC.
5. The Analytics Generic evidence publisher verifies the source binding,
   provenance hash, OCI digest, required Sigstore bundle structures, scanner
   hashes, zero security exceptions and deterministic archive contents. The
   actual cryptographic verification belongs to the preceding protected
   Cosign job step. Forgejo PUT must return 201 and authenticated readback
   bytes must match exactly.

## Release authorization and limitations

A reviewed PR and local test pass **do not issue any signature or registry
write**. The job must run as `workflow_dispatch` on the accepted protected
`main` commit with `product=analytics`, `auth_probe=false`, an unused strict
`X.Y.Z` version, and `source_sha` exactly equal to the dispatched commit.
Existing GitHub environment approvals and OIDC trust boundaries apply. Do not
run Task014 or claim production deployment from Task013 receipts.

Until a real protected run completes with its pinned scanner 0 Critical/High,
zero exceptions, exact Zot digest roundtrip, verified Sigstore blob/OCI
signatures and Forgejo evidence roundtrip, operational status is **HOLD**.
Do not merge or deploy without the owner's release approval.

## Related tests

`python3 -m unittest discover -s release/tests -p 'test_analytics*.py' -q`

`python3 -m unittest release.tests.test_workflow_policy release.tests.test_registry_absence_preflight -q`

Both run without registry credentials. The OCI fixtures and simulated scanner
results are deliberately non-production; a successful fixture is never proof
that the actual published Analytics image has zero vulnerabilities.
