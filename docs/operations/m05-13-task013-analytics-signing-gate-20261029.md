<!--
File: docs/operations/m05-13-task013-analytics-signing-gate-20261029.md
Purpose: Exact M05-13 protected-release acceptance handoff and fail-closed signing gate.
Related: .github/workflows/platform-release.yml; release/analytics_release_source_binding.py;
release/tests/test_analytics_release_source_binding.py; release/provenance.py;
release/publish_zot.py; release/publish_forgejo.py; release/vulnerability_policy.py.
-->

# M05-13 - Task013 Analytics signing and publication gate (29 October 2026)

## Immutable baseline

Review branch was cut at platform PR244 commit `1fd343d15a8faffe695f8272f7e2fa150fcf7b8f`.
Only Analytics Git PR52 SHA `4cdda7faeba57abb3388f9be5c450fe6afb1140d` is eligible.
Never use the earlier PR49/PR50/PR51 OCI digest as a production release digest.

## Completed in this review

The existing pre-sign adapter now verifies that the original Task013 Python and npm
artifact hashes, SBOMs, security-policy identity and policy result match the
original provenance subjects. It also requires the original Sigstore signing
references to point to the *same* verified Analytics OCI manifest digest.
This denies inconsistent source claims before adding external source provenance.
The original synthetic canary source and its release workflow jobs are unchanged.

## Precisely outstanding release boundary

The existing protected workflow's `analytics-source-admission` job builds and
scans an **unsigned local** Analytics OCI image only. The existing protected
`gate`, `build`, `publish-zot` and `publish-forgejo` jobs still accept
`product=canary` only and the original release handoff is canary-shaped
(Python wheel, npm package, OCI archive). A successful Analytics source-admission
cannot and must not borrow the canary's OIDC publication authority.

Before a real Analytics release, the original protected Task013 must be
*explicitly* integrated as a product-aware, reviewed Analytics release path:

1. Select `product=analytics` under the same GitHub workflow, only from
   `refs/heads/main`, verifying exact platform SHA and frozen Analytics PR52 SHA.
2. Reuse the current exact-Git-only Buildx/BuildKit-produced OCI archive; retain
   and verify the exact source TAR and OCI archive through the signed release
   boundary, with no rebuild or mutable tag substitution.
3. Require the original pinned Syft/Grype full OCI scan and existing policy
   PASS with `Critical=0`, `High=0`, `exceptions=[]`, including a valid DB status.
4. Reuse existing `registry_absence_preflight.py` product=analytics preflight
   for only `omnilyzer/analytics` and Analytics-specific Forgejo Generic evidence.
   Fail if either destination/version already exists, without changing canary.
5. Extend original verified publication handoff/provenance to support the
   Analytics OCI-only identity, not invented wheel/npm artifacts. Publish the
   *same* previously scanned image with existing `publish_zot` and prove the
   exact manifest digest from Zot by digest readback.
6. Bind the original manifest and provenance to the previously verified
   immutable source TAR, archive SHA and exact Zot-returned digest; execute
   original Cosign 3.1.2 keyless sign-blob/sign and verify operations with
   issuer `https://token.actions.githubusercontent.com` and exact protected
   `platform-release.yml@refs/heads/main` certificate identity.
7. Publish already signed Analytics evidence to the existing Forgejo origin,
   using the original protected OIDC audience and no long-lived credentials;
   separately verify fetched bytes and signature bundles.

**Production gate:** protected-main merge following independent review, exact
main SHA approval, security PASS and zero exceptions, GitHub Actions
`workflow_dispatch` under the existing restricted environment, both actual
registry round trips, Cosign verification, signed manifest/provenance and
M05/Task014 handoff. Do not dispatch from review branch or manually bypass
GitHub environment restrictions. No registry or production action in this PR.

**Current decision:** pre-sign input hardening PASS; actual Analytics signing,
publication and real registry signature verification NOT EXECUTED. Hence
signed Analytics release remains HOLD, regardless of local test success.
