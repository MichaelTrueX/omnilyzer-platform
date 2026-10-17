<!--
File: docs/operations/task013-release-0145-acceptance.md
Purpose: Authoritative acceptance record for the single authorized and
         completed Task 013 coordinated immutable release 0.14.5.
Related:
  .github/workflows/platform-release.yml
  release/registry_absence_preflight.py
  release/verify_handoff.py
  release/publish_zot.py
  release/publish_forgejo.py
  release/provenance.py
  docs/operations/task013-authenticated-version-preflight.md
  docs/operations/task013-forgejo-oidc-auth-probe.md
Authority: Historical evidence and release acceptance only.
           No DEV or PROD application deployment is authorized.
-->

# Task 013 release 0.14.5 — SUCCESS (17 October 2026)

## 1. Release authority and identity

The owner explicitly approved one controlled fresh-version publication
after an authenticated version-absence preflight and independent artifact
verification. The release used existing **short-lived GitHub OIDC** for both
Forgejo and zot. No PAT, credential exception, account or DNS mutation was
needed. No DEV or PROD deployment was part of the authorization.

- Repository: `MichaelTrueX/omnilyzer-platform`
- Source: protected `main` commit
  `c1b83b115c356716c3c570818a61c8a0710ab9c8`
- Version: `0.14.5`
- Workflow: `.github/workflows/platform-release.yml@refs/heads/main`
- Run: [39025630261](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39025630261)
- GitHub event: `workflow_dispatch`; run attempt: `1`
- Started: `2026-10-17T10:37:53Z`
- Completed: `2026-10-17T10:41:26Z` (GitHub recorded update)
- Conclusion: **success**

The earlier partially published immutable `0.14.4` remains historical
and was not retried or overwritten.

## 2. GitHub Actions acceptance record

| Job | Result |
| --- | --- |
| `gate` | SUCCESS |
| `build` | SUCCESS |
| `publish-zot` | SUCCESS |
| `publish-forgejo` | SUCCESS |
| `forgejo-auth-probe` | SKIPPED (correct for normal release) |

All mandatory release steps returned `success`, including:
the exact source SHA and environment policy; one OCI build;
Buildx/BuildKit versions; Syft CycloneDX SBOMs and Grype scans;
fail-closed vulnerability policy; complete immutable handoff;
authenticated registry-absence preflight; zot OCI publication;
Cosign keyless signing and certificate identity verification;
Forgejo OIDC PyPI, npm and generic evidence uploads;
and authenticated exact-byte roundtrip retrieval of all Forgejo
distributables in the publisher workflow.

The denied-release diagnostic artifact upload was skipped because
the security policy did **not** deny the release.

## 3. Four authenticated destination-absence checks

The first registry-writing job confirmed all four destinations were
unused before the initial registry write. It obtained two independently
minted short-lived OIDC JWTs using the already-allowed GitHub identity,
then authenticated against both Forgejo and zot.

- PyPI `omnilyzer-release-canary` version `0.14.5`: ABSENT
- npm `@omnilyzer/release-canary` version `0.14.5`: ABSENT
- generic evidence `task013-release-evidence` version `0.14.5`: ABSENT
- OCI tag `omnilyzer/task013-release-canary:0.14.5`: ABSENT

Both registries' authentication baselines returned HTTP 200. Exact
version endpoints returned HTTP 404, with additional bounded Forgejo
package-list checks. The step's GitHub conclusion was `success`.

This verifies pre-publication absence, not a permanent guarantee against
writes by an unrelated independent actor. The existing immutable zot
tag refusal and package duplicate protection remain in force.

## 4. Published OCI receipt and exact source fingerprints

- zot registry: `https://oci-dev.omnilyzer.ai`
- Repository: `omnilyzer/task013-release-canary`
- Tag: `0.14.5`
- Manifest digest:
  `sha256:2f9db44a1cb475bec5a82ad7f81508e2b6ecd327f32b358ec1f1deca95e5385e`
- Original source commit:
  `c1b83b115c356716c3c570818a61c8a0710ab9c8`
- OCI archive `task013-release-canary-0.14.5.oci.tar` SHA-256:
  `1dcf48dca212548c7c92a5d287773dde73f1d7072760e51f3989a027a99c61e7`
- Python wheel `omnilyzer_release_canary-0.14.5-py3-none-any.whl` SHA-256:
  `a83f971290b5656508d72dd059c26b95c6c4fa5a4449c6e61ddf4cadd90d1b78`
- npm archive `omnilyzer-release-canary-0.14.5.tgz` SHA-256:
  `db45569ee646e647c6bb60c7e70e6810f0f952181657e89a95737eb2e2e38b7a`

The GitHub Actions run produced two Task 013 retained artifacts:

- `platform-release-handoff-39025630261-1`
- `platform-release-oci-39025630261-1`

A separate Docker Buildx workflow metadata artifact was also present;
it was **not** substituted for signed release evidence. Handoff transport
artifacts use one-day GitHub retention, so independently downloaded
copies have been retained in owner-only evidence directories.

## 5. Independent two-host evidence verification

On `truexdevelopment`, the original immutable GitHub handoff and OCI
publication receipt were downloaded to:

- `/home/trusthansen/omnilyzer-security-evidence/task013-release-0145-independent-handoff`
- `/home/trusthansen/omnilyzer-security-evidence/task013-release-0145-receipt`

A detached worktree at the exact signed source commit ran the repository's
`release.verify_handoff` code with `--require-production-evidence`
and successfully validated its artifact manifests, production-tools
evidence and expected source/version. A separate Python check compared
the independently downloaded build manifest's
`expected_oci_manifest_digest` against the independent zot publication
receipt and verified the exact repository, version and SHA.

On `michael-laptop`, the same two GitHub artifacts were downloaded under:

`/home/michael/Development/task013-release-0145-independent-39025630261`

A **separate second execution** of the same source-pinned verifier
revalidated the entire handoff. It independently confirmed the
OCI manifest receipt, source SHA and OCI archive SHA-256. Temporary
source worktrees used for verification were removed afterward.

**Verification qualification:** These checks independently validate
the retained GitHub build handoff and zot publication receipt on two
machines distinct from the public registry server. Authenticated
download-byte comparisons of PyPI/npm/generic outputs, and keyless
Cosign signing and verification, were executed by the original
successful GitHub release workflow. A separately authorized
postpublication third-party consumer download/signature audit has
**not** yet been performed; do not misrepresent the two-host offline
checks as that external-consumer test.

## 6. Remaining release and deployment boundaries

Task 013's former Forgejo OIDC HTTP 401 blocker is closed, and one
coordinated `0.14.5` release successfully completed. The existing
Buildx, SBOM, Grype, Sigstore, provenance, immutable OCI digest,
exact-publisher identity and protected environment policies were retained.

No Task 014 deployment broker, customer-facing application,
authentication session, localStorage token handler, migration, DEV runtime
or PROD runtime was modified or activated by this release. DEV and PROD
deployment remain separate **NO-GO pending their own acceptance**.

Do not re-dispatch `0.14.4` or `0.14.5`; a subsequent release must
use a new explicitly approved version with a fresh authenticated
preflight. Do not restore the old `repository_visibility=private`
condition after verified OIDC success.
