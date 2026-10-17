<!--
File: docs/operations/task013-forgejo-oidc-auth-probe.md
Purpose: Record the merged read-only OIDC diagnostic, its 401 result,
         reviewed server-side findings and a claim-name-only follow-up proposal.
Related: .github/workflows/platform-release.yml, release/request_oidc.py,
         release/forgejo_oidc_probe.py, release/tests/test_forgejo_oidc_probe.py,
         release/tests/test_workflow_policy.py,
         docs/operations/task013-forgejo-oidc-visibility-recovery.md,
         GitHub Actions release run 39010764876.
Authority: REVIEW-ONLY for the follow-up claim audit. No additional workflow
           dispatch, rule change, release publication or deployment is authorized.
-->

# Task 013: Forgejo OIDC authentication diagnostic (non-publishing)

## Purpose and compatibility

Release `0.14.4` completed source validation, executable OCI build, Grype
vulnerability policy, zot registry publication, and keyless signature checks.
Its first Forgejo PyPI upload failed `401 authGroup.Verify`; npm and evidence
publication did not run, leaving a **partial, non-deployable release**.

On 2026-10-17 the owner separately approved changing the existing Forgejo
Authorized Integration ID 1's sole mismatched `repository_visibility`
condition from `private` to `public`. The current rules, issuer, audience,
organization membership and `write:package` scope were independently compared
before and after the change. **End-to-end OIDC acceptance has not been
demonstrated.**

The existing Authorized Integration explicitly permits JWTs only from
`MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main`.
A new independent PR workflow or an operator terminal will **not** possess that
`workflow_ref`, so running a probe there would not test the real publisher.

## Original diagnostic mode - merged and executed

The merged `.github/workflows/platform-release.yml` has one additional
manual boolean input:

- `auth_probe`, default `false`: standard release path remains unchanged.
- `auth_probe=true`: the `forgejo-auth-probe` job runs; the `gate` is
  explicitly **skipped**, which automatically skips `build`, `publish-zot`
  and `publish-forgejo` via their unchanged `needs` chains.

The diagnostic uses the **same protected `task013-dev-release` GitHub
environment** as the existing publisher jobs, with job-level GitHub permissions
`contents: read` and `id-token: write`. There is no checkout credential
persistence. It rejects any repository, ref, source commit or workflow identity
that differs from the exact authorized main-branch run before requesting OIDC.

The job requests a fresh GitHub OIDC JWT with the **unchanged existing
Forgejo audience** and immediately presents it to one fixed HTTPS route:

```text
GET https://registry-dev.omnilyzer.ai/api/v1/packages/omnilyzer?type=pypi&limit=1
```

This is Forgejo's package-listing API, not a publishing endpoint. The existing
`write:package` scope includes GET. An authenticated HTTP 200 containing a
bounded JSON package list is accepted; empty lists are valid. **401, 403,
redirects, unexpected HTTP status, oversized payload, malformed JSON,
non-list responses, TLS or network errors are all denied.** Neither the
JWT nor the response body is logged or stored. The token stays in an exclusive
mode-0600 temporary file and is deleted by the job's exit trap.

The diagnostic Python module accepts only `--token-file`; it does **not**
accept URLs, HTTP methods, package names, registry credentials, version
selection or publication instructions. No OCI image, wheel, npm artifact,
signed bundle or registry object is created.

## Verified workflow isolation and original review

- The release workflow is only `workflow_dispatch` triggered; repository
  `main` is protected. No pull-request job can request the publisher JWT.
- The new `auth_probe` input is a typed boolean and defaults to `false`.
- Gate condition is exactly `inputs.auth_probe == false`, and the diagnostic
  is exactly `inputs.auth_probe == true`.
- Existing build and publisher job dictionaries are still validated against
  their original protected-main semantic SHA-256 fingerprints.
- The entire updated workflow also has an explicitly pinned SHA-256 in the
  executable canary regression suite **and** three original Task 014 source
  boundary suites (`deployment/tests/test_policy.py`,
  `test_runtime_assets.py`, `test_execution.py`). No Task 014 deployment
  behavior or environment files changed.
- The `release/forgejo_oidc_probe.py` regression suite tests single GET,
  exact destination, secret redaction, private token files, unauthorized
  responses, redirects, malformed JSON, unexpected content type, oversized
  responses and network failure.
- Existing release tests and release-consumer security baseline must pass.
- GitHub PR CI must pass at the exact reviewed commit. Draft PR review alone
  is not proof of the live OIDC integration.

## Actual authorized diagnostic and observed limitation

The owner explicitly approved merging PR #194 and executing exactly one
nonpublishing diagnostic. Merge commit:
`dc6b8cff55c435e1d8e9198da3b773e7136eee9c`.

One approved run
[39015221560](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39015221560)
ran on 2026-10-17 at this exact protected-main SHA. The source SHA, branch,
repository and workflow identity prechecks passed, and GitHub supplied the
fresh OIDC token without error. The sole fixed Forgejo package GET returned
`FORGEJO_OIDC_PROBE_HTTP_401`.

**Release gate, build and both publisher jobs were SKIPPED** and the run
created no artifacts. No new packages, keys or release versions were
created. The 401 does **not** establish which Forgejo authentication check
failed. The corrected Forgejo integration still has six exact claim rules
and the existing `write:package` capability.

## Read-only root-cause investigation

On 2026-10-17, additional nonmutating inspection verified:

- Forgejo v16.0.3 reads Authorized Integration rules via its database model
  `GetAuthorizedIntegration(ctx, issuer, audience)`, not a cached claim-rule
  object. Its optional cache concerns external OIDC metadata and JWKS.
  A service restart is not indicated to load the corrected database rule.
- The integration still has `repository_visibility=public`, the original
  issuer, audience, five other rules and publisher ownership; PostgreSQL
  agrees with the live Forgejo container's configured `forgejo` database.
- Forgejo's issuer allowlist explicitly permits
  `token.actions.githubusercontent.com`.
- From inside the Forgejo container, GitHub OIDC metadata and JWKS
  endpoints both returned HTTP 200 with valid TLS verification; the
  discovery issuer matched the configured one.
- The reviewed Nginx virtual host proxies to the expected Forgejo
  loopback service, and no separate Nginx authentication gate is present
  in that vhost.
- The Authorized Integration's database `updated_unix` (last-use tracking)
  remained at 2026-09-07 15:48:25 UTC, consistent with no confirmed
  successful authentication after the new diagnostic.

The version-matched code and GitHub's documented OIDC claim schema show
that Forgejo checks issuer/audience and claim rules **before** fetching
signing metadata. All six configured GitHub claim names are documented
by GitHub. These findings rule out some configuration hypotheses but
cannot prove the exact contents of the JWT issued during run 39015221560.

## Follow-up claim-name audit - DRAFT ONLY

A narrow source-only revision to `release/forgejo_oidc_probe.py` first
decodes only the JWT's JSON header and payload **in the existing GitHub
Actions process** (without treating the decoded claims as signed or
authenticated). It compares against the exact already-approved values:

- Header signing algorithm `RS256` and presence of a key ID.
- Issuer `https://token.actions.githubusercontent.com` and the existing
  generated Forgejo audience.
- Repository `MichaelTrueX/omnilyzer-platform`, owner `MichaelTrueX`,
  repository visibility `public`, ref `refs/heads/main`, exact
  release workflow ref on main, and `workflow_dispatch` event.

Output consists **only of fixed claim names with `MATCH` or
`MISMATCH`**. Actual values, signing headers, JWT bytes and response bodies
are never printed or uploaded. If any comparison fails, the diagnostic
stops before making any HTTP request. If they all match, it attempts the
same single previously reviewed HTTPS GET; only the existing strict
authentication outcome is reported. This is **not** a replacement for
cryptographic verification by Forgejo.

The workflow YAML, OIDC issuance module, registry endpoints, security
scopes, release publishers, application code and DEV/PROD settings are
unchanged. Existing offline network mocks and additional claim reporting
regressions must pass along with independent PR CI.

## Next separate authorization boundary

Do not run the modified diagnostic from a draft pull request: the issuer
identity is restricted to the exact merged `platform-release.yml` workflow
on protected `main`. After all PR checks pass, obtain explicit approval
to merge and execute at most one read-only probe. Accept only
`forgejo-auth-probe=SUCCESS` with every original release/publisher job
`SKIPPED`. If any rule does not match, investigate the named claim with
the actual integration still fail-closed; do not log raw values or loosen
the allowlist. If every claim matches but Forgejo still returns 401,
investigate signature verification or package API permissions next, with
a separate minimal non-publishing plan. Retain `0.14.4` as a historical
partial release and do not publish `0.14.5` without separate approval.

## Explicit non-claims

This follow-up does not prove end-to-end authentication until an
authorized real run succeeds. It does not authorize another merge,
diagnostic dispatch, release, registry publication, restoration or
modification of Forgejo rules, DEV/PROD activation or Task 014 broker
replacement. It requires no permanent credential.
