<!--
File: docs/operations/task013-forgejo-oidc-auth-probe.md
Purpose: Explain the non-publishing OIDC authentication diagnostic proposed
         after the approved Forgejo integration visibility correction.
Related: .github/workflows/platform-release.yml, release/request_oidc.py,
         release/forgejo_oidc_probe.py, release/tests/test_forgejo_oidc_probe.py,
         release/tests/test_workflow_policy.py,
         docs/operations/task013-forgejo-oidc-visibility-recovery.md,
         GitHub Actions release run 39010764876.
Authority: REVIEW-ONLY. This document does not authorize a merge, diagnostic
           workflow dispatch, release, registry publication or deployment.
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

## Proposed diagnostic mode (not yet merged or run)

The existing `.github/workflows/platform-release.yml` receives one additional
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

## Local review and acceptance, before any merge

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

## Future authorized execution - **not part of this review**

Only after a separate explicit merge and probe-dispatch approval:

1. Merge the reviewed PR under protected-main rules. Record the new main SHA.
2. Dispatch the existing `platform-release.yml` **once** from `main` with
   `auth_probe=true`, `source_sha` equal to that exact new SHA and
   `version=0.14.4` solely as the already-used harmless concurrency label.
   The diagnostic job does not build or publish that version.
3. Inspect GitHub run jobs, not merely the overall workflow conclusion.
   Accept **only** `forgejo-auth-probe=SUCCESS`, and
   `gate/build/publish-zot/publish-forgejo=SKIPPED`.
4. Accept the fixed `FORGEJO_OIDC_READ_ONLY_AUTHENTICATION_ACCEPTED`
   result and confirm no token, body or artifact leaked into workflow logs.
5. If the probe is denied, stop; do not rerun publication, broaden existing
   JWT claim rules, create a PAT or infer that the earlier visibility mismatch
   was the only issue. Evaluate whether to restore the before snapshot under
   a new narrowly scoped approval.
6. If successful, seek **separate owner approval** for one new coordinated
   release version (provisionally `0.14.5`). Preflight that every registry
   destination is unused, and preserve the partial `0.14.4` record.
7. Revalidate signed schema-v2 provenance, independent zot and Forgejo
   retrieval, signatures, exact digests and fail-closed negative cases.
   Live DEV/PROD activation remains outside this authorization.

## Explicit non-claims

This proposed change does not prove production application compatibility or
remediate the unrelated Task 014 deployment broker. It grants no merge, registry
publication, service activation, rollback deletion, owner password reset, or
additional registry entitlement. It requires no user-created PAT.
