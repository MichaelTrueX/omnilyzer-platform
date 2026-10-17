<!--
File: docs/operations/task013-forgejo-scoped-token-fallback.md
Purpose: Review a bounded, temporary alternative to the unresolved Forgejo
         v16 external-OIDC authentication failure for Task 013 releases.
Related: .github/workflows/platform-release.yml, release/publish_forgejo.py,
         release/tests/test_publish_forgejo.py,
         release/tests/test_workflow_policy.py,
         docs/operations/task013-forgejo-oidc-auth-probe.md,
         GitHub runs 39010764876, 39015221560 and 39016477179.
Authority: DRAFT REVIEW ONLY. No credential issuance, protected GitHub secret,
           live config change, merge, release or deployment is authorized.
-->

# Task 013: package-only Forgejo credential fallback

## Decision under review

For the sole-proprietor Omnilyzer Task 013 synthetic DEV release, replace
**only the Forgejo package API bearer credential** with a dedicated, expiring
Forgejo **personal access token scoped to `write:package`**, owned by the
existing non-administrator `gha-publisher` account. Do not use a token
belonging to the human owner or an unrestricted administrator.

GitHub Actions will store it only as the secret `FORGEJO_PUBLISH_TOKEN` in
the protected **`task013-dev-release` environment** (not at the repository
level). The credential must never be committed to the repository, passed
as a CLI argument, displayed in logs, uploaded as an artifact or included in
an OIDC/Sigstore signing bundle.

This is a pragmatic tradeoff, not an improvement in token lifetime:
a scoped long-lived credential entails rotation and revocation obligations
that short-lived OIDC normally avoids. Forgejo officially recommends
Authorized Integrations over static access tokens when working correctly;
however two controlled tests have established that the deployed Forgejo 16
rejects GitHub OIDC despite the exact expected claims. Continued blind
retries do not advance the release. The OIDC failure remains unresolved.

Reference: https://forgejo.org/docs/v17.0/user/authentication/token-scope/
and https://forgejo.org/docs/latest/user/api/authorized-integrations/.

## What remains unchanged

The original workflow remains manually dispatched from protected main with
an exact SHA, gated environment, immutable build handoff, pinned Buildx,
Syft and Grype, fail-closed vulnerability scanning and deny evidence.

The zot OCI publication **continues to use its working short-lived OIDC**.
Cosign keyless **release-manifest, provenance and OCI signing continue to
use GitHub OIDC identities and existing exact certificate verification**.
Forgejo itself is not reconfigured: its Authorized Integration, account
permissions, allowed issuer, audience and claim rules remain intact.
No application login/session, CSP/CORS, routes, Docker runtime or DEV/PROD
deployment code is modified.

The Forgejo publisher changes only the credential supply step. It still
verifies the original handoff and signs evidence **before** receiving the
package credential, publishes immutable PyPI/npm/generic artifacts with the
same package URLs, and independently reads back every published byte.
Its file reader requires an explicitly chosen PAT or legacy OIDC format,
a one-use regular file with mode 0600, no symlink, no whitespace and a
bounded ASCII payload. A missing GitHub environment secret fails closed.

## Preconditions requiring separate explicit approval

1. Confirm the `gha-publisher` account is still active, non-admin and
   authorized to publish to the `omnilyzer` organization. Do not reset
   an unrelated owner's password or modify organization ownership.
2. Create **one new token** for `gha-publisher` with only `write:package`
   scope, the narrowest appropriate resource selection, and a short
   expiration (prefer approximately 30 days where supported). Do not
   grant repository, organization-admin or global `all` scopes. Forgejo
   `write:package` can include write/delete API operations, so retain
   the existing Nginx public DELETE denial and account-level controls.
3. Conduct an **authenticated read-only** package API call with that
   credential, using an isolated local/private channel. Require HTTP 200
   from a documented protected package list/read endpoint. Do not attempt
   any package write for initial credential verification. If 401/403,
   **stop without starting a release**.
4. Set `FORGEJO_PUBLISH_TOKEN` as a GitHub **environment** secret in
   `task013-dev-release`, with main branch protection retained. Never
   paste the token into this conversation, a workflow argument, a
   screenshot, source file or an issue/PR comment. Verify only secret
   **presence and environment association**, not its value.
5. Obtain explicit approval to merge this PR after all CI checks and
   protected branch status are verified. The merge does not itself
   trigger any release.
6. Only then obtain **separate** approval for one future Task 013 canary
   version, provisionally `0.14.5`, after checking all destination tags
   and package versions are unused. Do **not retry 0.14.4** or overwrite
   its existing zot digest.
7. Inspect independent package roundtrips and schema-v2 Sigstore evidence
   acceptance. Do not claim DEV/PROD deployment readiness from only a
   GitHub green workflow status.

## Failures, rollback and expiration

- Missing, expired or revoked scoped PAT: fail closed and keep release
  publication **NO-GO**. Do not guess alternate credentials or fall back
  to unrelated administrator tokens.
- Any independent failure after the immutable zot tag has been published
  leaves an incomplete version. Retain that immutable tag for audit;
  use a new version after remediation, never re-run the same version.
- Credential compromise: revoke only that PAT, remove the corresponding
  GitHub environment secret and investigate logs. Never dump secrets.
- Controlled rollback: a future approved PR may return Forgejo
  publishing to working OIDC after a verified signature/authentication
  acceptance. The existing Authorized Integration must not be deleted
  or its permission rules weakened to make this fallback work.
- Record a calendar reminder to rotate/revalidate before token expiry;
  prefer renewal in a single planned owner maintenance action.

## Test and scope constraints

The proposed PR contains source/tests/documentation only; **no actual
credential is generated or stored**. No Task 013 release is dispatched,
no registry publication occurs, and no live Forgejo, nginx, PostgreSQL,
GitHub environment secret, DEV or PROD configuration is modified.

The release workflow remains disabled for automatic triggers; the test
suite pins its full SHA and verified legacy job fingerprints. The change
allows only this reviewed exception to the original rule forbidding
persistent registry credentials, and strictly limits it to Forgejo's
package-publishing step under the preexisting protected environment.

The release consumer's own authentication and deployment broker (Task
014), frontend localStorage token handling, and all customer-facing
routes are outside scope.
