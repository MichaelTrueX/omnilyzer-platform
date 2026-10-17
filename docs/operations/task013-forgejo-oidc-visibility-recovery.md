<!--
File: docs/operations/task013-forgejo-oidc-visibility-recovery.md
Purpose: Record the verified 0.14.4 partial-release authentication failure and
         stage one narrowly scoped Forgejo OIDC Authorized Integration correction.
Related: .github/workflows/platform-release.yml, release/request_oidc.py,
         release/publish_forgejo.py, release/README.md,
         release/environments/dev.json, GitHub PR #192,
         GitHub Actions run 39010764876.
Authority: DOCUMENTATION / REVIEW ONLY. This document neither changes a live
           integration nor authorizes a release, merge, deployment or retry.
-->

# Task 013 - Forgejo OIDC visibility claim reconciliation

## Decision and immediate restriction

**Recommendation: retain GitHub Actions OIDC** for the existing package-publishing
integration. Forgejo v16.0.3 already implements Generic JWT Authorized Integrations,
including direct GitHub Actions OIDC validation. Do not introduce a static PAT,
change the registry's issuer, allow wildcard repository claims or weaken the
publisher account's permissions. The identified mismatch is one exact claim rule.

**Current state: partial release / NO-GO.** Release `0.14.4` was dispatched once
on 2026-10-17, GitHub run
[39010764876](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39010764876),
from protected main
`05bd5dab1ca8b4c32cc6f30b082df20c911ac50f`.
Its source gate, OCI build, original Critical/High vulnerability policy,
zot publish and keyless signing step all succeeded. The first Forgejo request,
`POST /api/packages/omnilyzer/pypi`, failed HTTP 401
`authGroup.Verify`. Forgejo's npm and Generic publication were never attempted.
No complete, externally retrievable schema-v2 release bundle is confirmed.
Neither DEV nor PROD was deployed. **Do not rerun version 0.14.4**, overwrite
the existing zot tag, delete a registry artifact or infer deployment readiness
from the zot job success.

## Read-only incident evidence, 2026-10-17

GitHub REST API reported the GitHub source repository
`MichaelTrueX/omnilyzer-platform` as `visibility=public`,
`private=false`, numeric repository ID `1350104356`.

A local, read-only SQL transaction against the existing Forgejo PostgreSQL
database (no passwords, tokens or signing keys accessed) showed:

- Forgejo version: `16.0.3`.
- Authorized Integration ID: `1`, name `github-task008c-publisher`,
  owner `gha-publisher`.
- Issuer: `https://token.actions.githubusercontent.com`.
- Audience: `u:2:316bec9a-53e4-4807-9557-7febdc979d0a`.
- Scope: `write:package`; resource mapping: all repositories (scope is
  **package API operations**, not repository write permissions).
- The owner account `gha-publisher` is a member of the `omnilyzer`
  organization through team `package-publishers`.
- Existing exact claim rules restrict `repository` to
  `MichaelTrueX/omnilyzer-platform`, `repository_owner` to
  `MichaelTrueX`, `ref` to
  `refs/heads/spike/008c-forgejo-registry` or `refs/heads/main`,
  `workflow_ref` to the historic Task 008 publisher or
  `MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main`,
  and `event_name` to `push` or `workflow_dispatch`.
- The **incompatible rule** is precisely:
  `{"claim":"repository_visibility","compare":"eq","value":"private"}`.
  GitHub's documented `repository_visibility` claim is `public` for this
  public repository. This is sufficient to prevent authentication regardless
  of the JWT signature. It was not necessary to access or log any JWT.
  Other unobserved causes are not excluded until an authorized read-only
  authentication check passes after a future change.

The workflow's `FORGEJO_AUDIENCE` value already agrees with the stored
Authorized Integration audience. The pipeline also already uses the documented
`Authorization: Bearer <JWT>` convention. Therefore neither a new PAT nor
changes to `release/request_oidc.py` or `release/publish_forgejo.py`
are justified by current evidence.

## Proposed one-field correction - **not applied**

After **separate explicit approval** to modify the live Forgejo Authorized
Integration, edit only Integration ID `1`, owned by `gha-publisher`,
keeping the same issuer, audience, ownership, capability scope, resource
selection, and all other claim rules.

| Claim | Before | Proposed |
|---|---|---|
| `repository_visibility`, operator `eq` | `private` | `public` |

The before/after rule objects are:

```json
{"claim":"repository_visibility","compare":"eq","value":"private"}
```

```json
{"claim":"repository_visibility","compare":"eq","value":"public"}
```

Do **not** broaden the rule to an empty value, wildcard, `in` list or
`private,public`. The existing exact repository, allowed workflow paths,
main ref, event restrictions and `write:package` scope are security controls
and must be preserved. Do **not** make the GitHub repository private merely
to satisfy this old rule; changing repository visibility is a separate
product/security decision and would have broader consequences.

The supported management path is **Forgejo > Settings > Authorized Integrations**
while signed in as the integration owner. If an administrator cannot edit a
different user's integration through the UI, do not reset credentials or create
an all-scope admin token. A separate, explicitly authorized, backed-up,
single-row update can be developed and tested only if the supported UI cannot
make the change. This document does not authorize database writes.

## Guarded execution plan for the future approval

1. Reconfirm the protected-main GitHub repository is still public, compare
   the six existing integration claim restrictions to the read-only baseline,
   and confirm Integration ID `1` still matches its original owner/audience.
   Stop if anything differs.
2. Preserve the exact current `claim_rules` JSON in a root-only, temporary
   operational evidence file before any change; no JWTs, passwords or
   secrets need to be copied. Ensure rollback is possible.
3. Make **only** the `repository_visibility: private` to `public` edit in
   the same Authorized Integration using its supported management interface.
   Do not delete/recreate the integration, because that would change `aud`.
4. Re-read the stored integration **without changing it again**. Verify all
   other rules, the issuer, audience, permission scope, owner and team
   relationship are byte-for-byte or semantically unchanged.
5. In a separately approved, non-publishing diagnostic, request a fresh
   GitHub OIDC identity **from the exact approved main-branch workflow context**
   and make one safe authenticated read to the restricted package API. Require
   a success response before any new publication. Do not expose JWTs in
   console, artifacts, URLs or screenshots. The diagnostic workflow must
   avoid new registry write permissions and must not publish anything.
6. If the read-only authorization check fails, restore the preserved original
   rule and **stop**. Investigate additional issuer/audience/claim problems
   separately. Do not relax additional claims speculatively.
7. Once the auth probe passes, obtain **separate** approval for a completely
   new release version (provisionally `0.14.5`) from its actual protected-main
   commit. Verify all registry destinations are unused before dispatching
   exactly once. Retain version `0.14.4` as partial historical evidence.
8. Independently verify the final Forgejo package roundtrips, schema-v2
   provenance/signature bundles, Sigstore OCI signature, exact digest and
   all tamper-negative tests. Keep DEV and PROD activation **NO-GO** until
   that downstream acceptance has passed and is separately approved.

## Rollback criteria

Before a controlled change, retain the original exact JSON object
`{"claim":"repository_visibility","compare":"eq","value":"private"}`
and the complete integration snapshot. On an unexpected permission, owner,
issuer, audience, scope or workflow change, or a failed authenticated probe,
restore the original complete claim rules via the supported interface,
re-read them, and end the operation. Do not delete the integration,
its publisher account, packages or zot image; do not revoke unrelated
credentials. The original 401 state is safe because it fails closed.

## Source-of-truth references

- GitHub's OIDC reference: `repository_visibility` reflects the actual
  repository visibility and can be `public`, `private` or `internal`:
  https://docs.github.com/en/actions/reference/security/oidc
- Forgejo Authorized Integrations: exact JWT claim rules, accepted bearer
  JWTs, integration capabilities and user ownership:
  https://forgejo.org/docs/v17.0/user/api/authorized-integrations/
- Forgejo package access: members with appropriate rights may publish
  to their organization: https://forgejo.org/docs/latest/user/packages/
- Actual failed GitHub release:
  https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39010764876
- Earlier successful, unpublished PR security acceptance:
  https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39009971055

**Boundary: REVIEW-ONLY draft PR.** No server configuration changed, no
registration/login altered, no static secrets created, no files published
to Forgejo, no release retried, no deployment performed.
