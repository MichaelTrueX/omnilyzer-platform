<!--
File: docs/operations/task013-forgejo-oidc-visibility-recovery.md
Purpose: Record the verified 0.14.4 partial-release authentication failure,
         the approved one-rule Forgejo OIDC repair and its guarded recovery tests.
Related: .github/workflows/platform-release.yml, release/request_oidc.py,
         release/publish_forgejo.py, release/README.md,
         release/environments/dev.json, GitHub PR #192,
         GitHub Actions run 39010764876.
Authority: This version documents a separately user-approved live single-rule
           change. The draft PR itself remains documentation-only, and grants no
           merge, release, publishing, DEV or PROD deployment authority.
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

## Approved one-field correction - **applied 2026-10-17**

The owner explicitly approved editing the live Forgejo Authorized Integration
in this conversation on 2026-10-17. A guarded PostgreSQL transaction then
changed **only one claim-rule JSON value** in Integration ID `1`, owned by
`gha-publisher`, without recreating the integration. All other rules, issuer,
audience, ownership, permission scope, resource selection and timestamps
were compared inside the transaction and confirmed unchanged.

| Claim | Before | After |
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

The standard supported management path is **Forgejo > Settings > Authorized
Integrations**, signed in as `gha-publisher`. No interactive owner session was
available through the authorized connected terminal. The owner separately
approved changing the live rule, so a **single guarded direct database
transaction** was used instead. This path is exceptional, not a general
recommendation for routine integrations management. It did not create access
tokens, alter application code or restart either container.

### Executed transaction and preserved rollback evidence

Preflight reconfirmed the GitHub source was public and validated the six-rule
baseline, exact owner, issuer, audience, scope, and the record's pre-change
rules hash. Owner-only rollback snapshots were stored on
`truexdevelopment` with mode `0600`:

- Before: `/home/trusthansen/omnilyzer-security-evidence/forgejo-authorized-integration-id1-before-20261017.json`;
  SHA-256 `aa9c19f8a0e05116e0afc3bd2636c2c7526eb68c9d57e8f1b4717b3aa1a919b4`.
- After: `/home/trusthansen/omnilyzer-security-evidence/forgejo-authorized-integration-id1-after-20261017.json`;
  SHA-256 `ac9dbb26ad2035a4cecddf006bc6855814d25ce39292700ebc33d04ade20c6dd`.

The transaction used serializable isolation, row-level locking, a 5-second
lock timeout, exact preimage comparison and an enforced one-row update.
The transaction also compared the old/new complete record except for
`claim_rules` before committing. A fresh independent read compared both
snapshot JSON objects and proved that **only rule array element 2**
changed from `value=private` to `value=public`. Both Forgejo/DB
containers remained running. An unauthenticated HEAD to the Generic evidence
endpoint continued to return HTTP 401, so the registry was not accidentally
opened to anonymous users. **No OIDC bearer token or credentials were read
or copied.**

## Remaining acceptance plan - no publication authorized

1. **Outstanding live auth proof:** Request a fresh GitHub OIDC JWT in the
   exact allowlisted main-branch release-workflow identity, then use it for a
   **read-only** package API request without publishing. Neither an operator
   shell nor a pull-request CI job can synthesize the valid, short-lived JWT
   with the required `workflow_ref`. The current main workflow invokes
   publishing on success, so it must **not** be dispatched as an auth probe.
   A separately reviewed non-publishing diagnostic mechanism is necessary
   before claiming end-to-end authorization success.
2. If the eventual authorized read-only probe fails, restore the preserved
   original rule and **stop**. Investigate any additional issuer, audience,
   JWKS, claim or reverse-proxy problems separately. Do not speculate by
   loosening other rules.
3. Only after a successful authenticated non-publishing probe and **separate**
   release approval, use a fresh release version (provisionally `0.14.5`)
   from the protected-main commit. Check that every registry destination is
   unused before one dispatch. Preserve the partial `0.14.4` history.
4. Independently verify all package roundtrips, schema-v2 provenance and
   Sigstore signatures, OCI digest, and negative tests. DEV and PROD
   activation remain **NO-GO** unless separately accepted and authorized.

## Rollback criteria

The full original configuration is preserved in the mode-0600 before-snapshot.
On an unexpected permission, owner, issuer, audience, scope or workflow change,
or failed future authenticated probe, restore the original complete claim
rules through an approved, narrowly guarded mechanism, re-read and compare
the entire integration, and end the operation. Never delete the integration,
the publisher account, packages or the existing zot image. Do not revoke
unrelated credentials or regenerate its audience. The original private-only
rule will deny the current public repository and is the safe fail-closed
rollback state.

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

**Boundary: draft PR remains DOCUMENTATION-ONLY.** Its separate, explicitly
approved live one-rule Forgejo integration update is complete; no new
registration/login configuration, static secret, Forgejo package publication,
release rerun, PR merge, DEV activation or PROD deployment was performed.
OIDC end-to-end authentication has **not yet been demonstrated**.
