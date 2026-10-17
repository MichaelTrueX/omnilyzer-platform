<!--
File: docs/operations/task013-forgejo-oidc-auth-probe.md
Purpose: Authoritative Task 013 Forgejo OIDC incident and recovery record,
         including the actual publisher host, production integration repair,
         independently verified successful authentication, and release boundary.
Related:
  .github/workflows/platform-release.yml
  release/request_oidc.py
  release/forgejo_oidc_probe.py
  release/tests/test_forgejo_oidc_probe.py
  release/tests/test_workflow_policy.py
  docs/operations/task013-forgejo-oidc-visibility-recovery.md
  docs/operations/task013-forgejo-scoped-token-fallback.md (CLOSED PR #196 only)
Owner: Omnilyzer Task 013 release operations
Authority: Incident-record maintenance. No new release, package publication,
           Forgejo authorization change, DEV or PROD deployment is authorized.
-->

# Task 013: Forgejo GitHub OIDC authentication — RESOLVED (2026-10-17)

## 1. Executive result

**Authenticated Forgejo package API access is restored and verified
end-to-end from the actual allowlisted GitHub Actions workflow on protected
`main`.** No long-lived Forgejo PAT or replacement authentication scheme is
necessary.

- **Authorized publisher:** Forgejo Authorized Integration ID `1`,
  `github-task008c-publisher`, account `gha-publisher`, scope `write:package`.
- **Precisely corrected field:** `repository_visibility` equality rule
  `private` → `public`; all other integration rules and metadata preserved.
- **Actual public publishing service:** Forgejo v16.0.3 on
  `truexmainserver` (`46.62.147.181`), with Nginx forwarding
  `registry-dev.omnilyzer.ai` to loopback Forgejo port `3021`.
- **Successful nonpublishing GitHub runs:**
  [#39023482352](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39023482352)
  and
  [#39023494150](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39023494150).
  Both succeeded at protected-main SHA
  `6f1646ff05740df86ccf74de8fc9a05961ca8f17`.
- **Read-only probe proof:** all ten locally decoded header/claim comparisons
  reported `MATCH`, followed by the fixed
  `FORGEJO_OIDC_READ_ONLY_AUTHENTICATION_ACCEPTED` response.
  Each run returned a successful authenticated JSON package-listing GET.
- **Publication boundary:** in both runs, the release gate, build, zot
  publisher and Forgejo publisher jobs were **SKIPPED**; zero run artifacts
  were created. These diagnostic runs were not releases.

## 2. Incident background — partial release 0.14.4

On 2026-10-17,
[release run #39010764876](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39010764876)
for version `0.14.4` passed source/release policy checks, its OCI build,
Syft/Grype vulnerability gate, zot publication and local Sigstore signing
checks. Forgejo rejected the first PyPI upload with
`401 authGroup.Verify`. The npm/generic evidence destinations did not
complete, leaving `0.14.4` a **partial historical release**.

The existing immutable zot image `0.14.4` must never be overwritten by a
re-run of that version. **No DEV or PROD application deployment occurred**.

## 3. Two different Forgejo instances caused diagnostic confusion

The initial read-only and corrective steps examined an older instance on
`truexdevelopment` (`46.62.161.155`, Forgejo Docker loopback port `3010`).
That host carried a similar integration ID `1`, and it also required
`repository_visibility=private`. The resulting change and the
[failed read-only runs #39015221560](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39015221560)
and
[#39016477179](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39016477179)
did not test the database configuration actually serving the public registry.

Cloudflare's authoritative DNS record for
`registry-dev.omnilyzer.ai` already pointed, **intentionally**, to
`46.62.147.181`. Its routing was established on 2026-10-03 together with
`oci-dev.omnilyzer.ai` on `truexmainserver`. The public registry and OCI
routes must **not** be changed to point to the older development host.

Cleanup of the obsolete development instance was independently confirmed:
the temporary `write:package` PAT created only for diagnosis was revoked,
its local file destroyed, and the original authorized-integration claim-rule
baseline (`repository_visibility=private`) restored via a narrowly guarded
single-row transaction. No replacement publisher secret was installed into
GitHub. The obsolete documentation/replacement-token drafts
[PR #193](https://github.com/MichaelTrueX/omnilyzer-platform/pull/193)
and [PR #196](https://github.com/MichaelTrueX/omnilyzer-platform/pull/196)
were closed without merging.

## 4. Production-authoritative read-only preflight

On the **actual public registry host**, the owner ran an explicitly
privileged, read-only PostgreSQL inspection via:
`/home/trusthansen/forgejo-prod-auth-preflight-20261017.sh`.

The report, retained mode `0600`, is:
`/home/trusthansen/forgejo-prod-auth-preflight-20261017.json`.

That report found three GitHub Authorized Integrations. Publisher ID `1`
still required `repository_visibility=private`, although GitHub independently
confirmed `MichaelTrueX/omnilyzer-platform` is **public**.

The publisher's exact audience was
`u:2:316bec9a-53e4-4807-9557-7febdc979d0a`, matching the existing
`.github/workflows/platform-release.yml`. Its five other allowed claims,
issuer, publisher identity, non-admin status, organization membership and
package-only scope all matched the intended publishing contract.
The distinct promotion consumer (integration ID `3`) already required
`repository_visibility=public` and was not modified.

## 5. Guarded production correction and rollback

The owner explicitly executed the checksum-verified production script:
`/home/trusthansen/forgejo-prod-oidc-fix-20261017.sh`.

The script rejected wrong host/identity, validated the previously approved
read-only report and the original six-rule policy, and preserved the original
full integration metadata in a root-only backup:

- Before snapshot: `/root/forgejo-task013-publisher-id1-before-20261017.json`
  (SHA-256:
  `50e73699c356b8483d2111be6d176a01ab99ff4c32a4b6bd562de7d3d41a2f7f`).
- After snapshot:
  `/home/trusthansen/forgejo-task013-publisher-id1-after-20261017.json`
  (SHA-256:
  `34ec79db6339ed040c96399fdcad5437a2737515eaa0a0ff538113df12e28ded`).

One serializable PostgreSQL transaction checked the exact account,
publisher integration, issuer, audience, scope and every original claim;
verified publisher-team membership; then updated **one JSON claim value**.
It enforced an exact one-row change and compared the complete previous and
updated records inside the transaction.

A fresh independent database read compared both full snapshots and
confirmed that no other claim, identity, authorization field or update
timestamp changed. No service restart, static token, account mutation,
DNS adjustment, OCI publishing or release was necessary.

If rollback is ever separately authorized, use the original root-only
snapshot and a new guarded single-row operation. Never restore it
speculatively after the verified successful end-to-end authentication.

## 6. Postcorrection authenticated evidence

The unchanged, merged `platform-release.yml` workflow was run with
`auth_probe=true`, `source_sha` equal to the protected-main commit, and
`version=0.14.4` only as the diagnostic concurrency label. That value was
**not** published or rebuilt.

Both successful runs used exactly the original allowlisted
`workflow_ref` on `refs/heads/main`. Within the job, a fresh GitHub OIDC
JWT was requested for the publisher audience. The diagnostic verified only
static header/claim comparison results (never JWT content), then issued one
authenticated fixed HTTPS GET:

```http
GET https://registry-dev.omnilyzer.ai/api/v1/packages/omnilyzer?type=pypi&limit=1
Authorization: Bearer <short-lived GitHub OIDC JWT, never persisted>
```

The probe accepted HTTP 200 and a bounded JSON package list. Both GitHub
workflow conclusions were `success`, the diagnostic job alone was
`success`, and the four original release jobs were `skipped`.
Neither run uploaded a GitHub artifact.

Two runs occurred close together because an earlier diagnostic was already
in progress before a second dispatch was issued. Both passed; **do not
dispatch another diagnostic solely to repeat this proof**.

## 7. Next gate: a fresh coordinated release, not a diagnostic

The **OIDC authentication blocker is CLOSED**. A separate end-to-end release
publication and retrieval acceptance remains outstanding.

- `0.14.4` is immutable and partial; do not rerun or overwrite it.
- Before approving `0.14.5` (or a later unused version), confirm the final
  protected-main SHA, absence of that version at all zot/Forgejo destinations,
  release environment approval and security gate readiness.
- Obtain **separate explicit authorization** for a single publication attempt
  of the selected unused version. Set `auth_probe=false` (the default) and
  require all regular publisher jobs, not the diagnostic job, to succeed.
- Verify exact-byte PyPI/npm/generic evidence retrieval, OCI digest and
  schema-v2 provenance, Sigstore signatures, expected package identities,
  and fail-closed negative tests independently.
- Keep DEV and PROD **deployment NO-GO** until later deployment-specific
  acceptance and approval. Do not conflate this Task 013 fix with the
  separate Task 014 deployment-broker authority changes.

## 8. Security invariants retained

The existing exact issuer/audience, GitHub source and workflow rules,
`write:package` publisher permission, protected GitHub environment and
short-lived token flow remain unchanged except for the justified visibility
rule. Existing SBOM, Grype, Buildx, keyless Sigstore, provenance,
signed-release manifest, immutable registry object and rollback/acceptance
controls remain. The application authentication and localStorage session
token flow are unrelated and were not modified.
