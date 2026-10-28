<!--
File: docs/operations/analytics-platform-bridge-20261027.md
Purpose: Cross-repository Omnilyzer Task013/014 -> Analytics P0 source-admission,
         responsibility matrix, DEV evidence, no-bypass blocker and rollback.
Links: release/products/analytics-source.json,
       release/analytics_source_admission.py,
       release/tests/test_analytics_source_admission.py;
       deployment/promotion.py, deployment/execution.py, deployment/docker_runtime.py,
       docs/operations/task014-dev-0146-acceptance.md;
       MichaelTrueX/omnilyzer draft PR36 (3743d9fd...), Issue #27.
Status: REVIEW-ONLY. NO PRODUCTION INSTALL, MAIN MERGE OR DEPLOYMENT.
-->
# M01 P0: Analytics as first real product on original Omnilyzer platform

Date: 27 October 2026. Architecture: Model A, NOT a CMS.
Sources: `MichaelTrueX/omnilyzer-platform` main
`182ce8225e64903c56ab1ba5617c26a06cd83ed9`;
`MichaelTrueX/omnilyzer` PR36
`3743d9fd72de0b6dd62388782e10e07da0d77837`.
Canonical cross-chat communications: https://github.com/MichaelTrueX/omnilyzer/issues/27 .

## Executive finding

The platform already has Task013 keyless Sigstore/OCI signed build and publish
to zot + Forgejo and Task014 broker/executor, exact digest, OIDC source authority,
private ingress, rollback and rootless blue/green Docker. It really deployed a
**synthetic signed 0.14.6 canary** to DEV, and read-only check of
`127.0.0.1:3020/metadata` on `omnilyzerdev` returned its exact
`8d321e12...` source SHA.

The separately owned Analytics PR36 is a functioning Next14 + PostgreSQL
product. **It does not currently consume the platform's Task013 signer or
Task014 broker at all.** The two projects are not integrated by sharing the
Omnilyzer name, Nginx host or a GitHub account. There is NO approved Task014
Analytics software image and NO authenticated signed Analytics release at zot.

The critical blockers are actual closed, canary-specific deployment invariants,
not missing configuration documentation:

* `deployment/policy.py` allows OCI `omnilyzer/task013-release-canary`
  only. `promotion.py` and `release_consumer.py` pin the same identity.
* `deployment/schemas/executor-request.schema.json`, `execution.py`,
  `docker_runtime.py` and DEV Compose pin canary image, runtime/migration
  semantics, blue/green targets, paths, callback and `canary-dev` ingress.
* Task013 publisher, Sigstore claims and Task014 OIDC pin
  `MichaelTrueX/omnilyzer-platform` protected main and the exact reviewed
  workflow SHA. The platform's release plan assumes all build inputs are
  committed paths under that platform checkout; this cannot be bypassed with a
  mutable GitHub URL, copied .next directory or an unreviewed unsigned image.
* Current executor `NoSecretsReference` **explicitly requires zero secrets**
  for the canary. Real Analytics necessarily needs protected DB credentials,
  JWT access and refresh secrets. Reusing the canary's no-secret reference
  while injecting credentials would contradict the existing signed contract.
* Runtime startup probe expects canary `/livez`, `/readyz` and
  `/metadata` with marker semantics. The Analytics user-facing app and API
  require reviewed product-specific readiness and migration probes.

Do not mutate or widen these restrictions in the installed service to claim
an end-to-end release.

## Reuse/ownership matrix

| Capability | Original platform | Analytics PR36 today | Required integration |
|---|---|---|---|
| Git source and code review | Protected `omnilyzer-platform` main, reviewed workflow SHA | Independent `omnilyzer` draft PR36 | **Implemented:** exact commit + manifest + 5 critical-source hashes pinned in `release/products/analytics-source.json`; no mutable branch trust |
| Artifact build | Task013 platform wheel, npm, OCI build-once | Existing `next build`, manual/SSH scripts | Reuse Task013 OCI build and scanners after approved immutable cross-repo source staging; do not build a second signer |
| Provenance and signature | Task013 keyless Sigstore/Fulcio/Rekor, OCI cosign | None connected for Analytics | Reuse platform identity/verification; signed Analytics product publication **not yet authorized** |
| Registries / immutable references | Forgejo release evidence + zot OCI digest | GitHub source, ad-hoc host builds | Reuse both registries and exact image digest; no digest currently exists for Analytics |
| Broker / executor | Task014 restricted short-lived OIDC, replay, frozen digest, Unix executor | Product direct deploy scripts | **Platform only** manages new Analytics promotion; existing canary deny list remains intact until reviewed additive integration |
| Deployment and rollback | Rootless Docker blue/green, guarded source, audit, state recovery | `scripts/deploy*.sh`, vhost and Next process control | Retire/restrict overlapping product host deployment scripts AFTER protected DEV flow, retain database-specific app recovery |
| Product runtime | Canary app/metadata, loopback 3020 | Next14 process, API and dashboard | Separate product process and port, independent site ingress; no canary overwrite |
| PostgreSQL/backup | Deployment state/replay store, not Analytics business DB | Dedicated Analytics PG16 schema, tenant RLS, backup/archiver | Analytics retains OWN database, roles, migrations, point-in-time/offhost backup; platform owns only deployment ordering and rollback authority |
| Identity/session | Platform ADR proposes Keycloak/BFF; Task014 GitHub OIDC is CI deploy identity | JSON Bearer/localStorage, PostgreSQL Session revocation + Workspace memberships | **Keep existing product auth**, no Keycloak/cookie/Redis; deployment OIDC is a distinct trust boundary |
| CSP/CORS/consent | Global release/ingress policy | App exact CORS/CSP, tenant tracking, CMP | Product owns app behavior, platform owns immutable deployment; no silent header rewriting |
| Operations | Task014 broker/audit/status, guarded slot rollback | `monitor-and-restart.sh`, `deploy-dev.sh`, backups | Use platform release execution/audit, only product-specific health and database maintenance survive |

## Verified NEW integration slice (not represented as a signed release)

1. Source binding `release/products/analytics-source.json` explicitly pins
   Analytics PR36 SHA, the PR36 full source manifest SHA and critical source
   files that govern auth, database, dashboard and dependency lock.
2. `release/analytics_source_admission.py` verifies **exact committed Git
   blobs**, correct repository remote, exact HEAD, clean tracked files, all
   29 manifest files, size+hash, and the additional critical code/lock hashes.
   Unknown configuration, wrong repo, changed hash, symlink and traversal
   are rejected. Receipt has `release_authorized:false` and
   `deployment_authorized:false`, by construction. This is an adapter to
   the EXISTING release source boundary, not a second release engine.
3. Nine source tests pass against the actual PR36 Git worktree, including
   explicit rejection of `omnilyzer/analytics` through CURRENT Task014
   `deployment.policy.validate_repository`. No bypass of actual OIDC.
4. Direct isolated Analytics DEV on `truexdevelopment`, sourced from PR36,
   ran actual Next.js HTTP + a NEW PostgreSQL16 database with scoped collector
   policies. A specific new `omni_runtime` TO-role event RLS policy was
   required and added in the sibling Analytics QA draft branch; using
   `TO PUBLIC` is forbidden. Real API test gave **1/1 PASS**:
   signed JSON login, membership/tenant denials, accepted collector pageviews,
   summary from real PostgreSQL, refresh and token revocation.
   The test app connects with a disposable migration-owner credential to
   bootstrap the schema; SET LOCAL ROLE of a non-bypass runtime principal
   verifies FORCE RLS separately. **This does not certify the final app pool's
   non-superuser database credential or hosted data protection.** Synthetic
   roles/secrets and database are removed on test cleanup.
5. Original live signed DEV canary `GET /metadata` remains 0.14.6. It is
   independent positive evidence of the Task014 deployment mechanism,
   NOT proof that Task014 delivered Analytics.

## Exact shortest remaining authorized path

1. Independently review both source branches and accept a pinned Analytics
   input/OCI Dockerfile under Task013 using a source identity that cryptographically
   binds BOTH repositories' commits. Reuse existing Syft/Grype high/critical
   denial policy, Sigstore/Forgejo/zot and OCI digest. Do not build in an
   untrusted CI upload path.
2. Extend the reviewed closed Task013/014 allowlist **additively** for
   `omnilyzer/analytics`, including provenance source repository, original
   platform workflow OIDC identity, signed cross-repo input, new limited runtime
   config/secrets contract, ingress and product-specific readiness/rollback.
   Preserve the original canary as independently functional. Source bind and
   runtime identity must be verified at BOTH broker and privileged executor.
3. Approve a protected-main change to the signer/promoter workflow and
   independently activate DEV-only broker authority. Under the current
   main-only GitHub OIDC/Sigstore policy and owner-prohibited merges there is
   no legitimate way to produce an **authorized signed Analytics release**.
   This is an **external authorization blocker**, not a CI failure to bypass.
4. Deploy Analytics as a separate rootless product process/PG; use authenticated
   HTTPS API and actual browser dashboard checks, migrations + rollback
   conservation, host-level effective grants and dynamic CSP/CORS/CMP.
   No public DNS/Cloudflare/production changes without explicit owner approval.

## Rollback / safety

* **Current source-only candidate:** discard branch and any isolated temporary
  DEV instances. No installed Task014 state or existing app changed.
* **A future signed Analytics DEV activation:** stop only Analytics's controlled
  ingress/writers, ensure DB backup/WAL watermark and current Session/event
  preservation, revert exact Analytics image digest via Task014's existing
  rollback transaction, then verify prior sessions/routes and DB record
  conservation. Never roll back a database snapshot over acknowledged writes.
  Do not alter or restart the separate 0.14.6 canary, existing public SaaS,
  main/release registries or other Cloudflare sites.
* Deploy keys and JWT secrets cannot appear in a signed plan, Git repo,
  logs, OCI layers or client metadata. Dedicated secret references must be
  reviewed before allowing an Analytics executor request.
* Production remains NO-GO until M04 signed acceptance and separate owner
  deployment authorization. Historical accepted Task014 canary evidence is
  reused, not rerun as another isolated simulation.

## 28 October 2026: source-admission reconciled with consolidated PR #42

NEW EXACT REVIEWED INPUT is `MichaelTrueX/omnilyzer` PR #42,
commit `597a3415dfee76cc63f6ba70d3660f287a09b0c8`.
PR #42 is STACKED on PR #40, itself on PR #36. M02's exact five
source files from PR #39 and M03's exact five from PR #41 have been
incorporated without modifications. The new product acceptance checks
real `/livez`, `/readyz`, actual signed auth and PostgreSQL
reporting against disposable PG16: 1/1 comprehensive E2E PASS.
Broad Node tests: 237 PASS, 0 FAIL, one skip, eight historical TODO.
TypeScript and fresh Next14 build PASS.

The updated `release/products/analytics-source.json` now binds this
full PR42 HEAD, the unchanged historical PR36 29-file verified source
manifest and **19 additional critical complete source blobs** spanning
auth, sessions, Prisma schema, dashboard, Website isolation, explicit
tenant RLS app role, /livez, /readyz and real acceptance source. The
read-only verifier tests all 48 SHA256+size identities; this is still
**source admission only** with explicitly false release/deploy authority,
NOT a signed Task013 package or a broker ExecutorRequest.

This newer section supersedes earlier passages naming PR36 as the
latest ready source commit; that commit remains the immutable R3/R4
security baseline and historical manifest. Never switch the platform
to an unreviewed mutable Analytics branch or package a .next working
copy as signed source.

The actual platform signed-product release blocker remains open:
Task013 protected-main OIDC + original released source identity,
product OCI build, Task014 executor canary-only OCI allowlist and
product-secret/ingress/readiness contract require separately reviewed
changes and owner authority to merge and activate.

## 28 October 2026: final packaged Analytics source PR45 accepted for review

The FINAL exact review-only Analytics package input is PR45 HEAD
`8648adba2db884cc78274080b9836ca46bafd630`, stacked directly
on canonical PR42 HEAD `597a3415dfee76cc63f6ba70d3660f287a09b0c8`.
M05's three complete new files (`Dockerfile.analytics`, `.dockerignore`,
`scripts/accept-m05-analytics-oci-dev.py`) are now **mandatory** in the
same source SHA and Git blob-hash identity check, plus the previous 29
manifest and 19 critical source files = **51 SHA-256 file identities**.
Package recipe and exact anti-secret build ignore policy cannot drift or
be removed without a new reviewed source binding. The original PR36
security source manifest remains pinned unchanged, with PR42 and PR45
newer code independently checked in its exact final Git tree.

M05's original platform PR226 provides the separate fail-closed product
runtime profile stacked directly on this PR225 branch. Do not copy or
compete with it: the profile validates runtime identity, secrets NAMES,
private ingress, health routes and event-preserving rollback. It neither
authorizes nor executes a Task013/014 release. The Analytics OCI was
built and tested locally (M05 PR45) but is **not** a signed, published OCI
digest or an authorized Task014 promotion.

Task013 signer source workflow and Task014 protected deployment are
STILL canary-only. Real owner-authorized protected-main signer expansion,
signed multi-repository provenance and product-scoped executor contract
remain explicit external gates.
