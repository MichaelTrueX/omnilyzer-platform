<!--
File: docs/operations/m05-analytics-task013-task014-release-integration.md
Purpose: Concrete M05 compare, minimal bridge and honest DEV release status.
Related: deployment/saas_product_contract.py,
  deployment/products/analytics-dev.json,
  deployment/tests/test_saas_product_contract.py,
  docs/operations/task013-release-0145-acceptance.md,
  docs/operations/task014-dev-0146-acceptance.md,
  MichaelTrueX/omnilyzer Dockerfile.analytics and app/readyz/route.ts,
  MichaelTrueX/omnilyzer issue #27 and pull request #36.
Authority: review-only source, no signed product release, live broker change,
  deployment, network exposure, DB migration or production permission.
-->

# M05 — Analytics via the existing Task 013/014 release platform

**Date: 27 October 2026. Status: PRODUCT PACKAGING AND CLOSED-ADMISSION PREFLIGHT; NOT A TASK014 DEPLOYMENT.**

## Comparison of the ACTUAL existing systems

| Release concern | Original platform Task013 / Task014 | Existing Analytics application (PR36) | Minimum integration |
| --- | --- | --- | --- |
| Source authority | Task013 protected platform main SHA + checked-in canary fixture | Independent private Analytics Git SHA on unmerged draft PR36 | Bind the exact Analytics Git object to the original signed Task013 provenance as a separately identified source; do not substitute it for platform GitHub OIDC identity |
| OCI build | Fixed Task013 canary Dockerfile, build once; immutable Zot manifest digest | Next14 application, Prisma6, separate collector role; previously no OCI recipe | `Dockerfile.analytics` (pinned Node base) and `.dockerignore`; build from reviewed exact Analytics source; scan and sign using EXISTING Task013 workflow |
| Release evidence | GitHub OIDC, Forgejo+Zot, Syft/Grype, Cosign, exact package/digest, replay protection | `rsync` and PM2 scripts; no signed product-bound artifact evidence | Extend existing release-plan/manifest and publisher to support an explicit Analytics product and external source evidence; do NOT weaken signer issuer/subject identity |
| DEV broker | Signature/evidence validator hardcodes `omnilyzer/task013-release-canary` | No Task014-compliant signed Analytics promotion | Add a strictly versioned product/profile identifier to the **existing** broker→executor request and reviewer-pinned installed allowlist; reject every unknown product |
| Runtime secrets | Task014 canary declares `NO_SECRETS_REASON` | Requires `DATABASE_URL`, **`COLLECTOR_DATABASE_URL`**, `JWT_SECRET`, `JWT_REFRESH_SECRET` | Bind explicit separate private runtime secret references via Task014's existing secret-reference trust boundary; never store values in Git, image metadata or signed manifest |
| Runtime | DEV task014 canary-blue/green, internal Docker network, 127.0.0.1:3020 proxy | Next14 on host port 3451; legacy PM2/Nginx routes, local dedicated PG | Add product-scoped blue/green services to Task014's existing Compose/executor; private port 3000 in container; do not replace/rename live canary or active production Nginx |
| Readiness | Canary-specific `/livez`, `/readyz`, `/metadata` | No private unprivileged application + collector PG readiness route | Private `/readyz` checks BOTH DBs and JWT runtime references; no secret/data disclosure. Platform must verify expected product/release identity separately |
| Database migration | Task014 canary has one fixed migration identity and check | PostgreSQL+FORCE RLS, Event ACL legacy PUBLIC policy, protected installer/rollback PR36 | Review separate product-scoped reversible expand/migrate/contract operation with external writer fence and true PG role catalog; never adopt the synthetic canary migration ID |
| Rollback | Task014 selected known-good OCI digest, health gate, blue/green traffic switch, audit/state | Legacy scripts do file backups and PM2 restarts; no complete immutable rollback | Register Analytics' previous signed known-good release and reroute only Analytics' private DEV ingress using EXISTING executor; no destructive DB restore after new writes |
| Stage isolation | Signed Task014 DEV canary accepted; STAGING and PROD disabled | Existing host stage on truexmainserver must not be altered | Preserve canary at 127.0.0.1:3020, develop Analytics in a separate private DEV service namespace, no public DNS/Cloudflare/Nginx/PG changes |
| Multi-module support | One synthetic canary hard-coded today | Analytics first, cybersecurity later | The product registry admits product profiles ONLY through reviewed allowlist and signed external-source binding; same Task013/014 services remain shared, no product-specific deployment daemon |

## What has been implemented on **separate unmerged draft branches**

1. Platform branch `feature/m05-analytics-task013-014-product-contract-20261027`: complete `deployment/saas_product_contract.py`, product-scoped source/profile `deployment/products/analytics-dev.json`, independent **20/20** standard-library tests. The admission helper **deliberately rejects** an otherwise plausible Analytics `TrustedRelease` until existing Task013 signed cross-repository source attestation and installed Task014 product authority are implemented and verified. This is a negative security gate, not an authorization shortcut.
2. Analytics branch `feature/m05-analytics-oci-product-package-20261027`, stacked on PR36 SHA `3743d9fd72de0b6dd62388782e10e07da0d77837`: complete OCI `Dockerfile.analytics`, root `.dockerignore`, internal non-sensitive `/readyz`. This introduces no cookie, session or JSON bearer changes and does not amend PR35/PR36.
3. **Read-only DEV Task014 baseline** on host `omnilyzerdev`: HTTP `GET http://127.0.0.1:3020/metadata` with `Host: canary-dev.omnilyzer.ai` returned the existing real signed canary `0.14.6`. Preserved intact.

## Mandatory steps to an ACTUAL signed Analytics DEV release

**No direct platform bypass is authorized.** M01 owns these integration source changes. M04 independently reviews each trust boundary:

1. Freeze reviewed exact Analytics source SHA and CI OCI build recipe, then pin a new product plan to its external Git identity; scan and sign immutable OCI via the EXISTING Task013 release workflow on protected platform main. Use platform's already qualified OIDC credentials/Forgejo/Zot/Cosign; produce authoritative manifest digest, SBOM, provenance and registry receipt. Do not use a local Docker image ID as a signed OCI registry digest.
2. Extend original `release.release_plan` / `release.release_consumer` and `deployment.policy` / `deployment.promotion` / `deployment.execution` with product ID and signed source binding, using explicit allowlists. The old Task013 canary must remain accepted unchanged. Do NOT construct a `TrustedRelease` directly from unsigned JSON or from a local tag.
3. Migrate the frozen installed Task014 DEV source set/config with independently approved, root-controlled stopped-service install and rollback. Preserve broker/executor single-use OIDC replay database, signing issuer/workflow subject and audit. The approved, current exact workflow SHA may need a guarded authority transition; a PR in GitHub has no such installed privilege.
4. Add one private product-scoped Analytics blue/green runtime to the original Compose adapter, separate from canary. Provide read-only, least-privilege runtime image/digest; synthetic DEV secrets stored only in host-approved secret location; isolated synthetic PostgreSQL roles and real DB readiness; tested migration and known-good rollback digest. Existing `omnilyzer-task014-dev` canary must continue to respond.
5. Only after the above: perform **one** authorized DEV dispatch through existing platform promotion workflow, verify broker request accepted, executor audit/state, chosen slot digest, health and private HTTP; then request rollback through the SAME executor and verify canary/Analytics isolation. Replays must be denied. Do not retry an uncertain request without reading protected replay/audit state first.

## Non-negotiable release gates

- No prod PostgreSQL or Cloudflare changes, no public collector enablement; PR35 stays separately approved for ingress.
- Never promote PR36 before separate M01/M04 real DB role/RLS and writer-fenced recovery approval; staging and production remain disabled.
- No JSON bearer/localStorage contract changes; no unencrypted stored real runtime secrets.
- Enforce exact product namespace, repository digest, platform signer identity, source attestation and stage; reject cross-product replay/digest/secret/rollback substitutions.
- A DEV package build or local smoke run is **not** a Task013 signed release or Task014 broker deployment.

## Future cybersecurity and websites

A future product adds a reviewed descriptor, its own signed source+OCI identity, independent secrets/DB and runtime/ingress profile. Task013 signing/evidence transport and Task014 broker/executor/replay/audit/blue-green machinery remain the **shared SaaS foundation**. Websites may have separate static hosting while consuming shared identity/security; no CMS/page builder or separate product deployment platform is added.

**Product DEV release STATUS:** open until the original signed OCI publication, protected DEV installer/source-generation and broker-authorized promotion/rollback are actually observed.


## 28 October 2026: M03 source/readiness contract reconciliation

**Review-only profile correction (M03).** The canonical Analytics PR #42 source is
`597a3415dfee76cc63f6ba70d3660f287a09b0c8`. M05 packaged that
same source without changing existing Analytics routes on child branch
`feature/m05-analytics-oci-on-canonical-pr42-20261028`, exact HEAD
`8648adba2db884cc78274080b9836ca46bafd630`. Its complete
`Dockerfile.analytics`, `.dockerignore` and private isolated OCI
acceptance script are additional files that MUST remain part of the
reviewed final source identity; an OCI image cannot be represented as
having the older PR42 SHA when its Docker build recipe was added later.

This revision pins `deployment/products/analytics-dev.json` to exact
`8648adba...` and the actual Next14 `/readyz` endpoint. The
`deployment/saas_product_contract.py` review-only closed readiness
allowlist is similarly updated to `/readyz`, with explicit tests
rejecting the absent legacy `/api/v1/readyz` path. Root `/livez`
remains process-only; `/readyz` checks required PostgreSQL credentials,
column privileges and auth config. The product profile contains only
secret **names**, never secret values.

**Unresolved cross-repository source authority:** M01's separate
`omnilyzer-platform` PR #225 `release/products/analytics-source.json`
still pins original PR42 `597a341...` and its exact critical source
hashes. M01 must independently reconcile and authorize the packaged
source's new exact HEAD and source/input manifest before Task013 can
sign anything. Do not silently update an already signed source
receipt or claim this isolated descriptor change authorizes a
`TrustedRelease`. `validate_existing_signed_release` continues to
reject unsigned external-source mappings. Existing Task014 canary
source allowlist, broker and executor remain untouched.

Source provenance is fixed at a published Git SHA for reproducible review.
Any later change to the product source, OCI recipe, runtime contract or
signed input requires a new explicit reviewed pin. This branch makes no
network, OCI registry, Task013 signer, Task014 broker, live DEV, database
or production change.
