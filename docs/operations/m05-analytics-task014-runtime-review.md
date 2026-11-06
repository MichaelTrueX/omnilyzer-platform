<!--
File: docs/operations/m05-analytics-task014-runtime-review.md
Purpose: Full Task013/014 versus Analytics comparison, real DEV evidence,
         minimum platform integration, and precise rollback handover.
Linked files: deployment/saas_product_runtime.py;
 deployment/products/analytics-runtime-dev.json;
 deployment/tests/test_saas_product_runtime.py;
 release/analytics_source_admission.py (M01 PR225);
 docs/operations/analytics-platform-bridge-20261027.md (M01 PR225);
 Omnilyzer Analytics PR42 and M05 PR45;
 docs/operations/task013-release-0145-acceptance.md;
 docs/operations/task014-dev-0146-acceptance.md.
Status: REVIEW ONLY. No signing, protected-main merge, broker install,
 DEV promotion, Nginx or production change authorized.
-->

# M05 — Analytics product runtime in the existing Task013/014 platform

28 October 2026, Asia/Manila. Task013 signing and Task014 immutable broker/executor already work for the SYNTHETIC 0.14.6 DEV canary on omnilyzerdev. This work reuses those components. Omnilyzer is a shared SaaS/website platform, NOT a CMS or a parallel distribution system.

The canonical Analytics product source is M01 PR42 (SHA 597a3415dfee76cc63f6ba70d3660f287a09b0c8) plus M05 OCI PR45, stacked directly on PR42. PR45 contains exactly three full new files: Dockerfile.analytics, .dockerignore, scripts/accept-m05-analytics-oci-dev.py. It reuses the already reviewed M03 root /livez and /readyz; no duplicate health routes. Former PR44 is CLOSED unmerged.

## Comparison and smallest necessary integration

| Concern | Original Task013 / Task014 platform | Analytics product | Minimum shared-platform delta |
| --- | --- | --- | --- |
| Git source | Protected platform-main SHA, exact release workflow and OIDC identity | Independent private Analytics Git SHA and reviewed source | Use M01 PR225 source-admission, repin to final PR45 package SHA, bind both source identities in SIGNED Task013 evidence |
| Build and provenance | Build once OCI, SBOM/Grype, Sigstore/Cosign, immutable Zot and Forgejo | Real pinned Node20 OCI package with locked Next14/Prisma6 | Add an Analytics variant to EXISTING Task013 release plan and build; never introduce a second signer |
| Release/promotion identity | Signed manifest, exact registry digest, OIDC broker, replay and audit | Local image digest only; NO signed registry publication | Add explicitly allowed Analytics product+repository/source-claim to Task014 consumer, broker and executor; preserve immutable digest |
| Secrets | Synthetic canary has NoSecretsReference | Four distinct secret names: DATABASE_URL, COLLECTOR_DATABASE_URL, JWT_SECRET, JWT_REFRESH_SECRET | Approved private secret reference and separated PostgreSQL roles; never store values in image/manifest/Git |
| Runtime | Only canary blue/green private Nginx and port3020 | Rootless Node20, container port3000, PostgreSQL16 dual role | Add Analytics-only slot to SAME Task014 Compose/executor, no canary replacement or public port |
| Health | Synthetic canary /livez, /readyz, /metadata | Reuses M03 root /livez and /readyz, no user data disclosed | Verify health and SIGNED artifact/release identity separately before slot switch |
| Database migration | Synthetic canary fixed migration/checksum | Analytics FORCE RLS, separate auth and collector SQL grants | Scoped product migration/rollback, installer/catalog reconciliation, all-writer fence; no data-reset on image rollback |
| Rollback | Previous signed digest, readiness gate, broker/executor audit and traffic switch | Isolated local QA containers destroyed; no activated Task014 Analytics slot | Analytics-only known-good signed digest rollback via original executor, preserve acknowledged events and Sessions |
| Multiple products | Reusable signing/execution mechanisms but fixed canary policy | Analytics first, independent Cybersecurity later | Reviewed per-product metadata and runtime ACL, same Task013/014 identity and broker; no new framework |

## Complete review-only implementation

Platform draft branch stacked on M01 PR225 adds:
- deployment/saas_product_runtime.py: pure strict metadata validator; explicitly DOES NOT sign or authorize a release, does not reimplement M01 source verification or grant installed broker authority.
- deployment/products/analytics-runtime-dev.json: exact Analytics DEV-only OCI repository and container port; private ingress, separate auth/collector PostgreSQL role requirement, root M03 health routes and four runtime secret NAMES (not values).
- deployment/tests/test_saas_product_runtime.py: 19/19 PASS, including invalid future product, canary impersonation, PROD/public ingress, unsafe rollback, duplicate JSON, incorrect port, missing collector DB secret, secret values, and symlink confusion.
- This document describes source, release, deployment, safety and future products.

The actual source-admission proof remains in M01 PR225, release/analytics_source_admission.py, and release/products/analytics-source.json. Its current committed source SHA pins pre-package PR42, so M01 MUST repin/retest against final Analytics PR45 integrated Git commit before Task013 signing.

## Executed genuine DEV package/runtime evidence

M05 built a full OCI image from canonical M01 PR42 plus the exactly copied three PR45 files on truexdevelopment. Local image ID:
sha256:0e570264fc2278198ad5aea8a9e185a7b028cc6a7dabf5f0f002a4860782dc05.

Actual disposable Docker Next14 + PostgreSQL16.15: 9/9 PASS. Runtime UID10001; no JWT/PG values in image Config.Env; real isolated PostgreSQL DB; liveness HTTP200; readiness 503 without needed tables/grants; readiness 200 with separately limited auth+collector columns; revoke collector Website.id returns 503; regrant returns 200; liveness remains 200; all temporary containers and network cleaned. Full runnable source: scripts/accept-m05-analytics-oci-dev.py in Analytics PR45. This is a real local container acceptance, but NOT a signed Task013 artifact or a Task014 broker-delivered DEV release.

Original live signed 0.14.6 canary remained unchanged. Its /metadata was independently verified with the required canary Host header on private 127.0.0.1:3020 (no public exposure).

## What is STILL required for an actual signed Analytics DEV release

1. M01 incorporate/freeze PR45 source with PR42 and repin PR225 exact external source SHA and full file hashes. M04 independently review the final combined tree and release identity.
2. Extend the ORIGINAL Task013 protected-main workflow to build, scan and sign this reviewed Analytics OCI with a SIGNED external-repo source attestation; reuse GitHub OIDC, Forgejo, zot, Cosign and existing vulnerability policy. Do not trust an unsigned external checkout.
3. Extend existing Task014 policy, broker/executor request, root-controlled installed application source set, private runtime secret-reference, per-product blue/green slot, approved migration and ingress. Preserve all canary identities and deployment state.
4. Obtain owner authorization for protected-main signer change, reviewed installed DEV broker/source generation, immutable release publication and one controlled DEV promotion. A draft GitHub PR cannot authorize the live broker, and no retry after uncertain signed publication without audit review.
5. Test actual signed OCI digest, provenance and source pin from Zot; broker acceptance, replay rejection, executor audit, selected Analytics slot and real health, auth/collector/Session behavior. Trigger the Analytics-only previously-signed known-good digest rollback through the SAME Task014 executor and verify canary unaffected.

Rollback is digest/slot and app-compatible schema, NOT overwriting PostgreSQL after acknowledged writes. Stop/writer-fence Analytics only, preserve Sessions and collector events, require adequate backup and forward-recovery. Existing DEV canary, other websites, prod Nginx/Cloudflare/DNS, shared platform role databases and customer sites stay untouched.

## Future modules

A Cybersecurity product adds a separately reviewed descriptor, signed independent source and digest, private DB and runtime secrets, health and rollback contract. The sign/verify/broker/execute chain remains the SAME Task013/014 machinery. Shared identity/tenant/Website Engine and customer websites do not require a new CMS or per-product deployment framework.

**Status: M05 OCI + runtime descriptor locally GREEN; Task013-signed Analytics publication and Task014 original-broker DEV deployment NOT YET DONE. This is a hard signed-authority and installed-runtime gating difference, not something to bypass.**
