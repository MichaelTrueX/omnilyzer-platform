<!--
FILE: docs/operations/m01-analytics-product-consolidation-20261028.md
PURPOSE: Single original-platform review source for M01 source admission,
         M05 Task013/014 product metadata, M03 readiness fixes and actual
         native-Path reader corrections. Distinguishes trusted source review
         from an authorized signed release and installed DEV deployment.
RELATED: release/analytics_source_admission.py;
         release/products/analytics-source.json;
         deployment/saas_product_runtime.py;
         deployment/products/analytics-runtime-dev.json;
         deployment/saas_product_contract.py;
         deployment/products/analytics-dev.json;
         deployment/tests/test_analytics_cross_repo_product_binding.py;
         MichaelTrueX/omnilyzer PR45; platform PR225, PR226, PR227, PR228;
         docs/operations/task014-dev-0146-acceptance.md.
STATUS: UNMERGED REVIEW ONLY; NO RELEASE OR HOST CONFIGURATION CHANGES.
-->

# Omnilyzer Analytics - one integrated Task 013/014 product contract

**28 October 2026. Source-only local DEV verification.**

## Fixed immutable source identity

| Boundary | Actual value | Control |
| --- | --- | --- |
| Original platform main, existing signed canary | `182ce8225e64903c56ab1ba5617c26a06cd83ed9` | Unchanged; current Task013/014 source authority |
| Canonical Analytics final source | `MichaelTrueX/omnilyzer@8648adba2db884cc78274080b9836ca46bafd630` | Exact OCI-packaged PR45 Git commit |
| Analytics historic R3/R4 manifest | `d5a8b056581e4f30d4e352d04492b0bf8f8b2560b3b01eda1c679a8b1a0d9a3e` | 29 original committed file hashes |
| Analytics critical source | 22 additional SHA256 Git blobs | Source+auth+prisma+UI+health+OCI build input |
| OCI desired repository | `omnilyzer/analytics` | Product-specific review metadata only |
| Internal application port | `3000` | Future independent private DEV slot |
| Health | `/livez`, `/readyz` | M03 runtime, dual-DB readiness |
| Runtime secret **names only** | `COLLECTOR_DATABASE_URL`, `DATABASE_URL`, `JWT_REFRESH_SECRET`, `JWT_SECRET` | References, never credential values |
| Session transport | JSON Bearer + `localStorage.accessToken` | Preserve currently approved product API compatibility |
| Tenancy | Product Workspace+Website schemas + PostgreSQL FORCE RLS | Product-bound security, NOT yet shared foundation identity API |
| Rollback | Prior verified immutable Analytics digest; preserve DB writes | No future destructive DB snapshot rollback permitted |

## Reconciliation and corrected bugs

This candidate is based on the latest M01 source-gate PR225 and retains the
complete M05 PR226 runtime source, M05/M03 PR227 strict SaaS product contract
source and M01 PR228 runtime loader correction. The original source binding
and product profile now both use exact packaged PR45 SHA and the actual
Next14 `/readyz` route, not marketing `/` or nonexistent
`/api/v1/readyz`.

Two different original profile loaders contained a concrete native-path bug:
`type(path) is Path` always rejects concrete `PosixPath` and `WindowsPath`
instances. The loaders now use `isinstance(path, Path)` and still deny
symlink inputs and raw string caller paths. Both complete profile files
are opened under the actual original platform test harness. A separate
cross-contract test checks source/OCI/port/health/secrets identity together
and confirms original Task014 still denies the unapproved Analytics image.

The independent `M02` Firefox+PG browser test of PR45 passed on a fresh
disposable local Next/PG instance (Issue #27, comment #6458060145).
It does not prove public hosted CMP, CSP/CORS or signed Task014 deployment.

## Genuine limitations, not softened by local green tests

The `release/analytics_source_admission.py` receipt is intentionally
`release_authorized=false` and `deployment_authorized=false`.
The original Task013 OIDC workflow builds/signs **canary only**; Task014's
actual policy, installed source-set, broker/executor, Compose, OCI registry
repository and runtime secrets contract remain bound to synthetic canary
`omnilyzer/task013-release-canary`. The profile objects in this review
do **not** change those original allowlists or grant authority.

The original platform's identity/Workspace/Website Engine abstractions
are not yet actually consumed by the Analytics product runtime; matching
table names and original-platform source admission are NOT shared-identity
integration. Current product JSON Bearer localStorage tokens and DB-backed
revocation must remain until a separate explicit identity design decision.

## Next genuine engineering and authorization gates

1. Add an explicit Analytics independent-repository source and OCI package
   to the ORIGINAL protected-main Task013 workflow and existing plan,
   including signed exact external SHA, SBOM, Grype and OCI manifest digest.
   No alternate signer or local image ID accepted as provenance.
2. Extend the ORIGINAL Task014 signed evidence consumer, sealed OCI
   repository allowlist and product identity with independently reviewed
   cross-repository signed claim. No manually constructed `TrustedRelease`,
   unsigned `signed_external_source`, or hardcoded "allow" shortcut.
3. Add a separate private Analytics blue/green slot, explicit secrets
   references, limited PostgreSQL roles, readiness checks and non-destructive
   rollback via the existing broker and executor. Preserve signed canary.
4. M04 must review exact combined source and provenance; any protected-main
   source-set transition, signed release dispatch or DEV activation requires
   owner approval. Only then run actual signed DEV ingest/UI/report/revoke/
   rollback acceptance, including canary and other-website parity.

No protected main, existing service, real database, secret, OCI registry,
DNS, Cloudflare, host Nginx or live deployment was altered by this work.
