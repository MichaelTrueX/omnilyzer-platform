<!--
FILE: docs/operations/m01-task014-analytics-signed-source-pin-20261028.md
PURPOSE: Record the original-platform signed external-source *review* check,
         its immutable exact PR45 product policy and current authorisation
         limitations before a signed Task014 product-aware broker is added.
RELATED: deployment/analytics_signed_source_pin.py,
         deployment/tests/test_analytics_signed_source_pin.py,
         deployment/promotion.py (M05 PR234; original signature verifier),
         release/analytics_release_source_binding.py (M05 PR233 pre-sign),
         release/analytics_task013_build_input.py (M05 PR231),
         release/analytics_oci_context.py (M01 PR232),
         deployment/products/analytics-dev.json,
         deployment/products/analytics-runtime-dev.json,
         release/products/analytics-source.json,
         deployment/release_consumer.py and deployment/policy.py.
AUTHORITY: PRE-DEPLOYMENT REVIEW ONLY. NO permission grant, new signer,
           installed broker, executor, active runtime or production change.
-->

# Task014 Analytics: pin verified signing evidence to reviewed product source

Date: 28 October 2026. All changes are on a separate review-only branch
stacked on M05's existing original-platform signed-evidence verifier PR234.

## Why this closes a separate trust boundary

M05 PR233 adds the exact external Git source claim to BOTH original Task013
pre-sign evidence documents, and M05 PR234 validates that the claim is
present and identical in the two original signed release blobs. Those
changes provide essential **signature and source provenance checks**.

However, a *legitimate signature* for some future Analytics Git revision
does not by itself mean that revision is in the currently reviewed
product release. The original platform still needs a separately reviewed
**specific source/product/runtime compatibility policy**. The additive
`deployment/analytics_signed_source_pin.py` performs this policy check
on the original `SignedExternalSource` projection and `TrustedRelease`
from M05 PR234.

## Closed exact identities verified

- Git source: `MichaelTrueX/omnilyzer` commit
  `8648adba2db884cc78274080b9836ca46bafd630`.
- Git tree: `5806948189acba458cd8b817db15a563ea3eebee`.
- Original 29-file R3/R4 source manifest:
  `d5a8b056581e4f30d4e352d04492b0bf8f8b2560b3b01eda1c679a8b1a0d9a3e`.
- Original M01 source-critical path set: 22 additional files,
  including Dockerfile, .dockerignore, auth/readyz/Prisma.
- Deterministic **Git-only** source build context:
  `d64d272944b775085ad62e9d8ef0f4be5b272fc87286f8f607d59105ccb4b818`.
- Product repository `omnilyzer/analytics`, port 3000, private
  `/livez` and `/readyz` health paths, independent restricted
  PostgreSQL auth/collector roles.
- Original committed product-profile canonical fingerprint (from
  `deployment/products/analytics-dev.json`).
- Original committed runtime-profile canonical fingerprint (from
  `deployment/products/analytics-runtime-dev.json`).
- Signed source OCI digest equals release OCI digest, and the exact
  `oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:...` image reference
  has the original pinned release workflow and certificate identity.

No digest from a standalone unsigned local BuildKit OCI export is
hardcoded as an authorized artifact: local OCI digests can differ between
build executions despite an identical immutable source TAR. A trusted
signed/published OCI digest must be verified by ORIGINAL Task013/014.

## What this module DOES NOT do

This function accepts the existing dataclass `TrustedRelease` for
review. Python dataclasses can be instantiated by a caller, so even an
exact positive match returns an **inert inspection receipt** with
`release_authorized=false` and `deployment_authorized=false`.
It **must not** be used alone as broker/executor permission.

The only permitted future authorization path is original, independently
audited `verify_release_evidence` with actual Sigstore/Cosign/registry
results and the original Task014 authenticated single-use broker/replay
controls, followed by a separate reviewed product policy and installed
executor approval. A forged locally constructed `TrustedRelease`
object, as used in synthetic unit tests, has NO deployment authority.

No modifications were made to original protected-main Task013 signing,
`deployment.policy.validate_repository`, Task014 release consumer,
broker, executor, Nginx, Compose or installed systemd services. Current
Task014 correctly denies `omnilyzer/analytics`.

## Completed regression evidence and remaining P0

- **197/197 local original Task014 signed-source, promotion, release
  consumer, broker, execution, broker-integration, SaaS profile and
  exact M01 source admission tests PASS** with an isolated Analytics PR45
  Git checkout and explicit source tests enabled. Original negative-case
  broker/evidence logs are expected fail-closed assertions, not errors.
- Tests reject wrong Git SHA/tree/context, profile fingerprints,
  signer/issuer/workflow, wrong or missing OCI digest, other product
  and unauthenticated/different claim shape.
- Existing synthetic canary release and canary-only repository policy
  remain intact.

**Strict release/deployment NO-GO persists** until the original
protected-main Task013 has actually signed/published Analytics with
an authorized external private repository source, original Task014
consumes *actual* verifiable signatures and enables a reviewed isolated
product executor with private nonembedded secrets, blue/green health,
separate PostgreSQL roles and immutable-digest rollback. Shared
identity/Website Engine runtime use remains another distinct P0;
current Analytics JSON Bearer/localStorage/session revocation must not
silently change due to a separate Sumlaude Keycloak/BFF identity plan.

No protected main or live/production runtime was modified.
