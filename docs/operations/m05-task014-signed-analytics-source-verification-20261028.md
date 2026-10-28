<!--
FILE: docs/operations/m05-task014-signed-analytics-source-verification-20261028.md
PURPOSE: Explain an additive original Task014 signed release source-claim
         verifier without authorizing Analytics promotion or changing canary.
LINKED FILES: deployment/promotion.py;
              deployment/tests/test_analytics_signed_source_evidence.py;
              deployment/policy.py; deployment/release_consumer.py;
              deployment/saas_product_contract.py; deployment/execution.py;
              release/analytics_release_source_binding.py;
              docs/operations/m05-task013-analytics-external-source-evidence-20261028.md.
STATUS: DRAFT original signed-evidence parse only, runtime remains DENIED.
-->

# M05 - Original Task014 Analytics signed-source evidence verification

**Date:** 28 October 2026 (Asia/Manila)
**Source:** original Omnilyzer platform, additive on M05 Task013 PR233.

## Purpose and precise security boundary

This change extends the ORIGINAL `deployment/promotion.py`
`verify_release_evidence` function, not a parallel verifier or broker.

When the release is the existing synthetic Task013 canary, it retains the
same seven-field provenance schema and original `TrustedRelease` identity.
If either original signed document unexpectedly contains `external_source`,
the canary is rejected.

When the artifact repository is specifically `omnilyzer/analytics`, the
existing signature-verification path may read a strict
`external_source` claim in both original signed blobs. The claim must
match exactly in the original manifest AND original provenance. It binds
external Analytics Git source SHA/tree, platform SHA/tree, the complete
51-file source manifest, deterministic Git-only Docker context, OCI
Dockerfile and ignore hashes, product/runtime metadata, source repository,
whole-archive SHA-256, manifest digest and private `/readyz` readiness
contract.

The existing original Task013 provenance hash chain is verified BEFORE
parsing; original Sigstore release-manifest and release-provenance signatures,
protected-main workflow certificate/issuer and exact OCI Cosign signature are
verified BEFORE returning a `TrustedRelease` with its new immutable
`SignedExternalSource` projection. No caller-provided unsigned JSON mapping
is independently accepted as signature proof.

## Current denial remains intentional

**The normal original `PromotionRequest.from_dict` still denies
`omnilyzer/analytics` in `deployment/policy.py`.** Therefore the original
Task014 `release_consumer`, authenticated broker and installed executor still
cannot promote Analytics even if the two signed documents become available.

This distinction is deliberate: recognizing a validly signed external
source is NOT an authorization to install or run a product. Original
Task014 role-based runtime references, release allowlist, replay protection,
isolated blue/green slots, restricted secret material, origin path and
signed immutable-digest rollback are separate P0 deliverables.

Existing DEV canary0.14.6, rootless runtime source set, GitHub protected
workflow and all live system configurations remain unchanged.

## Tests and limits

Run locally, no registry login and no protected environment use:

```bash
python3 -m unittest -q \
  deployment.tests.test_analytics_signed_source_evidence \
  deployment.tests.test_promotion \
  deployment.tests.test_release_consumer
```

Actual isolated execution on 2026-10-28: **163/163 PASS** including
original execution, broker/executor and integration regressions. Tests
include old canary positive, Analytics unsigned normal promotion denial,
strict two-document source consistency, deterministic frozen source identity,
wrong platform SHA, wrong repo/product/ready/source count/hash, full OCI
archive mismatch, unknown/missing fields, wrong original certificate issuer,
false blob or OCI verification and canary with injected claim.

**Critical distinction:** Positive Analytics tests use synthetic
`sigstore_result`/`oci_signature_result` fixtures and synthetic signed
schema-shaped bytes. They establish strict Python release verification
semantics under the original validator's verifier interfaces. They do
**not** produce or verify an actual Cosign signature, run an authorized
GitHub Actions Task013 release, retrieve Forgejo/Zot registry evidence, or
deploy/rollback a real DEV product.

## Remaining original Task013/014 chain

1. Integrate verified Analytics Git-only OCI source context into ORIGINAL
   protected-main Task013 workflow, with separately approved short-lived
   cross-private-repository read authority. Preserve original canary release.
2. Build, scan and publish an actual immutable Analytics manifest through
   ORIGINAL Task013 Zot/Forgejo/Syft/Grype/Cosign path; attach the exact
   external-source pre-sign documents provided by M05 PR233.
3. M04 independently verify ACTUAL signed release bytes, source SHA,
   certificate identity, OCI registry digest and adversarial substitutions.
4. Only then extend original Task014 promotion request policy and
   verified release consumer with explicit Analytics-only product/version
   authority and scoped secret references. Reconcile original installed
   source set; do not use review metadata to bypass broker or executor.
5. Activate isolated private DEV blue/green application slot only after
   specific owner permission. Verify session/tenant/report, persisted
   events, canary parity and rollback to a previously signed digest.
6. Shared SaaS identity/Website Engine consumption remains a separate
   integration gap: matching Analytics Prisma models do not demonstrate
   actual use of the common platform services.

**Status:** code-level signed external-source claim parsing READY FOR
M04 REVIEW; actual signed Analytics DEV release and Task014 broker-managed
deployment remain NO-GO. Nothing live has been changed.
