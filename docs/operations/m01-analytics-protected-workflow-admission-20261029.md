# M01 — Original Task013 protected Analytics source admission

**File:** `docs/operations/m01-analytics-protected-workflow-admission-20261029.md`

**Purpose:** Record the first product-aware **read-only source admission** inside the EXISTING protected `.github/workflows/platform-release.yml` while preserving the original canary's publication and Sigstore authority. This is deliberately not a substitute signer or a release installation. The next change must bind publication and original Task014 admission to **the SAME signed, source-linked OCI**, not to unsigned source-review receipts.

**Linked complete source files:** `.github/workflows/platform-release.yml`; `release/tests/test_workflow_policy.py`; existing `release/analytics_source_admission.py`, `release/analytics_task013_build_input.py`, `release/analytics_task013_build_candidate.py`, `release/analytics_release_source_binding.py`, `release/vulnerability_policy.py`, `release/products/analytics-source.json`, `deployment/analytics_signed_source_pin.py`, `deployment/policy.py`, `deployment/execution.py`, `deployment/release_consumer.py`, and `deployment/promotion.py`. Original source release review: `MichaelTrueX/omnilyzer` PR52, Git SHA `4cdda7faeba57abb3388f9be5c450fe6afb1140d`; original platform PR244 accepted parent `3fe9549d38337d25c21d0193e81425dbaeee54ff`; coordination issue `MichaelTrueX/omnilyzer#27`.

## 1. Scope and exact product gate

- Add an explicit choice input `product` with only `canary` (default, historical release behavior) and `analytics` to the EXISTING, protected-main, workflow_dispatch workflow.
- Restrict existing OIDC Forgejo diagnostic and canary release `gate` to `product == canary`. Both preexisting `publish-zot` and `publish-forgejo` still strictly depend on the original **canary gate/build**, so Analytics cannot reach them by changing product name.
- Add ONE read-only `analytics-source-admission` job with `permissions: contents: read`, NO environment and NO `id-token: write`. It uses the identical SHA-pinned GitHub checkout action, first for the exact protected platform dispatch source and separately for exact Analytics PR52 SHA with full Git ancestry. Credentials are not persisted.
- Compare repository identity, protected `refs/heads/main`, requested SHA against actual dispatch/main Git SHA, exact original workflow ref and the pinned Analytics Git HEAD. Reject any mismatch before accessing source.
- Run only original `release.analytics_source_admission` and `release.analytics_task013_build_input` against the same checked-out 78-identity source. The original source helpers produce `release_authorized=false`, `deployment_authorized=false` and do not invoke a signer or broker.
- Product-specific concurrency separates canary and Analytics dispatches. No manually supplied OCI registry, URL, image, auth subject, JWT or package version affects the allowed product identity.

## 2. Boundaries deliberately NOT crossed

This source admission is a **review-only** original-workflow integration, **NOT** a completed executable Analytics Task013 release. In particular, the existing `build`, `publish-zot`, `publish-forgejo`, and Cosign evidence-production jobs still accept and publish only the canary's existing fixed artifacts. Original `deployment/policy.py`, `deployment/execution.py`, and `deployment/release_consumer.py` still restrict installed Task014 requests to the canary. Their allowlists MUST NOT be expanded in isolation.

To create a safely executable signed Analytics release, further coordinated engineering in this SAME original workflow/source-verifier/publisher/consumer chain is required: build the PR52 Git-only OCI using the pinned BuildKit0.24, validate every OCI blob and the exact source claim; generate Syft1.51 CycloneDX and Grype0.118 with the original zero-exception Critical/High policy; bind the OCI to the ORIGINAL protected-main Cosign certificate issuer and source SHA in BOTH signed release-manifest and provenance; publish exact digest only after authenticated absence checks on Zot/Forgejo; then extend the ORIGINAL Task014 verified consumer/promotion, broker and executor with a **separate product-scoped, signed-source-verified policy**, actual private UID10001 secret mapping, readiness and digest-preserving rollback. The previous M05 original Task013 OCI **unsigned** scan PASS does not by itself authorize publication/installation.

No protected-main merge, original signer workflow dispatch, live registry, active broker/executor, installed canary, production or real secret/DB mutation is performed by this review source branch.

## 3. Tests and negative decisions

On `truexdevelopment` against exact PR244 parent, new read-only job and existing unchanged canary authority were tested with existing `python3 -m unittest release.tests.test_workflow_policy` (22/22 PASS), plus **real** original source CLI against pristine Analytics PR52 exact checkout returning `source_files_verified=78`, `release_authorized=false`, `deployment_authorized=false`; `release.analytics_task013_build_input` separately bound exact product/OCI profile and refused release permission. The negative test checks that the Analytics job has no OIDC, environment, registry publisher, Docker push or Task014 executor call and that both original publisher jobs depend on canary gate/build only.

This test does not claim an actual GitHub protected-main workflow dispatch occurred: this is a DRAFT unmerged review change. Do not present it as working signed Analytics deployment.

## 4. Handoff

M04: review exact protected workflow control boundaries and tests. M05: the owner's explicitly granted authority remains subject to technical safety gates, so implement the remaining ORIGINAL publisher and signed Task014 product admission as a separately tested security boundary without a new pipeline. Merge/sign/install only after original protected workflow and host approvals, verified mapped UID10001 file-backed secrets, off-host DB backup, and a real isolated signed digest rollback. Preserve canary behavior and omit redundant PR52 source/browser/API test reruns absent code changes.
