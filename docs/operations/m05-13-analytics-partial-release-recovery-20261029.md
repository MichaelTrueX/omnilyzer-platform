<!-- File: docs/operations/m05-13-analytics-partial-release-recovery-20261029.md -->
<!-- Purpose: Fail-closed recovery for immutable Analytics Task013 versions partially published to Zot. -->
<!-- Links: .github/workflows/platform-release.yml; release/analytics_publish_zot.py; -->
<!-- release/registry_absence_preflight.py; release/analytics_forgejo_evidence.py; -->
<!-- release/tests/test_analytics_publish_zot.py; deployment/saas_product_contract.py. -->

# Analytics Task013 — fail-closed partial-release recovery

## Security principle

Zot commits the immutable `omnilyzer/analytics:<version>` tag in the first
protected publisher job. The second job signs the digest using protected-main
Cosign/OIDC and publishes verified Forgejo Generic evidence. A failed second
job **does not roll back Zot automatically**. An OCI tag without verified
signed provenance is not a trusted Task013 release and MUST NOT be admitted
by Task014, installed in DEV, or promoted.

A failed post-PUT readback can likewise leave an occupied tag even when Zot
publisher itself returns failure. The original registry absence preflight is
intentionally fail-closed on an occupied version; do not weaken this check.

## Deterministic recovery procedure (operator-controlled; no automatic mutation)

1. Record the failing protected `platform-release.yml` GitHub run URL,
   `run_id`, `run_attempt`, requested immutable version, platform `main` SHA,
   exact Analytics source commit, failed job/step, and timestamp. Preserve
   existing run logs and artifacts according to approved retention.
2. Treat the version as **quarantined / NOT RELEASED**. Record the expected
   source-bound digest from the verified source claim if available. Using
   the original authorized, read-only Zot and Forgejo OIDC methods, inspect
   exact `omnilyzer/analytics:<version>` tag and digest, Generic
   `analytics-release-evidence/<version>` package presence, manifest and
   provenance signature bundles, and Cosign OCI signature against the
   pinned protected-main workflow identity. Distinguish 404 from 401/403/5xx.
3. Do not infer authorization from a tag alone, a successful upload-artifact,
   unsigned JSON, image layer hash, or an unverified Cosign bundle. A missing
   signature, unknown issuer/identity, missing Forgejo receipt, wrong digest,
   or failed Critical/High policy is **HOLD**. Task014 remains denied.
4. Never force-push, reuse, or overwrite the occupied version. No unreviewed
   registry `DELETE`, cleanup token, permission relaxation or automatic retry
   is allowed. If cleanup is strictly necessary, first preserve evidence,
   obtain explicit owner approval and separate registry-administrator review,
   document the exact immutable objects, and use the existing authorized
   registry maintenance mechanism. Do not assume deletion repairs the
   original release identity.
5. After source/security blockers are fixed and independently reviewed,
   request a **new**, unused immutable semantic version and fresh protected
   Task013 dispatch with `source_sha` equal to the accepted `main` commit.
   The same zero Critical/High, zero exceptions and complete signature,
   publication and readback gates apply unchanged.
6. Only after a **new successful** protected run verifies complete evidence
   and registry roundtrips may the separate signed Task014 process consider
   the exact OCI digest. Task014 requires its own authorization, runtime
   validation, installation and rollback proof.

## Current source blocker (2026-10-29)

PR #244 documents the actual Analytics OCI scan as **0 Critical / 54 High**.
The zero-High/zero-exception release gate must reject this image. Do not
initiate a public release or claim a green scanner from the synthetic unit
fixtures. Source remediation and a fresh actual pinned scan are required
before any publish/merge/release authorization.

## Regression coverage

`release/tests/test_analytics_publish_zot.py` simulates a Zot tag committed
before a failed authenticated readback. It asserts the publisher does not
emit a successful receipt, that the tag remains occupied, and that retrying
the same version refuses a second PUT. A separate test rejects registry
readback returning different manifest bytes. `release/tests/test_workflow_policy.py`
asserts the protected second job visibly marks a partial release as HOLD on
failure without automatic registry mutation or Task014 admission.
