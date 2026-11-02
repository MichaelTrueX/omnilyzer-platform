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

## Exact PR52 OCI security evidence (2026-10-29)

The **original pinned Task013** unsigned OCI run has now completed for exact
Analytics PR52 `4cdda7faeba57abb3388f9be5c450fe6afb1140d` and exact original
platform build source `b315601e74b68096a0c887b54d7aebed35ab7ca0`.
The retained sanitized machine-readable report is
`docs/operations/m05-pr52-oci-security-scan-20261029.json` (added by this
review follow-up), transcribed byte-for-byte from the original local scanner
artifact. It records Syft 1.51.0 CycloneDX 1.6, Grype 0.118.0, Grype DB
`2026-10-29T06:23:34Z`, **0 Critical / 0 High / 3 Medium / 1 Low**, zero
blocked findings and policy `PASS`. The source TAR SHA256 is
`c4474ae71ac2acf58876c9ab502e009c866fbeb29862ce991374b8396abf092f`.

These are **UNSIGNED local build and scanner results**, not a successful
protected-main workflow run or registry attestation. The image may produce a
different OCI digest when built again; never pin a different build's digest to
this receipt. The protected workflow must perform its OWN pinned actual scan
and source binding and must reject any new Critical/High or exceptions.
Release deployment, registry publication, Task014 and rollback acceptance
remain **HOLD** until separately authorized and genuinely verified.

## Regression coverage

`release/tests/test_analytics_publish_zot.py` simulates a Zot tag committed
before a failed authenticated readback. It asserts the publisher does not
emit a successful receipt, that the tag remains occupied, and that retrying
the same version refuses a second PUT. A separate test rejects registry
readback returning different manifest bytes. `release/tests/test_workflow_policy.py`
asserts the protected second job visibly marks a partial release as HOLD on
failure without automatic registry mutation or Task014 admission.
