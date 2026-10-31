<!--
FILE: docs/operations/m05-analytics-normal-release-procedure-20261029.md
PURPOSE: Record the permanent one-time integration acceptance contract and the ordinary Analytics release operator workflow, explicitly distinguishing shipped controls from missing executable capabilities.
LINKS: .github/workflows/platform-release.yml, release/analytics_source_admission.py, release/analytics_task013_build_candidate.py, release/analytics_release_source_binding.py, release/analytics_release_evidence.py, release/analytics_publish_zot.py, release/analytics_forgejo_evidence.py, deployment/analytics_signed_source_pin.py, deployment/broker.py, deployment/executor.py, deployment/docker_runtime.py, deployment/runtime/dev/analytics.compose.review.yaml, GitHub Issue MichaelTrueX/omnilyzer#27.
SECURITY: This document is not a deployment approval, signing identity or substitute for a verified signed release. No credentials, runtime secret values or arbitrary destinations may be placed in release inputs.
-->

# M05 – Ordinary Analytics releases (Task013 → Task014)

## 31 October 2026: operational entry checklist

Before preparing or dispatching Task014, use the
[Task014 pre-release checklist](task014-pre-release-checklist.md). It separates
ordinary-release checks from platform qualification and defines the evidence
needed before execution. The dated implementation table below records the
29 October assessment, not current installed state. Task013 Analytics 0.15.0
publication has since succeeded, and the owner-reported transport transition
reached `ready_for_signed_task014` on 31 October. Signed application acceptance
remains pending in this record. Current promotion code still contains fixed
0.15.0/source/run pins; subsequent-version repeatability remains unproven.


## 1. Permanent operator contract

Once the original protected Task013/014 product integration is accepted and installed, an ordinary change to the Analytics application **must not require a new platform PR, handwritten vulnerability report or new deployment code**. Product development occurs in `MichaelTrueX/omnilyzer`; the standard CI and protected release workflow must handle every new reviewed source commit. A protected production approval may be one click; no approval may bypass failed source, vulnerability, signature or runtime gates.

## 2. Intended standard procedure after one-time integration is proven

1. Merge a reviewed Analytics code change into the approved product branch after existing application, database, browser, authorization and collector tests pass. Record its immutable 40-character commit SHA; never use `latest` or an unsigned mutable branch as the deployed identity.
2. In GitHub Actions for `MichaelTrueX/omnilyzer-platform`, run the existing **Platform release** workflow with `product=analytics`, selected release version, exact protected platform workflow SHA and the reviewed Analytics source SHA. Its configured source access must validate that exact source automatically, not require changing platform files each time.
3. The same original Task013 job runs source-appropriate tests, pinned OCI BuildKit, real Syft CycloneDX SBOM and Grype with the existing no-exception Critical/High policy. A denial fails the run before any publication.
4. Under the original protected GitHub OIDC identity, generate and cryptographically sign original immutable manifest/provenance (including the exact external Analytics source), OCI digest and source/SBOM/scanner hashes. Authenticate separately to Zot and Forgejo, prove destination version absence, publish exact immutable OCI and Analytics Generic evidence and read both back byte-for-byte/digest-equivalent. Failure stops the run; no overwrite or fallback to unsigned receipt.
5. Original Task014 acquires and verifies those actual signed bytes and signature identity, checks the exact source/product/runtime profiles, obtains an authorized one-shot GitHub OIDC deployment request and installs the digest-pinned image in the isolated product slot. It must not share the canary port/Compose project, database role, secrets or ingress.
6. The deployed product receives four private file-backed secrets from the target runtime identity (not source/manifest or logs). Task014 verifies `/livez`, `/readyz`, real authenticated Workspace/Website/report, collector persistence, tenant isolation, session revocation, CORS/CSP and consent against the restricted PostgreSQL roles. Keep the previous exact signed digest and configuration for write-preserving rollback.
7. If deployment, functional health or promotion fails, return to the previous signed slot/ingress without deleting database writes. If the production environment requires an approval, use its one protected GitHub environment approval before actual traffic activation.
8. Preserve automated signed evidence, registry digests, workflow run IDs, tests, deployment result and rollback evidence for audit. No manual vulnerability spreadsheet or per-release platform-code modification.

## 3. Verified current implementation versus remaining mandatory work

| Boundary | Current verification at 2026-10-29 | Acceptance state |
| --- | --- | --- |
| Exact PR52 source binding | 78 Git identities and frozen product SHA | Current candidate PASS; **not reusable for next Analytics SHA** |
| Original Task013 build, Syft/Grype | Real unsigned PR52 OCI 0 Critical/0 High; original policy preserved | PASS on current candidate |
| Product-specific protected signing/publishing | Integrated PR244 contains the Analytics GitHub workflow branch, Zot, Cosign and Forgejo Generic publisher; local tests PASS | Not yet run from protected main; **hosted end-to-end HOLD** |
| Dynamic future product SHA | Workflow and source/build admission contain literal PR52 SHA; product pin contract requires fixed hash set | **NOT IMPLEMENTED: next ordinary release still needs code change** |
| Original Task014 signed Analytics consumer/executor | Reviewed signed source pin and product contracts exist; installed broker, executor and runtime are still canary-only | **NOT IMPLEMENTED** |
| Real DEV host/runtime | `truexdevelopment` Docker available but not verified rootless for product; four private secrets absent; restricted live DB backup/restore not accepted | **NOT READY** |
| Hosted signed OCI and actual DEV health/rollback | No protected signed Analytics workflow execution/registry readback/installed product | **NOT EXECUTED** |

## 4. One-time release acceptance requirements

Do not mark this integration complete until the following are evidenced by **one real protected GitHub Actions Analytics release** on the accepted source: actual source SHA not hardcoded into platform release infrastructure for future code revisions, automatic tests and real OCI scanner pass, original GitHub OIDC and Cosign signatures verified, immutable Zot/Forgejo exact digest readback, Task014 signed admission, installed isolated service with UID10001-mapped 0600 file secrets and least-privilege PostgreSQL, authenticated functional checks, real rollback, and one successful subsequent dry-run using a new approved product commit without editing platform release code.

The required next work is **executable code and actual runtime validation**, not another generic review or an unverified owner assertion. Existing canary must remain operational and fail-closed throughout.
