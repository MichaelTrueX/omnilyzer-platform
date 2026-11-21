<!--
File: docs/operations/task014-pre-release-checklist.md
Purpose: Give the delivery agent an evidence-based entry checklist for Task014.
Related: ../../AGENTS.md, m05-analytics-normal-release-procedure-20261029.md,
         ../../../.github/workflows/platform-promote.yml,
         ../../../.github/workflows/task014-c34d-review.yml.
Authority: Operational instructions only. No install, deployment or bypass grant.
-->

# Task014 pre-release checklist for ChatGPT

Read this before preparing any Analytics promotion, including a continuation in
a new chat. Resolve release-contract gaps before substantial product work.
Use the existing Task013/014 workflows, tests and canonical feature issue.
For actual known DEV failure modes, run the single read-only matrix from
[Task014 failure-prevention preflight](task014-failure-prevention-20261102.md).
For a DIFFERENT Analytics source/version, review the
[Task14B source/release identity impact matrix](task14b-release-identity-contract-20261102.md)
and keep dispatch on HOLD until its independent source approval and original
signed consumer contract are implemented and accepted.
The delivery agent owns this checklist; the owner should not relay routine
commands, collect test evidence or reconstruct the release inputs.

## Current accepted state: 16 November 2026

Analytics `0.16.0` completed the real signed private DEV promotion in
[Task014 #43838827603](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/43838827603).
The [canonical closeout](https://github.com/MichaelTrueX/omnilyzer-platform/issues/281#issuecomment-6913244435)
binds the exact signed image, source, installed authority, real HTTP/PG and
browser consent acceptance, preserved replay and actual `0.16 -> 0.15 -> 0.16`
maintenance OAT. That OAT had an explicitly approved one-time caller exception;
it is not a standing executor bypass. Its app tables were empty after fixture
cleanup, so nonempty event survival was not demonstrated.

**This completed release is not proof of ordinary release repeatability.**
The installed generation-3 coordinator remains first-successor-only. A next
product version and an ordinary post-success rollback require the supported,
reviewed executor path; do not reuse the consumed dispatch, OAT or installers.
Sections 5-6 below retain dated integration history, not current instructions
to repeat installation. Re-read current GitHub and live receipts before action.

The [owner's subsequent PROD instruction](https://github.com/MichaelTrueX/omnilyzer-platform/issues/281#issuecomment-6915187222)
targets this same signed0.16 artifact after the current work is complete.
No staging server is required: the intended route is accepted DEV -> PROD.
The disabled Canary-only `deployment/environments/prod.json` and DEV executor
are not an enabled Analytics PROD path. Qualify the actual production runtime,
configuration, secrets, ingress, recovery and applicable Issue280 security gates
before activation; a former staging-server requirement is not a blocker.

## 1. Decide which kind of work this is

| Kind | Expected work |
| --- | --- |
| Ordinary product release | New reviewed product source and signed image, compatible runtime/schema. Reuse the installed deployment platform. Run the per-release checks below. |
| Platform or environment change | Broker/executor code, workflow authority, systemd, transport, runtime profile, secret layout or database permissions change. Requalify the affected installed boundary before promotion. |
| First installation or migration | Explicit installation/migration plan, authority, backup and recovery. Do not disguise setup as an ordinary release. |

An ordinary release must not require a new deployment framework, host bootstrap,
handwritten sudo repair, infrastructure PR or manual vulnerability report.
If it does, record a platform-readiness blocker and fix its owning cause.
Do not weaken signature, source, tenant or replay checks to make it proceed.

## 2. Checks required before every Task014 promotion

Mark each item PASS, FAIL or UNKNOWN with an existing run/result/source link.
An unchecked box is UNKNOWN. Permission denied means UNKNOWN, not missing.
A failed or unknown required item blocks dispatch. A checked box without
evidence is not PASS. Read-only checks must report all independent mismatches
in one pass, rather than stopping at the first mismatch.

- [ ] **Current context:** Read AGENTS.md, the canonical feature issue and current
  PR/source HEAD. Confirm product, target environment, scope and authorization.
  Historical notes and conversation memory do not establish installed state.
- [ ] **Supported release:** Verify that the existing producer, request builder,
  signed consumer and installed admission support this product version/source.
  Check for literal version, digest, source and originating-run pins. A new
  version must be supported through the approved release contract; copying
  0.15.0 inputs or editing constants for every release is not reusable automation.
- [ ] **Exact identities:** Record all rows in the identity table below. Match
  the signed evidence to the intended product and image. Do not substitute one
  SHA for another, trust a mutable tag, or derive root authority from a request.
- [ ] **Task013 complete:** The exact release run succeeded, required tests and
  policy passed, and the immutable image, SBOM, provenance and signature bundles
  exist in the approved repositories. Enforce the accepted zero Critical/High
  release policy. Preserve the release; Task014 does not rebuild or re-sign it.
- [ ] **Authentication and read access:** Existing diagnostics/evidence confirm
  the deployment workflow identity can read the exact Forgejo evidence and Zot
  Analytics image/signatures. OIDC audiences, issuer, repository/workflow claims
  and the installed registry token protocol are correct. Do not assume an
  exchange extends token expiry. Successful manifest access does not prove
  complete large-blob streaming; require relevant size/digest/stream evidence. Registry authentication and
  repository read permission are separate checks. Never print tokens.
- [ ] **Installed authority - mandatory root-attested four-part gate:**
  Record one secret-free, source-bound `PASS` matrix for **the same current protected
  GitHub main SHA**: (1) original root-owned C32H
  `/etc/omnilyzer/deployment/broker/dev.json`, (2) independent Analytics broker
  `/etc/omnilyzer/deployment/broker/analytics.json`, (3) Analytics executor
  `/etc/omnilyzer/deployment/dev/analytics-executor.json`, and (4) the running
  original broker generation, loaded identity authority and restart/reload
  evidence following a source or config change. Inspect each file using the
  exact original schema, owner/group/mode and approved root read-only tool.
  Check the GitHub main SHA **again immediately before dispatch**. Any mismatch,
  unavailable protected read, unknown running generation, or later GitHub commit
  is a hard `HOLD`, regardless of Task013 signature, owner GO or CI success.
  A main commit, including a docs-only merge, changes the OIDC workflow SHA
  under the existing authority contract; defer merging or perform a separately
  reviewed root workflow-authority transition before another dispatch.
  Never confuse the two Analytics-specific files with original C32H authority.
  Do not silently rotate broker authority or repeat a real dispatch to diagnose it.
- [ ] **Runtime prerequisites:** Confirm the rootless daemon, approved image
  platform, private networks, slot/port availability and broker/socket state.
  Confirm image size and measured transfer capacity fit the operation, cleanup,
  response and edge budgets. An idle socket-activated executor need not be running. Unresolved failures,
  pending jobs or unknown deployment state require investigation, not a reset.
- [ ] **Secrets and database compatibility:** Verify approved secret names,
  ownership/modes and runtime access evidence without reading values into chat.
  Verify restricted auth/collector roles, FORCE RLS and schema compatibility.
  Classify any required schema migration and its writer/rollback implications.
  Do not rerun first-install database bootstrap for an ordinary release.
- [ ] **Recoverable state:** Identify the current signed image/configuration,
  candidate slot and approved rollback behavior. First install may require
  stop-only recovery. Confirm relevant recovery evidence and backup availability.
  Preserve existing writes, replay/audit state and unrelated applications.
- [ ] **Observable single dispatch:** Confirm no conflicting/uncertain request,
  capture the exact inputs and establish where run, broker, executor and
  application results will be inspected. Retain a once-only submission marker.
  An ambiguous submission is investigated before another request is sent.

### 2A. Prevent repeat Task014 failures before a signed dispatch (21 November 2026)

This section is mandatory for the single accountable M05 release owner. It
preserves existing Task013/014 security/approval/independent review, and does not
authorize or create a second deployment workflow, an extra test platform or an
automated retry.

**Release admission record for each distinct run (required, fail closed):**

| Evidence | Accept only | Otherwise |
| --- | --- | --- |
| GitHub workflow | Exact protected `main` commit SHA captured, then reconfirmed immediately before submission | HOLD |
| Original broker C32H | Root-attested canonical `broker/dev.json` `expected_workflow_sha` equals that exact SHA | HOLD |
| Analytics broker | Root-attested canonical `broker/analytics.json` `expected_workflow_sha` equals the same SHA | HOLD |
| Analytics executor | Root-attested canonical `dev/analytics-executor.json` `expected_workflow_sha` equals the same SHA | HOLD |
| Running broker | Exact reviewed source generation, loaded C32H authority; after a rebind, changed PID and healthy restart with unchanged signed active Analytics OCI and durable route | HOLD |
| Authorization | Fresh explicit one-run owner GO only after all preceding controls PASS | NO DISPATCH |

**Current exact implementation, still uninstalled:** Draft
[PR #315](https://github.com/MichaelTrueX/omnilyzer-platform/pull/315)
adds `--release-preflight` to its existing root-only one-time broker SHA
rebind operator. The command executes no mutation and exits nonzero if
the original C32H broker, Analytics broker and Analytics executor do not
share the same frozen `630db1ae...` workflow SHA and exact generation4
trust, if broker process timestamp predates the protected original
configuration, or if the signed0.16.0 active OCI/route is not coherent.
After M04 source/security approval and owner-authorized installation,
execute `--preflight` and `--apply` only for the exact reviewed one-field
repair, then execute `--release-preflight` **before requesting a separate
fresh owner GO/unique Task014 run**. Reverify GitHub protected main SHA
in the owner-side dispatcher immediately before submission. GitHub CI
cannot automatically inspect root-owned DEV config; do not represent
successful CI checks as this mandatory runtime preflight. No silent
reuse of this 630-specific code for a future workflow revision.

The M05 owner must **collect or reuse** one already accepted root-attested
read-only matrix for the *same* installed generation, configuration bytes,
running broker instance and GitHub SHA. Reuse is invalid if any of these changes.
If a root read is blocked by UID1005 isolation, do not report a presumed PASS:
use the existing reviewed, bounded, owner-attended root preflight **once**.
Do not require the owner to manually compare multiple files or interpret logs;
the script must return a closed PASS/HOLD matrix with no secret values. This is
a mandatory release gate and is not a new framework, workflow, or approval chain.


1. **Check the real request/admission contract, not just the producer.**
   Compare the exact protected GitHub workflow SHA, canonical successor schema,
   source/owner proof, prior/next signed evidence, broker generation and
   installed UID991 ordinary handler with the **actual** root-owned configuration
   and the live signed active/candidate images. Before dispatch, run the
   source-bound, focused existing producer/consumer positive and malicious-input
   cases covering this real generation and rollback state. Validate protected
   signer/registry access from the correct service security context when
   possible. A synthetic success does not verify a future live GitHub JWT;
   `task014_diag oidc_codes=ok` only checks **unverified CI-side claims**.
   Record any unexercised live OIDC/credential/security boundary as UNKNOWN,
   never PASS.
2. **Do not reintroduce solved historical incompatibilities.** Inspect the
   actually installed modules before diagnosing a new error. Historical fixes
   include the GitHub JOSE `x5t` acceptance in
   [PR #202](https://github.com/MichaelTrueX/omnilyzer-platform/pull/202),
   Forgejo Generic Registry `application/octet-stream` in
   [PR #203](https://github.com/MichaelTrueX/omnilyzer-platform/pull/203),
   and deterministic RootlessKit route-rule comparison in
   [PR #300](https://github.com/MichaelTrueX/omnilyzer-platform/pull/300).
   Those fixes are not a diagnosis of a different live request. Compare
   **the exact failing phase** and current installed source before changing code.
   Historical proof (not an identical-current-cause claim): on 18 October 2026,
   the old `_parse_compact_token` rejected GitHub's valid canonical JOSE
   `x5t` header **before RS256 signature verification**. An authentic
   synthetically signed token reproduced `OIDC token header is invalid` and
   HTTP 403 semantics. [PR #202](https://github.com/MichaelTrueX/omnilyzer-platform/pull/202)
   accepted only canonical 20-byte unpadded base64url `x5t`, retained RS256,
   validated `kid`, signature and every existing identity restriction.
   The reviewed source was installed by guarded root migration; the next
   real DEV run [#39107441829](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39107441829)
   returned **503 instead of 403**. This supports progress but the original
   October live JWT was never retained, so do **not** claim definitive
   historical-root-cause proof. The installed 21 November `oidc_verifier.py`
   already includes that exact `x5t` fix and its original tests.
3. **Correlate each error to one actual run and UTC interval.** Record the unique
   run ID and attempt, GitHub job start/end and protected workflow SHA first.
   Extract only bounded secret-free marker lines from the broker and UID991
   executor's existing journals for the exact UTC request window, using
   `journalctl --utc --since ... --until ... -o short-iso-precise`, then
   filter to `TASK014_ANALYTICS_BROKER_BOUNDARY phase=...`,
   `TASK014_ANALYTICS_UID991_HOLD phase=...` and
   `TASK014_ANALYTICS_SUCCESSOR_HOLD phase=...`. Never diagnose one request
   by reading the last 50 markers spanning several old deployments. A failed
   `Submit DEV promotion once` and a generic HTTP 403 or 503 are not a
   cause-specific exception trace. A marker with `outcome=passed` is valid
   only for its matching time-scoped request and component.
4. **Discriminate the security boundary before fixing.** HTTP 403 with
   `router_signed_response outcome=rejected` means a
   `BrokerRejectedError` propagated through the selected signed successor
   handler, **not** proof of a Docker, Unix socket, route or replay failure.
   If no preceding signed-review or replay markers occur in that request
   window, inspect the fail-closed early broker request/OIDC validation first;
   do not infer an OIDC root cause without a focused reproduction. A distinct
   `broker_unix_send outcome=unavailable` or
   `recovery_unconfirmed` belongs to the same incident only when its timestamp
   matches. Different branches of the same error-handling code may map to the
   same HTTP response. If fixed phase telemetry cannot distinguish the
   relevant boundary, make **one** minimal static, secret-free existing-module
   instrumentation change with focused regression and the required independent
   review before any new live signed attempt.
   **Nov 21 repeat failure guard:** Signed Task014 run `#44871118758` at
   `05:30:01.944473 UTC` proved `broker_verify_oidc outcome=rejected`
   *before* signed evidence review or replay. This **does not identify**
   signature-vs-identity denial. A green `task014_diag oidc_codes=ok` checks
   only unverified CI-side claims; healthy public GitHub JWKS discovery and
   working lookup of *one* current key cannot authenticate a historical JWT.
   Compare actual real same-run JWT **verification vs authorization**
   boundaries, using only private allowlisted fixed phase codes and
   security-reviewed code. The original verifier and policy Git blobs matched
   those of the successful earlier first successor release; do not weaken
   JWT algorithm/header, audience, issuer, key provenance, GitHub workflow
   SHA, time or identity constraints, or guess that old x5t fix has regressed.
   If existing telemetry groups multiple rejection causes into a single phase,
   fix the missing **secret-free precise phase classifier once** with focused
   tests and independent security review *before* a newly authorized request;
   do not send multiple live releases merely to learn where a 403 happened.
   **Required pre-dispatch OIDC acceptance record, reused per unchanged
   installed source/policy instead of adding generic pipelines:**

   | Exact control | Evidence needed | What does NOT count |
   | --- | --- | --- |
   | JOSE header/RS256 | Run the existing real-RS256 synthetic-JWT `test_oidc_verifier.py` positive with valid `x5t` and `kid`, plus tampered-header, malformed `x5t`, duplicate header and non-RS256 negatives | Only checking JWT payload/claim values |
   | Three bounded audiences | Verify deployment, Zot and Forgejo tokens through the existing cryptographic verifier and negative audience/issuer/cross-token tests, not one shared audience | A successful Zot-only `auth_probe=true` or public JWKS fetch |
   | Signed identity policy | Check source-pinned repository/actor, `workflow_ref`, `workflow_sha`, `ref`, environment, event and token times/expiry; compare to actual installed root config and pinned protected main | A CI `oidc_codes=ok` computed from **unverified** claims |
   | **All three workflow SHA pins** | Verify exact root-controlled `expected_workflow_sha` in original C32H `broker/dev.json`, separate Analytics `broker/analytics.json` and `dev/analytics-executor.json` matches protected GitHub main; prove running original broker reloaded `dev.json` after any reviewed rotation | Only checking the Analytics broker/executor pair or live `/readyz` HTTP200 |
   | Broker integration | Reuse existing source-bound real-signature positive/negative broker admission tests whenever verifier, caller or identity boundary changed; observe protected replay and no mutation on failures | A GitHub workflow gate PASS, /readyz HTTP200, synthetic collaborator that skips cryptographic verification |
   | Incident verdict | After rejection, one exact run/attempt/UTC window of fixed protected phase markers, broker replay status, and a proven matching source defect before repair | Another undiagnosed 403, a generic `broker_verify_oidc rejected`, or old runs' log tail |

   **Boundedness:** No production JWTs, signatures, JTI, exception messages,
   claim values, secrets, raw headers or private keys may be retained in
   GitHub, logs, chat, debug output or a new telemetry stream. The existing
   non-promoting `auth_probe` verifies a different Zot credential path, not
   broker-side deployment-JWT verification; it may be reused only within
   that documented scope. If a live signed broker token cannot be verified
   without dispatch, explicitly record that limitation as UNKNOWN; do not
   claim a substitute test passed, or send repeated releases solely for
   diagnostics. Retain the original Task014 mandatory independent security
   review and owner approval; avoid any new general infrastructure.
   October JOSE compatibility and November OIDC denial are **related
   failure boundaries, not proven identical root causes**.

   **21 November 2026 confirmed omitted authority:** Real signed Task014
   run #44876028251 at 06:33 UTC failed HTTP403 with protected
   `broker_oidc_identity outcome=rejected`, then
   `router_signed_response outcome=rejected`. Owner-native root read proved
   original broker `/etc/omnilyzer/deployment/broker/dev.json` still
   pinned `c6d6b067f932e60d82f8b7a9d75a2629a62606c8`, although both
   Analytics-specific root configs and GitHub protected main were at
   `630db1ae5a05a691493764637e066e487f52f599`. The real
   `analytics_broker_service.py` verifier gets its SHA from the *original*
   config, so verifying only Analytics-specific files missed a release-blocking
   mismatch. Independent scoped fix is draft PR #315 (one-field rebind,
   original service restart and private route preservation). The prior
   owner-approved new run has been consumed and must NOT be retried; no
   source merge, root install, or new signed dispatch is implied by the
   documentation. Do not claim the historical JWT's other claims or
   cryptographic result were independently retained.

5. **Establish durable postfailure custody before another request.** Read the
   protected broker and executor replay status for the **specific run ID**,
   root-owned route phase, slot-retirement intent, exact signed active/candidate
   image/container and any recovery HOLD using authorized read-only methods.
   `ROUTE_PHASE=switched` and `RETIREMENT_PHASE=NONE` do not by themselves
   prove whether a **different** request's replay JTI was consumed.
   Never replay a previous run/attempt/JTI, reset the replay DB, restart
   an executor to clear a result, stop/remove old signed containers or send
   a second signed Task014 request on an unexplained 403/503. Preserve all
   previous receipts and known-good serving images. Fix the demonstrated
   owning component, complete necessary source/security review, source-bound
   installed acceptance and authorized state reconciliation once, then use
   a **new** owner-authorized signed run only after the gates genuinely pass.
   Keep Task013 immutable and PROD unchanged unless separately authorized.

**Observed example, NOT a finished release:** [Task014 #44866000599](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/44866000599)
on 21 Nov 2026 failed at 04:25:31 UTC with HTTP 403. Its **time-filtered**
broker journal shows only
`TASK014_ANALYTICS_BROKER_BOUNDARY phase=router_signed_response outcome=rejected`
at `04:25:31.603896 UTC`; broad historical `tail` output also contained
older `broker_unix_send`, `broker_replay_consume`, `broker_executor_receipt`
and `recovery_unconfirmed` markers that **must not** be attributed to this
run. Owner read-only postfailure observation was
`ROUTE_PHASE=switched; RETIREMENT_PHASE=NONE; ACTIVE_SLOT=green;
ACTIVE_DIGEST=sha256:a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1`.
A later authorized read-only lookup found `ABSENT_OR_PRUNED` for this
run's replay row; that is **not** proof the row was never consumed.
The original exact first `BrokerRejectedError` cause remains **UNKNOWN**.
At the subsequent separately authorized [Task014 #44871118758](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/44871118758)
(21 Nov 2026 05:30:01.944473 UTC), the newly installed D4A private
broker emitted `broker_verify_oidc outcome=rejected` followed by
`router_signed_response outcome=rejected`. The replay lookup again returned
`ABSENT_OR_PRUNED`. This proves an early actual OIDC verification or identity
reauthorization boundary rejection, **not** whether header, `kid`, RS256,
issuer/audience, identity or time caused it. Public GitHub JWKS disclosure
and cache lookup were successful, and current installed `x5t` tests exist,
so repeating PR202/other historical repairs without an exact reproduction
would be a new error. The fixed-phase diagnostic source in existing draft PR313 at
`330f3255f0067b9ddbe30d50466830bd71a55a11` was **subsequently
installed on DEV** through an independently reviewed, owner-attended root
cutover. Its historical 191 focused tests and seven GitHub checks support
source qualification only, not successful signed0.16.1 promotion.
A subsequent authorized third Task014
[run #44876028251](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/44876028251)
failed HTTP403 at `broker_oidc_identity`. Owner-root evidence proved the
original C32H broker pinned `c6d6b067...` while the Analytics broker,
executor and protected GitHub main used `630db1ae...`.
The one-field correction is still **uninstalled, draft PR315** at HEAD
`8255193bae78187ec0dfa3cf0146ed5fb8c4075b` (source SHA256
`1c08877d859e1d8ffa09400cda93dd16f36824d21fc9d31fd8f369410a818fec`).
M04 technical review found and corrected an interrupted-rollback defect;
61/61 focused source tests and separate fault injections PASS. This is NOT a
formal independent M04 approval, actual root rebind or triple-config preflight.
All three historical Task014 attempts are closed failed events.
**Analytics 0.16.1 remains NO-GO on DEV; signed0.16.0 remains serving.**
**NO blind redispatch, Task013 rerun or PROD promotion.**

**Operational safety while the 0.16.1 release is pending:** The protected
`main` SHA `630db1ae5a05a691493764637e066e487f52f599` is pinned by the
currently installed workflow/DEV authority. Even a documentation-only merge
to `main` changes GitHub OIDC `workflow_sha` and can invalidate the
pending dispatch. Stage instructions in a **separate documentation branch**
and merge only after the current signed deployment authority is deliberately
reconciled. Do not alter the installed immutable
`analytics-app-release-330f3255f0067b9ddbe30d50466830bd71a55a11`
source to "apply" this document. The earlier `6acbdc1` and D4A references
are historical evidence, not the current installed DEV authority.

### Release identity record

| Field | Required source of truth |
| --- | --- |
| Product and environment | Approved feature/release scope and product/runtime profiles |
| Product source SHA | Reviewed application commit, bound in signed source evidence |
| Task013 platform source SHA | Platform revision recorded by the originating signed release |
| Task013 originating run ID and version | Successful immutable release evidence |
| OCI repository@sha256 digest | Signed release and registry readback |
| Manifest/provenance/source-claim hashes | Verified signed evidence; authenticated lookup only where the existing workflow supports it |
| Task014 workflow SHA | Exact revision to execute, matching independent installed broker authority |
| Installed deployment source SHA | Actual approved broker/executor source generation; distinct from product source |
| Product/runtime/Compose identities | Approved signed/runtime contract and matching installed configuration |
| Current state and rollback target | Actual deployment state and approved previous release or stop-only plan |

## 3. Baseline qualification: first install or affected platform change

Reuse accepted evidence when the relevant source, configuration and environment
are unchanged. Record what invalidates it. Do not restart healthy services or
repeat destructive/privileged probes for every product release.

| Boundary | Required joined proof | Requalify when |
| --- | --- | --- |
| Installed source and configuration | Exact source archive/config/approval delta, closed installed tree, and real loader output consumed by startup. Preserve field projection between Canary and Analytics identities. | Source-set builder, loader, config schema or installed generation changes. |
| systemd and rootless Docker | Actual service UID/GID, loaded unit/drop-ins, sandbox mounts and daemon access inside the executor namespace; coexistence with Canary start/stop. Host path visibility alone is insufficient. | Unit, namespace, socket binding, daemon layout or host/systemd behavior changes. |
| Broker-to-executor transport | Actual Analytics sender through a PID1-created listener, expected peer identity, framing and kernel-sealed descriptor transfer. Wrong peers/paths/inodes are rejected. | Shared transport, listener path/owner, service identity or activation configuration changes. |
| Registry credentials and verification | Real approved OIDC authentication, verified token semantics and read access; signed evidence verification through the installed consumers. | Reader/verifier, registry policy, workflow identity, realm, audience or blob-stream deadlines change. |
| Recovery | Stop confirmation, exact publication/readback, interrupted-write evidence preservation and stopped recovery using the installed lifecycle contract. | Cutover, unit publication, source/authority layout or recovery logic changes. |

Use the existing C34D workflow and its native systemd qualification for these
regressions. The native harness in
`deployment/tests/accept_task014_analytics_recovery.py` is guarded for an isolated
CI runner. Do not run it against the live DEV host. Any owner-local platform
transition must be separately scoped, exact-byte reviewed and recoverable.
Invalid-request probes must stop before credentials, replay or deployment;
their rejection proves only that boundary, not successful application deployment.

## 4. Execute and establish completion

After every required entry check passes, submit one request through
`.github/workflows/platform-promote.yml`. Preserve all existing signature,
source, OIDC, environment and replay gates. Monitor the resulting run through
broker acceptance, executor result, exact running image and application health.

Completion requires evidence for the agreed real application journey: private
readiness, login/session behavior, collector/event persistence, cross-tenant
denial, approved network/CORS/consent boundaries, coexistence and recovery.
Use designated synthetic acceptance data and non-destructive procedures.
Never run an isolated fixture script that creates/drops tables on the live DB.
Reuse unchanged accepted proofs where appropriate and state their scope.

On failure, stop automatic retries, preserve audit/journal/invocation and
deployment/replay state, and collect the full relevant mismatch set. Reproduce
the owning defect with the real producer/consumer or native boundary before a
repair. Reconcile the installed state before asking for privileged changes.

Publish one concise result in the canonical issue using this record:

```text
Product/environment/version:
Release and deployment identity table: [link]
Entry checks: PASS / BLOCKED; evidence and any unknowns:
Baseline qualification: retained proof / changed boundaries and new proof:
Dispatch run and outcome:
Exact deployed image and real application acceptance:
Rollback/recovery evidence and current state:
Remaining blocker and next action:
```

## 5. Historical V3 handoff: 9 November 2026 — superseded by acceptance above

**Historical pre-install state; DO NOT repeat these completed operations.**
At that time distribution was accepted and installation was still HOLD. The original signed
[Task013 run #42534753909](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/42534753909)
produced a real Syft/Grype zero-Critical/High, Zot+Forgejo+keyless-Cosign
signed Analytics `0.16.0` (immutable
`oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1`)
from reviewed product commit `a86a9b5e6a72afac05628e85335cbdf47c6f0255`
and protected Task013 platform `d18f8f5cab4be0be7873472c26d44d5d9c42a195`.
M04 independently reviewed the actual signed job/log evidence in Issue #281.
This is not proof of installation, private green3142, tenant isolation or
write-preserving rollback. Do not dispatch Task013 for occupied `0.16.0`
again; do not silently repin 0.15.0 as the successor.

**First source-integration step:** The existing protected
`platform-promote.yml` is being extended with *explicit*
`analytics_successor=true` (default false), using the original
`validate_analytics_successor_ci_inputs`,
`resolve_analytics_successor_ci_release_inputs`, and
`build_analytics_successor_ci_request`. It requires the reviewed product
commit, canonical owner source approval SHA256, exact Task013 source SHA,
originating run, OCI digest, root-reviewed installed source commit and the
currently *observed* active signed rollback digest/slot. The three optional
release metadata hashes must be ALL supplied or ALL empty for the original
authenticated Forgejo resolution. CI source, token decoding and caller
supplied slot fields are **NOT independent root release authority**.
The original 0.15.0 schema2 path is preserved without a successor flag;
Canary cannot use successor fields. Gate failure occurs before OIDC and POST.
The workflow, CI input tests and V3 unsigned source review must pass
independent M04 review and merge protection before they are operational.

**Mandatory independent root installation rebind:** A new protected Task014
main commit changes the **GitHub OIDC workflow SHA**, but the original
DEV broker and the inactive owner-staged V3 candidate still reference the
historically approved workflow generation. Do not send a live successor
request until one reviewed owner-root procedure, in the original DEV
maintenance/recovery scope, independently:
1. Verifies actual protected main SHA, original signed Task013 evidence
   and owner Ed25519 source approval, complete exact installed source/26
   hashes, root metadata, original signed 0.15.0 and recovery assets;
2. Rebinds the existing root-owned C32H broker workflow authority and the
   independently root-owned V3 Analytics broker/executor source configs to
   the SAME exact new protected Task014 workflow SHA. The unsigned
   `build_unsigned_analytics_activation_inputs(...,
   owner_authorized_first_successor=True,
   approved_workflow_sha=exact_reviewed_main_sha)` generates bounded
   canonical review bytes only. No CI/request/HTTP parameter grants root
   installation or canary source/role/permission changes;
3. Installs only the originally reviewed V3 generation3 positive
   broker/executor source selection and paired immutable systemd drop-ins,
   with rollback receipts and an exact loaded-unit examination. The
   original immutable V1 0.15.0 image and blue3141 writer remain preserved;
4. Verifies original protected Canary/Analytics service separation, UID990
   broker/UID991 executor, socket sealed-FD+peer identity, Sigstore trust
   and private Zot/Forgejo OIDC read access, rootless Docker, RLS+DB writer,
   owner source signer and journal/backup recovery before a single V3
   Task014 dispatch;
5. Runs one real protected private signed successor request, independently
   verifies 3142 readiness + authentic 0.16.0 signed digest, 3141 route
   switch, tenant/consent/collector persistence and write-preserving
   rollback/replay, then obtains M04 independent installed boundary/OAT.

The existing `analytics-app-candidate` directory and UID991 verifier
resources were staged **inactively**, not enabled. An inaccessible root
trust file from the unprivileged account is UNKNOWN, not absent. The
private signed 0.15.0 remains on 127.0.0.1:3141 until all gates pass.
No public/production exposure, DB migration or new payment framework.

### 5.1 Owner-root V3 maintenance boundary, after live 9 November inspection

The actual root-only matrix found `/etc/omnilyzer/deployment/broker/dev.json`
schema2 still signed to protected promotion workflow `4978b32c...`; both
Analytics product configs under `/etc/omnilyzer/deployment/broker/analytics.json`
and `/etc/omnilyzer/deployment/dev/analytics-executor.json` are schema1
at reviewed commit `8ebf7422...`. The protected later promotion main was
`e1ecf4ac183df82741013e64a7cd9ab7e38f7064`. The staged source
install receipt is only schema2; actual 3141 blue/0.15.0 remains healthy,
3142 is absent. The approved actual 0.16.0 owner Ed25519 approval/signature
are staged privately under
`/home/trust/m05-task014-owner-signature-0160-d18f8f5c/` (owner-only
0700 folder, both files 0600) with hashes:
approval `1f7185c7d6d7caa33baf5a6dfc3ce9c4494c6b499501ded4fce4974918b0adbb`;
signature `b3aec8dffcd5cfca939be3658482db38d10a0b1970fdde8011252fef25df1dd0`.
This is NOT installed root trust. Original owner public signer in DEV is
present. The owner signing key is still on the owner's laptop only.

The original rootless 3141 loopback process was confirmed still executing
`analytics_loopback_guard.py --serve` from the original 13345-byte
blue-only pinned file. Its 2-second monitor rejects ANY green3142 or
substituted 3141 route; its termination path deletes blue3141.
The UID991 route journal directory under
`/var/lib/omnilyzer/deployment/analytics-route` is absent. Activating
V3 broker/UID991 receiver or dispatching schema3 while this original
monitor remains active is a **hard NO-GO**.

**Minimum corrective source and owner action, not a new deployment framework:**

1. Reuse original `analytics_dev_activation_inputs.py` to generate the
   V3 unsigned source and service review bytes for the **final protected
   main SHA after source review and merge**. Recheck actual root config,
   installed candidate's 26 SHA256 source files and existing original
   0.15.0 rollback image; do not restage those unchanged 26 files.
2. The root-only installer must verify the actual Ed25519 signature against
   the original `analytics-owner-source-signers` file and independently
   verify its 0.16.0 canonical source claim. Install only the bounded
   **public** approval, signature and allowed-signers copies into the
   executor's existing protected DEV hierarchy (root:991 0640) and three
   exact duplicate, still root-owned public files in the separately
   protected BROKER hierarchy (root:990 0640). Do not copy the private key,
   alter directory permissions, change any service groups or expose
   executor credentials to UID990.
3. The V3-only
   `analytics-v3-owner-public.conf` broker drop-in mounts a private
   `/etc/omnilyzer/deployment/dev` tmpfs root:990 0750 into that broker's
   mount namespace, then binds ONLY these three root:990 public files
   read-only onto the original verifier paths. Outside the UID990 mount
   namespace the real DEV hierarchy remains root:991 0750, unchanged for
   UID991; original protected trust and signature verification remains
   unmodified. Requires actual loaded-unit namespace test before dispatch.
4. Install the new **fixed original-unit** successor supervisor at
   `/opt/omnilyzer/deployment/analytics-loopback/analytics_loopback_successor_supervisor.py`
   from its exact reviewed Git blob as root:root 0644. Its
   `analytics-v3-supervisor.conf` drop-in selects that fixed script
   and explicitly clears the old `ExecStopPost` blue-only cleanup, while
   preserving UID991, original loopback-only RootlessKit unit and the
   pinned original 0.15.0 container ID. The new process requires
   root-owned generation3 config and an existing UID991:991 mode0700
   `analytics-route` journal before it runs. On the controlled first
   service restart, the old monitor removes its own blue3141 route and
   the V3 monitor may recreate ONLY that signed, original blue route.
   Subsequent 3142 and 3141 changes remain exclusively in the existing
   signed UID991 executor and fsync-protected journal. Unknown routes,
   corrupted journals, changed images or unapproved restarts fail HOLD;
   the supervisor does not select an OCI image from a request.
5. In a single separately owner-approved root maintenance transaction,
   preserve byte-exact before-images and a durable rollback receipt,
   stage the new C32H broker workflow authority, paired V3 broker/executor
   configs and the original-loopback service override, verify all static
   systemd syntax and root-owned file/dir modes, then activate while
   temporarily blocking Task014 dispatch. Before unblocking, prove
   `3141 /readyz` and `/livez` 200 on the ORIGINAL signed 0.15.0,
   canary 3020 unmodified, no green 3142, exact loaded systemd and
   UID990/UID991 mount separation, owner source verification from both
   principals, original socket/FD and journal identities, and a tested
   restoration of exact pre-install bytes if any check fails. Never
   restart the old blue-only supervisor while 3141 is switched to green.
6. Only after installed positive V3 source/authority and one independent
   M04 review may one protected Task014 `analytics_successor=true`
   dispatch consume the actual owner-signed 0.16.0 OCI digest. Perform
   actual 3142, consent/tenant/collector, durable replay and
   write-preserving rollback OAT before accepting the DEV release.
   A source, synthetic or static systemd PASS is **not** live acceptance.

This corrective source must not be installed before its independent
source review and owner-controlled reversible host preflight. The
legacy 0.15.0 private source/service and the original Canary baseline
are intentionally unchanged by the PR.

## 6. Historical repeatability limit, verified 31 October 2026

At platform revision `2654c66ccc906baced9c17a5dfca260bef900ab3`,
`deployment/analytics_ci_request.py` consumes fixed `PINNED_VERSION`,
`PINNED_PLATFORM_COMMIT`, digest and originating-run values from
`analytics_signed_release_consumer.py`; `analytics_signed_source_pin.py`
also fixes the application source. This is qualification of Analytics 0.15.0,
not proof that a subsequent ordinary version can be released without platform
code changes. Keep **Supported release** blocked for a different version until
that capability is implemented and verified under the existing controls.

The owner's 31 October transport transition reported
`ready_for_signed_task014`, including actual executor context and sealed sender
rejection proof. It did not dispatch the signed release or establish application
acceptance. These observations are historical evidence, not reusable live-state
assertions. Consult the current issue and installed state before acting.

See [the ordinary release procedure](m05-analytics-normal-release-procedure-20261029.md)
for the permanent automation requirement. Prove a subsequent approved product
commit through the existing path without editing deployment infrastructure
before claiming ordinary-release repeatability. This file supplies operating
instructions; it does not add an automatic GitHub Actions gate.
