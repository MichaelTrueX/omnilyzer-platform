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
The delivery agent owns this checklist; the owner should not relay routine
commands, collect test evidence or reconstruct the release inputs.

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
- [ ] **Installed authority:** Compare actual installed source/configuration and
  loaded units to the approved baseline. Bind the dispatch workflow SHA to the
  independently installed broker authority. A new main commit, including a
  documentation-only merge, can change workflow_sha under the current contract.
  Reconcile that before dispatch; do not silently rotate the authority.
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

## 5. Current repeatability limit, verified 31 October 2026

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
