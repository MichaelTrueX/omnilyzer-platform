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

## 5. Actual signed Analytics 0.16.0 to protected Task014 V3 handoff (9 November 2026)

**Distribution accepted, installation still HOLD.** The original signed
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
