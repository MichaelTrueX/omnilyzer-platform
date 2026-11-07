<!--
File: docs/operations/task14b-release-identity-contract-20261102.md
Purpose: P0 source impact matrix and P1 bounded trust design for Task14B.
Related: docs/operations/task014-pre-release-checklist.md,
         release/analytics_source_admission.py,
         deployment/analytics_signed_release_consumer.py,
         MichaelTrueX/omnilyzer-platform Issue #281.
Authority: Owner approved Ed25519 key-separation DESIGN on 2026-11-03.
           Local workflow implementation is unsigned/unmerged and does not
           authorize key provisioning, release dispatch or deployment.
-->

# Task14B: signed Analytics successor-release identity contract

## Current local workflow integration (2026-11-03)

The owner approved the **model only**: private Ed25519 approval key remains
on the owner's own machine; a distinct protected GitHub Actions public signer
allowlist and independent root-owned DEV public trust must be provisioned
separately. No key was installed, generated or imported in this deliverable.

The candidate `.github/workflows/platform-release.yml` reuses its ORIGINAL
Analytics build/scan/encrypted GPG handoff/Zot/Forgejo/Cosign jobs. New optional
dispatch fields `analytics_source_sha` and
`analytics_owner_signature_base64` select the separately verified successor.
They MUST either both be supplied or both be omitted. Omitting them retains
the immutable 0.15.0 source. The platform `source_sha` remains the
protected PLATFORM main SHA, never the product SHA. Canary is explicitly
blocked when Analytics-only inputs are present.

For a successor the original source job checks exact 40-hex product checkout,
then the existing `analytics_task013_build_candidate --successor` verifies
the real Git source/ancestry, canonical owner signature and protected GitHub
identity BEFORE passing any source TAR to BuildKit. The source-binding CLI
`--successor` regenerates the exact canonical schema 2 claim and its owner
approval SHA. The original Syft/Grype zero Critical/High/no-waiver scans and
GPG encryption remain unchanged. The protected Zot publisher verifies
the signed owner source + immutable OCI + decrypted claim BEFORE requesting
the first OIDC token, then uses the original authenticated immutable upload.
The protected Forgejo signer rechecks owner Ed25519 and the exact claim
BEFORE the original keyless Sigstore/Cosign steps.

The public signer allowlist is read only from independently managed
`secrets.ANALYTICS_OWNER_ALLOWED_SIGNERS` on the platform repository, not
workflow inputs, product checkout or source-controlled key files. Without this
separately provisioned setting the successor release MUST fail closed.
Original first-install 0.15.0 and Canary must remain compatible.

**Still HOLD:** This branch is neither pushed nor merged; protected GitHub
Actions is not using it. The owner's actual signature/key trust, M02/M04
acceptance of a real new Analytics source, Task014 ordinary successor
request/broker/executor/OIDC/replay/ingress+rollback are still missing.
No release/DEV deployment authorization or installed service change.

## Task014 successor private Zot manifest preflight (2026-11-03)

The existing `deployment/analytics_private_registry.py` now reuses
its original exact rootless Docker command runner, verified runtime socket,
short-lived sealed descriptor, bounded manifest probe, private volatile
0600 Docker auth config and unconditional temporary-directory cleanup for
an explicitly selected successor. New
`AnalyticsPrivateZotPullAdapter.preflight_analytics_successor`
requires the exact canonical schema-3 request and
`product_id="analytics-successor"` sealed credential matching the
candidate OCI digest. It performs only `docker manifest inspect`
for that fixed OCI repository and digest; stdout, stderr and credentials
never enter request output, argv or diagnostic logs.

The original 0.15.0 `preflight_analytics` and `pull_analytics`
retain their historical source/version/digest pins. There is deliberately
NO successor `pull` operation or inherited original executor path: even
the explicit lower-level `successor_preflight=True` option denies Docker
`pull`. Tests with the existing synthetic rootless runner prove image
identity, temporary credential permissions, original source compatibility,
and rejection of changed request bytes, wrong sealed FD, missing rootless
socket and a direct attempt to pull. A regression test passes a correctly
sealed successor request into the original executor and confirms it
rejects BEFORE starting durable replay or Docker work.

**Authority limit:** a successful private manifest probe verifies
registry readability for the supplied (syntactically valid) scoped
credential, NOT owner approval, GitHub OIDC, Sigstore/Cosign provenance,
the installed active image or permission to begin a deployment. All
new tests are isolated. This method is not installed/wired into the
root-owned executor; no actual Zot operation was performed. The full
signed release trust, replay, candidate slot, health, route replacement
and write-preserving rollback remain HARD HOLD pending integration and
independent M04 review.

## Task14B versioned installed source closure, PR282 CI repair (2026-11-04)

**CI evidence and owning defect:** The draft PR #282 C34D run 41756851073
failed on two independent source-closure assertions: missing V2-only
`analytics_active_state_review.py` and `analytics_route_journal.py` in
the statically attested source inventory, and the original 70-source
installed archive failing an actual isolated Python import because
`release.analytics_owner_source_selection` was absent. This is a genuine
installer-source integrity defect. Neither Python path injection, a
hand-copied file, a broadened schema-1 signed installation allowlist
nor relaxing import checks is an acceptable resolution.

**Implemented in candidate SOURCE, no host installation:**
`deployment/analytics_executor_service_config.py` retains exactly
20 historically accepted Analytics schema-1 installed Python source
paths. It defines a **distinct, inert, sorted V2 exact source set**
with 23 Python files: those original 20 plus exactly
`deployment/analytics_active_state_review.py`,
`deployment/analytics_route_journal.py` and
`release/analytics_owner_source_selection.py`.
The C34D AST closure assertion now checks BOTH the old 20-source
contract and the complete V2 graph, including a separate exact
`release.*` import closure, rather than omitting the crypto module.
Unknown or dynamic dependencies still fail.

The ORIGINAL schema-1 32-entry Git handoff, canonical TAR verifier,
root-owned installation approval and original deployed 0.15.0 runtime
remain byte/behaviorally unchanged. A SEPARATE inert schema-2 source
review and TAR consists of 35 closed and deterministic Git-object
entries: original 32 plus exactly the three new source modules.
The V2 manifest embeds the original closed source review and adds
schema2, fixed purpose, SHA, 35-entry source list and explicit
`deployment_authorized=false`/`signed_release_authorized=false`.
The V2 verifier requires an externally supplied approved SHA256,
independently validates original 32-entry canonical verification,
checks every file size/mode/digest, TAR header, ordered path and
canonical bytes, and rejects V1/V2 swaps, unknown files, changed
owner-trust code and malformed manifests.

The SAME existing C31B protected isolated FD staging path has a
test-only, explicitly selected V2 mode; it writes 73 complete files
(43 independently hashed historical base files plus 30 new files),
reuses closed owner/mode/inode/fsync/no-follow verification, and
does NOT overwrite any original Canary source. A separate real Python
process successfully imports BOTH Analytics broker and executor
entrypoints from the isolated V2 tree with no development-worktree
path and no bytecode carryover. Negative tests prove V1/V2 source
confusion or forged owner-trust blob fails BEFORE staging writes.
The original root-only installed entrypoint still accepts ONLY the
original schema1 approval and 70-file path. V2 is not silently
enabled in existing host configuration.

**Follow-up C34D native systemd fixture, PR282 run 41761101143:** The
earlier source-closure and isolated package stages PASS on the exact
GitHub V2 snapshot, but the native systemd255 PID1 Unix/SCM_RIGHTS
receiver test still failed because its *separate fixture* used
`shutil.copytree(deployment)` and omitted the attested release owner
module. The native fixture now derives its complete 73-file source
graph from the SAME immutable Git-object V2 manifest/archive and
`_review_and_combine` source-preimage verifier, rather than granting
any ambient PYTHONPATH or copying an unreviewed release module.
The original actual Unix socket, PID1 authentication, sealed FD,
UID/GID and systemd lifecycle assertions remain unchanged. The
portable isolated-process source/import regression confirms that the
new native fixture's owner-release import is available; **the
privileged native systemd255 GitHub CI job must still independently
PASS on this exact follow-up source commit**.

**Task013 Canary review-only dependency security repair:** The
separate no-publish PR282 run 41761101200 again FAILS the unchanged
zero Critical/High policy due the previously pinned Chainguard
Python 3.15.1 / py3-pip-wheel / libexpat1 OCI base. The actual
sanitized Grype denial evidence confirms six blocked OCI findings.
The Dockerfile, canary OCI verifier and unit-test expected pin now
propose the exact SHA256-verified 2026-11-04 public Chainguard Python
index digest
`sha256:31dd69d84fe5235fe18f8ceb5b76620e6f44a0ce1f9b0d3a46c491576f8b453b`.
The historical October digest and evidence remain in
`release/README.md` with a separate dated November review log.
No latest tag is used at build time. This is NOT vulnerability
acceptance until new no-publish Syft/Grype PASS and independent
Cosign Chainguard publisher/issuer verification. Policy and allowed
exceptions remain unchanged.

**Still HARD HOLD:** No root-approved V2 source-install approval schema
or exact installed UID/GID manifest has been activated. Protected
Analytics broker/executor still admit only original schema2/0.15.0.
A complete owner-signed next release, sealed-FD replay/actual-rootless
executor path, one V2 supervisor/recovery installation and M04 final
exact-HEAD review remain mandatory. Original Task013 Canary scan
vulnerability-policy FAILED in PR282 run 41756851074; resolve the
actual findings in its OWN scan/dependency boundary without weakening
zero Critical/High. A source-import fix cannot override release
security policy or authorize a signed dispatch.

## Task14B schema-3 original Unix transport integration (2026-11-04)

The EXISTING `deployment/analytics_unix_boundary.py` now exposes a
separate, explicitly selected `_send_analytics_successor_private`
that reuses the original protected Analytics systemd Unix socket,
PID1/UID/GID/inode metadata checks, original bounded deadlines,
`SO_PEERCRED`, `SCM_RIGHTS` framing and a non-disk,
request-scoped kernel-sealed FD. Before any socket connection, it
refuses malformed/noncanonical schema-3 bytes, wrong product,
private Zot image/digest mismatch and wrong/expired/old 0.15.0 or
Canary sealed scopes. The original v2 sender, original Canary
sender, and default installed receiver behavior remain untouched.

An opt-in `structural_successor_receive_only=True` on the SAME
original Analytics receiver validates schema-3 request/image shape
and successor-sealed Linux FD under existing `SO_PEERCRED`,
**then deliberately rejects without invoking any executor at all**.
That is a test-only compatibility boundary, not the real new
receiver, and must never be enabled in a live service as a substitute
for independently trusted owner signature, GitHub OIDC, signed
Task013 provenance, original JTI replay, active Docker state and
protected blue/green executor. Its unconditional rejection is
captured at construction, so later executor implementation changes
cannot silently turn it into an authorization path. A real local
AF_UNIX socket test exercises the exact kernel FD handoff to this
rejecting receiver and proves no replay begin/finish or Docker
operation occurs. Negative tests cover cross-scope, wrong image,
wrong stage, noncanonical request and original v2 behavior.

**HARD HOLD:** The broker still does NOT invoke this successor
transport. The installed schema-2 receiver still denies a v3 request
and no protected deploy/replay/rollback integration or real image
activation has been added. Kernel transport correctness alone is not
owner authorization or real release readiness.

## Task014 successor Linux sealed credential scope (2026-11-03)

The ORIGINAL `deployment/private_registry_fd.py` now supports an
explicit, opt-in `product_id="analytics-successor"` mode. Historical
Canary remains the unchanged default; historical Analytics
`product_id="analytics"` remains exactly pinned to signed 0.15.0.
The successor mode requires a SHA256-only immutable OCI reference at
`oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:...` other than 0.15.0,
and checks that the image exactly matches the request's manifest digest.
It also requires canonical bytes and syntactically valid nonzero
owner-approval, source-claim and promotion hashes in ONE schema-3
Analytics DEV request. It does NOT independently verify those hashes
against signed evidence. Private candidate endpoint remains localhost3142; no public
origin or destructive rollback flag is allowed. Duplicate or malformed
JSON, different image, unsigned-looking claim, wrong product, origin,
repository, stage, operation or legacy v2 all fail BEFORE creating a
kernel memfd. On readback, the receiver recomputes exact request/image
identity and verifies the ORIGINAL sealed memfd metadata, token TTL and
SHA256 request-binding. Existing SCM_RIGHTS transfer, redaction,
CLOEXEC and kernel F_SEAL_* protections are reused unchanged.

Tests use actual Linux `memfd_create`, `fcntl` seals and
`socket.socketpair`/SCM_RIGHTS to prove the new image/request arrives
unchanged and cannot be read as original Analytics or Canary. They also
verify no memfd creation on untrusted successor input. No external
network, Docker, root service, real Zot token or JWT was involved.

**Crucial:** this FD layer verifies request IMAGE SHAPE only. It does
NOT authenticate an owner signature, GitHub OIDC, Sigstore/Cosign evidence
or active installed state. Calling it directly does not grant deployment
rights. The original `analytics_promotion_broker` currently runs only
read-only first-successor verification; it does NOT yet forward schema3
or consume replay. The original `analytics_unix_boundary`,
`analytics_executor` and root-owned private registry preflight remain
closed/pinned to the original 0.15.0. They MUST be extended in one
end-to-end, security-reviewed change before allowing the broker to seal,
replay-consume and send a real next release. Never dispatch a successor
to today's original executor, as that could consume durable replay on
a guaranteed rejected operation.

## Task014 staged private candidate and reversible route control (2026-11-03)

**Existing authority reused, not a parallel proxy:** Task14B imports the
entire original DEV-accepted supervisor
`deployment/analytics_loopback_guard.py`, its full original
`deployment/tests/test_analytics_loopback_guard.py` and rootless systemd
unit from unmerged platform draft PR #278 exact HEAD
`edf7454ee28dd25f914e8e151225d43433d29361`. The original
`--serve` and `--cleanup` execution modes, root-pinned 0.15.0 blue,
3020 Canary scope and installed systemd unit remain unchanged.
**Copying the original source to this isolated Task14B candidate branch
does not merge PR278, install a new unit, rotate its key or change DEV.**

The existing `deployment/analytics_active_state_review.py` now permits
exactly TWO routes in normal operation, or exactly THREE *during staging*:
original Canary 127.0.0.1:3020, stable Analytics 127.0.0.1:3141 and
temporary candidate 127.0.0.1:3142 to the **other** running, healthy,
isolated Analytics slot. A third forwarding rule with any other public
parent, port, child IP/port, nonisolated network, duplicate ID, changed
Canary or same OCI image fails. The inspected candidate must have NO
Docker-published host port, an approved UID10001/capability/readonly
profile, immutable local OCI image ID and exact RepoDigests, then answer
both `/readyz` and `/livez` over localhost3142 with HTTP200.
Changed RootlessKit rules between observations fail closed.
`review_analytics_successor_with_live_active` accepts
`require_staged_candidate=True` for a later executor stage gate and
binds that exact candidate OCI digest to the reviewed new signed release,
not an untrusted CI-provided digest. The routine remains a read-only
validator and authenticates neither owner signature nor OIDC itself.

In the SAME original source file, a new PRIVATE helper
`_switch_reviewed_private_route` performs an exact reversible 3141
RootlessKit DELETE/POST transaction, for either blue-to-green or
green-to-blue, after checking UID991, an explicit inert V2 opt-in flag,
original network ID, both exact immutable image + container IDs, hardened
Docker state, unchanged Canary3020/active3141/candidate3142 port-rule IDs
and the actual candidate health. It rechecks all route IDs immediately
before deletion; on synchronous DELETE/POST/health/acknowledgement failure
it attempts to remove ONLY the newly created 3141 rule and restore the
exact old mapping. Unexpected third-party rules, changed Canary/candidate
or failure to verify restored old health are HARD HOLD, never a false
success. The opt-in environment flag is **NOT deployment authority**,
and this helper is unreachable from the original `main()` / installed
unit. Tests use only synthetic local API responses; original blue-only
supervisor lifecycle tests still pass.

**Route recovery now implemented IN SOURCE, NOT activated:** The dedicated
`deployment/analytics_route_journal.py` uses ONLY the fixed future
`/var/lib/omnilyzer/deployment/analytics-route/transaction.json` location.
The directory is NOT created by import or by this development work. The
one-time root-owned V2 installation must provision it as UID991:GID991
mode0700, permit only that directory in the future systemd
`ReadWritePaths` (the installed original unit remains ProtectSystem=strict,
with NO such exception), and approve the exact installed source manifest.
No signer, token, tenant data, secret or SQL value is written to the journal.

A single canonical schema1 journal record contains SHA256 of the exact
reviewed request, previous/next private slot, immutable OCI image and actual
64-character container ID, verified private child IP, incrementing generation
and `prepared`/`switched`/`restored` status. The original existing replay
SQLite database remains completely unchanged and continues to own JTI
uniqueness. Real Linux file tests verify owner/mode, symlink/unknown-file
refusal, bounded duplicate-safe canonical JSON, atomic write-to-exclusive
temp, file fsync, rename, directory fsync, readback and process reopen.
An exclusive kernel directory lock spans the entire future route-swap or
recovery operation, blocking concurrent invocations. Durable `prepared`
is written BEFORE even attempting DELETE on 3141. `switched` is written
only after verified new route, OCI and HTTP200 checks; `restored` only
after verified old route/health. Unfinished `prepared` blocks another
upgrade until the independently authorized recovery path runs.

The private, unexported
`analytics_loopback_guard._recover_reviewed_private_route` now reconciles
a PREPARED journal after process restart: if old3141 still exists, verify
it and mark restored; if old3141 disappeared, recreate it from the
independently verified previous immutable container; if new3141 was
published without durable commit, remove ONLY the recognized new rule
and restore old3141. Exact Canary3020/candidate3142 rule identities must
remain unchanged. Unknown rules, changed old image/ID/health, wrong request
SHA or failure to verify restoration are hard HOLD. Tests include all
three interruption points, concurrent operations, actual persistent
journal I/O and multiple synchronous RootlessKit partial-write failures.
These are isolated simulations, NOT a real DEV/root/supervisor acceptance.

**Committed-state restart validation now exists IN SOURCE:** The read-only
`deployment/analytics_active_state_review.py` adds
`inspect_committed_analytics_route`. Under UID991 (or separately
authorized root diagnostic) and an exclusive lock on the SAME
protected journal, it rejects missing or `prepared` records and accepts
only `switched` or `restored` when the expected exact request SHA,
slot, immutable OCI digest, container ID and journal-recorded private
child IP all match a freshly inspected live Docker image,
`RepoDigests`, RootlessKit 3141 mapping and application health.
It rechecks the journal while still locked. Concurrent change, unknown
release, fake active IP, removed original image, public port or
mismatched container causes a generic read-only HOLD, not a new route
or silent admission. Tests use real journal fsync/reopen/flock and
mocked host API observations. The journal lock is also bound to the
owning Linux thread, preventing a second thread sharing the same Python
object from using another thread's open transaction. Original signed
0.15.0 without a successor journal continues on the ORIGINAL service.

**CRITICAL trust boundary:** This committed-route inspector is NOT
a signature verifier. Its expected OCI, slot, container and request SHA
arguments MUST be sourced from a separately protected and
independently verified signed owner-approved Task013/014 release plus
durable replay. A caller-supplied dataclass or the journal itself cannot
grant that authority. The running supervisor is NOT wired to this
helper, and there is no installation/active credential or source change.

**Still NOT an atomic or automatically installed supervisor:** The
RootlessKit port API cannot replace 3141 atomically. DELETE/POST can
briefly interrupt requests, and an in-flight HTTP request could fail;
no zero-downtime guarantee is claimed. The current installed PR278 guard
does not load the new journal; actual V2 signed source admission,
safe service reattachment and recovery acceptance are not installed.
The original UID991 executor, broker-to-executor signed first-successor admission,
durable JTI replay, write-preserving DB/schema compatibility and
candidate lifecycle must be joined as ONE reviewed integration. A
journal file or environment opt-in is NOT deployment authority. DO NOT
invoke the private switch/recovery helpers, create 3142 on live DEV,
modify the original unit or restart it before exact-byte owner-approved
installation and independent M04 review.

## Task014 first-successor broker security chain, no dispatch (2026-11-03)

The existing `deployment/analytics_promotion_broker.py` now captures the
existing `review_successor` method at construction, alongside its ORIGINAL
`review` method. The new
`review_first_successor_without_forwarding` requires exact canonical,
duplicate-safe schema-3 request bytes BEFORE any OIDC or registry access,
then executes the existing GitHub deployment OIDC identity verifier, the
original Task013/Task014 **signed** 0.15.0 release review, the separately
root-owner-Ed25519-approved next signed release review and independent Zot
and Forgejo JWT audience verification. It invokes the canonical
`parse_analytics_successor_request` against the exact accepted **signed
0.15.0 rollback hint**, but it does NOT observe Docker/RootlessKit:
the broker runs as restricted UID990 with no rootless socket access.
Only the separately trusted UID991 executor can inspect the actual
active image/route before replay and cutover. Malformed requests, false
OIDC, altered signed source/digest or missing root-owned signer trust
fail closed without minting an SCM_RIGHTS sealed credential, consuming
durable replay or contacting the executor. A dishonest live-image hint
is NOT deemed proven by broker review. The original 0.15.0 broker
`authorize_and_forward` and Canary path remain unchanged.

This is intentionally FIRST-successor-only: the previous signer is the
original 0.15.0 verifier. An additional verified prior-owner-approved
release will be needed for second and later upgrades. The new method does
not authenticate a caller-provided dataclass, grant deploy rights, perform
any Docker/RootlessKit mutation, or accept an uninstalled receiver as
authority. All new broker and host tests use synthetic signed proof and
mocked local Unix responses, NOT a real privileged DEV admission.

**Resolved in candidate SOURCE, not installed ingress:** the original
`deployment/runtime/dev/analytics.compose.review.yaml` publishes blue
to localhost3141 and green to localhost3142, while PR278 also reserves
3141 as the STABLE RootlessKit Analytics ingress. This prevents safe
reverse green-to-blue staging if blue still attempts to publish3141.

The NEW, explicitly opt-in
`deployment/runtime/dev/analytics.compose.successor-ports.yaml` uses the
native Docker Compose `!reset []` merge to remove BOTH successor Docker
host-port publications and retain all original runtime/secret/network
hardening. This is independently validated by rendering both profiles
through actual Docker Compose v5.5.1 (no daemon operation), checking the
original first-install Compose is unchanged while future successor
profiles have zero host-published ports. The schema-3 request producer
and consumer now distinguish stable, private ingress3141 from independent
temporary candidate health3142 **for either slot**, and the read-only
active-image inspector allows historical pinned 0.15.0 blue with its
exact original localhost3141 binding but rejects any future successor
blue/green container with published host ports. The historical
signed blue 0.15.0 MAY remain healthy as the rollback standby while
the exact observed RootlessKit 3141 rule serves green: the actual
accepted internal=true Docker network did not create a second host
listener merely because Docker HostConfig advertises port3141.
Matching is determined by the actual RootlessKit child IP, not a
hypothetical Docker host bind. Ambiguous routing or changed published
ports are denied. Tests cover standby rollback preservation, both slot
directions and runtime profile preservation.

**Still implementation HOLD:** The original signed 0.15.0 and installed
PR278 RootlessKit route/supervisor are untouched. Merely validating the
new override does NOT install it, start a candidate, create a health route
or activate a cutover. A bounded, synchronous route replacement and
best-effort rollback now exist IN SOURCE, but this is not crash-atomic
or signed owner-authorized deployment. The existing protected broker
and UID991 executor still need sealed scoped OCI credentials, durable
replay/recovery intent, health/DB compatibility and one qualified
supervisor replacement before invoking that route controller. Actual
host acceptance and independent M04
review remain required. Do not claim Docker Compose syntax acceptance
as real production/DEV availability.

## Task014 root-owned active image and route verification (2026-11-03)

The new product-scoped `deployment/analytics_active_state_review.py`
reads ONLY the existing local rootless Docker and RootlessKit Unix APIs
with strict bounded, duplicate-safe JSON and fixed resource names.
`inspect_analytics_active_state` explicitly permits ONLY the
installed socket-activated rootless executor UID991 or a separately
authorized root-owned diagnostic. The broker uses its separate UID,
and must never acquire Docker/RootlessKit socket permissions. The
inspector does NOT accept GitHub/CI-provided active slot or digest,
load a mutable state file, modify routes, start Docker, read secrets,
alter database contents, or change Canary.

It cross-checks the original Canary 3020 forwarding rule and exactly
one private Analytics 3141 forwarding rule, actual rootless backend
network, running/healthy hardened UID10001 Analytics container,
actual private child IP, Docker bind-port/privilege/cap/network
profile, and its immutable `Config.Image`. A separate Docker image
inspection also checks the ACTUAL image ID, Linux/amd64 platform and
exact local `RepoDigests`. One mismatch, unknown socket, altered
route, duplicate rule, public bind or ambiguous matching image gives
HOLD. The route is re-read after image inspection to catch ordinary
concurrent changes. Both active blue and active green are supported
without a pinned per-release digest.

`deployment.analytics_execution.review_analytics_successor_with_live_active`
uses this read-only executor/root-diagnostic observation, requiring the
selected active image/digest to equal separately verified evidence for
the **previous signed release**. The strict schema-3 parser uses the
measured active digest/slot and rejects mismatched GitHub rollback hints.
This function cannot authenticate caller-constructible Python evidence,
verify Sigstore itself, consume replay, reserve forwarding or deploy.

**Verified installed separation, 2026-11-03:** systemd
`omnilyzer-deployment-broker.service` is running as
`omnilyzer-broker`; the socket-activated, idle
`omnilyzer-deployment-analytics-executor.service` runs as UID991
`omnilyzer-executor`, and its separate socket is listening.
An earlier synthetic test wrongly invoked the Docker-capable inspector
from the broker. The broker's first-successor review now verifies
the ORIGINAL signed blue 0.15.0 and next owner-selected signed release,
but treats the recorded previous digest/slot as an UNTRUSTED HINT and
does not touch Docker. The authorized executor must measure the real
rootless route against this exact request BEFORE beginning replay.
The original 0.15.0 forwarding method is untouched and no schema-3
forwarding exists.

**Verified original live-loopback guard:** the exact root-owned
`/opt/omnilyzer/deployment/analytics-loopback/analytics_loopback_guard.py`
SHA256 remains
`e87be219e93130a3f9103aac21d2d809b2b226c990ed56fa24e441540870196c`.
Its unit SHA256 remains
`aa61b6d9a329136594c6e37dfd07a1ddfb417dd551462d0ba806b49e2df29c7f`.
The installed guard runs continuously as UID991 with a root-owned
0600 EnvironmentFile pinning the ORIGINAL blue container ID; it is
designed to remove unrecognized routes and restart the fixed old rule.
Therefore a green route cutover WITHOUT an owner-reviewed replacement
of the EXISTING guard will fail, even when all successor OCI/signer and
replay checks pass. This cannot be fixed by granting Docker access to
the broker or by temporarily bypassing the guard. It requires ONE
cohesive, separately owner-authorized guard/ingress upgrade and
write-preserving rollback transaction. Current code and synthetic
checks do not prove such a route replacement exists, nor that the
rootless executor can restart a root-owned systemd unit.

No rootless live socket was opened from the restricted omnigpt account.
Do not claim Task14B release readiness until the original UID991
inspector, route-owner integration, repeatable restart/recovery and
all required independent checks have been qualified on real DEV.

## Task014 successor CI request projection (2026-11-03)

The original `deployment/analytics_ci_request.py` now has
`validate_analytics_successor_ci_inputs`,
`resolve_analytics_successor_ci_release_inputs` and
`build_analytics_successor_ci_request` alongside the UNCHANGED 0.15.0
schema-v2 request builder. The new schema-v3 bytes are strictly a
**CI-side untrusted proposal**, never a signature, session, root authority
or deployment permission. There is no new workflow entrypoint or network
POST for the successor in `.github/workflows/platform-promote.yml`.

The new validator requires a true next SemVer, exact platform and product
commits (both distinct from the original source where relevant), exact image
SHA256 digest and distinct prior image digest, one of the two private slots,
owner's canonical approval SHA256, originating Task013 run ID, immutable
evidence hashes and original DEV GitHub runner context. The client reuses
the ORIGINAL CI JWT projection and root-reviewed product/Compose/secret
source expectations, then produces the canonical schema-3 request with
private opposite-slot port and write-preserving rollback. Its canonical
intent also binds the independently observed **previous digest**.

For normal releases the original short-lived private Forgejo OIDC audience
may read the precise selected release version to resolve all THREE omitted
manifest, provenance and source-claim hashes from the exact bounded archive
after matching selected source/version/platform/digest/owner approval.
Partial hash omission, other JWT audiences, mismatched archive source,
wrong owner SHA or malformed evidence fail closed. Reading package metadata
in CI does NOT verify Sigstore/Cosign/Ed25519: only the root-controlled
broker may do so. Synthetic tests prove the generated CI bytes are
accepted by the existing **inert** root schema-3 validator for both slot
directions and that original v2 remains closed.

**Activation HOLD:** the protected platform-promote workflow still runs
the historical v2 Analytics request and no root-owned service consumes v3.
The active digest/slot currently appears as an **untrusted CI input** in
this proposal. It MUST later be obtained and reconciled by the installed
UID991 rootless-executor live-state inspector, not trusted from GitHub dispatch.
Do not wire v3 into the active deployment path until original broker,
replay, Unix socket receiver, private Zot pull, installed rootless Docker,
write-preserving reversible route switching and migration compatibility
are all implemented and accepted. No new trusted key or release deployed.

## Task014 original OIDC and signed successor review composition (2026-11-03)

The existing `deployment/analytics_registry_review_composition.py` now
retains its original `review()` method for 0.15.0, and exposes a separate
read-only `review_successor()`. Both pass through the SAME existing
verified GitHub deployment OIDC, authorized workflow identity, independent
Zot/Forgejo registry JWT audience checks, original bounded authenticated
TLS readers, Sigstore bundle and Cosign OCI signature verifiers.

The successor's owner source approval paths are captured at handler
construction, not supplied through the remote promotion request. The handler
uses `load_and_verify_owner_signed_source` with the existing independently
root-controlled Ed25519 signer anchor, validates owner SHA/tree/version and
canonical approval digest BEFORE private registry access, then invokes the
existing `acquire_and_review_owner_approved_analytics_release` to verify the
actual immutable Forgejo signed evidence and Zot digest. The original signed
0.15.0 path remains unchanged. No root signer trust is provisioned today, so
a successor must fail closed in installed DEV.

The returned tuple (read-only signed release, owner source selection, owner
signature receipt) is **NOT** an authorization capability. All public
dataclasses are caller-constructible and unit tests replace actual
cryptographic network collaborators with synthetic fixtures. In particular,
the installed Analytics broker/replay/executor is NOT routed to
`review_successor` yet. Implementing that root-owned broker admission
requires verified current active slot/digest, request SHA, replay and sealed
credentials, plus a real reversible private RootlessKit ingress switch and
database-write-preserving rollback.

## Task014 reusable successor canonical request review (2026-11-03)

The existing `deployment/analytics_execution.py` now contains an **inert**
`AnalyticsSuccessorRequest` schema 3 and
`parse_analytics_successor_request`, alongside the completely unchanged,
closed original schema-2 first-install request parser. This is NOT an
installed broker/executor change, an authorized deployment operation or
an endorsement of data supplied by a caller.

Schema 3 uses the **independently verified active signed OCI digest and
actual active private slot** as the rollback baseline; it does not depend
on the source code being changed at every release. First-upgrade acceptance
has blue 0.15.0 active and green candidate on 127.0.0.1:3142. Later a
verified green active slot can select blue candidate on 127.0.0.1:3141.
Both directions require unchanged root-reviewed Compose/runtime/product/
secret identities, no public origin, and
`preserve_database_writes=true` rollback to the observed active digest
and slot, never a caller-selected database restore. It binds the
owner's canonical approval hash, exact selected product Git SHA and source
tree, reviewed signed Task013 release version/OCI digest/manifest and
provenance SHA256, originating release run, original already-authorized
Task014 GitHub OIDC identity and canonical promotion request intent.
Duplicate/noncanonical JSON, changed images/sources/runs, wrong active slot,
public ingress, altered secrets, rollback data reset and replay mismatch fail.

The function reuses the historical strict schema-2 parser to validate every
unchanged nested runtime/secret/identity field without relaxing first-install
checks. It cannot authenticate constructible dataclasses. The trusted,
root-owned broker must obtain actual detached-owner key verification,
Sigstore/Cosign/Grype and OIDC from the existing independent verifiers,
measure host active state itself and enforce replay BEFORE exposing a
successor executor operation. Neither the installed Task014
`analytics_ci_request.py`, broker nor executor routes this schema. The
current PR278 private loopback supervisor still pins one immutable BLUE
container and cannot atomically switch to the GREEN target.

**Operational repeatability HOLD:** schema 3 can validate both slot
directions with a dynamically supplied *trusted* active-release digest, but
that trusted root-owned active-state ledger and any write-preserving atomic
RootlessKit route switch have NOT been implemented or independently tested.
A caller cannot self-attest the active image/slot. The installed broker must
reconcile the signed previous release, rootless Docker container/image,
actual route, database/migration compatibility and replay before acting.
Real next-version release/DEV activation, independent M04 review and
owner-approved root trust provisioning remain HOLD.

## Problem statement and verified P0 (2026-11-02)

Original private 0.15.0 DEV install is M04-accepted and must stay untouched.
A read-only scan of current platform main `060eb4b426aa7a495e08ea397184edad6727b758`
found **21 production files and 118 textual release/source pin references**.
Some are legitimate historical/runtime identity pins and MUST NOT be
mechanically replaced. Source PR52 exact SHA
`4cdda7faeba57abb3388f9be5c450fe6afb1140d`, original Task013
run `40881693662`, platform source `b9e22e745ecbaf96dc15998e91d1a74f70e5ad77`,
OCI digest `sha256:6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1`
are immutable historical release facts.

### A. Future release producer and signed input, needs controlled changes

| Production file | Existing pin | Successor need |
| --- | --- | --- |
| `.github/workflows/platform-release.yml` | Four literal PR52 checkout/receipt checks | Obtain exact independently approved product SHA; reject mutable branches and wrong repo |
| `release/products/analytics-source.json` | Source commit, manifest and 49 critical file hashes | Source-review authority that cannot be rewritten by the submitted product itself |
| `release/analytics_source_admission.py` | Frozen source binding, baseline ancestry, closed critical paths | Preserve full committed Git tree/manifest checks; verify reviewed successor policy |
| `release/analytics_task013_build_candidate.py` | `EXPECTED_SOURCE` PR52 | Build strictly admitted committed tree, never editable filesystem checkout |
| `release/analytics_release_evidence.py` | Literal external PR52 source | Bind new exact source/OCI/scans and original OIDC execution into signed claim |

### B. Task014 consumer/request verification, needs controlled changes

| Production file | Existing pin | Successor need |
| --- | --- | --- |
| `deployment/analytics_signed_release_consumer.py` | Version 0.15.0, origin run, platform SHA, digest, image | Verify all signed manifest/provenance/OCI Sigstore/Cosign bytes and original signer, per selected approved release |
| `deployment/analytics_signed_source_pin.py` | PR52 commit/tree/context/manifest | Compare signed source with independently reviewed product profile and approved source authority |
| `deployment/analytics_ci_request.py` | Reads `PINNED_*`, emits fixed image/source/run | Construct request only from verified signed release and bounded workflow identity; runner inputs remain untrusted |
| `deployment/analytics_execution.py` | Fixed release/source/product SHA and OCI | Existing installed executor checks must remain fail-closed on unapproved digest, identity, replay and stage |
| `deployment/analytics_promotion_broker.py` | Exact image pin | Only verified expected image from reviewed installed authority may reach sealed descriptor transport |
| `deployment/analytics_unix_boundary.py` | Exact image pin | Preserve source-to-executor sealed FD and product/image allowlist |
| `deployment/analytics_private_registry.py` | Exact image pin | Authorize only independently verified image and registry transport |
| `deployment/analytics_executor.py` | Exact image pin | Controlled blue/green successor image with rollback, no arbitrary image pulls |
| `deployment/analytics_first_install.py` | Both slots pinned original image | **Historic first-install code must not be reused for ordinary release**; retain fixed stop-only recovery |
| `deployment/analytics_executor_service_config.py` | Original image dependency | Preserve installed authority and source-set pin; do not rotate for normal release |

### C. Historical and diagnostics: do not automatically modify

`release/analytics_task014_readonly_probe.py`,
`deployment/analytics_registry_stream_readiness.py`,
`deployment/analytics_source_handoff.py`,
`deployment/analytics_task014_resume.py`,
`deployment/private_registry_fd.py` include frozen 0.15.0 preflight,
recovery or transport evidence. Determine at the owning caller whether they
are future release controls; preserve historical exact SHA where not.

## P1 proposed minimum trust contract, pending security review

1. **Source approval is independent of product bytes**. A user-provided SHA,
   self-declared product manifest, branch/tag, or ordinary unsigned descriptor
   does not prove independent approval. Existing protected workflow/environment
   and independently reviewed product-source authority must be proven as a
   *real* enforced boundary before making a source input dynamic. The current
   product default branch contains legacy/demo login code; do not treat it as
   an approved base. No fallback to mutable `main` or unreviewed PR HEAD.
2. **Task013 creates immutable evidence** only after source approval, locked
   source/tree/manifest checks, pinned no-network builder, real zero-waiver
   Syft/Grype, signed release and provenance, Cosign/Sigstore, immutable Zot
   and Forgejo byte readback, and exact originating workflow run.
3. **Task014 consumes, never trusts the dispatch inputs**. Version, source,
   digest and origin run may *select* an exact immutable evidence bundle; the
   installed consumer must verify the original signature and source approval
   against trusted local authority before accepting it. Strictly bind all
   fields, image digest, runtime profiles, workflow SHA, replay and user/slot
   identity. No caller may synthesize a `TrustedRelease` from JSON.
4. **Release transition is explicit**. The existing 0.15.0 containers/DB and
   exact pin continue running. An approved successor needs isolated candidate,
   real readiness/tenant tests, narrow private traffic switch and write-safe
   rollback; don't replay first-install/bootstrap or recreate sibling Canary.
5. **Proof required**: old 0.15.0 accepted unchanged; a distinct independently
   reviewed source/version accepted without editing platform code/config;
   unauthorized commit, altered signed claim, digest mismatch, wrong workflow,
   wrong product, replay, mutable tag, unknown actor and missing rollback all
   denied; original GitHub Actions CI and M04 independent exact-HEAD review.

## Current status

**P0: initial production-file inventory complete**; caller/dataflow tracing
and actual GitHub environment approval policy are not yet fully verified.
**P1: proposed, not yet independently approved**. **P2-P5: not executed**.
No signer, consumer, request, installed service, production, registry or
deployed Docker mutation is authorized by this design.

## GitHub source-approval policy inspection (2026-11-02)

Actual authenticated GitHub REST read of environment
`task013-dev-release` returned HTTP200: the only reported protection-rule
type is `branch_policy`; there are **zero required reviewer rules** and
`can_admins_bypass=false`. This is NOT an independent source approval gate.
The platform public repository's `main` branch protection endpoint returned
HTTP404 `Branch not protected`. The private Analytics product repository's
`main` branch-protection endpoint returned HTTP403 with GitHub's plan message
`Upgrade to GitHub Pro or make this repository public`. Its actual protection
state therefore cannot be claimed. The original product PR52 has a GitHub
`COMMENTED` review, not a GitHub `APPROVED` review.

**Security design consequence:** A new workflow input `analytics_source_sha`
cannot by itself be treated as reviewed source authority. Even if an existing
GitHub environment limits branches, a dispatch actor or writable workflow is
not independent approval of that arbitrary source. No step may remove
`EXPECTED_SOURCE` or `SOURCE_COMMIT` equality checks until a reviewed,
enforced, per-release source approval binding replaces them. The minimum
candidate can be an owner-authenticated explicit exact-SHA approval coupled to
the signed Task013 OIDC/workflow run, with a documented solo-owner risk
acceptance and immutable source bytes; stronger separately signed owner
approval is possible but must not be invented without review. No fallback
to owner name alone, a GitHub comment, a mutable tag or an unsigned source
manifest. Test both authorized next SHA and unauthorized same-repository SHA.

## Solo-owner release authorization design, verified constraints

Additional authenticated GitHub REST results: both repositories list only
`MichaelTrueX` as collaborator. The existing Task013 environment permits
only branch `main`; its sole protection type is branch policy and it has no
mandatory reviewer approval. Use the **actual authenticated release actor**
from GitHub workflow context and original GitHub OIDC for the owner's
per-release approval, rather than pretending that a second reviewer or
protected private source main exists. This is zero-new-service and works for
the currently verified single-operator organization.

**Proposed execution boundary (requires focused M04 review before activation):**
a Task013 owner-dispatched exact product source commit, version and source
review reference are treated only as a *selection*. Source checkout origin,
exact commit/tree, immutable Git object, approved PR/source review record and
full source integrity must be checked BEFORE build. A reviewed source claim
can then be bound to original Task013 workflow/actor, provenance, zero-waiver
scanner, signed manifest and OCI. Task014 independently verifies those signed
identities against trusted installed approval and rejects wrong digest, source,
workflow, actor, replay, version, product and external-source substitution.

**Owner-authenticated is not independent review:** M04 remains an independent
*procedural* QA requirement with exact SHA and one consolidated review.
Its GitHub `COMMENTED` status is not a cryptographic approval. An unauthenticated
review URL or a self-declared `approved=true` in source cannot grant release.
If a later collaborator receives write access, the owner-only trust assumption
must be explicitly requalified before any further dynamic release.

## P2 bounded preparatory code (not connected to live workflow)

The isolated candidate includes
`release/analytics_owner_source_selection.py` and
`release/tests/test_analytics_owner_source_selection.py`. This
stdlib-only **inert** validator checks the actual owner actor ID, original
GitHub release workflow/ref, platform checkout SHA, fixed product origin,
exact committed product HEAD/tree, approved 0.15.0 ancestry and clean tracked
source. It validates a selected release version but returns
`independent_review_verified=False`,
`release_authorized=False`, and `deployment_authorized=False`.
Its result cannot be submitted as a signed receipt or used by the executor.

Local isolated Git fixtures prove one valid owner-selection structure and
negative rejection of unauthorized actors, mutable refs, wrong source SHA,
incorrect product/repository, dirty worktrees, broken ancestry and malformed
semver. Focused new suite 9/9 PASS; original release baseline suites 39/39
PASS. **The module is not integrated into Task013 or Task014**. It is a
preparatory source-integrity component pending comprehensive original signer,
source-review and installed Task014 trust integration, and is not a new release
GO. Retain the existing hard pins until verified replacement tests and
independent M04 acceptance are complete.

## P1 implementation candidate: owner-held detached source signature

This isolated, unintegrated next-stage component supplements the owner-selected source preflight with an actual OpenSSH Ed25519 detached signature. It is a cryptographic source-approval option without a second SaaS control plane. It is NOT a substitute for original Task013 GitHub OIDC/Cosign/Sigstore signatures or independent M04 QA.

- A one-time reviewed, owner-controlled public key must be installed in the **existing root-controlled DEV directory** as `/etc/omnilyzer/deployment/dev/analytics-owner-source-signers`. The file does **not yet exist**. It must be root-owned, regular, non-symlinked and not writable by group/others; all ancestor directories must remain root-owned and not group/other writable. Repository or workflow inputs cannot replace this independent host trust anchor. Installation requires separate owner authorization.
- The corresponding owner private key stays exclusively on an owner-controlled machine. Never copy private keys or passphrases into ChatGPT, GitHub Actions, Docker, DEV, or a repository. Each release requires an explicit owner-signed, exact-source approval record.
- The signed deterministic record binds product, repository, source commit and tree, release SemVer, original release-workflow ref, exact platform workflow commit and owner numeric actor ID. The OpenSSH signing namespace is `omnilyzer-analytics-source-v1`; allowed signer identity is `MichaelTrueX`.
- The validator checks canonical source bytes and the detached SSH signature against ONLY the pinned root-controlled allowlist. A missing key, symlink, changed path, different key, wrong commit/tree/version/workflow or altered signature denies. The checked signature and trusted signer bytes are independently snapshotted into private temporary files before OpenSSH verification, preventing source-path substitution.
- All tests use temporary generated fixture keys. A positive test does not establish that a real owner key exists or has authorized a real release. A verified owner signature does not prove independent review, Task013 signature, security-scan pass or Task014 deployment permission. The result deliberately retains `independent_review_verified=False`, `release_authorized=False`, `deployment_authorized=False`.

**One owner decision before activation:** Whether to establish a dedicated owner-held SSH Ed25519 source-approval key and accept one deliberate signing action for each new release. This is the simplest proposed separate source-approval authority where GitHub does not enforce independent source review. Using GitHub dispatch actor plus OIDC alone proves authenticated workflow execution, not a distinct owner source-approval signature. M04 acceptance remains separate in either model.

**Hold:** No root-owned key has been installed; no workflow or signed-release consumer has been wired to this preparatory verifier. A GitHub Actions Task013 runner cannot read the DEV root-owned key; checking a key from GitHub source alone is NOT sufficient. Task014 must independently verify the owner signature against its root-owned anchor before promotion. Original immutable 0.15.0 pins and DEV runtime are unchanged. No successor release before complete producer/signer/consumer/executor integration, M04 QA and separate owner dispatch/deployment approvals.

## P2 candidate: original signed Task013 evidence remains first-class

A separately staged, **read-only** successor comparison now reuses the original
`deployment/analytics_signed_release_consumer.py` parser and existing
Sigstore/Cosign verifier interfaces, rather than inventing another signing
protocol. The original `verify_analytics_signed_evidence` and its hard
0.15.0 source/version/run/digest identity remain the only installed path.
`verify_owner_selected_analytics_signed_evidence` is a NON-INSTALLED review
adapter for a future exact product SHA, platform SHA, SemVer, source tree,
signed release run ID and OCI digest. The proposed release's signed manifest
and provenance must mutually match; the original signer identity, scanner
hashes, zero security exceptions, source claim and immutable OCI signature
must still verify. It must also match the detached owner-selected source
record and unchanged installed product/runtime/secret contract.

**This does not authorize Task013 or Task014.** All receipt classes are public
data classes and synthetic verifiers in unit tests can produce successful
shaped results. Before any privileged successor admission, the source
selection AND detached owner signature MUST be checked against the separate
root-owned trust anchor, and the ORIGINAL concrete Sigstore/Cosign verifiers
MUST authenticate actual registry bytes. The Task013 producer's original
static `analytics-source.json`, pinned build candidate, workflow checkout,
installed source manifests and first-install-only Task014 broker/executor
remain fixed. This P2 bridge by itself does not implement repeatable releases.

A production successor source must never be published under the assumption
that the old 49-file critical hash list admits newly changed files. The
producer must bind the complete reviewed Git tree and immutable OCI build
context, and the new owner signature must be verified independently at
Task014 before enabling regular signed upgrade and rollback. None of that
may be bypassed by modifying 0.15.0 historical pins.

## Task013 successor source and OCI preflight, isolated source-only implementation

The existing `release/analytics_task013_build_input.py` exposes
`review_successor_build_input` for a new exact Analytics Git commit. It calls
the already reviewed `verify_owner_source_selection` against the real
GitHub workflow identity, exact source Git origin/HEAD/tree and original
0.15.0 ancestry, then the original `snapshot_committed_tree` producer.
The complete eligible Git file set is materialized into one temporary
deterministic, regular-file-only source archive with the original size/path/
exclusion rules. Dockerfile, .dockerignore, runtime health and OCI test source
hashes derive from **the archived Git bytes**, not an editable list of 49
release-specific hashes. It records whole-tree SHA, context SHA256 and number
of included files. The existing immutable 0.15.0 product/runtime configuration
is checked independently and is not misrepresented as a new source SHA.

The existing `release/analytics_oci_archive.py` accepts the strictly closed
new **schema 2 unsigned review receipt** as well as the unchanged original
schema 1/78-file receipt, and reuses the original OCI image descriptor/layer
hash verification, Linux/amd64, UID10001, fixed Next server command, localhost
port contract and forbidden runtime secret environment checks. In both cases
the result explicitly denies release/deployment authority. The successor
source/OCI contract was exercised with independently created local temporary
Git histories and synthetic OCI layer manifests. Those tests do NOT prove a
real BuildKit build, authenticated registry or vulnerability scan.

**Hard HOLD:** The original published Task013 workflow still checks out the
literal PR52 SHA, uses original static 49 critical hashes and build-candidate
source SHA, and invokes the original signer. Those gates are deliberately
NOT changed by this preparatory code. A GitHub actor/payload-only validation
does NOT allow executing an unapproved successor Dockerfile in the protected
Task013 build job. Before replacing those hard pins, complete the separately
approved owner-held signing-key trust decision and independent signer
verification across the Task013 and root-controlled Task014 boundaries.
After that, integrate the already existing pinned Buildx/BuildKit with the
exact reviewed Git context, original scanner/SBOM/zero-high policy and signer;
only then change the protected workflow and install an independently reviewed
upgrade/rollback-aware Task014 consumer. No temporary bypass, fake signed
receipt, dynamic caller-selected version or new build infrastructure is
permitted.

## Successor Task014 owner-authenticated registry readback, isolated candidate

The existing `release/analytics_owner_source_selection.py` now includes
`load_and_verify_owner_signed_source`, which reconstructs the exact approved
product SHA/tree, SemVer, platform workflow SHA and owner identity from a
bounded, canonical JSON approval, then checks a detached real Ed25519
signature against the independently root-controlled DEV signer allowlist.
The version is above 0.15.0, unknown fields, duplicates, altered content,
missing trust anchor and wrong signatures all fail closed. It does not rely
on an untrusted caller-supplied approval receipt or a GitHub-side public key.

The existing `deployment/analytics_signed_release_consumer.py` exposes
`review_owner_approved_analytics_signed_evidence` and
`acquire_and_review_owner_approved_analytics_release`. The latter reads the
root-verified owner approval BEFORE any private registry credential, retrieves
the exact selected version from the existing authenticated Forgejo route,
reuses the original signed manifest/provenance, Sigstore/Cosign and scanner
policy verifiers, and ONLY THEN performs an authenticated, digest-addressed
Zot GET. The downloaded OCI manifest hash, Docker-Content-Digest header and
signed release digest must all match. This is a read-only consumer extension,
and the prior 0.15.0 GET/verifier path stays unchanged.

The test suite includes a **real disposable Ed25519 signature** over
synthetic canonical source approval bytes, synthetic original Sigstore/Cosign
results, and the existing no-network TLS HTTP-response fixtures for the
original Forgejo and Zot consumers. These are not live external registry
transactions or real current-release Sigstore cryptographic proofs.
Every returned result remains inert and cannot authorize deployment.

**Remaining HOLD:** The owner-controlled DEV trust anchor is not provisioned;
producer verification prior to executing successor Dockerfile, approved
reviewed product changes, protected workflow checkout, original release
scanner/sign/publish integration, actual Task014 OIDC/replay/executor,
stable private blue/green traffic switching, write-preserving rollback,
independent M04 acceptance and separately owner-approved live deployment
are still required. No new public endpoint, service, Docker, database,
registry or root change occurred.

## Successor schema 2 producer-to-consumer compatibility (2026-11-03)

The **existing** Analytics-only Task013 source and evidence modules now support
an explicitly differentiated schema 2 successor claim without rewriting the
original 0.15.0 schema 1/78-file claim. Schema 1 remains reserved for the
PR52 commit. Schema 2 instead binds the exact successor Git commit/tree,
the complete bounded deterministic Git archive count/context SHA256, matching
SemVer and the SHA256 of canonical detached-owner approval, together with
the existing exact OCI archive/manifests, product/runtime profile hashes,
Dockerfile/.dockerignore/OCI test source and protected workflow commit.

The new `prepare_successor_source_claim` in
`release/analytics_release_source_binding.py` reuses
`review_successor_build_input`, `snapshot_committed_tree` and the
original `verify_archive`. It **regenerates** the complete build context
and matches the supplied TAR byte length and SHA256, then verifies all
OCI blobs, original runtime hardening and immutable manifest digest. It
does not load arbitrary caller-supplied source receipt bytes.

The original production-relevant
`release/analytics_release_evidence.create` now validates strict schema 2
fields and source identity while retaining its original Grype database
validation, zero-waiver Critical/High policy, scanner SHA256 provenance,
existing Sigstore certificate identity and Forgejo publish preparation.
The original `deployment/promotion._verified_external_source_claim`
and `deployment/analytics_signed_release_consumer` now parse schema 1
or schema 2, with exact key sets and no other schema/downgrade. The
`review_owner_selected_signed_analytics_source` boundary additionally
requires the signed schema 2 owner-approval hash to match the **independently
verified** owner signature receipt. The original 0.15.0 source verifier
does not silently permit any successor as schema 1.

One local end-to-end synthetic integration test uses an actual temporary
Git history to construct the deterministic source TAR, synthetic OCI
archive, complete schema 2 source claim and original Analytics release
manifest/provenance bytes, then runs the original Task014 read-only
signature/source parser with **synthetic** Sigstore/Cosign verifier returns.
It rejects source-archive modification, root-user OCI image, source
version mismatch and owner-approval SHA substitution; no real signed
release or registry publishing took place.

**Still HOLD:** The protected GitHub Task013 workflow still pins 0.15.0
in both private checkouts and in `analytics_task013_build_candidate.py`,
and still uses its original 78-file-only source/publisher stages.
Schema 2 support in the code alone does NOT make an owner-selected
successor Dockerfile safe to execute. A separately approved trusted owner
signer anchor and real owner signature verification must be enforced
BEFORE any such BuildKit execution, preserved across the scanner/handoff,
protected Zot/Forgejo and independent root-owned Task014 verifier.
The installed Task014 broker/executor/ingress/rollback is still first-install
only; no new release approval, CI dispatch, root/registry write or
deployment was performed.

## Pre-BuildKit owner-signature gate for a future successor (2026-11-03)

The existing `release.analytics_owner_source_selection` module now offers
`review_ci_owner_signed_source`. It verifies the selected product's ACTUAL
Git origin, commit, original 0.15.0 ancestry, tree, protected workflow SHA,
owner actor and exact SemVer. Only after those checks does it verify the
canonical detached SSH/Ed25519 approval signature using a single independently
configured signer allowlist. The signature is transported as strictly canonical
base64, with size limits, exact owner identity and signature namespace.

The existing `release.analytics_task013_build_candidate` keeps its original
0.15.0 default path and exact `EXPECTED_SOURCE` pin. Its optional successor
mode now calls the owner-signed Git gate **before the original pinned Buildx/
BuildKit builder is inspected or invoked**, recomputes the complete Git source
context and compares all expected hashes and source counts, reuses the
ORIGINAL `verify_archive` OCI-hardening checks and returns only an UNSIGNED
version 2 local OCI/approval-hash receipt, all release/deployment authority
flags FALSE. The Docker command still has NO `--push` or mutable tag.
A test signs an actual temporary Git history using a disposable Ed25519 key
and simulates the actual builder's OCI output; wrong signature/actor/version/
Git SHA/key all reject **before** invoking the builder. No real Docker build
or release signature has been executed.

The new `--successor` CLI is explicit and fail-closed. It is not yet
referenced in `.github/workflows/platform-release.yml`. When a reviewed
protected workflow does activate it, the original GitHub context must be
read from actual runner-provided `GITHUB_*` environment variables. Future
workflow inputs `ANALYTICS_SOURCE_COMMIT`,
`ANALYTICS_RELEASE_VERSION` and
`ANALYTICS_OWNER_SIGNATURE_BASE64` identify the exact proposed release.
`ANALYTICS_OWNER_ALLOWED_SIGNERS` must come from an out-of-repository
independently configured CI setting, NEVER checked-out source, dispatch
input or caller-provided path. A CI runner is NOT the final source-approval
trust root: the existing DEV host's separate root-owned key allowlist and
original Sigstore/Cosign/Task014 OIDC/replay verification remain mandatory.

**Owner approved the signing model on 2026-11-03:** an owner-held
Ed25519 private key remains on the owner's own computer, with separately
managed public-key configuration for protected CI and root-owned DEV.
This approves design and continued code implementation, NOT key generation,
provisioning, release dispatch, service changes or deployment. No key has
been generated/provisioned, and no
workflow secrets, checkouts, release actions, live services or registry
writes have been changed. The approved legacy first-install and Canary
release workflows remain their original form. Do not activate `--successor`
or move the workflow checkout to dynamic source until the entire protected
scanner/publisher/handoff and Task014 recovery path has been reviewed and
the owner authorizes the material trust setup.

## Protected successor Zot and Forgejo signer handoff, inert local integration (2026-11-03)

The original `release/analytics_publish_zot.py` now supports an **optional**
`--successor-claim-file` mode while leaving historical 0.15.0 publication
unchanged. The new mode uses the same protected CI context loader as the
BuildKit entrypoint; it does not accept a public signing key from a CLI
option or Git checkout. BEFORE calling `_load_token` or creating the
original authenticated Zot client, `verify_successor_publisher_handoff`
independently verifies real Git origin/commit/tree/0.15.0 ancestry,
original protected workflow identity, detached owner Ed25519 signature,
full regenerated deterministic Git source TAR, exact OCI archive contents
and SHA256, original runtime hardening, version and **byte-exact canonical
schema 2 claim from the private encrypted handoff**. The original Zot
version-absence check and authenticated digest/tag readback are retained;
a mismatching old claim, altered approval, source TAR, signer or release
version cannot initiate any Zot operation.

The existing `release/analytics_release_evidence.py` can now require
`--successor` at the final protected signer stage. Unlike the source and
Zot jobs, this original Forgejo job does NOT check out Analytics Git.
It therefore rechecks the same canonical exact owner source approval
signature and approved claim/hash against actual GitHub runner context
and intended source version, without asserting an independent Git
checkout. A schema 2 claim without a valid detached signature is DENIED
before the original Grype/SBOM, provenance and Sigstore input generation.
Supplying successor approval to historical schema 1 is also DENIED.
Original Task013 zero-waiver/zero-Critical/High policy, Sigstore keyless
GitHub OIDC certificate and immutable Forgejo publication remain
unchanged and still mandatory.

Tests use **actual disposable Ed25519 signatures and real Git history**
plus a synthetic OCI archive and fake no-network Zot client; negative
cases prove mismatched source/claim/approval/actor/version and altered
transport never access the OIDC credential or the fake registry.
Protected Forgejo successor evidence has positive and negative real
Ed25519 verification, with synthetic scanner policy outputs. No
real remote signatures, OIDC tokens or registry writes are claimed.

**HOLD:** `.github/workflows/platform-release.yml` remains deliberately
UNCHANGED and still references PR52 0.15.0 in both checkouts and all
source/scan/publisher stages. The optional successor code is *not*
installed or active; the protected owner signer configuration and
root-controlled Task014 trust key require separate owner approval.
The final automated blue/green executor/ingress, rollback and M04
independent acceptance are not ready. No successful actual next-version
release or deployment exists.

## 2026-11-07: closed 23-file V2 root-owned service source grammar (candidate only)

The existing `deployment/analytics_executor_service_config.py` now accepts
an *explicitly root-selected* schema-2 source configuration whose file hashes
cover exactly `ANALYTICS_SUCCESSOR_INSTALLED_FILES` (23 Python modules,
including the owner source verifier). The original schema-1 configuration
still requires its original 20-module set and cannot accept the additional
files. The descriptor-relative `O_NOFOLLOW` installed-source verifier accepts
only one of the two exact ordered module vectors followed by the unchanged
four runtime assets. It rejects extra, missing, reordered, altered, symlinked,
non-root-owned or improperly permissioned sources. A V2 test exercises actual
filesystem file descriptors with projected root metadata and real hash checks.

The source grammar and V2 hash validation do **not** enable schema-3 routes,
consumer trust, broker forwarding, executor replay or blue/green deployment.
An independently authorized root-owned exact-source generation and systemd
transition, plus the verified signed source/OCI and recoverable task execution,
are still required. Original signed 0.15.0 remains the only installed release.

## 2026-11-07: Git-exact V2 source/config input generation (not root install)

The original `build_unsigned_analytics_activation_inputs` now has a closed,
optional `successor_source=True` review mode. It reuses the original
Task014 Git-plumbing + canonical V2 35-entry source manifest/archive, checks
each 23-module SHA against immutable Git objects, and emits root/broker
configuration for schema 2. The unchanged default generates the same V1
20-module configuration and 32-entry original source archive. No caller can
choose an arbitrary file list, release SHA, registry or deployment route.

This V2 output intentionally includes a schema-2 **unsigned** approval that
the *currently installed* root-only first-install parser does not accept.
Do not place it on the host or call it a usable installation: the already
installed 0.15.0 source generation cannot be overwritten in place. Its safe
one-time V1-to-V2 replacement must independently preserve original source,
active 0.15.0, signed provenance, DB writes and rollback before any schema-3
executor promotion. The new source generator has no host, registry, replay,
systemd, Docker or secret side effects.

## 2026-11-07: review-only V2 candidate beside active V1 (no live cutover)

The original root-only V1 first installer remains byte-compatible. The new
root-only `stage_approved_analytics_successor_candidate_generation()` uses
**separate exact root-owned 0600 approval and TAR files** and a canonical
schema-2 owner-approval whose sole permitted destination is
`/opt/omnilyzer/deployment/analytics-app-candidate`. All Git TAR bytes and
SHA entries must match the 35-source V2 manifest. The existing C31B verified
legacy preimage, descriptor-relative O_NOFOLLOW staging, exact 73-file hash
audit, fsync and scoped rollback are reused. The active
`/opt/omnilyzer/deployment/analytics-app` must already exist as an approved
root-owned directory and remains untouched, even on a simulated candidate
rename failure. A preexisting candidate or stale staging directory fails closed.

**Do not call this source staging a Task014 deployment.** The fixed candidate
source directory is inactive; it does not replace the active installed source,
install a service or authorize schema-3 broker/UID991 executor requests. Before
any later cutover, separate owner authorization, verified source/signature and
actual root-owned service migration/rollback/reconciliation are mandatory.
The currently installed signed Analytics 0.15.0 is preserved.

## 2026-11-07: fixed generation-to-directory binding before service activation

The existing broker and executor installed-source loader now select exactly
one root-owned product source directory from the protected configuration:
**schema 1** binds only the 20-module V1 list and
`/opt/omnilyzer/deployment/analytics-app`; **schema 2** binds only the
23-module V2 list and
`/opt/omnilyzer/deployment/analytics-app-candidate`. The original fd-relative
`O_NOFOLLOW`, root UID, immutable SHA/size/ctime/mode/inode and four runtime
asset checks are reused without allowing caller-supplied paths. Crossed V1/V2
manifest/root combinations fail before opening the first source descriptor.
The original broker and executor security collaborators, identities and
installed 0.15.0 source remain unchanged. A root-owned config alone does not
authorize an upgraded service or any schema-3 deployment; the separately
protected systemd entrypoint, genuine signed release, durable replay and
rollback cutover are still pending.

## 2026-11-07: review-only V2 service source transition plan

The existing `build_unsigned_analytics_service_inputs` now accepts the
explicit `successor_source=True` flag. It first verifies the entire canonical
35-entry V2 archive, 23 exact source hashes, approved fixed inactive candidate
path and matching broker/executor root-owned source config. It returns the
original four V1 systemd service inputs byte-for-byte **plus exactly two**
V2-only fixed `analytics-v2-source.conf` drop-ins. Both contain only
`[Service]` and `WorkingDirectory=/opt/omnilyzer/deployment/analytics-app-candidate`.
No arbitrary path, command, UID, runtime secret, Docker socket, service restart
or ingress mutation is accepted in either drop-in. The executable Python
command continues to come exclusively from the original source-verified unit.

**V2 drop-ins are inert review files, not a deployment procedure.** Their
separate root-owned installation and active config switch must be authorized
only after the exact signed successor schema-3 release, independently verified
source/OIDC/replay, current live OCI state and rollback route are integrated.
An approved rollback would remove only these two V2 drop-ins, restore the
original protected V1 config and confirm the unchanged V1 source and service
status, with durable route journal reconciliation. None of that privileged
activation or rollback is performed or authorized by the builder.

## 2026-11-07: actual UID991-only first-successor read-only manifest/OCI probe

The existing `AnalyticsPrivilegedExecutor` has a separate
`preflight_first_successor_without_deployment()` method. This is **not** the
schema-3 deployment API. A caller-constructible canonical request cannot
obtain execution permission: the method checks exact product OCI request
shape, one `analytics-successor` kernel-sealed credential FD, UID991 executor
identity, the independently observed healthy original signed 0.15.0 blue
container, the exactly staged green candidate/3142 private route, the
unchanged rollback digest/slot, and the existing successor-only Zot **manifest
PROBE**. It observes the rootless live state again after the manifest read,
rejecting a changed container/route. It does not invoke Docker pull, deploy,
replay begin/finish, route journal mutation, ingress change or rollback.

The existing Unix receiver offers an **explicit test-only**
`verified_successor_preflight_only=True` probe mode. It reuses the original
kernel `SO_PEERCRED`, `SCM_RIGHTS`, request framing, fd scope and validation.
After a successful preflight, it still raises the original *rejected* result;
no response indicating accepted deployment is ever sent. It cannot be combined
with structural successor test mode. The installed schema-2 receiver's default
and original 0.15.0 live service are unchanged. A real isolated AF_UNIX test
checks the sealed FD and actual receiver callback through the original
framing/peer implementation, asserts no durable replay, and confirms denial.

**Remaining permission gap:** broker verification of Ed25519 owner approval,
GitHub OIDC, Cosign/Sigstore and Forgejo must be conveyed across the trust
boundary in a way the UID991 executor can independently validate; a Python
signed-evidence dataclass or this read-only probe is not sufficient. The true
schema-3 receiver, durable replay, candidate pull, health, route journal
switch and rollback remain fail-closed and require one independently reviewed
integrated release candidate. No root-owned installation, registry write,
service activation or deployment is authorized by this change.

## 2026-11-07: independent real owner signature at UID991 before successor host reads

The existing executor's `preflight_first_successor_without_deployment()`
now **reuses** `release/analytics_owner_source_selection.py` to verify a real
OpenSSH Ed25519 detached signature from the exact root-owned trust anchor
`/etc/omnilyzer/deployment/dev/analytics-owner-source-signers`. The two
separately installed immutable review input files are required at fixed paths:
`/etc/omnilyzer/deployment/dev/analytics-owner-source-approval.json` and
`/etc/omnilyzer/deployment/dev/analytics-owner-source-approval.json.sig`.
These must be installed/provisioned by an authorized privileged owner process
under the original protected systemd directory policy. No request-supplied
path, signer, key or Python receipt is accepted. The verifier checks the
original canonical source approval bytes, detached signature, source commit,
platform workflow commit, release version and approval SHA against the
canonical schema-3 request before any Docker/RootlessKit or private Zot probe.
Missing root trust/key/approval/signature, unknown signer, altered bytes or
mismatched source identity deny. Test-only fixtures generate an actual local
Ed25519 key to exercise OpenSSH signature validation, never install it as a
real trusted signer, and prove denial occurs before host API access.

**Still HOLD:** The required owner signer is not confirmed installed on the
actual DEV host; this code must reject a real request until authorization and
provisioning. Owner source signature is separate from GitHub OIDC and Task013
Cosign/Sigstore/repository + SCA attestation: those are NOT yet independently
reverified by UID991 over an authenticated successor request. The method
remains read-only and the Unix handler still hard-rejects promotion after
preflight. Actual persistent replay, immutable OCI pull, rootless 3141
cutover and journaled rollback are not implemented here. Signed Analytics
0.15.0 continues unchanged.

## 2026-11-07: closed broker successor-to-UID991 read-only transport composition

The existing `AnalyticsPrivatePromotionBroker` now has a separate internal
`forward_verified_first_successor_probe_without_deployment` method. It first
runs the already implemented, real triple JWT/OIDC + independently rooted
owner approval + original 0.15.0 signed evidence + successor verified
Sigstore/Cosign source/OCI review and exact schema-3 parser. It re-verifies
all nine GitHub OIDC identity fields against the reviewed schema-3 request
without loosening the original schema-2 identity binder; it independently
rechecks the actual Zot/Forgejo JWT audiences, credential validity and
remaining TTL, then creates a Linux sealed `analytics-successor` Zot FD bound
to the exact reviewed canonical request and future immutable image digest.
The FD is closed on all branches. The original schema-2 sender, registry
scopes, bearer transport, durable replay, source pin and service composition
are preserved byte-for-byte. No new transport or release framework exists.

The method is NOT registered in the active HTTPS router or installed broker
service, and deliberately does **not** consume broker replay. The separate
UID991 read-only successor receiver also rejects after verified preflight.
A failed socket or even a counterfeit `accepted` reply is always an
unavailable error; there is no product deployment success status and no
privileged image pull, traffic switch or database modification. Synthetic
signed/registry test fixtures verify concrete kernel-sealed image/FD scope,
source identity checks, no replay, FD cleanup and no fallback to legacy 0.15.0
or Canary. These synthetic fixtures are not real release proof or permission.

**Remaining HOLD:** A real receiver must still independently authenticate
full GitHub/OIDC, Sigstore/Cosign, original Task013 SBOM and signed provenance
through a verifiable cross-privilege evidence mechanism, then use persistent
anti-replay, a qualified immutable candidate image pull, health checks and
journaled blue/green cutover/rollback. The root-owned signer/approval sources
must be provisioned only under separately authorized DEV policy. A normal
successor release is not ready, and signed Analytics 0.15.0 remains active.

## 2026-11-07: actual broker-to-UID991 kernel-boundary joint regression

A new test within the **existing**
`deployment/tests/test_analytics_unix_boundary.py` constructs a disposable
real AF_UNIX listener, protected peer-checked Analytics transport, OpenSSH
Ed25519 signed owner-source fixture and the unchanged broker, handler and
privileged executor classes. The broker verifies its existing test OIDC and
synthetic old/new registry release receipts, then re-verifies a genuine signed
owner source, creates a short-lived sealed exact-digest Zot FD, transfers it
through the real `SO_PEERCRED`/`SCM_RIGHTS` boundary, and invokes the UID991
read-only active/candidate OCI and Zot manifest preflight. The receiver must
ALWAYS reject promotion. The test checks that neither replay implementation
begins, the credential FD is closed, old/new release review methods were
invoked, and live OCI state is inspected both before and after manifest read.
A second test mutates the real detached owner signature and verifies denial
**before** sealing or transferring any credential. No live signer key, JWT,
release or rootless Docker socket is used; the synthetic OIDC/release/OCI data
is explicitly **not** cryptographic Task013 acceptance. The original 0.15.0
live DEV service and HTTPS routing remain unaffected.

This verifies the joined **negative/safety** journey, not the positive
release acceptance. The existing first-successor handler still rejects even
correctly signed and health-checked candidates. A real schema-3 deployment
with independent UID991 Task013/Sigstore/Cosign evidence, persistent replay,
image pull, health/route transaction, restart reconciliation and rollback
remains HOLD until separately authorized and independently reviewed.

## 2026-11-07: resolve first-successor pre-pull/post-pull ordering

The original schema-3 **read-only** executor preflight had required an
already-running and privately healthy green candidate, creating a circular
prerequisite for a first, as-yet-unpulled successor. The same existing method
now retains a **strict default** `candidate_ready=True` for post-startup
health/digest/3142 verification and accepts an internally selected
`candidate_ready=False` *pre-pull review* only for an independently verified,
healthy signed 0.15.0 blue image with **no** candidate probe/route/digest.
Both stages independently verify the exact root-owned Ed25519 source approval,
sealed successor Zot FD, rollback identity and immutable registry manifest;
both re-read live OCI and the route after the bounded manifest read.

Crucially, the pre-pull phase now also reads the FIXED green container endpoint
using the original allowlisted, read-only UID991 rootless Docker client and
requires a genuine 404/absent container (not merely no port 3142). A stopped,
unrouted, stale or unknown green container requires separate recovery and is
never silently adopted. The exact green-absence check is repeated after the
Zot probe to close a simple create/reuse race. Missing rootless API, wrong UID
or noncanonical boolean phase fails closed. The installed Unix handler still
invokes the strict post-startup default and still rejects every schema-3
promotion; the new pre-pull option is NOT wired to a deployment action.

This corrects the safety/release sequencing contract, not the remaining
functionality: owner-signed full Task013 evidence, durable request replay,
actual authorized image pull, candidate creation/health, durable RootlessKit
route switch, restart reconciliation and rollback still need one integrated
end-to-end acceptance under independent M04 review. No signed 0.15.0 source,
service, Docker container, route or database is changed by this code.

## 2026-11-07: exact rootless successor image pull primitive (still not activated)

The existing `AnalyticsPrivateZotPullAdapter` now has an explicit
`pull_analytics_successor()` for a **future separately authorized** Task014
candidate stage. It reuses the original rootless Docker CLI, volatile 0700
runtime directory, ephemeral 0600 Zot auth config, exact immutable OCI
digest, 500-second bounded pull, token redaction and complete cleanup. Unlike
the fixed 0.15.0 pull, the next image is derived only from the canonical
schema-3 request. The new method requires the original UID991/GID991 product
executor, a genuine canonical root-trusted Ed25519 owner-source signature
matching source SHA, workflow SHA and version, and the original task-local
sealed `analytics-successor` Zot FD bound to the exact request/image. No old
schema-2 credential, forged request, caller-selected registry, unscoped FD,
rootful Docker socket or wrong principal is accepted.

Before attempting a pull, the module independently observes the original
signed blue 0.15.0 at localhost3141 and requires a completely absent green
candidate container, not merely an absent 3142 route. The original immutable
Zot `manifest inspect` remains a distinct preflight step. After its bounded
private pull, the adapter checks that the old writer's OCI/route snapshot
is byte-equivalent and the candidate container is still absent. Any drift
returns a hard, redacted error and prevents later deployment; the downloaded
image cache alone does not grant a service start or success receipt.

Synthetic local tests exercise a real temporary Ed25519 owner signature,
Linux sealed exact-digest credentials, actual scope/UID checks, a fake rootless
Docker command runner and ephemeral auth cleanup, including wrong credentials
and a changed active writer during the pull. **No real image, database, port
or service is altered.** The installed schema-2 executor and broker are still
pinned to 0.15.0; no schema-3 socket handler calls this method. A full signed
Task013 release attestation verified at the UID991 trust boundary, authorized
candidate Compose startup, health, anti-replay and durable route rollback
remain mandatory before any activation or release acceptance.


## 2026-11-07: staged candidate 3142 and crash-recoverable journal transaction

The existing deployment/analytics_loopback_guard.py has a source-only,
not-installed _stage_reviewed_private_candidate_probe operation. Its
explicit V2 UID991 supervisor checks the signed 0.15.0 blue image on
the first candidate, or a journal-verified previous writer on later releases,
a distinct hardened candidate image with immutable local RepoDigests, the
unchanged Canary3020 and Analytics3141 routes, and the
privately owned original RootlessKit Docker/bridge network. It requires the
fixed, fsync-protected AnalyticsRouteJournal and a nonzero canonical request
SHA from a separately verified signed Task013/OIDC/replay authority.
It creates only the next image's 127.0.0.1:3142 private health route.
The old writer at 3141 and Canary3020 remain untouched. No caller-provided
IP, public port, arbitrary image, mutable branch, key or registry is used.

The journal now uses the distinct durable phases prepared,
candidate_ready, switched, and restored. A PREPARED record is written
before the RootlessKit POST and cannot authorize the later cutover.
Only successful exact route inventory, both 3142 health checks, verified OCI
identity and fsync-confirmed candidate_ready permit the existing 3141
transaction to reuse the same request-bound journal record. A foreign
unfinished PREPARED or mismatched request/JTI continues to deny before any
3141 mutation. A failed 3142 POST/health/ambiguous acknowledgment triggers
scoped 3142-only cleanup, verifies signed old 3141 + Canary, and persists
restored. An unconfirmed rollback leaves the journal unresolved and
raises a hard operational HOLD, never a false GO.

Restart recovery is widened only to the identical journal: a process crash
after PREPARED but before 3142 publication safely confirms old 3141 and
persists RESTORED without mutating ports; an interrupted CANDIDATE_READY or
3141 cutover restores the signed previous writer and removes only the
exact journal-bound 3142 route before persisting RESTORED. Unknown Canary
or routing changes deny without speculative port mutation. All operations
remain under the original exclusive filesystem lock and original local
RootlessKit APIs. Isolated fake-API tests cover correct staging + cutover,
wrong identity/authority, bad POST acknowledgments, health failures,
unconfirmed DELETE, and three crash/restart timings. No live Docker/route,
secret, DB, source generation or installed 0.15.0 was changed.

Not release GO: The active V1 supervisor has no dispatch path to the new
candidate operation. Actual verified owner/GitHub OIDC/Sigstore/Grype
receipt at UID991, durable schema-3 replay, source-generation activation,
candidate Compose startup, controller/recovery service activation and one
approved real DEV deployment remain HOLD. This safety primitive cannot
self-authorize those missing release gates.


### 2026-11-07: next-generation reuse and post-cutover probe retirement

A completed journaled cutover now removes the temporary port3142 route
AFTER proving the new stable 3141 writer is healthy but BEFORE recording
the durable switched phase. This is mandatory: if 3142 still pointed to
the now-active writer, the existing rootless OCI observer would reject the
next successor as an ambiguous active/candidate combination. Success
leaves exactly two private rules: original Canary3020 and Analytics3141.

The existing rollback and crash-recovery paths accept both intermediate
inventories: candidate3142 still present or already retired. They restore
only the prior signed writer, remove only the exact request-bound 3142
rule when still present, recheck old /readyz + /livez, and record restored.
Unconfirmed API acknowledgment, wrong public forwarding or altered Canary
still yield a hard HOLD with an unresolved journal.

A first upgrade without any prior journal is pinned to signed blue 0.15.0.
Later upgrades reuse the SAME durable journal, which requires the old image,
slot and Docker container ID to match the last switched or restored state.
This permits green -> blue -> green releases without new hardcoded per-version
image IDs or route ports. Actual Task013 signed evidence and owner/replay
authorization must still be independently verified outside these low-level
routing primitives, and the existing V1 supervisor remains unmodified.
Synthetic tests now exercise both release generations and a crash between
retiring 3142 and fsyncing switched. None touch live RootlessKit or data.

## 2026-11-07: V2 Compose override now included in signed source closure

The original V1 20-module/32-Git-object/70-file root-approved source set is
unchanged. The V2 source graph now consists of the original 23 Python
modules **plus** exactly one runtime-critical file:
`deployment/runtime/dev/analytics.compose.successor-ports.yaml`.
The V2 Git handoff is therefore 36 objects, and the isolated candidate
root-owned source generation is 74 files including the previously attested
Canary inheritance. No new general-purpose source loader or release scheme
is introduced.

This additional file is necessary for safe staging: the successor Compose
`!reset []` directive must remove both successor host-published port
mappings so that RootlessKit alone owns localhost3141 and temporary3142.
The original first-install Compose still has historical port3141 and is
not rewritten. V2 root configuration lists the overlay's exact Git blob
SHA256 in `source_sha256`. The existing descriptor-relative root-owned
file verifier now checks the overlay's exact path, SHA, single-link 0644
regular file, immutable metadata and entire source closure before a V2
service can load. Caller-supplied mutable working-tree YAML cannot pass.
Only schema2 V2 source accepts this path, not the original V1 config.

The existing source archive/unsigned activation tests and one negative
tamper test verify that a change from `ports: !reset []` to `ports: []`
is rejected before any root write or Docker invocation. This is only a
prerequisite for candidate startup; the protected broker/executor still
have no authorized schema3 replay + Compose execution path, and there is
no release or deployment permission from this work.


## 2026-11-07: isolated green candidate startup primitive, not installed

The existing deployment/analytics_first_install.py now includes a
strictly separate, **source-only and uninstalled**
AnalyticsSuccessorCandidateOperation.stage_first_successor_green() that
reuses the same original Task014 rootless Docker CLI and UID-mapped secret
review. It does **not** use a new deployment framework, a mutable image tag,
a new token/session mechanism or a new service. The original signed V1
first-install path remains unchanged.

This first-successor-only operation requires UID991/GID991; independent
root-controlled owner Ed25519 source approval; a sealed per-request Zot
credential bound to the canonical schema-3 request and immutable OCI image;
the original signed blue 0.15.0 still healthy/active on localhost3141 and
genuinely empty green Docker slot; and existing Docker/Compose authority.
It calls the existing root-owned source loader with
require_successor=True, which explicitly DENIES original schema1 V1.
It also requires the two actual Compose file paths to live **inside** the
fixed, root-approved /opt/omnilyzer/deployment/analytics-app-candidate
generation. Its fixed V2 Git source closure attests the Compose !reset []
host-port override. An unrelated development worktree or path substitution
cannot supply a Docker Compose file by merely matching V1 hashes.

The original bounded Zot adapter pulls only the exact signed digest using
ephemeral 0600 Docker auth; the candidate operation independently checks
local RepoDigests, the original rootless network's exact ID and Internal=true,
and the new container's same private network ID, distinct non-public IP,
UID10001, read-only root, no-extra-capabilities, no new privileges and
zero host-published ports. Only the inactive analytics-green profile can be
started (--no-recreate --no-build --pull never). Internal container
/readyz and /livez plus Docker healthy state must pass before returning
the exact green container ID. **No 3142 probe, RootlessKit route switch or
public URL is created at this stage.**

The original Task014 monotonic deadline limits overall review, cold pull
and startup to 570 seconds, leaving a separate stop-only rollback reserve
if the partial candidate start fails. Failures never stop signed blue,
remove a volume/network/image, or touch PostgreSQL. Exact request hash and
candidate container ID scope an optional stop-only rollback after a later
executor finalization failure.

Synthetic tests use a real disposable OpenSSH Ed25519 signed source, actual
Linux sealed FD credentials, real source byte/path contracts, a fake Docker
runner and negative cases for untrusted UID, missing source, wrong identity,
wrong image/digest, public port or network, shared IP, unhealthy or delayed
startup, expiration/rollback, and wrong request/container. No real image
was pulled, created, stopped, published or routed by these tests.

**IMPORTANT HOLD:** This is only an *unwired low-level capability*. The
installed schema2 receiver still DENIES schema3. A future separately
authorized root-owned V2 service and authenticated broker/executor must
verify the **full** signed Task013 Sigstore/Cosign/SBOM/provenance/zero-high
policy and GitHub OIDC independently at the UID991 boundary and consume
the durable SQLite replay **before** invoking this class. After staging,
a separately authorized stage must journal the private 3142 route, re-check
health and execute the recoverable 3141 cutover. No such end-to-end DEV
success, approval or production rollout is claimed by this source change.


## Task14B V2 broker schema3 signed read-only ingress (2026-11-07)

The existing original HTTPS/loopback ingress remains **4 KiB**, and the
canonical first-successor schema3 request fits within it (2,655 bytes
in the checked test fixture). The original router rejects schema3 by
default. A read-only successor review can be captured only when the
root-verified Analytics broker source loader explicitly returns
`source_generation=2` from the exact protected V2 configuration and
fixed candidate installation. The original four-hash loader result and
schema1/0.15.0/Canary router behavior remain unchanged.

The V2-only route uses the already existing
`AnalyticsPrivatePromotionBroker.forward_verified_first_successor_probe_without_deployment`,
which verifies exact owner-signed source, original GitHub OIDC, signed old
and successor Task013 evidence, Zot/Forgejo scoped credentials and real
sealed FD. The receiver **always rejects**, even after successful
read-only kernel/UID991 inspection. The route cannot report 202, consume
replay, start a container, switch traffic or grant deployment. It responds
with the existing sanitized unavailable result for a structurally valid
schema3 request until independently reviewed and installed successor
execution is implemented.

The routing and root-generation regression uses the actual original
V1 handlers and a synthetic V2 counterpart to prove 0.15.0 and Canary
remain isolated; this is source-only evidence, not a live verified
owner-signature release or installed V2 service. The still-missing full
Task013 immutable Sigstore/Cosign/SBOM/zero-high evidence validation at
UID991, durable replay, OCI startup/3142/3141 cutover and write-preserving
rollback are **HOLD**. Do not silently promote this DENY-only preflight
into an accepting handler. A separate privileged release/installation
authorization and independent M04 review remain necessary.


## Task14B M05 sealed successor three-JWT read-only transport (2026-11-07)

The existing `deployment/private_registry_fd.py` now defines a **separate**
`analytics-successor` sealed FD **schema 2** carrying a scoped Zot-read JWT,
Forgejo-read JWT and deployment GitHub OIDC JWT. The existing broker first
authenticates each token for the reviewed GitHub repository, exact workflow,
run, three required audiences and read scopes; it then seals the three raw JWTs
into a kernel `MFD_ALLOW_SEALING`/CLOEXEC memfd. The existing `SCM_RIGHTS`
Unix transport passes exactly one descriptor, and UID991 can independently
read the original token trio through
`read_sealed_successor_review_credentials`. The signature-bearing tokens
never appear in the canonical request body, process arguments, environment,
disk, logs, exceptions or normal object representation.

The old six-field schema-1 memfd remains **unchanged** for Canary and signed
Analytics 0.15.0; the prior single-token successor read-only probe remains
valid solely for backward-compatible non-deploying tests. Schema-1 **cannot**
be mistaken for a complete three-JWT successor proof. The new schema-2 is
restricted to the original canonical schema-3 Analytics image/release request
SHA256 and a maximum of 27 KiB, validates kernel seals, 0-link inode,
exact payload identity, bounded printable compact token grammar, Zot expiry,
and no mutable OCI tags. It is **not** a cryptographic validation or deploy
authorization. No systemd/Docker/RootlessKit/network operation or replay
mutation is introduced in this transport.

**Actual remaining acceptance block:** UID991 must independently validate
the three JWT signatures and exact run/workflow claims using **its own
root-reviewed workflow SHA**, then independently acquire and verify original
Task013 Forgejo signed release, Sigstore/Cosign/provenance/SBOM/zero-High
policy, immutable Zot manifest and owner-signed source. These checks
must precede the durable SQLite replay begin, exact OCI pull, journaled
private 3142 probe and 3141 swap, and all success receipts. The currently
installed root-owned V1/V2 sources do **not** yet authorize the positive
schema-3 receiver; it always rejects. The new FD alone is not deployment.
No protected service change, owner authorization, new signed release or
M04 integrated acceptance is claimed in this increment.

### M05 next proof increment: independent UID991 three-token OIDC validation

`deployment/analytics_executor.py::_verify_executor_successor_identity`
now performs actual JWT **RS256/JWKS** verification of the forwarded, kernel-
sealed **schema-2** successor bundle. It reuses the original
`GitHubOIDCVerifier` and `GitHubRegistryCredentialVerifier`, checks all
three distinct audience/issuer and same-run restrictions and requires exact
actor, repository, workflow revision, GitHub run/attempt, JTI, issued-at and
expiry values in the canonical schema-3 request. Wrong signer, wrong
audience/workflow, mismatched request fields, expired credential, or original
one-token schema-1 FD all fail closed. This isolated proof has no container,
network registry, filesystem write, replay consume or success response.
The original 0.15.0 module import remains compatible with its historical
one-token FD: the schema-2 symbol is imported only when this future helper
is explicitly invoked.

The root-reviewed **schema-2 Analytics executor configuration** now
contains one additional, exact `expected_workflow_sha` field. The signed
historical Task014 DEV workflow revision is pinned once in the existing
unsigned V2 source-input builder; it is never accepted from the promotion
request, FD, HTTP header or broker assertion. Schema-1 keeps its original
eight keys and byte contract and rejects this extra field. Schema-2 rejects
missing/zero/invalid workflow SHA and uses the existing root-owned
fd-relative source reader to bind it to all 24 immutable V2 sources.

The original Analytics executor bootstrap accepts this pin only from its
root-verified schema-2 configuration. The existing product-specific
composition then selects the pre-existing **deny-only** UID991 schema-3
handler; this handler now performs **actual three-JWT cryptographic
verification before host OCI/manifest checks**, and it **still rejects
every request** before replay, pull, service, traffic or DB mutation.
Direct read-only probe test fixtures without the root V2 pin remain
synthetic and may never stand in for runtime deployment evidence.

This is a real protected source/interface change but **not** an
installation or release. A one-time separately approved root V2 source
upgrade is still required. The positive release-consumer verification,
replay-admitted candidate start, journaled cutover and rollback are not
implemented in the live schema-3 dispatcher and remain mandatory blockers.

**Important not-yet-wired trust boundary:** The helper intentionally requires
`expected_workflow_sha` as a separate *independently reviewed* input. This
must be obtained from a root-owned, V2-verified executor configuration,
not copied from the incoming request or broker assertion. Until that input,
the full independent Task013 Forgejo/Cosign/SBOM release review, durable
replay, candidate start, and journaled 3142-to-3141 cutover have all been
wired with negative real-host tests, the protected successor Unix receiver
**must continue to deny**. Cryptographic proof of identity by itself never
grants authorization to publish or deploy. Existing Canary, 0.15.0, rootless
systemd and signed-release policy are unchanged.

## M05 UID991 independent original Task013 signature proof, source-only (2026-11-07)

The original installed Analytics 0.15.0 and Canary verifier code and runtime
remain untouched. The existing signed successor broker at UID990 already
performs a complete Task013 read-only check. The future separately installed
UID991 executor must independently verify the **same original signed release
archive and OCI signature**, not accept broker-returned Python receipt values.

The current source-only `deployment/analytics_executor.py`
`_review_executor_successor_signed_release` reuses the original, unchanged:
- three real GitHub/JWKS-issued JWT verifiers and kernel-sealed FD credentials;
- fixed root-held owner Ed25519 exact product/owner/source selection;
- zero-input `DevSigstoreVerificationProvenance` reviewed upstream Cosign
  binary SHA256 and Sigstore TrustedRoot SHA256, with no values from the request;
- `CosignReleaseBlobVerifier`, `CosignOCISignatureVerifier`, and the original
  `acquire_and_review_owner_approved_analytics_release` reader for the Forgejo
  tarball, actual Syft/Grype policy artifacts, provenance, SBOM, Cosign
  signatures, exact source claim and immutable Zot manifest;
- original `parse_analytics_successor_request` checks, including the exact
  signed manifest/provenance/OCI/source hashes, verified OIDC run/workflow,
  previous blue 0.15.0 digest and write-preserving rollback identity; actual
  local active state is read before AND after bounded registry verification.

**No second verifier framework or modified common Cosign code.** The existing
Cosign verifier requires its original immutable paths:
`/opt/omnilyzer/deployment/tools/cosign-v3.1.2-linux-amd64`,
`/etc/omnilyzer/deployment/broker/sigstore-trusted-root.json` (verify actual
original `broker_service_config` constant before any installation), and
private runtime directories under `/run/omnilyzer/deployment/dev`.
These directories are currently UID990 broker-owned; UID991 MUST NOT receive
the broker's supplementary group or permission to read the broker's live
credentials/configuration. Before any actual V2 UID991 installation, a
separately owner-approved root-controlled service/private mount namespace must
provide **separate reviewed root-owned readonly copies** of the exact Cosign
binary/TrustedRoot at the *unchanged original paths* ONLY inside that
executor's private mount. Parent ownership, group991, mode, upstream SHA256,
unchanged Cosign certificate identity/issuer, bounded temporary working
directories, startup reconciliation, service immutability and restart/rollback
must all be independently reviewed. The unchanged UID990 broker must continue
to see only its original files. NEVER bind or chgrp the original live broker
directory for UID991 globally.

The V2 unsigned source inventory now includes the original C32I
`deployment/sigstore_authority_provenance.py` through the exact immutable
Git object manifest: **37** review-source entries, **25** Analytics V2
installed source objects (original V1 still exactly 32 and 20 respectively),
and a proposed **75-file inactive candidate** retaining original inherited
sources. This is an auditable source closure, not a root-owned install.

Synthetic tests prove all three JWT audiences pass actual RSA signature
verification and are bound to the real original signed-evidence reader and
immutable verifier inputs; forged source, owner, signed subjects, untrusted
UID and active writer drift fail closed. A synthetic signer/host fixture is NOT
a real Cosign/Forgejo/OCI/UID991 host acceptance. The current original schema3
Unix receiver still unconditionally **DENIES** without replay, Docker,
journal, route switch or success response; Task14B remains HOLD.

**Remaining:** review/install private mount-scope and root-owned V2 asset
provisioning only with explicit owner authorization; integrate and qualify
positive request admission, durable SQLite JTI replay, genuine digest-pinned
green startup/3142 health, journaled 3141 cutover and write-preserving
rollback, followed by exact-HEAD independent M04 acceptance and separate
authorized new reviewed Analytics Task013/014 DEV release.

## M05 V2 kernel-socket to independent Task013 signed reader integration (2026-11-07)

The root-owned **generation-2** Analytics executor composition now selects the
existing Unix handler's **full-signed-read-only** branch using its immutable
original `expected_workflow_sha`. Generation-1 keeps its exact original
schema-2 0.15.0 first-install receiver, with no replacement credential path.
The earlier structural and manifest-only successor test variants remain
available for legacy contract tests but are no longer selected by V2 composition.

When that separately owner-approved V2 service is actually installed, its
original peer-checked AF_UNIX handler receives the canonical schema-3 request
and kernel-sealed three-JWT bundle with the existing SCM_RIGHTS wire protocol.
After original peer, seal and image binding checks, it calls the existing
`_review_executor_successor_signed_release` with the root-reviewed workflow
SHA and exact four reviewed source/profile hashes. That verifies independent
GitHub JWT audiences, root-controlled owner Ed25519 exact source, original
Sigstore/Cosign Forgejo and OCI signatures, provenance/Grype/SBOM policy and
actual active 0.15.0 state before and after remote evidence reads. It then
**ALWAYS returns a fixed rejection**, including after a fully verified review.
Any verification error also rejects. It cannot call the existing replay guard,
Docker stage/rollback or 3141/3142 route mutators, and cannot fabricate a
success response. An explicitly missing/forged workflow SHA or mixed successor
handler modes fail at construction. No additional socket or framework is built.

Regression coverage includes: real sealed three-JWT memfd over actual Linux
SO_PEERCRED/SCM_RIGHTS socket (synthetic signed-release checker only),
no-replay/no-deploy on purported review success, fail-closed signer failure,
strict V1/V2 composition selection and wrong/mixed workflow denial. Independent
real cryptographic JWT and synthetic Sigstore/owner/host tests remain separately
required. These tests **do not claim** actual UID991 host signer asset
installation, runtime service GO, durable replay, candidate start, 3141
cutover, rollback or public release.

**Next required work** remains the protected positive schema-3 executor chain:
root-approved, separate UID991 private-mount verifier source qualification;
original durable SQLite JTI begin/finish before any OCI mutation; reviewed
immutable candidate startup, private 3142 health, journaled 3141 route switch,
failure/restart reconciliation and write-preserving rollback. Only one owner
approval for actual protected installation/release as required by AGENTS.md;
independent M04 acceptance when the combined code is real and testable.

## M05 committed private 3141 cutover rollback and crash recovery (7 Nov 2026)

Previously the route journal could restore only PREPARED/CANDIDATE_READY
transactions that had not fully committed. If original SQLite
`finish_execution` failed immediately AFTER a successful 3141 cutover, the
already-SWITCHED journal had no safe way to record an operator-authorized
rollback to the original signed blue 0.15.0. A process crash after deleting
green3141 but before restoring blue3141 could leave ONLY Canary3020 and no
Analytics writer, with no independently recoverable phase.

The existing **Analytics-only** `deployment/analytics_route_journal.py`
now requires this strict, fsync-protected state machine:

`prepared -> candidate_ready -> switched -> rollback_pending -> restored`

The existing alternative `prepared/candidate_ready -> restored` remains
valid for aborted pre-commit swaps. `switched -> restored` is intentionally
DENIED because it would claim recovery without first writing the exact
rollback intent. `rollback_pending` blocks any new generation, replay or
candidate adoption until a privileged recovery of the SAME request/image/
container IDs completes. The original V1 source and Canary remain unchanged.

The existing `deployment/analytics_loopback_guard.py` now exposes the
**UNINSTALLED, protected private helper**
`_rollback_committed_private_successor` for the FIRST immutable
blue0.15.0 -> green successor, restricted to original UID991, exact
private supervisor scope, bounded original request SHA, exact fsync-
committed SWITCHED journal, verified healthy original blue container,
previous/next exact OCI image and immutable container IDs, and a strictly
unchanged two-rule inventory containing ONLY Canary3020 and green3141.
The helper writes `rollback_pending` and fsyncs it BEFORE mutating any
RootlessKit forwarding. It delegates to the existing checked recovery path
to restore blue3141 while NEVER removing Canary, stopping another product
or deleting database/volume writes.

The existing recovery helper also now accepts `rollback_pending` with
exact matching JTI/request/hash/source identities and the same UID991
scope. Only in this phase may the local route inventory consist of
**Canary3020 alone**, representing a crash just after deleting green3141
but before the first blue3141 POST. This special case is forbidden for
ordinary PREPARED/CANDIDATE_READY stages. The recovery rechecks the
original healthy signed blue container/NetworkID, the exact Canary
mapping and signed transaction, restores blue3141, verifies readyz and
livez, and atomically fsyncs `restored`. Failures leave the durable
rollback_pending HOLD for an explicit retry; they cannot falsely report
success. A completed rollback does NOT by itself stop green or authorize
a new release. The independent original SQLite JTI remains consumed
across retries.

Tests now exercise durable re-open across real Linux filesystem inode,
foreign JTI/image/container rejection, unchanged Canary and no public
ports, simulated process crashes before DELETE, after DELETE, and after
blue POST, source/UID/scope denials, failed fsync before any route DELETE,
and failed blue restore remaining HOLD. Fake local RootlessKit/Docker APIs
prove control flow, not permission to operate the real host. This helper
is NOT connected to the original installed 0.15.0 supervisor, and the
protected positive schema3 executor still is not installed or enabled.

**Next** integrate a separately approved signed/replay-bound UID991
candidate-to-route coordinator which calls original start/green health,
the existing journaled private 3142 stage and 3141 switch, then original
SQLite `finish_execution`; on failure after committed switch call this
new durable rollback BEFORE stopping exact candidate. Independent final
M04 review and explicit owner release/deployment authorization remain
mandatory.


## Task013 Canary Critical zlib regression, 7 November 2026 (M05)

On exact successor source SHA `b0f6b5a65cd7f9da7c8b38772ba8aa29d5b5507d`,
the otherwise successful Task013 unpublished build+SBOM+Grype gate
[GitHub run 42351612800](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/42351612800)
correctly blocked **Critical CVE-2026-4738** in Alpine package
`zlib 1.3.2-r1`, target `oci`. The original fixed policy required
zero Critical/High; the scanner's reported patched `zlib 1.4-r0` package
was NOT in the pinned, separately GitHub-attested Astral image. No policy
exception, SBOM deletion, severity downgrade or signature bypass is allowed.

The Canary does not import/use zlib or SQLite. In the original digest-pinned,
network-disabled `release/fixtures/task013-canary/oci/Dockerfile`, M05
extends the existing actual `apk del --no-network` cleanup to remove zlib
together with unused SQLite and its Python optional dynamic module, and
independently checks both APK absence and Python zlib module absence before
removing the shell and apk executable. The retained genuine APK database
must still show every remaining OS package to Syft and Grype. The original
base image digest, upstream GitHub attestation, nonroot UID10001, exact
Python entrypoint, source SHA, C34D and all original Task013/014 checks stay
the same. Source-level tests are necessary but NOT sufficient: only the
exact new GitHub CI build and unchanged Critical/High Grype policy can
confirm this removal is viable and the successor remains releasable.


### Canary scanner follow-up for original zlib dependency

The first source-only fix at `4aa69821351c671b24291c5d0ace204ebf4858df`
produced a valid OCI image but still FAILED the original scan, run
[42352295760](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/42352295760).
The actual immutable Docker build log states the remaining dependency
`zlib: apk-tools` and keeps the original `zlib 1.3.2-r1` package
in the final, true installed APK database. Both Syft and Grype correctly
reported it; this was NOT a scanner false positive.

The revised offline image cleanup now also removes unused `apk-tools`,
which the final nonroot Python process never calls. The build requires a
nonempty real APK installed database and uses explicit `grep`/exit-code
checks on `P:zlib`, `P:sqlite-libs`, and `P:apk-tools` to fail closed
if package dependency resolution preserves any of them. Syft/Grype's
original full OCI package inventory, zero-Critical/High policy and all
upstream pinned signature/build attestations remain unchanged. Acceptance
is conditional on the NEW same-commit unpublished Task013 container build
and actual scanner result, not source-only tests.


### Canary fix: zlib must be PATCHED, not removed

Exact unpublished build at `7e525dee8a2aa8afe5820e96d33fe11d44b7e256`,
[Task013 CI run 42352794289](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/42352794289),
proved that removing `apk-tools` also removed zlib but broke the Canary.
The real Python runtime failed `import http.server`: its `binascii`
extension dynamically requires `libz.so.1`. This is a genuine runtime
dependency, not a false-positive scan. The offline removal attempt must
not be released.

The corrected image retains the original immutable attested Astral
Alpine 3.23 digest, downloads only the independently sha256-pinned
**Alpine v3.23/main/x86_64 zlib-1.4-r0.apk** (reviewed same 56,762-byte SHA
`22ff5ae6b704ac1786d6565dcb3f5dde489e44a5038297a565382b76f656ee08`
on two different upstream mirrors), and uses the **existing vendor
APK signature keys** to install that exact package in a network-disabled
Docker RUN. BuildKit is permitted to fetch only the checksum-pinned
official HTTPS APK before RUN; no general network package refresh, new
registry, untrusted package, `--allow-untrusted`, or new signing bypass.
The actual installed APK DB must contain exactly one `P:zlib` with
`V:1.4-r0` and no vulnerable `1.3.2-r1` entry. The original `binascii`
and HTTP Python imports must work, and `zlib.ZLIB_RUNTIME_VERSION` must
start with `1.4`. SQLite remains absent, all existing OS package entries
remain transparently scannable by Syft+Grype, and the identical
zero-Critical/High policy applies without a waiver.

Only the exact-HEAD Task013 OCI build, unchanged Task013 security policy
and Task014 native CI can establish final acceptance. No installed
0.15.0, public server, source signer key, OCI image push, Task013 dispatch
or privileged system service is touched by this change.


## M05 complete FIRST-successor source transaction, 7 Nov 2026

The existing Task014 V1 source, V1 replay, V1 socket activation, Canary3020,
signed private Analytics 0.15.0 and its fixed release/source hashes remain
**unchanged**. This successor work is currently UNINSTALLED, not a release GO.

The original `deployment/analytics_executor.py` now contains an
Analytics-specific `_execute_reviewed_first_successor_transaction` with a
closed, root-installed-only UID991 service trust boundary. It verifies the
actual root-pinned workflow/source identity, then independently invokes the
**existing** UID991 original GitHub 3-JWT, owner Ed25519, Sigstore/Cosign,
SBOM/provenance, original signed blue0.15.0, immutable Zot evidence reviewer.
Only exact canonical schema3 and same-source rootless registry/pull collaborators
can continue. It reuses the existing original broker-consumed SQLite replay
begin/finish, kernel-sealed FD, source-pinned green candidate, private 3142
candidate health, fsync journal and stable 3141 cutover. A post-switch
`inspect_committed_analytics_route` must match the signed immutable green
container/image and the same JTI before replay can finish and the original
exact-format executor success response is returned.

At every pre/post 3141 error, the coordinator requires safe state, restores
the original signed blue0.15.0 ONLY under the original durable journal and
same request/image/container IDs, then stops only the exact candidate. On a
post-commit replay fsync failure it explicitly uses the new
`switched -> rollback_pending -> restored` durable transition before stopping
green. A foreign or unrecoverable journal emits HOLD and MUST NEVER stop a
container that could still be serving, claim rollback, or reuse the same
SQLite JTI. Crash/cancellation never yields a success receipt and still
requires independently authorized restart recovery. All database writes are
preserved. No public ingress, cookie, JWT transport or new release framework.

To preserve the strict AST import closure, the **distinct V2 only** successor
source list now additionally attests
`deployment/analytics_loopback_guard.py`, the real fixed route supervisor
code which was previously absent from the V2 source manifest. This is an
explicit narrow material expansion from **25 to 26** reviewed V2 installed
objects and from **37 to 38** separately Git-SHA-attested V2 source entries.
The inert exact V2 isolated staging now contains **76** source files instead
of 75. The original V1 remains 20 installed objects, 32 additive source
entries and 70 staged files, byte-for-byte unchanged. Every source byte is
read from the exact Git object, independently SHA-checked, owner-scoped and
not automatically installed.

Tests in `deployment/tests/test_analytics_first_successor_transaction.py`
qualify all phases against synthetic typed collaborators: positive exact
success, root workflow/source mismatch, UID denial, signed review failure,
unconsumed replay, live source/manifest drift, green start failure, 3142
probe failure, candidate preflight denial, failed 3141 switch, wrong
committed image, replay finish fsync failure, verified blue rollback, failed
rollback HOLD with candidate retained, and original V1/V2 Unix socket
remaining **DENY-only**. The original real AF_UNIX+SCM_RIGHTS and SQLite
replay tests remain independently enabled, including host permissions cases
which need CI/QA host.

**Not yet ready for real DEV release:** the present broker first-successor
probe, HTTPS router and installed socket receiver remain explicitly
DENY-only and do not call the positive source coordinator. The protected
root-owned V2 source/install, approved Cosign/TrustedRoot readonly mounts,
positive broker replay dispatch and independently authorized interrupted
restart recovery still require source-bound integration and M04 acceptance.
No signing, registry publication, merge or privileged host operation is
authorized by this change.

### M05 rootless first-successor broker handoff, source-only

The existing `deployment/analytics_promotion_broker.py` now has the
**uninstalled** Analytics-only method
`authorize_and_forward_first_successor`, completing the source-level
broker half of the candidate coordinator. It uses the actual original
OIDC verifier and both original and owner-signed successor Sigstore/Cosign
review handlers, rechecks all nine signed GitHub actor/workflow/run fields,
verifies independent Zot/Forgejo JWT audiences and expiration, and puts
all three original signed JWTs in the existing Linux sealed-FD schema2
bound to precisely the canonical request and immutable OCI image. The
original broker `SQLiteReplayGuard.consume` must durably record the
exact JTI/run/attempt/request hash before the only permitted successor
Unix sender can be invoked. A closed, canonical executor response must
contain the identical request SHA or the broker fails unavailable;
a forged positive JSON response never yields acceptance. A failed
forward consumes the JTI, closing the sealed FD, so ordinary replay
cannot silently trigger a second candidate.

The *present HTTPS broker/router and root-owned V2 Unix receiver remain
strictly DENY-only*. Neither existing public/private routing nor the
installed signed 0.15.0 can invoke this future method or its positive
UID991 coordinator. The additional method is not a permission to begin
a real release. The future positive authorization must be selected from
a separately verified, owner-approved root-owned V2 generation, preserve
the original SO_PEERCRED and SCM_RIGHTS checks, and receive an independent
M04 security/recovery acceptance before any installation. It must not
reuse the current read-only probe as positive admission.

Synthetic test cases in
`deployment/tests/test_analytics_promotion_broker.py` validate original
owner/OIDC/old+new signature review, the real sealed three-JWT format,
one original replay consume, exact response binding, signer failure,
forged success denial, missing successor sender denial, and replay
rejection before any second forward. Existing SGID SQLite and actual
Unix socket tests remain enabled and must be qualified by CI or an
authorized host with compatible filesystem permissions.


## UID991 isolated V2 Sigstore/Cosign service assets (7 November 2026)

The original Task014 broker verifier runs at UID/GID990 and owns its exact
Cosign v3.1.2 binary, Sigstore TrustedRoot and two private runtime workspaces.
The already developed independent UID991 successor evidence review invokes
the same original CosignReleaseBlobVerifier and CosignOCISignatureVerifier,
without changing their trusted paths or zero-Critical/High policy. The
original metadata guard requires root-owned (uid=0) assets grouped to the
actual verifier GID, 0750 parent directory, 0640 TrustedRoot, 0540 Cosign,
exact size/SHA256 and isolated 0700 principal-owned temporary workspaces.
A global UID990 supplementary group or weaker verifier policy is prohibited.

The existing build_unsigned_analytics_service_inputs(...,
successor_source=True) now emits a UID991-only analytics-v2-source.conf
review candidate alongside unchanged V1, Canary and V2 broker bytes.
Inside the UID991 service PRIVATE systemd mount namespace only, it binds
separately provisioned ROOT/UID991 directories:

* Source /etc/omnilyzer/deployment/dev/analytics-executor-sigstore
  (root 0:991, 0750) to original /etc/omnilyzer/deployment/broker.
  Source MUST contain only sigstore-trusted-root.json (0:991, 0640,
  exact pinned DevSigstoreVerificationProvenance SHA256). It MUST NOT
  include broker dev.json, credentials or signing secrets.
* Source /opt/omnilyzer/deployment/analytics-executor-tools
  (root 0:991, 0750) to original /opt/omnilyzer/deployment/tools.
  Source MUST contain cosign-v3.1.2-linux-amd64 (0:991, 0540,
  141150460 bytes, exact independent reviewed SHA256). Neither original
  UID990 directory nor its executable may be chmodded or altered.

The same V2-only drop-in mounts private tmpfs for
/run/omnilyzer/deployment/dev/blob-verifier and
/run/omnilyzer/deployment/dev/oci-verifier (both 0700, uid=991,gid=991)
under the existing private rootless mount parent, with no UID990 or
Canary shared RuntimeDirectory lifetime. The original O_NOFOLLOW
descriptor, inode/owner/mode/hash and sealed memfd checks still apply.

These are UNSIGNED review bytes in the PR, not an installed unit. The
already required root-approved Task014 installation must independently
validate source-dir symlink-free ownership and exact authenticated
asset hashes, copy the source using protected root ownership, and
verify service-private mount namespace + UID991 visibility before any
service changes. Owner Ed25519 source-approval paths/trust also require
the separately owner-approved root installation. Do not create keys,
install files, start or restart services or dispatch Task013 based on
this document. The schema3 Unix receiver remains intentionally
DENY-only. One existing M04 independent review follows integrated code.

## M05 first-successor root generation-3 execution selection and recovery

The original signed private DEV Analytics 0.15.0 V1 and ordinary generation-2
signed-review path remain unchanged and DENY-only. The new root-owned
generation-3 runtime config is a distinct future Product Owner-authorized
installation mode. It shares the exact SHA-reviewed 26-file V2 source closure
and 38-entry Git archive, and requires the literal boolean field
owner_authorized_first_successor=true. It rejects missing, false, integer,
string or noncanonical variants. Ordinary V2 and historical V1 reject this
field. The review-only builder can produce unsigned generation-3 input
without installing it, dispatching Task013, enabling a service, starting a
candidate or claiming user consent to privileged operation.

After separately authorized root source installation and identity validation,
the existing UID990 Analytics broker may select its independently reviewed
signed Task013, original durable replay and three signed JWT sealed FD
handoff. The original UID991 SO_PEERCRED/SCM_RIGHTS Unix handler may then
invoke the Analytics-specific signed green candidate/3142/3141 journal
transaction. Every request still independently reopens the exact root-owned
schema-3 config, verifies source/workflow and owner-signed release evidence,
and rejects any caller-created release receipt. The V3-only executor review
drop-in adds the fixed private supervisor scope environment
ANALYTICS_REVIEWED_SUPERVISOR_V2=1; original V1/V2 source/drop-ins remain
unchanged. Real root-owned signer copies/permissions and namespace mounts
require owner-authorized verification before any actual service activation.

Crash safety is handled before socket acceptance. Protected UID991 reads the
exact fsync'd mode0700 private journal after root-checked generation-3
admission. Empty journal permits a first signed request. Incomplete
prepared/candidate_ready/rollback_pending journal phases trigger existing
exact signed 0.15.0 blue route recovery, original Canary3020 preservation
and independent blue writer verification, followed by mandatory HOLD.
Already switched, restored, unknown or corrupted journals also HOLD; a
switched journal may reflect a FINISHED replay JTI and cannot be rolled back
by guessing. Failed recovery never claims success, stops a possibly serving
container or erases database writes. All source-only restart and real local
Unix sealed-FD tests are distinct from actual root UID991 host acceptance.

Still requires an independently accepted exact-HEAD source/real-host M04
review, separately explicit owner authorization for root V3 installation,
a newly approved signed Task013 Analytics release and genuine private DEV
Task014 health, DB persistence, tenant isolation and write-preserving
rollback. Nothing in this source permits paid GitHub usage, public ingress,
production deployment or waiver of mandatory signature/security controls.
