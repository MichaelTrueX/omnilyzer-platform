<!--
File: docs/operations/m05-14-task014-analytics-runtime-20261029.md
Purpose: ONE current product-first M05-14 Analytics 0.15.0 original Task014
         release, isolated DEV source installation and acceptance handover.
Related: AGENTS.md; deployment/analytics_isolated_source_install.py;
         deployment/analytics_source_archive.py;
         deployment/analytics_source_handoff.py;
         deployment/analytics_executor_service_config.py;
         deployment/analytics_broker_service.py;
         deployment/systemd/dev/analytics-broker-enabled.conf;
         deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service;
         deployment/tests/test_analytics_isolated_source_install.py;
         deployment/analytics_first_install.py;
         MichaelTrueX/omnilyzer Issue #27 and platform PR #258.
Authorization: This document cannot grant root source installation, activate
               DEV, merge source or authorize production.
-->

# M05-14 — Analytics signed 0.15.0 via existing Task014 (current handover)

Status as of 2026-10-30: **DRAFT / NO-GO FOR LIVE DEV INSTALLATION / NO MERGE.**
The exact code and immutable Git commit in the latest open platform PR #258,
not ChatGPT memory or older text, are authoritative. Historical intermediate
plans (27 new alone, 30 objects, or replacing the original canary source) are
superseded. Preserve the existing Task014 root-owned original canary and
reuse its proven broker/OIDC/signer/replay/executor controls.

## FINAL M05-14 HANDOVER — 2026-10-30

**Development handover COMPLETE. Live Analytics 0.15.0 DEV acceptance NOT
COMPLETE; ACTIVE DEPLOYMENT NO-GO.** This is the last consolidated status
for this development batch, not another framework/PR/QA process.

**Delivered and verified:** one original Task014 workflow with Canary as
default and Analytics DEV schema-v2 path; exact signed original Task013
Analytics 0.15.0 OCI digest; immutable 70-source isolated generation and
four unsigned root review inputs; read-only host preflight; four reviewed
systemd-service review bytes (3 original Git objects plus a source-bound
C32ZF runtime-directory fragment); first-install stop-only rollback
implementation. Original Canary and production were NOT changed. The owner
successfully installed and ran the separate read-only root audit on DEV.
Last direct DEV observation: original broker and Canary executor socket
active; UID991 rootless Docker daemon socket available; isolated Analytics
source, protected configs, mapped secret directory absent; Analytics
executor socket inactive. Remote agent remains NoNewPrivs=1, not root.

**Two confirmed product-release blockers (do not suppress):**

1. **Concurrent systemd lifecycle.** The existing original Canary and the
   proposed Analytics executor use the SAME runtime-directory name
   \`omnilyzer/deployment/rootless-docker\`. The four service review inputs
   are UNSIGNED and deliberately NOT an installation grant. Under systemd's
   RuntimeDirectory removal semantics, stopping/restarting one service can
   remove the other service's mount destination. The dedicated Analytics
   service needs a separately tested, product-private rootless mount
   lifecycle or a proven safe equivalent BEFORE root installation. Hash
   verification and a green service-unit syntax test do NOT establish that
   coexistence property. Do not install the current review-only fragment.
2. **Critical Python runtime advisory.** GitHub Dependabot alert #25
   identifies Task014's \`PyJWT[crypto]==2.13.0\` as affected; fixed version
   reported is **2.14.0** (asymmetric PEM / HS confusion issue). A read-only
   inspection of the REAL DEV protected venv confirmed PyJWT 2.13.0 and
   cryptography 50.0.1. \`deployment/oidc_verifier.py\` explicitly fixes
   RS256 algorithm selection, which narrows the relevant attack surface,
   but does not justify waiving the published critical dependency finding.
   Task014's wheel SHA256 lock, exact immutable installed Python
   environment manifest and C31A source qualification all pin 2.13.0.
   Updating the runtime requires a single properly hash-verified 2.14.0
   wheel, regenerated/independently qualified installed-runtime source
   manifest, dependent tests and original Task014 release checks.
   **Do not run a direct \`pip install --upgrade\` on DEV.**

**Explicit next authorized action:** After those TWO blockers have been
resolved using the existing code/source qualification and privately
reviewed, a single owner-approved original Task014 ROOT installation
may install exact isolated sources, protected configs, product services,
mapped four secrets and restricted PostgreSQL roles/RLS, exercise REAL
three-audience OIDC + signed Zot/Forgejo/Cosign, private \`/readyz\`,
logged-in persisted Analytics journey and stop-only rollback. One
independent M04 DEV acceptance then yields GO/NO-GO. No merge, live
installation, credentials, database write, registry republish or product
rollout was authorized by this review batch. The owner need not rerun
the already successful read-only root-audit script.

**Source of truth:** exact current GitHub PR #258 HEAD and Issue #27.
Historical test totals remain attached to the exact SHAs they tested;
the relevant final focused regression suite ran **66/66 PASS** on the
unchanged implementation before writing this handover. GitHub had 7/7
successful required checks on the previous exact HEAD. Recheck checks
on any subsequent documentation-only commit; do not reuse the old SHA
to assert final CI or an actual installation.

## Functional acceptance target

One working PRIVATE DEV Analytics 0.15.0 journey, using the original
Task013/014 release process: authenticated signed immutable release through
GitHub OIDC, Zot and Forgejo; approved root-owned Analytics source and four
restricted file secrets; rootless UID10001 container health at private
/readyz; independent PostgreSQL application/collector roles with RLS;
real logged-in SaaS Analytics workflow with actual persistence and safe
first-install stop-only rollback. No public product ingress until acceptance.
No separate staging infrastructure, second public broker, new generic release
framework, credential transport change or unapproved production operation.

## Original signed release (distribution verified, not deployed)

- Task013 successful protected GitHub Actions run: 40881693662
- Version: Analytics 0.15.0
- Immutable OCI image: oci-dev.omnilyzer.ai/omnilyzer/analytics@
  sha256:6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1
- Actual Analytics source: PR52 commit
  4cdda7faeba57abb3388f9be5c450fe6afb1140d
- Original Task013 source platform Git commit:
  b9e22e745ecbaf96dc15998e91d1a74f70e5ad77

Original task publisher reported successful SBOM/scanner, Sigstore/Cosign,
Zot/Forgejo and zero critical/high vulnerability-policy waivers. Task014
must independently verify the real pinned signer, manifest, original OIDC
credentials, immutable digest and release evidence at live acceptance.
No synthetic TrustedRelease or preview receipt grants installation.
DO NOT rebuild, retag or republish signed 0.15.0.

## Actual DEV preflight (read-only, observed 2026-10-30)

- Host omnilyzerdev accessed solely as unprivileged omnigpt.
- ORIGINAL Task014 broker and executor socket are running.
- Original rootless Docker daemon under UID991 is present. The rootful
  Docker on truexdevelopment is NOT evidence of rootless DEV acceptance.
- Protected source root /opt/omnilyzer/deployment/app is root-owned 0755
  and contains 43 originally approved source files. The 40 Python files
  remain alongside three original canary runtime/Compose assets.
- All 43 original source blobs were checked by SHA256. 42 match original
  platform Git b9e22e; deployment/promotion.py is an older exact historical
  blob from ba4fd3cacb33f71a626eeb3877a886f0fe31c82a, SHA256
  dd5fdc5dfaf3734eb26bfc7dae293d0797480ab03930f3da165bed710c5cbea0.
- Original root also contains 18 root-owned .cpython-312.pyc bytecode
  cache files outside the closed canary source set; they must NOT be
  imported, edited, silently deleted or treated as new source authority.
- No Analytics source app, separate root-owned Analytics broker/executor
  config, approved four-file secret directory or 3141/3142 listener.
- No real Analytics signed read, PostgreSQL/RLS or app /readyz acceptance
  has been performed by M05-14.

## Implemented product-specific Task014 candidate (PR #258)

The new broker opt-in REUSES the original existing port 3031, original
GitHub OIDC/JWKS, replay SQLite, sealed registry FD, Forgejo/Zot,
Sigstore/Cosign, and canary routing. Analytics receives one separate
private Unix executor socket. The original installed C31/C32 canary broker,
executor entrypoint, source allowlist, Unix listener, replay and rootless
daemon remain unmodified. No new public route or second control plane.

The original C31B materializer is intentionally CLOSED to its historical
43-file source manifest. Broadening it or overwriting the protected canary
tree would compromise its recovery checks. This release now uses the
simpler, independent **isolated Analytics source root**:

- ORIGINAL CANARY: /opt/omnilyzer/deployment/app — never written.
- NEW ANALYTICS: /opt/omnilyzer/deployment/analytics-app — root-owned 0755
  source directory, not currently created on the DEV host.
- Both the optional existing-broker systemd drop-in and the separate
  Analytics executor service run with this isolated WorkingDirectory.
  This preserves the original broker port and exact canary default behavior.
- Separate Analytics root-owned config must attest the 20 new source
  Python SHA256s, exact product and runtime profile, signed source claim,
  reviewed Compose and original C17 process identities; no caller creates
  deployment authority.
- New release source root contains EXACTLY 70 approved source files,
  without copying any existing bytecode:
    39 historically identical original canary files, exact raw Git-object
    hashes protected by original C26/C31;
    4 intentionally updated shared modules with exact original preimages:
    oci_verifier.py, private_registry_fd.py, promotion.py and
    release_consumer.py; and
    27 newly reviewed Analytics source/runtime/systemd objects.

The canonical 31-file TAR still transports exactly the 27 new source
objects and four shared-module replacements. The accompanying canonical
review manifest also pins the hashes of the 39 inherited unchanged files,
the original four preimages and exact isolated source root. Original Git
objects, not mutable working-tree copies, produce it. Both are UNSIGNED
review inputs and explicitly do not authorize a deployment.

### New root-controlled source-only operation

The one new purpose-built Python module
deployment/analytics_isolated_source_install.py reuses original Task014
C31B directory, fd-relative no-symlink file access, bounded hashing,
single-link/mode/owner checks, exact 70-source final verification, fsync,
and fixed root-owned paths. It has no CLI, import from any runtime service,
route or workflow. A separately explicitly authorized root actor must
later install TWO root-owned 0600 input files:

- /etc/omnilyzer/deployment/dev/analytics-source-install.json
- /opt/omnilyzer/deployment/.analytics-source-review.tar

The first is canonical protected approval selecting exact source Git
commit, separately reviewed manifest/archive SHA256 and fixed new root.
The second is the already verified archive. No public review dataclass,
self-declared TAR metadata or unprivileged tool can create this approval.

If explicit owner/M04 authorization is later granted, a root-only local
call may:
1. Read and validate those root-owned inputs, require original source
   commit and exact archive digest, and open every ancestor without links.
2. Verify all 43 actual installed canary source file SHA256s against the
   exact mixed original Git baseline; never open/copy their 18 bytecode
   cache files. Reject any changed old source, symlink, wrong mode or owner.
3. Build a NEW staging generation of 70 exact files under the protected
   deployment parent, without touching the original canary app.
4. Verify the complete new generation with the original C31B source
   integrity reader, then atomically publish ONLY the new isolated
   directory. On tested stage/write/rename failure, delete only the
   exact newly created verified stage and preserve original files.
5. Return source-only success. This does NOT install/enable systemd,
   provision secrets, change C17 authorization, operate Docker/DB or
   authorize an Analytics promotion. A separately approved Task014
   activation and operational rollback remain mandatory.

The operation is intentionally NOT installed or invoked on omnilyzerdev
and its root-owned approval/OCI inputs are not present. Positive source
materialization proofs were executed exclusively under disposable local
directories with the real 43 historical Git blobs and canonical
31-file archive, without root permissions.

### Previous confirmed P0 corrections retained

- First install secret parent must be root:991 mode0710, while four exact
  UID/GID503216 mapped secret source FILES must each be regular mode0600.
  The prior contradictory requirement that parent also have GID503216
  has been removed. Wrong file GID fails before Docker.
- The broker and executor SHA-verifiers now require the original signed
  release/products/analytics-source.json claim (actual hash
  45e13536c413a5e5c0a39a4d8c98daf412614dec535398b2ba204039772c88b9).
- Real original source graph includes four shared changes; the complete
  original canary source selection remains unchanged and default canary
  behavior is regression-tested.

## Automated verification and limitations

Run focused real-file temporary filesystem tests for both imported
services, all 70 source blobs, 43 original hashes, 18 untouched dummy
legacy caches, original C31B exact source verification, symlink/preimage
rejection, canonical 31-file Git-based TAR, protected approval grammar,
and failure injection at the 9th file write and atomic publication.
Never confuse these with real root host acceptance.

Original Task014/canary regression and Analytics regression run in
parallel on the isolated truexdevelopment worktree. Required GitHub
dependency review, CodeQL, Python analysis, C34D and repository checks
must complete for the exact final PR SHA.

A local systemd-analyze verification on truexdevelopment cannot qualify
the production-style service ExecStart because its protected original
/opt/omnilyzer/deployment/venv/bin/python is not installed on that
development machine. A real unit/source/identity evaluation must be
performed read-only on the actual DEV server before activation.

## HARD NO-GO and next bounded acceptance

The NEW source installer code is NOT a root installation authorization.
M04's older review #5699460077 covered a different, earlier read-only
source HEAD and is not approval of this new privileged source boundary.

One bounded M04 review must check the precise isolated 70-file source
assembly, C31B input/hash/FD checks, original root immutability, root-owned
approval and archive trust, crash/stage cleanup, separate systemd root,
signed registry/OIDC/credential/replay gates and rollback.

Only after explicit owner approval for DEV installation and the necessary
preprovisioned protected inputs exist, use the original Task014 root-owned
host release mechanism to install the reviewed source-only generation;
then separately validate the private broker/executor, actual signed OCI
0.15.0 read, four UID10001 secret mounts, least-privilege PostgreSQL
collector/app roles and RLS, private blue /readyz, persistence, and
first-install stop-only rollback. Preserve original canary and all data.

NOT DONE: no live app, no merge, no production release, no M04 final GO.
GitHub PR #258 and shared Omnilyzer Issue #27 remain the canonical
review and coordination points.

## 2026-10-30 — Existing Task014 GitHub workflow product routing

Changed complete sources:
- \`.github/workflows/platform-promote.yml\` — exactly one existing
  workflow_dispatch; the previous Canary release inputs, original
  deployment.promotion path, original C33W activation policy, original
  Tailscale transport and three audience-separated GitHub OIDC tokens remain
  in their original task/stage. New explicit product_id choice defaults to
  **canary**. Analytics alone has two additional required-when-selected
  input values, \`analytics_installed_commit\` and
  \`analytics_source_claim_sha256\`, with closed schema gate. Production,
  STAGING, unknown product and wrong signed 0.15.0 release identity are
  rejected for Analytics before any private promotion.
- \`deployment/analytics_ci_request.py\` — one product-specific Python
  gate and canonical schema-v2 constructor used inside the existing GitHub
  deploy_dev job AFTER the original three ephemeral OIDC tokens are fetched.
  It checks the exact 0.15.0 origin/source/run/manifest digest, signed
  release hashes and OIDC token *shape* against GitHub runner metadata,
  computes original product/runtime/Compose hashes, builds private-only
  UID10001/four-secret and stop-first-slot request, and parses its own
  canonical result with the existing Analytics grammar. This CI module
  explicitly does NOT verify JWT signature or signed source; it is not a
  deployment grant. Only the existing root-owned Analytics broker verifies
  original JWKS/OIDC audience/workflow, Zot/Forgejo permissions, signed
  Sigstore/Cosign original release, real release hashes, replay, and exact
  reviewed installed source before a private executor action.
- \`deployment/tests/test_analytics_ci_request.py\` and changed original
  \`deployment/tests/test_final_dev_workflow.py\` — test actual embedded
  Task014 workflow Python through all THREE synthetically encoded OIDC
  audience tokens to a captured schema-v2 POST; exercise the true bash
  gate offline and preserve the original canary request/HTTP regression.
  Negative tests cover cross-product/stage, signed source/digest hashes,
  malformed OIDC and foreign workflow/run identity. No real tokens or
  deployment, and the synthetic POST is NOT real signed acceptance.

The GitHub runner's **workflow_sha is whatever protected current main
actually executes**; its new schema-v2 request contains the explicitly
reviewed installed source SHA, and the root-owned broker must independently
verify BOTH exact values against the deployed original broker and isolated
Analytics source configs. This PR DOES NOT install those configs, update the
existing broker OIDC workflow-SHA allowlist, or enable the root-owned
systemd opt-in. A new merged workflow revision is not automatically trusted
by an older root-owned broker. Consequently **real DEV installation stays
NO-GO** until one reviewed, owner-approved original Task014 root-owned
update has bound the source, workflow, broker/executor config, four secrets,
PostgreSQL RLS and signed immutable 0.15.0 release and proven private
/readyz/persistence/rollback.

## 2026-10-30 — One exact-commit, READ-ONLY root activation input handoff

Two new task-specific Python files close the former operator transcription
gap without adding root authority:
- \`deployment/analytics_dev_activation_inputs.py\` makes FOUR exact canonical
  inputs from the original immutable reviewed Git source: the canonical
  31-source archive (0600 root:root), separate root-only source-install
  approval (0600 root:root), the Analytics executor product configuration,
  and byte-identical broker product configuration (both expected root-owned
  0640 with their separately reviewed service group). All fields are parsed
  by the ORIGINAL existing strict Analytics approval and config grammar;
  the 20 exact Python source hashes, signed source-claim SHA and three
  profile/Compose hashes bind to the SAME Git commit. Output is
  **UNSIGNED / NOT INSTALLED / NOT A DEPLOYMENT GRANT**; no writes or tokens.
- \`deployment/tests/test_analytics_dev_activation_inputs.py\` proves
  identical broker/executor bytes, four fixed root destinations, every
  Python digest against the canonical USTAR, malformed archive/Git
  revision denial, and inability to self-authorize.

The separate \`deployment/analytics_dev_host_preflight.py\` is a purely
read-only **nine-resource / three-unit** status matrix. It distinguishes
MISSING from INACCESSIBLE (Unix EACCES) and INVALID, never reads secret
contents, and does not claim a cryptographic release or a completed
privileged installation. Exact command on a reviewed host copy:
\`python3 -m deployment.analytics_dev_host_preflight --read-only\`.
Tests: \`deployment/tests/test_analytics_dev_host_preflight.py\`.

### Actual read-only omnilyzerdev preflight observed 2026-10-30

The full module was executed in-memory through \`omnigpt\` on the REAL DEV
server. No file was created or service restarted. Original canary app root
is root-owned 0755; original broker and executor socket are ACTIVE; Analytics
executor socket is INACTIVE.

- **MISSING (observable ENOENT):** isolated \`analytics-app\` source,
  root-controlled \`source-review.tar\`, four-secret directory, host-visible
  rootless Docker bind socket.
- **INACCESSIBLE (EACCES, NOT asserted missing):** protected source approval,
  Analytics broker/executor config paths, rootless daemon socket
  \`/run/user/991/docker.sock\`. This is normal for some deliberately protected
  parent directories; a root-owned acceptance must determine their existence
  and exact metadata before installation. Do not assume they are absent.
- **INVALID:** none reported by these path/metadata checks. Original
  release signature, source 70-file root verification, actual rootless Docker,
  real OIDC/registry read, PG roles/RLS and private /readyz remain **UNVERIFIED**.

**One actual permission blocker remains:** the allowed \`omnigpt\`
connector session on DEV runs as UID1005 with no privileged install/secret
access; a sudo privilege probe is denied by the remote command policy. A
separately authorized ORIGINAL Task014 root actor must independently install
the exact reviewed code, source approval/archive, broker/executor config and
systemd assets; the read-only generator and in-memory host probe do NOT
provide that privilege. Owner and required M04 approval remain mandatory.

## 2026-10-30 — Owner-initiated, narrowly scoped DEV root audit

To unblock live-source and rootless metadata qualification without making the
remote agent a general privileged administrator, the single owner-run reviewed
bootstrap script is `deployment/enable_dev_root_audit.sh`.

The operator must personally download the file from an immutable Git commit,
verify its published SHA256, then run it using an **existing administrator's**
`sudo bash` on the **actual omnilyzerdev** host. The script fails closed on
wrong hostname/omnigpt UID, missing protected Task014 baseline, malformed
sudoers syntax, wrong existing installed files or unsafe root-owned parent
metadata. It installs only:
- `/usr/local/libexec/omnilyzer-dev-root-audit.py`: root:root mode0644,
  exact Python-stdlib read-only 9-path/3-unit metadata audit; no secret
  content, arbitrary input, Docker connection, container launch, source
  installation, state mutation or auth bypass.
- `/etc/sudoers.d/91-omnilyzer-dev-root-audit`: root:root mode0440,
  grants the specific `omnigpt` user ONLY
  `/usr/bin/python3 -I /usr/local/libexec/omnilyzer-dev-root-audit.py --read-only`.
  There is no sudo ALL/wildcard/shell. `-I` ignores Python environment and
  user-site imports. The script validates syntax with real visudo before
  writing and again after installation.

The remote Desktop Commander configuration may independently block `sudo`.
Only **after the operator has installed and authenticated this exact sudoers
rule** should its remote `sudo` command blockade be reviewed; that
configuration change is separate from OS authorization and MUST NOT widen the
OS rule. A missing or mismatched root file must STOP further operations.

To revoke the limited audit grant, the owner can use their existing admin
account to remove only the two fixed installed files:
`sudo rm -f /etc/sudoers.d/91-omnilyzer-dev-root-audit
/usr/local/libexec/omnilyzer-dev-root-audit.py`. This does not alter the
original broker, executor, rootless Docker or any Analytics data.

**This is NOT approval to merge, install Analytics, open rootless sockets,
supply secrets, deploy images or run migrations.** Those require the already
reviewed, independently root-owned original Task014 source admission plus
explicit DEV deployment authorization and M04's final real installation
acceptance. One read-only root helper avoids both blanket root access and a
fresh per-feature administrative control plane.

### 2026-10-30 — Owner's real root audit accepted; rootless mount corrected

The owner executed the exact immutable, SHA-verified
`deployment/enable_dev_root_audit.sh` as admin `trust` on the REAL
`omnilyzerdev`. The script reported success, exact expected root-owned
helper SHA256 `d58a2b4d199254aa72348a5c768a73244a91dea5f263adb39d71bdd32b2f4d12`
(root:root 0644) and installed sudoers SHA256
`2adcdfadab749a1b7e1b35ef2c73cc1ae6cfea154cadb0890a3178af3694381f`
(root:root 0440). The helper was also independently verified from the
unprivileged live DEV connector (same source hash and metadata).

**The remote agent remains deliberately UNPRIVILEGED.** An attempted
`sudo -n /usr/bin/python3 -I /usr/local/libexec/omnilyzer-dev-root-audit.py
--read-only` failed with Linux `no_new_privileges`, as verified from
`/proc/self/status: NoNewPrivs: 1`. This is a second restriction beyond
the narrow OS sudoers entry; no attempt to bypass it was made. The
Desktop Commander blockedCommands `sudo` entry was restored immediately.
The owner's personally executed root audit is the authoritative read-only
report; an in-chat root installation is NOT available via this agent.

**Real root-audit result (not an installation):** original canary and
broker/executor socket healthy; Analytics source, archive, configs and four
secret directory missing; product executor socket inactive. The rootless
daemon's REAL `/run/user/991/docker.sock` **EXISTS** (UID991:GID991, mode
01660), and independent process inspection confirms a running rootlesskit/
dockerd/containerd under UID991.

**CORRECTION to older host-preflight checklist:** The missing path
`/run/omnilyzer/deployment/rootless-docker/docker.sock` is a
**systemd executor-private mount target**, not a permanent host prerequisite.
Original deployed `omnilyzer-deployment-executor.service.d/
rootless-docker-socket.conf` uses `RuntimeDirectory` and
`BindReadOnlyPaths=/run/user/991/docker.sock:/run/omnilyzer/deployment/
rootless-docker/docker.sock`. The separately reviewed Analytics executor
service has the same private bind. It is EXPECTED that the target is not
present in the idle HOST namespace. The unprivileged 9-path diagnostic
records its raw host absence but now correctly excludes that entry from
install-blocking host prerequisites and explicitly marks
`actual_executor_mount_verified=false` until one genuine, approved service
start validates it INSIDE the executor. The root-owned helper already
installed by the owner is immutable and still reports the raw observation;
do not ask for another privileged script merely to alter its diagnostic
wording or mistake the raw absence for an installation blocker.

Source change is restricted to
`deployment/analytics_dev_host_preflight.py` and
`deployment/tests/test_analytics_dev_host_preflight.py`. The original
canary source, Docker socket authority, service drop-in and executor
behavior remain untouched. No root operation, service mutation, secret
disclosure or runtime acceptance resulted.

### Analytics systemd runtime-directory handoff resolved in review bytes (NOT installed)

The proposed Analytics executor unit retains the exact original rootless
Docker socket bind but does not itself declare the required service-private
RuntimeDirectory. Instead of modifying the unit or inventing another runtime
framework, \`deployment/analytics_dev_activation_inputs.py\` now produces
**four additional UNSIGNED, canonical service review inputs** tied to the
same exact Git commit as the 31-object source archive:

- Existing broker opt-in drop-in, existing Analytics executor unit and
  existing Analytics executor private socket: exact Git-object bytes already
  checked by the original 31-member handoff.
- New product-specific review-only \`rootless-runtime.conf\`, DESTINATION
  \`/etc/systemd/system/omnilyzer-deployment-analytics-executor.service.d/\`
  \`rootless-runtime.conf\`. Contains ONLY the original, SHA-pinned Task014
  C32ZF \`RuntimeDirectory=omnilyzer/deployment/rootless-docker\` and
  \`RuntimeDirectoryMode=0700\`. Its source is compared against the immutable
  original \`deployment/systemd/rootless/rootless-docker-executor-socket.conf\`
  hash \`afef78b7ed57beedc2a8496b602c3f7d6dad7981dd88258f6b7e8c35a7fbed2d\`
  via original C26 Git blob reader, with the matching exact daemon/bind paths
  verified. The existing Analytics unit's \`BindReadOnlyPaths\` remains
  single-source; the review drop-in does NOT duplicate that mount.

\`deployment/tests/test_analytics_dev_activation_inputs.py\` exercises
original Git source selection, SHA matching, exact four destination paths,
negative altered-source and bind rejection and canonical bytes. All outputs
remain **UNSIGNED, INERT, NOT ROOT-AUTHORIZED**. The independently owner-
approved original Task014 root installation must verify and apply these
exact service inputs, preserve the existing broker/canary and test the mount
inside the real activated Analytics executor. Neither passing unit review
nor the owner's earlier read-only root audit authorizes active deployment.
