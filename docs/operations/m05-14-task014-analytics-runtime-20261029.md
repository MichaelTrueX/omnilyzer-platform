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

## Current runtime correction: private mount duplicate (2026-10-31)

Signed Task014 run 41172418361 reached the Analytics executor, but systemd255
failed before ExecStart with 226/NAMESPACE at
/run/omnilyzer/deployment/rootless-docker. The original Canary remains
healthy; Analytics application acceptance is NOT verified.

The Analytics service listed the same target in ReadWritePaths and the
generated private TemporaryFileSystem. In systemd v255 namespace.c,
mount_path_compare sorts READ_WRITE before TMPFS and drop_duplicates keeps
the first entry. The private tmpfs was discarded, leaving a required absent
host path. Remove that redundant Analytics ReadWritePaths entry.
Keep the existing writable state directory, exact Docker socket binding,
private Docker tmpfs mode/identity and all other sandbox restrictions. Mount
its parent privately as root-owned0755 and rebind only the exact Analytics
listener inode read-only into that parent. This isolates the nested Docker
mountpoint dentry from Canary host RuntimeDirectory removal. The service input
builder rejects reintroducing the duplicate writable mount or changing either
private mount or the listener rebind.

This does not require creating a shared host runtime directory, changing
the original Canary service, or touching database/bootstrap/secrets.
systemd may create a bare host mountpoint while preparing its private tmpfs;
do not mistake its presence for private namespace or coexistence acceptance.
Before another signed promotion, the owner-controlled transition must verify
the complete current state, the exact private mount and Docker socket under
the executor service sandbox, and clear only the Analytics failed-start limit.
Concurrent Canary/Analytics start-stop and the real application journey remain
required before DEV GO. Preserve the immutable signed Analytics 0.15.0 release.


Status as of 2026-10-30: **CODE MERGED; ANALYTICS DEV APPLICATION NO-GO.**
PR #258 (source `eedbf26ca164728a4b2b4d906a9fb9f58bfbe816`) and database
fix PR #263 are merged. Issue #27 records the owner's successful PostgreSQL16
bootstrap, five SQL phases and four private secret files. Never rerun that
bootstrap. Existing installed Analytics source remains pinned to PR258;
the corrected activation operator was restored byte-for-byte for download
but is NOT cleared for execution. Its revision-compatibility stop remains
necessary for that unmodified installed generation.

## Current correction: independently reviewed product generations

The original broker `reviewed_commit` pins Canary runtime and ingress.
The original executor `reviewed_commit` likewise pins Canary execution
references. Analytics has its own root-owned `reviewed_installed_commit`,
source-file hash set, Compose/profile hashes and separately installed code.
Requiring those two different authorities to carry an equal commit rejects
a valid independently reviewed product generation. Focused regressions
reproduce the denial in BOTH loaders before the correction.

The correction removes only that cross-product equality requirement in the
Analytics broker/executor loaders. Both retain original protected C17/C32H
configuration loading, strict descriptors, ownership, modes, process/group
identities, canonical closed Analytics config and full product source hashes.
The returned Analytics commit remains its OWN root-controlled product commit.
OIDC/workflow authority, sealed registry access, signed 0.15.0 image,
Cosign/Sigstore, replay, private socket and original Canary pins are unchanged.
No new configuration schema, trust root, service or release framework is added.

Validation: both distinct-generation regressions fail before the source fix;
86 focused broker/executor/product/configuration tests pass after it, including
invalid product revisions, protected ownership and product-byte tampering.
Synthetic source tests are NOT a live installation or signature assertion.
The broader Analytics suite on the restricted DEV connector ran 196 tests:
192 passed, 2 expected skips, and 2 errors because setgid temporary-directory
creation/chmod is denied by this host boundary. Those two existing durable
replay/Unix tests require an appropriate test runner; they are not waived.
The existing read-only C34D GitHub test workflow now runs the Analytics
suite and existing M05-14 Compose/signed-admission tests automatically.
It adds no workflow, permissions, credential access or deployment action.
GitHub CI must resolve this validation before merge.

This correction is a review candidate only. It is NOT installed on DEV, does
not authorize root changes and does not make the old activation script ready.
M04 must review the exact corrective commit and generation transition before
a narrowly pinned owner-local source update/activation. Preserve the current
70-file generation/config/archive and database; do not rewrite Canary's
protected commit, change expected hashes to live values, rerun database setup
or blindly overwrite the existing source. Read-only live compatibility metadata
is still inaccessible to the unprivileged connector, so the actual original
protected commit values have not been asserted by this delivery.

Next: one bounded exact-commit M04 source review, followed by a reviewed
generation transition and original signed Task014 promotion. Then verify real
private readiness/login/collector persistence, restricted DB/RLS tenant-deny,
secret permissions, Canary coexistence and first-install rollback; obtain the
required independent live acceptance. Production remains outside this scope.

The historical sections below describe earlier snapshots. Current GitHub
PRs, exact source commits and Issue #27 take precedence over those snapshots. Historical intermediate
plans (27 new alone, 30 objects, or replacing the original canary source) are
superseded. Preserve the existing Task014 root-owned original canary and
reuse its proven broker/OIDC/signer/replay/executor controls.

## FINAL SECURITY FIX — PyJWT 2.14.0 SOURCE / C31A VENV REQUALIFIED

The vulnerable PyJWT 2.13.0 dependency pin has now been REPLACED in this
PR's **future** C1/C24/C31A source requirements with PyJWT 2.14.0.
The original reviewed cryptography/cffi/pycparser pins and pip 26.2.1
installer are unchanged. Exact upstream wheel and artifact metadata were
downloaded and SHA256-checked against PyPI; the new wheel's SHA256 is
ad0cef71c756a56e74863c2919cf0985f72decbcfcb550ee2f422e7c62b5eedc.
The locked requirements SHA256 is
8466e0fca40b070d25710168094e6d52099ec3e2c65ef67f0ae0d26e1a20fc86.

The ORIGINAL pip wheel's isolated, no-pip Python3.12 bootstrap and strict
no-index / no-deps / no-compile / require-hashes installation were actually
executed on the development workstation. A clean control install of the old
2.13.0 wheel reproduced all 24 retained C31A PyJWT file/path SHA hashes
before replacing them with hashes from the verified clean 2.14.0 wheel.
The complete FOUR-WHEEL closure also installed successfully in an isolated
no-pip Python3.12 environment with the current reviewed lock. The resulting
new 237-entry C31A installed-file evidence manifest has 197 files,
36 directories, 4 symlinks, length 57,825 bytes and exact SHA256
0ca874d1ebe3f61ea1356bc20d40a1afb30d1ddb515a68b09b486c48f8471be5.
220/221 actual installed package objects matched the new C31A manifest
exactly in the temporary-path full-closure installation; the single
cffi RECORD differs because its generated bin/cffi-gen-src shebang contains
the actual venv root path. That original path-sensitive RECORD remains pinned
to the fixed /opt/omnilyzer/deployment/venv target, as before. This DOES
NOT constitute a full real installed-target C31A acceptance.

C24 lock, immutable wheel contract, C31A static manifest/source distribution
identity, original host provisioning-plan SHA pins and affected tests were
updated TOGETHER. Original historical C32D predecessor migration source
hashes deliberately remain unchanged, as they identify an older installation
generation. No direct pip install/update was performed on DEV; its live
protected venv is still PyJWT 2.13.0, and enabling this new C31A source
against that old venv must FAIL CLOSED until separately root-provisioned.

Real Analytics DEV remains **NO-GO** pending one owner-authorized Task014
root installation, final on-target C31A full qualification, product-private
systemd coexistence mount/start-stop proof, true original signer/JWKS/registry
evidence, four mapped secrets, restricted PostgreSQL RLS, /readyz/persistence
and first-install stop-only rollback, then ONE independent M04 acceptance.
This does not permit a runtime waiver, unsigned install or silent merge.

## Final corrective patch — service-private Docker namespace review

The prior assertion that the reviewed service fragment \`RuntimeDirectory\`
sharing was safe has been withdrawn. The corrected deterministic, UNSIGNED
\`deployment/analytics_dev_activation_inputs.py\` generator now emits
\`[Service]\` plus exactly:

\`\`\`ini
TemporaryFileSystem=/run/omnilyzer/deployment/rootless-docker:mode=0700,uid=991,gid=991
\`\`\`

For the Analytics executor ONLY. \`TemporaryFileSystem\` creates a fresh
mount namespace for the service, overlaying its original fixed
\`BindReadOnlyPaths=/run/user/991/docker.sock:/run/omnilyzer/deployment/rootless-docker/docker.sock\`
destination with its own private UID991/GID991 tmpfs rather than
reusing the host lifecycle-managed canary RuntimeDirectory. The three
other service inputs remain byte-exact original reviewed Git blobs;
canary's installed drop-in is unchanged. Existing C32ZF's original
source SHA, UID991 socket identity and mode contract remain
independently checked. Negative tests deny a mode 0777 override or
changed Docker socket. During the final correction, a literal escaped
newline defect in the original review output was also found by the REAL
systemd parser and FIXED. The generated file now contains distinct
\`[Service]\` and \`TemporaryFileSystem\` lines. Python configparser
and systemd-analyze verify accept the real syntax. Other systemd-analyze
complaints on the isolated build host concern absent installed app
executable and socket unit, not INI syntax. This is CODE-LEVEL
mitigation ONLY. A real
systemd service-start, simultaneous Canary/Analytics start-stop,
private mount identity and Docker socket access test are still
REQUIRED before DEV GO. The generated fragment is unsigned and must
not be root-installed simply because it passes offline tests.

**Python security advisory:** Upstream PyPI's verified
\`pyjwt-2.14.0-py3-none-any.whl\` SHA256 is
\`ad0cef71c756a56e74863c2919cf0985f72decbcfcb550ee2f422e7c62b5eedc\`
(released 2026-09-11). The known critical GHSA-ffc3-869f-jxw9
requires both mixed HS+asymmetric JWT algorithm allow-list and
malformed raw public-key PEM handling; Task014 currently enforces
RS256-only decoding, reducing exposure, BUT the installed exact
PyJWT 2.13.0 remains vulnerable by dependency policy. The above
hash is an externally published upstream artifact digest, not a
completed Task014 offline-wheel approval, installed-runtime
provenance or a waiver. Upgrade 2.14.0 by the original reviewed,
hash-pinned venv-and-manifest release process before live admission.
No \`pip install\` or protected DEV host mutation occurred here.

## FINAL M05-14 HANDOVER — 2026-10-30

**Development handover COMPLETE. Live Analytics 0.15.0 DEV acceptance NOT
COMPLETE; ACTIVE DEPLOYMENT NO-GO.** This is the last consolidated status
for this development batch, not another framework/PR/QA process.

**Delivered and verified:** one original Task014 workflow with Canary as
default and Analytics DEV schema-v2 path; exact signed original Task013
Analytics 0.15.0 OCI digest; immutable 70-source isolated generation and
four unsigned root review inputs; read-only host preflight; four reviewed
systemd-service review bytes (3 original Git objects plus a source-bound
product-private systemd tmpfs fragment); first-install stop-only rollback
implementation. Original Canary and production were NOT changed. The owner
successfully installed and ran the separate read-only root audit on DEV.
Last direct DEV observation: original broker and Canary executor socket
active; UID991 rootless Docker daemon socket available; isolated Analytics
source, protected configs, mapped secret directory absent; Analytics
executor socket inactive. Remote agent remains NoNewPrivs=1, not root.

**Two mandatory release qualification gates remain (do not suppress):**

1. **Concurrent service acceptance — unproven on the real DEV host.**
   The previous shared host RuntimeDirectory review fragment was replaced
   in the current exact source with a product-private UID/GID991 tmpfs
   namespace overlay. The original Canary runtime, 3 original systemd
   assets, signed source and Docker socket path remain unchanged.
   Source and negative tests PASS; real \`systemd-analyze verify\` now parses
   the generated ini fragment without syntax errors. No actual Analytics
   service or canary/Analytics simultaneous start-stop test has occurred.
   Full private mount and independence proof still required before GO.

2. **Installed DEV Python runtime still requires safe re-provisioning.**
   GitHub critical Dependabot alert #25 applies to the LIVE original
   DEV PyJWT 2.13.0 installation. The source dependency pin, wheel
   SHA lock and C31A future-runtime manifest are now coherently updated
   to patched 2.14.0; the isolated four-wheel acceptance passes.
   The running DEV protected venv is NOT updated or independently
   root-qualified. New C31A code MUST reject it until the original
   root-controlled Task014 package installation/review process has
   installed and qualified the exact pinned full closure. No direct
   pip upgrade or security-policy waiver is permitted.

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

**Source of truth:** the exact current GitHub PR #258 HEAD and Issue #27.
No source/release approval follows from unsigned review inputs. Test
counts must be tied to the exact tested SHA. Mandatory latest-HEAD CI
must be checked before any owner-authorized promotion; no source-level
test replaces real DEV signed release, application persistence or rollback.

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


## 2026-10-31: owner activation verified; authenticated metadata handoff

The owner-local reviewed transition completed with
`BROKER_AND_SOCKET_READY_FOR_SIGNED_TASK014`. Independent read-only checks
verified all 70 installed Analytics source hashes at
`b42bf8a804ebda94879776d0aa1d5221fa45bba3`, all four installed systemd assets,
all 43 unchanged original Canary files, the active Analytics broker and socket,
and HTTP 200 from the existing private Canary. Both root-controlled rollback
backups remain retained. This is activation evidence, not application acceptance.
PostgreSQL bootstrap is already complete and MUST NOT be rerun.

The original signed Analytics 0.15.0 evidence remains the immutable private
Forgejo package from Task013 run `40881693662`; do not rebuild or republish it.
Task014 previously required three hashes before it could authenticate to read
that package. For Analytics only, leave `release_manifest_sha256`,
`provenance_sha256`, and `analytics_source_claim_sha256` ALL empty to resolve
those request inputs inside the existing protected DEV job after its original
three-audience OIDC diagnostic. The resolver reuses the exact private package
GET, closed archive parser, and schema/scanner linkage checks. It never prints
tokens or archive contents. A partial empty set is rejected; the existing
complete explicit-hash path remains available. Canary input requirements and
all broker signature/source/OIDC/replay verification remain unchanged.

Dispatch still pins `product_id=analytics`, `target_stage=dev`,
`release_version=0.15.0`,
`source_sha=b9e22e745ecbaf96dc15998e91d1a74f70e5ad77`,
`manifest_digest=sha256:6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1`,
`originating_release_run_id=40881693662`, and
`analytics_installed_commit=b42bf8a804ebda94879776d0aa1d5221fa45bba3`.
The package-derived hashes remain UNTRUSTED request values until the root-owned
broker independently downloads and cryptographically verifies the same release.
This runner-only change does not replace the installed closed source generation.

Before dispatch after this change merges, the broker's separately reviewed
workflow-only authority must bind the exact new merged main SHA. Preserve its
original Canary `reviewed_commit`, executor configuration, runtime/ingress pins,
replay, database and secrets. Do not dispatch against the prior workflow pin or
interpret this code fix as live functional/security/rollback acceptance.


## 2026-10-31: live promotion reached registry authentication; scoped token correction

Owner workflow-only update to merged main
`a09ddd45579db1a3ff7873082a063af4c47d5a13` succeeded and was independently
verified with unchanged installed Analytics70 and Canary43. One real original
Task014 run `41162462416` passed its gate, three-audience OIDC diagnostic,
Tailscale join and authenticated Forgejo metadata read, but the broker returned
503. Analytics executor had no start timestamp and port3141 remained absent;
the previous private application continued returning HTTP200. Do not report
this as a deployment or rerun the PostgreSQL bootstrap.

The existing read-only Zot diagnostic run `41163125919` passed its actual
Docker OIDC authentication check without invoking the broker or deployment.
The exact Analytics manifest's live 401 challenge names the fixed
`https://oci-dev.omnilyzer.ai/zot/auth/token` realm and repository pull scope.
The owning defect is protocol confusion: a GitHub OIDC JWT was sent directly
as registry Bearer by the evidence reader and as `registrytoken` by Cosign.
The existing approved Docker pull code already uses `Basic(oidc:GitHubJWT)`
to obtain a registry-scoped Bearer token.

The read-only HTTP consumer now uses that exact fixed same-host realm/service
and a constructor-selected canary or Analytics `pull` scope, then requests the
unchanged digest-addressed manifest with the returned registry token. Responses
remain bounded, duplicate-free, nonredirecting and fail closed. Forgejo's
existing OIDC Bearer path is unchanged. Cosign's private0600 Docker config now
uses the same `auth` Basic-exchange convention as the existing Docker pull path;
all descriptor/cleanup/ownership and signature checks remain in force.

These two files belong to the separately reviewed31-file compatibility archive,
not the inherited39. The current installed b42 generation still contains the
old bytes until one reviewed owner-local source/config generation transition
is applied. Generate exact new activation inputs from the reviewed fix commit,
preserve the original Canary43 tree and its four fixed historical preimages,
backup the complete current b42 generation and configs, and bind workflow
identity to the exact eventual merged main SHA. A runner-only change or a
workflow-only rotation cannot install these two host files. The immutable
signed Analytics0.15.0 artifact/run40881693662 must not be rebuilt or republished.
