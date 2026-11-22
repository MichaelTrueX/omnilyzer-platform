# M05 Task14B P0: DEV-only recovery-aware immutable source cutover

Status: SOURCE ONLY, DRAFT, INDEPENDENT M04 ROOT QA OUTSTANDING. This document does not authorize any root operation, source switch, Task014 retry or PROD change.

## Proven root afterstate and target

Root-native owner output identified current broker and executor JSON SHA256, both de054fbc2f54c35835ed53d91aa2caa5da965d4a619db3e9f6c909c94598d4cc. The old protected installer module SHA256 is cc7dfd7fb022a01772bb2f18fd1705f6e4f15e706903e4b47c8833b7d7f9ac5b. Two currently selected systemd drop-ins SHA256 are 43bcd3234c8428cedd5d4bda06db3a0b4144c1275ca2121230046affe4f89342 (broker) and fa635a6d8321cf202487aca19abafaf20f62af38f9f9fb5d55892b7b82511ea6 (executor).

Original live root: 330f3255f0067b9ddbe30d50466830bd71a55a11. Proposed new root: 17972bff312a3df7c6e5e4f3d83b239b9b11aba1 (draft PR316).
Old broker active, executor FAILED exit-code, socket FAILED service-start-limit-hit, signed0.16.0 green private readyz HTTP200. This operator deliberately does NOT demand an initially active socket.

All 76 original root-owned source files have been compared read-only to the cfc Git revision: 74 byte-identical, exactly 2 modified: deployment/analytics_executor.py SHA256 34de557ca2d5e63adb6cc5c18c827dd5f266040e699525670d21c9667b84f5ff, deployment/analytics_route_journal.py SHA256 b4029a2a1f152ac7848ff2b9e73e9fb8a6ce40101b58cb301d57fb82730171cc. New SHA root must be immutably stage-installed and verified independently via draft PR317 before cutover.

## Proposed four exact root configuration outputs

- Broker JSON (root:990 0640) SHA256: 09d54fac2ed1be212d64db42d8d1570dbc4849614c5a108fa6e6c1adf5fb8386.
- Executor JSON (root:991 0640) SHA256: 09d54fac2ed1be212d64db42d8d1570dbc4849614c5a108fa6e6c1adf5fb8386.
- Broker systemd drop-in (root:root 0644) SHA256: a85e2f8bd49f1c79ae5683506e58065ceebbf0784b6ce395dcdba8652aa7b529.
- Executor systemd drop-in (root:root 0644) SHA256: 6b0b1b4619dbe34037cfe12e35181daf516ba34266cbeff7a31d51f23ab722de.

Broker and executor JSON remain byte-identical. Only source commit + two source_sha256 entry hashes differ from old JSON; all original security controls, identity, owner, workflow630, route, environment and remaining 24 hashes are retained. Each systemd drop-in replaces exactly one WorkingDirectory reference. The new review artifacts are UID1005 private mode0400, not root-installed.

## Exact root cutover preconditions

The separately reviewed candidate operator, intended path /usr/local/libexec/omnilyzer-m05-legacy-recovery-cutover-cfc.py, will require root:root mode0500, single-link, exact path and pinned source hash. Its only valid actions are --preflight and --switch.

Before any service mutation, validate:
1. Four live root-owned current configuration preimages with exact owner-native SHA256, four proposed UID1005 review payloads with exact expected new SHA256, strict unchanged OIDC/owner policies, and source config schema4.
2. Newly staged root:root SHA-named cfc source root, exact 76-file root-owned manifest closure with no extra modules; all source SHA256 must match the independent pinned full manifest. Existing root330f remains untouched.
3. Owner-root final0.16 receipt SHA256 e1efe4109156c6c0116a806dc287f7edbd6e828973db77f2fe4f6d2ceaa5d341 and all four OAT root0600 receipts. Confirm gen1 switched to restored then gen2 switched under original signed0.16 request SHA73071f42, plus current route green signed0.16 OCI and exact container.
4. Historical root:991 mode0440 certificate already minted under UID991 journal by the independently reviewed legacy migration operator. Compare certificate with original OAT raw receipt hashes, original signer source, canonical current journal, immutable OCI/container and root final SHA. No UID991 self-minting.
5. Immutable readonly SQLite replay: old successful run43838827603 status FINISHED or ABSENT; failed run44890393889 status CONSUMED, never replayed, reset or marked FINISHED.
6. Independent UID991 RootlessKit container/image/route check from SHA-pinned cfc source, broker active, loopback active, private readyz200, executor exactly FAILED exit-code and socket exactly FAILED service-start-limit-hit. Any changed state is HOLD.
7. New root0700 cutover journal must be unused. No existing temp backups. No configuration path or root source may be symlinked, mutable, group-writable or wrong owner.

## Transaction design and rollback

After all preflight checks, write a root-only rollback journal and exact old config bytes before stopping the broker. Stop broker and failed socket, install exactly four reviewed new config bytes atomically, daemon-reload systemd, reset failed state of only the known executor/socket units, start new socket and broker, and verify source selection and signed0.16 live health. No Docker/container, replay/JTI, PostgreSQL or PROD mutation.

If any step fails: stop new broker/socket; restore all FOUR original root config bytes atomically; daemon-reload; start only original broker and verify original0.16 HTTP200. The old socket was failed before this transaction; leave it stopped/fail-closed, do not falsely call it healthy. Preserve exact rollback receipt and original snapshots. An ambiguous or incomplete rollback is HOLD for manual reconciliation, never blind retry.

An active new socket alone is NOT proof of working executor, and is NOT permission to dispatch Task014. After root switch, separate actual UID991 startup, authenticated request chain, rollback route and original signed0.16 verification are required. The consumed failed Task014 #44890393889 must never be rerun.

## Test evidence and outstanding gates

7/7 source-only positive/negative tests PASSED. All systemctl, journal write, root config replacement operations were MOCKED. Missing certificate denies before service mutation. Exact known failed socket state is required. Simulated new socket start failure restores old bytes and does not restart old failed socket. Current nonroot connected session cannot access actual protected credentials or execute root due no_new_privs.

Pending: truly independent M04 review of both PR316 and PR317 plus this operator, root-only positive verification of source stage and historical completion, actual root preflight, approved immutable source installation and controlled source cutover. No operation should be considered production-ready based on this document or synthetic test suite alone. PROD unchanged.

### M04 storage durability review amendment

In addition to fsync on each root-only preimage file, the bounded cutover operator now fsyncs the rollback directory and its parent after creating all four preimage files plus the complete manifest, BEFORE it stops the broker. The same directory metadata fsync is performed after the success marker and the fail-closed rollback marker. The preimage journal persists even on failure. This addresses the power-loss window in which file data might be durable but parent directory entries for the only trusted rollback copies are not. Source-only simulated service tests still pass; real native-root filesystem crash/recovery tests remain mandatory.

### Independent M04 rollback-path correction

The previous root cutover source caught and silently discarded failures in the
rollback handler while preserving only the original cutover exception. Thus a
partial restoration could leave one or more protected JSON/drop-in files on the
new source and still look superficially identical to a safe rollback HOLD.
That is not an acceptable incident recovery claim.

The revised source now, after attempting restoration, **reads back each exact
original preimage** using the existing root owner, group, mode, single-link and
stable-FD verifier. It requires both old failed units remain inactive before
restarting the original broker, then independently verifies old WorkingDirectory
and signed0.16 private readiness before writing the explicit
`ROLLBACK_TO_330F_FAILCLOSED` root receipt.

If any protected file, service or metadata cannot be restored, it attempts to
fsync the distinct `ROLLBACK_UNVERIFIED_HOLD` root receipt and raises a
different hard failure; it **must not** falsely write the successful rollback
marker, start the old failed socket or auto-retry a consumed Task014. Even if
the disk prevents this marker, the original root-only preimages remain, and
manual native-root afterstate inspection is mandatory.

9/9 source-only tests PASS, including simulated interrupted second rollback
write, byte-content mismatch during restoration, correct stop/start order and
exact returned root config. Systemd operations and file writes were MOCKED.
These are necessary negative controls, not a native-root recovery acceptance.

Before any source stage, independent M04 must also review PR317's latest pinned
protected-importer SHA256 check and confirm the actual root-only importer
metadata. Neither this amendment nor GitHub Repository Quality authorizes a
new Task014 run or a new privileged maintenance operation.

## 22 November 2026 source correction - supersedes cfc pre-install hashes

PR316 source HEAD 17972bff312a3df7c6e5e4f3d83b239b9b11aba1 fixes the independent CodeRabbit
root chown race, replay writer lifetime, source-probe binding and certificate
publication ordering. The source-only security test group passed 75/75 on
small-laptop. The root-installed 330f application remains untouched.

The revised source-stage manifest and two immutable replacement payloads are
in the separate, user-owned DEV review handoff
`.delivery/m05-pr316-source-stage-17972-20261122/`. Four exact cutover
payloads are in `.delivery/m05-pr316-recovery-cutover-17972-20261122/`.
No previous cfc input hash or native-root PASS is sufficient for the new
target; an exact independent review of this version, renewed root read-only
preflight and owner-approved controlled DEV recovery are mandatory before any
stage/cutover. No Task014 JTI replay or PROD change is allowed.
