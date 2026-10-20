# File: docs/operations/task014-private-source-cutover.md

# Task 014 — Private Zot source generation cutover and rollback

**Status:** Draft, review-only. No DEV host installation or service action is authorized.

**Related files:** `release/task014_source_cutover.py`,
`release/tests/test_task014_source_cutover.py`,
`deployment/application_source_set.py`,
`deployment/application_manifest.py`,
`deployment/broker_service_config.py`, PR #207, and issue #182.

## Purpose and existing platform boundaries

Task 014 needs to install the already-developed **private Zot authentication
integration** without creating a new deployment service, changing the existing
application root, opening Zot to anonymous access, or touching PROD.

The existing DEV source directory is
`/opt/omnilyzer/deployment/app`. It contains precisely the old 41 regular
files. The new closed application selection has **43 files**: 40 Python modules
and 3 runtime assets. Of these, **32 currently match byte for byte, 9 must be
replaced and 2 must be added**. All existing 41 files were inspected and found
to be owned root:root with mode 0644. Historical source baseline is commit
`875773c69b19220bd1059e7240dcd296bc3c19a9`.

The reviewed code-source commit of PR #207 at the time of this work is
`334306600e60f65581a5acd9a55e2f9ea9e9c46b`. Its **draft-only**
canonical C26 application manifest SHA-256 is
`ace4295216a75bc353cdca4ef1ea6d6f66328344705331c01519150a5865c607`.
**Do not treat this digest as the digest of any future merge commit**:
`reviewed_commit` is part of the canonical manifest, so the final digest
must be regenerated from the precise approved protected-main SHA.

## Review-only source preparation library

`release/task014_source_cutover.py` is not one of the 43 application runtime
files. It has no CLI, GitHub Actions dispatcher, automatic execution, or
privileged service. Import alone does nothing.

Its `reviewed_plan(repository, reviewed_commit)` function verifies the exact
checked-out Git commit and generates all 43 source hashes and previous 41 source
hashes. It requires the old-to-new difference to be exactly the nine reviewed
replacement modules and two reviewed additions. The exact file modes must be
0644, and the allowed path set must be sorted, unique and complete.

Its `readonly_preflight(plan)` checks the existing application root for
**all 41 old files** and all expected parent directories, rejecting symlinks,
unlisted objects, other owners/modes, changed bytes, oversized files or
unexpected extra content.

**Privileged operations, not authorized now:**
`prepare_staging(plan, repository)` creates a complete 43-file root-owned
candidate in a hidden *sibling* of `app` under the existing
`/opt/omnilyzer/deployment` directory, requires root identity and exact old
source, validates all source bytes, fsyncs file and directory data and keeps
the old application unchanged.

`activate_staging(plan, staging)` must run only after the broker, executor
socket and executor service are stopped. It rechecks the complete old and new
generations before issuing one Linux `renameat2(RENAME_EXCHANGE)` operation
on the two sibling directories; this makes the active 43-file generation
switch **atomic**, not eleven independent overwrites. The entire previous
41-file tree is preserved under the staging directory name. Its post-swap
verification automatically exchanges the trees back on failure.

`rollback_staging(plan, staging)` rechecks the installed 43-file generation,
the preserved previous 41-file generation and service inactivity before a
single atomic exchange returns the entire previous application source to
the original `app` path. Neither operation reads or mutates the replay DB,
application state, Docker image, audit, Nginx config, Zot access policy,
GitHub settings, or PROD.

Do not manually remove the former application's sibling backup unless an
independent restore acceptance has passed and the owner explicitly approves
retirement. Do not rerun old signed promotions/replay identities.

## Offline acceptance evidence

The `release/tests/test_task014_source_cutover.py` suite operates only inside
a disposable temporary directory, with nonprivileged test identity stubs
**confined to test code**. The production library provides no bypass argument.
The tests exercise:

- Exact 41-to-43 source admission, including the nine changes and two additions.
- No-write full old-generation preflight.
- Complete staging with all content hashes and strict file and directory modes.
- Linux atomic exchange and exact restoration from the retained old tree.
- Rejection of extra files, symlinks, corrupt old bytes and missing new files.
- Rejection when services have not been independently quiesced.
- Automatic swap-back following simulated post-switch verification failure.
- Automatic swap-back when the durability fsync fails.
- Refusal to restore from a modified, unreviewed application generation.

**The tests do not establish real DEV cutover acceptance.** They prove only
the offline library and Linux exchange semantics.

## Release gates — ALL must be separately authorized

**Gate A — source-only merge:** The owner must separately approve merging
security-corrected PR #207. Its current status is DRAFT, and it is still
unmerged. Any stacked source-cutover PR also requires its own review before use.

**Gate B — exact-source bundle:** Record the actual protected-main final merge
SHA, regenerate the 43-file manifest from that exact Git checkout, review
every file SHA256 and path, and capture the old 41-file host baseline. Keep
the new source tree and trusted previous tree available for recovery. Staging
and atomic exchange need a root-owned approved host operation, not an
interactive user copying files into the running application.

**Gate C — configuration migration:** The existing root-owned broker and
executor configurations pin a reviewed source and, for the broker, the exact
`expected_workflow_sha`. They remain outside the 43-file application tree.
Review and separately authorize atomic configuration updates bound to the
new exact GitHub protected-main SHA, preserving identities and immutable
runtime/ingress digests. **The source-cutover library intentionally does not
modify those files**. Do not loosen the workflow SHA verifier. Prepare exact
config rollback bytes and directory permissions before any service stop.

**Gate D — controlled DEV service acceptance:** Explicitly authorize
quiescing broker/executor/socket; then stage, validate and atomically exchange
the application directory. Before any service activation, verify current
root ownership, source hashes, Python import closure, exact broker and
executor authority configurations, and the rootless Docker socket's
read-only bind at `/run/user/991/docker.sock`. Verify that systemd creates
the executor-private `0700` runtime directory with UID/GID 991. During an
authorized service test, check `0600` temporary Docker auth creation and
cleanup, broker peer credentials, request secrecy and pre-replay rejection.
If acceptance fails, atomically restore the entire old source tree, restore
approved old configs, and preserve replay/audit/state.

**Gate E — new signed DEV promotion:** Requires **another, explicit owner
approval** after all DEV acceptance gates pass. Must use one new signed run
identity; prior run IDs `39119544953` and `39220114634` are consumed and
must not be retried/reset. PROD remains excluded.

## Current operator decision

This artifact authorizes no operation. The present safe stopping point is an
**offline-tested, reviewable privileged source cutover design**. The additional
root-controlled configuration migration and end-to-end DEV sandbox acceptance
remain separate release blockers. No time estimate or future execution is
implied.
