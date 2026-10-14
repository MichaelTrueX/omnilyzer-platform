<!--
File: docs/operations/task014-c34f-application-generation-evidence.md
Purpose: Exact 41-file C34E source-delta review and safe future migration contract.
Related: deployment/c34f_application_generation_evidence.py,
deployment/tests/test_c34f_application_generation_evidence.py,
deployment/application_source_set.py, deployment/application_manifest.py,
deployment/state_store_successor_host_migration_runtime.py, Issue #182.
-->

# Task 014 C34F — frozen application-generation evidence

**REVIEW ONLY. Not a root migration, production authorization or live deployment.**

## Verified Git facts

From a clean isolated checkout on `omnilyzerdev`, exact 41-file Git
source manifests were compared for:

- Installed-authority reference: `176ed3a31ffcf23346639ef22ac9bcab3794f0df`
- C34D workflow-only `main`: `57919c3b9aca0cb98e85bbb26460f6267d093fa9`
- C34E draft proposal: `9289bbc59533e94917ab423a7d29018d011a14a8`

The first two contain identical protected-file bytes. The proposal changes
**exactly three** protected files: `deployment/broker.py`,
`deployment/broker_https_ingress.py` and
`deployment/broker_integration.py`. All other **38 of 41 files** are unchanged.

| Frozen generation | Canonical 41-file manifest SHA-256 |
|---|---|
| Installed-authority reference | `384f5b4e4ca9849da62ab17b624137a52b9292fd3e03d03fefcbabed3bc0ee4b` |
| C34D workflow main | `d3f9f0d27e0a57b8a61f4beb33a9dc925cbc806a80f2ffa38b8ace013391d49b` |
| C34E proposal | `39d8431d48984754c847159f83ef218b550f78695e9fb87a2cc02058d7ffb706` |

The digest differs between the first two rows because the manifest
embeds the reviewed commit SHA, even when application bytes are identical.

Path-set digest: `c846e3d863f8c651ffc2de4d3671c9b8c0631c72366a360637d9cc45f98b60ab`.
Per-file before/after SHA-256 values are pinned in
`deployment/c34f_application_generation_evidence.py`.

## Review qualifier

`review_c34f_generation()` is a no-argument, read-only Git-object evidence
qualifier. It reuses the repository's existing source allowlist, closed
Git-object reader and canonical manifest structure, comparing **all 41 paths**.
It refuses missing objects, altered source, unexpected extra changes, forged
review identities and mismatched manifest digests. Failure messages contain
no source byte contents or sensitive filesystem details.

A passing qualification proves only that those repository Git objects match
the pinned proposal. It does **not** prove installed files have these bytes.


## C34G — pure five-file transition authority

The review-only `deployment/c34g_migration_authority.py` extends the source
evidence with an **exact six-state prefix machine**, validated by
`deployment/tests/test_c34g_migration_authority.py`. The only admitted
successive operations are:

1. Replace `deployment/broker.py`
2. Replace `deployment/broker_https_ingress.py`
3. Replace `deployment/broker_integration.py`
4. Replace canonical executor `reviewed_commit`
5. Replace canonical broker `reviewed_commit`
6. Complete: **no additional mutation**

For every state it compares **all 41 SHA-256 digests in canonical path order**,
not merely the three changed paths. It also compares the full normalized
executor and broker configuration bytes. Their only permitted modifications
are `reviewed_commit`, with the previous C34D broker
`expected_workflow_sha` retained. Source/config mixes outside these six
prefixes are forbidden; classification raises a fixed error and does not
guess recovery by accepting an arbitrary hybrid. The immutable
`C34GMigrationState.rollback_operation()` additionally names the only legal
reverse step: restore broker config, then executor config, then the three source
modules in reverse order. This is a **pure rollback plan**, not an executable
root rollback procedure; live rollback remains blocked pending independent
acceptance and backup verification.

This authority has **no privileged filesystem reader or installer**.
Its caller supplies observed content digests; future root-only code must prove
those values were read from the actual installed files under owner, mode,
symlink, link-count, traversal and TOCTOU controls. The proposed target
`9289bbc...` is not a merged deployment authority. **Do not execute** the
old C33AE migrator, the old SHA-only workflow rotation, or a hand-crafted
five-file copy against live DEV.

Before a privileged step is ready, still required are an independently pinned
**final merged target commit**, exact root-owned installed source/config
qualification, stopped-unit and rootless runtime checks, durable stage/backup
design, one-step idempotent prefix advancement, recovery tests for interrupted
writes, journal-control qualification, an operator-controlled service restart,
and a negative acceptance suite demonstrating rollback without touch to
replay, audit, credentials or running canary. C34G provides only the
**pure authority constraint** that such a runtime must obey.

## C34G — root-owned read-only installed predecessor preflight

To close the gap between **repository** manifests and **installed** bytes, an
independent standard-library-only checker now exists at
`deployment/c34g_installed_predecessor_preflight.py`. It is also staged
directly on `omnilyzerdev` (not through Windows) at
`/home/omnigpt/repos/omnilyzer-platform/.task014-c34d-operator/c34g_installed_predecessor_preflight.py`.

The checker is **read-only and fail-closed**, and requires an explicitly
authorized root account. It embeds all 41 exact predecessor SHA-256 values
from commit `176ed3...`, validates the entire canonical manifest, checks
root ownership/mode/hardlink/symlink/directory constraints with descriptor
traversal and stable file fingerprints, refuses any extra installed path,
and checks the two root-controlled canonical configurations. Broker
`expected_workflow_sha` must remain `57919c3...`; both configs must
still reference the source predecessor. It also snapshots relevant service
activity before and after inspection without reading private journals.

The review CI runs synthetic tests for its exact 41-file manifest, canonical
encoding, root-identity restriction, stable PASS/HOLD receipt and absence of
mutating Python filesystem primitives. **These tests do not certify a live
root execution.** The on-host script is independently SHA-256 verified
before any operator runs it. A preflight PASS only proves the predecessor
is still intact; it does not authorize stopping services, installing files,
modifying JSON authority or sending a promotion.

No privileged commands have been performed by the assistant. The installed
host result must be reviewed separately before a five-file transition can be
approved. If HOLD occurs, neither the source nor config should be
automatically repaired by the checker.

## Exact dependency for a privileged successor-generation transition

The historical C33AE migrator changes precisely one state-store source file
against a different frozen predecessor. It cannot safely be repurposed by
changing its constants or invoking it against the running C34D broker.

A separate security-reviewed **three-file** installer must pass all of:

1. Freeze the **eventual merged** C34E `main` commit. Proposal commit
   `9289bbc...` is not the final source authority: recompute and repin the
   full manifest, because its canonical reviewed-commit changes after merge.
2. With root-only privileges, prove every installed member of the 41-file
   allowlist matches the exact expected existing source and owner/mode
   constraints. Do not infer this from the JSON `reviewed_commit` alone.
3. Verify the current C34D workflow pin, canonical root-owned
   broker/executor configurations, systemd service identities, restricted
   rootless Docker, replay/audit continuity and ingress. The source-generation
   transition must explicitly update **both** configurations' `reviewed_commit`
   to the final merged target commit. Existing
   `dev_post_provision_qualification.py` requires the executor configuration's
   `reviewed_commit` to equal the 41-file manifest revision, and the broker
   uses its own `reviewed_commit` for immutable runtime/ingress references.
   Retain broker `expected_workflow_sha=57919c3b9aca0cb98e85bbb26460f6267d093fa9`
   unless a distinct reviewed workflow rotation is approved. Keep the
   runtime/ingress hashes and every unrelated configuration field unchanged.
4. Under a reviewed process lock and **stopped broker/executor socket**
   boundary, stage and atomically replace exactly the three approved source
   files **and** the two approved canonical configuration files. Verify
   exact before/after bytes, UID/GID, mode, no symlinks or hard links and
   unchanged/unlisted path sets. Revalidate every allowed intermediate
   prefix and post-state, including `fsync`.
5. Test partial progress, power-loss/restart recovery, exact rollback,
   root-owned backup and service restart qualification in isolated acceptance
   before installation. Leave credential, replay, audit and session state
   unchanged. Do not enable automatic retries.
6. Requalify the running broker and effective logging controls only after
   the three source and two configuration files align to the full new
   41-file manifest. Record a bounded operator receipt without JWTs,
   claims, JTI, request bytes or private logs.
7. Require **separate explicit authorization** before another live promotion.
   The October 14 one-shot C34D attempt has been consumed.

This document is the review and acceptance boundary, **not** a runnable
privileged change procedure. C34E PR #189 and C34F remain draft; no
application file is copied into `/opt/omnilyzer/deployment/app`.
The unchanged protected `main` SHA is
`57919c3b9aca0cb98e85bbb26460f6267d093fa9`.
