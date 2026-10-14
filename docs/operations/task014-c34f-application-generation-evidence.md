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
3. Verify the C34D workflow pin, canonical broker/executor configurations,
   systemd unit identities, restricted rootless Docker, replay/audit continuity
   and ingress. Preserve all unrelated source bytes and configuration fields.
4. Under a reviewed process lock and **stopped broker/executor socket**
   boundary, stage and atomically replace only the three approved modules.
   Refuse symlinks, hard links, missing files, unexpected modes or unlisted
   paths. Revalidate each stage, source-set prefix, and post-state with fsync.
5. Test partial progress, power-loss/restart recovery, exact rollback,
   root-owned backup and service restart qualification in isolated acceptance
   before installation. Leave credential, replay, audit and session state
   unchanged. Do not enable automatic retries.
6. Requalify the running broker and effective logging controls only after
   all three files and the full new 41-file manifest pass. Record a bounded
   operator receipt without JWTs, claims, JTI, request bytes or private logs.
7. Require **separate explicit authorization** before another live promotion.
   The October 14 one-shot C34D attempt has been consumed.

This document is the review and acceptance boundary, **not** a runnable
privileged change procedure. C34E PR #189 and C34F remain draft; no
application file is copied into `/opt/omnilyzer/deployment/app`.
The unchanged protected `main` SHA is
`57919c3b9aca0cb98e85bbb26460f6267d093fa9`.
