<!--
File: docs/operations/task014-c34j-atomic-file-mechanics.md
Purpose: Acceptance boundaries for descriptor-scoped, resumable backup and
atomic single-file publication as one component of a future root-only five-file
Task 014 DEV migration.
Related: deployment/c34j_atomic_file_mechanics.py,
deployment/tests/test_c34j_atomic_file_mechanics.py,
deployment/c34i_merged_migration_authority.py,
deployment/c34i_stopped_host_gate.py,
deployment/c34i_final_main_seal.py,
deployment/dev_post_c31_application_update.py,
deployment/state_store_successor_host_migration_runtime.py,
docs/operations/task014-c34i-host-transition-gates.md,
GitHub issue #182, draft PR #190.
-->

# C34J — backed-up atomic write mechanics (review only)

## Source and deployment separation

**The C34J module is deliberately NOT a root installer.** It is a
descriptor-scoped file-operations component that makes neither privileged
service decisions nor source-revision decisions. It has no host path,
command-line interface, `sudo`, systemctl, GitHub workflow dispatcher, or
deployment activation. No live DEV host file has been modified.

The earlier operator-executed C34G root preflight qualified all 41 existing
application files and both root-owned configurations in the running predecessor
state. That result does not authorize a source transition.

## Exact five-file scope

A future complete orchestrator must bind an independently reviewed protected
main SHA and progress through the five operations in order:

| Step | Installed file | Mandatory original backup |
| --- | --- | --- |
| 1 | `deployment/broker.py` | `00-broker.py` |
| 2 | `deployment/broker_https_ingress.py` | `01-broker_https_ingress.py` |
| 3 | `deployment/broker_integration.py` | `02-broker_integration.py` |
| 4 | Executor canonical `executor.json` | `03-executor.json` |
| 5 | Broker canonical `dev.json` | `04-broker.json` |

The *broker configuration's two fields* must change in the final committed
generation: `reviewed_commit` and `expected_workflow_sha`, both to the final
approved `main` revision. The executor configuration changes only
`reviewed_commit`. The existing running predecessor retains its already
approved C34D workflow authorization and is not touched by this PR.

## Reusable mechanics

`seal_original_backup()` requires a prequalified, retained, private
backup-directory file descriptor with ownership/mode 0700. The future
orchestrator must create this directory under a root-owned, approved location
and ensure it contains only the five expected backup filenames.

Each file is created without following symlinks and with mode 0600; partial
backup contents may be resumed only if they are an exact prefix of the
expected original bytes. The completed backup is flushed to stable storage,
read back and checked, and its directory is fsynced. Repeated calls cannot
overwrite a nonmatching or already sealed backup. For a live transition, the
backup directory must be root:root (uid/gid 0:0), independent of the executor
and broker configuration GIDs.

`publish_exact_file()` requires a previously sealed matching backup and
an independently qualified destination-directory descriptor. It rejects
unknown destination names, a mismatched backup name, altered source bytes,
symlinks, hard links, bad owner/GID/mode, wrong stage names and any stage
content not matching an exact prefix of the reviewed target bytes. A single
temporary stage is written and fsynced in the destination directory; only
after the original destination is rechecked can it be atomically renamed.
The parent directory is fsynced; post-state source bytes are checked again.

A repeated operation after successful publication **must not overwrite**
anything: the caller must instead reclassify the new prefix and advance to
the next operation.

## Verified synthetic acceptance

Unprivileged tests in
`deployment/tests/test_c34j_atomic_file_mechanics.py` exercise normal
publication, durable private backup creation, partial backup/stage resumption,
a complete stage, mismatched backup substitution, corrupt stage content,
missing backups, symlinks, hard links, source tampering, directory modes and
invalid destinations. These tests use only fresh temporary directories and
synthetic bytes; they cannot access /opt, /etc, the broker, registry, replay or
audit state.

## The still-missing root orchestrator

**Do not invoke the primitives on live DEV yet.** They deliberately do not
supply these mandatory controls:

1. A verified protected-main merge SHA and source-seal identity, not a draft
   revision, plus the corresponding separately reviewed workflow OIDC pin.
2. A root-only installed-state reader that recognizes **each** of the six
   C34I final-main migration prefixes, including one allowed partial stage.
3. A durable root-owned backup directory, source provenance checks, exact
   expected backup manifest and verification of **all five backups before the
   first file publication**.
4. Exclusive deployment process lock, stopped broker, executor service and
   executor socket, preserved rootless Docker/runtime, replay and audit state.
5. Safe descriptor traversal for all app/config/staging/backup directories,
   independent UID/GID checks and source-set no-extra-file enforcement.
6. A one-prefix-only public operation with fail-closed crash/power-loss
   acceptance, delayed service restart until complete five-file integrity,
   redacted operator receipt and explicitly reviewed recovery/rollback.
7. Independent security review plus permission to activate; no implied
   approval to merge or perform another GitHub promotion.

The C34I stopped-host gate returns `migration_ready=False` by design.
It is not acceptable to bypass that flag or monkeypatch its constants
to make the writer live. Draft PR #190 stays unmerged. Incident #182
remains open while the original HTTP 403 cause is unresolved.
