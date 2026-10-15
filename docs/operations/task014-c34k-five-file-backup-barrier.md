<!--
File: docs/operations/task014-c34k-five-file-backup-barrier.md
Purpose: Define all-five-original backup durability and recovery
qualification before any Task 014 protected source/config publication.
Related: deployment/c34k_five_file_backup_barrier.py,
deployment/tests/test_c34k_five_file_backup_barrier.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/c34i_merged_migration_authority.py,
deployment/c34i_stopped_host_gate.py,
docs/operations/task014-c34j-atomic-file-mechanics.md,
Task 014 issue #182 and draft PR #190.
-->

# Task 014 C34K — complete predecessor-backup barrier

**REVIEW ONLY — not a root host installer and not a live deployment approval.**

## Why the barrier is necessary

C34J proves how a *single* already-validated original may be backed up and
atomically replaced. For a five-file migration, publishing even the first
module before verifying that **all five** original source/configuration
backups are durable would make a partial failure difficult to reverse safely.

C34K inserts a transaction-level stop: first inspect **all five installed
original bytes** and validate their intended file identities, then seal all
five private 0600 backups, then independently reread the complete cohort.
A caller receives a successful receipt only when every backup exists and
matches its exact original bytes. Incomplete or corrupt cohorts never return
success, and the module itself cannot publish source/config files.

## The five closed pairs

| Migration role | Installed basename | Private backup basename |
|---|---|---|
| Broker authorization | `broker.py` | `00-broker.py` |
| Strict HTTP ingress | `broker_https_ingress.py` | `01-broker_https_ingress.py` |
| Promotion construction | `broker_integration.py` | `02-broker_integration.py` |
| Executor config | `executor.json` | `03-executor.json` |
| Broker config | `dev.json` | `04-broker.json` |

`C34KOriginalSource` binds a single verified `C34JFileIdentity`, an
already-open directory descriptor, and the exact predecessor source bytes.
`seal_all_five_original_backups()` rejects duplicate, missing or re-ordered
roles. It never guesses a location or substitutes arbitrary backup names.
The future reviewed root orchestrator—not this module—must prove that every
input came from the exact protected 41-file source generation and canonical
root-owned configurations for the approved final SHA.

## Fail-closed and crash recovery

Before any backup write, the module validates the private backup directory
as mode 0700, rejects unrecognized directory entries, and rereads each of
the five installed originals through no-follow, single-link descriptor
checks. It rejects a changed fifth file **before writing any of the first
four backups**.

The C34J primitive then writes backups in closed order, resuming only an
exact original-byte prefix after an interruption. A failure may leave an
exact partial backup **prefix**; this is not reported as success or
automatically discarded. An unexpected filename, symlink, wrong mode,
corrupted existing backup or mismatched byte sequence is a hard HOLD.

`require_complete_original_backups()` checks all five backups again without
creating files or rereading installed originals. It can therefore preserve
rollback evidence even after a separately authorized source step has changed
one of the protected files. A future one-prefix writer must call this
check **before each individual publication**.

## Rehearsal coverage

Synthetic, non-root tests create a disposable local directory hierarchy,
seal and recheck all five backups, inject failure at the third backup, verify
partial-prefix recovery, corrupt a backup, inject unrecognized files and
symlinks, change the fifth source, tamper with directory permissions, reorder
roles and verify the complete cohort remains readable after a synthetic
installed-file change. Tests verify that no source file is modified by
the backup barrier.

## Limitations and live HOLD

C34K is a **backup-only contract**. Passing its tests does not prove that
directory descriptors originated from privileged root-controlled install
paths or that the source bytes were bound to a final reviewed main SHA. It
does not acquire the deployment lock, stop broker/executor/socket services,
freeze rootless runtime/persistence, inspect journald, identify the live
source generation, or authorize replacing even one installed file.

The root-controlled five-file orchestrator remains separately required. It
must use a newly approved final-main source seal, enforce the 41-file
source/config prefix at every step, check all five backups, validate stopped
service and rootless runtime boundaries, and qualify rollback, restart and
power-loss recovery in disposable root acceptance. The C34I gate retains
`migration_ready=False`.

**Do not merge PR #190, install application files, rotate workflow authority,
reset audit/replay state, or dispatch a new promotion on the strength of this
review.** Issue #182 remains open until the cause of the prior HTTP 403 and
the subsequent corrective acceptance are both evidenced.
