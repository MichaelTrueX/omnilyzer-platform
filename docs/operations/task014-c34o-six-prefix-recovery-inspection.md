<!--
File: docs/operations/task014-c34o-six-prefix-recovery-inspection.md
Purpose: Review-only handover for closed read-only recovery state validation
across all six Task 014 source/configuration prefixes.
Related: deployment/c34o_six_prefix_recovery_inspection.py,
deployment/tests/test_c34o_six_prefix_recovery_inspection.py,
deployment/c34n_root_predecessor_adapter.py,
deployment/c34m_descriptor_source_observation.py,
deployment/c34l_one_prefix_coordinator.py,
deployment/c34k_five_file_backup_barrier.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/c34i_merged_migration_authority.py,
docs/operations/task014-c34n-root-predecessor-adapter.md,
Task 014 draft PR #190, incident issue #182.
-->

# Task 014 C34O — read-only six-prefix recovery-state inspection

**REVIEW ONLY. There is no root-executable installer, restart mechanism,
workflow dispatcher, or release permission in this module.**

## Objective

C34N qualifies the intact, stopped C34D *predecessor only*. C34M collects
all 41 source digests and validates one interrupted C34J staging artifact.
C34L binds all five original backups, those source digests and two complete
canonical configs to one of six *proposed final-main* migration prefixes.

C34O joins these checks for **read-only recognition** of an in-progress
migration, including an exact, partially written next-step staging file.
It deliberately does not generalize C34N into an enabled root installer.

## Fixed source/config and backup order

The only permissible forward source/config states are:

| Prefix | Published files relative to predecessor | Next permitted operation |
| --- | --- | --- |
| 0 | None | `broker.py` |
| 1 | `broker.py` | `broker_https_ingress.py` |
| 2 | Both preceding modules | `broker_integration.py` |
| 3 | All three broker modules | Executor `reviewed_commit` |
| 4 | Prior three modules and executor config | Broker `reviewed_commit` **and** `expected_workflow_sha` |
| 5 | All five publications | Complete; no further stage permitted |

All three changed broker module blobs must exactly match the approved C34E
source bytes, and the other 38 protected modules must remain unchanged.
The final source seal embeds the exact *separately approved merged protected
main commit*, **not** the historical draft commit.

The protected backup directory must contain exactly five root-private,
single-link mode-0600 original backups. All five are revalidated in every
recovery inspection, even if earlier published files no longer match the
original versions. No incomplete backup cohort is acceptable.

## Read-only qualification algorithm

`inspect_c34o_six_prefix_candidate()` accepts one pre-opened source root
descriptor, a separate private-backup descriptor, a verified prospective
C34I merged-main authority, and exactly five original/target byte pairs.

1. Compare all ten byte payload SHA-256 values against *independently
   derived* C34I Git/config digests. Caller-supplied labels cannot redefine
   the permitted content.
2. Open the four **fixed** application/module/executor/broker directory
   chains under the supplied root descriptor using C34N no-follow traversal,
   checking all ancestor/leaf ownership and mode identities.
3. Read canonical `executor.json` and `dev.json` through bounded C34J
   descriptor reads, reject duplicate/noncanonical JSON, and construct
   strictly typed config objects.
4. Let C34M hash every allowed installed application file and identify at
   most one approved pending C34J stage across the application/config trees.
5. Use C34K/C34L to reread all five backups and classify the 41-file and
   dual-config state against the *six exact C34I ordered prefixes*.
6. Check any staged file name, owner/group/mode, full-or-partial bytes and
   expected next phase against the separately verified target payload;
   phase 5 rejects all pending stages.
7. Re-read both configs, check directory and backup-FD metadata, and
   repeat the entire inspection. Only exactly equal prefix and stage
   fingerprints across both passes return a receipt.

The returned `C34ORecoveryObservation` reports only prefix (0–5), fixed
next operation, target SHA, 41 protected files, complete backup state and
whether one valid stage is pending. It hardcodes
`recovery_authorized=False`; caller-created positive receipts are rejected.
Any mismatch produces one fixed error without exposing source bytes,
configuration contents, private paths or secrets.

## Isolated acceptance and limitations

Synthetic tests use all 41 actual predecessor Git source blobs and
prospective C34E broker bytes, with a **synthetic final-main SHA**,
canonical executor/broker config objects, and five durable-style private
original backups. A disposable nonroot directory tree mirrors the exact
`/opt/omnilyzer/deployment/app` and `/etc/omnilyzer/deployment/{dev,broker}`
layout beneath a temporary *fake filesystem root*. Source/config state is
read using real descriptor operations and advanced with existing C34J
atomic-file mechanics **only within the synthetic tree**.

Tests cover all six forward prefixes, reverse *state recognition* using
sandbox-only restores (not a rollback writer), every pending stage, empty,
partial and corrupted stage content, absent/corrupt/partial/unlisted
backups, unexpected source files/symlinks, mixed config states, noncanonical
JSON, changed directory permissions, bad payload hashes, stage mutation
between observation passes and attempted positive authorization.

**Not proven by these tests:** root-owned backup directory provenance,
full transitive Python import sealing, trusted protected-main branch
provenance, stopped service/socket state, global deployment lock,
rootless-runtime or replay/audit preservation, actual power-loss durability,
privileged rollback, broker/executor reactivation, or a successful
GitHub promotion. Those controls are still separate mandatory dependencies.

## Remaining release blockers

- The currently running DEV broker must not be stopped on the strength of
  this review. No live inspection, root invocation or restart is authorized.
- This module imports draft Python code from a normal Git checkout.
  **Never invoke it as root from that unprivileged checkout.** Future root
  execution requires an independently verified root-owned immutable
  package containing the entire transitive import closure, with approved
  source/byte provenance and strict ownership/modes.
- A future trusted root adapter must establish and retain the exclusive
  lock, stopped units, canonical source/config fd lineage and backup
  directory, and independently verify the exact final protected-main
  commit and closed source payload before and after each prefix.
- C34O does not write, remove or roll back anything. The root-owned
  write/rollback and reactivation controller requires separate
  implementation, privileged isolated acceptance and explicit user approval.

Protected `main` stays at the C34D SHA; PR #190 remains DRAFT and
Issue #182 OPEN. The prior HTTP 403 is not yet explained or resolved.
