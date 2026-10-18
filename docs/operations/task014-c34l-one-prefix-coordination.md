<!--
File: docs/operations/task014-c34l-one-prefix-coordination.md
Purpose: Describe the read-only C34L integration of exact merged-main
source/config prefix evidence, all-five original backup qualification and
the non-authorizing next-step contract.
Related: deployment/c34l_one_prefix_coordinator.py,
deployment/tests/test_c34l_one_prefix_coordinator.py,
deployment/c34i_merged_migration_authority.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/c34k_five_file_backup_barrier.py,
docs/operations/task014-c34i-host-transition-gates.md,
docs/operations/task014-c34j-atomic-file-mechanics.md,
docs/operations/task014-c34k-five-file-backup-barrier.md,
Task 014 issue #182 and draft PR #190.
-->

# C34L — protected five-file one-prefix coordination

**State: review-only; no live host installer, service restart or promotion.**

## Why this exists

The previous parts of the migration were individually verified but not
connected:

- C34I classifies **all 41 protected application file SHA-256 values** and
  the **two complete canonical configurations** into one of six permitted
  stages, bound to an independently reviewed *final protected main SHA*.
- C34J publishes exactly one original-backed, staged/atomic file.
- C34K requires a complete, privately sealed and byte-rechecked set of the
  five **original predecessor backups**.

C34L's `prepare_c34l_one_prefix()` binds these facts into an exact,
bounded, **non-authorizing** next-step receipt. It has no source-file writer
or service/host locator and cannot authorize live activation.

## Invariants and data ownership

The input is a C34I immutable prospective final-main authority, one full
41-file digest observation, the two fully validated typed configuration
objects, five ordered predecessor source identities and descriptor references,
and one closed backup directory descriptor. The authority, not an untrusted
source argument, provides each original and target SHA-256:

1. The original/target blob digests for each of the three broker modules.
2. SHA-256 over the original/target canonical executor configuration bytes.
3. SHA-256 over the original/target canonical broker configuration bytes,
   where the broker's final `reviewed_commit` **and**
   `expected_workflow_sha` match the verified protected-main revision.

The input source list must exactly equal five ordered basenames with
approved C34J file identities; each original byte payload and target hash
must match its corresponding C34I reference. No caller-selected paths,
sixth role or alternative backup mapping are accepted.

Next, C34L invokes the read-only C34K
`require_complete_original_backups()` gate to re-read **all five**
private root-style backups and detect any missing, linked, corrupted,
misnamed or otherwise noncanonical file. Only then may C34I classify
the **complete 41-file source state and both configs**. An invalid/mixed
prefix returns one fixed error; it cannot be interpreted as an invitation
to repair or skip steps.

The output contains only the current migration prefix (0–5), the one
expected next operation and basename, the original and target SHA-256,
the target final-main commit, and `all_five_backups_verified=True`.
At phase 5 it reports `complete`, with no next destination. Every
receipt has `live_authorization=False` and rejects forged positive values.

## Isolated end-to-end acceptance

The C34L tests construct a disposable nonroot filesystem containing **all
41 real predecessor Git blobs** and two synthetic valid canonical
configurations. They seal all five original backups using C34K, verify a
C34L plan, exercise C34J's real descriptor-scoped atomic single-file
publication **inside that isolated directory only**, and rebuild a complete
41-file/config observation after each of the five allowed steps.

Negative acceptance refuses:
- the fifth missing/corrupt backup at any prefix;
- a source/config revision changed out of order;
- unrelated protected file-content drift;
- a substituted original/target SHA or reordered source role;
- forged live-approval and arbitrary target basename.

A half-written **synthetic** C34J stage may be resumed without advancing
the C34I prefix prematurely. None of these tests uses root, real /opt or
/etc, Docker, the network, JWTs, or live deployment credentials.

## What C34L emphatically does *not* establish

**A complete root-controlled migration orchestrator remains missing.**
The C34L call receives observations from its caller; it does not prove the
underlying descriptor lineage or GitHub protected-main provenance. A
future privileged adapter must hold the existing exclusive host process
lock, confirm all three stopped service/socket units and preserved rootless
runtime/replay/audit, and perform the actual no-follow 41-file/config
scan immediately before and after each operation. It must also verify
the approved merged-main Git identity and manifest, root-owned backup
directory and five original sources, stage-prefix recovery, and redacted
operator receipt, with independently tested restart/rollback paths.

A successful C34L receipt is **not** a file-publication capability and
must not be passed directly to a live C34J writer without those root-only
requirements. The C34I stopped-host gate remains
`migration_ready=False`. PR #190 stays draft. Protected `main` is
intentionally not changed. Incident #182 remains open.
