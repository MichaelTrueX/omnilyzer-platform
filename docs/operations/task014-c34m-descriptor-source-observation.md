<!--
File: docs/operations/task014-c34m-descriptor-source-observation.md
Purpose: Review-only observation contract for the complete protected 41-file
installed source set, two canonical configuration staging directories,
and exact pending C34J one-step recovery.
Related: deployment/c34m_descriptor_source_observation.py,
deployment/tests/test_c34m_descriptor_source_observation.py,
deployment/c34l_one_prefix_coordinator.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/c34k_five_file_backup_barrier.py,
deployment/c34i_merged_migration_authority.py,
docs/operations/task014-c34l-one-prefix-coordination.md,
Task 014 incident #182 and draft PR #190.
-->

# Task 014 C34M — descriptor-scoped installed-source observation

**REVIEW ONLY — no root migration, no live host access, no activation.**

## What was missing

C34L can prove that a complete set of 41 application hashes and two
canonical configurations matches exactly one six-phase C34I transition,
provided its observations come from a trusted source. It did **not**
acquire or validate the descriptors used to produce those 41 hashes.

The next step is to independently inspect the installed source under a
reviewed maintenance boundary, refusing any unlisted path or unexpected
stage. C34M provides only the **read-only descriptor-scoped source
observer** needed for that adapter.

## C34M source-scanning constraints

`observe_c34m_closed_generation()` takes already-open directory
descriptors for the application and both root-owned canonical config
directories, plus explicitly validated ownership/group identities.

The implementation:

1. Revalidates the exact existing 41-file `DevApplicationSourceSet`
   and its frozen C34F relative-path allowlist digest.
2. Traverses the complete application filesystem using `O_NOFOLLOW`
   directory descriptors; rechecks owner, group, mode and pre/post
   metadata identity; rejects symlinks, hardlinks, missing files,
   unexpected files/directories, and unauthorized directory modes.
3. Reads each installed regular file through the existing bounded C34J
   no-follow reader and returns only SHA-256 digests in canonical order.
4. Detects only the exact three allowed broker-module C34J stage names
   plus the two allowed canonical configuration stage names. There may
   be **at most one** stage across the entire source/config transition.
5. Does not return configuration or source-file bytes, credentials,
   arbitrary pathnames or a writable host file descriptor.

The resulting observation is **not** sufficient on its own for a host
publication: it has no final-main authority, completed migration phase,
exclusive lock, stopped-service evidence or deployment permission.

## Stage-prefix verification

After the complete source/config state is independently classified by
C34I, `attest_c34m_next_stage()` may read only that phase's exact stage
basename. It refuses stages for earlier/later operations, a stage after
phase 5, any symlink, hardlink or wrong mode/GID. For a valid stage, the
actual bytes must be an exact prefix of the approved target bytes.

A stage immediately after `O_CREAT|O_EXCL` may be zero bytes; a fully
staged target must match the full reviewed bytes and canonical final
mode. The root-only initial mode-0600 configuration stage may
temporarily have group root before the existing C34J alignment step.
No stage is silently removed or rewritten by the C34M reader.

The approved target bytes must be sourced from the final merged-main
Git manifest or canonical configuration source authority. Caller-supplied
test values do not constitute that evidence.

## Acceptance and remaining HOLD

Synthetic tests exercise all 41 file reads, symlink/hardlink/unlisted-file
rejection, incorrect directory mode, missing source files, all five
interrupted stage names, empty/partial/full stage handling, unexpected
stage bytes and attempts to forge multiple or out-of-order stages.
The tests operate only on a disposable **nonroot** sandbox; they have no
contact with installed /opt or /etc data.

**The complete root-controlled C34M host adapter remains unimplemented.**
It must first acquire and retain the root-only chain of trusted source,
executor and broker configuration directory descriptors, hold the
pre-existing exclusive deployment lock, verify all units and socket
inactive, preserve rootless runtime and replay/audit continuity, and
obtain the approved final protected-main SHA. It must reconcile
C34M's descriptor-derived hashes with C34I/C34L after securely loading
both complete canonical configs and reverify the snapshot immediately
before and after every C34J atomic publication. A tested root-owned
backup and recovery/rollback procedure is required before any restart.

No code in C34M can stop/start services, delete stages, open production
network sockets, write files or dispatch a promotion. C34I and C34L
continue to return `migration_ready=False` and
`live_authorization=False`, respectively.

**Do not merge draft PR #190, alter the installed broker or retry
GitHub promotion on the strength of this observer.** Incident #182
remains open.
