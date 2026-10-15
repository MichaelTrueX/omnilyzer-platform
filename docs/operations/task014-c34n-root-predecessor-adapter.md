<!--
File: docs/operations/task014-c34n-root-predecessor-adapter.md
Purpose: Document the root-only, read-only stopped-host predecessor adapter,
its no-follow directory lineage, incident limitations and next acceptance.
Related: deployment/c34n_root_predecessor_adapter.py,
deployment/tests/test_c34n_root_predecessor_adapter.py,
deployment/c34m_descriptor_source_observation.py,
deployment/c34i_stopped_host_gate.py,
deployment/state_store_successor_host_migration_runtime.py,
docs/operations/task014-c34m-descriptor-source-observation.md,
Task 014 draft PR #190 and incident issue #182.
-->

# Task 014 C34N — root-only predecessor observation

**DRAFT / NOT FOR HOST EXECUTION.**

## Scope

C34N adds a fixed-path root-only reader for the **stopped**, unmodified
41-file predecessor on `omnilyzerdev`. It is specifically **not** the
one-step or five-step migration installer.

The C34G operator's earlier root-owned preflight passed against the
**running** predecessor. It does not prove that the three broker/executor
units have been stopped, or that they can restart safely after migration.
C34N must not be executed on the live machine without a separately
approved maintenance window and evidence that its stop preconditions
have been met.

## Fixed trust boundary

The only production entrypoint,
`qualify_c34n_root_predecessor()`, requires existing C33AE's
real/effective root identity, then acquires and eventually releases the
existing nonblocking exclusive deployment process lock.

Under that lock it verifies:
- C33AE's broker, executor service and executor socket **stopped** state,
  including no remaining broker/executor MainPID or executor socket;
- unchanged rootless Docker manager/runtime signatures;
- canonical broker and executor configuration objects from the existing
  root-only file readers, sharing runtime/ingress identities;
- predecessor source reviewed commit
  `176ed3a31ffcf23346639ef22ac9bcab3794f0df` and the
  existing authorized C34D workflow pin
  `57919c3b9aca0cb98e85bbb26460f6267d093fa9`.

It then opens a fixed `/` anchor, never a caller-selected root path.
Each expected component is opened relative to a retained parent
descriptor with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, compared to
the no-follow directory entry and rechecked after scanning:

| Directory | Exact role |
| --- | --- |
| `/opt/omnilyzer/deployment/app` | 41-file application root, root:root 0755 |
| `/opt/omnilyzer/deployment/app/deployment` | protected broker module directory, root:root 0755 |
| `/etc/omnilyzer/deployment/dev` | executor configuration directory, root:executor_gid 0750 |
| `/etc/omnilyzer/deployment/broker` | broker configuration directory, root:broker_gid 0750 |

Ancestors must be root-owned and non-writable by group/other.
C34M reads the complete 41-file source set through those qualified
descriptors and discovers any existing C34J stage in the app and
configuration directories. C34N admits **only** all 41 exact frozen
predecessor SHA-256 values, canonical source path ordering, and
**no pending stage**. It reads all 41 files twice, compares both root
configuration objects and the root/service/runtime snapshots, then
revalidates every parent and leaf descriptor identity.

On any failure, it closes descriptors and attempts to release the
exclusive deployment lock, returning only a fixed nonsecret HOLD error.
Even a successful evidence object hardcodes
`migration_ready=False`.

## Isolated acceptance

Unit tests create an entirely synthetic 41-file predecessor under a
disposable unprivileged directory tree. They test the complete source
snapshot and root-anchored (synthetic-anchor) directory chains, refusal
of extra files, pending stages, symlink replacement, group/world-writable
ancestors, wrong configuration modes, source hardlinks, and directory
rename after opening. Separate mocks verify exclusive-lock release,
stopped-service failure, runtime signature drift, wrong workflow SHA and
root-identity denial. Tests cannot interact with real systemd or the
installed production source.

## Mandatory remaining work

1. **No root live run is authorized.** The current broker is supposed to
   remain active. The stopped-host C34N precondition would fail today.
2. C34N knows only the pristine predecessor. A later root reader must
   recognize the six C34I **final merged-main** source/config prefixes,
   without accepting unexpected pending stages.
3. A final approved protected-main seal, secure Git source bundle,
   canonical config revisions and OIDC `workflow_sha` transition still
   require independent authority review.
4. Root-owned complete five-file backups, replay/audit continuity policy,
   stopped-unit and rootless preservation, interrupted-write recovery,
   rollback, reactivation and host-level root acceptance are not provided
   by this read-only adapter.
5. C33AE's prior `_persistent_state()` precondition expects a pristine
   audit history. That assumption must be reviewed for the current
   attempted promotion before reusing it; **do not erase or reset**
   replay/audit as an installation prerequisite.

A successful C34N check, should one eventually be authorized, is
**not** a deployment permission and does not resolve the original
HTTP 403. Keep PR #190 DRAFT, protected main unchanged, and incident
#182 OPEN.
