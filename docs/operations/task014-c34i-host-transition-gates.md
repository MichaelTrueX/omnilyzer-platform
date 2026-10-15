<!--
File: docs/operations/task014-c34i-host-transition-gates.md
Purpose: Define the reviewed stopped-host qualification and final-main source
seal required before Task 014 five-file migration can become deployable.
Related: deployment/c34i_stopped_host_gate.py,
deployment/c34i_final_main_seal.py,
deployment/c34g_migration_authority.py,
deployment/c34g_installed_predecessor_preflight.py,
deployment/state_store_successor_host_migration_runtime.py,
deployment/tests/test_c34i_stopped_host_gate.py,
deployment/tests/test_c34i_final_main_seal.py,
GitHub issue #182, draft PR #190.
-->

# Task 014 C34I — root transition safety boundary

**Review-only release candidate. No deployment, service stop, SHA rotation or
workflow dispatch is approved or performed.**

## What passed on the installed host

The operator executed the exact, SHA-256-verified C34G read-only installed
predecessor checker and received:

```text
C34G_PREFLIGHT_PASS source_41_exact config_pair_canonical workflow_pin_c34d services_unchanged
C34G_NO_MUTATION_NO_DEPLOYMENT
```

This confirms the live source set and canonical config *at the time of the
inspection*, while broker/exec socket were still operating in their normal
running state. It does not certify a safe stopped-service migration.

## C34I stopped-host qualifier

`deployment/c34i_stopped_host_gate.py` adds a **root-only, read-only**
qualification under the existing deployment process lock. It requires:

1. Real/effective UID and GID root, no unprivileged impersonation.
2. The existing C33AE environment probes show the broker and executor
   socket/service are in their **expected stopped states**, not merely that
   a systemctl stop was requested.
3. Rootless runtime identity and process signatures remain stable.
4. The actual 41 installed files pass the C34G exact source checker,
   including no extra source files, unauthorized changed bytes, modes or links.
5. Root-controlled canonical executor and broker readers independently
   verify the predecessor `reviewed_commit`, C34D
   `expected_workflow_sha`, and shared runtime/ingress authority.
6. All root/config/source/unit/runtime observations are repeated under the
   same exclusive lock before returning a bounded receipt.

The receipt intentionally includes `migration_ready=False`: it establishes
environmental prerequisites, **never grants file-write permission**.
No callable host installer or systemd transition is exported by this module.
It must not be invoked on the running DEV host until a separately authorized
maintenance window has stopped the required units; otherwise it is expected
to refuse.

## C34I final-main source seal

`deployment/c34i_final_main_seal.py` resolves a release-authority issue
present in earlier C34F/G proposals: the draft source commit
`9289bbc59533e94917ab423a7d29018d011a14a8` is **not** the eventual
protected `main` merge commit, and source manifest canonical bytes embed
the exact `reviewed_commit`.

When a merge is independently approved and the final `main` SHA is known,
`prepare_c34i_final_main_source_seal(independently_reviewed_main_sha=...)`
will re-read all **41 immutable Git objects**, reject unexpected source
changes, prove the three modified broker bytes match the already-reviewed
C34E blobs and derive the full canonical manifest SHA-256 for the *actual*
merged commit. It rejects all historical/draft SHAs.

The seal's `approval_granted` is intentionally fixed to `False`.
Only a separate, independently reviewed release authority, verified branch
provenance and operator-approved root install package could advance to
activation. A SHA that happens to have the right contents is insufficient:
GitHub protected-main identity and trust must be verified outside this
pure Git-object helper.

**Important downstream incompatibility:** the existing C34G
`C34GMigrationAuthority` and C34H sandbox deliberately still require
`C34E_PROPOSAL` as their exact target SHA. They cannot be reused with a
different merged `main` revision just because the three broker blobs match.
Before building/enabling a root writer, a separately reviewed successor
authority must bind the new seal, its computed 41-file manifest and the
same five exact source/config transitions. That authority must fail closed
on any other proposed revision, stage drift or source/config mismatch.
Do not substitute a different commit into C34G by monkeypatching constants.

## Remaining, explicit implementation work

A root-capable **five-file writer has NOT yet been enabled**. Its future
implementation must reuse the project's established no-follow descriptor
chain, source-set verifier, bounded stage-prefix validator, process lock,
fsync/atomic-rename method and fixed service/identity checks. It must also
add independent root-owned backup creation/verification and interrupted-write
recovery at every filesystem prefix, tested in a disposable root-owned
acceptance environment. No trust-boundary widening or manual copies into
`/opt/omnilyzer/deployment/app` are acceptable.

After a final-main merge, all five intended publications must be bound to
that exact SHA: three protected Python module files, executor canonical
`reviewed_commit`, broker canonical `reviewed_commit`. The unchanged
C34D `expected_workflow_sha` remains separately root-authorized; neither
this module nor a source merge rotates it.

**Important:** Do not merge draft PR #190 into `main`, stop DEV services,
perform a migration, reset replay/audit, dispatch GitHub Actions or activate
a canary solely on the strength of these new C34I checks. Incident #182
remains open until the actual HTTP 403 root cause is established.
