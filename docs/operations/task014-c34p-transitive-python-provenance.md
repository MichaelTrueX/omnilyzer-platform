<!--
File: docs/operations/task014-c34p-transitive-python-provenance.md
Purpose: Review C34O/C34N Python transitive import closure and root-owned
sealed-package requirements before any Task 014 privileged migration.
Related: deployment/c34p_dependency_source_closure.py,
deployment/tests/test_c34p_dependency_source_closure.py,
deployment/c34o_six_prefix_recovery_inspection.py,
deployment/c34n_root_predecessor_adapter.py,
deployment/c34i_final_main_seal.py,
docs/operations/task014-c34o-six-prefix-recovery-inspection.md,
draft PR #190 and incident Issue #182.
-->

# Task 014 C34P — immutable Python import provenance

**REVIEW ONLY. No package installation, root code execution, service action,
merge, workflow SHA rotation or DEV promotion.**

## Finding — transitive Python closure is not the five-file migration

The exact existing C34O root-side recovery inspector imports supporting
deployment modules. A static AST traversal of the reviewed candidate's
immutable Git objects reaches **73 local Python source files** (the package
initializer and 72 import-reachable deployment modules), not merely the
new C34O, C34N and C34M sources.

It also reaches at least one non-stdlib Python top-level dependency:
`cryptography`, through `deployment/jwks.py`. This package, its native
wheels/OpenSSL dependencies, and the specific Python interpreter must be
reviewed under existing provisioning authority. The mere presence of
`cryptography` on the unprivileged development host is **not** an
approved root environment or proof of package provenance.

## What C34P implements

`inspect_c34p_git_blob_closure(candidate_sha, blob_reader)` is a
read-only static source auditor. It:

1. Starts at exactly `deployment/c34o_six_prefix_recovery_inspection.py`
   and `deployment/__init__.py`. Only source paths within the flat
   `deployment/*.py` package are considered.
2. Parses immutable candidate Git blob bytes using Python AST **without
   importing or executing any inspected module**.
3. Traverses all reachable local imports, including those in conditional
   blocks, with cycle detection and a 192-module bound.
4. Rejects unresolvable or nested relative imports, wildcard imports,
   dangerous explicit dynamic import/execution calls, missing Git objects,
   invalid Python syntax, oversized blobs and unexpected import patterns.
5. Checks that every collected source object still has the identical
   SHA-256 content when fetched for a second time.
6. Distinguishes a finite reviewed allowlist of standard-library top-level
   names from unresolved third-party names.
7. Produces a deterministic candidate-SHA-bound source manifest digest
   over every sorted local relative path plus its SHA-256 and dependency
   classifications.

`C34PSourceClosureReceipt.root_execution_approved` is **always False**,
including when no third-party dependencies are detected. The helper
consumes a blob-reader callback: this audit cannot prove on its own that
the callback accessed a genuine protected GitHub main commit, or that a
Python install/interpreter was assembled from reviewed sources.

The C34P audit source and its own tests are **separate review tooling**;
they are not part of C34O's 73-source runtime import closure. A later
root-package builder must define exactly which runtime entrypoints will
be shipped and include their package initializer and full import closure.

## Evidence at the reviewed candidate

A non-root Git blob scan of candidate
`854682a4e252b503a341f903ab28a9428b5b14c6` reported:

- Local transitive source modules including `deployment/__init__.py`:
  **73**
- Unresolved third-party import roots: **`cryptography`**
- Root execution approved: **False**

The manifest digest includes the exact candidate commit SHA. It changes
whenever the reviewed commit changes, even if the same 73 source bytes
remain unchanged; regenerate the receipt after the final review revision.
Do **not** interpret a draft commit's digest as an install-time source seal.

## Supply-chain/privilege controls still required

Before a final reviewed protected-main revision could be installed as
root-executable code, a separate root-owned installer package review must
establish all of the following:

- Independently verified protected GitHub `main` commit provenance and
  complete Git source-tree evidence for **every** approved local module;
  a checksum from a mutable/unprivileged checkout is not sufficient.
- Fixed Python interpreter executable, version, ABI, binary/shared-library
  provenance, standard-library installation and `sys.path` / package path.
  No user site-packages, environment-driven `PYTHONPATH`, writable path
  components or implicit import paths from the `omnigpt` Git checkout.
- Complete, frozen and verified wheelhouse for `cryptography`, including
  native ABI/platform dependencies and the existing Sigstore/wheel
  qualification standards. Resolve any additional external package that
  emerges from later source revisions.
- Root-owned package directories with exact mode/UID/GID, link restrictions
  and an immutable root-approved import graph. Scan both direct imports
  and potential runtime plugin/entrypoint/resource loading not provable by
  static AST alone. No unsafe dynamic code loading.
- Full stopped-host unit checks, exclusive deployment process lock,
  rootless-runtime and replay/audit continuity, five-original backup
  integrity, six-prefix 41-file authority, negative crash/rollback tests and
  independently approved activation of the exact final-main workflow SHA.

C34P intentionally does not make a new deployment layout, install
`cryptography`, relax permissions, rotate workflow authorization, update
sessions/tokens, or alter any protected GTM/Omnilyzer application routes.

## Limits and acceptance

This is **conservative static analysis**, not a comprehensive Python or
native dependency verifier. Obfuscated calls, reflection, configuration-
driven plugins, runtime resources, standard-library native modules and
arbitrary package setup execution must be evaluated separately before
privileged use. The 73-file result is the direct static import closure
for the current reviewed entrypoint, **not** a guarantee that 73 files
are sufficient to run privileged recovery safely.

Synthetic tests verify traversal of cyclic imports, missing/mutated
objects, syntax errors, unexpected relative/wildcard imports, explicit
dynamic imports, stable deterministic hashing and non-authorizing
receipts. The real-Git integration test reads only local candidate Git
objects, disables Git lazy object fetching, asserts the exact **73**
source files and the unresolved `cryptography` dependency, and checks
digest reproducibility. It executes no inspected source and does not
download third-party packages.

**HOLD:** PR #190 remains DRAFT and Issue #182 OPEN. The original
GitHub promotion HTTP 403 still lacks definitive root-cause evidence.
Root-owned code execution, source migration and service reactivation are
not approved by this review.
