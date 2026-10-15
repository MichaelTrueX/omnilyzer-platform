<!--
File: docs/operations/task014-c34q-python-runtime-compatibility.md
Purpose: Reconcile proposed Task 014 C34O Python imports with the established
C24/C27/C31A/C31P/C32H Python interpreter, wheelhouse and Sigstore authority
without asserting that installed root runtime has been qualified.
Related: deployment/c34q_python_runtime_compatibility.py,
deployment/tests/test_c34q_python_runtime_compatibility.py,
deployment/c34p_dependency_source_closure.py,
deployment/installation_integrity_contract.py,
deployment/python_interpreter_provenance.py,
deployment/python_environment_qualification.py,
deployment/wheelhouse_qualification.py,
deployment/pip_installer_provenance.py,
deployment/sigstore_authority_provenance.py,
docs/operations/task014-c34p-transitive-python-provenance.md,
Task 014 draft PR #190, issue #182.
-->

# Task 014 C34Q — existing Python runtime requirements reconciliation

**REVIEW ONLY. This is NOT a host or root-execution qualification.**

## Key finding

C34P's transitive static analysis of the candidate C34O recovery reader
found **73 local deployment Python files**, including the package
initializer, and one top-level non-stdlib import:
`cryptography`, reached through `deployment/jwks.py`.

The package is **not unknown to Omnilyzer's existing provenance
architecture**. The established C24 dependency-lock and wheelhouse
requirements already include the following exact closure:

| Distribution | Locked version | Existing wheel/manifest authority |
| --- | --- | --- |
| PyJWT | 2.13.0 | C24, C31A |
| cryptography | 50.0.1 | C24, C31A |
| cffi | 2.1.1 | C24, C31A |
| pycparser | 3.0 | C24, C31A |

The exact wheel filenames and SHA-256 values are already defined in
`deployment/installation_integrity_contract.py`. The original dependency
lock is `deployment/requirements-linux-x86_64-py312.lock` with
SHA-256 `13c7b3f0050f9aff0a94ab324a66276638f8b1b9dd0c62232ec205b24d874d0d`.
Four wheels are mandatory and unreviewed extra wheels, source builds
and network installation are disallowed.

Existing C27 interpreter evidence is fixed to CPython 3.12 on
Ubuntu 24.04 Linux x86-64 with glibc. C31A defines a fixed populated
`/opt/omnilyzer/deployment/venv` file-tree manifest and the four exact
installed distribution identities. C31P retains the pinned pip installer
authority, and C32H defines the Sigstore trust/toolchain provenance.

## What the new C34Q code actually checks

`qualify_c34q_runtime_requirements()` is a **pure/read-only requirements
reconciliation**, not a host probe. It accepts a candidate Git commit,
a byte-only Git object reader and a canonical typed executor configuration
whose `reviewed_commit` must be that same candidate SHA.

It reconstructs a C24 installation-integrity requirement for that
candidate, checks its closed exact four-wheel and no-network/no-source
build policy, invokes C34P to traverse all 73 local source blobs, and
requires exactly one non-stdlib top-level import root, `cryptography`.
It reads the exact C24 locked dependency file bytes from the same
candidate Git object source, checks SHA-256 and four wheel-hash records,
and revalidates existing C27/C31A/C31P/C32H immutable models.
It reconciles the fixed installed distribution **requirements** with
the wheel closure and Python version/platform.

The receipt records only SHA-256 provenance, immutable requirements,
source count and unresolved imports. Importantly, it hardcodes
`installed_runtime_qualified=False` and
`root_execution_approved=False`. Any attempt to change those fields
on a receipt is rejected.

C34Q does **not** import C34O's 73-file source closure, execute
`cryptography`, read installed files or trust a mutable checkout as a
protected GitHub branch. A self-consistent local Git object source is
not independently authenticated by this module.

## Verified scope and next required evidence

Tests use immutable local Git blob reads with lazy fetching disabled;
they exercise exact reconciliation, corrupted lock bytes, missing
transitive source, new or removed third-party imports, wheel requirement
drift, mismatched executor reviewed commit, and forged host/root approval.
The tests execute in CI and an isolated `omnigpt` checkout, not as root.

A root-owned immutable executable package remains **HOLD** until a
separate independently reviewed deployment controller proves:

1. The candidate SHA is the final independently approved protected
   GitHub `main` revision, not this unmerged draft commit.
2. The complete C34P import graph is securely sealed and installed to
   a root-owned read-only path, with reviewed Python module loading,
   no writable `sys.path`, `PYTHONPATH`, user-site or untrusted plugin
   directories. Static AST analysis alone does not prove dynamic/native
   import safety.
3. The actual pinned CPython executable, Ubuntu interpreter archive,
   native libraries and exact C24 wheels are checked on the **intended
   root execution environment** by the existing qualified readers.
4. The existing C31A populated virtualenv file-tree evidence and its
   file-level SHA-256, owner/mode and symlink controls pass on that
   exact host or a separately approved isolated root acceptance clone.
5. Root-owned backup, six-prefix recovery, stopped-service
   control, replay/audit continuity, root rollback and service restart
   tests are independently reviewed before deployment approval.

**Do not reinstall packages, create a new Python environment, alter
`/opt`, change production services or run untrusted draft Python as
root.** Continue to reuse the existing C24/C27/C31/C32 provenance model
and promote no new runtime authority without independent approval.
PR #190 remains DRAFT; Issue #182 remains OPEN, and the original 403
root cause remains unresolved.
