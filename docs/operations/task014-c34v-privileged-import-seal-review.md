# Task 014 C34V - Privileged Import Seal and Dynamic Loading Requirements

**File:** docs/operations/task014-c34v-privileged-import-seal-review.md

**Purpose:** Review the proposed C34O Python source closure, identify obvious unsafe dynamic loading paths, and specify how a future immutable root-owned package would be accepted without implementing privileged execution.

**Related:** deployment/tests/test_c34v_privileged_import_seal.py; deployment/c34p_dependency_source_closure.py; deployment/host_service_layout.py; deployment/python_environment_qualification.py; deployment/tests/test_c34u_signed_external_native_provenance.py; deployment/c34o_six_prefix_recovery_inspection.py; .github/workflows/task014-c34d-review.yml; docs/operations/task014-c34p-transitive-python-provenance.md; draft PR #190; Issue #182.

## Decision and interpretation

**C34V static source/import review: PASS (review only). Actual root-owned source and runtime seal: NOT IMPLEMENTED. Dynamic library-loading closure: NOT VERIFIED. Privileged execution: HOLD.**

No production module, installer, new source directory, system service, privileged runner, token handling, route, configuration or session design is introduced. The reviewed source files are read from immutable candidate Git blobs and parsed as Python AST; the inspected modules are never imported or executed.

C34V builds on existing C34P source closure analysis and C34U signed native provenance instead of creating competing package or signing infrastructure.

## Source evidence - October 15, 2026

Initial source baseline: draft PR #190 HEAD a3a9e0b88df79cf3ba8cf4760bc1945cce0c8553; protected main 57919c3b9aca0cb98e85bbb26460f6267d093fa9. Nonprivileged audit user: omnigpt, omnilyzerdev. Git lazy object retrieval disabled during the test.

| Review evidence | Observation |
| --- | --- |
| C34P transitive local Python imports | 73 reviewed Git-blob source files |
| Unresolved third-party Python imports | cryptography only |
| Explicit SQLite extension-enable toggles | 3, all literal False |
| Explicit direct dynamic import or loader calls | None found by C34V targeted AST scan |
| Explicit sys.path/sys.meta_path/sys.path_hooks mutations | None found by targeted AST scan |
| Independent signed static native library provenance | 14 external packages and 19 native targets, verified by C34U |
| Installed root-owned complete C34O package seal | Not implemented or approved |
| Original broker 403 | Open, not resolved |

The three source calls appear in deployment/replay_sqlite.py (two) and deployment/dev_persistent_state_prerequisites.py (one), all disable extension loading. Synthetic negative tests reject True, dynamically derived values, integer 0, suspicious imported loaders, direct calls and path mutation. This AST analysis is inherently incomplete for reflection, native code and configuration-driven plugins.

The C34P graph conservatively includes imports behind conditions and is not a proof that all 73 modules execute or are safe under root.

## Existing path structure to reuse

Keep the already-reviewed C21/C23 host layout without inventing another directory scheme:

- Installation root: /opt/omnilyzer/deployment
- Application root: /opt/omnilyzer/deployment/app
- Python virtualenv: /opt/omnilyzer/deployment/venv
- Python executable: /opt/omnilyzer/deployment/venv/bin/python

These are known **contract values**, not a statement that the C34O recovery inspector is installed or authorized there. Root must never import Python from the omnigpt source checkout, mutable current working directory, relative Python path, or user site.

## Proposed future immutable root-execution acceptance requirements

The following are requirements for a **separate, later approval**, not C34V implementation claims:

1. Independently attest an approved protected GitHub main commit and the exact blobs of all 73 reachable source files. Recompute the C34P candidate-SHA-bound manifest when that main revision becomes final. A draft hash cannot authorize privileged execution.
2. Construct a package from only independently authenticated blobs and exact reviewed wheel artifacts. Seal every file and source directory using C23 root owner/group/mode, descriptor-based no-symlink constraints, trusted parent directories, count/hash equality, and a no-extra-file policy. Protect against mutable .py, pyc, __pycache__, native module substitutions, symlink swaps and time-of-check/time-of-use races.
3. Verify the existing C27/C29/C34S interpreter and standard-library bytes, C31A virtualenv, exact wheelhouse and C34U signed external library scope as prerequisites. Those checks are not themselves root-safe execution authorization.
4. Define and independently approve a closed privileged Python import/search environment: exact sys.path and sys.meta_path policy, verified standard-library and app/cryptography module origins, no user site, current directory imports, unreviewed .pth, sitecustomize, usercustomize, path hooks or uncontrolled entrypoints. Ensure the verifier and launcher itself are independently root-owned and sealed before executing anything.
5. Potential Python -I -S isolation **requires a separate bootstrap design** because in Python 3.12 -S disables normal site processing and may prevent the existing cryptography wheel from being found. It is not acceptable to simply change the existing executor service command and assume the current app, routes and imports still work. No alternate runtime folder should be introduced without a verified need.
6. Before any privilege transition, use a reviewed, fixed environment with at minimum the C34V hazardous set absent: LD_AUDIT, LD_DEBUG, LD_LIBRARY_PATH, LD_ORIGIN_PATH, LD_PRELOAD, PYTHONBREAKPOINT, PYTHONHOME, PYTHONINSPECT, PYTHONPATH, PYTHONSTARTUP, PYTHONUSERBASE. Also independently review other LD_* and PYTHON* variables, inherited file descriptors, current working directory, subprocess environment, locale and Linux dynamic loader behavior; this eleven-variable set is a minimum, not a complete sandbox.
7. Separately test dynamically resolved modules not covered by ELF DT_NEEDED: ctypes, dlopen, NSS, OpenSSL provider configuration, cryptography backend, SQLite extensions, lazy Python imports and future plugin/import mechanisms. Static C34P/C34V analysis cannot establish an exhaustive runtime loading closure, even when it returns no obvious findings.
8. Use a separate, preapproved root-only immutable source observer and approved recovery coordinator. Do not execute the draft C34V audit or C34O modules as root to establish their own trust. Root-only config validity, exclusive stopped-service lock, backup integrity, crash/rollback acceptance, final protected-main SHA, rootless runtime and replay/audit continuity remain independent required controls.

## Requirements-to-implementation traceability

| Requirement | Evidence | Status |
| --- | --- | --- |
| C34V-01 Enumerate all reviewed transitive local imports | Existing C34P Git-blob closure reused | Verified, review-only |
| C34V-02 Reject explicit dangerous dynamic loader and path changes | New targeted AST and negative tests | Verified for syntactic cases |
| C34V-03 SQLite native extension loading disabled | Three literal False calls; negative tests | Verified for reviewed sources |
| C34V-04 Preserve existing app/venv paths | Existing host_service_layout checked | Verified contract only |
| C34V-05 Never infer privileged root authority | Frozen C34VReviewReceipt, four permanent False authority flags | Implemented and verified |
| C34V-06 Authenticated immutable root-owned 73-source package | Architecture requirements only | Proposed, NOT implemented |
| C34V-07 Closed dynamic native and Python module runtime | Architecture requirements only | Proposed, NOT verified |
| C34V-08 Privileged backup/recovery/restart acceptance | Prior C34I-C34O controls unchanged | BLOCKED |
| C34V-09 Original broker HTTP 403 | Issue #182 investigation | OPEN |

Status terms: proposed = requirements without implementation; implemented = draft code exists; verified = specific evidence/tests passed; released = approved and promoted. Only the **review tool** is implemented and verified in C34V. Neither C34V nor the Task 014 migration is released or authorized for root use.

## Reproduction and acceptance evidence

Run the complete C34V source-only review without touching host installations or root-owned configurations:

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    python3 -m unittest -v deployment.tests.test_c34v_privileged_import_seal

This audits Git blobs of the exact current candidate commit using git cat-file with GIT_NO_LAZY_FETCH=1, checks the C34P closure and performs targeted AST syntactic review. It does not execute inspected source. The receipt holds protected_main_attested, actual_root_owned_seal_verified, dynamic_loading_closed and root_execution_approved as always False.

## Handover and remaining blockers

Recommended subsequent review-only C34W: assess actual closed dynamic-loading policy and feasibility of reusing the existing root-owned app/venv package for a separately sealed recovery inspector. This needs independently verified protected main, complete approved source package, safely configured Python module and native-library search, sealed verifier/toolchain, and separate privileged stopped-host recovery testing.

Preserve the original token validation, OIDC separation, in-memory sessions, replay/audit persistence, C34K original backups, C34O six-prefix recovery invariants and all existing service routes. Do not change the current production architecture until required acceptance has been reviewed and explicitly approved.

**HOLD:** PR #190 remains draft, Issue #182 remains open. Do not merge, deploy, install root-owned C34O source, invoke draft code as root, stop/restart units, modify permissions or secrets, rotate workflow authorization or retry promotion.
