# Task 014 C34W - Existing Root-Owned Source Feasibility and Runtime Loader Boundary

**File:** docs/operations/task014-c34w-installed-source-feasibility.md

**Purpose:** Determine whether the existing root-owned Omnilyzer DEV application/virtualenv layout can safely carry the reviewed C34O 73-file recovery import graph, without replacing live files or inventing a new installation structure. Specify the review-only next-step architecture and preserve root execution HOLD.

**Related files:** deployment/tests/test_c34w_installed_source_feasibility.py, deployment/c34p_dependency_source_closure.py, deployment/tests/test_c34v_privileged_import_seal.py, deployment/host_service_layout.py, deployment/tests/test_c34u_signed_external_native_provenance.py, .github/workflows/task014-c34d-review.yml, docs/operations/task014-c34v-privileged-import-seal-review.md, GitHub draft PR #190 and Issue #182.

## Decision

**C34W: verified installed-source feasibility assessment, result HOLD.**

It is feasible **in principle** to reuse the existing approved host layout as a future package destination, but **the currently installed files do not meet the recovery inspector's 73-file immutable source closure**. Reusing the layout does not make the installation complete, cryptographically trusted or approved for privileged execution.

This stage performs only nonprivileged read-only host observation, deterministic tests and requirements documentation. It does **not** stage/install missing files, alter existing services, promote source, change root permissions, rewrite the Python import mechanism, make backups, or run draft Python as root.

## Exact observed evidence — omnilyzerdev, 15 October 2026

Read-only audit user: omnigpt. Source checkout: /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review, at C34V draft PR #190 HEAD 370da5b6910efc2c9d354f7505b5bb453bc58fe2. Protected main unchanged at 57919c3b9aca0cb98e85bbb26460f6267d093fa9. No merge was performed.

The C34P AST-derived blob graph is calculated from that exact draft Git revision (73 local modules, including deployment/__init__.py) with Git lazy-object fetching disabled. The test reads existing installed source as regular, root-owned 0644 files using descriptor-based O_NOFOLLOW byte hashing and repeated metadata checks. The approved C21/C23 path requirements (root-owned 0755 ancestors) were observed for the existing application and virtualenv. No inspected deployment source module was imported or executed.

| Inventory characteristic | Observation |
| --- | ---: |
| Reviewed recovery source graph | 73 Python files |
| Installed flat application package | 38 Python files |
| Names shared by both inventories | 19 |
| Shared files with exact matching SHA-256 | 18 |
| Shared file with different SHA-256 | 1 |
| Required recovery files missing | 54 |
| Existing deployed application files not in recovery graph | 19 |
| Symlinks in the reviewed immediate application source files | None accepted by descriptor audit |

The single differing shared file is **deployment/broker.py**; this is an observation, not authority to overwrite it. The missing recovery set includes **deployment/c34o_six_prefix_recovery_inspection.py** and its C34G–C34N supporting modules, along with host installation/provenance helpers. The existing 19 additional installed Python files include service startup, authentication, OIDC, ingress and executor modules. They must not be removed merely because they are not statically imported by the recovery inspector.

**Installed union estimate:** Existing 38 Python files plus 54 missing recovery files would produce **92** source names, *before* assessing the one conflicting source file and any additional runtime resources. This is only a set-size estimate, not an approved 92-file build, complete live-service closure or installation proposal.

Read-only interpreter flags were inspected with only importlib.util.find_spec, **without importing cryptography**:

| Command on existing venv interpreter | cryptography discoverable? |
| --- | --- |
| python -I | Yes |
| python -I -S | No |

Python -I does not disable all site processing; it is not proof of a sealed privileged import resolver. Python -I -S excludes normal site processing, and the existing cryptography wheel is consequently not discoverable through its standard venv configuration. Do not modify the actual executor unit to use either option until the complete runtime behavior, imports and current service requirements have been separately validated.

Actual read-only acceptance receipt:

    C34W_INSTALLED_HOLD candidate=73 installed=38 shared=19 missing=54 differing=1 surplus=19 isolated_crypto=true isolated_no_site_crypto=false root_approved=false

## Architecture conclusions

1. **Reuse existing directories rather than create a new platform hierarchy:** preserve /opt/omnilyzer/deployment/app and /opt/omnilyzer/deployment/venv as defined in the existing host_service_layout contract. No changes to paths are justified by this review.
2. **Do not replace the installed service module set with only the C34O 73-file source graph.** This would omit 19 already deployed source names, including live service modules. A future protected-main package plan must independently reconcile the service's original 38-file package, the complete recovery import graph and any associated resources. The differing broker.py requires explicit semantic/compatibility acceptance, not last-writer-wins file copying.
3. **Define an independently authorized package manifest:** cover every required existing service and recovery source plus resources, owner/group/modes, file size and SHA-256, permitted paths/ancestors, wheelhouse, native libraries, symlinks, import roots and extra-file prohibition for each explicitly approved scope. It must be built from an independently approved protected-main commit; a mutable unprivileged review branch is not an authority.
4. **Separate root-owned staging from execution:** any later installer or root verifier requires review, protected-main seal, guarded stop/lock, verified backups/rollback and an explicit authorization. Do not run this C34W nonprivileged source observer as root to establish its own trust.
5. **Do not assume -I -S is a working production solution.** An approved sealed bootstrap would need a reviewed cryptography import policy; changing normal site behavior can break unrelated existing service functionality.
6. **The signed static native closure does not prove every future runtime load.** Continue C34U's 19 static SONAME evidence but separately assess NSS dynamic modules, OpenSSL provider configuration, ctypes/dlopen, lazy imports, foreign library loaders, site/.pth path hooks and inherited env. No privileged runtime loader seal has been observed.
7. **Proposed minimum privileged environment policy:** deny LD_*, PYTHON*, OPENSSL_*, NSS_*, BASH_ENV, ENV, GCONV_PATH, IFS and LOCPATH by default. Model a minimal fixed, validated environment and explicit allowlist for any required locale/timezone or service variables. This is a proposed model only; no actual service environment was read or changed.

## Requirements-to-implementation traceability

| Requirement | Implementation / evidence | Status |
| --- | --- | --- |
| C34W-01 Verify draft PR/head/protected main identity | GitHub and local exact Git SHA checks | Verified observation; not protected-main approval |
| C34W-02 Compare C34P source closure with actual installed app | C34P reused, descriptor-based installed-source byte hashing | Implemented/verified read-only; installation HOLD |
| C34W-03 Ensure source extras and conflicts are never silently dropped | Pure comparison, negative tests and exact local receipt | Implemented/verified |
| C34W-04 Verify existing root-owned directory path conditions | Nonprivileged lstat, mode/UID/GID; no-follow file hashing | Verified observation; not a root-source seal |
| C34W-05 Assess -I and -I -S wheel discovery | Nonprivileged read-only interpreter specs, no wheel import | Verified observation; bootstrap HOLD |
| C34W-06 Model future environment-variable injection rejection | Pure synthetic closed-environment tests | Implemented/verified review model; not active runtime |
| C34W-07 Reconcile full live-service-plus-C34O source manifest | Required future design; one differing broker.py | Proposed, NOT implemented |
| C34W-08 Seal privileged launcher and complete dynamic loading | Requires independent root and runtime acceptance | NOT implemented, BLOCKED |
| C34W-09 Resolve broker HTTP 403 and authorize stopped-host recovery | Issue #182 and existing C34I–C34O gates | OPEN, BLOCKED |

Status labels: **proposed** means requirements only, **implemented** means draft tests/doc or runtime code exists, **verified** means specifically identified evidence passed, and **released** means merged, approved and activated. C34W is implemented and verified **only as review-only testing and documentation**. It is not a released root deployment.

## Reproduction

No root privileges or package changes needed for default offline tests:

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    python3 -m unittest -v deployment.tests.test_c34w_installed_source_feasibility

Explicit nonprivileged read-only installed-host audit, disabled by default in GitHub CI:

    OMNILYZER_C34W_HOST_READONLY=1 python3 -m unittest -v \
      deployment.tests.test_c34w_installed_source_feasibility.C34WActualHostReview

This audit must yield an expected HOLD receipt for the observed installed source gap. If installed counts, bytes, permissions or candidate source change, it fails closed and requires renewed review; it does not automatically accept a different installation.

## Recommended next review-only stage: C34X

Reconcile the separately verified **existing-service source manifest** with the complete proposed C34O recovery-source closure, including the single broker.py discrepancy and resources. Avoid destructive replacement or creating a second service package unless the existing controlled installation path demonstrably cannot support it. Evaluate a sealed package manifest and strictly read-only installer acceptance contract using synthetic fixtures, and separately document native dynamic-loading coverage still unresolved. Keep all service startup, OIDC, token, localStorage/session, CSP/CORS and replay/audit behavior unchanged.

Root execution and migration remain HOLD: independent protected-main SHA, complete root-owned source and Python-loader seal, original HTTP 403 diagnosis, canonical config validation, stopped-host exclusive lock, full backups and privileged recovery/rollback/restart tests plus separate authorization are still required.

**No merge, deployment, root installation, running unreviewed modules as root, permission changes, service stop/restart, OIDC rotation or promotion retry.**
