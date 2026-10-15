# Task 014 C34Z - Protected Main, Dynamic Loader and Broker Diagnostic Release Gaps

**File:** docs/operations/task014-c34z-protected-main-loader-gap.md

**Purpose:** Document bounded release-readiness evidence: compare 95 complete C34Y service/recovery source and runtime resources against historical protected main; review all 92 candidate Python sources for explicit loader patterns; identify five additional NSS/OpenSSL modules requiring independent signed payload verification; preserve unapproved C34E broker diagnostics.

**Related files:** deployment/tests/test_c34z_main_loader_release_gap.py; deployment/provenance/c34z-protected-main-gap-review.json; deployment/provenance/c34y-service-recovery-source-review.json; deployment/tests/test_c34y_service_recovery_manifest_review.py; deployment/tests/test_c34x_service_recovery_source_reconciliation.py; deployment/tests/test_c34v_privileged_import_seal.py; deployment/tests/test_c34u_signed_external_native_provenance.py; deployment/tests/test_c34e_diagnostic_events.py; .github/workflows/task014-c34d-review.yml; PR #190; Issue #182.

## Decision and scope

**C34Z scoped read-only review: VERIFIED. Protected-main source-package release: HOLD. Full runtime loader provenance: HOLD. Broker diagnostics approval: HOLD. Root execution and promotion: HOLD.**

This task creates only a small protected-main review data file, a nonprivileged test module and this documentation, and registers tests in the existing Task 014 CI. It makes NO installation, service stop/start, root execution, broker or OIDC/token policy change, host package modification, merge, permission edit or promotion attempt. None of the review observations is a root signing or installation authority.

## Protected-main source comparison — 15 October 2026

- Historical candidate: draft PR #190 commit 72c75914e307fa03105600874a10d69b0caae204, bound to the C34Y 95-entry source manifest SHA-256 d817404801ca9d7364a2aaadf0f120a19c49cb806f60692e3d8dae90de59e4a5.
- Observed protected main: 57919c3b9aca0cb98e85bbb26460f6267d093fa9; Git tree: 4a8d30bdb5827664ca650a19cd324377445f6eb4.
- New read-only historical snapshot: deployment/provenance/c34z-protected-main-gap-review.json; 15,204 bytes, SHA-256 b82fe038205c8e949135f54490d84688c20255ac9f83d14d263732bc7de3972f.
- The nonprivileged auditor compared 95 immutable Git objects in the retained main and candidate Git commits. CI validates the historical signed-off *review snapshot* and the current candidate objects. Exact Git-main-object replay is opt-in because GitHub CI uses a shallow checkout and might not contain the prior main commit.

| Comparison against protected main | Files |
| --- | ---: |
| Exact SHA-256 byte match | 81 |
| Absent from main | 11 |
| Different bytes | 3 |
| **Total** | **95** |

Missing in protected main:

- deployment/c34f_application_generation_evidence.py
- deployment/c34g_installed_predecessor_preflight.py
- deployment/c34g_migration_authority.py
- deployment/c34i_final_main_seal.py
- deployment/c34i_merged_migration_authority.py
- deployment/c34j_atomic_file_mechanics.py
- deployment/c34k_five_file_backup_barrier.py
- deployment/c34l_one_prefix_coordinator.py
- deployment/c34m_descriptor_source_observation.py
- deployment/c34n_root_predecessor_adapter.py
- deployment/c34o_six_prefix_recovery_inspection.py

Different in protected main: deployment/broker.py, deployment/broker_https_ingress.py and deployment/broker_integration.py. C34X pinned both installed and draft SHA-256 digests for these files and found equality of normalized AST only after removing the known diagnostic logger declarations and literal warning calls. This does NOT prove runtime behavioral equivalence or authorize changing OIDC, ingress 403, replay, token handling, or service code.

**Protected main does not currently contain the complete 95-file candidate package.** A release decision is blocked by 11 missing and three differing files.

## Extended 92-file Python AST loading review

C34V analyzed the 73-file recovery import closure. C34Z reuses the same syntactic detector against **all 92 candidate service-plus-recovery Python Git objects**, after rechecking individual SHA-256 and exact C34Y membership. The review found zero direct loader or import-path mutation patterns within that detector's coverage and exactly three literal SQLite enable_load_extension(False) calls.

**This result is intentionally narrow.** Static AST detection cannot exclude reflective/dynamic import, native dlopen, lazy provider loads, NSS resolution, OpenSSL external configuration, Python site processing, subprocess behavior or runtime file/path substitution. Zero detected patterns does not mean a complete privileged loader closure is proven.

## Five specifically observed external native plugin proof gaps

C34U authenticated 19 static ELF DT_NEEDED targets against 14 signed Ubuntu package groups. These other files are **not** among the 19 independently checked native target bytes:

| Candidate late-loaded module | Locally observed dpkg owner |
| --- | --- |
| /usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so | libssl3t64 |
| /usr/lib/x86_64-linux-gnu/libnss_dns.so.2 | libc6 |
| /usr/lib/x86_64-linux-gnu/libnss_files.so.2 | libc6 |
| /usr/lib/x86_64-linux-gnu/libnss_mdns_minimal.so.2 | libnss-mdns |
| /usr/lib/x86_64-linux-gnu/libnss_systemd.so.2 | libnss-systemd |

All five were observed as root-owned regular mode-0644 files, with expected dpkg owner labels. They were NOT loaded or executed. Their content hashes were NOT independently compared with signed Ubuntu .deb payloads in C34Z. Even for files owned by libssl3t64 and libc6, a C34U verification of other library target files does not authenticate these additional provider/NSS files. The two libnss-* package owners are additionally outside C34U's 14-package set.

Dynamic loader configuration can also depend on /usr/lib/ssl/openssl.cnf (symlink into /etc/ssl) and /etc/nsswitch.conf. Separate attestation of configuration, symlink/dir controls, actual provider selection and NSS lookup behavior is required before any privileged runtime acceptance.

## Broker diagnostics, privacy and controlled service changes

C34E's bounded stage logger and selected 403/503 regression tests are present in the draft review branch. C34X determined that the three differing source versions can be classified as specific diagnostic additions under six exact blob hashes, but the diagnostic behavior has not been approved for installed-service replacement. Preserve existing 202/403/503 semantics, GitHub OIDC validator, replay guard, request/response privacy, memory-based sessions and existing JSON-token/localStorage contracts. The original promotion HTTP 403 remains unresolved; diagnostics do not by themselves fix it.

## Requirements and implementation acceptance traceability

| ID | Required result | Source evidence | Status |
| --- | --- | --- | --- |
| C34Z-01 | Review complete candidate vs protected-main provenance | Exact 95-path snapshot, preserved main commit/tree and optional Git-object replay | Implemented, review verified |
| C34Z-02 | Identify missing/different release inputs | 81 matches, 11 absent, 3 different | Verified blockers, HOLD |
| C34Z-03 | Review whole union for explicit dynamic imports/loaders | AST review of 92 source Git blobs, three disabled SQLite extension calls | Verified **syntactic subset** only |
| C34Z-04 | Locate additional NSS/OpenSSL native-loading proof gaps | Five exact modules, nonprivileged owner/mode and package label observation | Verified metadata; signed byte provenance NOT verified |
| C34Z-05 | Preserve broker diagnostic approval boundary | Three pinned divergent modules, existing C34E tests | Verified observation, approval NOT granted |
| C34Z-06 | Approve protected main and root-owned import package | Main lacks 11 required files, three source differences; root-owned package not installed | Proposed, NOT approved |
| C34Z-07 | Close privileged loading and operational recovery gates | C34U/V/W/X/Y and original C34I-O safety requirements | OPEN/HOLD |

Status definitions: proposed means design only; approved requires explicit independent authorization; implemented means review code and evidence exist; verified means specified tests pass; released means accepted and deployed. This stage is implemented/verified strictly as **review**, not approved/released for root operation.

## Reproduction (nonprivileged)

Default CI-safe test, with no main history fetch or installed native reads:

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    umask 0022
    python3 -m unittest -v deployment.tests.test_c34z_main_loader_release_gap

Optional retained main-object replay, no network:

    C34Z_MAIN_GIT_READONLY=1 python3 -m unittest -v \
      deployment.tests.test_c34z_main_loader_release_gap.C34ZMainObjectReplay

Optional native plugin metadata only, no loading or code execution:

    C34Z_DYNAMIC_HOST_READONLY=1 python3 -m unittest -v \
      deployment.tests.test_c34z_main_loader_release_gap.C34ZNativeMetadataReplay

Expected receipts:

    C34Z_REVIEW_HOLD candidate=95 main_matching=81 main_missing=11 main_differing=3 python_sources=92 explicit_loader_findings=0 late_modules=5 root_approved=false
    C34Z_MAIN_HOLD matched=81 missing=11 differing=3 release_attested=false
    C34Z_NATIVE_HOLD late_module_candidates=5 signed_plugin_provenance=false

No host sources, service units, privileged configs or root-owned files are changed by these tests. The original main commit may not be present in CI's shallow Git checkout; the optional replay must not silently fetch missing source.

## Architectural impact and next review-only handover

**C35A proposed:** independently authenticate the five observed NSS/OpenSSL native plugin file bytes to signed Ubuntu .deb package payloads and review their runtime configuration; assess an exact complete service-plus-recovery protected-main package acceptance plan. Reuse existing installation layout and proven C34U signing sources; do not create root installation architecture unless independently required. Subsequent signed-main integration and stop/backup/rollback/restart testing need distinct approvals.

Outstanding gates are all FALSE: protected_main_source_complete, late_native_modules_signed_verified, diagnostics_behavior_approved, root_owned_source_and_loader_sealed, root_execution_approved. Original HTTP 403 remains open. Preserve the protected-main commit, draft PR, OIDC, JSON-token response, localStorage, in-memory sessions, CSP/CORS, existing routes, root-owned source and six-prefix/five-original recovery constraints.

**No merge, root execution, installation, service stop/restart, broker permission change, workflow token rotation or promotion retry is authorized.**
