# Task 014 C34Y — Complete Candidate Source and Resource Manifest Review

**File:** docs/operations/task014-c34y-source-resource-manifest-review.md

**Purpose:** Review an exact content-addressed, non-destructive inventory of the 92 proposed Python source files and three root-owned runtime resources, while preserving the installed service and demonstrating why these bytes do not yet authorize privileged import, installation or promotion.

**Related files:** deployment/provenance/c34y-service-recovery-source-review.json; deployment/tests/test_c34y_service_recovery_manifest_review.py; deployment/tests/test_c34x_service_recovery_source_reconciliation.py; deployment/tests/test_c34w_installed_source_feasibility.py; deployment/c34p_dependency_source_closure.py; deployment/provenance/python-runtime-py312-linux-x86_64-installed.json; deployment/provenance/c34u-external-native-package-set.json; .github/workflows/task014-c34d-review.yml; docs/operations/task014-c34x-service-recovery-reconciliation.md; draft PR #190; Issue #182.

## Decision and trust boundary

**C34Y: complete scoped 95-file candidate inventory CREATED and independently review-verified. Protected-main/root-owned approved installation manifest: NOT created or approved. Privileged execution: HOLD.**

This stage creates a checked-in **review-only JSON data file**, one test-only Python source file and review documentation, and extends the existing Task 014 CI test sequence. The JSON is a historical snapshot of candidate Git source bytes and existing installed file observations, **not** a production installation recipe, signing authority or approved manifest for any root process.

No root execution, service change, package deployment, permission change, OIDC/credential change, installation, promotion retry or PR merge took place. The existing application/venv directory structure and existing auth/token handling are untouched.

## Exact Git and host baseline (October 15, 2026)

- Baseline candidate Git commit: 482ab09ca3350c37a025720a4d28e796507819b0, initially the HEAD of draft PR #190 after C34X acceptance.
- Protected main at review start: 57919c3b9aca0cb98e85bbb26460f6267d093fa9.
- Nonprivileged host: omnilyzerdev, user omnigpt. Root-owned, installed application source observed only under /opt/omnilyzer/deployment/app; existing virtualenv path under /opt/omnilyzer/deployment/venv.
- Source manifest: deployment/provenance/c34y-service-recovery-source-review.json, 26,640 bytes, SHA-256 d817404801ca9d7364a2aaadf0f120a19c49cb806f60692e3d8dae90de59e4a5.
- All 95 current draft Git blobs are checked against their individually pinned path, byte count and SHA-256. The C34P import-closure parser is reused to verify membership of all 73 recovery sources; service-only source names and entrypoint names are also checked.
- All expected installed root-owned source files and three resources are independently reobserved with the existing C34W/X non-following descriptor checks. C34Y intentionally does not mark 54 absent recovery sources as installed.
- Normal draft branch additions of C34Y tests, documentation or manifest do not change the reviewed Python source and runtime resource bytes; any change to one of those 95 blobs triggers a review HOLD.

## Exact 95-file manifest composition

| Item group | Scope | Observed state |
| --- | ---: | --- |
| Python files required by both service and C34O recovery | 19 | 18 matching, 1 divergent |
| Existing service-only Python source files | 19 | 17 matching, 2 divergent |
| C34O recovery-only Python source files | 54 | 54 absent from installed application |
| Runtime resources outside Python import graph | 3 | 3 matching |
| **Total reviewed artifacts** | **95** | **38 matching, 54 absent, 3 divergent** |

The proposed combined Python source set contains exactly **92 distinct file names**, preserving all 38 existing service source names rather than destructively replacing them with the C34O 73-file graph.

Each record includes: repository-relative path, scope classification, exact candidate Git SHA-256, byte size, proposed installed file mode 0644, UID=0, GID=0, observed installed state, and observed installed SHA-256 or null if absent. The proposed owner/mode fields are requirements for a future installer review; they are **not** evidence that all 95 files have been installed or sealed as root-owned files.

The manifest's root_execution_approved field is fixed FALSE. The accompanying frozen C34Y test receipt also hardcodes every future privilege and deployment gate to FALSE.

### Preserved divergent service modules

The candidate pins the precise three existing C34E diagnostic changes as divergent from the installation; none is silently upgraded:

| File | Installed SHA-256 | Proposed candidate SHA-256 |
| --- | --- | --- |
| deployment/broker.py | b7728fb25e0c314ad724cd63ac7edc5ec1d24e05a4737cb7af2c8310bc58c34d | 4486fc877a2788bca9aeaa56b98790c6cf216c3b80312dd5e9595832d487fc96 |
| deployment/broker_https_ingress.py | 484b3378f27064a48393a76379249174e30780d4df39c9f4bf5554788f4dc925 | f0bd4c9e3e5b890232b780bd8aa01fb47a0b240454fc988106c30ef5f94b39e7 |
| deployment/broker_integration.py | 8abdda62c81282c07f403bd924f4d41b35ff8d113d2bee6a66e2ff32e8339b13 | 05441f3edb490cf4ff17ecfdfdd7e547bd96efb64228e606235cfc6c794d6ac6 |

C34X's reviewed AST normalization detected diagnostic-only **syntactic** differences under six exact SHA-256 pins; this is not a behavioral equivalence test, authorization to change the live broker, or resolution of the original 403. Its code and related auth/OIDC/replay semantics must receive a separately recorded change-control decision.

### Runtime resources and Python/native dependencies

The three immutable Git resource objects are retained: deployment/runtime/dev/canary-runtime.json, deployment/runtime/dev/compose.yaml and deployment/runtime/dev/nginx/nginx.conf. They all matched the nonprivileged read-only installed-host observations. Existing service entrypoints deployment/broker_service_entrypoint.py and deployment/executor_service_entrypoint.py are included within the 92 Python source files.

The source-review JSON also pins the existing C31A installed Python environment manifest SHA-256 (3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b) and C34U independently signed external native package-selection manifest SHA-256 (c59040077ca8829aaf2758d47c9dea4bc9d25a771ab3c27d75a59c853de57b0c). The review test checks those exact files remain unchanged.

C34X found cryptography and jwt as the existing service's top-level third-party import roots, both represented in the C31A 237-entry virtualenv manifest. C34U authenticated 14 external Debian package groups and 19 static DT_NEEDED native library paths. Those facts **do not** establish an independently approved full runtime dynamic-loader closure, immutable root bootstrap or authority to run the package as root.

## Requirements-to-implementation traceability and acceptance

| ID | Requirement | Implementation or evidence | Status |
| --- | --- | --- | --- |
| C34Y-01 | Cover the 92 distinct existing-service and recovery source names without deletion | Deterministic manifest and C34P/C34W/C34X source graph reconciliation | Implemented, verified review-only |
| C34Y-02 | Preserve three existing runtime resources | Three exact Git paths, size/hash records and host read-only byte equality | Implemented, verified review-only |
| C34Y-03 | Pin every candidate source's exact file size, SHA-256 and proposed ownership | 95 sorted content-addressed manifest records | Implemented, verified *candidate* bytes |
| C34Y-04 | Detect changed, missing, unexpected or substituted files | Fixed manifest digest, per-entry validation, current Git hash checks and negative tests | Implemented, verified within reviewed scope |
| C34Y-05 | Retain and expose diagnostic divergences | Exactly three installed/candidate hash pairs pinned and fail-closed | Verified observation, changes NOT approved |
| C34Y-06 | Reuse existing Python and native dependency provenance | Exact SHA-256 pins to C31A and C34U inputs | Implemented, verified pin integrity only |
| C34Y-07 | Audit installed root-owned files with no host mutation | Existing C34W/X descriptor-based observers reused; explicit opt-in host test | Implemented, verified host snapshot |
| C34Y-08 | Provide non-authorizing receipt and prevent forged root approval | Frozen receipt, root_execution_approved and four other gates permanently FALSE | Implemented, verified negative tests |
| C34Y-09 | Prove approved protected-main provenance and independently sealed root-owned execution package | Separate main attestation, package installer and root-owned verifier | **Proposed, not approved or implemented** |
| C34Y-10 | Close runtime loader, original HTTP 403, maintenance lock, backup, rollback and restart | Existing C34I–C34X safety gates and Issue #182 | **Open / HOLD** |

**Status definitions:** Proposed is a design requirement; approved needs a distinct explicit decision; implemented means draft review files exist; verified means the identified, bounded tests/evidence passed; released means accepted and deployed. C34Y is implemented and verified strictly as a review-only artifact. It has not been approved for production or released.

## Verification and reproduction

Default Git-only unit tests (with no root execution or installed-host reads):

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    umask 0022
    python3 -m unittest -v \
      deployment.tests.test_c34y_service_recovery_manifest_review

This validates all 95 HEAD Git blobs, 73 recovery closure paths, service entrypoints, source scope counts, record hashes, related dependency manifest pins, duplicate JSON keys, missing files, fabricated approvals and substitutions. The file is bound to the original reviewed C34X Git source commit while checking the *current* draft HEAD's file bytes; the original commit is a candidate reference, not protected-main attestation. In a shallow CI checkout the earlier Git commit may not be fetched, so verification relies on exact pinned contents and current HEAD Git objects rather than silently downloading missing Git history.

Explicit nonprivileged read-only installed-host replay (not part of normal CI):

    OMNILYZER_C34Y_HOST_READONLY=1 python3 -m unittest -v \
      deployment.tests.test_c34y_service_recovery_manifest_review.C34YRealHostReplay

Expected receipts:

    C34Y_MANIFEST_REVIEW_PASS sources=92 resources=3 candidate_objects=95 installed_verified=false root_approved=false
    C34Y_HOST_HOLD installed=38 absent=54 divergent=3 resources=3 source_union=92 root_approved=false

The host replay does not install missing files, accept divergent broker source, alter site-packages, or turn a clean 95-object Git graph into an approved installation.

## Architecture impacts and C34Z handover

C34Y confirms that the **existing application and virtualenv path hierarchy can remain intact for future planning**, but an independently sealed root-owned source/resource package is not currently present. It is unsafe to patch the live service using a recovery-only module inventory, and impossible to turn the draft manifest into root authority without separate approvals.

A later **C34Z review-only stage** should close additional resource/import/data and package-activation acceptance gaps without performing host changes. Required review items:

1. Independently attest a specific protected-main Git commit and verify the entire intended service-plus-recovery Python source and three-resource set **against that approved main**, then reevaluate any changes to the SHA-256 manifest.
2. Approve or reject the three C34E diagnostic modifications under protected service auth/ingress/OIDC/replay behavior tests. Preserve the existing 403 behavior until the original promotion 403 root cause is understood.
3. Define a separately approved, root-owned **non-destructive** install/seal process using the existing C21/C23 layout and actual root-controlled verifier. Prove no extra-files, symlinks, writes outside the package, and rollback to exact original service source/resource bytes.
4. Prove complete Python and dynamic-library import constraints, including PyJWT/cryptography, standard-library native modules, C34U static linked system libraries, NSS/OpenSSL providers and late native dlopen.
5. Require protected configuration checks, stopped-host exclusive lock, C34K five-original backups, C34O six-prefix recovery integrity and explicit authorization for any future actual root tests, restart or promotion.
6. Keep current JSON-token/localStorage session semantics, in-memory sessions, CSP/CORS, OIDC workflow restrictions, GitHub authorizations and existing routes intact.

**Root-owned package created: FALSE; diagnostic changes approved: FALSE; dynamic loading verified: FALSE; protected main attested: FALSE; root execution approved: FALSE.** No merge, deployment, service/unit change, source installation, root execution, OIDC rotation or promotion retry is authorized. PR #190 stays DRAFT and Issue #182 remains OPEN.
