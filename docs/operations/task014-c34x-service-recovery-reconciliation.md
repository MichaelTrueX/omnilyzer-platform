# Task 014 C34X - Non-destructive Service + Recovery Source Reconciliation

**File:** docs/operations/task014-c34x-service-recovery-reconciliation.md

**Purpose:** Reconcile all existing deployed broker/executor Python source and runtime configuration resources with the proposed C34O transitive recovery module graph. Establish which resources, authentication dependencies and divergent service modules must be preserved before designing a privileged sealed install manifest.

**Related:** deployment/tests/test_c34x_service_recovery_source_reconciliation.py, deployment/tests/test_c34w_installed_source_feasibility.py, deployment/c34p_dependency_source_closure.py, deployment/tests/test_c34v_privileged_import_seal.py, deployment/provenance/python-runtime-py312-linux-x86_64-installed.json, .github/workflows/task014-c34d-review.yml, docs/operations/task014-c34w-installed-source-feasibility.md, PR #190, Issue #182.

## Decision

**C34X source-set reconciliation: implemented and verified as a read-only review. Non-destructive installation manifest: NOT APPROVED. Root executable package: NOT IMPLEMENTED. Promotion: HOLD.**

The assessment reuses the installed application path (/opt/omnilyzer/deployment/app), the existing Python virtualenv, C34P immutable candidate-Git blob graph, C34W root-owned source observers and the C31A installed Python environment manifest. It creates **no new deployment structure**. All inspectable files remain unchanged.

Source baseline for this review: draft PR #190 at commit 2e155530b3ea6a06e4cf7f31a05081364c3d1b31. Protected main remains 57919c3b9aca0cb98e85bbb26460f6267d093fa9. Later C34X CI commits alter the draft HEAD but do not change the six explicitly pinned broker/ingress/integration source fingerprints unless separately reported and re-reviewed.

## Independently observed source-set evidence

The nonprivileged installed-source audit read exact current root-owned 0644 Python files through O_NOFOLLOW file descriptors with stability checks and compared their SHA-256 bytes with candidate Git objects. The test never imported or ran the inspected files.

| Measure | Observation |
| --- | ---: |
| Installed broker/executor Python package files | 38 |
| C34P C34O transitive recovery source files | 73 |
| Shared source names | 19 |
| Required recovery sources absent from installed app | 54 |
| Current installed service sources outside C34O closure | 19 |
| **Combined distinct source names** | **92** |
| Installed Python files identical to corresponding draft Git objects | 35 |
| Installed Python files differing from corresponding draft Git objects | 3 |
| Exact root-owned runtime configuration resources | 3 |

The 92-file source union is an **inventory**, not a root-approved output manifest. It omits any further required generated artifacts, metadata, full native-loader closure and future independently approved installation requirements. It would be unsafe to overwrite the current app with the recovery-only 73 files, because doing so would omit 19 live-service modules.

## Three divergent service files

| File | Installed SHA-256 | Candidate SHA-256 |
| --- | --- | --- |
| deployment/broker.py | b7728fb25e0c314ad724cd63ac7edc5ec1d24e05a4737cb7af2c8310bc58c34d | 4486fc877a2788bca9aeaa56b98790c6cf216c3b80312dd5e9595832d487fc96 |
| deployment/broker_https_ingress.py | 484b3378f27064a48393a76379249174e30780d4df39c9f4bf5554788f4dc925 | f0bd4c9e3e5b890232b780bd8aa01fb47a0b240454fc988106c30ef5f94b39e7 |
| deployment/broker_integration.py | 8abdda62c81282c07f403bd924f4d41b35ff8d113d2bee6a66e2ff32e8339b13 | 05441f3edb490cf4ff17ecfdfdd7e547bd96efb64228e606235cfc6c794d6ac6 |

The source diff adds a bounded, literal-stage diagnostic logger/filter in broker.py and diagnostic warning calls in broker, HTTP ingress and promotion integration. A review-only AST normalizer removes the specific known logger/filter declarations, utility imports, module documentation and literal stage-warning expressions from **only these exact six pinned blob versions**; the remaining ASTs compare identically.

**Limit:** AST equivalence after this restricted removal does not prove the diagnostic code's runtime exception handling, concurrency, performance or security behavior is identical. In particular, side effects in a logging filter and behavioral consequences of logger calls require separate test and change-control review. C34X intentionally keeps diagnostic_changes_approved=FALSE and never copies an alternate broker.py onto the installed service.

## Existing runtime resources

The installed application includes three root-owned mode-0644 non-Python artifacts, all observed byte-for-byte identical to the same paths in the draft Git commit:

| Relative path | Observed SHA-256 |
| --- | --- |
| deployment/runtime/dev/compose.yaml | ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc |
| deployment/runtime/dev/canary-runtime.json | 8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f |
| deployment/runtime/dev/nginx/nginx.conf | cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b |

The C34X opt-in host test rejects unexpected extra runtime files and parent directory ownership/mode changes. This inventory is not a mandate to modify or redeploy Docker/nginx configurations.

## Whole-service third-party dependencies

C34P's recovery-only static graph references cryptography. A separate conservative installed-service AST scan of all 38 currently deployed .py modules identifies **cryptography and jwt** as the two third-party import roots, with no missing local module imports.

The existing C31A retained installed virtualenv manifest already records cryptography 50.0.1 and PyJWT 2.13.0 (plus cffi 2.1.1 and pycparser 3.0) and has 237 installed-environment entries. C34X checks the retained manifest's distribution records as a consistency boundary; this does NOT grant the complete future root import package authority. C31A's independently verified wheel and file evidence remains a separate prerequisite.

The current executor and broker entrypoint sources are retained: deployment/executor_service_entrypoint.py and deployment/broker_service_entrypoint.py. No entrypoint or service command changes are recommended in C34X.

## Requirements-to-implementation traceability

| Requirement | Evidence / implementation | Status |
| --- | --- | --- |
| C34X-01 Inventory existing service and C34O recovery source union | C34P graph plus C34W source observer and C34X source-set comparison | Implemented, verified review-only |
| C34X-02 Preserve every installed service file | 38 installed-source names included in 92-name proposed union; missing-service negative test | Implemented, verified review-only |
| C34X-03 Pin and classify three service-source divergences | Six exact SHA-256 pins, source AST normalization of known diagnostic changes | Implemented, observed; **not approved** for live replacement |
| C34X-04 Preserve installed non-Python resources | Three exact paths, root-owned file observations and Git byte equality | Implemented, verified review-only |
| C34X-05 Account for full service Python third-party roots | AST scan finds cryptography and jwt, checked against C31A retained manifest | Implemented, verified scope; root runtime not accepted |
| C34X-06 Block forged installation/root authority | Immutable C34X receipt keeps five authority flags FALSE | Implemented, verified |
| C34X-07 Independently signed protected-main union package | Future source/resource manifest plus sealed installation | Proposed, NOT implemented |
| C34X-08 Privileged Python and ELF runtime closed loading | C34V/W and C34U constraints remain; NSS/providers/dlopen/open files not exhaustively attested | Proposed, NOT verified |
| C34X-09 Original HTTP 403/root recovery authorization | Issue #182 and existing six-prefix/five-backup recovery gates | OPEN, HOLD |

Status definitions: **proposed** = design only; **approved** = separate explicit authorization; **implemented** = draft code/evidence exists; **verified** = specific tests pass; **released** = accepted/merged/deployed. C34X implements and verifies *only review-only analysis*. It is neither approved nor released for privileged operation.

## Reproduction and negative testing

Default offline Git-only/source-fixture tests:

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    python3 -m unittest -v deployment.tests.test_c34x_service_recovery_source_reconciliation

Explicit nonprivileged read-only installed-host test (not enabled in CI):

    OMNILYZER_C34X_HOST_READONLY=1 python3 -m unittest -v \
      deployment.tests.test_c34x_service_recovery_source_reconciliation.C34XActualHostReview

All host checks are observational. Counts, hashes, source versions and resources fail closed on any unknown change. The static AST classifier cannot authorize root, finalize the source manifest, validate the effect of diagnostics, prove full Python import provenance or evaluate native dlopen behavior.

Expected actual-host receipt:

    C34X_UNION_HOLD installed=38 recovery=73 union=92 shared=19 candidate_exact=35 divergences=3 resources=3 third_party=cryptography,jwt root_approved=false

## Architecture impacts and required C34Y handover

C34Y should review an **exact non-destructive full-service-plus-C34O root-owned source and resource manifest** using the existing installation/qualified-wheel infrastructure. Only after independently signed protected-main evidence, a complete package closure, runtime-loading and auth compatibility tests, backed-up stopped-host recovery and explicit separate authorization could an installer be considered.

Specific blockers:

- Decide how proposed diagnostic-source changes to broker, ingress and integration will be approved **without weakening current 403, OIDC, replay, token and session semantics**; no silent overwrite.
- Construct a complete source-and-resource manifest preserving 38 current services, 54 new recovery source names, and the exact three runtime resources; future source modifications need new review.
- Re-verify PyJWT/cryptography and all stdlib/native binaries under an independently sealed Python launcher; evaluate NSS/OpenSSL provider and other dynamic loading beyond static ELF DT_NEEDED.
- Attest a protected main SHA independently, seal root-owned verifier and source bytes, enforce service stopped-state/exclusive lock and five-file backup, maintain six-prefix rollback/restart and reconcile the original HTTP 403.
- Keep repository quality/security checks and stage-specific negative tests, with no claims of merged, released or deployed state until verified.

**No root execution, service mutation, installation, GitHub PR merge, configuration/OIDC rotation, permission change, deployment or promotion retry authorized. Draft PR #190 remains DRAFT and Issue #182 remains OPEN.**
