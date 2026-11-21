# M05 Task14B P0 - PR316 exact immutable source-stage handover

Status: DRAFT REVIEW ONLY / ROOT NOT EXECUTED / NO LIVE DEV CHANGE / NO PROD.

- Signed Analytics0.16.0 remains green and private ready HTTP200.
- Current immutable root source: 330f3255f0067b9ddbe30d50466830bd71a55a11.
- Target reviewed app source: cfc274117fed99e01c24fda62ab0065170f3314a (draft PR316).
- Existing root-owned immutable source contains 76 root:root 0644 files and 9 root:root 0755 directories. Exact Git source diff requires ONLY 2 runtime replacements: analytics_executor.py and analytics_route_journal.py. Other 74 files unchanged.
- Destination new root SHA-named directory and the exclusive staging directory are ABSENT.
- New root-source-stage-reviewed.py reuses the original, protected, root-only installer at /opt/omnilyzer/deployment/.m05-ordinary-reviewed-source-f4a69fc9a3afa361255365ed6d19419bcb58c1c8 and original audited stage+atomic rename functions. The 76-file runtime excludes the source-installer module, so it must not be imported from the runtime source.
- New operator installation destination: /usr/local/libexec/omnilyzer-m05-ordinary-source-stage-cfc.py, root:root mode0500 and one link. No existing file is overwritten.
- **Current proposed root operator source SHA256 f39c07b68aeeec662b879490f0cd80e7887469eff46c7dfbe7d126ac2c3f011f.** The earlier operator 01f2e7aee65a40dcf95e314b92d8548bf8e60d553e734cb7f0dddc365c7e0c0e is superseded and MUST NOT be installed for this reviewed recovery transaction.
- Exact canonical 76-file manifest SHA256 f931fcd93d0a36245a3b7c66482040e0b27483c4254764cd95299a9d6be13f32 (user 1005:1005 mode0400, one link).
- Reviewed replacements:
  - deployment/analytics_executor.py SHA256 34de557ca2d5e63adb6cc5c18c827dd5f266040e699525670d21c9667b84f5ff
  - deployment/analytics_route_journal.py SHA256 d6163f72d113b9c64765c6390923aab93e1d41408883f99d595f56fbaad10374
- Root operator has only --check (read-only) and --stage (one-time new immutable 76-file source creation), with original root-only identity and exact hash checks. No broker/executor socket, service, Docker, OCI image, replay/JTI, database, Task014 dispatch, OAT certificate or PROD mutation.
- The unprivileged 76-file source/2-replacement identity test PASSED, but positive native-root --check and --stage were NOT performed; UID1005 cannot inspect the original root0500 installer code.
- The separate target source approval remains UNSIGNED. Draft handover does not authorize a release or privileged operation.

## Remaining gates

1. Independent M04 approval of exact root-operator source SHA256, reviewed replacement hashes and existing protected installer import boundary.
2. Native owner-root verify exact operator and source approval, then read-only --check. No root --stage before M04 approval.
3. On approved source-stage success, separately prepare the legacy OAT root 0440 certificate, protected source config/systemd switch and rollback plan; executor/socket are currently failed from Task014 #44890393889 and must not simply be reset.
4. Only after actual attested UID991 recovery and stable signed0.16.0 may one fresh signed0.16.1 Task014 run/JTI be dispatched. Previously failed run is consumed. PROD unchanged.


## Independent source review amendment: protected installer content trust

The previous source-only operator inherited the approved 76-file root source
admission, but imported a separate root-only installer without first binding
the actual imported module bytes to the owner's new root SHA256 evidence.
That is an explicit **security defect**, not merely a missing test.

The revised operator rejects if the root-protected pre-existing
`deployment/analytics_isolated_source_install.py` does not match the exact
owner-root SHA256
`cc7dfd7fb022a01772bb2f18fd1705f6e4f15e706903e4b47c8833b7d7f9ac5b`
before any importer executes. Its parent directories and file must also pass
the existing exact root-only, non-symlinked ownership/link-count metadata
check. It refuses any previously loaded `deployment` Python module to
prevent import-cache substitution, then checks the imported module origin.

Source-only tests: 4/4 PASS, including original Git module vs owner-root
SHA, mutation-rejection BEFORE import or stage, preloaded-package denial,
and positive isolated 76/76-file source closure with exact two replacements.
Those source-only checks are NOT a claim that UID1005 read the protected root
module or that native-root `--check`/stage passed.

M04 must verify **actual** protected installer file mode, UID/GID, hash and
full import dependency trust under native root before approving its one-use
source stage. An unexpected mode remains HOLD, never a reason to weaken the
predicate or repeat a failed privileged source stage.

## M04 root import-closure correction - exact PR318 review amendment (21 Nov 2026)

The protected importer `analytics_isolated_source_install.py` imports additional privileged Python code from its existing root-only historical source package. Checking the main importer hash alone was not a complete imported-source integrity proof.

The amended **existing** root-only operator verifies all **61 statically identified importable source members** *before* adding the private source package to Python's module search path or importing a `deployment` module. The 45 members already covered by the exact SHA-pinned 76-file historical baseline reuse its hashes. The 16 outside that baseline have separate exact source SHA256 pins derived from the immutable PR316 cfc Git source, including the original importer and `release/__init__.py`. Each file requires root ownership, one link, a non-symlinked root-controlled ancestor chain, stable read metadata, no group/other writable mode, and exact SHA256. Preloaded `deployment` or `release` modules are rejected. The original 76-file output stage and all live service/replay boundaries are unchanged.

**Focus QA on omnilyzerdev, source-only:** 7/7 importer-closure tests PASS, including independent AST import-graph equality, Git pinned SHA comparison, simulated closed-source 76/76 assembly, tampered importer rejection, tampered *transitive* source rejection before Python import, preloaded-package rejection, and nonroot invocation denial. Latest candidate SHA256 for the test file: `fce08a5604e4e149515a871908a3a98ebcd546417c89efac163aa3074fce04e6`.

**No native root acceptance yet:** The root-only source package is not readable through UID1005's `no_new_privs` connection. A real root `--check` MUST establish that every installed import source actually matches these pinned reviewed bytes, with the new operator identity and mode, before a single source stage may be authorized. A SHA mismatch is a HARD HOLD and must not be papered over using a hash obtained from the live host. The tested files are staged privately for review only. A separate independent M04 decision and owner-native root cutover/rollback acceptance remain mandatory.

GitHub review location: [PR318](https://github.com/MichaelTrueX/omnilyzer-platform/pull/318), source path `deployment/operators/m05_source_stage_cfc.py`. Do not install the earlier PR317-only version after this amendment.

## Native-root findings and exact original installer mode - 21 Nov 2026

Owner executed the SHA-pinned native-root read-only source preflight and then inspected the four mismatching historical protected files. All four are ordinary root:root single-link **0400** source files. The original `deployment/analytics_isolated_source_install.py` hash is `cc7dfd7fb022a01772bb2f18fd1705f6e4f15e706903e4b47c8833b7d7f9ac5b`, which **exactly matches independently reviewed Git source**. The prior stage operator erroneously demanded 0500 for that **data** file. The repaired stage operator now demands exactly 0400 for the importer; the privileged executable operator retains 0500. Focused 7/7 source-only importer tests PASS. This correction is a tighter file permission check, not a security relaxation.

The following three root-protected files in the historical SCRATCH Python package are **not yet source-qualified** against the independently reviewed 330f runtime manifest:

- `deployment/analytics_active_state_review.py`: observed SHA256 `07850982dfbce02fcb1499445aa42ba27d127c38b4306a82fd42265e376b389c`.
- `deployment/analytics_executor.py`: observed SHA256 `ff55ac11e07209e3a3bd44ff0d69ac32bb0e6c73b1f895ac2b4f62c8975930a1`.
- `deployment/analytics_first_install.py`: observed SHA256 `985cf6f82b9ae23af7bc4f3b0fb2d63bdf97e2f87702b127f8180a1ac3be3ee6`.

None of those three SHA256 values matched an exact file revision in the locally reachable Git history or the currently available source-only delivery manifests. This does NOT prove compromise. It proves **provenance is currently insufficient to execute the historical private SCRATCH import tree with root privileges**. These host-observed hashes must never be adopted as expected pins without independent source provenance. A subsequent root preflight will remain HOLD unless the import dependency source is redesigned or the original exact approved source files can be established independently.

**Delivery boundary:** No native-root source stage, cutover, service restart, Task014 replay mutation, failed-run retry or PROD change is permitted. Reuse the existing immutable source-stage and reviewed root module infrastructure, but bind the actual root-imported dependency bytes to a verified provenance source instead of forcing SCRATCH files to agree with a different source generation. Independent M04 approval remains required before installation.
