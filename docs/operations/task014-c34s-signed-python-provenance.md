# Task 014 C34S - Independent Signed Python Package Provenance

**File:** docs/operations/task014-c34s-signed-python-provenance.md

**Purpose:** Preserve independently reconstructed Ubuntu signature-to-installed-byte evidence and the remaining root-safety restrictions.

**Related:** deployment/python_interpreter_provenance.py; deployment/dev_host_qualification.py; deployment/c34r_installed_python_observation.py; deployment/tests/test_c34s_signed_python_provenance.py; deployment/provenance/python3.12-3.12.3-1ubuntu0.17-amd64-payload.json; .github/workflows/task014-c34d-review.yml.

## C34S review decision

**C34S, four-package interpreter/payload scope: PASS. Root execution, deployment, and original HTTP 403 incident: HOLD.**

C27 already pins the Ubuntu archive public key, signed Noble Security InRelease, Packages index and four exact Debian artifacts. C29 already binds a 658-entry payload manifest to these C27 artifacts and verifies installed file bytes without following symlinks. C34R already witnesses the system interpreter. Rather than adding another production trust model, C34S reuses these audited components and contributes one review-only test module with an optional nonprivileged signed-package replay.

## October 15, 2026 independent host audit

Audit source:
- Repository: MichaelTrueX/omnilyzer-platform
- Protected main: 57919c3b9aca0cb98e85bbb26460f6267d093fa9
- Draft PR #190 HEAD at start: 52c3ad235d5ef30025960f5cf8f31b36610ea712
- Nonprivileged executor: omnigpt on omnilyzerdev
- Checkout: /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
- Network: historical Ubuntu snapshot requested only into mode-0700 temporary audit storage; no package manager installation

Independent verification steps and actual observations:

1. Retained 1,660-byte public key matched its C27 SHA-256. GPGv verified the retained Ubuntu InRelease signature against full fingerprint F6ECB3762474EDA9D21B7022871920D1991BC93C.
2. The signed InRelease matched its exact C27 size (126,127 bytes) and SHA-256 603d902fbcedd1666b0897c005771162a7b36288a56aac6a5f557556d53d66de.
3. Historical compressed Packages.xz matched 1,009,196 bytes and SHA-256 7068ebb5e7f7f862612a63d66e1178de0d136086ae02bc7fe95947ab09d8b6a1. This checksum and the plain Packages digest were both present in the signed release.
4. Decompressed Packages matched 5,476,895 bytes and SHA-256 f8fca2bdd59ee4de64a30fc88df870356c6f43e19372b0dbc7caf8b1f2bb2536. All four exact package name/version/architecture/filename/size/hash records matched C27.
5. Downloaded the four exact signed-index artifacts: libpython3.12-minimal, libpython3.12-stdlib, python3.12 and python3.12-minimal, all version 3.12.3-1ubuntu0.17, amd64. Each archive's bytes and SHA-256 matched its signed index record.
6. Without extraction or installation, reassembled every Debian tar file and symlink record from the four archives and compared all attributes to the retained C29 manifest: 284 + 348 + 18 + 8 = **658 entries; zero mismatches**.
7. Re-read the actual host files through existing C29 descriptor-based verification: **658 installed entries MATCH**, comprising **651 regular files, 7 symlinks and 46 native .so modules**.
8. C34R's system binary witness matched the signed-deb payload entry for /usr/bin/python3.12: size 8,020,928 bytes; SHA-256 e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f. It is independently checked evidence, **not a new trust anchor**.
9. Installed package versions, architecture and status were verified before and after the scan.

Observed test output:

    C34S_PASS signed_release packages_index=exact debs=4 installed_payload=658 native_so=46 root_approved=false
    Signed host integration: 1 PASS
    Offline security tests: 8 PASS; optional signed host integration SKIP without staged archives

## Reproduction without modifying installations

Stage the exact C27 snapshot's signed-index Packages.xz and its four identified .deb files in a mode-0700 nonprivileged temporary folder. The snapshot URL and filenames are fixed in the already-reviewed C27 model. The test itself has **no network download mechanism** and will neither extract nor install the packages.

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    PYTHONPATH=. python3 -m unittest -v \
      deployment.tests.test_c34s_signed_python_provenance

    OMNILYZER_C34S_ARCHIVE_DIR=/path/to/private/snapshot \
    PYTHONPATH=. python3 -m unittest -v \
      deployment.tests.test_c34s_signed_python_provenance.ActualHostSignedPackageAudit

The full test calls local gpg/gpgv for the actual signature, checks the exact signed Packages hashes and package records, validates four .deb hashes, reads their tar members through dpkg-deb without extracting, compares each archive entry to C29, and reads/hashes the installed source via C29. A malformed package version, archive hash, manifest, native module or interpreter witness fails closed.

The CI-safe tests also include signature-record malformation/duplication, substitution, package metadata mismatch, altered manifest, modified native library and no-root-approval assertions. Existing C29/C34R negative tests remain unchanged.

## Boundary and remaining HOLD gates

**The verified universe is the four C27 Python packages.** The 46 native .so modules are package-owned CPython extensions, not proof of the entire recursively linked OS library closure. Libraries from other packages (for example libc, libssl, libcrypto, libffi), verifier toolchains, final application import sources and environment configuration require separate explicit qualification before privileged execution.

The C34R controls remain unchanged: interpreter_package_approved=False, installed_executor_config_verified=False, root_execution_approved=False. C34S does **not** establish root-owned immutable source/import package integrity, final approved protected-main SHA, canonical root-only configurations, stopped-service lock/preflight, five-backup recovery acceptance or authorization to migrate. The original HTTP 403 remains unresolved.

**Do not merge, deploy, restart services, rotate OIDC/workflow authorization, execute draft Python as root or retry promotion.** Continue with verified transitive native and privileged-source/root-runtime gates under separate review and approval.
