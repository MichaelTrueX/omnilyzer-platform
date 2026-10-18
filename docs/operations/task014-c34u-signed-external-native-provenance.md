# Task 014 C34U - Independent Signed External Native Package Provenance

**File:** docs/operations/task014-c34u-signed-external-native-provenance.md

**Purpose:** Record independently verified Ubuntu signatures, package metadata, exact .deb archive content and the corresponding installed 19 native ELF library objects. Preserve restrictions against privileged execution and live deployment.

**Related:** deployment/tests/test_c34u_signed_external_native_provenance.py; deployment/tests/test_c34t_native_dependency_inventory.py; deployment/tests/test_c34s_signed_python_provenance.py; deployment/provenance/c34u-external-native-package-set.json; deployment/provenance/c34u-noble.InRelease; deployment/provenance/c34u-noble-security.InRelease; deployment/python_interpreter_provenance.py; .github/workflows/task014-c34d-review.yml; PR #190; Issue #182.

## Decision

**C34U static external native provenance: PASS, independently authenticated in a nonprivileged review-only audit. Root execution: HOLD.**

C34S authenticated the four C27 Python Debian packages. C34T identified 19 externally linked static ELF shared-object names from 49 starting objects, inspecting 68 ELF objects associated with 14 additional Ubuntu package groups. C34T's installed versions and hashes alone were not signed-package evidence.

C34U independently authenticates all 14 external package artifacts using the reviewed C27 Ubuntu archive public key, two retained upstream signed InRelease files, their signed Packages SHA-256 indexes and the exact .deb checksums. It then compares the signed Debian archive members with all 19 installed native library targets and package-defined symlink aliases.

This is a **scope-specific provenance result**, not an assertion of exhaustive dynamically loaded libraries, root authority, or a repaired HTTP 403.

## Exact signed provenance retained in Git

C27's pinned Ubuntu Archive Automatic Signing Key 2018 remains the only public-key trust source. Full fingerprint: F6ECB3762474EDA9D21B7022871920D1991BC93C.

| Signed suite | Retained InRelease | InRelease SHA-256 | Packages SHA-256 |
| --- | --- | --- | --- |
| noble | deployment/provenance/c34u-noble.InRelease | cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0 | 8f6f71ae839c8cba390a7643fcbbdacddb0bc7d12c1583a2dd80a1f8443a30e5 |
| noble-security | deployment/provenance/c34u-noble-security.InRelease | 97d485dd8c7d8d79091073d42b021169c4c6563893f4a680fde10bbc2a6a834a | ba62ef3ceddb89df11c724ba1ec9856091054a78616e3390255b35491bf3c255 |

Compact, reviewed source-selection manifest: deployment/provenance/c34u-external-native-package-set.json. Its SHA-256 is c59040077ca8829aaf2758d47c9dea4bc9d25a771ab3c27d75a59c853de57b0c (4,405 bytes).

The noble InRelease is the April 2024 original release. The selected noble-security InRelease is from October 15, 2026. Both signatures were verified against the exact C27 signer fingerprint. There was no need to change host-installed package versions.

| Package | Signed installed version | Suite |
| --- | --- | --- |
| libbz2-1.0 | 1.0.8-5.1ubuntu0.1 | noble-security |
| libc6 | 2.39-0ubuntu8.9 | noble-security |
| libcrypt1 | 1:4.4.36-4build1 | noble |
| libdb5.3t64 | 5.3.28+dfsg2-7 | noble |
| libexpat1 | 2.6.1-2ubuntu0.6 | noble-security |
| libffi8 | 3.4.6-1build1 | noble |
| libgcc-s1 | 14.2.0-4ubuntu2~24.04.1 | noble-security |
| liblzma5 | 5.6.1+really5.4.5-1ubuntu0.3 | noble-security |
| libncursesw6 | 6.4+20240113-1ubuntu2.2 | noble-security |
| libreadline8t64 | 8.2-4build1 | noble |
| libsqlite3-0 | 3.45.1-1ubuntu2.8 | noble-security |
| libssl3t64 | 3.0.13-0ubuntu3.16 | noble-security |
| libtinfo6 | 6.4+20240113-1ubuntu2.2 | noble-security |
| zlib1g | 1:1.3.dfsg-3.1ubuntu2.2 | noble-security |

## Independently observed acceptance - October 15, 2026

The isolated checkout on omnilyzerdev originally matched draft PR #190 HEAD 425900661f6e3828577253f49b6e7f201e19fca8. Protected main was 57919c3b9aca0cb98e85bbb26460f6267d093fa9. All audits executed as nonprivileged omnigpt.

1. Verified the retained C27 key and two retained signed upstream InRelease records with GPGv, requiring the exact 40-digit fingerprint.
2. Verified both locally staged uncompressed Packages indexes directly against the SHA-256 sections of the respective signed releases. The two index files total 13,397,960 bytes, and are not committed as large sources.
3. Matched all 14 exact package names, versions, amd64 architectures, signed filenames, package lengths and SHA-256 hashes.
4. Retrieved **14 exact Debian artifacts totalling 7,563,328 compressed bytes**. No package-manager installations occurred. Each archive was authenticated to the corresponding signed Packages index before inspection.
5. Parsed the signed .deb tar payloads in memory using dpkg-deb; neither wrote nor extracted any file to the installed system.
6. Reused the complete existing C29 (658 Python package entries), C34R interpreter observation, and C31A (237 populated virtualenv entries) checks and C34T's actual 49-root/68-ELF/19-SONAME static closure.
7. Compared all 19 linked actual native library regular-file lengths and SHA-256 digests to exact members of their independently authenticated .deb archives. Compared actual library symlinks to the archive's signed link targets where applicable. No mismatch.
8. All result flags for complete dynamic loading, root-owned immutable Python imports, canonical protected configuration and privileged execution remain FALSE.

Receipt:

    C34U_SIGNED_NATIVE_PASS releases=2 debs=14 sonames=19 root_approved=false dynamic_loading_verified=false

The CI-safe security suite exercises retained source checks, malicious index/package substitutions, wrong package versions, forged privilege approvals, and real comparison-function negatives for changed native bytes and symlink targets.

## Reproduce without host modification

Default CI-safe unit tests have no network requirement or installed native host reads:

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    python3 -m unittest -v deployment.tests.test_c34u_signed_external_native_provenance

The optional full host audit requires a separate private mode-0700 directory owned by the unprivileged audit account, containing two signed-index-linked *uncompressed* files named noble.Packages and noble-security.Packages, plus the 14 exact .deb archives named by package name, such as libc6.deb and libssl3t64.deb. Every staged byte is verified against committed signed evidence. The test cannot download, install or extract packages onto the host.

    OMNILYZER_C34U_ARCHIVE_DIR=/path/to/private/signed-artifacts \
    python3 -m unittest -v \
      deployment.tests.test_c34u_signed_external_native_provenance.ActualSignedExternalNativeAudit

The archives are temporary audit evidence, not new trust anchors. Source manifests and exact signed InRelease files remain in Git. Audit artifacts can be safely cleaned from nonprivileged temporary storage once their hashes and Git evidence are verified.

## Limitations and remaining HOLD gates

- **The 19 static ELF DT_NEEDED targets are proven, not the entire runtime loading closure.** Python dynamic native imports, ctypes/dlopen, OpenSSL provider loading, NSS modules, custom dynamic loader overrides, and potentially future packages still need a separate dynamic-loading policy.
- Neither the source package nor the verifier toolchain is yet independently sealed as a root-owned immutable execution package. The recorded Git branch remains draft and cannot authorize root to import Python from an omnigpt checkout.
- Root configuration, final protected main SHA, the maintenance/stopped-host exclusive lock, complete original backups, root crash/rollback/restart acceptance and explicit live promotion approval remain separate gates.
- The broker's original HTTP 403 remains unresolved.
- C34U hardcodes these fields to FALSE: complete_dynamic_loading_verified, immutable_root_import_package_approved, canonical_root_config_approved, root_execution_approved. Earlier C34R and C34I-C34O authority flags remain unchanged and non-authorizing.

## Recommended next review-only stage: C34V

Develop only the immutable privileged Python source/import and closed dynamic-loader execution requirements. Reuse C34P's 73-file static Python import graph and existing C27/C31A/C34S/C34U provenance. Do not add a new installation architecture unless required by verified gaps. Explicitly reject environment-variable injection, mutable user Python paths, forged root receipts, unpinned dynamically loaded modules and unauthorized source substitutions. The root-owned sealed runtime must remain a **proposal/test model**, not installed root code, until a distinct future authorization.

No merge, live deployment, root installation, privileged draft module execution, service restart, OIDC/workflow SHA rotation, protected configuration changes or promotion retry is authorized.
