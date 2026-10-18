# Task 014 C35A — Ubuntu-Signed NSS/OpenSSL Late Native Module Evidence

**File:** docs/operations/task014-c35a-signed-late-native-provenance.md

**Purpose:** Close the precise signed-payload provenance gap for five previously observed NSS/OpenSSL late-loadable native files on omnilyzerdev. Identify configuration trust limitations, preserve the original Task 014 403 and privileged-execution gates, and hand over a bounded next review stage without host changes.

**Linked files:** deployment/tests/test_c35a_signed_late_native_modules.py; deployment/provenance/c35a-signed-late-native-modules-review.json; deployment/tests/test_c34z_main_loader_release_gap.py; deployment/tests/test_c34u_signed_external_native_provenance.py; deployment/provenance/c34u-external-native-package-set.json; deployment/provenance/c34u-noble.InRelease; deployment/provenance/c34u-noble-security.InRelease; deployment/python_interpreter_provenance.py; .github/workflows/task014-c34d-review.yml; docs/operations/task014-c34z-protected-main-loader-gap.md; draft PR #190; Issue #182.

## Decision and scope

**C35A signed five-file native provenance: PASS (scoped verification). Dynamic native loading configuration: HOLD. Protected main and root execution: HOLD.**

The previous C34U audit verified 19 static ELF DT_NEEDED native target files. C34Z discovered five additional potential runtime-loaded OpenSSL/NSS module files whose signed bytes had **not** been verified by C34U. C35A independently authenticated the exact installed bytes of those five modules using signed Ubuntu package index and archive contents.

C35A reused **existing C27 Ubuntu Archive Automatic Signing Key 2018**, full fingerprint F6ECB3762474EDA9D21B7022871920D1991BC93C, and the **two existing retained C34U signed Ubuntu InRelease records**, noble and noble-security. No new keyring, trust roots, release snapshot or package installation structure was introduced.

The test-only implementation reads signed source and installed files as a nonprivileged user. It does not load native modules or execute any inspected source. No service unit, production app, root-owned file, configuration, Docker process, OIDC/JWT setting or deployment changed.

## Independently verified evidence — October 15, 2026

Source baseline: draft PR #190 at HEAD 0ecdde9432d0f5969107c9179bb88c96d61e8570, protected main 57919c3b9aca0cb98e85bbb26460f6267d093fa9, unchanged during the C35A read-only audit. Nonprivileged audit user omnigpt on omnilyzerdev.

The source-selection model is retained at deployment/provenance/c35a-signed-late-native-modules-review.json (2,856 bytes, SHA-256 b78cf375285ea4aa086e79ff96f2658540e185dd7ab050bb45cb40ec70547244). It retains four exact package records, five installed module paths and their signed archive member hashes/size, and three explicitly **non-signed** host configuration observations.

| Native module | Signed Ubuntu package | Package version | Bytes compared against signed .deb |
| --- | --- | --- | ---: |
| ossl-modules/legacy.so | libssl3t64 | 3.0.13-0ubuntu3.16 | 129,256 |
| libnss_dns.so.2 | libc6 | 2.39-0ubuntu8.9 | 14,336 |
| libnss_files.so.2 | libc6 | 2.39-0ubuntu8.9 | 14,336 |
| libnss_mdns_minimal.so.2 | libnss-mdns | 0.15.1-4build1 | 18,664 |
| libnss_systemd.so.2 | libnss-systemd | 255.4-1ubuntu8.18 | 371,112 |

All five files exactly matched their signed Debian tar member lengths and SHA-256 content. These are the **five named files only**; C35A does not certify arbitrary modules or runtime loading decisions.

Four signed .deb archives were authenticated (total 5,392,058 compressed bytes):

- libc6 (noble-security): SHA-256 ff5557d99b51f761c4b7c92368b9cc45565eda17df9bf9eb4b134d09825008be
- libnss-mdns (noble): SHA-256 a08a47e5094be0ea83dc42483a498972bdca9a36b36dcf4abb3bf488e71dc242
- libnss-systemd (noble-security): SHA-256 81295714c4611b0f912448ff2816c1f1663515e1e0f3ba83467367ea9433bd6e
- libssl3t64 (noble-security): SHA-256 219f43b1cd836a4da550938db5fda93160d269d39a4edcf1f1ce698a470db797

**Archive evidence chain:** check the exact pinned C27 signing key, use gpgv to independently verify both signed C34U InRelease records with the exact signer, match staged full Packages indexes to the signed InRelease SHA-256/size, compare exact name/version/amd64/archive path/hash/size against signed Packages records, verify all four downloaded .deb SHA-256 contents, inspect tar members in memory using dpkg-deb, and compare five root-owned installed native files with those signed members via no-follow descriptor-based SHA-256. C34U's existing authenticated package selection is reused for libc6 and libssl3t64; the two new package records are authenticated to the signed noble and noble-security index records. No apt install, dpkg unpack onto the host, dynamic module load, network access by the auditor test, or root execution occurred.

Observed receipt:

    C35A_SIGNED_LATE_NATIVE_PASS signed_releases=2 authenticated_debs=4 native_files=5 configs_observed=3 configs_signed=false dynamic_loader_closed=false root_approved=false

## Loader configuration — observed but NOT authenticated

In addition to these five binary files, the following host configuration paths were observed as root-owned regular 0644 files. Their local hashes are retained in the C35A manifest for drift detection; they are **not independently signed source verification**:

| Host path | Observed SHA-256 |
| --- | --- |
| /etc/ld.so.conf | d4b198c463418b493208485def26a6f4c57279467b9dfa491b70433cedb602e8 |
| /etc/nsswitch.conf | c82823e2e926b49e843d84bc8ec6d7f0861bda70bdd9d8716674609596ddb863 |
| /etc/ssl/openssl.cnf | 529815b0dd4bd6608bafeeb3d410b0683374e61aef792b3e3f38b3767d26f747 |

The observed /usr/lib/ssl/openssl.cnf is a root-owned symlink to /etc/ssl/openssl.cnf. Its symlink mode 0777 is normal metadata for a symbolic link and is **not evidence that the target is writable**. The target was observed as root-owned regular 0644. The audit checks the exact alias target but not whether the *effective privileged runtime* accepts or ignores configurations from other sources.

Potential additional native providers, /etc/ld.so.conf.d entries, NSS action selection, OpenSSL provider/autoload semantics, symlink parent-chain trust, module dependency closure, dynamic library search and inherited environment remain **separate unresolved gates**. This is not an exhaustive runtime native-loader inventory and does not establish whether a specific module is loaded by the protected service.

## Requirements-to-implementation traceability

| ID | Requirement | Evidence / implementation | Status |
| --- | --- | --- | --- |
| C35A-01 | Reuse independently pinned Ubuntu archive trust | C27 pinned signer and C34U retained noble/noble-security signed InRelease | Implemented, verified |
| C35A-02 | Verify installed five module bytes against upstream signed package payloads | Four authenticated .debs, five exact tar member vs installed file byte matches | Implemented, verified for five files |
| C35A-03 | Prevent package owner/version metadata from being mistaken for proof | Signed index and archive checks required before member acceptance | Implemented, verified |
| C35A-04 | Preserve scope and reject forged privileged approvals | Frozen receipt with permanently false config/dynamic/main/root fields; negative tests | Implemented, verified |
| C35A-05 | Record untrusted loader configuration separately | Three exact observed paths/hashes, expected OpenSSL symlink | Implemented, verified observation only |
| C35A-06 | Independently verify all effective runtime configuration and possible native imports | Additional system/plugin config and dynamic loader policy | Proposed, NOT verified |
| C35A-07 | Promote complete source from approved protected main | C34Z observed 11 missing, 3 differing main files | BLOCKED |
| C35A-08 | Resolve original HTTP 403 and root operations safely | Issue #182, stopped-service lock, five backups, six-prefix rollback/restart | OPEN / HOLD |

Status vocabulary: proposed = requirement/model only; approved = separate explicit authorization; implemented = code/data exists in draft; verified = bounded evidence/tests pass; released = independently accepted and activated. C35A implements and verifies **signed bytes for the selected five files only**. No privileged release approval is inferred.

## Reproduction without package installation

Default CI review tests require only the retained manifest and signed C34U source records, not Ubuntu network access or installed native paths:

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    umask 0022
    python3 -m unittest -v deployment.tests.test_c35a_signed_late_native_modules

For a complete independent signed installed-file audit, stage exact packages and the two uncompressed Packages indexes in a private mode-0700 directory owned by the nonprivileged audit user. The two required index filenames are noble.Packages and noble-security.Packages; the four archive filenames are libc6.deb, libnss-mdns.deb, libnss-systemd.deb and libssl3t64.deb. The audit never trusts these inputs without verifying each stage of the signed Ubuntu evidence chain.

    OMNILYZER_C35A_ARCHIVE_DIR=/path/to/private/verified-artifacts \
    python3 -m unittest -v \
      deployment.tests.test_c35a_signed_late_native_modules.C35AActualHostSignedReplay

These temporary downloaded archives are not needed in Git; the retained exact signed InRelease records, upstream archive hashes and module member hashes remain in GitHub review evidence. They may be deleted from nonprivileged temporary storage after exact-commit audit acceptance.

## Architecture impacts and next review-only handover

**Proposed C35B:** build a nonprivileged, review-only **closed loader-configuration and potential dynamic-provider inventory** based on exact source and protected-host evidence. Account for OpenSSL and NSS configuration, libc loader paths, module dependency ELF DT_NEEDED, all anticipated late load sites, module source packages and inheritance/privilege restrictions. Assess compatibility with existing service auth/replay/JWT, no new directory layout unless a proved requirement, and retain full 92-source/three-resource protected-main blockers (11 missing and three divergent). Do not implement root-owned launcher or install until independently approved.

**Still HOLD:** signed or immutable runtime loader configuration, full native runtime closure, three unapproved broker/ingress/integration diagnostic changes, 11 absent protected-main source modules, original broker HTTP 403, independently approved root-owned source/sealed verifier, protected OIDC and token behavior, stopped-host exclusive lock, backups, rollback/restart and distinct deployment authority.

All approval flags remain False: observed_config_bytes_are_signed, native_runtime_loader_closed, protected_main_approved, privileged_import_package_approved and root_execution_approved. PR #190 remains draft and unmerged; no live deployment, root execution, service modification, secrets rotation or promotion retry is authorized.
