# Task 014 C34T - Transitive Native Dependency Inventory

**File:** docs/operations/task014-c34t-native-dependency-inventory.md

**Purpose:** Document the read-only static native dependency scope and its signed-provenance gaps before any privileged Python code execution.

**Related files:** deployment/tests/test_c34t_native_dependency_inventory.py; deployment/dev_host_qualification.py; deployment/python_environment_qualification.py; deployment/python_interpreter_provenance.py; deployment/c34r_installed_python_observation.py; .github/workflows/task014-c34d-review.yml.

## Decision

**C34T static inventory PASS. Signed external-native provenance NOT YET VERIFIED. Privileged execution HOLD.**

C34S verified the complete installed payload of the four original C27 Python Debian packages, including 46 native extension modules. Those bytes are authenticated through signed Ubuntu package artifacts. However, those native modules depend on external system libraries, which are NOT included in the four C27 packages.

C34T creates no production Python module, installation mechanism, package manager, privileged helper, new source trust anchor or runtime authorization. It adds only CI-safe regression tests and an opt-in nonprivileged actual-host observation.

## Actual host evidence - October 15, 2026

The authoritative starting source was the unmerged PR #190 at C34S HEAD eb54d55d40f09e30f3b35493f82a407e6a50bba3. Protected main was 57919c3b9aca0cb98e85bbb26460f6267d093fa9.

Read-only audit performed as omnigpt on omnilyzerdev, inside the existing isolated checkout, without sudo or mutation:

1. Reused existing C29's 658 installed Python-package payload file/symlink validations.
2. Rechecked the C34R interpreter witness against the C27-authenticated payload.
3. Reused the complete existing C31A 237-entry virtualenv tree qualification and exact pinned bytes of both native wheel extensions: cryptography's _rust.abi3.so and cffi's _cffi_backend.cpython-312-x86_64-linux-gnu.so.
4. Read only ELF DT_NEEDED records with readelf -d, without executing inspected binaries or loading native extensions.
5. Recursively observed linker-cache resolutions, read native libraries through root-owned file descriptors with SHA-256 hashes and repeated inode/metadata checks, and observed owners/versions from dpkg-query.
6. Rejected missing or ambiguous loader-cache results, altered ELF search paths, noncanonical paths, native-module/ownership mismatches, symlink substitution, spoofed package metadata and forged privileged approval.

| Static observation | Result |
| --- | ---: |
| Starting interpreter and native ELF objects | 49 |
| Objects in recursive static ELF closure | 68 |
| Distinct DT_NEEDED shared-object names | 19 |
| Unresolved static names | 0 |
| Installed external Debian package groups | 14 |
| Offline positive/negative CI-safe cases | 7 PASS |
| Optional nonprivileged installed-host case | 1 PASS |

19 dynamically linked shared-object names:

    ld-linux-x86-64.so.2   libbz2.so.1.0    libc.so.6
    libcrypt.so.1          libcrypto.so.3   libdb-5.3.so
    libexpat.so.1          libffi.so.8      libgcc_s.so.1
    liblzma.so.5           libm.so.6        libncursesw.so.6
    libpanelw.so.6         libpthread.so.0  libreadline.so.8
    libsqlite3.so.0        libssl.so.3      libtinfo.so.6
    libz.so.1

External packages and versions **observed locally, not yet independently authenticated**:

| Package | Observed Ubuntu version |
| --- | --- |
| libbz2-1.0 | 1.0.8-5.1ubuntu0.1 |
| libc6 | 2.39-0ubuntu8.9 |
| libcrypt1 | 1:4.4.36-4build1 |
| libdb5.3t64 | 5.3.28+dfsg2-7 |
| libexpat1 | 2.6.1-2ubuntu0.6 |
| libffi8 | 3.4.6-1build1 |
| libgcc-s1 | 14.2.0-4ubuntu2~24.04.1 |
| liblzma5 | 5.6.1+really5.4.5-1ubuntu0.3 |
| libncursesw6 | 6.4+20240113-1ubuntu2.2 |
| libreadline8t64 | 8.2-4build1 |
| libsqlite3-0 | 3.45.1-1ubuntu2.8 |
| libssl3t64 | 3.0.13-0ubuntu3.16 |
| libtinfo6 | 6.4+20240113-1ubuntu2.2 |
| zlib1g | 1:1.3.dfsg-3.1ubuntu2.2 |

Observed receipt:

    C34T_STATIC_PASS roots=49 linked_elf=68 sonames=19 package_groups=14 signed_external=false root_approved=false

## Reproduction

CI-safe unit tests, without installed system or network reads:

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    python3 -m unittest -v deployment.tests.test_c34t_native_dependency_inventory

Explicit nonprivileged host-audit opt-in, without privileged access:

    OMNILYZER_C34T_HOST_READONLY=1 python3 -m unittest -v \
      deployment.tests.test_c34t_native_dependency_inventory.C34TInstalledHostEvidence

No target binaries or libraries are executed by the host audit. The audit itself runs Python and local system metadata readers, which are not yet independently authenticated under privileged runtime requirements.

## Limits and remaining HOLD gates

- The loader-cache mapping and dpkg-query ownership/version records are local observations. Their values must not be promoted into trusted source/checksum authority.
- Coverage is the static DT_NEEDED ELF closure. It is not an exhaustive inventory of libraries resolved dynamically through Python modules, dlopen, NSS, ctypes, OpenSSL providers, audit hooks or other runtime mechanisms.
- C34T does not authenticate the readelf/ldconfig/dpkg-query executables, external Ubuntu .deb packages or their installed native payload bytes against a signed source.
- It does not verify root-only canonical configuration, seal the full Python source/import closure, resolve the original broker HTTP 403, or authorize final-main adoption, stopped-service migration, backups, crash/rollback, restart or promotion.
- C34T approval fields are hardcoded FALSE: signed_external_packages, sealed_root_imports, root_execution_approved. Earlier C34P-C34S and C34I-C34O approvals are unchanged and non-authorizing.

## Recommended follow-up - C34U

Reuse existing C27 Ubuntu archive-key contracts to independently resolve each of the **14 observed external packages** to signed package indexes and exact binary .deb artifacts from the appropriate Ubuntu Noble suites (noble, noble-updates and/or noble-security). These package versions cannot automatically be assumed to exist in C27's noble-security snapshot.

Compare signed package members to the observed native library bytes, include the dynamic loader, and explicitly assess dynamic-runtime library-loading policy. Only after independent approval should a separate root-owned immutable Python source/import package and privileged isolated execution environment be considered.

**No merge, deployment, service restart, OIDC rotation, installed-file/config alteration, draft root-code execution or promotion retry authorized.**
