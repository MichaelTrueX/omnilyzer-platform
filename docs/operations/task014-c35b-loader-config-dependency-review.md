# Task 014 C35B — OpenSSL, NSS and Linux Loader Configuration Review

**File:** docs/operations/task014-c35b-loader-config-dependency-review.md

**Purpose:** Provide a nonprivileged and independently reproducible assessment of the observed Linux native-library loader configuration, NSS resolution order, OpenSSL provider configuration and six native ELF dependency sets. Authenticate the newly discovered libcap2 dependency without changing installed services, configuration or privileged execution behavior.

**Related files:** deployment/tests/test_c35b_loader_config_dependency_review.py; deployment/provenance/c35b-loader-config-dependency-review.json; deployment/tests/test_c35a_signed_late_native_modules.py; deployment/tests/test_c34u_signed_external_native_provenance.py; deployment/tests/test_c34t_native_dependency_inventory.py; deployment/tests/test_c34z_main_loader_release_gap.py; .github/workflows/task014-c34d-review.yml; docs/operations/task014-c35a-signed-late-native-provenance.md; draft PR #190; Issue #182.

## Decision — 16 October 2026

**C35B review-only configuration and dependency scope: IMPLEMENTED and VERIFIED. Effective privileged loader configuration and complete dynamic-loading closure: NOT VERIFIED, HOLD. Protected main and root execution: HOLD.**

Reuse the existing C21/C23 application layout, the C35A signed five-native-module evidence and the C27/C34U signing chain. No new runtime directory hierarchy, daemon, launcher, signing key, package installation or dynamic plugin activation is justified by this inspection. The new files are review-only manifest, test and documentation, plus a single existing CI workflow test registration.

Existing broker/ingress/executor source, root-owned Linux configuration, package installations, OIDC, token JSON/localStorage, memory sessions, CSP/CORS, routes, service units, protected main and GitHub authorizations remain unchanged.

## Baseline and method

The observed source baseline was draft PR #190 HEAD a13e64bdcc721cd416c9004fe0683729ade1209a; the protected main was 57919c3b9aca0cb98e85bbb26460f6267d093fa9. Inspections ran as nonprivileged omnigpt on omnilyzerdev. Installed ELF files were never executed or dlopened. Linux configuration files were read and hashed only; readelf -d and ldconfig -p were used as static metadata sources.

Review evidence is retained in deployment/provenance/c35b-loader-config-dependency-review.json, SHA-256 66ecbf08296607a9cb7e07f492f49bd5544164dd383025de3653f72fadebc085, 2,884 bytes. It contains six root-owned configuration file SHA-256 observations, six ELF DT_NEEDED lists, the exact signed libcap2 archive record, and explicitly FALSE loader/root acceptance flags.

## Observed NSS resolution choices

The following effective text was extracted from /etc/nsswitch.conf. This represents the observed configuration, **not** a verified trace of which modules a privileged recovery operation loads:

| NSS database | Configured modules and actions |
| --- | --- |
| passwd | files systemd |
| group | files systemd |
| shadow | files |
| hosts | files mdns4_minimal [NOTFOUND=return] dns |
| networks | files |
| services | db files |

The hosts selector condition [NOTFOUND=return] is semantically important: on the corresponding NSS status it can return without falling through to DNS. A source-to-runtime acceptance must preserve/assess that behavior, rather than silently reorder providers or assume dns always runs. The test rejects altered host module ordering and omission of the NOTFOUND action.

Three previously verified C35A NSS installed module bytes (dns, files and mdns-minimal) and the signed systemd module byte remain in their separate exact signed-content scope. C35B does not prove every future NSS source, process resolver interaction or plugin discovery path.

## Observed Linux native loader search configuration

/etc/ld.so.conf includes /etc/ld.so.conf.d/*.conf. Exactly three existing include-fragment files were observed, owned by root, regular mode 0644:

| Fragment file | Active search directory/directories |
| --- | --- |
| fakeroot-x86_64-linux-gnu.conf | /usr/lib/x86_64-linux-gnu/libfakeroot |
| libc.conf | /usr/local/lib |
| x86_64-linux-gnu.conf | /usr/local/lib/x86_64-linux-gnu, /lib/x86_64-linux-gnu, /usr/lib/x86_64-linux-gnu |

The inspected existing search directories are root-owned mode 0755; /usr/local/lib/x86_64-linux-gnu was absent at the time of observation. **/usr/local/lib and /usr/local/lib/x86_64-linux-gnu remain external search locations relative to the previously signed C34U/C35A native file lists.** Root ownership or an absent directory today does not independently seal future content or prevent newly installed native libraries from changing resolution.

The review test rejects unexpected ld.so.conf.d fragments, unexpected active search lines, unexpected directory modes and loader configuration drift. It does not execute a root process with the effective loader, prove every ld.so.cache entry, prohibit package changes between verification and execution, or independently attest the root-owned configuration ancestors.

## OpenSSL default provider configuration

The observed /etc/ssl/openssl.cnf includes the active directives openssl_conf = openssl_init, providers = provider_sect and default = default_sect. Explicit legacy or FIPS provider activation was **not** observed in this config. The active .include directive was also absent. These observations are not an assertion that the default provider can never be overridden, or that legacy cannot be loaded by explicit application code.

The existing /usr/lib/ssl/openssl.cnf alias points to /etc/ssl/openssl.cnf. The three C35A observed base configuration hashes remain locally consistent but are **not independently signed**. Environmental overrides such as OPENSSL_CONF, OPENSSL_MODULES or library loading from alternate paths have not been exhaustively excluded in a privileged runtime. A future privileged launcher requires its own independently sealed effective environment and OpenSSL provider initialization tests.

## Native ELF direct-dependency closure, new signed libcap2 result

C35B extended C35A by statically reading ELF DT_NEEDED metadata for each of the five already authenticated NSS/OpenSSL module files, plus their newly identified libcap dependency:

| ELF inspected | Direct dependencies observed |
| --- | --- |
| legacy.so | libcrypto.so.3, libc.so.6 |
| libnss_dns.so.2 | libc.so.6 |
| libnss_files.so.2 | libc.so.6 |
| libnss_mdns_minimal.so.2 | libc.so.6 |
| libnss_systemd.so.2 | libcap.so.2, libm.so.6, libc.so.6, ld-linux-x86-64.so.2 |
| libcap.so.2.66 | libc.so.6 |

All direct dependency names except libcap.so.2 were present in the previously authenticated C34U static native-target scope. **libcap.so.2 was an additional dependency not in that original signed set.** It was independently verified:

- Ubuntu package libcap2, amd64, version 1:2.66-5ubuntu2.4, signed noble-security index selection.
- Exact .deb archive size 30,500 bytes; SHA-256 23c627c77c66552a658e62852f244f4946dc543898e0ec5428d5dc6bffde2d6a.
- Installed target /usr/lib/x86_64-linux-gnu/libcap.so.2.66: 51,536 bytes, SHA-256 6ac6abc86ac891c6e13486470e26f1d939f47fda9e6b5d5508a7f5ec881adc84, exactly matching the authenticated .deb tar member.
- Alias /usr/lib/x86_64-linux-gnu/libcap.so.2 → libcap.so.2.66 matched the signed tar symlink.
- Reused C27's pinned Ubuntu 2018 public key and C34U's retained signed noble-security InRelease and its SHA-256-linked Packages index. No new signing trust anchor.

This proves the signed bytes and alias for the **specified libcap2 native file**. It does not prove that the six observed modules constitute an exhaustive set of possible privileged dynamic loads, and it does not independently validate system NSS or OpenSSL effective policy.

Receipt:

    C35B_LOADER_HOLD configs=6 modules=6 signed_extra_libcap=1 uncontrolled_search_dirs=2 config_signed=false complete_dynamic_loading=false root_approved=false

## Requirements-to-implementation traceability

| Requirement | Implementation/evidence | Status |
| --- | --- | --- |
| C35B-01 Preserve exact loader config observations | Six file hash/size records and read-only owner/mode checks | Implemented, review-verified; configuration NOT signed |
| C35B-02 Identify active NSS module choice and action semantics | Six NSS database selectors, NOTFOUND condition tests | Implemented, verified observed text |
| C35B-03 Inspect OpenSSL provider policy and alias | Default-provider declarations, no observed explicit legacy/FIPS activation, symlink target check | Implemented, verified observed subset |
| C35B-04 Identify loader search path risks | Three include fragments, existing and absent search dirs, fail-closed drift checks | Implemented, verified observation only |
| C35B-05 Inventory DT_NEEDED for five known signed modules | Six ELF sets including libcap dependency | Implemented, verified metadata |
| C35B-06 Authenticate extra libcap2 dependency | C27/C34U signed key/release/index + exact .deb tar payload and installed alias/bytes | Implemented, verified scoped provenance |
| C35B-07 Reject forged complete runtime and root approvals | Frozen receipt with four permanently FALSE gate flags | Implemented, tested |
| C35B-08 Independently seal effective privileged OpenSSL/NSS/ELF load behavior | Full environment, external search directories, configuration authority, TOCTOU and runtime trace | Proposed, **NOT VERIFIED** |
| C35B-09 Resolve protected main, C34E broker differences and original 403 | C34Z 11 absent/3 differing source files; Issue #182 | OPEN/HOLD |
| C35B-10 Accept privileged stopped-service migration and recovery | Existing lock, original backups, six-prefix rollback/restart and explicit promotion authorization | NOT APPROVED |

Status definitions: proposed = requirements only; approved = explicit independent decision; implemented = test/review source exists; verified = specified bounded evidence passed; released = approved protected-main activation. C35B is implemented and verified **only as review evidence**.

## Reproduction

Default CI-safe unit tests use only retained Git files and synthetic configuration fixtures:

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    umask 0022
    python3 -m unittest -v deployment.tests.test_c35b_loader_config_dependency_review

Opt-in nonprivileged host audit: stage the exact independently indexed/signed libcap2.deb and noble-security.Packages in a private mode-0700 directory owned by the audit account. No archive is trusted merely for existing in the directory. The test checks exact C27 key, signature, signed Packages digest, selected archive hash, .deb member bytes and symlink, all six configuration files, and six ELF metadata records:

    OMNILYZER_C35B_SIGNED_DIR=/path/to/private/signed-artifacts \
    python3 -m unittest -v \
      deployment.tests.test_c35b_loader_config_dependency_review.C35BActualSignedHostReview

The test never installs/extracts packages onto the host, loads native libraries, executes inspected Python modules, changes environment/units, connects to production PostgreSQL, restarts a process or performs privileged actions. Staged .deb/Packages files are temporary review inputs and may be removed after exact-commit verification. The manifest and signed upstream references remain in the draft PR.

## Architecture impacts and C35C handover

C35B demonstrates that the extra libcap2 native target can be authenticated with existing C27/C34U trust and that no change to the Omnilyzer installation directory structure is required. It also reinforces that static metadata and root-owned configuration hashes **are insufficient** to approve a privileged module loader.

Recommended C35C is **review-only**: independently determine which OpenSSL/NSS configuration sources and external library search paths are effective for the proposed future isolated recovery launcher. Design negative tests for environment/path substitution, NSS provider selection, LD cache and parent-directory mutations and library changes, while preserving existing executor/broker service behavior. Do not install or activate a privileged launcher before independent source, configuration, rollback and root authority approvals.

Required blockers remain: independently attested protected-main 95-entry service/recovery source manifest (11 missing, 3 divergent), three unapproved C34E diagnostic changes, original promotion HTTP 403 root cause, complete Python and native runtime loader seal, root-only canonical configuration, stopped-host exclusive lock, original backups, six-prefix crash/rollback/restart and distinct deployment authorization.

**Authority flags remain FALSE:** privileged_loader_config_signed, complete_dynamic_library_closure, protected_main_approved and root_execution_approved. PR #190 remains DRAFT/unmerged and Issue #182 OPEN. No root execution, merge, installation, service/OIDC/token or config changes, or promotion retry authorized.
