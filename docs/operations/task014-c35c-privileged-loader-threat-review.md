# Task 014 C35C — Privileged Loader Isolation and Path Substitution Threat Review

**File:** docs/operations/task014-c35c-privileged-loader-threat-review.md

**Purpose:** Assess whether observed non-root service isolation, loader configuration, library path trust, inherited environment and root-owned parent directories are sufficient for a future privileged C34O recovery process, without executing or installing such a process.

**Related files:** deployment/tests/test_c35c_privileged_loader_threat_review.py; deployment/provenance/c35c-privileged-loader-threat-review.json; deployment/tests/test_c35b_loader_config_dependency_review.py; deployment/tests/test_c35a_signed_late_native_modules.py; deployment/tests/test_c34w_installed_source_feasibility.py; deployment/tests/test_c34z_main_loader_release_gap.py; .github/workflows/task014-c34d-review.yml; docs/operations/task014-c35b-loader-config-dependency-review.md; PR #190; Issue #182.

## Decision and historical baseline — 16 October 2026

**C35C: nonprivileged bounded threat assessment IMPLEMENTED and VERIFIED. Future privileged loader closure, sealed root runtime and deployment are NOT IMPLEMENTED, NOT APPROVED and remain on HOLD.**

The baseline before C35C was draft PR #190 commit 300282c3a783b8acfbb1a76f2971d4354a3c5f69; protected main 57919c3b9aca0cb98e85bbb26460f6267d093fa9. No merge or service deployment has occurred. Read-only review on omnilyzerdev used user omnigpt.

C35C adds only a historical JSON observation manifest, CI-safe synthetic security tests, an opt-in nonprivileged actual-host metadata audit, this handover document, and test registration in the existing Task 014 workflow. No privileged code is executed, no service or configuration modified, no package installed, no source directory added, and no existing token, OIDC, memory-session, CSP/CORS or route semantics changed.

## Verified scope: units, loader config and parent paths

The C35C snapshot covers four root-owned systemd files: broker.service, executor.service, executor's rootless-docker-socket.conf drop-in and executor.socket. It covers seven host configuration files: ld.so.cache, ld.so.conf, three loader fragments, nsswitch.conf and openssl.cnf. Each is content-addressed with its observed SHA-256 and size. Parent-directory observations cover 20 path entries, including the /lib -> usr/lib symlink and currently absent /usr/local/lib/x86_64-linux-gnu.

**The broker and executor services were observed inactive during this audit.** No start or stop action was taken. This is an observed state, not proof the processes cannot later start.

Both service files use dedicated non-root identities (omnilyzer-broker and omnilyzer-executor), the established /opt/omnilyzer/deployment virtualenv Python command and application working directory. Their service definitions specify:

- NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes;
- UMask=0077 and empty AmbientCapabilities/CapabilityBoundingSet;
- Additional existing device, kernel and namespace restrictions.

The test verifies those directives and the complete exact unit-file hashes; it also detects a new/unreviewed systemd service drop-in. **These safeguards apply to those systemd unit processes. They do not transfer automatically to an independent root-owned recovery launcher.** No such root launcher has been installed or approved by C35C.

The host's root-owned mode-0755 parent directories and /lib symlink match the retained observation. A single directory metadata snapshot cannot eliminate time-of-check/time-of-use races, subsequent package installation or path substitutions. In particular, /usr/local/lib exists, is root-owned 0755 and currently contains a python3.12 directory; /usr/local/lib/x86_64-linux-gnu is absent but remains in the existing loader configuration. Neither path is thereby approved as an immutable privileged ELF search root.

## Loader configuration and environment injection

C35B previously observed six static ELF dependency records and authenticated the extra libcap2 native file, using the existing C27/C34U signed Ubuntu evidence. C35C reuses C35B's pinned manifest and adds:

1. Read-only SHA-256/size comparison of the existing loader cache, configuration fragments, NSS and OpenSSL configuration.
2. No-follow ownership/mode checks for specified root-owned parent directories and explicit recognition of the single observed /lib -> usr/lib symlink.
3. Exact source-unit hash checks and scrutiny of dedicated nonroot accounts and service hardening, including the executor drop-in.
4. A **pure proposed model** of a future root-only environment, permitting only LANG=C, LC_ALL=C, PATH=/usr/bin:/bin, TZ=UTC. Synthetic negative tests reject all unreviewed environment keys, especially LD_*, PYTHON*, OPENSSL_*, NSS_*, BASH_ENV, ENV, GCONV_PATH, IFS and LOCPATH, as well as altered PATH values.
5. Fail-closed tests for forged privilege approvals, changed JSON evidence, duplicate JSON keys, dangerous symlink parents and unexpected creation of the absent external search directory.

The proposed environment model was **not** installed, applied to any existing service or validated for application compatibility. It is not a complete sandbox specification; additional process attributes such as working directory, inherited file descriptors, Linux secure-execution mode, locale, system library cache resolution and subprocess environment must be reviewed before approval. The test does not inspect or reveal live environment values or secrets.

These observations neither certify a complete runtime dlopen closure nor prove the root launcher would use these exact config and library paths. The effective loader/NSS/OpenSSL behavior, root-controlled immutable configuration, provider activation, unreviewed dynamic modules and replay/rollback correctness remain separate unverified obligations.

## Evidence and acceptance

Historical manifest: deployment/provenance/c35c-privileged-loader-threat-review.json, 4,329 bytes, SHA-256 318d4911219e75875454a9661fe18f214b93e8e2f2fa27d8d2b3a238db50bff7. This is a review-only immutable source snapshot **not** an Ubuntu-signed or independently approved protected-main root artifact.

The optional host audit deliberately returns:

    C35C_PRIVILEGE_HOLD units=4 config_files=7 path_entries=20 services_inactive=true env_model_only=true root_launcher_installed=false loader_sealed=false root_approved=false

## Requirements-to-implementation traceability

| ID | Requirement | Implementation/evidence | Status |
| --- | --- | --- | --- |
| C35C-01 | Verify existing unit metadata and nonroot protections | Four exact SHA-pinned unit files, static directive checks and read-only inactive-state observation | Implemented, verified observation |
| C35C-02 | Account for systemd drop-in overrides | One existing executor drop-in recorded, unexpected extras fail closed | Implemented, verified scope |
| C35C-03 | Observe loader cache and NSS/OpenSSL config without mutation | Seven pinned configuration files, C35B source linkage | Implemented, verified observation; NOT signed config |
| C35C-04 | Inspect root-owned path ancestors, symlinks and missing external directory | 20 closed path records, negative tests for substitutions and drift | Implemented, verified time-bounded observation |
| C35C-05 | Model a minimal root environment and deny injection | Exact four-key synthetic model and poisoned-env negative tests | Implemented, model verified; NOT activated |
| C35C-06 | Never equate systemd nonroot hardening with root permission | Five immutable false approval flags in frozen receipt | Implemented, verified |
| C35C-07 | Independently freeze effective privileged loader and root source | No trusted root launcher, no runtime-native-load trace, external loader paths not sealed | Proposed, NOT verified |
| C35C-08 | Resolve protected main, broker HTTP 403 and operational recovery | 11 main-missing / three differing files, original Issue #182 and stopped-host/five-original/six-prefix controls | OPEN, HOLD |

**Status vocabulary:** proposed = design requirement; approved = separate explicit decision; implemented = draft review code/files exist; verified = only identified test or observation passes; released = approved production activation. C35C is implemented and verified **only as review evidence**, not approved or released.

## Reproduction

Default nonprivileged synthetic regression suite (no host access required):

    cd /home/omnigpt/repos/omnilyzer-platform/.task014-c34f-review
    umask 0022
    python3 -m unittest -v deployment.tests.test_c35c_privileged_loader_threat_review

Explicit observational host audit, skipped by CI unless requested:

    OMNILYZER_C35C_HOST_READONLY=1 python3 -m unittest -v \
      deployment.tests.test_c35c_privileged_loader_threat_review.C35CRealHostReview

If an existing service is running, a configuration file or directory changes, or any trusted path is missing, the current audit is intended to fail closed; it does not attempt to stop/start anything. An operator must reassess the current state and use the separate privileged stopped-host gates before any future mutation.

## Next handover and decision required

Proposed C35D should be **a release-gate consolidation review**, not another privilege escalation step. Evaluate whether further nonprivileged discovery would materially reduce the remaining risks, prioritize the original 403 diagnosis, reconcile the 11 missing protected-main source files and three unapproved C34E diagnostics, and require separate approval before writing or executing a privileged root-owned launcher. Avoid duplicating the existing C27/C34U provenance or inventing new directories.

A root execution proposal needs an independently attested protected-main package/loader/bootstrap, a complete set of native and Python load origins, authority over root-only configuration, stopped-service exclusive lock, C34K original backups, C34O six-prefix crash recovery and rollback/restart acceptance, plus explicit user approval. Preserve all existing routes, JSON-token/localStorage behavior, OIDC/authorization, memory sessions, CSP/CORS, protected services and rollback guarantees.

**Do not merge PR #190, deploy, start/stop units, modify system config, execute draft code as root, rotate OIDC/authorization secrets, or retry promotion.** All privilege flags remain FALSE.
