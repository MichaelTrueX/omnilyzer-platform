# File: docs/operations/task014-dev-root-readonly-attestation.md

# Task 014 — Root-controlled read-only DEV preflight

**Status:** Draft for independent review. No elevated DEV access, source
installation, configuration update, systemd restart, Zot registry operation,
replay reset or signed promotion is authorized by this document.

**Related:** `release/task014_dev_readonly_attestation.py`,
`release/tests/test_task014_dev_readonly_attestation.py`,
`release/task014_source_cutover.py`,
`release/task014_config_cutover.py`,
`deployment/broker_service_config.py`,
`deployment/executor_service_config.py`,
`docs/operations/task014-private-source-cutover.md`,
`docs/operations/task014-private-config-cutover.md` and issue #182.

## Why this additional preflight is necessary

The two canonical DEV configuration files are protected by distinct
root:service-group permissions. The connected unprivileged DEV account
(`omnigpt`) cannot read either file. This is the correct security boundary;
do **not** modify file permissions, add `omnigpt` to a service group, or
grant blanket passwordless sudo simply to inspect them.

The source-only PRs #207 and #209 are already merged. At the time of this
document, protected main is
`ddbd1f80e68f438adf757b77cfb93989e46bde1a`. The independently
regenerated 43-entry canonical source manifest SHA256 was
`3c88a2cae54d613036166a7b5fb22a2c2764d909c106db679b88273fc2db30c6`.
This SHA includes the reviewed Git commit and **must be regenerated when
the approved source commit changes**.

The actually installed old application root contains 41 root:root, mode
0644 files; the new closed 43-file set has exactly nine file replacements
and two additions. Neither missing private-registry module is installed.
Broker/socket/Nginx have been active, while executor.service has remained
in its historical failed state. No new signed promotion has been triggered.

## What is inspected and what is never disclosed

The new module `release/task014_dev_readonly_attestation.py` has no command
line interface, import-time execution, network access or privileged action.
It contains only an independently callable read-only attestation function.
It checks, without updating any live file:

- All 41 exact old application source paths and SHA256 values against the
  previously reviewed old generation. Every regular file must be root:root
  0644, each allowed directory root:root 0755, with no symlinks or extras.
- Broker config at `/etc/omnilyzer/deployment/broker/dev.json`, requiring
  directory root:990 mode 0750 and file root:990 mode 0640.
- Executor config at `/etc/omnilyzer/deployment/dev/executor.json`,
  requiring directory root:991 mode 0750 and file root:991 mode 0640.
- Both canonical schema parsers (broker schema 2, executor schema 1);
  duplicate/unknown fields and noncanonical bytes are rejected.
- Same reviewed old Git commit and identity topology in both configurations;
  unchanged runtime and ingress hashes. Installed user/group identities are
  broker 990, executor 991, replay 992, socket 993.
- Executor systemd sandbox, including service user/group, strict
  `ProtectSystem`, `UMask=0077`, private runtime directory 0700 and the
  reviewed rootless Docker socket bind.
- Only these four unit activity states: broker, executor socket, executor
  service and Nginx. It does **not** reset or start services.

**Allowed output:** final candidate manifest checksum, existing broker and
executor configuration SHA256 hashes, reviewed installed source commit,
currently pinned GitHub workflow SHA, a bounded sandbox validation result,
and the four systemd status strings. No raw JSON, OIDC JWT, environment
variables, Docker auth, private contents, journal, replay or certificate.

An attestation failure yields a generic HOLD rather than leaking file
contents or attempting a correction.

## Execution prerequisites (future, NOT currently approved)

1. Obtain **separate owner authorization for a root-controlled read-only
   preflight**. Source-only merge approval does not include this.
2. Make the **exact approved merged source** available through a trusted,
   root-owned, read-only checkout or verified bundle. Do not run privileged
   Python from an untrusted, user-writable checkout or Git branch.
3. Independently construct `SourceGenerationPlan` using the reviewed exact
   commit and confirm the full 43-file manifest SHA. Verify the code files
   match reviewed SHA256 values before privileged imports.
4. Invoke `attest_dev_host(reviewed_source_plan)` under the authorized root
   session and capture *only* `evidence.to_dict()` in the controlled
   approval record. Do not print configuration bytes or include privileged
   source files in Git commits or issue comments.
5. Verify both old file hashes and reported source/workflow revision pins
   independently. A mismatch with the reviewed predecessor means HOLD.
6. Do not create staging, modify `expected_workflow_sha`, stop services,
   generate OIDC credentials, pull Docker images, or consume replay as part
   of this **read-only** preflight.

The planned cutover (source exchange, config migration, service quiescence,
rollback and actual rootless executor acceptance) is a **different operation
with a separate authorization**. Both root-protected configs must be pinned
before approving that operation.

## Automated testing and evidence boundaries

`release/tests/test_task014_dev_readonly_attestation.py` uses synthetic
canonical service authority values and disposable files. Its patches for
temporary paths and unprivileged test owners are **test-only**: the production
library has no test/bypass argument.

The tests cover valid nonsecret attestation, required root authorization,
exact installed 41-source hash set, prior workflow/source pins,
cross-service identity, canonical JSON checks, protected file permissions,
symlink/hardlink/path integrity, rootless systemd sandbox drift, allowlisted
systemd properties, and error redaction.

This does **not** assert actual privileged host acceptance. The current
unprivileged host view is incomplete by design and must not be presented as
the completed root-only preflight.

## Strict release boundaries

Task014 replay entries for earlier failed promotion runs remain consumed;
never reset or reuse them. Release `0.14.5` has not been deployed. Private
Zot must stay private, with no anonymous registry read permission. PROD
remains untouched.

Any future signed DEV promotion requires new, separately approved GitHub
workflow execution after complete installed-state and rollback acceptance.
