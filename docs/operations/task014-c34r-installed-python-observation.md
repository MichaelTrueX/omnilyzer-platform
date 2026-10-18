<!--
File: docs/operations/task014-c34r-installed-python-observation.md
Purpose: Record the actual nonroot, read-only C31A virtualenv and CPython
system executable observation on omnilyzerdev, along with its explicit
limits and future root-package provenance requirements.
Related: deployment/c34r_installed_python_observation.py,
deployment/tests/test_c34r_installed_python_observation.py,
deployment/c34q_python_runtime_compatibility.py,
deployment/python_environment_qualification.py,
deployment/python_interpreter_provenance.py,
deployment/installation_integrity_contract.py,
docs/operations/task014-c34q-python-runtime-compatibility.md,
Task 014 draft PR #190 and incident Issue #182.
-->

# Task 014 C34R — read-only installed Python runtime verification

**Observed on 2026-10-15 using the unprivileged `omnigpt` account.**
No root imports, deployed-application writes, package installation,
service changes, GitHub promotion or workflow authority rotation.

## Objective and reuse

C34Q reconciles the 73-source C34P import closure against the fixed
existing C24/C27/C31A/C31P/C32H runtime requirements. C34R now
collects evidence **from the actual installed virtual environment**
rather than limiting itself to those requirement models.

The implementation intentionally reuses the existing
`qualify_dev_python_environment()` (C31A): the latter verifies
the closed retained repository manifest, then traverses the exact
`/opt/omnilyzer/deployment/venv` tree with no-follow descriptors,
root UID/GID and mode checks, SHA-256 of 197 regular file contents,
all 36 expected directories, all four exact symbolic link targets,
and a no-extra-entry policy. It includes the existing reviewed
distribution metadata and native installed `.so` file contents in
its closed file tree, without importing or executing anything from
the installed environment.

C34R additionally hashes the root-owned regular executable
`/usr/bin/python3.12` by a bounded, no-follow descriptor read
before and after C31A's tree verification. It requires stable inode,
ownership, permissions, size and bytes across both observations.
**Its binary hash is a witness, not an independently approved
Ubuntu artifact-to-installed-binary mapping.**

The nonroot C34R call accepts the C34Q immutable
requirement-consistency receipt and a typed executor configuration
constructed for the **same candidate Git commit**. This input does
not claim to be the inaccessible installed `/etc` executor config.

## Actual observed host evidence

| Checked item | Read-only observation |
| --- | --- |
| Virtualenv root | `/opt/omnilyzer/deployment/venv`, root:root, 0755 |
| C31A file tree | **PASS: 197 regular files + 36 directories + 4 symlinks** |
| Installed venv manifest SHA-256 | `3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b` |
| System interpreter | `/usr/bin/python3.12`; venv launcher resolves to it |
| Installed interpreter file SHA-256 witness | `e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f` |
| Installed interpreter file bytes | `8020928` |
| `dpkg-query` package version | `3.12.3-1ubuntu0.17` on amd64 for `python3.12`, `python3.12-minimal`, `libpython3.12-minimal`, `libpython3.12-stdlib` |
| `dpkg --verify` on those four installed packages | No discrepancies reported in nonroot verification |
| Installed executor config | **NOT READ:** `/etc/omnilyzer/deployment/dev` is root:group mode 0750 and inaccessible to `omnigpt` |
| Trusted signed Ubuntu package-to-binary mapping | **NOT PROVEN** |
| Root execution authorization | **FALSE** |

The installed package version agrees with C27's reviewed Ubuntu
Python archive package version, but agreement and `dpkg --verify`
alone do **not** prove that the installed native interpreter or all
loaded system libraries match a separately verified signed archive.
Nor does the C31A source manifest provide new independent Sigstore
attestation of the individual Python wheels. Do not collapse these
distinct authorities.

The C31A check ran once directly and once via the C34R adapter,
both in the existing nonprivileged isolated repository checkout.
Neither test read or modified the live broker's canonical executor
config or deployed application source.

## New C34R code and acceptance

The complete module
`deployment/c34r_installed_python_observation.py` returns a
`C34RInstalledRuntimeReceipt` only after:

1. Exact C34Q receipt and typed executor review revision agreement.
2. A fixed root-owned/no-symlink system binary read with SHA-256.
3. Existing C31A verified 237-entry virtualenv tree qualification.
4. Repeated interpreter read with identical fingerprint/bytes.

The three distinct approval flags are hardcoded to **False**:
`interpreter_package_approved`,
`installed_executor_config_verified` and
`root_execution_approved`. The input C34Q record remains
`installed_runtime_qualified=False`, because C34Q itself
never inspects the host.

Synthetic tests use mocked host qualifications, reject a changing
system binary, missing venv, malformed evidence, forged approvals,
mismatched source commits, symlinks and untrusted nonroot binaries.
They do not execute draft or installed code with elevated privileges.

## Remaining review gates

Before any root-owned C34O recovery package may be deployed:

1. Independently verify the exact final protected GitHub `main`
   SHA and complete C34P import-closure source package; this
   reviewed PR remains draft and is **not** that final revision.
2. Cross-check the system Python executable and required native
   libraries against their independently signed and reviewed C27
   Ubuntu package artifacts. The observed binary SHA-256 above
   must not become an unreviewed trust anchor by copying it into
   an installer.
3. Verify the canonical actual installed executor/broker configs
   under a separately authorized root-only, stopped-host gate,
   without weakening existing modes or owner/groups.
4. Qualify the sealed complete root-owned import package and
   fixed safe interpreter environment, without loading from
   untrusted `omnigpt` repository or user site-packages.
5. Perform separately authorized disposable privileged root
   migration rollback/restart acceptance, preserving all
   existing source, token, replay/audit and route invariants.

**HOLD:** Do not merge PR #190, stop services, invoke migration
code as root from the Git checkout, reinstall the venv, rotate
OIDC SHA or retry promotion. Incident #182 remains open until
the prior HTTP 403 is understood and recovery/deployment acceptance
is independently reviewed.
