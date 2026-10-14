<!--
File: docs/operations/omnilyzer-ai-development-workflow.md
Purpose: Durable developer/AI working agreement for Omnilyzer development with
GitHub and Remote Desktop Commander. Defines security boundaries, source-of-
truth rules, verification, incident handling and low-friction user handoff.
Related: .github/workflows/, deployment/README.md, docs/adr/,
Task 014 GitHub issues #181 and #182.
-->

# Omnilyzer — AI-assisted development operating procedure

## Scope

Use this workflow for Omnilyzer Platform development on `omnilyzerdev`.
GitHub is the source of truth for reviewed source and immutable release history.
Desktop Commander is the direct, **unprivileged** remote inspection and testing
channel. Administrative `trust` operations remain a separate, explicitly
authorized change-control lane. Do not confuse a test PASS with deployment
authorization.

### Lane A — GitHub source, review and CI

1. Read the latest `main` ref, relevant open issues/PRs and applicable
   README/ADR/contracts **before proposing edits**.
2. Use one isolated, descriptive feature branch per issue. Maintain a complete
   change inventory. Do not silently discard or rewrite existing code.
3. Keep external interfaces, routes, localStorage token flow, API responses,
   tenant isolation, CSP/CORS, and service authentication contracts unchanged
   unless the proposed change explicitly addresses them and has negative tests.
4. Prefer the established Python business/security boundary when moving
   functionality from JavaScript; do not migrate UI interactions blindly.
5. Add focused regression tests, broad security-critical tests and relevant
   source-integrity checks. Use PR CI without deployment environment secrets.
6. Link full source files with explicit repository paths and exact commit SHAs;
   retain a concise change log and rollout/rollback instructions.
7. For operational or security changes, get the reviewed merge SHA **before**
   changing root-controlled authority. No unreviewed PR-to-live shortcut.

### Lane B — Desktop Commander direct development access

Connected device: `omnilyzerdev`. Unprivileged agent: `omnigpt`.

- Allowed directories remain the existing Omnilyzer and GTM repository roots.
- Keep `sudo`, `su`, user management, system power/network controls and
  other dangerous commands blocked. Do not elevate the connector to root.
- Default to `read_file`/`read_multiple_files`, bounded searches, and
  read-only `start_process` commands for inventory, diffs and tests.
- Never inspect or export raw JWTs, cookies, access tokens, private keys,
  OAuth configuration values, auth databases, user data or full logs containing
  sensitive headers. Print only status, hashes and coarse failure stages.
- Maintain a **separate clean worktree** for new tasks if the checked-out
  repository has existing uncommitted work. Do not clean, reset or prune the
  historic Task 014 staging assets without a reviewed inventory and approval.
- Run test commands in the unprivileged environment. Docker/systemd mutations,
  direct deployments, dependency upgrades and service restarts are privileged
  change-control actions, not casual diagnostics.
- If Remote Desktop Commander is offline or over quota, use a **single**
  SHA-verified user-run diagnostic where necessary, not repeated PowerShell
  copy-and-paste loops.

### Lane C — root-controlled change operations

Administrative operations are separate from Desktop Commander and require
operator authorization through `trust` or an independently reviewed deployment
authority. Only a complete root-controlled script is acceptable where a
privileged change is needed. It must:

1. Freeze `main` and verify exact reviewed source/config digests and current
   service identities.
2. Refuse unexpected state; validate source and script SHA-256, users,
   permissions, mount points, lock ownership and service dependencies.
3. Write a local root-owned backup before mutation; identify non-idempotent
   publication boundaries and recovery actions.
4. Preserve deployment state, replay, audit, registry credentials, rootless
   Docker, restricted listener, ingress policy and existing client routes.
5. Apply at most the explicitly authorized operation; no hidden retry.
6. Revalidate the running process **after restart** because broker workflow
   authority is loaded at startup.
7. Capture a redacted success/failure receipt. Never infer success from
   a subprocess exit alone if on-host postconditions remain unverified.

### Deployment issue #182 (2026-10-14 hold)

The October 13 DEV promotion returned HTTP 403 after the GitHub runner had
connected through Tailscale and acquired deployment/registry OIDC tokens.
The historical replay and audit inspection could not attribute the rejection.
The C34D **workflow-only** diagnostic was merged at
`57919c3b9aca0cb98e85bbb26460f6267d093fa9` without changing the
protected broker source files. The existing active server remains pinned
to its preceding accepted `main` until a controlled authority rotation.
Do **not** dispatch a DEV promotion or merge another revision while that
exact-SHA rotation/one-attempt plan is in progress.

C34C PR #183 changes protected application files and remains an alternate
diagnostic design, not a license to copy broker modules into place.

### Standard low-repetition task pattern

For each assignment: discover current facts in one batch; author a compact
scope/risks plan; implement on a branch; execute CI and fix failures; compare
final source against original; report exact tests, changed files and next
authorized action. Ask the user for manual intervention only when a security
boundary forbids the connected tools from performing the operation.

This document is a durable technical handover, not a substitute for reviewing
the current GitHub state on every new task. Do not automatically modify memory
or assume documentation changes are already merged into `main`.
