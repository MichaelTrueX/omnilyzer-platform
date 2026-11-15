# Shared AI Operations v0.1 - Sumlaude and Omnilyzer

**Status: source candidate only, not installed or activated in production.**
The operating concept is permanent, not a one-time sudo exception.
Every privileged job remains tightly bounded and source-verified.

## Architecture and trust boundary

- `sumlaude-agent` is a dedicated Linux user on `truexmainserver`;
  `omnilyzer-agent` is reserved for `omnilyzerdev`.
  Neither belongs to sudo, docker, adm or the PostgreSQL group. A separate
  OAuth device pairing is required for each host.
- Each account runs its own Desktop Commander **as that non-admin user**.
  The existing `trusthansen` remote device retains its current sudo block.
  Do not weaken or disable that block.
- A root-owned polkit rule allows each agent only the **start** verb on its
  corresponding `<product>-ai-ops@<job>.service` systemd units.
  It grants no control over arbitrary services, unit files or sudo.
- systemd starts a **root-owned** `dispatcher.py` with no custom arguments
  besides the product and the unit instance name, which are strictly checked.
  Root-owned `/etc/shared-ai-ops/policy.json` registers the job names and
  exact SHA256 of root-owned job files. There is no arbitrary command input,
  shell interpretation, dynamic interpreter path or agent-writable policy.
- The dedicated service is sandboxed with private devices/tmp, no privilege
  escalation, restricted kernel controls and product-specific write paths.
  Each run emits journald markers and an exact systemd exit result.
- Adding a new privileged capability requires a source-reviewed root-owned
  job and policy update. **The agent cannot register its own root code.**
  After such registration, approved executions need no more terminal sudo.
  This is not a way to bypass the Product Owner's release approvals.

## Initial registered operations

| Product | Job | Actual effect |
| --- | --- | --- |
| Sumlaude | `status` | Reports whether protected S03 108-110 postcommit receipt is present. Read-only. |
| Sumlaude | `cleanup-108-110` | Requires exact original SHA-pinned 108-110 SQL and root operator, root file ownership/modes and independent COMMIT/postcheck receipts. Deletes only protected temporary SQL and the superseded one-shot operator. Root-only audit receipts remain. |
| Omnilyzer | `status` | Reports agent dispatcher readiness on `omnilyzerdev`. Does not activate Analytics or touch Task014. |

Further deployments, backups, restore rehearsals and system changes are **not yet
registered privileged operations**. Their own exact-source operators must be
reviewed and registered before unattended execution. A content or application
release is not automatically authorized by having this service installed.

## Installer and owner bootstrap

The canonical source is
`deployment/shared_ai_ops/` in a dedicated branch of
`MichaelTrueX/omnilyzer-platform`. `install-root.py` verifies fixed SHA256
for all source files before any operating-system modifications. It creates
the appropriate non-admin OS user, installs root-owned policy, job files,
polkit rule and systemd templates, and reloads systemd. It does **not** start
any migration, run cleanup, install the Desktop Commander package,
start an agent, expose a port, request a password, or enable a root service.

A local administrator first copies the SHA-reviewed installer to a protected
root-owned file, independently verifies its SHA, and runs that protected copy.
Do not `sudo python` a user-writable checkout. The exact owner bootstrap
command and staging SHA are recorded in the PR handoff once the candidate is
committed and copied to the correct server. Do not use an unpinned latest file.

**One-time OAuth pairing after installer PASS** on the intended host:

1. As the newly created product-specific OS user, install a fixed version
   of `@wonderwhy-er/desktop-commander` (currently pinned proposal `0.3.1`)
   inside its private home; no `sudo` within the agent account.
2. Start `/usr/bin/node` on the installed `dist/index.js remote` once.
   Product Owner confirms the displayed OAuth verification code **in the
   Desktop Commander UI**, not in the chat. Never share credentials/codes.
3. Once paired, stop that foreground instance and the administrator enables
   the preinstalled `<product>-agent-remote.service` for boot. It runs as
   the dedicated user with its home as the only writable filesystem path.
4. Confirm that Desktop Commander shows the new device separately and that
   its remote process genuinely runs as `sumlaude-agent` or `omnilyzer-agent`.

Example authorized connected-agent operation AFTER pairing:

    systemctl start sumlaude-ai-ops@status.service
    systemctl show sumlaude-ai-ops@status.service -p Result -p ExecMainStatus --no-pager

When the owner-approved postcommit cleanup job is run:

    systemctl start sumlaude-ai-ops@cleanup-108-110.service
    systemctl show sumlaude-ai-ops@cleanup-108-110.service -p Result -p ExecMainStatus --no-pager

A systemd status `success` is necessary, but it is NOT a substitute for checking
the specific root job's success markers and the unchanged protected audit data.
The connecting ChatGPT client must target the new dedicated-agent device ID
explicitly, not the existing `trusthansen` device.

## Security and operational limits

- No general sudo, sudoers `ALL`, SSH key injection, password sharing,
  privileged desktop process or user-writable root scripts.
- Neither product can start the other's job. The dispatcher rejects wrong
  host, unknown job, foreign policy/owner/mode, changed source SHA and
  unregistered parameters.
- Source changes require review and a root-owned policy update; do not build
  an unsupervised arbitrary-root deployment broker.
- Authentication of an 18+ learner, S01/M01 browser acceptance, school-admin
  feature activation and Analytics 0.16.0 Task014 are not implied by the
  existence of an operations agent.
- To revoke agent permissions: disable its remote systemd service and remove
  its polkit rule or revoke its Desktop Commander device; keep required audit
  receipts. The dedicated OS user can remain locked.
- Existing S03 one-shot mutation receipts are not discarded. Future generic
  DB release support must bind exact signed provenance, changed-risk QA, owner
  GO, preflight and postcommit readback before adding that registered job.

## Focused DEV-only verification

No paid GitHub Actions:

    python3 -m py_compile deployment/shared_ai_ops/*.py deployment/shared_ai_ops/jobs/*/*.py
    node deployment/shared_ai_ops/tests/test_polkit_policy.cjs
    systemd-analyze verify deployment/shared_ai_ops/*.service
    bash deployment/shared_ai_ops/tests/test_dispatcher_isolated.sh
    bash deployment/shared_ai_ops/tests/test_installer_isolated.sh

The last two tests run **isolated disposable containers** with `--network none`
on authorized development infrastructure; they never access production.
