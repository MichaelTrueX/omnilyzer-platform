# File: docs/operations/task014-private-config-cutover.md

# Task 014 — Exact broker/executor configuration migration and rollback

**Status: REVIEW-ONLY DRAFT.** No approval to modify live DEV services, configs,
private registry ACLs, GitHub protected main, replay data, or PROD.

**Related files:** `release/task014_config_cutover.py`,
`release/tests/test_task014_config_cutover.py`,
`release/task014_source_cutover.py`,
`docs/operations/task014-private-source-cutover.md`,
`deployment/broker_service_config.py`,
`deployment/executor_service_config.py`,
draft PR #209 (now targeting main after source-only PR #207 merged) and Task 014 issue #182.

## Scope: reuse exactly two existing canonical configuration files

The DEV deployment uses two existing, independently permission-protected files.
The source-only PR #207 was merged at protected-main commit
`12d849bb0b87361bc1e6e8b05fa9e1e72942011c`; no host installation
was performed as part of that merge:

| Path | Schema | Proposed updates | Must stay unchanged |
|---|---|---|---|
| `/etc/omnilyzer/deployment/broker/dev.json` | 2 | `reviewed_commit` and independently reviewed `expected_workflow_sha` | UID/GID topology, Cosign binary/trust root hashes, runtime/ingress hashes, DEV stage |
| `/etc/omnilyzer/deployment/dev/executor.json` | 1 | `reviewed_commit` | UID/GID topology, exact canary image reference, runtime/ingress hashes, DEV stage |

Both files remain in their current directories. Both retain canonical ASCII JSON
encoding and one final newline, their exact source schemas, root ownership,
service-specific group and existing 0640 mode. Both directories remain root-owned,
service-specific group mode 0750. There is **no new configuration schema, session
store, token store, service or network port**.

**The current unprivileged inspection account cannot read these root-owned live
files.** The exact old configuration values and SHA256 digests have therefore NOT
been verified on DEV. Only a later, separately approved root-controlled preflight
may read them, record their digests and authorize concrete target bytes. Never
invent their historical source SHA, workflow SHA, ACL or authorization contents.

## Review-only configuration generation

`release/task014_config_cutover.py` is an **offline, uninstalled maintenance
library**. It has no executable CLI entry point, automated GitHub workflow
invocation or import-time side effects.

`reviewed_config_plan(...)` accepts:
- independently read actual old broker and executor **canonical bytes**;
- exact independently approved SHA256 checksums of each old file;
- a reviewed 43-file `SourceGenerationPlan`, tied to the one approved Git commit;
- a separately reviewed exact 40-hex GitHub `workflow_sha` for broker OIDC checks.

It uses the existing immutable model parsers and serializers, rejects any unknown
schema field, preserves the entire approved host identity topology and
runtime/ingress digests, and permits only the three explicitly selected field
changes in the table. It does **not** derive `expected_workflow_sha` from the
current branch or automatically equate it to the source revision. The workflow
revision must be separately verified against the final protected-main workflow
and authorized. The plan exposes only four SHA256 digests for public review,
without printing live configuration JSON or credential bytes.

## Protected staging and two-file migration

`readonly_config_preflight(plan)` refuses any symlink, hardlink, wrong
owner/group/mode, unexpectedly changed or oversized canonical file, non-root
directory, or unexpected live bytes.

Only after root-controlled authorization may `stage_configurations(plan)`
create:
- one new canonical broker file and one new canonical executor file, with the
  same final 0640 root:service-group permissions;
- one private old broker backup and one private old executor backup, mode
  0600, retained in their existing protected directories.

Every staged file is created with an exclusive temporary name in the same
filesystem as its corresponding live file, fsynced, and independently verified.
The library never overwrites live configuration during staging.

`activate_configurations(plan, staged)` requires **broker, executor service
and executor socket all stopped**; it rechecks old exact configuration, both
candidate files, and both preserved old backups. Then it uses an individual
`os.replace` and directory fsync per target. If the second update or subsequent
integrity check fails, it attempts to restore both old configurations from the
unchanged, independently pinned old bytes. It verifies the restoration before
reporting a recoverable failure.

**Important atomicity limit:** These configuration files are in **different
directories**, so they cannot be published as one single atomic pair. Each
file replacement is atomic, but the pair can briefly be mixed *while all
control-plane services are stopped*. If restoration itself fails, the library
returns **"configuration state requires manual recovery"**. No service must be
started, and no deployment/replay must proceed in that state. Protected old
backup files must remain available until separately approved retirement.

`rollback_configurations(plan, staged)` requires the same service quiescence,
checks both currently active new files, checks both retained old backups,
restores the precise old canonical bytes, and verifies each result. A partial
failure is flagged as manual-recovery-required, not success.

## Interrupted replacement recovery before any service start

`recover_interrupted_configurations(plan, staged)` is the explicit,
service-quiesced recovery entry point after a crash or power loss between the
individual broker and executor replacements. It requires root, verifies both
private 0600 original backups and accepts only an exact old or exact new
canonical configuration at each of the two live locations. It restores every
recognized new file to its old byte-identical configuration and verifies the
complete old pair. It is **idempotent** when both files are already original.
An unknown, corrupted, mode-changed or symlinked configuration is not
silently overwritten: the operation returns **manual recovery required**, and
all control-plane services must remain stopped.

This interrupted recovery does **not** restore the complete source tree on
its own. Once the two previous configurations have been proven restored,
use the separate `release/task014_source_cutover.py` source-tree rollback
under its exact SHA/owner checks. Never start either service when source and
config generations are mixed. The offline regression suite tests both
recognized mixed states, idempotence and rejection of unknown config bytes.

## Coordinated source/configuration activation (NOT yet authorized)

An independently authorized DEV operator must:

1. Verify the exact reviewed protected-main merge/source SHA, exact 43-file
   application bundle and previous 41-file hashes. Regenerate the canonical
   manifest after any new merge. Do not reuse draft-only manifest SHA.
2. Under root-only preflight, read actual protected JSON configs; independently
   approve the two prior SHA256 hashes, reviewed source SHA, and target workflow
   SHA. Verify the six service identities and unchanged runtime/ingress hashes.
3. Prepare both the 43-file source sibling stage and all four config stage/backup
   files **without activating** either generation.
4. Quiesce broker.service, executor.socket and executor.service under separate
   owner approval. Preserve replay/audit/state and existing root-only backups.
5. Recheck source/config preflight; atomically exchange the entire application
   root; update broker and executor configs while services remain inactive.
6. If config update fails, verify both old configurations restored and exchange
   the source directory back to its 41-file predecessor. If any restore fails,
   leave services stopped and escalate for manual root-controlled recovery.
7. Independently attest the complete installed 43-file directory, new canonical
   configs, exact reviewed workflow SHA, service groups, socket permissions,
   rootless Docker UID/GID 991, the 0700 executor runtime directory, and
   ephemeral 0600 Docker credentials before permitting service acceptance.
8. If service acceptance fails, quiesce services again and restore **both**
   old config files and the entire old application generation. Neither file
   migration function changes the replay database, state, audit, Zot or PROD.
9. A new **signed DEV promotion** remains independently approval-gated after
   this acceptance. Previous run/replay IDs `39119544953` and
   `39220114634` remain consumed. Never reset/reuse them.

**This is an acceptance plan, NOT a command sequence to run now.** No user
approval has yet been given for source/config installation, systemd service
changes, a fresh signed promotion, or PROD operation.

## Offline acceptance evidence

`release/tests/test_task014_config_cutover.py` uses valid synthetic
broker/executor config models and disposable temporary directories. Test-only
patches substitute the unprivileged fixture identity and path; the production
library provides no test/override switch for root checks.

It verifies: exact canonical schema preservation; only two broker fields and
one executor field change; prior SHA-pinned checks; mismatched identities;
regular-file/owner/group/mode and symlink rejection; protected staging;
complete successful two-file migration and rollback; refusal on active-service
state; failed second-file replacement restoring both; tampered backup rejection;
durability-failure rollback; manual-recovery signaling when rollback itself
fails; interrupted mixed-pair recovery; and strict rejection of unknown state. Combined tests exercise the actual source-directory exchange followed
by configuration replacements, then coordinated restoration. Tests perform
**no** real DEV configuration reads or changes, service operations, Docker
pulls, OIDC requests or signed promotion.
