<!--
File: docs/operations/task014-c34h-isolated-rehearsal.md
Purpose: Explain non-live five-file staged replacement, recovery, and rollback
acceptance for the still-unmerged C34E broker diagnostics.
Related: deployment/c34h_transition_rehearsal.py,
deployment/tests/test_c34h_transition_rehearsal.py,
deployment/c34g_migration_authority.py,
deployment/c34g_installed_predecessor_preflight.py,
docs/operations/task014-c34f-application-generation-evidence.md,
Task 014 issue #182, draft PR #190.
-->

# Task 014 C34H — disposable migration recovery rehearsal

**Release-authority addendum (C34I/C34J):** this earlier stage models
C34D's authorized workflow SHA only while validating the **predecessor** or
unmerged C34E proposal. After a final protected-main merge, GitHub OIDC
`workflow_sha` changes to that merge SHA; the final broker must atomically
advance both `reviewed_commit` and `expected_workflow_sha` to that exact
approved revision under separate authority. See
`docs/operations/task014-c34i-host-transition-gates.md` and
`docs/operations/task014-c34j-atomic-file-mechanics.md`.
This addendum supersedes any earlier suggestion that the old workflow SHA
could be retained for future main-based promotions.


**Review only. Does not install or authorize anything on omnilyzerdev.**

## Verified baseline

The operator's SHA-256-verified C34G read-only preflight reported:

```
C34G_PREFLIGHT_PASS source_41_exact config_pair_canonical workflow_pin_c34d services_unchanged
C34G_NO_MUTATION_NO_DEPLOYMENT
```

This was the live **predecessor verification** only. It did not qualify
migration or repair authorization. The active C34D workflow authority is
`57919c3b9aca0cb98e85bbb26460f6267d093fa9`.

## C34H test-only scope

The new `C34HIsolatedRehearsal` constructor refuses root execution,
creates its own private temporary directory and populates it with
**all 41 old Git application blobs** and synthetic broker/executor configs
whose values satisfy C34G's closed identity policy. The caller cannot
select `/opt`, `/etc`, a registry endpoint or live workflow pin.

A synthetic transaction advances exactly five bounded source/config
replacements, in the sequence defined by C34G:

1. `deployment/broker.py`
2. `deployment/broker_https_ingress.py`
3. `deployment/broker_integration.py`
4. Canonical executor configuration `reviewed_commit`
5. Canonical broker configuration `reviewed_commit`

At each step, the simulator validates all 41 source SHA-256 digests,
reparses both strict canonical configs, verifies the current C34G
prefix, stages an exact byte payload in the destination directory,
flushes/fsyncs the stage, replaces one file and fsyncs the directory.
It never changes the workflow authorization SHA.

## Interruption and negative acceptance

The synthetic fault points are:

- `after_stage_create`: zero-length stage, no destination mutation
- `after_half_write`: recoverable validated payload prefix
- `before_replace`: full durable stage, old destination intact
- `after_replace`: new destination already published

After a simulated interruption, the next call checks the classified
source/config phase; it either resumes the exact stage prefix or advances
from an already completed step. Synthetic rollback proceeds in the
reverse C34G order (broker config, executor config, source modules).
Unexpected staged content, unlisted path/digest or source symlink
causes a hard stop. No auto-retry can contact a live deployment.

## Limits — NOT a privileged installer

The simulator deliberately does **not** claim any of the following:

- Root-only installed file owner/GID/mode verification on a running host
- A durable root-owned on-host backup or sealed payload package
- Exclusive host process lock or rootless Docker preservation evidence
- Secure stage-directory fd lineage, journal retention and power-loss
  semantics under real process crashes
- Root-only stopped broker/executor/socket service management or restart
- Approval of eventual merged `main` SHA, which differs from current
  unmerged C34E source proposal `9289bbc...`
- A new DEV promotion or proof of the original HTTP 403 root cause

These remain mandatory before a root-capable C34H successor migrator
could be reviewed. In particular, changing any active broker file by
hand would violate the pinned full 41-file source and configuration
authority. No live migration is to be attempted from this draft.
