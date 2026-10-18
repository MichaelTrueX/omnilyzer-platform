# Task 014 P0 - Draft Diagnostic Instrumentation and Recovery Model Acceptance

**Date:** 16 October 2026  
**Status:** Isolated PR implementation + synthetic verification; NOT installed, released, merged or operationally accepted.  
**Related:** [Issue #182](https://github.com/MichaelTrueX/omnilyzer-platform/issues/182), [draft PR #190](https://github.com/MichaelTrueX/omnilyzer-platform/pull/190), `docs/operations/task014-p0-403-security-change-control-review.md`, `docs/operations/task014-p0-403-rejection-origin-contract.md`.

## Purpose and interpretation of authority

Following the product owner's "continue", advance the **isolated PR review** to the narrow diagnostic source/candidate and offline fault tests, without changing the installed DEV services or authoritative root migration plan. This document is an **implementation-status addendum**, not a replacement for the preceding chronological research records. Previous statements that "listener instrumentation is not implemented" refer to the state **before this draft implementation**; now it is implemented **in the unmerged PR only**, **not** on the host.

**Absolutely excluded from this authorization:** merge to main, live origin reload, Nginx log creation, Tailscale changes, privileged source or configuration writes, protected source installation, service start/restart, replay/audit changes, real JWT or OIDC traffic, dispatch/retry of promotion, G0 closure, authorization or production releases.

## Exactly what was changed on the review branch

| Component | Implemented review-only change | Operational state |
| --- | --- | --- |
| `deployment/broker.py` | Adds exactly `task014_diag stage=listener_framing_rejected` to C34E's existing bounded fixed allowlist, 13 -> 14 messages | Git candidate only |
| `deployment/broker_loopback_listener.py` | On `_FramingRejected`, assigns the original fixed `_REJECTED` response **first**, then best-effort logs that fixed literal through the shared private logger, suppressing ordinary diagnostic exceptions | Git candidate only |
| `deployment/ingress/dev-broker-tailscale-origin.status-only.review.conf` | Separate, **non-installed** origin candidate with `log_format task014_status_only 'status=$status upstream_status=$upstream_status';` and a dedicated status-only log directive | Git candidate only, do not copy into conf.d |
| `deployment/tests/test_c34e_diagnostic_events.py` | Extends AST static stage privacy verification to the listener, fixes expected allowlist count at 14 | Isolated regression test |
| `deployment/tests/test_task014_p0_403_rejection_origin.py` | Maintains evidence of three byte-identical fixed HTTP 403 sources, while verifying new listener-stage presence | Isolated regression test |
| `deployment/tests/test_task014_p0_403_instrumentation.py` | Exercises stage emission, malformed HTTP framing, unchanged 202/403/503, logger failure and suppression, status-only variable whitelist, exact Nginx server equivalence and optional isolated `nginx -t` | Isolated regression test |
| `deployment/tests/test_task014_p0_six_file_recovery_model.py` | Tests **synthetic** six-original backup and all seven forward/reverse interruption states, missing/corrupted/symlinked originals and fail-closed prefix mismatch | **Test model only**, NOT operational C34K/C34O replacement |
| `.github/workflows/task014-c34d-review.yml` | Registers both new test modules in existing read-only PR CI | Review CI only |

Original installed Nginx `/etc/nginx/conf.d/omnilyzer-task014-dev.conf` is unchanged with `access_log off`. The current `deployment/ingress/dev-broker-tailscale-origin.nginx.conf` remains unchanged as well. The new candidate is **not** included by any installed config. Origin status-only log path and its permissions/retention are placeholders for later operator approval: even correct `nginx -t` syntax cannot authorize installing or enabling it.

## Security invariants reviewed

- Only a **static** private `listener_framing_rejected` event is new. It is handled by the same in-process C34E allowlist/rate filter (maximum 32 events per 60 seconds across stages). No tokens, request bytes, headers, IDs, IPs, claims, JWTs or exception contents enter the event.
- The logger is **not** allowed to alter public 202/403/503. The fixed 403 response is selected before logging; ordinary logger exceptions are swallowed. It does not change framing bounds, handler dispatch, replay or signature validation.
- Listener-origin `403`, semantic ingress `403`, and downstream broker `403` continue to be indistinguishable in the public wire representation. Internal logging provides possible *additional future* evidence, not proof of historical request provenance.
- A missing private event still means UNKNOWN, possibly due to logging suppression, service inactivity, access policy or edge rejection. The Nginx candidate records only self-generated status fields, with no client-controlled or request-body variables in `log_format`.
- The static candidate Nginx server directives are byte-identical to the current origin after replacing the deliberate dedicated log directive with original `access_log off;`. Testing `nginx -t` is performed only with an isolated nonprivileged temporary `nginx.conf`, a synthetic log path and no service operation.

## Six protected originals and seven interruption prefixes

Adding `deployment/broker_loopback_listener.py` creates **four** changed protected application modules plus the existing **two** canonical authority configurations, hence **six** originals and prospective **seven** interruption states (prefixes 0..6). C34K's existing **five-original** backup barrier and C34O's existing **six-prefix** (0..5) model were intentionally **not modified**, rewritten, or silently treated as accepting the new source set.

The new tests use synthetic files in an isolated TemporaryDirectory and demonstrate:
- No forward publication before all six original backups are present and hash-matched.
- Exactly seven defined forward/reverse prefixes, with deterministic classification and restoration of every synthetic source.
- Refusal of missing, corrupt or symlinked originals, prefix drift and unexpected content changes.
- Preservation of the frozen C34K/C34O five-file/six-prefix historical contracts.

**Important limitation:** This is NOT a production-grade six-original recovery engine. It does not validate root-owned descriptors, `fsync`, symlink/hardlink race closure, atomic replacement, exclusive source/config lock, stopped-host checks, journald, privileged Python loader, installed source provenance or real rollback after systemd restart. Those require a *separate independently approved and signed source-generation/runtime change*. Do not relabel this test model as a migration authorization.

## Status and release blockers

| Gate | Status at this commit | Required for release |
| --- | --- | --- |
| Review-only P0 private listener source | Implemented in draft; synthetic acceptance tests | Independent security/source-generation approval, installed successor sealed with exact merged main |
| Review-only status-only Nginx origin config | Separate review candidate; isolated syntax test on available host | Approved path ownership/mode/retention, included-context and rollback verification, operator privacy consent |
| Six-file/seven-prefix recovery | Synthetic **model tests only** | Real fail-closed 6-backup/7-prefix implementation, fresh exact protected manifest and isolated operator acceptance |
| G0 original October 13 HTTP 403 | **UNKNOWN** | Unambiguous approved internal/outer request correlation and owning-layer fix |
| G1 main source | HOLD, legacy 11 missing and three divergent at historical snapshot | New protected-main content/source/registry review, no mutation of historical receipts |
| G2 observability | New source draft, not approved or installed | Independent security review |
| G3 privileged runtime | HOLD | Signed, verified root loader/service authority |
| G4 deployment/recovery | HOLD | Real 6-file/7-prefix and external Nginx rollback authority, stopped service approval |

**Final verdict:** All current milestone progress is offline only; original P0 root cause unresolved, **release NO-GO**. Passing source tests or GitHub CI must never activate any service. Further protected-source implementation or operational changes require their own explicit approval.
