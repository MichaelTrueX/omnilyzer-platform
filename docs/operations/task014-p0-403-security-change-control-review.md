# Task 014 - P0 Rejection Provenance Security and Change-Control Decision

**Decision date:** 16 October 2026  
**Status:** REVIEW COMPLETE, DESIGN CONDITIONALLY ACCEPTABLE; SOURCE CHANGE AND ACTIVATION **NOT APPROVED**  
**File:** `docs/operations/task014-p0-403-security-change-control-review.md`  
**Related:** `docs/operations/task014-p0-403-rejection-origin-contract.md`, `deployment/tests/test_task014_p0_403_rejection_origin.py`, `deployment/broker_loopback_listener.py`, `deployment/broker.py`, `deployment/broker_https_ingress.py`, `deployment/broker_integration.py`, `deployment/ingress/dev-broker-tailscale-origin.nginx.conf`, `deployment/application_source_set.py`, `deployment/c34k_five_file_backup_barrier.py`, `deployment/c34o_six_prefix_recovery_inspection.py`, `docs/operations/task014-c35d-release-gate-consolidation.md`, [Issue #182](https://github.com/MichaelTrueX/omnilyzer-platform/issues/182), [draft PR #190](https://github.com/MichaelTrueX/omnilyzer-platform/pull/190).

## Purpose, authority and executive decision

The product owner approved **continuation of the narrowly scoped security and change-control review** after the seven-test P0 diagnostic contract was accepted on October 16. This document assesses an **implementation-ready design**, not an approved implementation or operational deployment. It does not change production application source, Nginx, Tailscale, installed configs, secrets, root process, journal, replay state, services or workflow authority.

**Decision: CONDITIONAL DESIGN GO, IMPLEMENTATION / RELEASE NO-GO.**

A future controlled observation can distinguish an **upstream/Nginx origin 403**, an **HTTP/1.0 listener-framing 403**, and a **semantic/broker 403** only if independently accepted instrumentation establishes the origin and the event belongs unambiguously to the authorized request. C34E alone is insufficient: the listener handles `_FramingRejected` before C34E. The original October 13 403 remains UNKNOWN. A regression on synthetic traffic is not historical root-cause evidence.

Prioritize a bounded, **two-boundary** diagnostic design, not additional general-purpose privileged-loader reviews. Before source or operational changes, obtain distinct security acceptance, protected generation/change-control acceptance and operator authorization; any later workflow promotion is a separate explicit decision.

## 1. Actual inspected source and host facts

- Protected application selection has **41 entries** (38 Python and 3 runtime resources), including `deployment/broker_loopback_listener.py`. The existing C34E candidate changes **three** protected modules: `broker.py`, `broker_https_ingress.py` and `broker_integration.py`. No listener instrumentation is installed.
- The existing `C34K` backup barrier explicitly handles **five** originals (three source files and broker/executor configs). The `C34O` recovery classification handles **six prefixes, numbered 0 through 5**. C34I, C34X, C34Y, C34Z and C35D frozen assertions use that three-source source-identity model.
- A fourth protected source change adds **one more exact original backup**, for **six original protected files** (four sources plus broker and executor configurations) and **seven ordered forward/reverse prefixes, 0 through 6**, if each protected file is published as one step. This is a *new prospective model*, not a validated or approved extension. Merely changing the numbers in a fixture is inadequate. All affected durable backup barriers, source/hash assertions, interruption points, stop/lock protections and rollback checks must be independently re-established.
- C34Y has a historically fixed 95-entry candidate and C34Z observes 81 matching, 11 missing and 3 differing files against protected main. Those facts remain true **for the pinned historical candidate only**. A later listener change would introduce a fourth divergence, requiring a **new** source selection/manifest snapshot. Do not rewrite historical evidence to show 80/11/4 or falsely treat the old 95-entry receipt as a new protected-main seal.
- Current installed `/etc/nginx/conf.d/omnilyzer-task014-dev.conf` was verified to match the reviewed origin source SHA-256 `3508d56ac408c966df0cea24ec8f33e85524af429c7f7009efa5d0246dc26518`. It has `access_log off`; a single, exact promotion location; `proxy_pass http://127.0.0.1:3031`; `proxy_http_version 1.0`; explicit `Connection close`, canonical Host and narrowly forwarded headers.
- Installed `/etc/nginx/nginx.conf` has its `include /etc/nginx/conf.d/*.conf;` **inside** the `http` context (observed line 59). Therefore a **candidate** private `log_format` can be defined at the beginning of the *dedicated Task 014 origin config* without changing global nginx.conf. Nginx syntax and include-order collisions have **not** been validated using isolated offline parsing; do not assume deployment readiness.
- Current broker unit outputs to journald, with no explicit journald rate limit at the unit (`LogRateLimitIntervalUSec=0`, `LogRateLimitBurst=0`). Existing C34E in-process allowlist/filter is capped at 32 emitted static codes per 60 seconds. An event missing from journald can mean suppression, inaccessible/rotated journal or no receipt. The host's previous 403 history cannot be reconstructed by new instrumentation.
- Existing focused review tests establish **byte-identical HTTP 403** public responses for synthetic framing, semantic ingress and broker rejections. They do **not** supply causal attribution to historical requests.

## 2. Candidate narrow Nginx provenance: change-control review

**Preferred configuration shape (illustrative, NEVER install this from a documentation excerpt):**

```nginx
# Only within the dedicated Task 014 file already included by nginx.conf under http {}
log_format task014_status_only 'status=$status upstream_status=$upstream_status';
server {
    # Existing listen, server_name and closed location unchanged.
    # Only in a separately approved short diagnostic window:
    # access_log /operator-approved-restricted-path task014_status_only;
}
```

This is **not** an operational config patch. The proposed status-only log must have a reviewed fixed path, root-owned restricted open/rotate/cleanup permissions, separate no-secret storage, maximum retention/size, worker access policy, a documented rollback to `access_log off`, independent syntax validation and a verified no-interference start/reload plan. Examine inherited/default HTTP log settings and error handling; do not enable the global `combined` log. Only `$status` and `$upstream_status` are candidate runtime variables for the private format. Avoid `$request`, `$uri`, `$args`, `$remote_addr`, `$http_*`, `$upstream_http_*`, `$request_body`, request duration/size and any client-provided identifier. A restrictive read policy and short exposure window are essential.

**Interpretation rules:**

| Nginx observation for a proven one-request window | Permitted conclusion | Forbidden inference |
| --- | --- | --- |
| `status=403 upstream_status=403` | An upstream 403 was seen by this Nginx request path | That the semantic broker or OIDC generated it |
| `status=403 upstream_status=-` | No upstream status was recorded for this observed request | That Tailscale, rather than Nginx or logging, necessarily rejected |
| No qualifying Nginx record | **UNKNOWN** unless independent, complete private edge receipt proves an upstream miss | No request reached the host, or the broker refused |
| Multiple, contradictory, delayed or truncated records | **AMBIGUOUS** | Pick one record and assert a root cause |

Use this information **only** with independent installed-process identity, active Serve routing, operator-controlled timestamp/single-attempt correlation and no competing traffic. If exact association fails, the result remains UNKNOWN. Never return diagnostic stages in public HTTP headers or bodies, and do not add a query parameter or client-controlled request ID for correlation.

## 3. Candidate listener-framing stage: code-security review

**Change surface:** Existing `deployment/broker_loopback_listener.py` would import the existing private `_AUTHORITY_LOG` from `deployment.broker`, already reached transitively from the current HTTPS ingress dependency. Add exactly one fixed allowlisted literal `task014_diag stage=listener_framing_rejected` to the `deployment/broker.py` allowlist (13 -> 14 codes) and emit **only** on catching `_FramingRejected`. Reuse the existing singleton rate filter; do not create a new logger, request-scoped collector, metrics service, token handler or dependency.

**Implementation guardrails (not yet code):**
1. Assign the existing fixed rejected response **before** invoking any diagnostic. An exception in logging/filter/sink must never convert the 403 to 503, terminate the loop or modify the public status/body. Add explicit fault-injection tests for formatter/filter/handler failures, including clock rollback and exhaustion.
2. Only a fixed literal without arguments may be logged. Do not log request bytes, partial framing, exceptions, stack traces, header names/values, JWT/JTI/claims, identity, IP, connection descriptor, response body, raw HTTP method, path or input-dependent fields.
3. Preserve `_FramingRejected` catch placement, `_read_request` and `_parse_head` bounds, sequential socket lifetime, constant network bytes (including `Cache-Control`, `Content-Length`, `Connection`), 202/403/503 mapping and OIDC/replay/executor behavior. The event is private diagnostic only; it cannot become a new authorization oracle.
4. Verify the actual logger's process-level journald routing and privacy in isolated acceptance. Logger filter rejection or missing event is a **HOLD/UNKNOWN**, not evidence of a later rejection stage.
5. The old tests deliberately require 13 code literals and no listener stage; they must be updated only in a **separately authorized implementation commit**, with an explicit historical baseline preserved. Do not silently weaken the existing security tests to make new instrumentation pass.

**Failure-mode matrix for isolated tests:** valid 202; malformed HTTP/1.1 403; duplicate/malformed framing; valid framing plus wrong semantic Host 403; synthetic broker rejection 403; synthetic 503; logger throws; logger suppresses because of 32-event cap; inaccessible journal; broken Nginx sink; concurrent or overlapping observations; service absent; bad config provenance; rollback after each of six protected file publications and the separate Nginx logging change. Test no token or public-stage leakage for every case.

## 4. Protected application, config and operational separation

**App source migration scope (candidate, NOT APPROVED):**
- Source files: exactly `deployment/broker.py`, `deployment/broker_https_ingress.py`, `deployment/broker_integration.py`, `deployment/broker_loopback_listener.py`.
- Root canonical configs: existing broker and executor authority (2 files), with merged-main `reviewed_commit` and broker `expected_workflow_sha` updated **only under a future independently approved final main SHA** as dictated by current protected-authority contracts.
- Source set entry count stays at 41, but exact changed-source count becomes 4. The older C34F/C34X/C34Y/C34Z historical three-change hashes and C34K five-original/C34O six-prefix authority cannot be represented as accepting the new source.
- Required new isolated proof: 41-file exact source manifest and non-destructive service union; independent merged-main seal; full 6-original backup barrier; 7-prefix consistent recovery and rollback with fsync/descriptor/no-follow protections; stopped broker, executor **and socket**, exclusive lock, verified root-owned configs, no interrupted publication; service restart/rejection compatibility under new generation. The still-missing 11 protected-main recovery files and G3 runtime loader/root seal remain unresolved and block operational adoption.
- Installed diagnostic logging must not be used as justification for relaxing OIDC verification, removing replay barriers, bypassing release provenance, changing JSON token/localStorage session behavior or introducing new deployed services.

**Nginx origin configuration scope is distinct.** `deployment/ingress/dev-broker-tailscale-origin.nginx.conf` is not one of the 41 application source files. Its separately root-owned installed path and any temporary log file require their own exact source hash, root permissions, syntax/effective-include verification, operator authorization and reversible rollout. Do not pretend this file is automatically covered by the six protected originals or by C34O's existing recovery snapshots. Use separate, explicitly approved reversible staging or extend the transaction model with new independently verified authority; do not assume a combined seven-file writer is already valid.

**Sequencing to minimize risk:**
1. Obtain independent security sign-off on the exact privacy/logging and non-interference design, including whether one short-lived status-only log is permitted at all.
2. Obtain a separately approved **source-generation plan** covering 4 source changes, 2 canonical config changes, 6 backups/7 prefixes and the 11 missing main sources plus runtime-loader controls. Before this sign-off, implementation/deployment remains HOLD.
3. Validate a private/isolated Nginx config syntax, a fake-socket listener, full existing security regressions and stoppage/restart/rollback acceptance **without operating on live services**.
4. A separate authorized operations window may make *reversible* diagnostic changes, with explicit preflight/postflight and rejection on any negative evidence.
5. Only after independent production-readiness acceptance may the owner authorize **one** new DEV workflow promotion. Observe nonsecret evidence from both boundaries; stop and roll back diagnostics. No automatic rerun.

## 5. Threat review and decision gates

| Risk | Severity | Control and blocking evidence |
| --- | --- | --- |
| Nginx default logging exposes IP, request URI or JWT headers | **HIGH** | Use dedicated status-only log format and root-restricted short-lived log; negative static/isolated configuration review mandatory |
| Incomplete request-level correlation attributes a different 403 to the promotion | **HIGH** | Single authorized window, trusted clock, no overlapping traffic; ambiguous/missing evidence returns UNKNOWN |
| Logger malfunction changes 403 response or process behavior | **HIGH** | Set fixed response before optional diagnostic, exception-isolate and negative fault tests; prove byte-identical responses |
| Changed listener bypasses frozen three-source generation and protected backup | **CRITICAL** | New exact 4-source + 2-config source/backup/recovery approval, not C34K/C34O reuse |
| New Nginx file not covered by 41-source source manifest | **HIGH** | Separate root source/config seal, log lifecycle and rollback; no unauthorized include/layout change |
| Synthetic test success incorrectly closes historic G0 | **HIGH** | Original October 13 cause UNKNOWN; allow only an independently correlated new observation or genuine historical contemporaneous evidence |
| Missing journal stage mistaken for confirmation of earlier failure | **HIGH** | Suppression/access/rate-limit checks; absence means UNKNOWN |
| Privileged loader or stopped-host prerequisites bypassed for speed | **CRITICAL** | Maintain G1-G4 HOLD and NO-GO; separate operator authority and protected-main merge gates |

**Change-control outcome:** The proposed design is technically viable **as a proposal** and adequately narrow for a *future independently approved source implementation*. It is **not safe to adopt the existing five-file recovery path for four changed sources**, and status-only Nginx logging must not be enabled without privacy, configuration-context and rollback acceptance. **The review does not certify a runtime, instrument the broker or diagnose the original request.**

## 6. Requirements traceability and status

| Control | Evidence | Status |
| --- | --- | --- |
| P0-SEC-01 distinguish status collisions and prove absence of historical attribution | Prior 7-test synthetic P0 module, original GitHub runs and fixed listener/ingress response code | **VERIFIED offline; real origin UNKNOWN** |
| P0-SEC-02 demonstrate possible status-only origin config within existing http include | Installed `nginx.conf` include placement and currently exact-origin config | **Static feasibility REVIEWED; not parsed/activated** |
| P0-SEC-03 ensure bounded fixed listener stage and private evidence | Existing C34E singleton 13-code filter, `_FramingRejected` catch | **DESIGNED, no source implementation** |
| P0-SEC-04 identify true protected change cardinality | C34K five originals, C34O 0..5 prefixes, 41-source allowlist, C34X/Y/Z pinning | **REVIEWED; successor 6/7 model NOT IMPLEMENTED** |
| P0-SEC-05 preserve secret privacy, fail-closed errors and public responses | Risk table, fault and no-oracle tests listed here | **REVIEW CRITERIA ONLY** |
| P0-SEC-06 verify actual full release authority, operator logging and controlled observation | Requires independent approvals, isolated end-to-end tests and release decision | **NOT APPROVED, NOT VERIFIED** |

**Final acceptance labels:** Security/change-control **review performed and recorded**; implementation **not authorized**; evidence-based root cause **not proven**; protected main **unmerged**; G0 **BLOCKED**, G1/G2/G3/G4 **HOLD**; release **NO-GO**. Do not start a new source/deployment phase merely because this document or CI checks pass.
