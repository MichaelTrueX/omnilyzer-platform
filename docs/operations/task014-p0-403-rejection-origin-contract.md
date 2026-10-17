# Task 014 - P0 HTTP 403 rejection-origin diagnostic contract (review only)

**File:** `docs/operations/task014-p0-403-rejection-origin-contract.md`  
**Related:** `deployment/tests/test_task014_p0_403_rejection_origin.py`, `.github/workflows/task014-c34d-review.yml`, `deployment/broker_loopback_listener.py`, `deployment/broker_https_ingress.py`, `deployment/broker_integration.py`, `deployment/broker.py`, `deployment/ingress/dev-broker-tailscale-origin.nginx.conf`, [Issue #182](https://github.com/MichaelTrueX/omnilyzer-platform/issues/182) and [draft PR #190](https://github.com/MichaelTrueX/omnilyzer-platform/pull/190).

## Purpose, authorization and decision

This is an **offline diagnostic-design and negative-regression milestone only**, prepared after explicit user approval on 2026-10-16 to continue the narrowly scoped diagnostic investigation. **No diagnostic instrumentation has been installed or activated. No new DEV promotion is approved.** The original HTTP 403 remains **UNATTRIBUTED**, and Task 014 remains **NO-GO**.

Do not infer authorization to edit installed Nginx, Tailscale, broker, listener, executor, protected root configuration, OIDC policy, replay records or systemd services. No dispatch, retry, merge, root execution, package install, privileged loader or protected-main source promotion follows from passing these offline tests. The entire C35D G0-G4 release register remains open.

## 1. Evidence and proven ambiguity

The original [October 13 run 38382512194](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/38382512194) passed gate, request preparation and private tailnet setup; its POST failed with HTTP 403. Later [October 14 diagnostic run 38538151015](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/38538151015) reported `task014_diag oidc_codes=ok` from **unverified runner-side claim comparisons** followed by `http_status=403 response_shape=fixed_broker_rejection_shape`. Neither proves server-side signature validation nor establishes the response origin.

Current nonprivileged October 16 host observation confirmed that installed `/etc/nginx/conf.d/omnilyzer-task014-dev.conf` matches the reviewed origin configuration byte-for-byte (SHA-256 `3508d56ac408c966df0cea24ec8f33e85524af429c7f7009efa5d0246dc26518`). Current, sanitized Tailscale Serve metadata references HTTPS origin port 3032; Nginx proxies to loopback port 3031. Those are **current states, not historical request-path attestations**. Nginx `access_log off` and inaccessible historical journal metadata prevent attribution; previously recorded replay/audit observations were nondispositive.

**Source-proven response collision**:

| Boundary | Current source behavior | Public HTTP result |
| --- | --- | --- |
| Outer/private upstream | A separate proxy or policy may reject before Nginx | Not established |
| Nginx promotion origin | Named validations return 400, 405, 411 or 415; no explicit 403 in reviewed location | Origin status alone cannot exclude all upstream components |
| `broker_loopback_listener._FramingRejected` | Catches malformed HTTP/1.0 framing before semantic dispatch | `403 {"status":"rejected"}\n` |
| `parse_dev_promotion_ingress` | Rejects forwarded semantic headers, canonical framing and body | Identical fixed 403 body |
| Broker/registry/replay rejection | `BrokerRejectedError` mapped by ingress dispatcher | Identical fixed 403 body |

The companion synthetic test proves that a malformed HTTP/1.1 listener request, a wrong forwarded Host and a broker rejection emit byte-identical 403 responses. **Therefore HTTP status and fixed body shape are insufficient to identify a cause.**

## 2. Smallest safe future design, not yet implemented

A useful diagnostic requires two independently reviewable layers. Do not install only one and claim completeness.

**A. Outer Nginx/Serve provenance (candidate, requires independent operational acceptance).**
- Confirm the actually active Serve-to-Nginx and Nginx-to-broker linkage from read-only *approved* operator metadata. Current `tailscale serve status --json` alone is insufficient for the historical run.
- Consider a **restricted, opt-in, short-lived** Nginx log facility for a single authorized validation, recording only fixed classification fields such as `status`, `upstream_status`, whether an upstream was attempted, and an operator-controlled short observation window.
- Do not include `Authorization`, any `X-Omnilyzer-*-OIDC` headers, JWT claims/JTI, IP, URI query, request/response body, token lengths or raw errors; no `$request`, `$http_*`, `$upstream_http_*` or `$request_body`. The existing `access_log off` must remain until an explicit reviewed change.
- Nginx `log_format` is normally defined in the `http` context, not in the current dedicated `server` block. Inspect the *installed* include/context and enforce no extra deployment topology before proposing an actual configuration edit.
- A 403 with `upstream_status=403` may establish Nginx forwarded an upstream 403 for the **correlated observed request**; it does not prove that the broker's semantic handler produced it. An absent upstream status is not sufficient by itself to blame Tailscale or Nginx.

**B. Internal listener framing provenance (candidate, protected generation change).**
- The existing C34E draft records 13 exact, allowlisted, operator-only stage codes with a process-local maximum of 32 messages/60 seconds. It deliberately does **not** instrument `broker_loopback_listener.py`.
- A prospective narrowly scoped change would add exactly one static `listener_framing_rejected` stage to the existing bounded logger, emitting only when the loopback listener catches `_FramingRejected` before semantic dispatch. Never log exceptions, request headers, token contents, partial frames, peer address, body or payload length. Keep public 202/403/503 response bytes and timing behavior unchanged.
- This would create a **fourth protected service-source difference** alongside `broker.py`, `broker_https_ingress.py` and `broker_integration.py`. Do not silently reuse C34F/C34X/C34Y/C34Z frozen **three-difference** authority. An independently reviewed exact protected-source graph, provenance/manifest, rollback and root configuration plan is required.
- Logging cannot be used to make an external oracle. Failures of the logging clock/filter/sink must not change authorization or response. A missing stage code may mean log rate suppression, access limitations, a pre-listener rejection or no request, not a successful validation.

**C. Correlation and interpretation.**
- Limit a future observation to **one** separately authorized attempt after acceptance. Require authenticated, operator-controlled evidence of the actual active proxy configuration, journal/log availability, time synchronization and an isolated observation window. If other traffic could produce indistinguishable events, classify `AMBIGUOUS`; do not invent a request ID or expose sensitive identifiers.
- The fixed public HTTP status/body remain unchanged, and the internal stage vocabulary is never returned to callers.
- Prove outer-source vs upstream 403 first. Then use a corroborated listener-framing stage or C34E semantic/broker stage to narrow. If the evidence cannot tie an event to the one transaction, return `UNKNOWN` regardless of plausible source-derived causes.
- Keep separate hypotheses for unexpected proxy behavior, canonical body mismatch, signed OIDC/registry verification, request binding, release evidence and replay. No synthetic model establishes the real historical root cause.

## 3. Review-only acceptance criteria and explicit blockers

| ID | Requirement / result | Acceptance evidence | Status |
| --- | --- | --- | --- |
| P0-DIAG-01 | Demonstrate fixed-403 ambiguity with no secrets or network | Existing fake-socket listener plus synthetic broker fixtures | **Offline test implemented** |
| P0-DIAG-02 | Confirm currently reviewed Nginx-to-listener HTTP contract | Static reviewed `proxy_http_version 1.0`, `Connection close`, port 3031, public Host | **Offline test implemented** |
| P0-DIAG-03 | Preserve diagnostic privacy and static stage constraints | Verify fixed 13-code bounded broker vocabulary; no listener stage currently installed | **Offline test implemented** |
| P0-DIAG-04 | Review complete next instrumentation boundaries and safety invariants | This document, stage/correlation/rollback exclusions | **Documented proposal, NOT deployed** |
| P0-DIAG-05 | Actual Nginx upstream-origin evidence for a single authorized attempt | Independently accepted, restricted and correlated observability | **NOT APPROVED/NOT VERIFIED** |
| P0-DIAG-06 | Listener stage instrumentation in a sealed merged source generation | Security review, new exact 4-source diff manifest, source migration and acceptance | **NOT APPROVED/NOT IMPLEMENTED** |
| P0-DIAG-07 | Prove original incident root cause and owning-layer fix | Historical contemporaneous evidence or distinct future authorized attempt plus synthetic owning-layer regression | **BLOCKED / UNKNOWN** |

This proposal does **not** modify production source or the C34D promotion workflow. The only review branch changes for this bounded task are the complete offline regression module, this document and one invocation in the existing read-only review CI. Reuse existing directory layout; no new application/service/package/installer architecture.

## 4. Test command and next gate

From the existing nonprivileged review checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v deployment.tests.test_task014_p0_403_rejection_origin
```

CI must verify this module and the existing Task 014 security-critical regression suite on the **exact resulting draft HEAD**, plus repository-quality and dependency review. Those pass results establish the **offline design contract only**, not any live diagnostic deployment or authorization.

**Release verdict:** G0 UNKNOWN, G1/G2/G3/G4 HOLD, **NO-GO**. Do not start protected-listener code edits, root source migration or workflow dispatch without a separate exact-scope decision and required release-gate approvals.
