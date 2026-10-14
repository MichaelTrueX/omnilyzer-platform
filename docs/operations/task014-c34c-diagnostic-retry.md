<!--
File: docs/operations/task014-c34c-diagnostic-retry.md
Purpose: Review-only plan for token-free Task 014 failure-stage diagnostics.
Related: deployment/broker.py, deployment/broker_https_ingress.py,
deployment/broker_loopback_listener.py, deployment/broker_integration.py,
.github/workflows/platform-promote.yml, issue #182.
-->

# Task 014 C34C: Diagnostic retry (review only)

**State: HOLD. No merge, installation, workflow rotation or live retry is authorized.**

## Scope and contract

The broker writes fixed, static stage codes to the existing service logger.
It never records JWTs, JTI, claims, actor IDs, request bodies, headers, source digests
or token-verification exception text. Its externally visible HTTP response remains
the same (fixed 403 or 503, and fixed 202 for accepted requests).

The workflow prints only the HTTP status and whether an HTTP 403 response exactly
matches the small fixed broker rejection body. `broker_shaped_403` is a *shape*
classification, **not proof** that the response originated at the broker.
It does not print response bytes or retry.

## Rejection categories

- HTTP framing failures remain intentionally unlogged by the restricted listener, preserving its frozen transport contract. A broker-shaped 403 without a downstream stage event is inconclusive and requires independent network-layer evidence.
- `ingress_rejected`: semantic request/header contract rejected.
- `promotion_request_rejected`: canonical promotion payload rejected.
- `deployment_oidc_rejected`: deployment JWT cryptographic rejection.
- `deployment_claims_rejected`: reviewed GitHub claims or revision rejected.
- `registry_oidc_rejected`: registry JWT or cross-token binding rejected.
- `executor_request_rejected`: executor request identity/policy rejected.
- `replay_rejected`: durable replay protection rejected authorization.
- `broker_rejected`: generic broker rejection; may duplicate one specific event.
- `*_unavailable`: trust or execution could not be established, returns fixed 503.
- `release_or_request_unavailable`: release verification/build stage unavailable.

## Non-live acceptance

Run focused tests and the existing Task 014 security suite before review:
`python -m unittest deployment.tests.test_c34c_diagnostic_events deployment.tests.test_final_dev_workflow deployment.tests.test_broker_https_ingress deployment.tests.test_broker_loopback_listener deployment.tests.test_broker`.

Review CI permissions, fixed response behavior, side-effect-free fixtures and
log access. Denied-request logging is bounded per event but **not rate limited
in code**; confirm Tailscale restrictions and journal throttling before activation.

## 2026-10-14 host preflight evidence

The separately executed read-only `omnilyzer-c34c-report.json` reported
23 PASS, 1 REVIEW, 1 HOLD, zero FAIL. The current `main` broker source and
workflow authority remained installed, broker.service/executor.socket remained
active, and C34C was **not** installed or retried. Historical service journals
did not supply a broker rejection stage.

**Preflight checker correction:** The REVIEW on
`broker_authority_canonical` cannot be interpreted as a configuration defect:
the standalone checker used `json.dumps(..., sort_keys=True,
separators=(",", ":"), ensure_ascii=False).encode("utf-8")`, whereas the
authoritative `deployment.policy.canonical_bytes` uses
`ensure_ascii=True` **and an exact final newline**. Since the checker omitted
that newline, it cannot pass for a valid canonical broker file. Do not rotate
or rewrite configuration because of this false-positive REVIEW. A later
checker must compare exact `parse_canonical_broker_service_configuration`
and `canonical_bytes` behavior using independently verified, inert code.

## Application-generation dependency

C34C modifies `deployment/broker.py`,
`deployment/broker_https_ingress.py` and
`deployment/broker_integration.py`, each in the explicitly selected 41-file
`DevApplicationSourceSet`. These are protected installed application
bytes, **not** merely a GitHub workflow revision.

The C33AE successor migration and its pinned application manifest enforce
reviewed source identity and an inactive-unit migration boundary. Consequently,
the existing broker workflow-SHA rotation **alone is insufficient** to install
this PR. Do not copy files into `/opt/omnilyzer/deployment/app`, reload/restart
the active broker, or change `reviewed_commit` to `main` without a separately
approved successor-generation migration with full 41-file manifest/digest
evidence, exact installed-source provenance, service lifecycle plan, rollback
and runtime integrity qualification.

The executor socket is currently active and the broker service is running;
historical migration tools that require those units inactive must not be
invoked directly. A matching C34C-specific live transition authority has
**not** been implemented or qualified in this PR.

## Only after a separate approval

1. Review full diff and the complete source-generation impact, including
   control-plane integrity, sign-off and root-only installation.
2. Implement and test a dedicated application-generation transition that
   preserves current runtime, configuration and audit/replay identities, and
   supports explicit safe service stop/restart with rollback.
3. Merge only after independent security review; freeze a final reviewed
   `main` commit and stage exactly verified source and a full manifest.
4. Run the exact root-controlled installation and qualification; use the
   existing explicit workflow-authority rotation only when its preconditions
   are met and the live service is properly restarted with approved bytes.
5. Confirm private journal access, rate controls, source/config authority,
   executor/replay isolation and canary rollback before considering one live
   diagnostic run.
6. Authorize **one** DEV canary promotion with no retry, correlate the fixed
   GitHub response shape with the private stage events and preserve evidence.

No root mutation, GitHub workflow dispatch, promotion or merge may be inferred
from this review-only documentation. Do not activate the diagnostic branch.
