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

- `http_framing_rejected`: broker listener rejected HTTP framing.
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

## Only after a separate approval

Review the complete diff and the regression suite. Approve the new GitHub
workflow SHA and the restricted broker installation via Task 014's existing
authority rotation procedure. Confirm the installed source SHA and capture
only operator-accessible static log codes. Authorize **one** new synthetic
canary promotion knowing a successful invocation can deploy it. No automatic retry.

Do not rotate the authority or execute the deployment from this review branch.
