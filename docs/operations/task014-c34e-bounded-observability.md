<!--
File: docs/operations/task014-c34e-bounded-observability.md
Purpose: Review-only bounded internal-stage observability and protected-source
generation handoff for the unresolved DEV HTTP 403 in GitHub issue #182.
Related: deployment/broker.py, deployment/broker_https_ingress.py,
deployment/broker_integration.py, deployment/tests/test_c34e_diagnostic_events.py,
.github/workflows/task014-c34d-review.yml, draft C34C PR #183,
docs/operations/task014-c34d-one-shot.md.
-->

# Task 014 C34E — bounded broker diagnostics (review only)

**No live source installation, migration, workflow rotation or promotion is
authorized by this change.** Preserve the state of the completed one-shot
C34D GitHub run 38538151015, the broker's running source, and root-only
configuration, replay database and audit history.

## Observed basis

The October 14 C34D run reported `oidc_codes=ok` for **unverified**
runner-side JWT payload fields, then HTTP 403 with the exact fixed
`{"status":"rejected"}` body. Root-controlled after-the-fact forensics
showed zero current replay entries for that run, a replay last-seen marker
of 2026-09-25T03:03:46Z and zero audit files. A 403 was therefore most likely
generated **before replay consumption**. These findings do not prove JWT
signature validity or which process generated the 403.

A root-owned post-run checker originally looked for
`/etc/omnilyzer/deployment/dev/broker.json` and incorrectly reported
a missing configuration. The authoritative path is
`/etc/omnilyzer/deployment/broker/dev.json`. This is a checker defect,
not evidence of live configuration corruption.

## Instrumentation design

C34E builds upon the review-only C34C fixed-stage diagnostic source. Only
existing protected broker modules are changed; the HTTP listener, public
responses and authorization, replay and executor contracts remain unchanged.
C34D's workflow-only diagnostic remains intact.

The single `omnilyzer.task014.authority` logger permits only 13 enumerated
literal messages and uses a process-local, lock-protected ceiling of 32 emitted
events in 60 seconds. It emits no tokens, token IDs, claims, request material,
HTTP headers, exception details or user IDs. If its clock fails, it suppresses
logging without changing authorization. This rate limit is necessary because
the current broker systemd unit reports `LogRateLimitIntervalUSec=0` and
`LogRateLimitBurst=0`; operator controls must still preserve restricted
journal access.

The strongest post-deployment indicators are:
- `ingress_rejected`: forwarded semantic HTTP fields failed strict policy
- `promotion_request_rejected`: canonical promotion payload failed
- `deployment_oidc_rejected`: server-side signature/header/claim verification
  definitively rejected the deployment token
- `deployment_claims_rejected`: normalized signed-claim binding rejected
- `registry_oidc_rejected`: registry JWT signature or cross-token binding failed
- `executor_request_rejected`: generated request identity validation failed
- `replay_rejected`: replay protection rejected the identity

Generic `broker_rejected` may follow one of these specific codes. Fixed 503
unavailability stages cannot be mistaken for a 403.

**Known residual ambiguity:** the unchanged HTTP/1.0 loopback listener must
not log request bytes or change its frozen framing contract. It can return
an identically shaped 403 on a framing failure without any downstream stage
event. Do not infer `OIDC` failure from silence. Private ingress provenance
must be independently correlated from restricted, redacted host-side evidence.

## Protected installed-source transition gate

`deployment/broker.py`, `deployment/broker_https_ingress.py` and
`deployment/broker_integration.py` belong to the protected 41-file
`DevApplicationSourceSet`. The existing broker is running, and
`omnilyzer-deployment-executor.socket` is listening.

It is **not safe** to simply copy these files, restart Python, reuse the
historical C33AQ rotation function, or rotate only the workflow commit SHA.
A separately reviewed successor-generation migration must bind the exact
merged reviewed `main` revision, all 41 file hashes, the current installed
source identity, root-only configuration, state, rollback and service lifecycle.
Its preconditions and postconditions must be tested in a fresh controlled
acceptance environment; fail closed on any mismatch. Preserve the current
`reviewed_commit` fields where the contract demands it—never automatically
rewrite them to a repository head revision.

No new live promotion attempt is approved by this PR. An eventual explicitly
approved attempt must stop after one transaction, correlate its timestamp
against operator-only stage logs, and never publish sensitive evidence.

## Validation

The C34E static-code privacy tests, bounded-rate tests, broker/ingress unit
tests, C34D workflow diagnostics, and the existing 566-test security-critical
baseline must pass in non-live PR CI. GitHub CI cannot certify host migration,
journal policy, private network provenance or canary readiness. Keep incident
#182 open until a specific root cause and corrective acceptance are evidenced.
