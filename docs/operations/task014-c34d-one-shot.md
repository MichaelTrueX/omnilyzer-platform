<!--
File: docs/operations/task014-c34d-one-shot.md
Purpose: One final, workflow-only observable DEV promotion with no protected
application-source change.
Related: .github/workflows/platform-promote.yml,
deployment/ci_oidc_diagnostics.py, deployment/state_store_successor_live_authority.py,
Task 014 incident issue #182 and separate draft PR #183.
-->

# Task 014 C34D — one observable workflow-only DEV attempt

**Status: REVIEW ONLY. NO MAIN MERGE, HOST CHANGE OR PROMOTION DISPATCH.**

## Why C34D rather than C34C

The broker's installed 41-file application set is protected by frozen source
manifests and migration tooling. C34C would require an entirely new application
generation, offline installation review and restarted service. C34D limits the
change to the GitHub runner's workflow and a CI-only helper/test module,
avoiding modification of that protected installed source set.

The helper decodes untrusted JWT claim payloads locally only for diagnostics.
It produces fixed field-mismatch codes, never JWT/claim values. **This is not
signature verification or an alternative authorization decision.** Actual
cryptographic validation and replay remain in the installed broker. If the
runner's claims fail the same static broker policy checks, the workflow fails
closed *before the POST* rather than sending a known unauthorized request.

On HTTPError, print only `http_status` and the exact fixed rejection-body
shape; raw HTTP response/headers are never emitted. A fixed-looking 403 does
not prove which component generated it.

## Prerequisites for a single live attempt

1. PR checks and independent source/security review pass, including the
   unchanged scope of application-source manifest, workflow permissions, OIDC
   audiencies, Tailscale configuration and one-POST/no-retry contract.
2. Approve C34D workflow-only merge into protected `main`, **freeze final
   commit** and record exact 40-character SHA. A different merge commit means
   a different broker identity. Do not dispatch before rotation.
3. Perform an independently approved, root-controlled stopped-service
   transition for the exact `main` SHA using existing
   `rotate_state_store_successor_workflow_authority` code, with complete
   C33AE source/config proof, rollout backup/rollback and all existing
   precursor/inactive-unit qualifications.
4. Requalify the canonical broker authority and the *running instance* after
   restart. The pinned revision is loaded only at broker startup. The running
   broker must not be left with a stale in-memory `expected_workflow_sha`.
5. Use a **new** DEV promotion workflow dispatch, not rerun an old job.
   Inputs must be the exact previously accepted immutable Task 013 canary
   release references. Verify source/registry evidence again.
6. Only one dispatch. On a failure, collect the status/shape and bounded OIDC
   mismatch codes; compare with root-controlled replay, audit and network
   evidence, and stop. Never dump a JWT, unredacted Nginx request or registry
   credentials.

## Decision tree after the attempt

- `oidc_codes` includes a field mismatch: the GitHub-issued token's reported
  claim fields differ from the broker's published policy. Note that values
  were decoded, **not cryptographically verified** on the runner.
- `oidc_codes=ok` and a fixed-shaped 403: all runner-side static checks match
  the broker policy, so investigate private ingress and signed-verifier paths;
  the result alone cannot prove the responding component or signature.
- A different 403 body shape: investigate Tailscale/Nginx response provenance
  before blaming OIDC.
- An HTTP 202 means the broker accepted the promotion; independently qualify
  resulting DEV canary state before resolving #182.

## Explicit HOLD

The C34D branch and pull request do not authorize service stoppage, config
rotation, code installation or a new dispatch. Every authority step must be
qualified. No auto-retry or automatic rollback after uncertain publication.
