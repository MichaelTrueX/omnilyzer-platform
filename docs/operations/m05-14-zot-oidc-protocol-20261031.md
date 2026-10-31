<!--
File: docs/operations/m05-14-zot-oidc-protocol-20261031.md
Purpose: Record the evidenced Zot response compatibility fix and read-only verification boundary.
Related: deployment/release_consumer.py, release/analytics_task014_readonly_probe.py,
.github/workflows/platform-promote.yml and Omnilyzer issue27.
-->

# Task014 Zot OIDC response compatibility

The installed Zot is v2.1.20, commit 3b5796d. Its upstream
[pkg/api/token_exchange.go](https://github.com/project-zot/zot/blob/3b5796d/pkg/api/token_exchange.go)
returns the validated OIDC credential unchanged in both token and access_token.
Its bearer middleware also accepts the OIDC JWT directly. PR266's assumption
that the returned token must differ from the input was incorrect. Rejecting
that equality prevents the real documented protocol from completing.

Restore the original direct OIDC Bearer manifest GET, which Zot already
authenticates. Remove the unnecessary token-endpoint round trip rather than
expanding the original HTTP reader. Preserve fixed host/repository, strict
bounded headers/body, TLS, redirects, exact digest and signature checks. Existing independent broker JWT,
source, signature, replay and executor authorization remain mandatory.

The original a09ddd45 promotion failure has not been attributed to raw Bearer
usage. The later 89b30c35 promotion run41166713056 also returned HTTP503 before
executor activation. Correcting the newly introduced response rejection does
not establish the earlier failure's cause or prove deployment readiness.

Use the existing platform-promote.yml auth_probe=true with product_id=analytics
and target_stage=dev for a read-only component matrix. It exercises the actual
fixed Zot GET and strict OCI parser/digest, fixed Forgejo GET, existing closed
archive and scanner/signed-field parsers, then real Cosign verification of both
blobs and the immutable OCI signature using the original pinned CI installer.
Independent checks continue after failures; stdout contains fixed status and
HTTP-envelope metadata, never credentials, bodies or raw subprocess output.
Private credential/evidence files and verification caches are temporary and
removed. The canary diagnostic remains the default.

This diagnostic has no Tailscale join, broker POST, replay operation, host
provisioning, container, database, secret-file, signing or publication action.
It does not prove the host broker's identity, descriptor snapshots, memfd
sealing or service sandbox. Those remain separate live host acceptance checks.
Do not rebuild or republish Analytics0.15.0/run40881693662, reset replay or rerun
PostgreSQL bootstrap. Actual DEV acceptance remains pending.

## Real read-only matrix result

Run41168342282 on reviewed main60bc8f56 passed the actual Forgejo archive,
scanner/signed-field checks and both real Cosign blob signatures. The added
Zot token endpoint returned200 JSON with Transfer-Encoding:chunked and no
Content-Length, so the strict reader stopped before the manifest GET. This
response does not establish the manifest's envelope or the original failure.
Restore the supported direct Bearer GET before changing its HTTP contract.
Real OCI signature verification independently returned failure. The diagnostic
now captures at most65537 stderr bytes with a90second deadline and pinned-PID
process-group cleanup, emitting only fixed categories. Registry access denial
is a diagnostic category, not a proven distinction between authentication and
repository authorization. Never print raw stderr, credentials or bodies.
The host remains unchanged until the full real matrix passes.
