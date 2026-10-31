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

Remove only the equality rejection. Preserve the fixed HTTPS realm, host,
service, closed pull-only repository, bounded response and duplicate/member/type,
expiry, redirect, TLS and cleanup checks. Existing independent broker JWT,
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
