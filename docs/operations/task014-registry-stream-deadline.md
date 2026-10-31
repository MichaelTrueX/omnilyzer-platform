<!--
File: docs/operations/task014-registry-stream-deadline.md
Purpose: Record the verified cold-pull failure and bounded correction contract.
Related: ../../deployment/analytics_registry_stream_transition.py,
         ../../deployment/analytics_private_registry.py,
         task014-pre-release-checklist.md, issue27.
Authority: Source qualification only; owner-local activation and live acceptance
           remain separate evidence. No release rebuild or token extension.
-->

# Analytics registry streaming and completion deadlines

## Observed failure, 31 October 2026

Signed Task014 run41191140314 passed broker admission and reached a real rootless
Docker pull. Docker reported unexpected EOF before the180s pull cancellation.
The owner's registry audit confirmed all13 config/layer blobs match the fixed
published manifest. Nginx logged premature upstream closure and truncated
responses for the29MB,56MB and233MB layers. Zot's HTTP timeout settings were
absent, so the installed2.1.20 CLI applied its60s response-write default.
Nginx already had buffering disabled and900s proxy deadlines. The image and
signed release have not been rebuilt or changed.

The exact installed official Zot binary SHA256 is
`a32e42d042d1f17b5b1317e55cc1a415a744c873dcd05c25c56b665478258bcb`.
An isolated loopback regression with that binary stalled a client for65s:
default settings returned2681472 of33554432 bytes; an explicit90s write deadline
returned all33554432 bytes with the correct SHA256. Both disposable servers and
their data were removed. The native verifier also accepts the900s candidate.
An additional real-OIDC fixture used an ephemeral RSA/JWKS provider and a6s
token. Its authenticated32MiB stream completed after a9s client stall, while a
new connection with the same expired token received401. No live credentials or
registry were involved.

## Registry correction

`deployment/analytics_registry_stream_transition.py` derives from the already
used registry permission transaction. Its exact live configuration preimage is
`880dca7bb8aede9a833e31e938abc7b6f2ee1dd96911be927de6ce5502318d1a`.
It adds only `http.writeTimeout: "900s"`, proves semantic equality after removing
that field, and preserves authentication, authorization, read timeout, storage
and all other values. The candidate is checked with the exact native verifier
before atomic publication. The operation retains private exact backups, restarts
only Zot and verifies stable401 behavior plus unchanged Nginx/Forgejo processes.
Explicit recovery accepts only the retained old or derived target bytes.
Unknown configuration is preserved and unqualifiable recovery stops only Zot.

This is a one-time platform correction. It is not a new ordinary-release step.
The read-only companion reports only selected timeout fields, published blob
integrity and bounded transfer diagnostics; it never prints credentials.

## Analytics completion policy

The old Canary180s pull/225s whole-pull credential assumption is insufficient
for a cold330MB Analytics image over this link. The correction explicitly
distinguishes fresh admission from completion of already-authenticated work.

| Bound | Analytics | Original Canary |
| --- | --- | --- |
| GitHub OIDC and sealed-FD lifetime maximum |300s, unchanged |300s, unchanged |
| Fresh credential threshold before replay |225s, unchanged |225s, unchanged |
| Single pull command ceiling |500s, also clamped to remaining normal-work budget |180s, unchanged |
| Whole normal first-install operation |570s monotonic deadline |Unchanged |
| Independent stop-only cleanup |45s stop +30s stopped-state check |Unchanged |
| Manifest preflight before normal work |30s |Unchanged |
| Executor response |720s |600s, unchanged |
| Existing edge |900s |900s, unchanged |

Normal work checks the common deadline before and after each command and pull,
and before final success. A late pull cannot begin Compose; late startup or
readiness uses the fixed stop-only reserve. Replay finalization and response
have additional operational margin:570+75+30+15=690<720. Broker prefix117 plus
response720 is837<900. Filesystem/fsync stalls are not given hard real-time
guarantees by these arithmetic bounds.

No token expiry, issuer, audience, FD grammar, replay or signature rule changes.
Expired credentials are rejected before admission. A new HTTP request after
token expiry must still fail at Zot. Work already admitted and streams already
authenticated may finish within the bounded job window; this is an explicit
Analytics policy change, not a claim of a longer-lived registry token.

Zot2.1.20's `newOIDCBearerTokenResponse` returns the original OIDC token and its
original expiry. Do not assume a Basic exchange mints a different/longer-lived
credential or restore a helper that rejects an unchanged returned token.
Inspect the exact owning source version before reusing an authentication helper.

## Validation and activation

The existing C34D test collection runs the transaction and Analytics deadline
tests. Regressions cover exact preimage/delta, failed publication/restart,
interruption and unknown-state recovery, fresh admission versus simulated long
completion, remaining-budget clamping, late success, stop-only reserve and
unchanged Canary limits. Native stream qualification is
`deployment/tests/accept_zot_stream_deadline.py`; its hostname/hash guard confines
it to the isolated truexdevelopment fixture. Do not run it on DEV/production.
The earlier real timeout journal demonstrated Docker daemon cancellation when
the unchanged command runner killed its timed-out CLI.

Before another signed dispatch, owner-local registry activation must pass,
the exact corrected Analytics source/configuration and final workflow authority
must be installed, and the full entry matrix must pass. Source/CI qualification
does not prove the cold pull or the real application journey. Inspect actual
pull/startup/health and recovery results before accepting Task014.
