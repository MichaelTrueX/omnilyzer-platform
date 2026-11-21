# Task14B DEV: durable completion and legacy 0.16.0 recovery

Status: SOURCE ONLY / HARD HOLD. Not installed, dispatched, restarted or used
on PROD. Original runtime source is immutable 330f3255.

## Proven incident

Task014 run 44890393889 passed original broker owner-source and signed
request reviews, then consumed its fresh GitHub JTI, but the inherited Unix
executor failed before socket acquisition during successor_restart_recovery.
Broker HTTP503, failed executor and start-limited socket. Signed Analytics
0.16.0 still privately serves readyz and livez HTTP200.

The owner's bounded root read-only check proved switched generation2 green
with the exact immutable signed 0.16.0 image. The historical execution proof
was ABSENT, old successful run43838827603 replay was ABSENT, and failed new
run44890393889 replay remained consumed. A historical owner-approved OAT
returned the originally signed 0.16.0 to the same green container, moving
journal gen1 switched to restored to gen2 switched under the same request SHA.
Its original root final receipt exact hash and four OAT root receipts were
verified by the owner, including unchanged replay/DB and current journal.

The installed replay ledger legitimately deletes expired finished JWT records
upon later consume, but the startup code required that short-lived record
forever. The current gen2 journal also lacks a newer ordinary schema3 proof.
Neither source-only expiry changes nor fake replay insertion can fix both.

## New normal signed releases

After original SQLite replay finishes, fsync one exclusive UID991 mode0600
per-request completion receipt in the existing private execution proof
directory. Only finished replay plus exact immutable signed canonical request
and switched OCI/route identity can write it. The returned success response
comes only after fsync. A new JTI may later prune old finished replay.
Restart then requires the immutable post-finish completion, both owner-signed
source identities, independently validated original signed request, active
image/RepoDigest/container/route and stable journal. An observed consumed or
executing prior request still denies. No changes to JTI replay semantics.

## Unique historical gen2 owner OAT bridge

A read-only UID991 restart exception is limited to original signed
run43838827603, original request SHA, owner source, exact green0.16 digest
and container and generation2 journal. Its distinct completion certificate
must have root UID0/group991 mode0440, created only after the root-attested
historical final receipt and four OAT receipts have been verified.

The source-only root operator has a read-only preflight and a distinct bounded
apply that creates one such certificate. It verifies actual historical root
receipt bytes/SHA, exact gen1/gen2 OAT lineage, current UID991 live route
and Docker image, original and failed JTI classifications, and no certificate
preexistence. It does not write SQLite replay, container/route state, service
configuration, host ingress, signing materials or PROD. An unexpected outcome
is HOLD without automatic retry.

Historical OAT receipts are evidence of a past owner-approved maintenance
transaction, not a new signed Task014 release. The legacy certificate can
never authorize any other product/version/run/generation.

## Independent acceptance requirements

1. Complete real temporary Linux SQLite and filesystem plus negative tests
   of expiry, tampered certificate, unsafe file identity, partial replay,
   signed owner mismatch, active image/slot/container mismatch and OAT lineage.
2. Independent M04 review the exact source, migration operator, source manifest
   closure, pinned installed service identity and root safety boundaries.
3. Deploy the new source IMMUTABLY on DEV only under the existing approved
   release mechanism. Do not patch the active source or weaken its OIDC SHA.
4. Only after review/authorization, run exactly one owner-native root
   attestation operation and separately prove UID991 recovery, protected
   socket and active signed0.16 stability. No blind reset-failed action.
5. A new signed Analytics0.16.1 Task014 must use a NEW GitHub run/JTI after
   proven recovery. Failed run44890393889 is consumed and cannot be replayed.
6. Preserve all PROD protections and original signed release records. The
   later second ordinary new-version release without source/root changes is
   still required to satisfy the original Task14B Definition of Done.
