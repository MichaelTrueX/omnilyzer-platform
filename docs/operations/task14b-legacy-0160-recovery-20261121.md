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

### M04 source-review clarification: historical owner proof

The permanent ordinary successor path always revalidates both current
Ed25519 owner approvals from the canonical persisted request and root
approval. The narrow historical OAT has no new ordinary schema3 request:
its 0.16.0 owner verification occurred in the original signed Task014
run43838827603. On restart, the immutable exact SHA256 of its subsequent
root final-release receipt and exact SHA256 root OAT lineage are the
historic completed owner-attestation trust anchor. The root-owned bridge
pins the exact original product and platform source SHA; it cannot
create new signed owner authority. This intentionally does NOT pretend
to re-read the original release's missing/older per-version Ed25519 file.
The current installed root approval directory is 0750 and was not
readable to UID1005, so its contents were not independently examined
in this unprivileged M04-style source review. Acceptance still requires
native root review and an explicit independent security verdict.

### Additional M04 review: immutable source closure and root operator

The installed Generation4 application source graph is exactly 26 reviewed
files under the root-owned SHA-named directory. The historical certificate
reader and its pinned source identities are now in the EXISTING allowlisted
'deployment/analytics_route_journal.py'. The former separate
'deployment/analytics_legacy_0160_attestation.py' was removed from the patch
because the generation4 archive would otherwise omit it and make real
UID991 restart fail despite green source-only tests. Preserve this exact
runtime allowlist and independently rebuild its 26-file SHA binding.

'deployment/analytics_legacy_0160_migration.py' is intentionally not a
permanent runtime dependency. It is a separate root-operator SNAPSHOT,
requiring its own exact Git SHA256 review and owner-native installation as
root:root 0500. Its entrypoint refuses Python -I execution from a mutable
checkout, symlink source or arbitrary /usr/local helper path. It only admits
an approved root-owned 0755 SHA-named installed generation path beneath
/opt/omnilyzer/deployment; this root-only companion must not be copied
or run until that exact source generation has been immutably installed
and its separate operator bytes formally approved by M04.

No new module changes to PROD or to the Canary baseline are authorized.

The old original local owner-approval path is beneath a root:GID991
0750 directory, which UID1005 cannot inspect. The old original Task014
release had its own already-verified signed owner source; for this unique
historical OAT recovery, the root final receipt's SHA256 and exact
owner-approved source SHA metadata are the durable attestation, not a
fresh signed owner authorization. This is an explicit historical authority
exception requiring independent M04 source/security review, not a
permission for future ordinary schema3 releases. Those continue to verify
both Ed25519 owner approvals at each restart.

The native-root QA gate remains unfulfilled for the separately installed
operator: root:991 0440 creation, exact generation2 historical continuity,
race/interrupted write, read-only OAT receipts, UID991 reader and 0.16 private
route all require direct verification. No tests here used PROD or touched
the working signed0.16 service.

### M04 second installation review: operator packaging contract (supersedes older path language)

The ordinary source installer accepts exactly the independently approved
38-record archive and installs only the fixed 26-file privileged runtime
closure, plus the existing bounded runtime evidence. It NEVER includes the
one-shot `analytics_legacy_0160_migration.py` operator. An older proposed
operator location *inside* the SHA-named installed tree was consequently
uninstallable without modifying the immutable source after publication. That
route is PROHIBITED.

The one-time operator is therefore a separately reviewed, root-only
`/usr/local/libexec/omnilyzer-m05-legacy-0160-migration.py`, installed
root:root 0500 with an independently verified full SHA256 matching the
exact reviewed Git source. The root actor must explicitly supply the
approved 40-hex source commit as the second argument for either
`--preflight` or `--apply`. There is no default to `main`, HEAD or a
request-selected path. Before the operator imports any deployment Python,
its hard-coded entrypoint validates root UID/EUID/GID/EGID, the exact
operator pathname (including root-owned non-writable ancestry), exact
root:root mode0500 single-link script, and the immutable reviewed
root:root 0755 SHA-named installation with exact root-owned 0644
`analytics_route_journal.py` and `policy.py`. A user worktree, symlink,
wrong mode, wrong identity or unknown SHA is HOLD. A reviewed source SHA
is not a release approval: only the separately authorized native-root
installation/activation process may supply it, after verifying the exact
38-file archive, signed owner authority and all 26 code hashes.

Source-only tests assert both the reviewed expected filesystem state and
independent negative failures for root script owner/mode/link, imported
module owner/mode/link, untrusted parent directory and wrong SHA. No
root 0500 installation or root-to-UID991 positive migration has occurred.

M04 must review the complete root handoff procedure before approving
installation: 1) immutable source install, 2) separately SHA-pinned operator
installation, 3) root read-only preflight and complete historical evidence
verification, 4) one-time `--apply` with root-owned certificate, 5) source
config+service restart transaction with rollback preflight and no JTI reset.
Every failure is HOLD with no silent auto-retry. Do not supply any root
command that could run before all those gates are verified.
