<!--
File: docs/operations/task014-failure-prevention-20261102.md
Purpose: Reusable Task013/014 failure-prevention preflight, informed by
         actual signed Analytics 0.15.0 DEV first-install incidents.
Related: task013-release-readiness.md; task014-pre-release-checklist.md;
         m05-analytics-normal-release-procedure-20261029.md.
Authority: Guidance only. This file cannot authorize a workflow dispatch,
           service restart, credential access, release, or production change.
-->

# Task014 failure-prevention preflight

## Baseline and scope

The first private Analytics 0.15.0 DEV install, authenticated two-tenant E2E,
isolated PG16 restore, encrypted second-machine backup and owner-approved
shared rootless Docker-manager restart are **accepted as bounded DEV evidence**.
M04 issued DEV-only GO on 2026-11-02. Neither that approval nor a successful
signed Task013 release authorizes production, another dispatch, host reboot or
new product source. See Omnilyzer coordination Issue #27 and platform PR #278.

Apply this procedure before a materially changed Task013/014 release boundary.
Reuse valid evidence for unchanged boundaries. Keep one current mismatch matrix,
one owning diagnosis and one consolidated M04 review. Do not re-run a successful
signed dispatch just because a later unrelated test fails.

## One read-only, fail-closed matrix before privileged action

1. **Authority and exact Git source**: compare active GitHub `main`, reviewed
   product PR HEAD, source tree, release workflow SHA, signed Task013 origin run,
   OCI digest and actual installed authority. Product default `main` may be
   legacy/demo source: the signed 0.15.0 product was PR52 SHA
   `4cdda7faeba57abb3388f9be5c450fe6afb1140d`. Never sign a mutable
   branch, silently change reviewed hash pins, or infer deployment from a PR.
2. **Actual host identities**: discover binary paths, UIDs, systemd system AND
   user service names and loginctl/runtime sockets. DEV `runuser` was
   `/usr/sbin/runuser`; the rootless user unit was
   `omnilyzer-task014-rootless-docker.service`, not `docker.service`.
   Assumptions must be checked against the installed namespace, not just host
   paths. Include all independent mismatches in the first read-only report.
3. **Real producer-to-consumer interfaces**: qualify source builder, loader,
   configuration projection, systemd sandbox, PID1-created socket, peer identity,
   sealed descriptor, executor, rootless Docker, registry stream and app.
   Mismatched eight-versus-ten identity fields and UID0/PID1 sender credentials
   escaped isolated mocks. Verify exact permitted peer, framing, socket inode,
   namespace and object schemas; never broaden an allowlist on failure.
4. **Database and roles**: enumerate actual bounded non-system PG roles and
   archive TOC dependencies before isolated restore. Earlier restore attempts
   failed from incomplete *test fixture* role selection, not an observed live
   DB fault. Use only a disposable networkless/no-host-mount PG16 instance,
   check archive hashes, original schema, and exact cleanup. State honestly
   that NOLOGIN role recreation does not prove original privileges/ACLs.
5. **Registry and release**: prove complete large-layer streaming, OCI digest,
   OIDC audience/issuer, Zot/Forgejo authentication, credential expiry and
   coherent upstream/downstream timeouts. Small manifest GET success is
   insufficient. One examined 900-second Zot HTTP write timeout addressed a
   real truncation boundary. Preserve original zero Critical/High policy,
   provenance, Sigstore/Cosign identity, immutable destinations and replay.
6. **Shared lifecycle**: inventory all five DEV containers and restart
   policies, pinned image/container IDs, networks, 127.0.0.1:3141 and Canary
   3020. Rootless restart may interrupt PostgreSQL and Canary: require a
   separately approved maintenance window, stop cleanup, exact-ID postcheck,
   broker/Beszel health and rollback. User-manager restart PASS is not
   whole-host boot-order PASS.
7. **Backup security**: check protected original archive and isolated restore
   first; encrypted off-host copy and its real private decrypt/hash receipt
   second. Never ask for or log user-held recovery passphrase. Point-in-time
   backup on a second laptop is not recurring or geographic disaster recovery.
8. **Application acceptance**: signed deployment success and CI are not the
   authenticated browser/API/PG journey. Prove actual auth/session, cross-tenant
   isolation, collector persistence, denial, private ingress and cleanup once.
   Re-check only boundaries changed by the next release.
9. **Classify findings**: identify whether each mismatch is product, test
   fixture, platform contract, host prerequisite, external registry, or owner
   authorization. Fix it at its owning layer. Preserve raw root-private evidence
   while publishing only non-secret status. Do not reset replay/identity state
   or retry ambiguous dispatch.
10. **Stop and close**: after one consolidated defect-fix batch and focused
    tests, run relevant CI and one independent final M04 review. A repeated
    identical failure triggers root-cause/architecture escalation, not a third
    blind command. No waiver of critical checks. Publish exactly one acceptance
    record and close the scope; track unrelated future gates elsewhere.

## One non-privileged Task14B DEV matrix (source-only qualification)

The existing platform preflight has a bounded successor mode. Invoke from the
isolated, reviewed platform source using Python without sudo:

    python3 -m deployment.analytics_dev_host_preflight --successor-read-only

This is one aggregate read-only report rather than one root command per failed
asset. It includes the original Task014 installed path/socket/unit statuses,
metadata status of the proposed owner-key trust anchor under the existing
root-controlled configuration directory, the actual Analytics broker, loopback
unit, executor socket and Beszel monitor status, and HTTP response statuses
from ONLY private 127.0.0.1 Analytics 3141 /readyz + /livez and Canary
3020 /readyz. No redirects, secret value reads, Docker/DB operation, login,
credential acquisition, or privileged access occurs. Only fixed GET
requests contact the localhost listener.

**Interpretation:** inaccessible is not missing. The unprivileged
omnigpt user cannot infer whether the root-controlled owner-key file exists
inside an inaccessible directory, nor independently establish privileged
role/volume/socket metadata. preflight_observations_complete=false remains
whenever such authority cannot be inspected. HTTP 200 proves only the private
health endpoint at the time of the read. HTTP 503 on Canary3020 is the
previously documented maintenance baseline, NOT a new canary failure or GO.
Even with fully observed services and endpoints, release_decision=HOLD,
task14b_supported_release_verified=false,
task14b_owner_signature_verified=false,
task14b_m04_qa_accepted=false and task14b_rollback_verified=false
until each distinct boundary has independent real evidence.

This check does not satisfy Task14B's separate host-level root-controlled
preflight, approved owner signature, privileged service qualification,
original signed Task013 provenance/OCI verification, or genuine successor
rollback tests. Do not turn its statuses into deployment authority.

## Reuse limit

The accepted 0.15.0 release is still hard-pinned in many Task013/014 code
paths. A next version is HOLD until Task14B Issue #281's dynamic, independently
authorized source/release contract is actually implemented, verified and
separately accepted. Task14A 0.15.0 DEV remains closed. Browser/CSP/no-store,
host reboot, future container recreation and recurring backup gates are
separately tracked in platform Issue #280.
