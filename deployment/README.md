# Task 014: exact-digest promotion and deployment control plane

Task 014 consumes accepted Task 013 release outputs and controls their ordered deployment. The release system builds, scans, signs, and publishes artifacts. This package does not build or publish anything; it accepts only a trusted release already identified as `repository@sha256:...`.

## Phase 1 boundary

Phase 1 is a repository-side, non-live foundation. All three environment files set `deployment_enabled` to `false`, leave runtime configuration, secret, and ingress references unset, and name the intended GitHub environments without attaching a deployment job. The `Platform promotion request` workflow has one read-only gate job. It validates and hashes a request, confirms the selected environment remains disabled, and then exits. It has no deployment job, environment attachment, OIDC permission, registry credential, or runtime adapter.

Later phases must activate each environment deliberately, supply merge-SHA-bound references, maintain required branch and environment protections, configure them for later stages, and validate live ingress, migration, health, switching, rollback, ownership, restart/recovery, registry authorization, TLS, and audit rotation. PROD requires explicit approval. The current DEV protection state is recorded below; deployment remains disabled.

## GitHub protection state (2026-09-24)

The repository is now public. `main` is protected by the active repository ruleset `Protect main`. The GitHub deployment environment `task014-dev` exists with `deployment_branch_policy.protected_branches=true` and `deployment_branch_policy.custom_branch_policies=false`. The branch/environment protection capability prerequisite is satisfied for DEV; these protections must remain enforced. ADR 0011's 2026-09-08 private-repository limitation remains historical context.

C31 provisioning and its pinned step-20 recovery have now completed and converged under separate authorization. Installed runtime assets remain inactive. Deployment activation remains prohibited. `deployment/environments/dev.json` retains `activation.deployment_enabled=false`.

## Pinned C31 step-20 recovery (completed historical procedure)

The failed C31 run from `e386cc07708fcb0b94fae5a7b9422a15c9e2c792`
completed step 19 and failed closed at replay initialization in step 20. Its
authorization was consumed. The reviewed recovery accepted only a commit with
that exact commit as a direct parent. It proved the pinned
old C17 and old C26. Every proposed current C17 field except
`reviewed_commit` must reconstruct the pinned e386 C17 SHA-256 before
readiness or recovery treats it as authority. Recovery also proves the retained
237-entry Python environment, exact initial deployment state, absent or exact
zero-consumption replay, pristine audit,
absent provisioning snapshot, and exact old/current replay directory modes.
The three changed C25 files migrate in a fixed order from exact Git blobs;
only exact completed prefixes and a verified next-file stage may be resumed.
An installed current C17 requires all three replacements; the predecessor C17
requires the old replay-directory mode. Other step-order combinations fail
closed.
Before advancing past an existing application prefix, recovery retries the
fixed deployment-directory sync. It likewise retries the exact C17 parent
directory sync before advancing from an already-current C17.
The replay directory transitions once from root:replay-group `0770` to
root:replay-group `02770`; a rerun accepts the exact new mode. Unknown residue,
an active deployment state, journal/WAL/SHM leftovers, or unrelated lineage
blocks recovery without repair.

The reviewed operator flow was: merge the fix, use a trusted root-controlled exact
commit execution tree, and run this one read-only command with the already
qualified C28 and C31P staging locations:

```sh
python3 -B -m deployment.dev_c31_recovery_readiness --wheelhouse-path "$C28_WHEELHOUSE" --pip-installer-staging "$C31P_STAGING"
```

A successful result reports the reviewed commit, predecessor, C17, application,
directory, deployment-state, replay and audit states, Python manifest, and
whether a separate C31 authorization could be considered. The command did not
execute C31 or grant authorization. The separately authorized C31 operation
subsequently completed and converged. No systemd, Docker, registry/OIDC, or
deployment activation followed; `deployment_enabled` stays `false`.

## C32B read-only release consumers

`release_consumer.py` adds inert fixed-route GET consumers for the exact Task 013
zot OCI manifest digest and Forgejo Generic `release-evidence.tar.gz` package.
The archive is bounded and restricted to the Task 013 file set. The exact
release manifest, provenance, and signature bundles pass to an injected
signature verifier; `promotion.verify_release_evidence()` remains the release
policy boundary. Only after that verification does C32B project the existing
promotion request and already-authorized GitHub identity into the existing
canonical DEV executor request. Consumers accept distinct short-lived read
credential types and retain neither tokens nor network results in state or audit.
They perform no credential exchange, Docker operation, workflow activation, or
host mutation.

Task 013's published release manifest and provenance do not include the
originating GitHub release run ID. C32B therefore requires an injected,
independent release-run verifier to bind that ID to the exact release hashes,
source, version, and digest before constructing a request. This PR supplies no
live implementation of that verifier. The accepted identity policy validates
`workflow_sha` as an exact SHA, while the current configuration does not pin it to a reviewed
revision. Activation must add an independently reviewed revision binding and
resolve the release-run evidence gap before treating either as live authority.

## C32C inert broker integration

`broker_integration.py` adds a supplied-value handler for one exact canonical
DEV `PromotionRequest` and compact OIDC token. It rejects unknown and
noncanonical promotion fields and bounds both inputs before invoking the
existing broker. The broker now supports a constructor-bound request builder:
it cryptographically verifies the token through its verifier, reauthorizes the
exact returned identity, invokes C32B's fixed-route release acquisition and
injected signature/release-run checks, constructs the existing
`ExecutorRequest`, reparses and binds its final canonical bytes, consumes replay
against their SHA-256, and sends those same bytes once through the existing
transport. The executor independently reparses and validates them. The prior
canonical-byte broker API remains available to existing inert callers.

This is repository implemented and deterministically tested, not installed,
activated, or live validated. The handler has no listener, service entrypoint,
credential exchange, or production composition. Read credentials should remain
inside the future unprivileged environment-local broker, separately scoped for
zot and Forgejo; they must not be given to arbitrary GitHub workflow code.
The real Sigstore/OCI verifier requires a separately reviewed trust-root and
verification design. The release-run verifier requires independent Task 013
run-to-artifact evidence, potentially a verified GitHub run/artifact source;
the promotion's run ID alone is insufficient. Before activation, a reviewed
authority must also pin `workflow_sha` to the approved workflow revision,
independently of the token and request agreeing with each other. No current
main commit is made permanent authority here.

`broker.py` is selected by C25/C26 and its repository bytes have changed; the
new integration module is not selected. The completed C31 installed application
tree therefore must not be treated as this C32C generation. A separately
designed, integrity-checked post-C31 update and source-set review are required
before installing or composing C32C on the host. C31 recovery and host state
are unchanged. Deployment activation remains prohibited.

## Phase 2B2 deployment-authority and runtime contract

[ADR 0011](../docs/adr/0011-oidc-restricted-deployment-authority.md) selects a GitHub-hosted deployment job attached to a protected environment, short-lived GitHub Actions OIDC, an unprivileged restricted broker, a closed canonical request over a local Unix-domain socket, and a narrow privileged executor. The broker has no Docker socket. The executor must parse and independently revalidate the request and exposes no shell, arbitrary command, arbitrary Compose file, arbitrary filesystem path, arbitrary repository, arbitrary image, or arbitrary environment.

`identity.py` remains pure authorization policy for **already cryptographically verified** GitHub OIDC claims. It requires the exact DEV audience, repository and numeric identity, workflow ref and revision, main ref, environment, manual event, GitHub-hosted runner, run and actor IDs, temporal claims, and a bounded JTI. Caller-supplied time makes the five-minute lifetime, sixty-second receipt, and thirty-second skew rules deterministic. `ReplayGuard` defines atomic single-use behavior through expiry plus skew. Its in-memory implementation is test-only; the durable implementation described below remains inert and unwired.

### C1 OIDC verifier and dependency boundary

C1 adds a concrete but inert, repository-only verifier in `oidc_verifier.py` and a bounded discovery, HTTPS, JWKS, and in-memory cache boundary in `jwks.py`. The verifier accepts only a compact RS256 JWT, the fixed GitHub issuer, the exact single-string Task 014 DEV audience, and one completely validated RSA JWK selected by a safe `kid`. It uses PyJWT backed by cryptography, passes the literal `algorithms=["RS256"]`, and forwards only verified claims to `authorize_verified_github_oidc()`. The single caller-supplied `received_at` remains authoritative for all temporal authorization. C1 does not consume replay.

Discovery and JWKS retrieval have fixed GitHub HTTPS locations, GET-only behavior, validated system TLS, no proxy-environment handling, no redirects, exact status and JSON media-type requirements, bounded headers and bodies, and approximately three-second connect/read limits with monotonic checks. Python's standard system resolver is used; it does not prove a hard overall DNS or end-to-end deadline. Resolver behavior and the complete deadline require activation-time host qualification.

The JWKS cache is memory-only, serialized, atomically replaced only after complete validation, and reusable for at most 300 seconds. Shorter upstream `max-age`, `no-cache`, and `no-store` directives shorten or eliminate reuse. Unknown keys receive at most one controlled refresh per verification. Expired keys are never used after refresh failure, removed keys cease to be accepted after successful replacement, and no keys or tokens are persisted.

The dedicated [dependency contract](DEPENDENCIES.md) records the CPython 3.12 Linux x86_64 target, exact direct and transitive pins, accepted binary-wheel filenames, hashes, licenses, and provenance. C1 neither creates nor claims a reviewed production wheelhouse or host installation.

C1 adds no replay persistence, broker HTTP API, Unix transport, executor, registry consumer, audit projection, installation asset, workflow authority, listener, or deployment activation. A separate live-authority review remains an absolute prerequisite before any live workflow or DEV deployment can be enabled.

### Durable SQLite replay boundary

`replay_sqlite.py` now supplies an inert, repository-only `SQLiteReplayGuard`. It provides explicit initialization, read-only `validate()`, and the closed `consume()`, `begin_execution()`, and `finish_execution()` operations, but no broker consumes it and no executor transitions it. This repository change does not install or initialize the production directory or database at `/var/lib/omnilyzer/deployment/authority/replay.sqlite3`, and it creates or opens no filesystem state merely by import or construction.

Future reviewed installation must create the dedicated replay directory as root:replay-group mode `02770` and the database as root:replay-group mode `0660`. The setgid bit makes new database and `DELETE` rollback-journal inodes inherit the reviewed replay GID even when the initializer, broker, and executor have different effective primary GIDs. The database owner remains exactly root. A transient journal may be owned only by root, the reviewed broker UID, or the reviewed executor UID; its replay GID, mode `0660`, regular-file type, single link, and size bound remain exact. This permits the other reviewed writer to recover a hot journal after a crash. The store rejects symlinks, hard links, permissive or mismatched ownership and modes, unexpected directory entries, and databases exceeding 16 MiB. It uses only standard-library SQLite, rollback-journal `DELETE` mode, 4096-byte pages, at most 4096 pages, at most 10,000 live rows, and a busy timeout no greater than 1,000 milliseconds. WAL and shared-memory files remain prohibited pending activation-time filesystem qualification.

On Linux, each operation traverses every absolute directory component from `/` using retained directory descriptors and `O_DIRECTORY|O_NOFOLLOW`, then validates the final descriptor against the configured pathname. It opens and retains the database with `O_NOFOLLOW`, connects SQLite through the held authority-directory descriptor, and compares the named and held database identities before and after use. This prevents an ancestor or authority-directory symlink from redirecting SQLite, prevents a directory replacement after opening from redirecting access, and detects persistent database replacement. CPython 3.12's standard `sqlite3` API accepts only a filename or URI and exposes neither an existing-file-descriptor connection nor its SQLite VFS file handle. It therefore cannot prove that SQLite opened the previously validated database inode against an attacker able to replace and restore the database leaf name entirely between the library's internal `open` and the next identity comparison. The same filename-only limitation applies to replacement and restoration of the rollback journal between its bounded precheck and SQLite's internal recovery open. Activation must qualify the directory as writable only by the narrowly trusted authority principal; eliminating those residual windows would require a reviewed native SQLite VFS or a different storage boundary.

Initialization retains the securely created database descriptor through schema creation and durability checks. Any reported failure attempts to quarantine that exact inode by removing its authority mode, truncating and synchronizing it, and unlinking and synchronizing the directory when the name still identifies it. This prevents ordinary fsync, schema, commit, and connection-close failures from leaving normally accepted state. No userspace implementation can guarantee the post-crash outcome if the filesystem reports failure for both the original durability operation and every quarantine operation, or if power is lost during that uncertainty; activation-time filesystem qualification and explicit operator replacement of any failed initialization residue remain required. Normal operations never initialize, migrate, repair, delete, or replace malformed state.

Each consumption durably binds only the bounded JTI, expiry-plus-skew retention epoch, executor-request SHA-256, GitHub run ID and attempt, and one closed lifecycle status. JWTs, bearer tokens, claims JSON, credentials, canonical request bytes, responses, and outcome details are never replay fields. A transaction validates the filesystem, database identity, exact schema, integrity, size, and SQLite policy; advances a persistent clock watermark; performs bounded deterministic expiry cleanup in `retain_until, jti` order; checks capacity; and inserts the complete binding under `BEGIN IMMEDIATE` with `synchronous=FULL`. Duplicate JTIs and duplicate run-ID/attempt pairs are definite replay rejections; uncertain storage, locking, integrity, schema, mode, clock, or durability failures are unavailable failures.

The only states are `consumed`, `executing`, and `finished`, with only forward one-time transitions. Every transition matches the complete binding. A consumed row may begin execution only while its retention remains valid. Expired consumed and finished rows may be cleaned, but an executing row is never deleted automatically and continues to count toward capacity. If an executor crashes after entering `executing`, the request is never automatically retried or reset; later operator reconciliation requires separate review. The persistent watermark never moves backward, rejects wall-clock rollback beyond the authorization skew, and prevents a small rollback from resurrecting an already expired and removed identity.

The durable replay code remains non-live: there is no installed state, broker, transport, executor wiring, listener, service, registry access, or deployment activation. Maintained branch and GitHub environment protections, activation-time filesystem qualification, and a separate live-authority review remain absolute prerequisites before the store or any live workflow or DEV deployment can be enabled.

### Restricted broker core

`broker.py` supplies the inert repository-only `RestrictedDeploymentBroker`. Its verifier, replay guard, and opaque executor transport are mandatory constructor-bound collaborators with no unsafe defaults and cannot be replaced per request. Construction invokes none of them and performs no network, filesystem, replay initialization, socket, listener, service, Docker, registry, application, or deployment action.

For one exact built-in string token, exact built-in canonical request bytes, and exact non-negative built-in integer receipt time, the broker calls the verifier once, independently reconstructs and reauthorizes the exact base GitHub identity using that same receipt time, parses the canonical executor request, binds every request identity field, hashes the original request bytes, consumes replay once, and only then sends the same original bytes through the bound transport. Invalid tokens, requests, identity mismatches, and definite replay duplicates return the generic `deployment request is not accepted`; metadata, replay-storage, transport, response, and unexpected collaborator failures return `deployment authority is unavailable`. Neither message contains token, claim, JTI, request, hash, run, path, host, SQL, dependency, response, or subprocess details.

The transport response remains opaque because the future privileged-executor response schema is not part of C4. C4 permits an empty exact built-in `bytes` response and caps every response at 64 KiB; strings, mutable buffers, views, subclasses, coercible objects, and oversized values fail closed. Replay is never reset, deleted, retried, or transitioned if transport or response validation subsequently fails. The broker never calls replay `begin_execution()` or `finish_execution()`.

C4 adds no HTTP endpoint, public listener, Unix-socket implementation, broker installation, executor implementation, systemd or Nginx asset, workflow authority, environment attachment, registry consumer, token exchange, runtime invocation, production filesystem state, or deployment activation. GitHub protection and a separate live-authority review remain absolute activation prerequisites.

### Bounded Unix executor transport

`unix_transport.py` adds the inert client-side `UnixExecutorTransport` for the
broker's existing opaque-byte transport contract. It captures the one fixed
production rendezvous path `/run/omnilyzer/deployment/executor.sock` and all
standard-library operations during construction without inspecting the path or
creating a socket. Each call validates exact nonempty built-in request bytes,
uses one connection for one request, transmits a four-byte unsigned big-endian
length followed by those exact bytes, shuts down its write side, and accepts
one similarly framed exact built-in response. Empty responses are allowed;
request and response payloads are each bounded to 64 KiB, and truncation,
oversized declarations, trailing bytes, or a second frame fail closed.

Before connecting, the pathname must identify a non-symlink Unix socket with
one link, exact mode `0660`, the configured executor owner UID, and the
separately configured socket-group GID. After connecting, Linux `SO_PEERCRED`
must report a positive PID and the configured executor process UID and GID;
the path is then checked again for the same device, inode, and accepted
metadata before any request byte is sent. Peer credentials authenticate the
connected local process, while pathname metadata constrains the rendezvous
point. The socket-file group is deliberately distinct from the executor
process GID because a future systemd-created socket may be broker-group
accessible while the executor retains a different effective group.

Two consecutive captured-monotonic deadlines bound the exchange. The existing
caller-selected 1–3,000 millisecond deadline still begins before pathname
validation and covers validation, creation, connection, credential and metadata
checks, exact request transmission, and successful write-side shutdown. Only
after `shutdown(SHUT_WR)` succeeds, the transport creates one separate fixed
600,000 millisecond response deadline. That same response deadline—never
restarted—covers the four-byte response header, declared body, EOF proof, and
final cleanup checks. This allows the executor's bounded deployment operation to
finish before returning its C6 response without weakening the strict connection
and request-delivery bound or creating an unbounded wait.

Every potentially blocking socket operation receives only its current phase's
remaining budget. Failure after request delivery is uncertain: the client closes
without reconnecting or resending and reports only the generic unavailable error.
There is no caller-controlled response timeout, reconnect, resend, retry,
heartbeat, polling/status API, background execution, shared framing state,
descriptor inheritance, compact-token or claims-mapping transmission, added
identity envelope, arbitrary path, client bind, listener, or server
implementation. The canonical request itself retains its required bounded OIDC
JTI and execution-identity fields; removing them would violate the existing
executor contract and exact-byte forwarding rule. All operational errors are
reduced to `executor transport is unavailable` without path, identity, payload,
framing, timing, timeout, errno, or dependency details.

C5 does not install or qualify the parent ownership and mode chain beneath
`/run/omnilyzer/deployment`, create or contact the production socket, or
implement the executor listener. Activation must separately install and
validate that complete chain. Root-equivalent local compromise is outside what
a Unix-socket client can defend against. GitHub protections and a separate
live-authority review remain mandatory before this inert transport may be
installed, connected to a production executor, or used for deployment.

`execution.py` continues to define immutable closed runtime, no-secret, ingress, and executor-request models. Its broker protocol now exposes only the safe token, canonical-request bytes, and receipt-time API implemented by the restricted broker. The only operation is `deploy` to DEV. Canonical JSON reuses the repository's sorted, compact, ASCII, newline-terminated representation. Privileged-executor and transport types remain protocols. C4 adds no HTTP or Unix server, systemd service, or public endpoint.

### Restricted privileged-executor core

`executor.py` supplies the inert repository-only `RestrictedPrivilegedExecutor`. Its replay lifecycle and one approved deployment operation are mandatory, immutable constructor-bound collaborators. They must expose ordinary instance methods `begin_execution()`, `deploy()`, and `finish_execution()`; construction invokes none of them and performs no filesystem, socket, network, process, Docker, registry, service, application, or deployment action. No collaborator or operation selector can be supplied per request.

For one non-empty exact built-in `bytes` request within the 64 KiB request bound, C6 independently invokes the trusted canonical request parser and thereby reconstructs the exact base `ExecutorRequest` under the closed Task 014 DEV policy. It hashes the exact original bytes, snapshots the exact built-in JTI, GitHub run ID, run attempt, and lowercase SHA-256 binding, then orders exactly one `begin_execution`, one fixed `deploy`, and—only after an exact `None` operation result—one `finish_execution`. Definite begin replay conflicts return `executor request is not accepted`; uncertain replay, operation, finish, hash-provider, collaborator-contract, and response failures return `executor is unavailable`. Neither generic message discloses request, identity, hash, dependency, runtime, or host details. There are no retries, replay resets, rollbacks, repairs, or deletions.

Success is the closed canonical ASCII JSON response `{"executor_request_sha256":"<64 lowercase hex>","schema_version":1,"status":"succeeded"}\n`, bounded by the existing 64 KiB broker/transport response limit. The Python parser is authoritative and rejects duplicate members, noncanonical encodings, non-exact built-in values, and boolean or floating-point schema versions that JSON Schema cannot distinguish in every standards implementation.

The executor captures one coherent operation tuple at the start of each call, uses a non-reentrant in-process execution gate, and retains its pre-operation replay/hash snapshot even if trusted same-process code forcibly mutates the request or executor object. These defenses limit accidental or hostile redirection inside one Python process; they do not replace operating-system process isolation or make arbitrary code in that process trustworthy.

C6 implements replay lifecycle and a closed success response only. The durable audit identity projection already exists in `audit.py`, but this slice deliberately emits no audit event: complete result and failure audit sequencing must be composed with the real deployment operation in a later separately reviewed change. Audit emission remains mandatory before activation, and no live authority may be activated without complete audit wiring. C6 does not compose the Unix transport, deployment controller, Docker runtime, registry access, production replay or audit paths, installation, services, or deployment activation.

### Bounded Unix executor connection handler

`executor_server.py` adds the inert C7 handler for one already-connected Unix
stream socket supplied by a future separately reviewed listener. Import and
construction create no socket, listener, filesystem entry, service, runtime,
registry connection, application process, or deployment action. The handler
accepts no pathname or listener dependency. It constructor-binds one ordinary
`execute(canonical_request)` method plus exact broker UID/GID values and one
1–3,000 millisecond socket-I/O timeout.

Before reading, the handler independently requires a non-inheritable AF_UNIX
SOCK_STREAM connection and exact Linux `SO_PEERCRED` bytes containing a
positive PID and the configured broker UID/GID. One coherent fail-closed
monotonic deadline covers peer checks, the four-byte unsigned big-endian request
length, the exact nonempty request body of at most 64 KiB, and exact EOF. Partial
reads and EINTR retain the same deadline; truncation, missing EOF, trailing data,
and a second frame fail before execution. The exact received bytes are passed
unchanged to the captured executor exactly once; semantic parsing and DEV policy
remain solely the executor's responsibility.

Deployment execution is outside the three-second request deadline. Only after
execution returns does a new deadline bound canonical response validation,
partial-safe transmission of the four-byte length and exact response bytes, and
write-side shutdown. The existing `parse_canonical_response()` contract and
64 KiB response bound are authoritative; no error response is fabricated.
Every path closes the supplied connection. Post-request failures are uncertain
and never retry execution, resend, reconnect, reset replay, or reverse a
completed deployment. Operational failures expose only `executor connection is
unavailable`; control-flow exceptions remain preserved after cleanup.

C7 does not create, bind, listen on, accept, install, enable, or contact the
production socket. Its real-socket tests use unnamed AF_UNIX `socketpair()`
descriptors only and never bind a filesystem pathname. Listener ownership,
process composition, installation, service lifecycle, audit sequencing, and
activation remain future separately reviewed work.

### Bounded inert Unix executor listener

`executor_listener.py` adds the inert C9 boundary for one connection accepted
from an already-created, already-bound, constructor-supplied AF_UNIX stream
listener. C9 never creates, binds, listens on, installs, enables, discovers, or
removes the fixed `/run/omnilyzer/deployment/executor.sock` pathname. A future
separately reviewed installation or systemd socket layer must create that
socket and enforce its ownership, group, mode, and lifecycle.

Before its single bounded `accept()`, C9 verifies the listener domain, type,
active-listening state, non-inheritability, fixed pathname, descriptor/path
identities, and exact socket-file mode `0660`, link count, owner, and group.
Linux exposes the open socket descriptor through a sockfs device/inode and its
pathname through a separate filesystem device/inode, so those unlike inode
numbers are not incorrectly equated. Instead C9 requires one unique listening
entry in `/proc/self/net/unix` that binds the descriptor's sockfs inode to the
fixed path; connected accepted-socket rows are distinct and ignored. C9 also
independently snapshots the descriptor and pathname
identities. It rejects symlink or non-directory ancestors and repeats the
complete validation before dispatch. Python's pathname `lstat()` interface
cannot make multiple ancestor and leaf observations one atomic kernel
transaction; the before/after identity and unique proc-binding checks fail
closed for observed substitution, but they do not claim to eliminate a
rename-and-restore race by a process already able to mutate the protected
production directory hierarchy. Production directory ownership and permissions
therefore remain an installation-layer prerequisite responsibility.

One non-restarting monotonic deadline of at most three seconds covers validation,
one accept, post-accept validation, and restoration of the listener's prior
timeout state. C9 accepts no second connection, performs no retry, and rejects
concurrent or reentrant calls on one instance. After successful post-accept
validation and timeout restoration, it passes the exact accepted socket once
to the constructor-captured C7 `UnixExecutorConnectionHandler.handle()` method.
C7 remains solely authoritative for broker peer authentication, request and
response framing, execution, socket-I/O deadlines, and accepted-connection
cleanup. Accordingly, the accept deadline ends before C7 may perform a
minutes-long deployment. C9 closes only connections that fail before dispatch
and never double-closes a connection transferred to C7.

C9 provides no loop, daemon, worker, fork, signal, status, shutdown, service
installation, or activation API. Its tests use deterministic filesystem and
listener fakes plus unnamed `socketpair()` descriptors; they never touch or
create the production path. Required GitHub branch and environment protections
remain an absolute prerequisite for live authority. DEV, STAGING, and PROD
remain disabled.

### Audited DEV deployment operation

`deployment_operation.py` adds the inert C8 composition behind the executor's
closed `deploy(ExecutorRequest) -> None` boundary. Construction captures only
ordinary runtime, state-store, audit-sink, and UTC-clock methods plus one exact
reviewed commit and the reviewed runtime/ingress SHA-256 values. It has no
production constructor, startup path, listener, workflow hook, filesystem path,
command, service, registry client, or activation API.

Each call independently reconstructs an exact-base request and its nested
references, rejects mutation or subclasses, and checks the request's repository,
commit, allowlisted paths, file hashes, loopback ingress, no-secrets contract,
and exact image/digest against the constructor-bound review. It similarly
reconstructs one exact, candidate-free DEV state before using the existing
controller's candidate, gate, and completion transitions.

The closed sequence durably audits and checkpoints candidate preparation and
migration before health, metadata, Nginx, and traffic gates. Every audit event
is deterministically identified from the exact canonical executor-request hash,
constructed with `AuditEvent.for_executor_request()`, and rebound with
`require_executor_request()` before one append attempt. Schema-2 now includes
the distinct terminal `promotion_failed` event with result `failed`; rejection
history remains unchanged.

After a confirmed candidate switch, any state or final-audit failure causes one
closed attempt to restore the former blue/green route—or the no-active
maintenance route on a first deployment—and then the original durable state.
No runtime action, state write, audit append, migration, traffic switch, or
compensation is retried. Failures expose only `DEV deployment operation is
unavailable`; no dependency output or request identity is included.

The Docker runtime's new `restore_traffic("dev", previous_slot)` capability
accepts only exact `blue`, `green`, or `None`. It uses the same atomic fragment
replacement, Nginx validation/reload, and old-route self-restoration boundary as
the normal switch and exposes no arbitrary path, fragment, upstream, service,
or command.

C8 remains non-activatable repository code. Its tests use deterministic fakes
and temporary local directories only; they perform no Docker, Compose, network,
registry, application, production-filesystem, listener, service, host, or
deployment operation.

### Hardened fixed-path DEV deployment state store

`state_store.py` adds C10's inert `FilesystemDeploymentStateStore` behind the
exact `load() -> DeploymentState` and `save(DeploymentState) -> None`
collaborator boundary consumed by C8. Import and construction perform no
filesystem operation. The only production pathname is the non-configurable
`/var/lib/omnilyzer/deployment/dev/state.json`; C10 provides no initialization,
directory creation, repair, reset, deletion, enumeration, migration, chmod,
chown, arbitrary-path, or temporary-path API.

A future separately reviewed installation must provision the complete path and
an initial canonical no-active DEV state before this store can operate. `/`,
`/var`, `/var/lib`, `/var/lib/omnilyzer`, and
`/var/lib/omnilyzer/deployment` must be root-owned real directories and may not
be group/other writable unless they have the root-owned sticky-directory
protection used by standard temporary roots in tests. C23 later closed that
ancestor ownership projection; the deployment-owned final `dev` directory has
the configured numeric owner and group and must be exactly `0700`. The existing
`state.json` must be a single-link regular file, never a symlink, with exact
mode `0600`, configured owner/group, and a nonempty size no greater than 16 KiB.

Every operation traverses from `/` with retained descriptor-relative
`O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` opens, compares named and opened
device/inode identities, rejects unexpected directory entries or fixed
temporary residue, and revalidates the retained chain. A process-local
non-reentrant gate covers threads and store instances; a non-waiting exclusive
`flock()` on the retained `dev` directory coordinates cooperating processes.
The advisory lock is retained through validation, replacement, verification,
temporary cleanup, and non-locking descriptor cleanup. Processes with
equivalent filesystem authority must cooperate with this advisory lock.

Loads use an exact no-follow state descriptor, bounded progress-checked reads,
an explicit EOF proof, strict UTF-8 JSON with duplicate-member and non-standard
constant rejection, the authoritative closed `DeploymentState.from_dict()`
parser, and exact canonical persisted-byte equality. They return only an exact
base `DeploymentState` for stage `dev`.

Saves first reconstruct the complete exact-base state and nested migration
graph twice through non-virtual field access, without calling caller
serialization, conversion, iteration, equality, or deepcopy hooks. The
authoritative parser validates the snapshot, and only bounded canonical bytes
are retained. Under coordination C10 validates the existing canonical state,
creates the fixed `.state.json.tmp` leaf exclusively with no-follow/CLOEXEC and
mode `0600`, completes bounded writes, fsyncs and revalidates the temporary,
reconfirms the original state and directory identities and bytes, atomically
replaces `state.json`, fsyncs the directory, then reopens and verifies the exact
result. Pre-replacement failures preserve the original; cleanup unlinks only a
temporary name still matching the created inode. Post-replacement or durability
uncertainty fails closed without rollback, repair, or a claim that the old
state remains active.

All operational failures expose only `deployment state storage is unavailable`;
control-flow exceptions are preserved after cleanup. Descriptor-relative
opens and repeated named/descriptor observations narrow substitution races but
do not form a transaction with the filesystem namespace. A process already
able to mutate the protected directory hierarchy can attempt changes between
observations, and repeated exact-state observations cannot prove detection of
every theoretically reversible concurrent Python-object mutation. Secure
directory authority, advisory-lock cooperation, and process isolation remain
installation requirements. Supported-API immutability prevents ordinary
configuration reassignment; it is not a defense against arbitrary code
execution inside the interpreter.

C10 does not compose the executor process and did not access the production
state path during implementation or testing. Its real-filesystem tests use
only secured temporary directories and remove only test-created objects. All
environments remain disabled, and a separate live-authority review remains
an absolute prerequisite for activation.

### Inert DEV executor composition and restricted networks

`executor_composition.py` adds C11's closed, inert composition root. It
constructs the fixed-path DEV state store, production-path replay guard without
initializing it, default filesystem audit sink, subprocess command runner,
closed Docker runtime adapter, audited deployment operation, restricted
executor, connection handler, and listener wrapper. The caller must supply an
already-provisioned listener plus the narrowly scoped candidate HTTP client and
reviewed installation/release values. Import and construction perform no
filesystem, replay, audit, socket, process, Docker, HTTP, registry, application,
or deployment operation. Only a later explicit `serve_once()` call crosses the
listener boundary; C11 provides no installation or activation layer.

The composition root sits below external trigger and authorization
acquisition. It neither acquires nor validates OIDC tokens, contacts GitHub,
creates GitHub deployments or environments, nor decides how a deployment is
initiated. The current `ExecutorRequest` and replay identity contract remains
GitHub-oriented and C11 does not weaken or generalize it to non-GitHub
identities.

Omnilyzer must later support applications in restricted or private networks
where external deployment initiation or external health monitoring may be
prohibited. A separately approved future profile may allow an explicitly
authorized manual/local trigger from inside the private network while
preserving the same immutable release, exact OCI digest,
SBOM/provenance/signature requirements, deployment engine, state and audit
controls, and migration and blue/green semantics. C11 does not implement that
trigger. Monitoring may later be internal to the private network, or use
outbound-only telemetry if the applicable network policy permits; C11
implements no monitoring functionality.

### Inert GitHub-authorized DEV broker composition

`broker_composition.py` adds C12's one concrete GitHub-authorized DEV broker
profile. It composes the existing GitHub OIDC verifier, fixed-path durable
replay guard, fixed-socket executor transport, and restricted broker without
performing verification, network access, replay initialization or consumption,
socket inspection or connection, request forwarding, or deployment during
import or construction. Its only public operation delegates a later explicit
request to the reviewed broker core.

This GitHub DEV authorization profile is intentionally separate from C11's
executor composition, and the current GitHub OIDC and `ExecutorRequest`
identity semantics remain unchanged. Restricted-network applications may
later require a separately reviewed manual/local authorization
profile, but C12 neither implements nor generalizes for that profile. Any such
future profile must preserve release verification, exact-digest enforcement,
state and audit controls, migration behavior, and the executor boundary. The
future C13 host-installation contract should describe resources required by
both concrete process compositions without assuming every deployment is
GitHub-triggered.

### Inert DEV host installation contract

`installation_contract.py` adds C13's pure declarative DEV host contract. It
unifies the numeric installation identities projected into C11 and C12 and
describes their fixed state, replay, audit, and executor-socket resources. The
shared replay directory and database are root-owned with one dedicated replay
group; state and audit ownership follow the executor UID/GID; socket ownership
uses the executor UID and a dedicated socket-access group distinct from the
executor process GID. Both compositions receive identical replay ownership and
socket-group expectations, while broker and executor peer UID/GID values remain
explicit service identities. Required supplementary-group memberships are
declared without querying or changing host group state.

C13 remains repository-only and performs no host preflight or provisioning. It
does not inspect or create a path, initialize replay, write initial state,
create an audit file or socket, install a systemd asset, or start a service.
DEV, STAGING, and PROD remain disabled pending separate live-authority review.
A later separately reviewed slice must
qualify complete ancestor chains and provision, initialize, install, and start
the required host resources and services.

This host-resource isolation contract does not assume every future deployment
is GitHub-triggered. C12 and the current request/replay identity semantics remain
GitHub-oriented. A future restricted-network profile may require a separately
reviewed local/manual authorization mechanism and an explicit identity-schema
extension or version. C13 implements neither;
compatible profiles must retain exact-digest release verification, deployment
controls, and the reusable C11 executor boundary.

### Closed Docker Compose candidate probe

C14 supplies the concrete candidate-probe collaborator that was missing from
C11. It selects only the exact blue or green Docker Compose candidate service,
then runs one fixed bounded helper inside that container. The helper requests
only `/livez`, `/readyz`, or `/metadata` from the candidate's own
`127.0.0.1:8080` loopback. Candidate application ports remain unpublished on
the host, and the client provides no proxy, DNS, arbitrary network target,
shell command, or retry surface.

C14 introduced the client as non-live repository code without wiring it into
the executor composition. C15 performs that composition closure as described
below. C14 changed no workflow, environment, installation contract, service,
or activation authority, and introduced no application-specific fork; the same
deployment engine remains reusable within any future separately reviewed
restricted-network authorization profile.

### Closed DEV executor candidate-probe composition

C15 closes C11 around C14's reviewed concrete candidate probe. The arbitrary
`candidate_http_client` constructor input is removed. Instead,
`DevExecutorComposition` constructs one `SubprocessCommandRunner`, supplies
that same instance to both `DockerComposeCandidateHttpClient` and
`DockerRuntimeAdapter`, and binds the same unchanged exact canary image to both
components.

Import and construction remain inert: no candidate probe, Docker or subprocess
operation, path access, or listener action occurs. The already-provisioned
listener remains caller-supplied because socket creation and service activation
are still deferred to a separately reviewed layer. C15 adds no host
installation, workflow authority, environment activation, socket creation,
Docker execution, or deployment, and it remains below any future external
authorization mechanism.

### Closed systemd executor socket-activation handoff

C16 adds an uninstalled, one-shot handoff for a future systemd-provided
executor listener. An explicit early-bootstrap acquisition accepts exactly one
descriptor starting at FD 3: `LISTEN_FDS` must be exactly `1`,
`LISTEN_FDNAMES` exactly `omnilyzer-executor`, and `LISTEN_PID` the canonical
decimal identity of the current process. When `LISTEN_PIDFDID` is present, its
canonical value is verified against a temporary pidfd for the current process,
and that temporary descriptor is always closed.

Every acquisition attempt consumes `LISTEN_PID`, `LISTEN_PIDFDID`,
`LISTEN_FDS`, and `LISTEN_FDNAMES`, whether it succeeds or fails. The inherited
FD is wrapped without duplication, made non-inheritable, and returned for a
later service/bootstrap layer to supply to `DevExecutorComposition`. This
environment mutation is process-global, so acquisition must occur during early
single-threaded bootstrap.

C16 does not duplicate `UnixExecutorListener` validation of socket type, path,
inode, mode, ownership, listening state, or ancestor safety. It does not create,
bind, or listen on the executor socket, construct the executor composition,
provision a host resource, or introduce, install, enable, or start a `.socket`
or `.service` unit. A later separately reviewed systemd socket asset will need
to provide exactly one descriptor named `omnilyzer-executor`; no such asset
exists in C16, and deployment activation remains blocked.

### Closed DEV executor service configuration contract

C17 defines the pure canonical contract for a future root-owned DEV executor
service configuration at `/etc/omnilyzer/deployment/dev/executor.json`. Its
future directory and file modes are respectively `0750` and `0640`, with root
ownership and executor-group read access. The configuration contains no secret
or credential. Its six numeric service identities are validated through C13,
so C13 remains authoritative for host identity and ownership relationships.

One exact `canary_image` binds an executor process lifetime to one immutable
digest. The exact `reviewed_commit`, runtime-configuration SHA-256, and three
ingress SHA-256 values select one reviewed reference set. Runtime and ingress
paths remain code-owned—including the fixed three `INGRESS_PATHS`—and cannot be
configured. The JSON schema is closed, duplicate-free, ASCII canonical,
newline-terminated, and bounded to 4096 bytes.

C17's parser is pure: it neither reads nor creates the future `/etc` resource.
Its projection supplies exactly C15's non-listener/non-clock constructor values;
C16 socket acquisition and the production clock remain separate future
bootstrap inputs. C17 does not construct or run the executor, add a systemd
unit, install a service, or activate deployment. A future change to the image,
reviewed commit, runtime hash, or ingress hashes will require a separately
controlled root-owned configuration replacement and executor restart or
re-bootstrap; that replacement mechanism does not exist in C17.

### Hardened DEV executor service configuration loader

C18 adds the hardened read-only loader for an already-existing C17
configuration at `/etc/omnilyzer/deployment/dev/executor.json`. It traverses
from `/` with descriptor-relative opens; directories require `O_DIRECTORY`,
`O_NOFOLLOW`, and `O_CLOEXEC`, while `executor.json` additionally requires
`O_NONBLOCK`. Standard ancestors must be root-owned and not writable by group
or other. The final `dev` directory must be root-owned mode `0750`, and the
configuration must be a root-owned, regular, single-link file of mode `0640`
within the C17 4096-byte bound.

Named and opened inode/device identities are matched, the exact bounded bytes
are passed only to C17's canonical parser, and the complete directory chain and
file are revalidated after reading. The final directory and file GID must match
C17's `executor_gid`; the process's real and effective UID/GID must match the
configured executor identity. Supplementary groups must equal C13's required
executor groups, apart from an optionally reported primary GID, with no
unrelated group authority. Process identity is snapshotted before and after the
load, and all owned descriptors are closed before return. The loader is
intended for early single-threaded service bootstrap.

C18 never creates, modifies, or provisions `/etc`. C16 socket activation stays
separate, and composing C15 remains future bootstrap work. C18 introduces no
service or systemd asset and leaves deployment disabled; it does not assert
that the production configuration file exists.

### Inert DEV executor service bootstrap

C19 is the inert bridge between the reviewed executor service boundaries.
Import performs no operational action. One explicit
`run_dev_executor_service_once()` call first loads exactly one hardened C18
configuration and obtains C17's exact non-operational C15 projection. Only
after that preparation succeeds does it acquire one C16 systemd listener,
construct C15 once with a fixed UTC second-precision audit clock, and invoke
`serve_once()` at most once.

After C16 returns, C19 owns that exact inherited listener until it closes the
listener exactly once before ordinary return or failure. There is no retry,
reload, reacquisition, or service loop, and cleanup preserves active
`KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` exceptions. No config
path, image, digest, identity, listener, or clock input is caller-configurable.

C19 adds no CLI or `__main__` entrypoint, creates/binds/listens on no socket,
and creates, installs, enables, or starts no systemd asset. It provisions no
host resource and does not automatically activate deployment authority. A
later separately reviewed slice may define inert systemd service/socket assets
or another host entry mechanism. Deployment remains disabled pending the
separate live-authority review.

### Closed DEV executor service process entrypoint

C20 adds only the closed process entrypoint for the future module execution
contract `python -m deployment.executor_service_entrypoint`. Import remains
inert, `main()` accepts zero arguments, and one call delegates exactly once to
C19. Exact normal exit codes are 0 for success, 1 for an ordinary bootstrap
exception or unexpected non-`None` result, and 2 for unsupported trailing
process arguments. Extra arguments are rejected before C19 is called. Ordinary
exceptions are neither printed nor logged; `KeyboardInterrupt`, `SystemExit`,
and `GeneratorExit` are not translated by `main()`.

C20 has no retry, service loop, signal handler, or environment configuration,
and no direct filesystem, socket, Docker, subprocess, or systemd behavior. It
adds no package or console-script installation and chooses neither an absolute
interpreter path nor a repository installation directory. No systemd service
or socket asset exists yet, no host resource is provisioned, and no deployment
authority is activated. Deployment remains disabled pending the separate
live-authority review. A later separately reviewed slice may bind a systemd
service asset to this reviewed module execution contract.

### Inert DEV host-service layout

C21 defines the closed, immutable, zero-input `DevHostServiceLayout()` contract:

| Field | Fixed future value |
| --- | --- |
| Installation root | `/opt/omnilyzer/deployment` |
| Application root | `/opt/omnilyzer/deployment/app` |
| Virtual environment root | `/opt/omnilyzer/deployment/venv` |
| Python executable | `/opt/omnilyzer/deployment/venv/bin/python` |
| WorkingDirectory | `/opt/omnilyzer/deployment/app` |

Future process argv is the immutable tuple
`("/opt/omnilyzer/deployment/venv/bin/python", "-m", "deployment.executor_service_entrypoint")`.
C20 retains the module entrypoint and its exit behavior; no shell is involved.

Symbolic future principals are broker `omnilyzer-broker / omnilyzer-broker`,
executor `omnilyzer-executor / omnilyzer-executor`, replay group
`omnilyzer-replay`, and socket-sharing group `omnilyzer-deployment`.
Names are symbolic only: C21 creates no account/group and selects no UID/GID
values. C13 retains numeric identity/resource ownership relationships and C17
retains exact service numeric identity authority. Future provisioning must
resolve these names to actual numeric IDs and make C17 match those exact IDs.
No Docker/sudo membership is assigned; the privileged executor mechanism
remains separately reviewable.

The existing Unix transport authority supplies
`/run/omnilyzer/deployment/executor.sock`; C21 never inspects or creates it.
Reserved future unit names are `omnilyzer-deployment-executor.service` and
`omnilyzer-deployment-executor.socket`. C21 adds no systemd unit and installs,
enables, or starts no service. C22 below adds inert, uninstalled systemd
socket/service assets tied to this layout.

Import and construction perform no host inspection or environment lookup.
C21 creates no path, creates no virtual environment, and installs no dependency.
Installation-tree ownership/modes and interpreter/venv integrity still require
future provisioning qualification. Deployment remains disabled pending GitHub
branch/environment protections.

### Inert DEV executor systemd socket and service assets

C22 adds exactly two repository assets:

- `deployment/systemd/dev/omnilyzer-deployment-executor.socket`
- `deployment/systemd/dev/omnilyzer-deployment-executor.service`

Both are inert, uninstalled, disabled and unstarted. Their names and layout
values project C21; C13/C17 retain numeric identity authority, and C18 still
validates real process identities/groups. These files create no account or group
and do not guarantee the host database has no additional memberships. Future
provisioning must resolve the symbolic names to C17's exact numeric identities
and provide only reviewed memberships satisfying C17/C18.

The socket unit has this single listener contract:

```ini
ListenStream=/run/omnilyzer/deployment/executor.sock
SocketUser=omnilyzer-executor
SocketGroup=omnilyzer-deployment
SocketMode=0660
DirectoryMode=0755
FileDescriptorName=omnilyzer-executor
Accept=no
Service=omnilyzer-deployment-executor.service
RemoveOnStop=yes
```

`DirectoryMode=0755` permits broker traversal without group/other directory
writes if future activation creates missing parents. C22 creates no directory
or socket. `Accept=no` passes one listening FD, rather than starting a service
per connection. Future systemd activation supplies FD 3, `LISTEN_FDS=1` and
`LISTEN_FDNAMES=omnilyzer-executor`; C16 continues to validate/consume activation
state, including optional PIDFD identity, and C9 retains listener validation.
The socket's `[Install] WantedBy=sockets.target` is declarative only.

The service has no `[Install]` section and must not be enabled independently.
It requires and follows `omnilyzer-deployment-executor.socket`. It uses
`Type=exec`, `User=omnilyzer-executor`, `Group=omnilyzer-executor` and only
`SupplementaryGroups=omnilyzer-replay`; the inherited listener requires no
executor socket-sharing group membership. C21's exact process layout is:

```ini
WorkingDirectory=/opt/omnilyzer/deployment/app
ExecStart=/opt/omnilyzer/deployment/venv/bin/python -m deployment.executor_service_entrypoint
Restart=no
```

The direct exec reaches C20/C19's one-attempt boundary with no shell, wrapper,
PATH lookup, extra arguments, environment configuration or automatic restart.
The complete reviewed hardening set is:

```ini
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/omnilyzer/deployment
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

The sole persistent read/write allowance is `/var/lib/omnilyzer/deployment`,
including reviewed state, replay and audit resources. Under
`ProtectSystem=strict`, `/etc` service configuration and `/opt`
application/venv remain read-only. Existing resource validators retain exact
ownership/mode authority; these directives provision nothing.

`ProtectProc`/`ProcSubset` are intentionally absent because C9 needs
`/proc/self/net/unix`. No separate PID namespace is selected. `PrivateUsers`
is absent to preserve real numeric host identity validation. `PrivateNetwork`
and `IPAddressDeny` are absent because the reviewed executor graph includes
bounded local candidate HTTP probing; address families are restricted to
AF_UNIX/AF_INET/AF_INET6. No system-call filter or `MemoryDenyWriteExecute` is
selected until the exact Python/native dependency/runtime graph is separately
qualified.

C22 grants no Docker/sudo/capability privilege and references no Docker socket
or credential channel. It does not make live Docker deployment functional.
No host path, account, group or venv is provisioned, no dependency is installed,
and neither unit is installed/enabled/started. No systemctl action occurs.
Deployment remains disabled pending GitHub branch/environment protections.
A later separately reviewed slice must qualify/provision host resources,
installation-tree ownership/modes, interpreter/venv integrity and the privileged
runtime mechanism before any installation or activation.

### Inert DEV host provisioning contract

C23 provides `DevHostProvisioningContract(*, installation=...)`, an inert
provisioning contract, not a provisioner. Its only input is one exact, already
validated `DevHostInstallationContract`; no independent identity, path, mode,
layout or configuration overrides are accepted. Import/construction perform no
host I/O. All five public value/contract classes are frozen and slotted, and
requirement collections are immutable tuples.

| Contract | Retained authority |
| --- | --- |
| C13 | Numeric identities, derived memberships, state/replay/audit/socket resources and their lifecycles |
| C17 | Canonical executor config path, modes and content authority |
| C18 | Real runtime process identity/group validation |
| C21 | Symbolic principals, /opt layout, interpreter/module argv and unit names |
| C22 | Inert systemd unit source assets |
| C23 | Closed projection describing required future host bindings/resources |

Named broker/executor users must have positive non-root UIDs and primary GIDs,
with distinct UIDs. The four symbolic groups must resolve to four distinct
positive GIDs. C23 rejects root aliasing and group aliasing; C13 remains broader
and reusable by design. No actual name lookup or numeric ID allocation occurs.
The future bindings project the supplied C13 installation object exactly:

| Symbolic principal | Numeric binding |
| --- | --- |
| Group `omnilyzer-broker` | `installation.broker_gid` |
| Group `omnilyzer-executor` | `installation.executor_gid` |
| Group `omnilyzer-replay` | `installation.replay_group_gid` |
| Group `omnilyzer-deployment` | `installation.socket_group_gid` |
| User `omnilyzer-broker` | UID `installation.broker_uid`, primary GID `installation.broker_gid` |
| User `omnilyzer-executor` | UID `installation.executor_uid`, primary GID `installation.executor_gid` |

Broker supplementary GIDs are C13's `broker_required_group_gids`, exactly
`(replay_group_gid, socket_group_gid)` under C23's distinct-group topology.
Executor supplementary GIDs are C13's `executor_required_group_gids`, exactly
`(replay_group_gid,)`; no executor socket-sharing membership is added. A later
account-creation mechanism must separately choose safe non-login account details
and ensure host memberships satisfy C17/C18.

`runtime_resource_requirements()` returns C13's original immutable objects
unchanged. State retains its canonical no-active-state prerequisite; replay
retains separate reviewed initialization; audit retains first-append creation;
the executor socket retains future runtime-service creation. C23's additional
paths do not collide with any C13 runtime resource path. Their exact order and
metadata are:

| Additional path | Kind | Mode | Numeric owner:group | Requirement |
| --- | --- | --- | --- | --- |
| `/opt/omnilyzer` | directory | 0755 | 0:0 | Must exist before activation |
| `/opt/omnilyzer/deployment` | directory | 0755 | 0:0 | Must exist before activation |
| `/opt/omnilyzer/deployment/app` | directory | 0755 | 0:0 | Reviewed application content before activation |
| `/opt/omnilyzer/deployment/venv` | directory | 0755 | 0:0 | Reviewed venv content before activation |
| `/etc/omnilyzer` | directory | 0755 | 0:0 | Must exist before activation |
| `/etc/omnilyzer/deployment` | directory | 0755 | 0:0 | Must exist before activation |
| `/etc/omnilyzer/deployment/dev` | directory | 0750 | 0:executor_gid | Must exist before activation |
| `/etc/omnilyzer/deployment/dev/executor.json` | regular_file | 0640 | 0:executor_gid | C17 canonical config before activation |
| `/var/lib/omnilyzer` | directory | 0755 | 0:0 | Must exist before activation |
| `/var/lib/omnilyzer/deployment` | directory | 0755 | 0:0 | Must exist before activation |
| `/run/omnilyzer` | directory | 0755 | 0:0 | Future systemd socket-directory creation only |
| `/run/omnilyzer/deployment` | directory | 0755 | 0:0 | Future systemd socket-directory creation only |

Here `0:0` is root:root and `executor_gid` is the C13 numeric executor GID.
C21 supplies the /opt layout; C17 supplies config path/modes and its parent is
derived textually. A future provisioner must obtain a separately reviewed C17
configuration object and write exactly its canonical bytes; C23 generates no
config JSON. The /run directories remain future systemd-created socket parents,
compatible with C22 `DirectoryMode=0755`; C23 does not create them.

The two future installation mappings, in socket/service order, are:

| Repository source | Future destination |
| --- | --- |
| `deployment/systemd/dev/omnilyzer-deployment-executor.socket` | `/etc/systemd/system/omnilyzer-deployment-executor.socket` |
| `deployment/systemd/dev/omnilyzer-deployment-executor.service` | `/etc/systemd/system/omnilyzer-deployment-executor.service` |

Both destinations require root:root 0644. Names come from C21 and sources are the
reviewed C22 assets. `/etc/systemd/system` itself is OS/systemd-owned and is not
a C23 directory-provisioning requirement. No source is read, hashed or copied
by C23, no unit is installed, no daemon-reload occurs and no systemctl command
is run.

`service_layout()` retains C21's descriptive Python path
`/opt/omnilyzer/deployment/venv/bin/python`; C23 does not classify it as a
provisioned regular file or decide whether it is copied or symlinked. Application
tree integrity and venv/interpreter/package integrity remain future-qualified;
no checkout, application file list, wheelhouse or new integrity hashes are
selected. No account/group, directory/file or venv is created, no dependency is
installed, and no state/replay/audit resource is initialized. No socket is
created. Docker privilege remains unresolved and separately reviewable; no
Docker/sudo/capability authority is granted. Deployment remains disabled pending
GitHub branch/environment protections.

Future work should separately close:

1. Installation/application/venv integrity qualification.
2. Read-only host qualification and provisioning mechanics.
3. Narrow privileged runtime authority.
4. Only after prerequisites, actual installation/activation.

## C24 DEV installation integrity qualification contract

`installation_integrity_contract.py` defines a closed, pure, inert installation
integrity **qualification contract**. It does not qualify the current host.
`DevInstallationIntegrityContract(*, configuration=...)` accepts only an exact
C17 `DevExecutorServiceConfiguration`, revalidates its canonical bytes in memory,
and caches one C21 layout and immutable application/environment requirements.
Forged or malformed C17 inputs fail with the fixed C24 TypeError. C17 remains
the sole reviewed source-revision authority; C21 remains the path authority;
C23 provisioning metadata and directory requirements remain unchanged.

Application requirements project C21's `/opt/omnilyzer/deployment/app` and
C17's `reviewed_commit`. A future approved manifest must bind to that commit,
use `canonical-relative-file-set-v1`, and describe every installed regular file
with canonical POSIX relative `path`, exact SHA-256 (`sha256`), and installed
`mode`. Entries must be sorted and unique by relative path, regular-files only,
and complete. Future qualification must fail closed on unlisted or missing
paths, symlinks, devices/FIFOs/sockets, digest mismatches and mode mismatches.
Directories remain governed by C23. No actual application file set is selected
in C24: the deployment-control-plane packaging boundary and manifest production
remain future reviewed work. C24 does not choose a checkout, deployment subtree,
runtime subset, archive, wheel, editable install, zipapp or copied repository.
No application manifest or approved application digest exists in C24.

Python environment requirements project C21's `/opt/omnilyzer/deployment/venv`
and `/opt/omnilyzer/deployment/venv/bin/python`. The target is **CPython 3.12,
Ubuntu 24.04, Linux x86_64, glibc**. The C1 dependency input is exactly
`deployment/requirements-linux-x86_64-py312.lock`, pinned to SHA-256
`13c7b3f0050f9aff0a94ab324a66276638f8b1b9dd0c62232ec205b24d874d0d`.
Tests independently hash the repository lock and cross-check its four records.
A future dependency change requires explicit coordinated C1/C24 review.

The exact ordered reviewed wheel closure is:

| Wheel filename | SHA-256 |
| --- | --- |
| `pyjwt-2.13.0-py3-none-any.whl` | `66adcc2aff09b3f1bbd95fc1e1577df8ac8723c978552fd43304c8a290ac5728` |
| `cryptography-50.0.1-cp311-abi3-manylinux_2_34_x86_64.whl` | `51afcfceb15597cf2635068e4ac9a56b2abde622edde17f37d85fd7b5306497a` |
| `cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` | `c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf` |
| `pycparser-3.0-py3-none-any.whl` | `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992` |

Source builds, network installation and extra wheels are forbidden. No
production wheelhouse exists yet and C24 selects no wheelhouse filesystem path.
It defines acceptance criteria, not a location: a future wheelhouse is acceptable
only when its **complete directory entry set** is exactly these four filenames
and every file SHA-256 matches C24. No extra wheel, sdist, metadata file,
requirements file, nested directory, symlink or unexpected filesystem entry
may be silently accepted. C24 does not perform that filesystem check.

Interpreter integrity evidence is mandatory before host qualification:
`interpreter_integrity_required=True`. C24 does not choose copy versus symlink,
a regular executable, venv shim, interpreter artifact or approved interpreter
hash. A later slice must establish reviewed interpreter origin and integrity
before host activation. Caller-selected application, interpreter, venv or
wheelhouse digests cannot confer trust through this contract.

Task 013's current package/release artifacts are synthetic canaries, not
accepted deployment-control-plane host installation evidence. C24 imports no
release authority and does not reuse canary wheels or release manifests as proof
of application or executor environment bytes. Any future packaging relationship
requires separate review.

C24 performs no host I/O, no hashing of the live host, no environment/package
discovery, no wheel download, no package installation, no venv creation, no
source copy, no application manifest generation, no systemd action, no Docker
action and no activation. Its requirements imply no qualified/approved/trusted
host state. Future work must separately establish:

1. Reviewed deployment-control-plane packaging and file-manifest production.
2. Reviewed CPython interpreter provenance and integrity.
3. Production wheel acquisition/staging with exact C24 file-set verification.
4. Read-only host qualification against those reviewed inputs.
5. Only later, provisioning/installation and activation.

## C25 closed DEV application source-set contract

`application_source_set.py` selects **what files** belong below the future C21
application root, `/opt/omnilyzer/deployment/app`. The zero-argument frozen,
slotted `DevApplicationSourceSet` projects that root and the executor entrypoint
from C21. Its explicit reviewed allowlist contains exactly **28 files: 25 Python
module/package files and 3 runtime data files**, sorted lexicographically with
unique paths. Each repository-relative path is also the future path relative to
the application root. For example, `deployment/executor_service_entrypoint.py`
would retain that path below the root. `ApplicationSourceFile` permits only
canonical POSIX relative paths with identical source/target mappings and the
closed kinds `python-module` and `runtime-data`.

C25 selects the installed executor application and its current import graph,
including `deployment/__init__.py`. It does not prove source bytes. C24 defines
what evidence a complete application manifest must contain: the
`canonical-relative-file-set-v1` semantics with sorted unique regular-file
entries containing `path`, `sha256`, and `mode`, bound to C17 `reviewed_commit`.
Future C26 is expected to turn this closed reviewed source selection into
deterministic manifest evidence with those semantics; C26 does not exist in
this slice. C25 supplies no hashes, modes, manifests, packaging format or build.

The exact runtime-data selection is:

- `deployment/runtime/dev/compose.yaml`
- `deployment/runtime/dev/canary-runtime.json`
- `deployment/runtime/dev/nginx/nginx.conf`

The Docker runtime anchors Compose and canonical runtime configuration beneath
`deployment/runtime/dev/`; Compose's relative `./nginx/nginx.conf` bind source
resolves to the third asset. Absolute `/var/lib/...` bind sources are future
host resources, not repository application source files. Tests parse the Python
import closure with stdlib AST without executing application operational
functions, and inspect the fixed Compose text without a new YAML dependency.
They require exact equality with the declared Python and runtime-data sets,
reject dead/new local modules and obvious dynamic imports, and inspect selected
repository files for regular-file and no-symlink status. Production code never
discovers, reads, inspects or hashes source files.

The selection excludes repository governance, tests, documentation, schemas,
environment policy files, provisioning contracts and installation assets:

- `deployment/runtime/dev/host-nginx.conf` is review-only and uninstalled. It
  remains in the existing ingress review/reference contract, but is not a
  runtime file below the C21 application root.
- `deployment/systemd/dev/` service/socket units are future host service assets
  installed under systemd authority, not application-root files.
- The dependency lock, wheels and `pyproject.toml` belong to the C24 Python
  environment boundary, not the application-root manifest.
- C21 layout and C23/C24/C25/C27 qualification, provisioning, source-selection,
  and provenance contracts are repository-side installation authority, not
  runtime application files. C25 does not select itself. The retained C27 key
  and signed metadata under `deployment/provenance/` are review evidence, not
  application-root files. The earlier C13 `installation_contract.py` remains
  selected because the executor runtime imports its identity constants.
- Tests, schemas, environment files, README/DEPENDENCIES documentation, and
  `release/`, `docs/`, `spikes/`, `.github/` and repository-root files are excluded.
  `oidc_verifier.py`, `broker_composition.py` and `runtime.py` are not in the
  current executor import closure.

`broker.py` and `jwks.py` deliberately remain selected: executor/Unix transport
imports broker constants, and broker imports identity and JWKS. C25 records the
reviewed graph as it exists; dependency cleanup requires a separate future
reviewed slice.

C25 does not make `/opt/omnilyzer/deployment/app` exist. No host is modified, no
application is installed, no venv is built, no dependency is installed, and no
systemd asset is installed or started. No packaging, archive, copy, Docker or
candidate operation occurs. Live activation remains blocked by the separate
live-authority review requirement.

## C26 deterministic DEV application manifest evidence

C25 selects **what files** belong in the future application. C26
`application_manifest.py` produces evidence of their exact bytes and normalized
modes at one exact Git commit. Generation requires a canonical absolute
repository root and a nonzero, exact 40-character lowercase commit SHA. It
qualifies Git's repository top level, requires **HEAD == reviewed_commit** and
an actual commit object, and rechecks HEAD after reading the selected objects.
Dirty working-tree state is irrelevant: working-tree application files are
never read as evidence, even when edited, replaced with symlinks or chmodded.

C26 consumes exactly one C25 source-set instance. All 28 selected files are
required, in C25 order; no extra repository file enters the evidence. Strict
NUL-delimited Git tree records must describe regular blobs with mode `100644`.
Executable `100755`, symlink `120000`, missing, duplicate, unknown or malformed
entries fail closed. Git `100644` deliberately maps to manifest mode `"0644"`;
this is a future installation requirement, not a working-tree permission claim.
A future installer must explicitly materialize that exact mode.

The fixed `/usr/bin/git` executable performs only read-only `rev-parse`,
`ls-tree` and `cat-file` plumbing with literal pathspecs. A closed environment
disables replacement objects, lazy promisor fetching, prompts, optional locks
and system/global Git configuration. No arbitrary process Git environment is
inherited. Each operation has a five-second deadline and bounded stdout;
stdin and stderr are suppressed. Blob sizes are qualified before raw content
is requested: at most 1 MiB per blob and 8 MiB combined. Missing objects fail
without a network fallback. SHA-256 hashes exact raw Git blob bytes, with no
checkout filters, newline normalization or text decode/re-encode.

The immutable manifest has exactly `manifest_kind`, `digest_algorithm`,
`reviewed_commit` and `entries`. Its kind is
`canonical-relative-file-set-v1`, its algorithm is `sha256`, and each of its
28 sorted unique entries contains exactly `path`, `sha256` and `mode`.
C26 consumes C24 application-integrity requirements without changing C24.
Canonical JSON reuses `deployment.policy.canonical_bytes`: sorted object keys,
compact separators, ASCII-safe bytes and exactly one final newline, bounded to
64 KiB. `to_dict()` returns fresh containers; `canonical_bytes()` returns
in-memory bytes. C26 never writes, uploads or commits the manifest. A manifest
committed into the commit it names would create a commit self-reference problem;
future reviewed work may store or transfer evidence outside that source commit.
There is no manifest self-digest or trust/approval/qualification boolean.

A caller-supplied commit does not become trusted through generation. A later
reviewed qualification/provisioning slice must require **C26 manifest
reviewed_commit == C17 configuration reviewed_commit**, compare this evidence
against the complete installed application, and establish the other C24
requirements. C21 retains application-root authority. Task 013 synthetic
release-canary evidence is not deployment-control-plane application-installation
evidence; C26 imports no release authority.

C26 does not qualify the host, inspect the application root or live venv, create
`/opt` application paths, install application files, create a venv, stage wheels,
prove CPython interpreter provenance, or install packages. It does not install
systemd assets, enable/start services, use Docker, contact the candidate, alter
workflows or activate deployment. Separate live-authority review
remains mandatory; the activation blocker remains absolute.

## C27 reviewed CPython interpreter provenance

The earlier C27 investigation correctly stopped because an Ubuntu archive key
found in the DEV host keyring was only host-provided data. Its UID and short key
ID could not independently make it a trust anchor. C27 resolves that review
blocker with Canonical's independently published full Ubuntu Archive Automatic
Signing Key (2018) fingerprint:

`F6ECB3762474EDA9D21B7022871920D1991BC93C`

Canonical publishes that full fingerprint in the
[Ubuntu Security Team FAQ](https://wiki.ubuntu.com/SecurityTeam/FAQ) and its
[image-verification guidance](https://documentation.ubuntu.com/security/software-integrity/image-verification/).
Canonical's [Ubuntu 24.04 Chisel archive configuration](https://ubuntu.com/chisel/docs/latest/reference/chisel-releases/chisel.yaml/)
embeds the same key and applies it to `noble`, `noble-security`, and
`noble-updates`. The repository-retained
`provenance/ubuntu-archive-key-2018.asc` contains exactly one public key. Its
computed full fingerprint matches the independently reviewed Canonical value;
that equality—not its local filename, UID, installed-keyring origin, or short
key ID—converts those exact key bytes into C27's accepted verification key. The
retained key file is 1,660 bytes with SHA-256
`2a3cc57ab6b47626b496a101c29af6dfe54d54d03d613f2326b9f2a30a15c39b`.

C27's verified chain is:

```text
Canonical-published full archive-key fingerprint
    -> exact retained public key with that computed fingerprint
    -> valid noble-security InRelease signature by only that key
    -> signed SHA-256 and size for main/binary-amd64/Packages
    -> exact reviewed package records extracted from those index bytes
    -> downloaded .deb bytes matching every record's size and SHA-256
    -> immutable, zero-input repository C27 evidence
```

The retained `provenance/noble-security-20260919T004615Z.InRelease` is the exact
126,127-byte Canonical Ubuntu Snapshot object at
`https://snapshot.ubuntu.com/ubuntu/20260919T004615Z/dists/noble-security/InRelease`,
SHA-256
`603d902fbcedd1666b0897c005771162a7b36288a56aac6a5f557556d53d66de`.
An isolated keyring containing only the accepted key verifies its OpenPGP
signature, created `2026-09-19T00:47:09Z`, with the exact full fingerprint. The
signed metadata identifies Ubuntu `noble-security`, component `main`, and
architecture `amd64`. It signs both of these index identities:

| Signed index path | Size | SHA-256 |
| --- | ---: | --- |
| `main/binary-amd64/Packages` | 5,476,895 | `f8fca2bdd59ee4de64a30fc88df870356c6f43e19372b0dbc7caf8b1f2bb2536` |
| `main/binary-amd64/Packages.xz` | 1,009,196 | `7068ebb5e7f7f862612a63d66e1178de0d136086ae02bc7fe95947ab09d8b6a1` |

The exact timestamped `Packages.xz` bytes match the signed compressed identity;
decompression produces exactly 5,476,895 bytes with the signed uncompressed
SHA-256. The retained host index was independently byte-equal to that result,
but host retention does not confer trust. The uncompressed index is not
committed because it is approximately 5.5 MiB. The selected package fields in
`python_interpreter_provenance.py` are compact, reviewed derived evidence from
that verified index; an extracted stanza is not itself archive-signed. The
retained `InRelease`, signed index identity, immutable snapshot URL, and exact
record fields preserve the relationship and allow independent reproduction.

The closed CPython artifact boundary is exactly:

| Package | Version | Architecture | Artifact path | Size | SHA-256 |
| --- | --- | --- | --- | ---: | --- |
| `libpython3.12-minimal` | `3.12.3-1ubuntu0.17` | `amd64` | `pool/main/p/python3.12/libpython3.12-minimal_3.12.3-1ubuntu0.17_amd64.deb` | 838,536 | `d646ad7112b5adec21ba0e1af015f04ae8ca7f5efdc619622547dd6673c4c14b` |
| `libpython3.12-stdlib` | `3.12.3-1ubuntu0.17` | `amd64` | `pool/main/p/python3.12/libpython3.12-stdlib_3.12.3-1ubuntu0.17_amd64.deb` | 2,070,530 | `45d3f530ba1f9d6e879ad46b92046fabab13fe50a82450e4f65557a3bbad1489` |
| `python3.12` | `3.12.3-1ubuntu0.17` | `amd64` | `pool/main/p/python3.12/python3.12_3.12.3-1ubuntu0.17_amd64.deb` | 650,732 | `6745c9463432e619d7402b117ad4ac86c31dcd3999ba20daa9e395f6f9909d86` |
| `python3.12-minimal` | `3.12.3-1ubuntu0.17` | `amd64` | `pool/main/p/python3.12/python3.12-minimal_3.12.3-1ubuntu0.17_amd64.deb` | 2,334,634 | `d452689b9660845345a4c3e05e4ad82c082d5474e04031b7aa47f1a6d5610a6e` |

The verified `Depends` records close the CPython packaging relationship:
`python3.12` requires the exact-version minimal interpreter and standard
library, while both lead to the exact-version minimal library. Each artifact
was retrieved read-only from the same timestamped Canonical snapshot and its
actual bytes matched the record's size and SHA-256. These artifact hashes prove
the reviewed `.deb` identities only. They are not an installed-file hash,
package-installation receipt, or live interpreter integrity measurement.

`python3.12-venv` is deliberately deferred. None of the four runtime package
records depends on it, and C27 defines interpreter/runtime provenance rather
than a future venv bootstrap mechanism. It must not silently expand this slice
to `pip`, setuptools, venv construction, or installation dependency
provenance. The native dependencies named by the records—such as libc, OpenSSL,
SQLite, ncurses, expat, and zlib—remain in the Ubuntu base/system-library trust
boundary; C27 does not pin the complete operating-system dependency closure.

`DevPythonInterpreterProvenance()` is a frozen, slotted, zero-input repository
value. It exactly matches C24's CPython 3.12, Linux, Ubuntu 24.04, x86_64/amd64,
glibc target and cannot accept caller-selected keys, packages, versions, hashes,
indexes, suites, or architectures. C24 remains unchanged and continues to
require `interpreter_integrity_required=True`. C27 performs no network access,
host inspection, package operation, venv creation, `/opt` access, or activation
on import or construction. It does not install or qualify anything.

C29 must separately verify the actual host: bind its Ubuntu release and amd64
architecture to C24/C27; validate installed package names, versions,
architectures and package-manager records against this exact closure; establish
how installed files map to the reviewed artifacts; hash and validate the actual
interpreter and required installed runtime files without confusing them with
`.deb` hashes; reject extra/substituted interpreter provenance; and combine that
result with C28 wheel evidence before any provisioning or activation decision.

## C28 closed staged wheelhouse qualification

`wheelhouse_qualification.py` performs an explicit, read-only qualification of
caller-selected staged wheel bytes. C28 obtains the wheel requirements only from
an exact, revalidated C24 `DevInstallationIntegrityContract`; it contains no
independent production filename or digest allowlist and does not change C24.
The supplied absolute path identifies the directory to inspect and confers no
trust. Import and immutable evidence construction are inert.

Qualification accepts only a complete directory entry set of exactly four
entries: the four C24 wheel filenames in the C24 closure. Every entry must be a
regular, non-symlink file and its bytes must have the exact C24 SHA-256. A
missing or renamed wheel, extra wheel, sdist, metadata or requirements file,
nested directory, symlink, FIFO, device, socket, hash mismatch, zero-length or
truncated replacement fails closed. Wheel bytes are streamed through SHA-256 in
fixed 64 KiB chunks rather than loaded into memory.

The qualifier traverses every path component from `/` with retained,
descriptor-relative `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` opens. Wheel files
are opened relative to the retained wheelhouse descriptor with
`O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`. Named and opened identities
are compared; file and directory metadata are revalidated after hashing; and
the complete entry set is scanned both before and after hashing. These checks
reject persistent path, directory and file replacement and narrow filesystem
race windows within this read-only boundary. A caller able to mutate the staged
tree concurrently is not made trusted by selecting its path.

Successful qualification returns only frozen, slotted evidence containing the
selected path, the `sha256` algorithm, and the exact ordered C24 filenames and
digests. It exposes no trusted, approved, ready or qualified boolean. C28
qualifies staged wheel bytes only. It does not download, create, populate or
modify a wheelhouse; use a network or source-build fallback; run `pip`; install
packages; create a venv; inspect or mutate `/opt`; contact a candidate image; or
activate anything.

C27 CPython interpreter provenance remains unresolved within C28 and is
deliberately not attempted by that slice. The separately reviewed C27 evidence
above now closes the repository provenance input. A later C29 must compare C27
and this reviewed staged-wheel evidence against the live host.
C28 itself does not install anything; it does not qualify a live host.

## C29 read-only DEV host qualification

`dev_host_qualification.py` is the closed pre-provisioning observation boundary.
`qualify_dev_host(*, configuration, application_manifest,
wheelhouse_evidence)` accepts only exact C17, C26 and C28 objects, reconstructs
and revalidates C23/C24/C27 internally, and returns frozen explicit observations.
Callers cannot replace the package closure, payload hashes, key, platform,
principals, paths, modes or reviewed commit. Failures expose only the fixed
`DEV host qualification is unavailable` error. Import and evidence construction
are inert.

### Artifact-derived installed-file evidence

C27 proves the four `.deb` artifact identities; those artifact hashes are not
installed-file hashes. For C29, the exact four C27 artifacts were retrieved
read-only from the immutable Canonical snapshot and checked against C27 before
`/usr/bin/dpkg-deb --fsys-tarfile` exposed each data archive. Every non-directory
payload member was accepted only as a regular file or symbolic link. There were
no hard links, unsupported types or duplicate installed paths.

The canonical retained
`provenance/python3.12-3.12.3-1ubuntu0.17-amd64-payload.json` is 127,763 bytes,
SHA-256
`8e1b6d6a96105e0d8d38a6749768101b0d4603f9568dffbf2a247bea0ee16319`.
It binds each package name, version, architecture and C27 artifact SHA-256 to
exactly 658 payload members: 651 regular files with installed path, mode,
root UID/GID, size and SHA-256; and 7 symbolic links with installed path, mode,
root UID/GID and exact target. Directories are structural tar members rather
than file-integrity evidence. Generated bytecode, caches and other files absent
from the artifacts are not represented as package payload.

C29 requires exact installed package names, versions and `amd64` architectures
through fixed read-only `dpkg-query`, but does not treat that database output as
file integrity. It separately traverses every retained payload path from `/`
using descriptor-relative `O_DIRECTORY | O_NOFOLLOW` opens. Regular files must
match kind, mode, UID/GID, size and artifact-derived SHA-256. Reviewed symlinks
must remain symlinks with exact targets. Named/opened identity and post-read
metadata checks reject missing files, byte changes, symlink/regular-file swaps,
wrong targets and persistent substitution. Hashing is bounded to 64 KiB chunks.

### Host observations and pre-provisioning absence

The platform observation requires Linux, Ubuntu `24.04` from the fixed
`/usr/lib/os-release`, `x86_64`/`amd64`, and a GNU libc environment. This binds
the C24/C27 target but does not expand C27 into complete Ubuntu or native-library
provenance. libc, OpenSSL, SQLite, ncurses and other base-system dependencies
remain trusted through the separately maintained Ubuntu base boundary.

C13/C21/C23 remain the sole identities, symbolic principals, paths, modes,
owners and lifecycle authority. A future-managed user, group, path, runtime
resource, configuration, socket or systemd asset may be absent before C31;
absence is recorded explicitly and is not a failure. If a principal name or
numeric ID already exists, both directions must match the reviewed identity;
an existing user must have the exact primary and required supplementary group
set. Existing reviewed paths must have exact type, mode and ownership with no
symlinked component. Existing C17 configuration and systemd assets must also
match their exact reviewed bytes. C17 canonical bytes remain the configuration
authority. For systemd units, C29 no longer reads the repository checkout as an
expected-content source: it hashes each installed destination through bounded,
descriptor-relative no-follow reads and compares it directly with the immutable
C23 SHA-256 for that C22 asset. Missing, modified, same-size substituted,
symlinked or metadata-conflicting units fail closed. Modified or missing checkout
bytes therefore cannot redefine C29's installed-unit expectation. An existing
future venv root must be empty; C29 cannot accept an unreviewed pre-populated
venv. Conflicting pre-existing objects fail closed and are never repaired.

The shared C22/C23 unit-content trust chain is:

```text
C22 reviewed unit bytes
        |
        v
C23 immutable SHA-256
       / \
      v   v
C29 installed-file check    C30 source-before-installation verification
```

C29 compares installed units with C23 digests; C30 compares captured candidate
source bytes with the same digests before writing. Checkout bytes cannot alter
C29's expectation, while a mutable checkout can only make C30 fail verification.
Neither boundary performs systemd daemon-reload, enable, start or activation.

An absent C21 application root is acceptable. An existing root with exact C23
directory metadata and no entries is also observed as absent for C31 step-10
recovery. A nonempty root must have a complete descriptor-relative tree that
exactly matches the revalidated C26 manifest bound to C17/C24
`reviewed_commit`: no missing, extra, symlinked, wrong-mode or wrong-hash file
is accepted. C23's closed application root metadata is projected across the
installed tree: every C26 file must have the reviewed installation UID/GID,
while every implicit structural directory must have that ownership and the
exact reviewed `0755` directory mode. Thus
neither broker nor executor may own or write installed application code or its
directories. Opened/named
identity and post-read checks cover both files and
directories. C29 reads but never regenerates application trust from host bytes;
C31 still owns installation and convergence.

C28 evidence is revalidated against C24 and copied into C29 observations; C29
does not recreate the wheel allowlist or install wheels. Because evidence does
not freeze a mutable directory forever, C31 must obtain fresh C28 qualification
immediately before consuming staged wheels.

C29 performs no apt, pip, package or account operation; creates no venv or path;
does not chmod, chown, repair, delete or replace; does not execute Docker or
systemd; contacts no registry or candidate; and grants no activation authority.
C30 remains the future narrowly privileged runtime boundary. C31 remains the
future account/path/configuration/application/venv/package installation and
provisioning mechanism. Live activation remains blocked pending separate live-authority review.

## C30 narrow privileged host runtime

C30 implements repository-side primitives for the middle of the fixed
`C29 -> C30 -> C31` sequence. It is separate from
`RestrictedPrivilegedExecutor` and `DockerRuntimeAdapter`: those existing
components retain the authenticated DEV deployment and Docker/Compose boundary,
while C30 can only perform individual future host-provisioning mutations. C30
does not change or compose either existing deployment boundary.

`DevPrivilegedHostRuntime(*, configuration)` revalidates the exact C17 object,
reconstructs C13/C21/C23 internally, and captures immutable closed authority.
Its only explicit operations create or verify one reviewed group, create or
verify one reviewed non-login service user with exact memberships, create or
verify one reviewed directory, atomically install the exact constructor-bound
C17 configuration, or atomically install one of C23's two repository-owned
systemd assets. Each C23 asset mapping binds its C22 source path, destination,
metadata and exact reviewed source SHA-256. Name, path and destination arguments
are selectors into those closed C13/C21/C23 sets; unknown values fail before
mutation. It does not expose a shell, arbitrary command, argv, environment,
path, principal, mode, ownership, digest, file payload or source selector.

Account creation uses only absolute `/usr/sbin/groupadd` and
`/usr/sbin/useradd`, with internally generated argv, a closed environment,
closed stdin/output, a finite timeout, collision checks in both name/ID
directions and post-operation verification. Users have `/nonexistent` home and
`/usr/sbin/nologin`; supplementary memberships are exactly C13/C23's set. No
sudo or Docker membership is granted.

Filesystem primitives traverse retained directory descriptors with
`O_DIRECTORY | O_NOFOLLOW`, reject symlink components and conflicting existing
objects, and use exact reviewed UID/GID/mode. Regular files use bounded writes,
a same-directory exclusive temporary regular file, `fsync`, atomic replacement,
post-install descriptor-relative verification and identity-bound cleanup on
failure. Before privileged asset installation, C30 reads the bounded C23 source
through descriptor-relative no-follow traversal, revalidates named/opened file
identity, hashes the exact captured bytes and requires the C23 SHA-256. Checkout
ownership is not content provenance: a mutable or replaced checkout can cause
the operation to fail, but cannot authorize different unit bytes. This is the
same immutable digest C29 uses to qualify an installed destination without
consulting checkout bytes. A directory
created by a failed invocation receives identity-bound, descriptor-relative
`rmdir` cleanup only while its pathname still identifies that exact empty
directory; cleanup never recurses or removes a pre-existing/substituted object.
These primitives never repair an unreviewed ownership or mode conflict.

Import and construction perform no host operation. No method runs
automatically, and nothing in C30 installs or activates this helper. C30 does
not perform provisioning order or convergence policy, application-tree
installation, venv construction, wheel/pip/apt installation, state/replay/audit
initialization, socket creation, systemd reload/enable/start, Docker or registry
operations, networking, workflow changes or deployment activation. C31 must
later supply the reviewed ordering, C26 application and C28 wheel orchestration,
venv/bootstrap mechanics, initialization, convergence and the systemd lifecycle.
No daemon-reload, enable, start or activation authority exists in C30.
Live activation remains blocked by ADR 0011's separate live-authority review requirement.

## C31P reviewed pip installer provenance and qualification

C31A stopped before defining provisioning because none of C24, C27 or C28
established trust in an installer. An arbitrary `pip` from `PATH`, system pip,
`python -m pip` merely because it exists, and pip created by `ensurepip` are not
accepted bootstrap roots. C31P closes that prerequisite without constructing a
production venv or installing any runtime package.

`DevPipInstallerProvenance()` is a frozen, slotted, zero-input record for the
provisioning-tool artifact only:

| Field | Reviewed value |
| --- | --- |
| Package/version | `pip` `26.2.1` |
| Wheel/tag | `pip-26.2.1-py3-none-any.whl`; `py3-none-any` |
| Size | 1,816,632 bytes |
| SHA-256 | `71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e` |
| Requires-Python | `>=3.10` |
| PyPI upload | `2026-08-04T22:51:12.472093Z` |
| Publication | PyPI Trusted Publishing from GitHub repository `pypa/pip` |
| Source/ref | `634a6ec1a5d9dcc2433571cdb2f4c58a4bb29caf`; `refs/tags/26.2.1` |
| Workflow | `.github/workflows/release.yml` |
| Certificate identity | `https://github.com/pypa/pip/.github/workflows/release.yml@refs/tags/26.2.1` |
| Sigstore log index | `2341605236` |

The PyPI JSON API independently supplied the artifact filename, byte count,
SHA-256, Python requirement and upload identity. PyPI's Integrity API returned
an in-toto publication statement whose subject is that exact filename and
SHA-256, a GitHub publisher identity for `pypa/pip` and `release.yml`, the
certificate identity above, and the Sigstore transparency entry. The PyPI
release page supplied the corresponding source commit and identifies the upload
as Trusted Publishing. The exact-tag workflow at that commit grants its
publishing job `id-token: write` and invokes the PyPA publisher action.

Those values are repository-reviewed immutable evidence of PyPI-verified
publication provenance. The repository does not retain the complete Sigstore
bundle or Fulcio/Rekor trust material and does not claim to reverify the
attestation cryptographically offline. That is distinct from the exact
artifact identity, which the local qualifier verifies directly, and from the
future act of staging an artifact.

`qualify_dev_pip_installer(*, staging_directory)` inspects a dedicated absolute
installer staging directory containing exactly one entry with the reviewed
filename. It accepts only a non-symlink regular file of exactly 1,816,632 bytes
whose bounded 64 KiB streaming SHA-256 is the reviewed digest. Every directory
component and the wheel are opened descriptor-relative with `O_NOFOLLOW`;
named/opened identities, exact EOF, post-read file metadata, directory
identities and the complete entry set are revalidated. A wrong filename, extra
entry, wrong size or digest, symlink, non-regular file, path substitution or
read race fails with one fixed public error. Qualification is read-only,
performs no import or execution of pip, and returns immutable evidence. The
caller selects only where to inspect and cannot select the expected artifact.

The reviewed wheel was also executed directly from its ZIP bytes under CPython
3.12 without installation. The future fixed command shape is:

```text
/opt/omnilyzer/deployment/venv/bin/python -I -c <reviewed-bootstrap> \
  <freshly-qualified-pip-wheel> <internally-generated-pip-arguments>
```

The reviewed bootstrap removes the wheel-path argument, inserts that exact
wheel first on `sys.path`, imports `pip`, requires both version `26.2.1` and an
`__file__` below that exact wheel path, then executes `pip` with `runpy` as
`__main__`. `-I` ignores `PYTHONPATH` and user site configuration; the
executable is an absolute C24 venv path and no `PATH` pip, `/usr/bin/pip`,
ensurepip, shell or network bootstrap participates. Development verification
ran the exact reviewed wheel with `/usr/bin/python3.12` and obtained version
`26.2.1` from inside the wheel; deterministic tests repeat the same origin and
version checks with a tiny test-owned ZIP and prove a wrong version cannot fall
back to another pip. Future C31 must preserve or freshly revalidate the staged
wheel identity immediately before this separate execution step and must supply
only its own closed installation arguments.

This installer wheel is not one of C24/C28's four runtime wheels, is not mixed
into the runtime wheelhouse, does not widen `extra_wheels_allowed=False`, and is
not a runtime dependency. C31 must still define exact orchestration, use a fresh
C28 runtime-wheel qualification, derive installed-file evidence from the four
reviewed runtime wheels, and ensure provisioning-only pip does not remain as an
unreviewed runtime distribution. C31P performs no host provisioning, venv
construction, runtime-wheel installation, systemd lifecycle operation or
activation.

## C31A closed provisioning plan and Python runtime integrity

C31A is an inert repository-side plan. It grants no mutation authority and
performs none of its steps. Its closed order is:

1. revalidate C17 configuration;
2. reconstruct C23/C24 authority;
3. revalidate the exact C26 application manifest and reviewed commit;
4. construct C27 interpreter provenance;
5. freshly qualify the C28 runtime wheelhouse;
6. freshly qualify the C31P installer staging directory;
7. run C29 pre-provision host qualification with that C28 evidence;
8. create the exact C23 groups;
9. create the exact C23 users;
10. create the exact required directories;
11. install the exact C26 application tree;
12. install the exact C17 executor configuration;
13. install the exact C22/C23 systemd assets;
14. construct the exact no-pip venv;
15. bind a fresh C31P qualification to installer consumption;
16. bind a fresh C28 qualification to runtime-wheel consumption;
17. install the exact four C24 runtime wheels;
18. qualify the populated Python environment;
19. establish initial deployment-state prerequisites;
20. initialize replay state only under its existing lifecycle;
21. establish audit prerequisites without destroying history; and
22. verify post-provision convergence and integrity.

C29 retains its pre-provision meaning: an absent future venv is acceptable and
a populated venv is a conflict. C31A adds the separate, read-only
`qualify_dev_python_environment()` post-provision boundary; it does not weaken
or reuse C29 as a populated-environment check.

Application installation authority is `reviewed Git blob bytes -> exact C26
path, SHA-256 and 0644 mode -> closed installation source -> exact
/opt/omnilyzer/deployment/app tree`. Future mechanics may use fixed
`/usr/bin/git` to extract a blob at the exact reviewed commit, but must hash the
captured bytes against C26 before any privileged installation. A working-tree
file or Git object identity alone is never byte authority. The result is
exactly 28 root-owned regular files under a root-owned 0755 directory hierarchy,
with no symlinks or extra entries, followed by exact-tree verification.

The no-pip venv command contract is exactly:

```text
/usr/bin/python3.12 -m venv --without-pip /opt/omnilyzer/deployment/venv
```

It uses the C27/C29-qualified system interpreter, an exact internal argv,
`shell=False`, a fixed minimal environment, umask 0022, no ensurepip, no system
site packages, no network and an absent or exact empty non-conflicting target.
The fixed runtime installer uses the venv Python with C31P's `-I` direct-wheel
bootstrap and these exact pip arguments:

```text
install --no-input --disable-pip-version-check --no-cache-dir --no-index \
  --only-binary=:all: --no-deps --require-hashes --no-compile \
  --find-links <identity-bound-runtime-wheel-snapshot> \
  --requirement <identity-bound-requirements-lock>
```

The closed environment includes `PIP_CONFIG_FILE=/dev/null`, `PIP_NO_INDEX=1`,
`PIP_NO_INPUT=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1`. Pip remains a separate
provisioning tool and is not installed as a runtime distribution.

Fresh qualification is not treated as sufficient if a later operation reopens
the same untrusted pathname. C31B must read and verify each C28/C31P source
through retained descriptors, copy from those still-open descriptors into the
fixed root-owned 0700 private input snapshot, re-hash and fsync the copy, and
retain the snapshot identity through consumption. Cleanup may remove only the
exact C30-created snapshot identity. Directory ownership alone does not confer
byte trust. The exact requirements lock is bound into the same closed input
mechanism.

The retained
`provenance/python-runtime-py312-linux-x86_64-installed.json` manifest was
derived by installing the four exact, hash-verified C24 wheels with the exact
C31P pip 26.2.1 wheel in isolated temporary no-pip CPython 3.12 environments.
Its canonical bytes are 57,824 bytes with SHA-256
`3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b`.
It closes 237 entries: 197 regular files, 36 directories and four symlinks.
Wheel payload and metadata files retain their reviewed wheel-derived hashes;
compiled extensions are regular hashed payload files. None of these wheels has
a `.data` mapping or wheel-provided symlink.

Pip 26.2.1 deterministically creates four `INSTALLER` files containing
`pip\n`, four empty `REQUESTED` files, rewrites four `RECORD` files, and creates
the `cffi-gen-src` script. The retained manifest hashes the exact production-root
forms of all of them. Installed `RECORD` is evidence to compare, not the trust
source. The script includes the exact production venv shebang and is mode 0755;
the other generated files are non-executable mode 0644. `--no-compile` is
mandatory, and any `.pyc` or `__pycache__` entry is outside the exact tree and
is rejected.

The qualifier uses descriptor-relative no-follow traversal and requires exact
root ownership, modes, entry set, regular-file sizes and SHA-256 values,
symlink targets, named/opened identity and post-read identity. It also requires
the exact four distribution identities (PyJWT 2.13.0, cryptography 50.0.1,
cffi 2.1.1 and pycparser 3.0), the exact `pyvenv.cfg`, no system site packages,
the reviewed `/usr/bin/python3.12` relationship, and no installed pip or extra
runtime package.

The cffi 2.1.1 installed `RECORD` has 34 rows. Pip 26.2.1 writes them through
Python `csv.writer`, whose default line ending is CRLF. The initial retained
manifest accidentally normalized this one file to LF (2,631 bytes,
SHA-256 `7f43cc4e11358f6468993deccf1bcd24bc451b7464deb7ea7b14e4fba361abdb`).
The corrected output evidence binds the actual CRLF file (2,665 bytes,
SHA-256 `e17a08d7a6b2a942aca45d2e533ca3c805d02d069a6674fdda39ba5e90193200`).
This changes no wheel input, installer command or C30 replacement behavior.

C31B supplies narrowly named closed mechanics for C26 tree materialization,
the identity-bound input snapshot, exact no-pip venv construction, exact
offline installation and identity-bound snapshot cleanup. C31C supplies the
separate state/replay/audit prerequisites. None of C31A, C31B, or C31C adds a
general command, path, copy, write or remove API. Replay must never replace an
existing database, and audit provisioning must preserve history. Systemd
daemon-reload/enable/start and live activation remain outside C31A and blocked
by ADR 0011's separate live-authority review requirement.

## C31B narrow privileged provisioning mechanics

`DevHostProvisioningMechanics` is an inert, constructor-bound C31B facade. It
is separate from, and does not broaden, `RestrictedPrivilegedExecutor`,
`DockerRuntimeAdapter`, or C30's existing public API. It exposes only two
explicit mechanics: materialize the exact C26 application tree, and construct
the exact reviewed Python environment from fixed qualified inputs. Import and
construction do no I/O. The facade is not composed into the broker, executor,
listener, service units or workflow. A separate C31 host operation reached
Python qualification on the DEV host and failed closed as described below;
this repository change authorizes no retry.

Application materialization opens the caller-selected repository location
without following symlink components and retains that directory descriptor.
Fixed `/usr/bin/git --no-replace-objects` reads only the exact 28 C25 paths at
the C17/C26 40-character commit through `/proc/self/fd`; lazy fetch, replacement
objects, prompts and Git configuration are disabled. All blob bytes are
captured within fixed bounds and independently SHA-256 checked against C26
before the application destination is mutated. Dirty working-tree bytes never
participate. The fixed C23 application root must already have exact ownership
and mode. Existing entries must be an exact subset, missing 0755 directories
and 0644 files are created descriptor-relative, and each file uses an exclusive
same-directory temporary inode plus a no-replace hard-link publication step,
file/directory fsync and final complete-tree verification. Conflicts, symlinks
and extra entries fail closed; no arbitrary pruning or recursive deletion is
available.

C31B privately composes C28 and C31P through their existing qualification logic
while their verified source descriptors remain open. It copies only from those
descriptors into this fixed single-use structure:

```text
/opt/omnilyzer/deployment/.provisioning-inputs/       root:root 0700
    pip/                                               root:root 0700
        pip-26.2.1-py3-none-any.whl                    root:root 0400
    wheels/                                            root:root 0700
        <the exact four C24 wheel filenames>           root:root 0400
    requirements/                                      root:root 0700
        requirements-linux-x86_64-py312.lock           root:root 0400
```

The source wheelhouse must still have exactly four entries and the installer
staging directory exactly one. The fixed repository lock is opened beneath a
retained repository descriptor with no-follow traversal and must match C24's
SHA-256
`13c7b3f0050f9aff0a94ab324a66276638f8b1b9dd0c62232ec205b24d874d0d`.
Every snapshot file is streamed in bounded chunks, rehashed, fsynced, reopened
read-only and retained by inode. C28/C31P source descriptors and directories
are revalidated after copying. Immediately before venv construction, before
pip, after pip and during cleanup, the snapshot names, inode metadata, complete
entry sets and file hashes are revalidated. A pre-existing snapshot root is
never reused.

Fresh exact C29 evidence is required before Python construction. It must bind
the C27 package/platform payload, the same C28 wheelhouse, and an absent exact
C23 venv target. The construction process is exactly:

```text
/usr/bin/python3.12 -m venv --without-pip \
  /opt/omnilyzer/deployment/venv
```

It uses `shell=False`, stdin/stdout/stderr disconnected, a fixed timeout,
umask 0022 and only `HOME=/nonexistent`, `LANG=C`, `LC_ALL=C` and
`PATH=/usr/bin:/bin`. An existing target is accepted only when it is the exact
empty C23 directory. No ensurepip, system pip or inherited Python environment
is used.

Runtime installation executes the C31P bootstrap with the exact venv Python,
`-I`, the retained private pip-wheel pathname, the private four-wheel directory
and the private C24 lock. Its arguments remain exactly `--no-input`,
`--disable-pip-version-check`, `--no-cache-dir`, `--no-index`,
`--only-binary=:all:`, `--no-deps`, `--require-hashes`, `--no-compile`, the
fixed `--find-links`, and the fixed `--requirement`. The closed environment
also fixes `PIP_CONFIG_FILE=/dev/null`, `PIP_DISABLE_PIP_VERSION_CHECK=1`,
`PIP_NO_INDEX=1` and `PIP_NO_INPUT=1`; no proxy, cache, index, compiler, source
build, dependency discovery or installer upgrade authority exists.

A zero return code is insufficient. C31B revalidates the retained snapshot and
then invokes C31A's `qualify_dev_python_environment()`; only its exact 237-entry
evidence permits the operation to return. Snapshot cleanup first proves every
created file and directory still has its recorded identity and that no unknown
entry exists, then removes only those fixed names descriptor-relative and
fsyncs parents. Partial application/snapshot artifacts receive the same
identity-bound cleanup where their complete known structure can be proven.
Substituted, unknown or nonempty state is never recursively removed. A failed
venv is deliberately left for operator inspection because safe generic tree
removal cannot be proven; C31B never destroys a pre-existing venv.

C31B Python-construction errors retain the generic public message and expose
only a fixed internal phase label. The label distinguishes input and snapshot
checks, the venv command, pre-install verification, offline pip,
post-install qualification and cleanup. It includes no exception, subprocess
output, source path or credential. A phase records where an error surfaced,
not whether that phase made a persistent mutation. Existing identity-bound
snapshot cleanup and failed-venv retention are unchanged.

Deployment-state initialization, replay initialization and audit prerequisites
are implemented separately by C31C. The complete 22-step orchestration and
every systemd lifecycle operation remain deferred. C31B performs no Docker,
registry, candidate-image, workflow, OIDC or activation operation. Actual host
provisioning and live activation remain prohibited by ADR 0011's separate
live-authority review requirement.

## C31C closed DEV persistent-state prerequisites

`DevPersistentStatePrerequisites` is an inert, uncomposed C31C boundary for
steps 19–21 of the C31A plan. It derives all paths, modes and identities from
C17/C13/C23 and composes C30's existing exact-directory primitive. It exposes
separate state, replay and audit methods because those resources intentionally
have different monotonic lifecycles; a later failure never rolls back or erases
an earlier persistent-security result.

The zero-input `dev_initial_state()` authority is the exact canonical no-active
DEV state. Active, previous and candidate identities are empty; migration is
`none` with no identity or checksum and `serialized_lock_required=true`. Its
bootstrap-only metadata is `updated_at=1970-01-01T00:00:00Z` and
`event_id=bootstrap-initial-state-v1`. These fixed sentinels satisfy the state
validators, cannot match the real deployment operation's
`c8:<request-hash>:<step>` event IDs, and are replaced by the first genuine
audited checkpoint. The canonical bytes are 492 bytes with SHA-256
`1267be5bd7f29db9e89289ad9bfc6e13b210641e8407cab8a52e9c08fde17f3f`.

State initialization uses the existing state-store descriptor traversal,
nonblocking process-local gate and directory `flock`, then exclusively creates
only `state.json` with C13 mode and ownership. It writes bounded canonical
bytes, fsyncs the file and directory, reopens and reparses the exact bytes, and
proves compatibility by loading through `FilesystemDeploymentStateStore`.
Exact initial state converges unchanged. Any valid genuine later deployment
state is classified as existing and never overwritten; malformed content,
metadata conflicts, symlinks, hard links and temporary residue fail closed.
Failure cleanup may unlink only the exact inode created by that invocation.

Replay preparation creates or validates only C13's exact root-owned `02770`
authority directory through C30. An empty directory receives exactly one call
to `SQLiteReplayGuard.initialize()` using its real clock semantics; the replay
clock is runtime monotonic state and is deliberately not the fixed deployment
bootstrap timestamp. An existing database is never initialized, reset,
replaced or migrated. The guard's read-only `validate()` path checks filesystem
identity, exact schema, SQLite integrity, metadata and stored rows without
advancing the replay clock. SQLite opens `/proc/self/fd/<database-fd>` for the
already retained database inode rather than re-resolving `replay.sqlite3`; a
journal is rejected as non-quiescent instead of recovered or removed. This
read-only path issues no persistent-setting pragma and leaves the database,
clock watermark and consumptions unchanged. Existing consumptions survive every
C31C rerun, and the guard's existing failed-initialization quarantine behavior
remains intact.

Audit preparation creates or validates only the exact executor-owned `0700`
`/var/lib/omnilyzer/deployment/audit` directory, separate from the hardened
state store under `dev`. It deliberately leaves `events.jsonl` absent in
pristine state: `FilesystemAuditSink` retains sole authority to create that
`0600` file on the first real audit append. If current or rotated history
exists, C31C validates exact file metadata and the existing bounded hash-chain
parser while retaining opened identities. Plain bytes are read only from those
descriptors; compressed rotations are read under a finite physical bound and
decompressed from the captured bytes under the existing decompressed-history bound. Both the
opened and final named identities are revalidated, so pathname replacement
cannot supply different validation bytes. C31C never appends, truncates,
replaces, rotates or deletes anything. Unknown or unsafe directory entries fail
closed.

The combined verifier is read-only and reports explicit initial/existing,
replay-verified and pristine/existing-history observations; it does not claim
activation readiness. C31C changes no C30 public API, is not connected to the
broker, executor, service or workflow, and has not been invoked against the DEV
host. C31C did not own step 22 or full orchestration; C31D now supplies that
verifier and composition. Further host provisioning, systemd lifecycle, OIDC
activation and live deployment remain prohibited pending separate review.

## C31D post-provision verification and closed orchestration

C31D keeps the pre- and post-provision meanings separate. C29 remains the
read-only qualifier for an absent or exact-empty future venv before the first
mutation. The distinct `qualify_dev_provisioned_host()` boundary is step 22: it
requires the exact C27 platform, packages and artifact-derived payload, all C23
principals, every pre-activation directory, C17 configuration bytes, both C23
systemd-file digests, the exact C26 application tree, the C31A 237-entry Python
environment, and C31C state/replay/audit verification. It also requires
`/opt/omnilyzer/deployment/.provisioning-inputs` to be absent. The C31B
application scan rejects its known temporary filename as an extra entry. The
verifier is descriptor-bound and read-only; it repairs, initializes, appends,
installs and removes nothing.

The closed `DevHostProvisioningOrchestrator` composes the C31A order without
adding destination, command or package authority. Its only operation inputs are
the repository, runtime-wheelhouse and installer-staging source locators. It
revalidates C17/C23/C24, derives C26 from exact reviewed Git blobs, constructs
C27, obtains fresh C28 and C31P evidence, and requires C29 before the first
mutation. It then invokes C30 in C23 group, user and directory order, invokes
C31B application materialization, installs only the C17 file and two reviewed
unit files, and invokes C31B's single Python operation. That single operation
represents steps 14–18, and all five step observations are recorded only after
the complete C31B operation and C31A Python qualification return successfully.
C31C remains responsible for steps 19–21. C31D's read-only convergence verifier
is the final step 22, after which orchestration stops.

### Operator execution boundary and authorization

`omnidev` is the unprivileged Codex/development identity. The existing server
administrator identity `trust` is the operator trust boundary. Root must never
import or execute C31 deployment Python from the `omnidev`-writable development
checkout, including through `PYTHONPATH`, the current directory, or a symlink
into that checkout. After a separate one-time provisioning authorization, the
administrator must prepare a separate exact-commit checkout or copy whose files
and every parent directory are administrator-controlled and not writable by
`omnidev` (including through group permissions or ACLs). Immediately before
provisioning, the operator must verify that this execution tree is clean, its
`HEAD` is the exact newly reviewed commit, its files still match that commit,
there are no extra importable files (including ignored or untracked files),
and C17 `reviewed_commit` names the same commit. The C31 `repository_root` and
all deployment module imports must resolve within that verified tree. Any
changed or extra file, commit mismatch, untrusted import path, or writable
ancestor blocks execution. Do not give
`omnidev` sudo, Docker, LXD, deployment authority, or write access to this
tree. This boundary adds no permanent CI or root deployment credential. The
reviewed baseline `4292d57ff50fbe105c1b1327cb8b5cd09da53491` identifies
the pre-change review state; it does not authorize a later commit or host run.

The C17 object used for prior C26/C28/C29 qualification is **not** provisioning
authorization. The manifest digest
`sha256:628af866084f08763b31a44c8a484c5ae4c64db6697f4c4ceaad91bbf54ba72a`
is a published Task 013 release artifact: Platform release run 34139853319
(run #7), version 0.14.2, source SHA
`9d29fa1a4010e6e72676580c36a94c1e97e8794b`, repository
`omnilyzer/task013-release-canary`. The zot and Forgejo publication jobs
succeeded, and downstream Cosign verification of that exact registry identity
succeeded, including transparency-log and certificate checks. The digest also
appears in tests; that occurrence alone grants no C17 authority. A real C17
requires separate review of the release evidence and the complete C17
configuration, including its exact `CANARY_IMAGE` digest and the newly reviewed
execution commit. This repository change does not create or persist a live C17.

Before mutation, C31D probes full convergence. A completely converged host
returns an explicit `already-converged` observation without C29 or any mutation.
If that probe fails, it grants no authority: C29 must still establish the exact
pre-provision state before C30 or C31B can run. Ambiguous partial state therefore
fails closed. Provisioning is monotonic and has no transactional rollback:
groups, users, installed files, a successful venv, deployment state, replay
history and audit history are never removed or reset after a later failure.

C31D failures carry only fixed `ProvisioningFailureEvidence`: the last
completed sequence (zero if none), the next or failed C31A step with its fixed
identifier and boundary, whether a host mutation call was attempted, and an
optional fixed C31B internal phase at step 14. The message remains fixed and
suppresses underlying exception details. Steps 14–18 are one C31B Python
operation; if it fails, none of those steps is marked complete and the failed
step is reported as 14, with the C31B phase when available. Earlier failure
evidence has no phase and cannot be interpreted retroactively. A failure while
releasing the lock after step 22 is attributed to step 22 even if verification
completed.

### Partial-failure recovery

Stop after any failure and retain existing resources and evidence. A failure
in steps 1–7 implies no intended managed mutation. From step 8 onward, earlier
successful resources can remain, including a resource created within the
failed step. Use the fixed failure evidence to locate the boundary, then
inspect the host with the existing read-only C29 pre-provision and C31D
post-provision qualification boundaries, alongside fresh C28 and C31P source
qualification where relevant. Diagnose any partial or invalid application,
venv, snapshot, deployment state, or replay data explicitly before retry;
never blindly delete or recreate it. Only a fully converged rerun returns
`already-converged` without mutation. Arbitrary partial failure is not
guaranteed to converge on retry; a failed qualification blocks further
provisioning until the exact condition and recovery are reviewed.

For a step-10 failure, C29 can accept exact existing C23 groups, users and
early directories with an exact empty application root and empty venv; the
application observation remains `absent`. Later resources may still be absent.
Any nonempty incomplete application root or populated venv blocks retry.

The reviewed c8646e1 partial state has a narrower C31-only recovery path.
Ordinary C29 still requires the current C17 bytes and current C26 application
manifest. If that qualification fails, C31 may requalify once against the
code-pinned predecessor commit `c8646e1ef72f0cbab4878d383f7765f07aef8417`
and canonical C17 SHA-256
`0d464f4c0792ddfc184b2fc65b4a46d7e233abf6471167e80ed2e728d9f6837c`.
The current reviewed commit must have the pinned recovery base commit
`fdae74dd656f421211b0c2463c6eecb217edccde` as a direct parent.
The retained file must parse as exact canonical C17, name that predecessor,
and agree with the new C17 in every field except `reviewed_commit`. The
current 28 C26 entries, reconstructed with the predecessor commit and fixed
manifest fields, must hash to the pinned canonical C26 SHA-256
`2743932cfb2e8d431f56de25aaab6c77177c52165ea3f35ca80281602909e69a`.
This does not require the predecessor Git object. C29 then checks the entire
host against those predecessor inputs, including exact file metadata and the
complete application tree. The host file cannot select recovery authority.
An unrelated, modified, incomplete, or changed-application predecessor fails
before mutation. Application byte changes need a separately reviewed migration
because C31B currently refuses to replace pre-existing application files.
Once this preflight succeeds, C31B accepts the exact empty venv observation
that its own precondition already verifies, and C30 retains its atomic C17
replacement. This exception does not activate deployment or authorize a host
retry.

The later failed C31 step-14 run against `c78e94f5e7c6b1a557ac041bdfb560bb82c1642b`
retained a populated Python environment after pip succeeded and the input
snapshot was removed. A separate C31-only branch is pinned to that predecessor,
its exact C17 SHA-256 `a570f9224ebeaa5d893299299b95734aaca28fc753eaa44bdabba8e7ac24b1b0`,
and its exact C26 SHA-256 `575d09be5933ea226313a20a958cbc5066cabcf20580e7343ee3034ac3a95f1e`.
The current reviewed commit must have that pinned predecessor as a direct parent;
a merge with that direct parent is accepted, while descendants without it are
not. The installed C17 must be either the exact pinned predecessor (agreeing
with the new C17 except for `reviewed_commit`) or the exact current C17.
Before any mutation, C31 checks the exact predecessor application tree, C23
principals, directories and assets, C27 packages and installed payload, the
corrected 237-entry Python tree, and absent `.provisioning-inputs`. C31C's
read-only validators then admit only the states reachable across interrupted
steps 19–22: absent deployment state or its exact canonical initial bytes;
an empty replay directory or a fully validated initialized database with no
consumptions; and a pristine, empty audit directory. A valid active deployment
state, replay consumption, audit history or residue is outside this recovery
generation and blocks retry without deletion or repair. C31C still validates
any audit entries before the empty-directory check, so malformed history also
fails closed. The only admitted C17/state/replay tuples are predecessor/absent/absent,
current/absent/absent, current/initial/absent, and current/initial/initialized;
predecessor C17 with initialized state cannot follow the step order. Any mismatch
blocks recovery without cleanup. On success, step 7 is reported as
`populated-recovery-verified`. Steps 8–11 and 13–18 are `retained-exact`.
If C17 is still the predecessor, step 12 uses C30's existing atomic replacement
and reports `installed`. If C17 is already current, step 12 reports
`retained-exact` and performs no rewrite. Steps 19–21 use C31C's existing
idempotent operations: an absent state or replay is initialized, while exact
prior results are preserved and revalidated. Final step 22 is rerunnable after
a failure. Ordinary C29 remains strict about an empty pre-provision venv. This
code path does not authorize a real host retry or deployment activation.

One instance uses a nonblocking thread lock, while independent processes use a
nonblocking kernel `flock` retained on the exact opened `/usr/bin` directory.
The anchor is fixed internally, opened descriptor-relative with no symlink
following, and retained across the already-converged probe and all 22 steps.
Its stable identity is the directory mode/type, device, inode, UID and GID;
volatile size, mtime and ctime are deliberately excluded. Replacing a child
such as `/usr/bin/python3.12` therefore neither creates a second lock object nor
causes a false identity failure. The complete named/opened directory chain is
revalidated before release, and all descriptors are close-on-exec. This creates
no lock-file state and prevents independent cooperating provisioning processes
from both passing preflight without adding lock-file cleanup or repair
authority. C27/C29 separately retain responsibility for qualifying the exact
system interpreter bytes; the directory lock supplies exclusion, not Python
provenance.

C31D does not require the executor socket, an audit file in a pristine audit
directory, enabled units or active services. It performs no daemon reload,
enable, start, socket bind, Docker or registry action. The modules remain inert,
uninstalled and uncomposed with broker, executor, listener, service and workflow
paths. A C31 run reached step 14 on the real DEV host and failed closed; the
retained state is described above. A retry, systemd lifecycle, deployment
workflow environment attachment/OIDC activation, registry consumer activation
and live deployment remain prohibited pending separate review.

PR B adds reviewed, non-installed assets under `runtime/dev/`, a closed `DockerRuntimeAdapter`, durable atomic state modes, and the initial chained filesystem audit sink. Each adapter instance binds one exact validated `CANARY_IMAGE` into its minimal controlled environment for every command and rejects cross-digest reuse. The adapter contains real narrow execution logic but is never invoked automatically. It exposes no arbitrary subprocess, Compose service, Nginx command, upstream, URL, or filesystem-path operation. Runtime tests inject command and HTTP clients; a separate non-mutating test runs only `docker compose config`. See the [DEV runtime qualification, design, and exact hashes](runtime/dev/README.md).

The DEV branch/environment protection capability prerequisite is satisfied as recorded above. Separate live-authority review remains mandatory. PR names do not determine authority: the boundary is whether a change remains inert and repository-only or grants, installs, exposes, or exercises live deployment authority.

Permitted pending separate live-authority review:

- closed verifier and authorization code;
- durable replay code;
- broker, transport, and executor code that cannot be activated;
- registry-consumer interfaces and deterministic mocked tests;
- audit schema and identity projection;
- inert, uninstalled systemd, Nginx, and layout fixtures; and
- deterministic repository tests and static validation.

Prohibited until the live-authority change is separately reviewed:

- `id-token: write` in a deployment workflow;
- GitHub environment attachment or a deployment job;
- live public broker ingress or listener;
- installation or enabling of host services or sockets;
- live registry credentials or token exchange;
- Docker or application execution;
- host, runtime, or infrastructure mutation;
- environment activation or populated live runtime references; and
- any static-key, personal-account, SSH, self-hosted-runner, or weakened-policy workaround.

Therefore **no live deployment workflow or DEV deployment may be enabled** until the live-authority change is separately reviewed. Live JWT/JWKS behavior, replay installation and wiring, broker/executor hardening, Unix-socket permissions, zot and Forgejo read-only consumers, host services, TLS/DNS/network integration, restart/reconciliation, and the first DEV deployment all remain to validate.

## Promotion identity and trust

A promotion request binds the strict release version, source SHA, approved OCI repository, manifest digest, exact image reference, release-manifest and provenance hashes, originating release run, target stage, and actor. Unknown fields, mutable references, malformed identities, and noncanonical hashes fail closed. Canonical JSON is sorted, compact, ASCII, and newline terminated before hashing.

`verify_release_evidence` consumes Task 013 outputs rather than duplicating publication. It requires the request hashes to match the supplied release manifest and provenance bytes, then cross-checks version, source, zot origin, repository, digest, exact image reference, release workflow, certificate identity, issuer, both blob verification results, and the exact OCI signature result. No formal SLSA level is claimed.

Promotion order is exactly DEV, STAGING, PROD. STAGING requires one matching successful DEV audit event; PROD requires one matching successful STAGING event. The receipt must match version, source SHA, repository, and digest. A tag, branch, or version alone is never promotion evidence.

## Blue/green and health model

The active slot remains in service while the exact candidate digest starts in the inactive slot. The ordered plan requires a serialized migration lock, migration identity/checksum verification, explicit migration execution, `/livez`, `/readyz`, application validation, Nginx syntax validation, traffic switching, atomic state persistence, and retention of the previous digest.

`/livez` represents process liveness only. `/readyz` is the traffic gate and must eventually verify required runtime configuration, database connectivity, and required migration/schema state. A failed candidate or gate produces no active-state transition, so current traffic remains untouched.

Application containers must run as a non-root UID/GID with a read-only root filesystem, dropped capabilities, `no-new-privileges`, narrowly scoped writable tmpfs, no Docker socket, and runtime secrets outside the image. The intended network direction remains ingress to Nginx, Nginx to the frontend/application network, application to the backend network, and PostgreSQL on the backend only. Phase 1 defines these contracts but does not claim runtime proof.

## Migrations and rollback

Migrations are explicit deployment operations, never application-startup behavior. A migration has a stable identity and SHA-256 checksum, requires eventual serialized execution, and must fail if recorded history has a different checksum. Migration failure blocks readiness and traffic switching. The final Django migration mechanism remains a Phase 2 design decision.

Rollback starts the retained previous immutable digest in the inactive slot, validates liveness, readiness against the current compatible schema, application behavior, and Nginx syntax, then switches traffic and records state. It never rebuilds and does not perform or imply destructive database down-migration. Missing or corrupt previous state fails closed.

## State and audit

Deployment state records active, previous, and candidate release/source/digest/slot identities plus migration state and event metadata. Complete identities are all-or-none, candidate and active slots cannot match, and writes use an owner-only same-directory temporary file, file and directory synchronization, and atomic replacement.

Audit-event schema 2 cleanly replaces the inert pre-activation schema 1. There is no compatibility, migration, repair, or schema-1 history acceptance: no production audit history exists because deployment authority has never been activated. The pre-C3 gap was recorded as “the current `AuditEvent` does not persist all of it”; PR C3 closes that repository contract before activation.

Every schema-2 event contains one closed immutable execution identity with the requested actor ID, exact GitHub repository ID, workflow ref and workflow SHA, run ID and attempt, bounded OIDC JTI, OIDC issued-at and expiry, promotion-request SHA-256, and the SHA-256 derived from the complete canonical executor request. The ambiguous generic actor string is removed. A request-bound constructor derives the artifact and identity fields from a revalidated `ExecutorRequest`, and the binding check rejects any event whose stage, release, source, repository, manifest digest, or complete identity belongs to another request.

The Python parser is the authoritative semantic boundary and requires exact built-in integers, excluding booleans, floats, and integer subclasses. JSON Schema draft 2020-12 defines integral JSON numbers such as `1.0` as integers and cannot distinguish their lexical representation; the schema documents that standards-level limitation rather than weakening the Python contract. Cross-field OIDC timestamp ordering and the 300-second lifetime are likewise enforced by the Python parser because standard draft 2020-12 has no cross-property arithmetic keyword. The aggregate byte size of complete canonical JSON also cannot be expressed by the schema vocabulary, so `AuditEvent.from_dict` and the sink enforce `MAX_EVENT_BYTES` authoritatively.

The filesystem audit sink, `FilesystemAuditSink`, independently reconstructs and validates the complete event before persistence, so direct dataclass construction cannot bypass schema, identity, artifact, timestamp, lifecycle, size, or secret-marker checks. Stored records contain no compact JWT, bearer token, claims JSON, credentials, canonical request bytes, HTTP headers, responses, subprocess output, or secrets. The existing canonical JSONL, hash chain, duplicate rejection, rotation, retention, owner-controlled modes, size bounds, and tamper-evidence behavior remain in place; the sink is not root-tamper-resistant.

This remains inert repository code. No broker currently creates the events, no executor or transport is wired to the sink, no production audit path was accessed or initialized, and no live end-to-end audit evidence is claimed. Maintained branch and GitHub environment protections and a separate live-authority activation review remain mandatory before any deployment authority can be enabled.

## Local validation

```bash
python3 -m unittest discover -s deployment/tests -p 'test_*.py'
```

The package is governed by [ADR 0006](../docs/adr/0006-immutable-oci-deployment-and-promotion.md) and [ADR 0011](../docs/adr/0011-oidc-restricted-deployment-authority.md). Task 007 remains historical validation evidence; production code does not import from `spikes/`.
