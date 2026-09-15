# Task 014: exact-digest promotion and deployment control plane

Task 014 consumes accepted Task 013 release outputs and controls their ordered deployment. The release system builds, scans, signs, and publishes artifacts. This package does not build or publish anything; it accepts only a trusted release already identified as `repository@sha256:...`.

## Phase 1 boundary

Phase 1 is a repository-side, non-live foundation. All three environment files set `deployment_enabled` to `false`, leave runtime configuration, secret, and ingress references unset, and name only the intended future GitHub environments. The `Platform promotion request` workflow has one read-only gate job. It validates and hashes a request, confirms the selected environment remains disabled, and then exits. It has no deployment job, environment attachment, OIDC permission, registry credential, or runtime adapter.

Later phases must activate each environment deliberately, supply merge-SHA-bound references, configure protected GitHub environments, and validate live ingress, migration, health, switching, rollback, ownership, restart/recovery, registry authorization, TLS, and audit rotation. PROD requires explicit approval. No repository file assumes those protections exist.

## Phase 2B2 deployment-authority and runtime contract

[ADR 0011](../docs/adr/0011-oidc-restricted-deployment-authority.md) selects a GitHub-hosted deployment job attached to a protected environment, short-lived GitHub Actions OIDC, an unprivileged restricted broker, a closed canonical request over a local Unix-domain socket, and a narrow privileged executor. The broker has no Docker socket. The executor must parse and independently revalidate the request and exposes no shell, arbitrary command, arbitrary Compose file, arbitrary filesystem path, arbitrary repository, arbitrary image, or arbitrary environment.

`identity.py` remains pure authorization policy for **already cryptographically verified** GitHub OIDC claims. It requires the exact DEV audience, repository and numeric identity, workflow ref and revision, main ref, environment, manual event, GitHub-hosted runner, run and actor IDs, temporal claims, and a bounded JTI. Caller-supplied time makes the five-minute lifetime, sixty-second receipt, and thirty-second skew rules deterministic. `ReplayGuard` defines atomic single-use behavior through expiry plus skew. Its in-memory implementation is test-only; the durable implementation described below remains inert and unwired.

### C1 OIDC verifier and dependency boundary

C1 adds a concrete but inert, repository-only verifier in `oidc_verifier.py` and a bounded discovery, HTTPS, JWKS, and in-memory cache boundary in `jwks.py`. The verifier accepts only a compact RS256 JWT, the fixed GitHub issuer, the exact single-string Task 014 DEV audience, and one completely validated RSA JWK selected by a safe `kid`. It uses PyJWT backed by cryptography, passes the literal `algorithms=["RS256"]`, and forwards only verified claims to `authorize_verified_github_oidc()`. The single caller-supplied `received_at` remains authoritative for all temporal authorization. C1 does not consume replay.

Discovery and JWKS retrieval have fixed GitHub HTTPS locations, GET-only behavior, validated system TLS, no proxy-environment handling, no redirects, exact status and JSON media-type requirements, bounded headers and bodies, and approximately three-second connect/read limits with monotonic checks. Python's standard system resolver is used; it does not prove a hard overall DNS or end-to-end deadline. Resolver behavior and the complete deadline require activation-time host qualification.

The JWKS cache is memory-only, serialized, atomically replaced only after complete validation, and reusable for at most 300 seconds. Shorter upstream `max-age`, `no-cache`, and `no-store` directives shorten or eliminate reuse. Unknown keys receive at most one controlled refresh per verification. Expired keys are never used after refresh failure, removed keys cease to be accepted after successful replacement, and no keys or tokens are persisted.

The dedicated [dependency contract](DEPENDENCIES.md) records the CPython 3.12 Linux x86_64 target, exact direct and transitive pins, accepted binary-wheel filenames, hashes, licenses, and provenance. C1 neither creates nor claims a reviewed production wheelhouse or host installation.

C1 adds no replay persistence, broker HTTP API, Unix transport, executor, registry consumer, audit projection, installation asset, workflow authority, listener, or deployment activation. Required private-repository branch and GitHub environment protections remain an absolute prerequisite before any live workflow or DEV deployment can be enabled.

### Durable SQLite replay boundary

`replay_sqlite.py` now supplies an inert, repository-only `SQLiteReplayGuard`. It provides explicit initialization plus the closed `consume()`, `begin_execution()`, and `finish_execution()` operations, but no broker consumes it and no executor transitions it. This repository change does not install or initialize the production directory or database at `/var/lib/omnilyzer/deployment/authority/replay.sqlite3`, and it creates or opens no filesystem state merely by import or construction.

Future reviewed installation must create the dedicated directory as mode `0770` and the database as mode `0660`, then provide reviewed numeric owner and group IDs. The directory is expected to be root-owned with a future reviewed deployment-authority group. The store rejects symlinks, hard links, permissive or mismatched ownership and modes, unexpected directory entries, and databases exceeding 16 MiB. It uses only standard-library SQLite, rollback-journal `DELETE` mode, 4096-byte pages, at most 4096 pages, at most 10,000 live rows, and a busy timeout no greater than 1,000 milliseconds. WAL and shared-memory files remain prohibited pending activation-time filesystem qualification.

On Linux, each operation traverses every absolute directory component from `/` using retained directory descriptors and `O_DIRECTORY|O_NOFOLLOW`, then validates the final descriptor against the configured pathname. It opens and retains the database with `O_NOFOLLOW`, connects SQLite through the held authority-directory descriptor, and compares the named and held database identities before and after use. This prevents an ancestor or authority-directory symlink from redirecting SQLite, prevents a directory replacement after opening from redirecting access, and detects persistent database replacement. CPython 3.12's standard `sqlite3` API accepts only a filename or URI and exposes neither an existing-file-descriptor connection nor its SQLite VFS file handle. It therefore cannot prove that SQLite opened the previously validated database inode against an attacker able to replace and restore the database leaf name entirely between the library's internal `open` and the next identity comparison. The same filename-only limitation applies to replacement and restoration of the rollback journal between its bounded precheck and SQLite's internal recovery open. Activation must qualify the directory as writable only by the narrowly trusted authority principal; eliminating those residual windows would require a reviewed native SQLite VFS or a different storage boundary.

Initialization retains the securely created database descriptor through schema creation and durability checks. Any reported failure attempts to quarantine that exact inode by removing its authority mode, truncating and synchronizing it, and unlinking and synchronizing the directory when the name still identifies it. This prevents ordinary fsync, schema, commit, and connection-close failures from leaving normally accepted state. No userspace implementation can guarantee the post-crash outcome if the filesystem reports failure for both the original durability operation and every quarantine operation, or if power is lost during that uncertainty; activation-time filesystem qualification and explicit operator replacement of any failed initialization residue remain required. Normal operations never initialize, migrate, repair, delete, or replace malformed state.

Each consumption durably binds only the bounded JTI, expiry-plus-skew retention epoch, executor-request SHA-256, GitHub run ID and attempt, and one closed lifecycle status. JWTs, bearer tokens, claims JSON, credentials, canonical request bytes, responses, and outcome details are never replay fields. A transaction validates the filesystem, database identity, exact schema, integrity, size, and SQLite policy; advances a persistent clock watermark; performs bounded deterministic expiry cleanup in `retain_until, jti` order; checks capacity; and inserts the complete binding under `BEGIN IMMEDIATE` with `synchronous=FULL`. Duplicate JTIs and duplicate run-ID/attempt pairs are definite replay rejections; uncertain storage, locking, integrity, schema, mode, clock, or durability failures are unavailable failures.

The only states are `consumed`, `executing`, and `finished`, with only forward one-time transitions. Every transition matches the complete binding. A consumed row may begin execution only while its retention remains valid. Expired consumed and finished rows may be cleaned, but an executing row is never deleted automatically and continues to count toward capacity. If an executor crashes after entering `executing`, the request is never automatically retried or reset; later operator reconciliation requires separate review. The persistent watermark never moves backward, rejects wall-clock rollback beyond the authorization skew, and prevents a small rollback from resurrecting an already expired and removed identity.

The durable replay code remains non-live: there is no installed state, broker, transport, executor wiring, listener, service, registry access, or deployment activation. Required private-repository branch and GitHub environment protections, activation-time filesystem qualification, and a separate live-authority review remain absolute prerequisites before the store or any live workflow or DEV deployment can be enabled.

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
`/var`, and `/var/lib` must be root-owned real directories and may not be
group/other writable unless they have the root-owned sticky-directory
protection used by standard temporary roots in tests. The deployment-owned
`omnilyzer`, `deployment`, and `dev` directories must have the configured
numeric owner and group, owner `rwx`, and no group/other write permission; the
final `dev` directory must be exactly `0700`. The existing `state.json` must be
a single-link regular file, never a symlink, with exact mode `0600`, configured
owner/group, and a nonempty size no greater than 16 KiB.

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
environments remain disabled, and enforceable private-repository branch and
environment protections remain an absolute prerequisite for activation.

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

Omnilyzer must later support restricted-network applications such as Bisma
behind an Aeven corporate firewall, where external deployment initiation or
external health monitoring may be prohibited. A separately approved future
profile may allow an authorized manual/local trigger from inside the corporate
network while preserving the same immutable release, exact OCI digest,
SBOM/provenance/signature requirements, deployment engine, state and audit
controls, and migration and blue/green semantics. C11 does not implement that
trigger. Monitoring may later be internal to Aeven, or outbound-only telemetry
if Aeven policy permits; C11 implements no monitoring functionality.

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
identity semantics remain unchanged. Restricted-network applications such as
Bisma may later require a separately reviewed manual/local authorization
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
DEV, STAGING, and PROD remain disabled, and the unresolved required GitHub
protection prerequisite is unchanged. A later separately reviewed slice must
qualify complete ancestor chains and provision, initialize, install, and start
the required host resources and services.

This host-resource isolation contract does not assume every future deployment
is GitHub-triggered. C12 and the current request/replay identity semantics remain
GitHub-oriented. A future restricted-network profile for applications such as
Bisma may require a separately reviewed local/manual authorization mechanism
and an explicit identity-schema extension or version. C13 implements neither;
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
or activation authority, and introduced no special Bisma fork; the same
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
existing protection prerequisite.

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
authority is activated. Deployment remains disabled pending the existing
protection prerequisite. A later separately reviewed slice may bind a systemd
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
ReadWritePaths=/var/lib/omnilyzer/deployment /var/log/omnilyzer/deployment
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

Persistent read/write allowances cover only `/var/lib/omnilyzer/deployment`
and `/var/log/omnilyzer/deployment`, including reviewed state/replay/audit
resources. Under `ProtectSystem=strict`, `/etc` service configuration and `/opt`
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
| `/var/log/omnilyzer` | directory | 0755 | 0:0 | Must exist before activation |
| `/var/log/omnilyzer/deployment` | directory | 0755 | 0:0 | Must exist before activation |
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

PR B adds reviewed, non-installed assets under `runtime/dev/`, a closed `DockerRuntimeAdapter`, durable atomic state modes, and the initial chained filesystem audit sink. Each adapter instance binds one exact validated `CANARY_IMAGE` into its minimal controlled environment for every command and rejects cross-digest reuse. The adapter contains real narrow execution logic but is never invoked automatically. It exposes no arbitrary subprocess, Compose service, Nginx command, upstream, URL, or filesystem-path operation. Runtime tests inject command and HTTP clients; a separate non-mutating test runs only `docker compose config`. See the [DEV runtime qualification, design, and exact hashes](runtime/dev/README.md).

The required private-repository branch and GitHub environment protections are not enforceable with the currently observed repository/account capability. Repository-side, non-live implementation is permitted before that prerequisite becomes enforceable. PR names do not determine authority: the boundary is whether a change remains inert and repository-only or grants, installs, exposes, or exercises live deployment authority.

Permitted before the prerequisite is resolved:

- closed verifier and authorization code;
- durable replay code;
- broker, transport, and executor code that cannot be activated;
- registry-consumer interfaces and deterministic mocked tests;
- audit schema and identity projection;
- inert, uninstalled systemd, Nginx, and layout fixtures; and
- deterministic repository tests and static validation.

Prohibited until the prerequisite is resolved and the live-authority change is separately reviewed:

- `id-token: write` in a deployment workflow;
- GitHub environment attachment or a deployment job;
- live public broker ingress or listener;
- installation or enabling of host services or sockets;
- live registry credentials or token exchange;
- Docker or application execution;
- host, runtime, or infrastructure mutation;
- environment activation or populated live runtime references; and
- any static-key, personal-account, SSH, self-hosted-runner, or weakened-policy workaround.

Therefore **no live deployment workflow or DEV deployment may be enabled** until the required private-repository branch and GitHub environment protections are enforceable. Live JWT/JWKS behavior, replay installation and wiring, broker/executor hardening, Unix-socket permissions, zot and Forgejo read-only consumers, host services, TLS/DNS/network integration, restart/reconciliation, and the first DEV deployment all remain to validate.

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

This remains inert repository code. No broker currently creates the events, no executor or transport is wired to the sink, no production audit path was accessed or initialized, and no live end-to-end audit evidence is claimed. Required private-repository branch and GitHub environment protections and a separate live-authority activation review remain mandatory before any deployment authority can be enabled.

## Local validation

```bash
python3 -m unittest discover -s deployment/tests -p 'test_*.py'
```

The package is governed by [ADR 0006](../docs/adr/0006-immutable-oci-deployment-and-promotion.md) and [ADR 0011](../docs/adr/0011-oidc-restricted-deployment-authority.md). Task 007 remains historical validation evidence; production code does not import from `spikes/`.
