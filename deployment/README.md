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
