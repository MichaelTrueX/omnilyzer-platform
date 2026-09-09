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

One captured monotonic deadline of at most three seconds covers validation,
creation, connection, credential and metadata checks, transmission, response,
EOF proof, and close. Every potentially blocking socket operation receives
only the remaining budget. There is no reconnect, resend, retry, shared
framing state, descriptor inheritance, compact-token or claims-mapping
transmission, added identity envelope, arbitrary path, client bind, listener,
or server implementation. The canonical request itself retains its required
bounded OIDC JTI and execution-identity fields; removing them would violate the
existing executor contract and exact-byte forwarding rule. All operational errors
are reduced to `executor transport is unavailable` without path, identity,
payload, framing, timing, errno, or dependency details.

C5 does not install or qualify the parent ownership and mode chain beneath
`/run/omnilyzer/deployment`, create or contact the production socket, or
implement the executor listener. Activation must separately install and
validate that complete chain. Root-equivalent local compromise is outside what
a Unix-socket client can defend against. GitHub protections and a separate
live-authority review remain mandatory before this inert transport may be
installed, connected to a production executor, or used for deployment.

`execution.py` continues to define immutable closed runtime, no-secret, ingress, and executor-request models. Its broker protocol now exposes only the safe token, canonical-request bytes, and receipt-time API implemented by the restricted broker. The only operation is `deploy` to DEV. Canonical JSON reuses the repository's sorted, compact, ASCII, newline-terminated representation. Privileged-executor and transport types remain protocols. C4 adds no HTTP or Unix server, systemd service, or public endpoint.

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
