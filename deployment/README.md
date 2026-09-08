# Task 014: exact-digest promotion and deployment control plane

Task 014 consumes accepted Task 013 release outputs and controls their ordered deployment. The release system builds, scans, signs, and publishes artifacts. This package does not build or publish anything; it accepts only a trusted release already identified as `repository@sha256:...`.

## Phase 1 boundary

Phase 1 is a repository-side, non-live foundation. All three environment files set `deployment_enabled` to `false`, leave runtime configuration, secret, and ingress references unset, and name only the intended future GitHub environments. The `Platform promotion request` workflow has one read-only gate job. It validates and hashes a request, confirms the selected environment remains disabled, and then exits. It has no deployment job, environment attachment, OIDC permission, registry credential, or runtime adapter.

Later phases must activate each environment deliberately, supply merge-SHA-bound references, configure protected GitHub environments, and validate live ingress, migration, health, switching, rollback, ownership, restart/recovery, registry authorization, TLS, and audit rotation. PROD requires explicit approval. No repository file assumes those protections exist.

## Phase 2B2 deployment-authority and runtime contract

[ADR 0011](../docs/adr/0011-oidc-restricted-deployment-authority.md) selects a GitHub-hosted deployment job attached to a protected environment, short-lived GitHub Actions OIDC, an unprivileged restricted broker, a closed canonical request over a local Unix-domain socket, and a narrow privileged executor. The broker has no Docker socket. The executor must parse and independently revalidate the request and exposes no shell, arbitrary command, arbitrary Compose file, arbitrary filesystem path, arbitrary repository, arbitrary image, or arbitrary environment.

`identity.py` is pure authorization policy for **already cryptographically verified** GitHub OIDC claims. It does not parse JWTs, verify signatures, or retrieve JWKS. It requires the exact DEV audience, repository and numeric identity, workflow ref and revision, main ref, environment, manual event, GitHub-hosted runner, run and actor IDs, temporal claims, and a bounded JTI. Caller-supplied time makes the five-minute lifetime, sixty-second receipt, and thirty-second skew rules deterministic. `ReplayGuard` defines atomic single-use behavior through expiry plus skew. Its in-memory implementation is test-only; production requires bounded durable local state that fails closed when unavailable or corrupt.

`execution.py` defines immutable closed runtime, no-secret, ingress, and executor-request models. The only operation is `deploy` to DEV. Canonical JSON reuses the repository's sorted, compact, ASCII, newline-terminated representation. Broker, privileged-executor, and transport types remain protocols: this phase adds no HTTP or Unix server, systemd service, JWT/JWKS implementation, or public endpoint.

PR B adds reviewed, non-installed assets under `runtime/dev/`, a closed `DockerRuntimeAdapter`, durable atomic state modes, and the initial chained filesystem audit sink. The adapter contains real narrow execution logic but is never invoked automatically. It exposes no arbitrary subprocess, Compose service, Nginx command, upstream, URL, or filesystem-path operation. Tests inject command and HTTP clients and make no Docker calls. See the [DEV runtime qualification, design, and exact hashes](runtime/dev/README.md).

The required private-repository branch and GitHub environment protections are not enforceable with the currently observed repository/account capability. Therefore **no live deployment workflow may be enabled**. This limitation must be resolved before PR C/D; it must not be worked around with a static SSH key, personal deployment identity, self-hosted runner on DEV, or weaker workload policy. Live JWT/JWKS behavior, replay persistence, broker/executor hardening, Unix-socket permissions, zot and Forgejo read-only consumers, host services, TLS/DNS/network integration, restart/recovery, and the first DEV deployment all remain to validate.

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

Audit events use a closed schema and deterministic canonical representation. They cover promotion, migration, liveness, readiness, traffic switching, and rollback outcomes, and bind candidate identity, slots, actor, migration identity, result, timestamp, and event ID. `AuditSink` is an append-oriented interface only; Phase 1 does not choose a permanent backend.

## Local validation

```bash
python3 -m unittest discover -s deployment/tests -p 'test_*.py'
```

The package is governed by [ADR 0006](../docs/adr/0006-immutable-oci-deployment-and-promotion.md) and [ADR 0011](../docs/adr/0011-oidc-restricted-deployment-authority.md). Task 007 remains historical validation evidence; production code does not import from `spikes/`.
