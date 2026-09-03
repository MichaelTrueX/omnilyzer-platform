# ADR 0006: Immutable OCI Deployment and Staged Promotion

- Status: Accepted
- Date: 2026-08-29

## Context

Omnilyzer needs deployment behavior that separates source and build activity from environment deployment. A reviewed artifact must progress through DEV, STAGING, and PROD without per-environment rebuilds, while environment configuration and secrets remain outside the image. Deployments also need explicit database migrations, readiness gates that prevent traffic from reaching an unready release, controlled traffic switching and rollback, structured audit evidence, and operational simplicity appropriate to the platform's initial scale.

Task 007 validated these mechanics with three isolated Docker Compose environments on the DEV host. It did not connect to or deploy on the real PROD server.

Reference evidence:

- [`spikes/deployment/README.md`](../../spikes/deployment/README.md)
- [`deployment-validation.md`](../../spikes/deployment/results/deployment-validation.md)
- [`spikes/supply-chain/README.md`](../../spikes/supply-chain/README.md)

## Decision

### OCI artifact

1. Omnilyzer application deployments use OCI container images as the standard application deployment artifact.
2. Application code is built into an image before environment deployment.
3. A deployment candidate is approved and promoted by immutable OCI digest.
4. After a candidate digest is established, deployments use digest references such as `repository@sha256:...`, not mutable application tags.
5. DEV, STAGING, and PROD promotion uses the same approved application image digest.
6. A stage must not rebuild the application.
7. Environment configuration is injected at runtime rather than baked into the application image.
8. Environment secrets are supplied through runtime secret mechanisms rather than Dockerfiles, source, image labels, or release metadata.
9. Human-readable tags may exist for discovery, but they are not sufficient deployment identity.
10. Mutable tag drift must not change an already approved deployment.

### Important reproducibility distinction

Task 007 validated:

```text
build once
    ↓
immutable digest
    ↓
promote exact digest
```

Task 007 did not validate:

```text
same source + same toolchain
    ↓
rebuild twice
    ↓
identical OCI digest
```

Independently reproducible OCI rebuilds remain **TO VALIDATE**. This ADR does not claim that reproducible OCI builds were proven.

### Promotion order

Promotion follows this order:

```text
DEV
 ↓
STAGING
 ↓
PROD
```

A later stage must not accept a candidate until the required earlier-stage promotion gates have succeeded. Production promotion is explicit. Direct source editing or ad-hoc rebuilding on PROD is not part of the deployment model.

### Deployment state

Deployment control persists relevant state outside application process memory. At minimum, deployment systems must know:

- active release;
- active digest;
- active slot;
- previous release;
- previous digest;
- migration or schema state.

The previous digest is required for reliable rollback.

### Initial orchestration

Docker Compose, or equivalently simple container orchestration, is the accepted initial orchestration direction. Nginx is the accepted initial reverse-proxy and traffic-switch boundary.

Docker Compose is not declared the permanent scaling solution. Kubernetes and Docker Swarm are not accepted by this decision. More complex orchestration should be introduced only when availability, scale, or operational evidence justifies it.

### Blue/green deployment

The accepted deployment pattern is:

```text
active slot
    |
continues serving
    |
start candidate in inactive slot
    |
explicit migration gate
    |
liveness/readiness validation
    |
application validation
    |
nginx -t
    |
Nginx reload / traffic switch
    |
new slot active
```

The active release must not be removed before candidate validation succeeds. Traffic switching should avoid unnecessary process replacement of the proxy. The Task 007 local request-loop result is evidence for these mechanics only; it does not establish production high availability.

### Health contract

Applications expose separate liveness and readiness concepts:

- `/livez` reports whether the application process is functioning.
- `/readyz` is the stricter deployment and traffic gate.

Readiness should cover dependencies necessary to serve traffic, including required runtime configuration, database reachability, and required database migration state. A process may be live but not ready. Traffic must not switch to a candidate until readiness succeeds.

### Database migration deployment model

Database migrations execute explicitly as a deployment step. Schema migrations do not run independently from every application process at startup.

Migration execution must be serialized. Migration history must record migration identity and support integrity or checksum verification. Migration failure blocks deployment. Task 007 validated a PostgreSQL advisory-lock model and migration checksums. The exact production Django migration implementation remains to be designed.

### Expand-compatible migrations

Expand-compatible database changes are the default deployment principle. A new release should avoid immediately destructive changes that prevent the previously deployed application from operating.

For a representative release:

```text
App 1.0
Schema 1
   ↓
Migration
   ↓
Schema 2 additive
   ↓
App 1.1
```

Application rollback may return to:

```text
App 1.0
Schema 2
```

when App 1.0 remains compatible with the expanded schema. Destructive down migrations are not the normal application rollback strategy. Contract or destructive migration steps require separate lifecycle planning after older application versions are no longer supported. Task 007 did not validate real Django migration compatibility.

### Rollback

Rollback uses a previously retained immutable image digest. The previous release is not rebuilt during an incident.

```text
current candidate digest
       ↓
start retained previous digest
       ↓
readiness against current compatible schema
       ↓
validate
       ↓
traffic switch
```

Database rollback and application rollback are separate concerns. Application rollback must not automatically imply a destructive database down migration.

### Configuration and secrets

The accepted stage model is:

```text
same OCI digest
+ different runtime configuration
+ different stage secrets
```

for DEV, STAGING, and PROD. Secrets must not be present in source, image layers, OCI labels, release metadata, safe diagnostic endpoints, or deployment audit records. Actual production secrets-management technology remains **TO VALIDATE**.

### Container security boundary

Baseline application-container controls, where supported, are:

- a non-root UID/GID;
- a read-only root filesystem;
- dropped Linux capabilities;
- `no-new-privileges`;
- narrowly scoped writable tmpfs mounts only where needed;
- no Docker socket mount;
- no production credentials in images;
- pinned base-image digests in controlled builds.

These controls do not complete container hardening. SBOM, vulnerability-scanning policy, signing, provenance, runtime security, and patch management remain separate work.

### Network boundary

The accepted initial topology is:

```text
external / host
      |
    Nginx
      |
frontend network
      |
 application
      |
 backend network
      |
 PostgreSQL
```

Application and PostgreSQL services should not normally expose host ports directly. Only the reverse proxy exposes the application boundary. PostgreSQL is backend-only, and Nginx does not require attachment to the database network.

Task 007's loopback binding was a spike safety constraint. Production ingress will be defined later with the real TLS, Cloudflare, and network architecture; this decision does not require production traffic to bind permanently to `127.0.0.1`.

### Auditability

Deployment operations generate structured audit evidence. Relevant events include:

- build and release identity;
- promotion start;
- migration start, success, or failure;
- readiness result;
- traffic switch;
- promotion success or rejection;
- rollback start and success.

Audit events should identify the stage, release, immutable digest, previous digest where relevant, actor, result, migration state, and timestamp. Audit records must not contain credentials or secret values. Exact production audit storage or service selection remains future implementation work.

### Immutable infrastructure references

Task 007 pinned its required infrastructure images by digest. Infrastructure images used in controlled deployment definitions should likewise be version or digest controlled rather than depending solely on floating tags. Routine patch and update processes must intentionally update these pins.

### Registry boundary

Task 007 used an ephemeral loopback registry only to validate registry-style immutable digest promotion. This does not select a production container registry. Registry and provider selection remains **TO VALIDATE**. This ADR does not select GitHub Container Registry, Docker Hub, Cloudflare, or another provider.

Task 008C subsequently evaluated Forgejo as a self-hosted registry candidate. Under the tested deployment/configuration, Forgejo accepted a different OCI manifest PUT to an existing tag with HTTP `201`; the previously verified manifest digest then returned HTTP `404 MANIFEST_UNKNOWN`. Forgejo OCI is therefore rejected under that tested configuration for this ADR's immutable-release and rollback requirements. This evidence reinforces rather than weakens the requirement to promote by immutable digest and retain the previous digest for rollback. Production OCI registry selection remains **TO VALIDATE**.

### Provenance boundary

The following concepts are distinct:

```text
immutable image digest
≠
signed provenance
≠
trusted publisher identity
≠
vulnerability approval
```

Task 007 validates immutable artifact identity and promotion. It does not validate OCI signing, Sigstore/Cosign, SLSA provenance, SBOM policy, trusted publishing, or vulnerability scanning and gating. These remain future production-release work.

## Architecture

The candidate is not rebuilt between stages.

```text
                  source
                    |
                    v
              controlled build
                    |
                    v
              OCI candidate
            repository@sha256
                    |
          +---------+---------+
          |                   |
          v                   |
         DEV                  |
          |                   |
      gates pass              |
          |                   |
          v                   |
       STAGING                |
          |                   |
      gates pass              |
          |                   |
          v                   |
        PROD <----------------+
          |
     blue / green
          |
        Nginx
          |
     application
          |
      PostgreSQL
```

## Release flow

```text
source revision
      ↓
build once
      ↓
immutable OCI digest
      ↓
security / policy checks
      ↓
DEV promotion
      ↓
DEV gates
      ↓
STAGING promotion
      ↓
STAGING gates
      ↓
PROD promotion
      ↓
inactive slot
      ↓
migration
      ↓
readiness
      ↓
traffic switch
      ↓
audit state
```

## Consequences

Positive consequences include:

- separation between build and deployment;
- consistent artifacts across stages;
- resistance to artifact drift;
- explicit promotion and database migrations;
- readiness-based traffic protection;
- runtime configuration and secret separation;
- retained-image rollback;
- blue/green traffic switching;
- a centralized ingress boundary;
- auditable deployment events;
- no requirement for Kubernetes at initial scale.

Tradeoffs include:

- two slots temporarily require additional resources;
- old images must remain available for rollback;
- expand-compatible migrations require discipline;
- deployment state needs reliable storage;
- Docker Compose remains single-host, simple orchestration;
- digest pins require deliberate updates;
- the real registry and provenance remain unvalidated;
- local traffic tests do not prove production high availability.

## Explicit non-decisions and remaining validation

This ADR does not validate or select:

- an actual real PROD deployment;
- an exact production container registry;
- registry authentication;
- independently reproducible OCI rebuilds;
- OCI signing;
- Sigstore/Cosign;
- SLSA provenance;
- SBOM policy;
- vulnerability-scanning policy;
- a production secrets manager;
- final TLS or Cloudflare ingress;
- public DNS;
- multi-host failover;
- Kubernetes;
- Docker Swarm;
- multi-region architecture;
- autoscaling;
- capacity or load limits;
- host-failure recovery;
- database backup or PITR;
- the production Django migration implementation;
- Keycloak production deployment;
- final audit-log storage.
