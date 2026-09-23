<!--
File: docs/architecture/deployment-model.md
Purpose: Defines the planned promotion flow and immutable deployment principles.
Related:
- docs/architecture/platform-principles.md
- docs/architecture/security-model.md
- docs/architecture/technology-decisions.md
-->

# Deployment Model

## Promotion flow

```text
developer workspace
    ->
feature branch
    ->
pull request
    ->
CI
    ->
DEV
    ->
STAGING
    ->
PROD
```

DEV, STAGING, and PROD are separate deployment stages. CI builds an immutable application image once; promotion uses that identical image digest across stages. Only environment-specific configuration, externally managed secrets, and stage-specific scale differ. Rebuilding for a later stage is not promotion.

Production source editing and direct production development are prohibited. Codex must not code on PROD. PROD must contain no uncommitted application source; deployments are traceable released artifacts produced through review and CI.

## Release and rollback

Releases require automated checks, artifact provenance, configuration validation, deployment health checks, and an auditable approval path. Rollback normally redeploys the last known-good immutable image and compatible configuration. Database changes require a tested recovery plan because application rollback alone may not reverse data changes.

Use expand/migrate/contract for incompatible database evolution:

1. **Expand:** add backward-compatible schema and dual-compatible application behavior.
2. **Migrate:** transform/backfill data with observable, restartable operations.
3. **Contract:** remove old structures only after all consumers have migrated and rollback windows have closed.

Destructive migrations require explicit approval, backups appropriate to the risk, restore validation, and a documented rollback or forward-recovery strategy.

## Scale and orchestration

Production should eventually scale horizontally, so application instances must not depend on memory-only shared state or mutable local source. OCI containers, simple initial orchestration, Nginx, and pgBackRest remain **TO VALIDATE**. Kubernetes is not initially required and needs demonstrated operational justification before introduction.

Development source and deployment artifacts must remain conceptually and operationally separate regardless of host layout. A developer checkout is not a production deployment artifact.
