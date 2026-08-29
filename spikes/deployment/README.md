# Task 007: immutable OCI promotion spike

This isolated fixture validates build-once OCI promotion through three local Compose projects. It does not deploy Omnilyzer or contact any external environment. Only Nginx is host-published, on `127.0.0.1:18080`, `:18081`, and `:18082`; application and PostgreSQL services remain on project-scoped Docker networks.

## Run

Prerequisites are the existing Docker Engine with Compose v2/buildx and Python 3.12. The official base-image tags and resolved digests are committed in `images.lock.json`.

```bash
python3 scripts/run_validation.py
```

The runner starts a loopback-only ephemeral registry, builds releases 1.0.0 and 1.1.0 exactly once each, pushes them, and deploys only `repository@sha256:…` references. The registry is test infrastructure only and makes no production registry selection. Synthetic per-stage password files, state, rendered Nginx configuration, manifest, and append-only audit JSONL live beneath ignored `.validation/` storage and are removed during cleanup. The concise evidence report is written to `results/deployment-validation.md`.

Migrations are release-bound files inside each image. `migrate.py` takes a PostgreSQL advisory lock, records identifiers and SHA-256 checksums, is idempotent, and rejects changed history. Applications never migrate at startup. Readiness checks configuration, database connectivity, and required migration identifiers; liveness checks only the process.

Blue and green applications are kept available while the controller checks liveness, readiness, release metadata, immutable image identity, and schema state. It syntax-tests Nginx before reload. Rollback reuses the retained 1.0.0 digest without reverting the additive schema migration.

## Safety and limitations

No Docker socket is mounted. Application containers run as UID/GID 10001 with a read-only root filesystem, all capabilities dropped, no-new-privileges, and only a temporary `/tmp`. All credentials and data are synthetic. Cleanup targets only uniquely prefixed Task 007 projects, registry container, volumes, networks, and temporary files.

This is local architecture evidence, not proof of production availability, security, load capacity, multi-host failover, or suitability of any production registry or secrets provider. See the generated results report for the full limitations list.
