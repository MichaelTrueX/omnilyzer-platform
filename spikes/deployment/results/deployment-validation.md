# Deployment validation

Recommendation: **adopt**

## Evidence

- Docker/Compose runtime: Docker client=29.7.2 server=29.7.2; Compose 5.5.0; Python 3.12.3; buildx available (v0.36.1)
- OCI image result: baseline and candidate built once and promoted by registry digest.
- Baseline digest: `sha256:dfb836e5dbab38d356995d367d315f5354240aef3f09a1597c14147372adacd2`
- Candidate digest: `sha256:52e1a955ec1847313aa84c5a487b869bf1b875a6083d0bd111503493a0312bd9`
- Candidate digest equality: PASS — DEV = STAGING = simulated PROD = `localhost:15007/omnilyzer-task007@sha256:52e1a955ec1847313aa84c5a487b869bf1b875a6083d0bd111503493a0312bd9`
- Runtime configuration separation: PASS — three distinct /config payloads, database system identities, volumes, and Compose projects
- Secret separation: PASS — three distinct synthetic secret-file hashes; no secret value reported
- PostgreSQL migration result: PASS — advisory-locked, idempotent migration history records identifiers/checksums; schema version 2 reached
- Pre-migration readiness rejection: PASS — candidate returned 503; Nginx and persisted state remained on 1.0.0
- Migration checksum rejection: PASS — altered temporary 001 rejected; real PROD-simulation history remained intact
- Promotion ordering result: PASS — PROD-before-STAGING promotion rejected
- DEV promotion: PASS — 1.1.0 active by approved digest
- STAGING promotion: PASS — 1.1.0 active after explicit migration gate
- PROD promotion: PASS — simulated PROD runs 1.1.0 by the approved digest
- Blue/green traffic switch: PASS — Nginx reloaded while both slots remained alive
- Request success/failure count: 200 total / 200 successful / 0 failed
- Container restart result: PASS — active STAGING container returned with the same image ID and release
- Tag-drift protection: PASS — mutable candidate tag drifted to baseline while the approved digest still resolved to 1.1.0
- Rollback result: PASS — retained baseline digest restored; 200 requests, 0 failures
- Schema after rollback: PASS — migration 002 remains recorded; 1.0.0 readiness and /data succeed without down migration
- Nginx boundary: PASS — only Nginx publishes loopback; Nginx/frontend and PostgreSQL/backend boundaries enforced
- Compose security result: PASS — digest-only deploy refs, no app build/ports, secret mounts, read-only rootfs, cap-drop ALL, no-new-privileges
- Image inspection result: PASS — UID/GID 10001, OCI labels, source/migrations/dependency present; no Git, socket, path, marker, or secret found
- Audit result: PASS — 33 JSONL records cover required events and contain no known secret
- Cleanup result: PASS — no Task 007 containers or named volumes remain

## Limitations

- Does not validate actual real PROD deployment.
- Does not validate multi-host orchestration.
- Does not validate Kubernetes or Docker Swarm.
- Does not validate a production container registry or registry authentication.
- Does not validate signed OCI provenance.
- Does not validate SBOM/signing or vulnerability-scanner policy.
- Does not validate the actual TLS/Cloudflare boundary or public DNS.
- Does not validate multi-region availability.
- Does not validate database PITR or backup/restore.
- Does not validate production load/capacity or autoscaling.
- Does not validate host failure.
- Does not validate real Django migration compatibility.
- Does not validate Keycloak deployment topology.
- Does not validate a production secrets manager.

The zero-failure request loop is local blue/green evidence only; it does not prove production HA or multi-host resilience.
