<!--
FILE: docs/operations/m01-task013-immutable-oci-context-20261028.md
PURPOSE: Describe reproducible source-materialized Analytics OCI context,
         threat model, verified local tests and remaining original Task013
         signed-release/Task014 deployment authority gates.
LINKS: release/analytics_oci_context.py;
       release/tests/test_analytics_oci_context.py;
       release/analytics_task013_build_input.py (M05 PR231);
       release/analytics_source_admission.py;
       MichaelTrueX/omnilyzer Dockerfile.analytics, .dockerignore, PR45;
       original .github/workflows/platform-release.yml, Task013/014.
STATUS: REVIEW SOURCE ONLY. No protected-main workflow or installed services edited.
-->

# Analytics OCI build must consume exact Git-committed bytes

28 October 2026. The original platform Task013 source producer currently builds
a synthetic canary from a fixed local fixture. M05 PR231 adds a review-only
deterministic Analytics build-input record covering the approved external
Analytics source commit, 51 exact source identities and product profiles.

## Resolved source-context integrity gap

A valid Git SHA and Dockerfile hash does not guarantee Docker's `COPY . .`
reads those same bytes if the CI working tree also includes extra untracked
files, ignored files or modifications. A mutable local Docker build context
can introduce bytes which are not bound to reviewed Git provenance.

The additive `release/analytics_oci_context.py` uses the *existing*
M01/M05 source admission and emits a canonical tar directly from Git blob
objects for the exact Analytics PR45 commit. No tracked file contents are
read from the mutable filesystem. It rejects symlinks/submodules and unsafe
paths, applies an extra strict exclusion layer for committed local-secret
and backup-like files (including historical `.env.memory` and
`.venv_backup_*`), bounds files and byte sizes, preserves executable bits,
normalizes tar owner/time, requires essential build source, and refuses
to overwrite an existing archive. It does not interpret unsigned source
metadata as release/signing authority.

The deterministic, sanitized tar should be supplied **as the actual Docker
build context** to the EXISTING Task013 BuildKit builder when that original
workflow is later extended for an authorized Analytics product. The
`.dockerignore` in the archive provides Docker's separate filtering layer.
Never revert to building directly from a mutable user checkout.
Do not include real JWT or PostgreSQL credentials as Docker build arguments.

## Direct local DEV evidence

- Five independent tests PASS: extra untracked source cannot enter build,
  dirty tracked files cannot change artifact bytes, symlink is rejected,
  SHA mismatch/output overwrite rejected, excluded secret patterns enforced.
- Read-only M05 Task013 source admission: exact Analytics PR45 Git commit
  `8648adba2db884cc78274080b9836ca46bafd630`, 51 critical/original
  source identities verified. No commit or runtime account changed.
- Actual immutable context: **532 committed non-secret-like files**,
  **10,229,760-byte TAR**, `sha256:d64d272944b775085ad62e9d8ef0f4be5b272fc87286f8f607d59105ccb4b818`.
  `Dockerfile.analytics`, `.dockerignore`, `package.json`, Prisma schema,
  `/readyz` and `/livez` route sources present. Historical tracked
  `.env.memory`, backups and previous local virtualenv excluded.
- The temporary TAR is deleted after verification; no source/test credentials
  written to registry, live Docker service or existing deployed host.
- The build helper returns `release_authorized:false`,
  `deployment_authorized:false`; it does not produce a signed OCI digest.
- **Actual Docker build from the produced TAR succeeded** using
  `docker build -f Dockerfile.analytics -t
  omnilyzer-analytics-immutable-source-test:20261028 - <
  /tmp/omni-analytics-exact-context-image-20261028.tar`, against the
  exact packaged PR45 source. Local image ID
  `sha256:78d4771a06e77d8e107dc5414d8e74088123423c87d86cbb2439ba8bd0fb8b2e`.
  Image runs as UID/GID `10001:10001`; `Config.Env` contains only
  the Node/Yarn PATH/version, NODE_ENV and NEXT_TELEMETRY_DISABLED,
  **no JWT/DB secret values**. Both test image tag and TAR were removed
  by the test trap. This is **local build compilation evidence only**;
  no signed OCI registry manifest, Task013 signature/provenance,
  Task014 broker deployment or protected-main mutation was performed.

## Important limits before a Task013 workflow uses this

1. Adapt the EXISTING release workflow's distinct Analytics build stage to
   invoke this source snapshot after M01/M05 immutable input verification.
   Preserve the present Task013 platform main-only OIDC claims, original
   canary fixture and release-version/replay identities.
2. Build/publish/scan/sign the exported exact context through the ORIGINAL
   Task013 BuildKit, Syft/Grype, Forgejo/Zot and Cosign pipeline with a new
   signed immutable external-source Git claim. Do not sign this unsigned
   preflight output as if it were the original protected source commitment.
3. The ORIGINAL Task014 `release_consumer`, broker/executor, sealed source
   sets and private product runtime must authorize Analytics independently
   against verified signed claims and an exact immutable registry digest,
   without widening the installed canary policy prematurely.
4. Retain restricted auth and collector database roles, signed JSON Bearer
   session revocation, Workspace/Website FORCE RLS, optional consent, CSP/CORS
   and immutable digest-only rollback preserving customer writes.
5. A main merge, workflow dispatch, installed DEV authority transition and
   live product deployment remain approval-gated. This source-only
   implementation does not trigger any of them.

This exports a reproducible product source input. It does not claim shared
identity/Website Engine runtime consumption or a signed Analytics release.
