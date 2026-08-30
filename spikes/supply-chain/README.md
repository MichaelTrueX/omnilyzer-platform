<!--
File: spikes/supply-chain/README.md
Purpose: Defines the governed Task 008 private-registry and GitHub OIDC validation spike.
Related:
- docs/adr/0005-versioned-platform-packaging-and-distribution.md
- docs/adr/0006-immutable-oci-deployment-and-promotion.md
- .github/workflows/task008-publish.yml
- .github/workflows/task008-consume.yml
-->

# Supply-chain registry and OIDC spike

## Hypothesis

GitHub Actions can use GitHub OIDC and short-lived Cloudsmith credentials to publish and consume one exact coordinated release across private standard Python, npm, and OCI package formats. Cloudsmith is a candidate under test, not an accepted architecture or production-provider selection.

The candidate private multi-format repository is `omnilyzer/platform-spike`. Publication uses the `gha-publisher-u76y` service account with effective repository `Write`; consumption uses the separate `gha-consumer` service account with effective repository `Read`. Neither workflow uses a long-lived CI credential or GitHub secret for Cloudsmith authentication.

## Acceptance criteria

- The publisher obtains a short-lived credential through GitHub OIDC, builds all three synthetic artifacts with one strict `X.Y.Z` version, and publishes them to the private repository.
- The Python package is `omnilyzer-supply-chain-spike`, the npm package is `@omnilyzer/supply-chain-spike`, and the OCI image is `docker.cloudsmith.io/omnilyzer/platform-spike/omnilyzer-supply-chain-spike`.
- The publisher records the source commit, exact release version, wheel and tarball SHA-256 values, and immutable OCI digest without recording a credential.
- The independently authenticated read-only consumer installs the exact Python and npm versions from Cloudsmith, pulls the exact OCI tag, verifies each reported version, and captures the immutable image digest without using local fixture artifacts.
- A missing, malformed, substituted, unauthorized, or unexpectedly mutable artifact causes validation to fail closed.
- Local preparation and policy tests succeed without Cloudsmith or network access.

**TASK 008A LIVE VALIDATION: PASS.** The publisher and the independently authenticated read-only consumer completed the exact-version, multi-format round trip.

## Security checks

The workflows grant only `contents: read` and `id-token: write`. Third-party actions are pinned to reviewed full commit SHAs, checkout persistence is disabled, build state stays under `RUNNER_TEMP`, npm lifecycle scripts are ignored, and the OCI fixture uses `FROM scratch` and is inspected rather than executed by the consumer. Docker authentication uses `password-stdin` and is followed by an unconditional cleanup step when login succeeded.

Cloudsmith trust is constrained to the private repository `MichaelTrueX/omnilyzer-platform`, `repository_visibility = private`, and these exact feature-branch workflow identities:

- Publisher: `MichaelTrueX/omnilyzer-platform/.github/workflows/task008-publish.yml@refs/heads/spike/008-supply-chain`
- Consumer: `MichaelTrueX/omnilyzer-platform/.github/workflows/task008-consume.yml@refs/heads/spike/008-supply-chain`

The provider is `https://token.actions.githubusercontent.com`. The publisher remains `Write`, not `Admin`; the consumer remains `Read`. Task 008A does not attempt deletion, replacement, or any consumer write operation.

## Test approach

The committed fixture version metadata uses only the harmless placeholder `0.0.0`. The scratch OCI fixture also contains one harmless synthetic text artifact so its image has a real filesystem layer while remaining non-executable and base-image-free. `scripts/prepare_release.py` accepts a strict release version and a new absolute output directory outside the spike source, copies all mutable inputs there, coordinates the Python, npm, and OCI versions, and records expected artifact names. Standard-library unit tests verify valid coordinated versions, malformed inputs, unsafe output use, the layered scratch-image contract, unchanged committed fixtures, exact workflow triggers and identities, action pins, credential policy, and ignored generated paths.

The temporary feature-branch push trigger paths are used because GitHub cannot dispatch a new `workflow_dispatch` workflow until that workflow exists on the default branch. Publication is isolated to changes to `control/publish.trigger`; consumption is isolated to `control/consume.trigger`. Both triggers contain `0.8.1`, and both live runs have completed. Production workflows should use protected release refs and/or protected environments rather than this temporary spike branch.

## Findings

**TASK 008A LIVE VALIDATION: PASS.**

The successful publisher retry ran from commit `f844573eb7c48e005ef4bc40e730a5b4982a3c40` in GitHub Actions run `33287331610` for release `0.8.1`, authenticated as `gha-publisher-u76y`.

Publisher passes:

- GitHub OIDC authentication succeeded.
- Python `0.8.1` publication succeeded.
- npm `0.8.1` publication succeeded.
- Docker registry authentication succeeded.
- OCI `0.8.1` publication succeeded.
- The immutable OCI digest resolved to `sha256:614acfc6b461bbe279b7848f78d9fa0623bfabda9aa146864e2ec5d67b66a4ce`.
- The release summary succeeded.
- Credentials remained masked.
- Docker logout cleanup succeeded.

The independent consumer ran from commit `1624b2ecfaa8a5a1822cde2c6227d09152aca987` in GitHub Actions run `33287727843` for release `0.8.1`, authenticated as `gha-consumer`.

Consumer passes:

- GitHub OIDC authentication succeeded.
- Exact Python `0.8.1` was downloaded from Cloudsmith and its package report/version assertion passed.
- Exact npm `0.8.1` was downloaded from Cloudsmith and its package report/version assertion passed.
- Docker registry authentication succeeded.
- Exact OCI `0.8.1` was pulled from Cloudsmith and its version label assertion passed.
- Immutable OCI digest validation succeeded.
- Docker logout cleanup succeeded.

The consumed OCI digest was `sha256:614acfc6b461bbe279b7848f78d9fa0623bfabda9aa146864e2ec5d67b66a4ce`, exactly matching the publisher digest.

Task 008A validates private multi-format Cloudsmith hosting; Python, npm, and OCI publication; GitHub Actions OIDC; separate publisher and consumer identities; exact-version consumption; an immutable OCI digest round trip; and the absence of long-lived Cloudsmith credentials in GitHub Actions.

## Task 008B permission boundaries

**TASK 008B PHASE 1 — PASS WITH PROVIDER CAVEAT.** The consumer cannot publish; the publisher can create new artifacts but cannot replace or delete them; and the exact sacrificial artifact remained byte-identical after both blocked operations.

**TASK 008B PHASE 1A CONSUMER PERMISSION VALIDATION: PASS.** GitHub Actions run `33289391416` authenticated `gha-consumer` through OIDC. Its Generic write attempt was explicitly denied with `403 Forbidden` and "You do not have permission to perform this action." An authenticated repository read remained available, and exact JSON state verification found zero probe artifacts.

**TASK 008B PHASE 1B PUBLISHER PERMISSION VALIDATION: INCONCLUSIVE / RETRY REQUIRED.** GitHub Actions run `33289502031` authenticated `gha-publisher-u76y`, and its sacrificial Generic create succeeded. The `--republish` attempt failed with `400 Bad Request` and an existing-package message referring to an unknown version attribute, rather than recognizable authorization-denial evidence. The workflow correctly declined to accept that failure as proof, and the delete test was not reached. Cloudsmith was then manually confirmed to require `Admin` for replacement and deletion, while the publisher has `Write`, Self Privilege deletion is disabled, and replace-by-default is disabled; these settings were not changed.

Publisher v2 GitHub Actions run `33290050894`, from commit `e8087f95d2516336ae889ad88325860625f21b26`, authenticated `gha-publisher-u76y` through OIDC. Its explicitly versioned sacrificial Generic create succeeded, the exact package/version/path became visible, and Cloudsmith's SHA-256 matched the local SHA-256. Replacement using the same filepath/version and `--republish` was blocked with `400 Bad Request`; the exact `slug_perm` and original checksum remained unchanged. Deletion of that validated `slug_perm` was explicitly denied with `403 Forbidden` and "You do not have permission to perform this action"; the exact package and checksum again remained unchanged. The workflow reported `replace_result=INCONCLUSIVE` and `delete_result=PASS` because replacement did not produce permission-specific denial text.

Validated negative evidence:

- the consumer `Read` identity cannot upload;
- the publisher `Write` identity can create;
- the publisher `Write` identity cannot republish or replace;
- the publisher `Write` identity cannot delete;
- all probes use disposable Generic artifacts under unique `GITHUB_RUN_ID`-derived filepaths and filenames;
- the validated Python, npm, and OCI release `0.8.1` is never mutated.

Cloudsmith Generic identity is the unique filepath and filename, not a separate package name. The consumer probe attempts only its unique sacrificial Generic upload, requires both a nonzero exit and recognizable authorization-denial output, then performs an authenticated JSON list and proves that no exact format/filename/filepath match was created. Any failure without explicit denial evidence is inconclusive and fails closed.

The publisher v2 probe adds an explicit `0.0.<GITHUB_RUN_ID>` Generic version to both create and `--republish`. It uses a small bounded list retry while Cloudsmith makes the create visible and requires exactly one format/filename/filepath/version match, a valid non-empty `slug_perm`, and a Cloudsmith SHA-256 equal to the original local file SHA-256. Replacement and deletion are classified independently as `PASS`, `INCONCLUSIVE`, or `FAIL`: an inconclusive replacement still proceeds to deletion after the original state is verified unchanged, while unexpected mutation fails immediately. Each denied or inconclusive operation is followed by an exact read proving the same `slug_perm`, version, filepath, filename, and original checksum remain. `slug_perm` is the sole package identifier used for deletion. Sacrificial publisher artifacts, including the artifact from run `33289502031`, remain in `omnilyzer/platform-spike` as evidence.

Each workflow starts with a pre-authentication gate that has only `contents: read`, has no OIDC authority, checks out full history without persisted credentials, validates `github.event.before` and `github.sha`, and classifies the complete net `before`-to-`after` Git diff. Only a one-file modification of the existing release trigger emits `release`; a one-file addition or modification of the respective permission trigger emits `permission`; all mixed, unrelated, removed, renamed, type-changed, or ambiguous states emit `none` and cannot enter a Cloudsmith job. The release and permission jobs alone receive job-scoped `id-token: write`. For every controlled rerun, the trigger commit must contain only its respective permission trigger file. The existing release triggers remain `0.8.1`.

Cloudsmith repository action thresholds and Self Privileges must be established through observed create, replace, delete, upload, and read behavior rather than inferred from `Read`, `Write`, or other labels. The provider caveat is that Generic `--republish` returns duplicate/existing-package `400` behavior for this restricted publisher rather than a permission-specific `403`, despite blocking the operation and preserving byte-identical state. No further live runs will attempt to force a `403` replacement response. Cloudsmith remains a validated candidate, not an **ACCEPTED DIRECTION**.

## Task 008B build/publish OIDC isolation

**TASK 008B PHASE 2 — PRE-LIVE / TO VALIDATE.** GitHub's `id-token: write` permission is job-scoped, so placing Cloudsmith authentication after build steps in one job does not prevent those earlier build steps from requesting GitHub OIDC credentials. The normal release path is therefore split into a `contents: read` build job with no ID-token authority and a dependent publisher job with `contents: read` plus `id-token: write`.

The build job prepares the coordinated release and builds all three releasable artifact types: the exact Python wheel, npm tarball, and final synthetic OCI image. It exports the already-built OCI image as a Docker image archive and records filenames, SHA-256 values, release version, source commit, archive format, expected local image reference, and expected OCI version label in a machine-readable manifest. Only the wheel, npm tarball, OCI image archive, and manifest cross the job boundary in a short-retention, run-unique GitHub Actions artifact. This is temporary transport of already-built immutable release artifacts, not a release registry or provenance mechanism.

The OIDC-enabled publisher does not build. It rejects unrelated handoff entries, verifies every manifest field and checksum, loads the already-built OCI archive, and inspects the expected local image reference and version label without executing the image. Only after those checks does it authenticate to Cloudsmith, publish Python and npm, retag and push the already-built OCI image, and resolve its registry digest. This preserves the broader Omnilyzer build-once principle. Sigstore/Cosign signing, SBOMs, and provenance are intentionally deferred to Phase 3. Cloudsmith remains a candidate release registry, not an accepted direction.

Task 008B still must validate:

- live validation of the Phase 2 build/publisher job isolation and handoff;
- Sigstore/Cosign keyless signing;
- signed release provenance;
- SBOM attachment and verification;
- vulnerability scanning and a policy gate;
- tamper/substitution failure;
- retention and rollback retrieval;
- provider operational, cost, and disaster-recovery findings.

## Recommendation

Task 008A and the Task 008B Phase 1 permission boundaries passed, with the documented Generic-republish provider caveat. Retain Cloudsmith as a validated candidate, not yet an **ACCEPTED DIRECTION**. Do not write ADR 0007 or change the package-registry/trusted-publishing decision from **TO VALIDATE** until the Phase 2 build/publish isolation is live-validated and later phases validate Sigstore/Cosign signatures, provenance, SBOMs, vulnerability scanning and policy, tamper/substitution rejection, retention and rollback, and provider operations/cost/disaster recovery.
