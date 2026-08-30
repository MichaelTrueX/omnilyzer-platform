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

The temporary feature-branch push trigger paths are used because GitHub cannot dispatch a new `workflow_dispatch` workflow until that workflow exists on the default branch. Publication is isolated to changes to `control/publish.trigger`; consumption is isolated to `control/consume.trigger`. The current release triggers contain `0.8.2`; the complete Task 008A evidence for `0.8.1` remains recorded below. Production workflows should use protected release refs and/or protected environments rather than this temporary spike branch.

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

Each workflow starts with a pre-authentication gate that has only `contents: read`, has no OIDC authority, checks out full history without persisted credentials, validates `github.event.before` and `github.sha`, and classifies the complete net `before`-to-`after` Git diff. Only a one-file modification of the existing release trigger emits `release`; a one-file addition or modification of the respective permission trigger emits `permission`; all mixed, unrelated, removed, renamed, type-changed, or ambiguous states emit `none` and cannot enter a Cloudsmith job. The release and permission jobs alone receive job-scoped `id-token: write`. For every controlled rerun, the trigger commit must contain only its respective permission trigger file. The existing release triggers now remain `0.8.2`.

Cloudsmith repository action thresholds and Self Privileges must be established through observed create, replace, delete, upload, and read behavior rather than inferred from `Read`, `Write`, or other labels. The provider caveat is that Generic `--republish` returns duplicate/existing-package `400` behavior for this restricted publisher rather than a permission-specific `403`, despite blocking the operation and preserving byte-identical state. No further live runs will attempt to force a `403` replacement response. Cloudsmith remains a validated candidate, not an **ACCEPTED DIRECTION**.

## Task 008B build/publish OIDC isolation

**TASK 008B PHASE 2 — PASS.** GitHub's `id-token: write` permission is job-scoped, so placing Cloudsmith authentication after build steps in one job does not prevent those earlier build steps from requesting GitHub OIDC credentials. The normal release path is therefore split into a `contents: read` build job with no ID-token authority and a dependent publisher job with `contents: read` plus `id-token: write`.

Publisher GitHub Actions run `33290748481`, from commit `90426cc0ce8f783c5a0bcd9b6d3b8cbc56e6f362`, published release `0.8.2`. Consumer run `33290873141`, from commit `97a428e7399c3713ac2e29eb1e32d5be59251fbc`, retrieved that exact release. All Python, npm, and OCI builds ran in the non-OIDC build job; the four-file CI handoff was verified before publisher authentication; publication of all three formats passed; and read-only exact retrieval passed. The publisher and consumer observed the same immutable OCI digest, `sha256:f02ed580970c3ade0eb679f95ec8cdacfdd69580a0680dcc9816be3c2aab09da`.

The build job prepares the coordinated release and builds all three releasable artifact types: the exact Python wheel, npm tarball, and final synthetic OCI image. It exports the already-built OCI image as a Docker image archive and records filenames, SHA-256 values, release version, source commit, archive format, expected local image reference, and expected OCI version label in a machine-readable manifest. Only the wheel, npm tarball, OCI image archive, and manifest cross the job boundary in a short-retention, run-unique GitHub Actions artifact. This is temporary transport of already-built immutable release artifacts, not a release registry or provenance mechanism.

The OIDC-enabled publisher does not build. It rejects unrelated handoff entries, verifies every manifest field and checksum, loads the already-built OCI archive, and inspects the expected local image reference and version label without executing the image. Only after those checks does it authenticate to Cloudsmith, publish Python and npm, retag and push the already-built OCI image, and resolve its registry digest. This preserves the broader Omnilyzer build-once principle. Cloudsmith remains a candidate release registry, not an accepted direction.

## Task 008B public signing, SBOM, and provenance

**TASK 008B PHASE 3 — PRE-LIVE / TO VALIDATE.** The non-OIDC build job now generates three CycloneDX JSON 1.6 SBOMs using Syft `1.51.0`: one from safely unpacked built-wheel contents, one from safely unpacked built-npm-tarball contents, and one from the already-built Docker image archive. Those SBOMs extend the temporary GitHub Actions handoff to exactly seven regular files. The OIDC publisher verifies all seven files and their hashes before authentication, then publishes the already-built artifacts, creates SLSA v1-formatted workload-generated provenance after resolving the immutable registry digest, and signs and immediately verifies the wheel, npm tarball, all SBOMs, provenance, evidence manifest, evidence archive, and exact OCI digest. This workload-generated statement is useful signed provenance; it does not itself establish SLSA Build L2, SLSA Build L3, reproducibility, or trusted control-plane provenance.

Phase 3 intentionally uses the **Sigstore Public Good** infrastructure with public transparency, as explicitly selected for this spike. No long-lived signing key or `COSIGN_PRIVATE_KEY` exists. Fulcio issues a short-lived certificate bound to the exact GitHub Actions publisher workflow identity, and Rekor makes the signing activity publicly auditable. Repository and workflow signing-identity metadata may therefore be public. Verification accepts only `https://github.com/MichaelTrueX/omnilyzer-platform/.github/workflows/task008-publish.yml@refs/heads/spike/008-supply-chain` from issuer `https://token.actions.githubusercontent.com`; it uses no wildcard identity, private-infrastructure mode, or transparency-log bypass.

The publisher packages exactly twelve non-secret metadata and Sigstore bundle files into a deterministic versioned evidence archive, signs that archive separately, and publishes only the archive and its bundle as filepath-oriented Cloudsmith Generic packages under `task008/evidence/<version>/` without republishing. The release wheel, npm tarball, and OCI archive are excluded from this evidence archive.

The OIDC-enabled consumer downloads the exact wheel and npm tarball without installation or import, pulls but never runs the OCI image, and retrieves the exact evidence archive and its separate signature bundle with the short-lived read-only Cloudsmith identity. Its authenticated Generic package lookup still requires one exact format/filename/filepath/version match, but credentials are sent only to the fixed `https://generic.cloudsmith.io/omnilyzer/platform-spike/` endpoint rather than a metadata-selected URL. The consumer verifies the archive signature before safe extraction, requires the exact twelve-file allowlist, verifies the evidence manifest and every direct blob/OCI signature against the exact identity and issuer, and validates all hashes, CycloneDX versions, SLSA statement fields, empty internal parameters, Git source dependency, immutable OCI digest, and the exact invocation ID derived from the signed run ID and attempt.

Only after every cryptographic and metadata check passes does that job upload an exact three-file, one-day GitHub Actions handoff containing the verified wheel, npm tarball, and a filename/checksum manifest. A dependent `execute-verified` job has `permissions: {}`, no checkout, OIDC, Cloudsmith, Cosign, Docker, or registry retrieval, revalidates the exact three-file handoff and both hashes, and only then installs and imports the local wheel and npm tarball with lifecycle scripts disabled. This is the sole release-code execution boundary. The order is therefore authenticated download, cryptographic verification, provenance/SBOM validation, immutable verified handoff, then unprivileged local code execution.

Task 008B still must validate:

- live validation of Phase 3 public Sigstore keyless signing;
- signed SLSA v1-formatted workload-generated provenance;
- CycloneDX SBOM publication and consumer verification;
- vulnerability scanning and a policy gate;
- tamper/substitution failure;
- retention and rollback retrieval;
- provider operational, cost, and disaster-recovery findings.

## Recommendation

Task 008A, the Task 008B Phase 1 permission boundaries, and the Phase 2 OIDC build isolation passed, with the documented Generic-republish provider caveat. Retain Cloudsmith as a **VALIDATED CANDIDATE**, not an **ACCEPTED DIRECTION**. Do not write ADR 0007 or change the package-registry/trusted-publishing decision from **TO VALIDATE** until Phase 3 and later work validate public Sigstore signatures, provenance, SBOMs, vulnerability scanning and policy, tamper/substitution rejection, retention and rollback, and provider operations/cost/disaster recovery.
