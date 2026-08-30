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

**PHASE 1 PRE-LIVE / TO VALIDATE.** The existing publisher and consumer workflows now contain isolated negative-permission probe jobs, but neither permission trigger exists and no live probe has run.

Planned negative evidence:

- the consumer `Read` identity cannot upload;
- the publisher `Write` identity can create;
- the publisher `Write` identity cannot republish or replace;
- the publisher `Write` identity cannot delete;
- all probes use disposable Generic artifacts under unique `GITHUB_RUN_ID`-derived filepaths and filenames;
- the validated Python, npm, and OCI release `0.8.1` is never mutated.

Cloudsmith Generic identity is the unique filepath and filename, not a separate package name. The consumer probe attempts only its unique sacrificial Generic upload, requires both a nonzero exit and recognizable authorization-denial output, then performs an authenticated JSON list and proves that no exact format/filename/filepath match was created. Any failure without explicit denial evidence is inconclusive and fails closed.

The publisher probe first creates one sacrificial Generic artifact and uses a small bounded list retry while Cloudsmith makes it visible. It requires exactly one format/filename/filepath match, a valid non-empty `slug_perm`, and a Cloudsmith SHA-256 equal to the original local file SHA-256. It then changes the local content and requires explicit authorization-denial evidence from `--republish`; the following read must show the same `slug_perm`, filepath, and original checksum. Deletion targets only that validated `slug_perm`, requires explicit authorization-denial evidence, and is followed by the same exact state and checksum verification. `slug_perm` is the sole package identifier used for the destructive-operation probe. Sacrificial publisher artifacts may remain in `omnilyzer/platform-spike` as evidence.

Each workflow starts with a pre-authentication gate that has only `contents: read`, has no OIDC authority, checks out full history without persisted credentials, validates `github.event.before` and `github.sha`, and classifies the complete net `before`-to-`after` Git diff. Only a one-file modification of the existing release trigger emits `release`; only a one-file addition of the respective permission trigger emits `permission`; all mixed, unrelated, removed, renamed, type-changed, or ambiguous states emit `none` and cannot enter a Cloudsmith job. The release and permission jobs alone receive job-scoped `id-token: write`. For the controlled live tests, each trigger commit must contain only its respective permission trigger file. The existing release triggers remain `0.8.1`.

Cloudsmith repository action thresholds and Self Privileges must be established through observed create, replace, delete, upload, and read behavior rather than inferred from `Read`, `Write`, or other labels. Cloudsmith remains a validated candidate, not an **ACCEPTED DIRECTION**.

Task 008B still must validate:

- separation of build and publisher jobs so build execution does not receive the job-scoped `id-token: write` permission;
- Sigstore/Cosign keyless signing;
- signed release provenance;
- SBOM attachment and verification;
- vulnerability scanning and a policy gate;
- tamper/substitution failure;
- publisher inability to replace or delete;
- consumer inability to publish;
- retention and rollback retrieval;
- provider operational, cost, and disaster-recovery findings.

## Recommendation

Task 008A passed. Retain Cloudsmith as a validated candidate, not yet an **ACCEPTED DIRECTION**, pending Task 008B. Do not write ADR 0007 or change the package-registry/trusted-publishing decision from **TO VALIDATE** until Task 008B has validated publisher inability to replace or delete, consumer inability to publish, Sigstore/Cosign signatures, provenance, SBOMs, vulnerability scanning and policy, tamper/substitution rejection, retention and rollback, provider operations/cost/disaster recovery, and build/publish job isolation.
