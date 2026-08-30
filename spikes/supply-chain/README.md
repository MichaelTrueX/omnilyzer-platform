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

The corrected publisher has now passed live validation, but until all three formats are independently consumed, the overall Task 008A outcome remains **INCONCLUSIVE / PUBLISHER PASS, CONSUMER PENDING**.

## Security checks

The workflows grant only `contents: read` and `id-token: write`. Third-party actions are pinned to reviewed full commit SHAs, checkout persistence is disabled, build state stays under `RUNNER_TEMP`, npm lifecycle scripts are ignored, and the OCI fixture uses `FROM scratch` and is inspected rather than executed by the consumer. Docker authentication uses `password-stdin` and is followed by an unconditional cleanup step when login succeeded.

Cloudsmith trust is constrained to the private repository `MichaelTrueX/omnilyzer-platform`, `repository_visibility = private`, and these exact feature-branch workflow identities:

- Publisher: `MichaelTrueX/omnilyzer-platform/.github/workflows/task008-publish.yml@refs/heads/spike/008-supply-chain`
- Consumer: `MichaelTrueX/omnilyzer-platform/.github/workflows/task008-consume.yml@refs/heads/spike/008-supply-chain`

The provider is `https://token.actions.githubusercontent.com`. The publisher remains `Write`, not `Admin`; the consumer remains `Read`. Task 008A does not attempt deletion, replacement, or any consumer write operation.

## Test approach

The committed fixture version metadata uses only the harmless placeholder `0.0.0`. The scratch OCI fixture also contains one harmless synthetic text artifact so its image has a real filesystem layer while remaining non-executable and base-image-free. `scripts/prepare_release.py` accepts a strict release version and a new absolute output directory outside the spike source, copies all mutable inputs there, coordinates the Python, npm, and OCI versions, and records expected artifact names. Standard-library unit tests verify valid coordinated versions, malformed inputs, unsafe output use, the layered scratch-image contract, unchanged committed fixtures, exact workflow triggers and identities, action pins, credential policy, and ignored generated paths.

The temporary feature-branch push trigger paths are used because GitHub cannot dispatch a new `workflow_dispatch` workflow until that workflow exists on the default branch. Publication is isolated to changes to `control/publish.trigger`; consumption is isolated to `control/consume.trigger`. The publisher trigger contains `0.8.1`; the consumer trigger remains absent. Production workflows should use protected release refs and/or protected environments rather than this temporary spike branch.

The remaining live sequence is:

1. Commit and push this documentation and test-state update without changing either trigger, so it triggers no workflow.
2. In a separate reviewed change, add `consume.trigger` containing exactly `0.8.1` plus a newline.
3. Push that change to trigger the read-only consumer.
4. Review independent Python, npm, and OCI retrieval.
5. Only then conclude Task 008A.

## Findings

**PUBLISHER LIVE VALIDATION: PASS.** The successful publisher retry ran from commit `f844573eb7c48e005ef4bc40e730a5b4982a3c40` in GitHub Actions run `33287331610` for release `0.8.1`.

Observed passes:

- The exact feature-branch/path publisher trigger worked.
- The GitHub OIDC to Cloudsmith exchange worked.
- The exact authenticated publisher identity `gha-publisher-u76y` was observed.
- Cloudsmith CLI `1.26.0` was installed and verified.
- Python `0.8.1` publication succeeded.
- npm `0.8.1` publication succeeded.
- Docker registry authentication succeeded.
- OCI `0.8.1` publication succeeded.
- The immutable OCI digest resolved to `sha256:614acfc6b461bbe279b7848f78d9fa0623bfabda9aa146864e2ec5d67b66a4ce`.
- The release record succeeded.
- Credentials remained masked in GitHub logs.
- Docker logout cleanup succeeded.

The overall Task 008A result remains **INCONCLUSIVE / PUBLISHER PASS, CONSUMER PENDING** because the separate read-only consumer has not yet run.

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

**INCONCLUSIVE / PUBLISHER PASS, CONSUMER PENDING.** Retain Cloudsmith as a candidate only. Run independent consumer validation for release `0.8.1` from the constrained GitHub feature-branch workflow. Cloudsmith is not yet an **ACCEPTED DIRECTION**; do not write ADR 0007 or change the package-registry/trusted-publishing decision from **TO VALIDATE** until complete live evidence and the remaining Task 008B controls have been reviewed.
