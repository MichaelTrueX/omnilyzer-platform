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

Until both GitHub-hosted workflows produce reviewed evidence, the outcome remains **PRE-LIVE / INCONCLUSIVE**.

## Security checks

The workflows grant only `contents: read` and `id-token: write`. Third-party actions are pinned to reviewed full commit SHAs, checkout persistence is disabled, build state stays under `RUNNER_TEMP`, npm lifecycle scripts are ignored, and the OCI fixture uses `FROM scratch` and is inspected rather than executed by the consumer. Docker authentication uses `password-stdin` and is followed by an unconditional cleanup step when login succeeded.

Cloudsmith trust is constrained to the private repository `MichaelTrueX/omnilyzer-platform`, `repository_visibility = private`, and these exact feature-branch workflow identities:

- Publisher: `MichaelTrueX/omnilyzer-platform/.github/workflows/task008-publish.yml@refs/heads/spike/008-supply-chain`
- Consumer: `MichaelTrueX/omnilyzer-platform/.github/workflows/task008-consume.yml@refs/heads/spike/008-supply-chain`

The provider is `https://token.actions.githubusercontent.com`. The publisher remains `Write`, not `Admin`; the consumer remains `Read`. Task 008A does not attempt deletion, replacement, or any consumer write operation.

## Test approach

The committed fixtures contain only the harmless placeholder `0.0.0`. `scripts/prepare_release.py` accepts a strict release version and a new absolute output directory outside the spike source, copies all mutable inputs there, coordinates the Python, npm, and OCI versions, and records expected artifact names. Standard-library unit tests verify valid `0.8.0`, malformed inputs, unsafe output use, coordinated versions, unchanged committed fixtures, exact workflow triggers and identities, action pins, credential policy, and ignored generated paths.

The temporary feature-branch push trigger paths are used because GitHub cannot dispatch a new `workflow_dispatch` workflow until that workflow exists on the default branch. Publication is isolated to changes to `control/publish.trigger`; consumption is isolated to `control/consume.trigger`. During the PRE-LIVE review state, neither trigger exists: the workflow implementation is committed and pushed first without causing a registry operation. Production workflows should use protected release refs and/or protected environments rather than this temporary spike branch.

The intended live sequence is:

1. Commit and push the workflow implementation without either trigger.
2. Have ChatGPT review that committed workflow implementation.
3. Add `publish.trigger` with the exact coordinated version in a separate reviewed commit.
4. Push that second commit to trigger the first live publisher run, then review its package identities, hashes, and OCI digest.
5. Intentionally add `consume.trigger` with that exact version in a later reviewed change.
6. Review independent read-only consumption of all three registry artifacts.

## Findings

**PRE-LIVE / INCONCLUSIVE.** Local tests can establish fixture coordination and static workflow policy only. No real GitHub Actions to Cloudsmith OIDC exchange, package publication, private resolution, permission enforcement, or provider behavior has yet been observed. No live evidence is claimed.

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

**PRE-LIVE / INCONCLUSIVE.** Retain Cloudsmith as a candidate only and run the staged publisher then consumer validation from the constrained GitHub feature-branch workflows. Do not write an acceptance ADR or change the package-registry/trusted-publishing decision from **TO VALIDATE** until live evidence and the remaining Task 008B controls have been reviewed.
