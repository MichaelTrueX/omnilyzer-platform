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

The temporary feature-branch push trigger paths are used because GitHub cannot dispatch a new `workflow_dispatch` workflow until that workflow exists on the default branch. Publication is isolated to changes to `control/publish.trigger`; consumption is isolated to `control/consume.trigger`. The current release triggers contain `0.8.3`; the complete Task 008A evidence for `0.8.1` remains recorded below. Production workflows should use protected release refs and/or protected environments rather than this temporary spike branch.

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

Each workflow starts with a pre-authentication gate that has only `contents: read`, has no OIDC authority, checks out full history without persisted credentials, validates `github.event.before` and `github.sha`, and classifies the complete net `before`-to-`after` Git diff. Only a one-file modification of the existing release trigger emits `release`; a one-file addition or modification of the respective permission trigger emits `permission`; all mixed, unrelated, removed, renamed, type-changed, or ambiguous states emit `none` and cannot enter a Cloudsmith job. The release and permission jobs alone receive job-scoped `id-token: write`. For every controlled rerun, the trigger commit must contain only its respective permission trigger file. The existing release triggers now remain `0.8.3`.

Cloudsmith repository action thresholds and Self Privileges must be established through observed create, replace, delete, upload, and read behavior rather than inferred from `Read`, `Write`, or other labels. The provider caveat is that Generic `--republish` returns duplicate/existing-package `400` behavior for this restricted publisher rather than a permission-specific `403`, despite blocking the operation and preserving byte-identical state. No further live runs will attempt to force a `403` replacement response. Cloudsmith remains a validated candidate, not an **ACCEPTED DIRECTION**.

## Task 008B build/publish OIDC isolation

**TASK 008B PHASE 2 — PASS.** GitHub's `id-token: write` permission is job-scoped, so placing Cloudsmith authentication after build steps in one job does not prevent those earlier build steps from requesting GitHub OIDC credentials. The normal release path is therefore split into a `contents: read` build job with no ID-token authority and a dependent publisher job with `contents: read` plus `id-token: write`.

Publisher GitHub Actions run `33290748481`, from commit `90426cc0ce8f783c5a0bcd9b6d3b8cbc56e6f362`, published release `0.8.2`. Consumer run `33290873141`, from commit `97a428e7399c3713ac2e29eb1e32d5be59251fbc`, retrieved that exact release. All Python, npm, and OCI builds ran in the non-OIDC build job; the four-file CI handoff was verified before publisher authentication; publication of all three formats passed; and read-only exact retrieval passed. The publisher and consumer observed the same immutable OCI digest, `sha256:f02ed580970c3ade0eb679f95ec8cdacfdd69580a0680dcc9816be3c2aab09da`.

The build job prepares the coordinated release and builds all three releasable artifact types: the exact Python wheel, npm tarball, and final synthetic OCI image. It exports the already-built OCI image as a Docker image archive and records filenames, SHA-256 values, release version, source commit, archive format, expected local image reference, and expected OCI version label in a machine-readable manifest. Only the wheel, npm tarball, OCI image archive, and manifest cross the job boundary in a short-retention, run-unique GitHub Actions artifact. This is temporary transport of already-built immutable release artifacts, not a release registry or provenance mechanism.

The OIDC-enabled publisher does not build. It rejects unrelated handoff entries, verifies every manifest field and checksum, loads the already-built OCI archive, and inspects the expected local image reference and version label without executing the image. Only after those checks does it authenticate to Cloudsmith, publish Python and npm, retag and push the already-built OCI image, and resolve its registry digest. This preserves the broader Omnilyzer build-once principle. Cloudsmith remains a candidate release registry, not an accepted direction.

## Task 008B public signing, SBOM, and provenance

**TASK 008B PHASE 3 — PASS.** Publisher GitHub Actions run `33292673187`, from commit `38d732ee808a22c1301018593d4c03cf3d957144`, published release `0.8.3`. The build job had no OIDC authority and was the only job that built Python, npm, and OCI. Syft `1.51.0` generated three CycloneDX JSON 1.6 SBOMs. The exact seven-file handoff was verified before publisher authentication as the Cloudsmith OIDC identity `gha-publisher-u76y`.

Publisher artifact and SBOM evidence:

- Python wheel SHA-256: `48ddc7e892f12fc5ba3ff302c52f667bb2abc548669b51cbc15d13b72854c6c6`.
- npm tarball SHA-256: `a69787acebd40f0f185f0b14beeadbfa1c4551c72d872d49628313e83b110399`.
- OCI Docker archive SHA-256: `046b1258b7c1ee1046e60a47f9e62cdb82b4cb6e55ba30ce969d9faf220d7f46`.
- Immutable OCI registry digest: `sha256:e60e4679a53ac144b529139fdfacc1933e1d530ade07327b19b1f8a822460406`.
- Python SBOM SHA-256: `4b7b03b2873174c6c207879479996d6eb27cb11c17d2c6d51d6720c7b8c8ae03`.
- npm SBOM SHA-256: `c3ca0f9cf6b03b3014cad14af566215a797ea53edefe6c933ce2cd0afbb62a27`.
- OCI SBOM SHA-256: `d5e7fece098d5f6cc15513c60c678799d896a92792151193aba8c4321cf5ed73`.

Python, npm, and OCI `0.8.3` publication succeeded, and the immutable OCI registry digest was resolved. The publisher created SLSA v1-formatted workload-generated provenance. Cosign `3.1.2` keylessly signed the six primary blobs and the immutable OCI digest, and immediately verified every signature against the exact workflow identity `https://github.com/MichaelTrueX/omnilyzer-platform/.github/workflows/task008-publish.yml@refs/heads/spike/008-supply-chain` and OIDC issuer `https://token.actions.githubusercontent.com`. Public Sigstore, Fulcio, and Rekor transparency-log verification succeeded. No persistent signing key was used.

The evidence manifest was signed and verified. Its deterministic twelve-file evidence archive was also signed and verified, then the archive and its external Sigstore bundle were published to Cloudsmith Generic. Docker logout succeeded.

Phase 3 intentionally uses the **Sigstore Public Good** infrastructure with public transparency, as explicitly selected for this spike. No long-lived signing key or `COSIGN_PRIVATE_KEY` exists. Fulcio issues a short-lived certificate bound to the exact GitHub Actions publisher workflow identity, and Rekor makes the signing activity publicly auditable. Repository and workflow signing-identity metadata may therefore be public. Verification accepts only `https://github.com/MichaelTrueX/omnilyzer-platform/.github/workflows/task008-publish.yml@refs/heads/spike/008-supply-chain` from issuer `https://token.actions.githubusercontent.com`; it uses no wildcard identity, private-infrastructure mode, or transparency-log bypass.

The publisher packages exactly twelve non-secret metadata and Sigstore bundle files into a deterministic versioned evidence archive, signs that archive separately, and publishes only the archive and its bundle as filepath-oriented Cloudsmith Generic packages under `task008/evidence/<version>/` without republishing. The release wheel, npm tarball, and OCI archive are excluded from this evidence archive.

Consumer GitHub Actions run `33292816649`, from commit `5cc565eaddc047f050a544f668b085d37cc5ee7b`, validated release `0.8.3` using the short-lived, read-only Cloudsmith OIDC identity `gha-consumer`. It downloaded the exact Python wheel and npm tarball without installing or executing either. It pulled and inspected OCI `0.8.3` without running it, and the digest exactly matched the publisher digest: `sha256:e60e4679a53ac144b529139fdfacc1933e1d530ade07327b19b1f8a822460406`. Consumer Docker logout succeeded.

The consumer retrieved the exact Generic evidence archive and external bundle, verified the archive signature before extraction, and safely extracted the exact twelve-file allowlist. It verified the evidence-manifest signature; matched the wheel, npm, and OCI hashes to the signed evidence; validated all three CycloneDX 1.6 SBOMs and the SLSA v1-formatted workload-generated provenance; and validated the publisher Git SHA, workflow/ref, and run-ID/run-attempt invocation ID. It independently verified all six blob signatures and the OCI signature against the immutable digest, including Rekor/transparency evidence.

Only after every check passed did the consumer create the exact three-file verified execution handoff containing the wheel, npm tarball, and manifest.

The dependent `execute-verified` job passed with only GitHub's `Metadata: read` baseline shown in its job permissions. It had no `id-token` permission, no `contents` permission, no Cloudsmith authentication, no `CLOUDSMITH_API_KEY`, no checkout, no Docker, no Cosign, and no package-registry retrieval. It downloaded the same-run verified handoff, required exactly the three expected files, and revalidated the wheel and npm tarball SHA-256 values from the manifest.

Python execution used only the local wheel with `pip --no-index --no-deps`; `report()` returned `0.8.3`, so the Python check passed. npm execution used only the local tarball with `--ignore-scripts`, `--no-audit`, and `--no-fund`; `report()` returned `0.8.3`, so the npm check passed. OCI remained inspection-only throughout. This preserves the execution order: authenticated retrieval, cryptographic verification, provenance and SBOM validation, immutable verified handoff, then non-OIDC local code execution.

## Task 008B vulnerability policy gate

**TASK 008B PHASE 4A — PASS.** Publisher GitHub Actions run `33294828516` and consumer run `33295062156` validated release `0.8.4`, including immutable OCI digest `sha256:44cdf2855105c824fcad999723ed7cc4f4a0ba276c8b953882413a1c61004967`. The validated release gate installs Grype `0.118.0` only in the non-OIDC build job through the pinned `anchore/scan-action/download-grype` sub-action. It verifies the exact CLI version, explicitly updates the public Grype vulnerability database once, captures sanitized non-secret database identity/status metadata, disables automatic updates for the scans, and scans exactly the three already-built CycloneDX 1.6 SBOMs in explicit `sbom:` input mode. It does not recatalog source, pull an OCI image, or execute release artifacts.

The initial version-controlled policy is:

- Critical: **BLOCK**.
- High: **BLOCK**.
- Medium: report.
- Low: report.
- Negligible: report.
- Unknown: report.

The standard-library Python evaluator receives the current UTC date explicitly, validates all policy, database-status, and Grype result structures, and emits deterministic newline-terminated JSON evidence. A policy exception must identify the exact vulnerability ID, package name, and installed package version; include a non-empty rationale; and have a mandatory canonical `YYYY-MM-DD` expiry date in the future. Expired, duplicate, malformed, unknown-field, wildcard, and regex-like exceptions fail closed. No exceptions are currently configured.

A BLOCK decision returns nonzero inside the build job before handoff-manifest creation and upload. The dependent publisher therefore cannot start, request its OIDC token, authenticate to Cloudsmith, publish artifacts, or sign release evidence. A PASS expands the exact same-run build handoff from seven to twelve files with three Grype JSON reports, sanitized Grype DB status, and the policy result. The handoff records hashes for all five files, Grype `0.118.0`, and the vulnerability-policy SHA-256. The publisher still performs no checkout, build, or scan; its pre-OIDC verifier independently binds the handoff policy SHA to the reviewed hash embedded in the workflow source.

The five vulnerability evidence files are not individually signed. Their hashes are incorporated into the signed evidence manifest, and the files are covered by both the evidence-manifest signature and deterministic evidence-archive signature. The archive allowlist contains exactly seventeen files, without including the policy source, Grype binary/database, runner cache, credentials, repository source, package artifacts, or OCI archive.

The OIDC consumer verifies the signed vulnerability report, database-status, and policy-result hashes; scanner version; exact Critical/High blocking policy; PASS decision; policy binding; structurally valid severity counts; and absence of blocking findings before it can create the existing exact three-file execution handoff. It does not rerun Grype. The `execute-verified` job remains `permissions: {}` and receives only the verified wheel, npm tarball, and execution manifest; it receives no scanner, database, or vulnerability evidence.

## Task 008B tamper and substitution negative validation

**TASK 008B PHASE 4B — PASS.** GitHub Actions run `33300180268`, triggered by commit `c628e4c149ab288b74960fb9db8cf92885691ffc`, completed the live tamper and substitution negative validation against known-good release `0.8.4` and immutable OCI digest `sha256:44cdf2855105c824fcad999723ed7cc4f4a0ba276c8b953882413a1c61004967`.

The run demonstrated the intended job isolation: `gate` passed and `tamper-negative-probe` passed, while normal `consume`, `execute-verified`, and `consumer-permission-probe` were skipped. The probe authenticated only through the short-lived, read-only Cloudsmith OIDC identity `gha-consumer`. It performed no repository checkout, had no `gha-publisher` identity, and performed no publication, signing of attacker-controlled content, Docker execution, artifact upload, `pip install`, or `npm install`. GitHub displayed only the `Metadata: read` token baseline. No tampered content executed, and the legitimate registry release `0.8.4` remained unchanged.

The four live negative cases passed as follows:

1. **Tampered signed evidence archive — PASS, attack rejected before extraction.** A temporary copy of the legitimate signed evidence archive was modified and checked with its legitimate external Sigstore bundle. Cosign returned nonzero as required, the expected-failure guard would have failed the workflow on an unexpected zero result, and the tampered archive was never extracted.
2. **Tampered Python wheel — PASS, attack rejected.** A temporary copy of the legitimate `0.8.4` wheel was modified and checked with the legitimate publisher-created `python-wheel.sigstore.json` bundle. Cosign returned nonzero as required, and no accepted execution handoff was created.
3. **Release-version substitution — PASS, substitution rejected.** The legitimate evidence archive and signed evidence manifest were first verified against the exact publisher workflow identity and OIDC issuer. Presenting that valid signed `0.8.4` evidence as requested version `0.8.5` then failed the signed `release_version` binding with `signed release_version rejects substituted release material`.
4. **Mutated verified-execution handoff — PASS, mutation rejected before execution.** An exact three-file candidate handoff was created and its hashes were proven valid before its wheel was modified after manifest creation. The checksum-validation semantics used by `execute-verified` rejected it with `verified wheel checksum mismatch`; no execution environment file was produced, and no package was installed or executed.

## Task 008B registry-only retention and rollback validation

The fully verified reference release is `0.8.5`. Publisher run `33300665806`, from commit `431c984d3c3e81f358c0653d8d8d4041a31883e3`, and consumer run `33300905736`, from commit `d608ec5ebd5b85b9f17ef340b648538c14a7a362`, validated immutable OCI digest `sha256:b01299d6afe9f635a567347cc7617876ab90c024e1bfe644d71097eadcc184d1`.

**TASK 008B PHASE 5 — ROLLBACK PASS / FINAL RETENTION PROOF PENDING.** GitHub Actions run `33301708289`, triggered by commit `5a19ab456891e2a15aa0694bb2f74d8674dc2b09`, completed the first live registry-only rollback validation. The explicit state remained **CURRENT = `0.8.5`** and **ROLLBACK TARGET = `0.8.4`**. The historical OCI image resolved to the reviewed immutable digest `sha256:44cdf2855105c824fcad999723ed7cc4f4a0ba276c8b953882413a1c61004967`.

The live job isolation passed: `gate` and `rollback-retention-probe` passed, while normal `consume`, `execute-verified`, `tamper-negative-probe`, and `consumer-permission-probe` were skipped. The probe authenticated only as the short-lived, read-only Cloudsmith OIDC identity `gha-consumer`. It retrieved the exact Python `0.8.4` wheel and npm `0.8.4` tarball from Cloudsmith, pulled OCI `0.8.4` without running it, and resolved it to the exact reviewed digest. It retrieved the exact versioned `0.8.4` evidence archive from Cloudsmith Generic and its external Sigstore bundle, verified the archive signature before extraction, safely extracted exactly seventeen regular evidence files, and verified the evidence-manifest signature.

The probe validated the artifact hashes; all three hash-bound CycloneDX JSON 1.6 SBOMs; Grype `0.118.0` evidence; the exact vulnerability-policy SHA, PASS decision, Critical/High blocking policy, and absence of blocking findings; and the SLSA v1-formatted workload-generated provenance, including publisher run/source binding and subjects for the retrieved wheel, npm tarball, and exact OCI digest. It verified all six blob signatures and the immutable OCI digest signature against the exact publisher identity and issuer with transparency-log verification enabled. Docker logout succeeded.

No historical GitHub Actions artifact was retrieved, and the rollback probe did not use `actions/download-artifact`. No rebuild, republish, floating version selection, verified-execution handoff, package installation, or rollback-artifact execution occurred.

GitHub Actions release handoffs remain intentionally transient same-run trust-boundary transport with one-day retention; they are not the durable release archive. This first registry-only rollback verification passed while historical one-day GitHub Actions artifacts may still exist. Because the probe has no dependency on those artifacts, the **ROLLBACK** and **REGISTRY-ONLY ARCHITECTURE** classifications are **PASS**. **POST-CI-ARTIFACT-EXPIRY RETENTION VALIDATION remains PENDING**: a second live execution after the relevant one-day artifacts have actually expired is still required for the strongest empirical retention evidence.

Remaining Task 008 work:

- post-one-day-artifact-expiry retention rerun;
- provider operations, cost, and disaster-recovery analysis;
- the final Cloudsmith architecture decision;
- ADR 0007 only after all evidence is reviewed.

## Recommendation

Task 008A and Task 008B Phases 1, 2, 3, 4A, and 4B passed; the Phase 5 rollback and registry-only architecture checks passed, with final post-expiry retention proof pending. The documented Generic-republish provider caveat remains. Cloudsmith remains a **VALIDATED CANDIDATE**, **NOT ACCEPTED DIRECTION**. Task 008 is not complete. Do not write ADR 0007 or make the final package-registry/trusted-publishing architecture decision until all Task 008 evidence is reviewed.
