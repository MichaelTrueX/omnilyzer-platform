<!--
File: release/README.md
Purpose: Defines the production platform release control plane introduced by Task 013.
Related:
- docs/adr/0005-versioned-platform-packaging-and-distribution.md
- docs/adr/0006-immutable-oci-deployment-and-promotion.md
- docs/adr/0010-forgejo-and-zot-package-registries.md
- .github/workflows/platform-release.yml
-->

# Platform release control plane

Task 013 begins production release tooling. This directory is deliberately outside `spikes/`: it implements the reviewed coordinated-SemVer, immutable-digest, split-registry architecture from ADRs 0005, 0006, and 0010. Phase 1 completed code and local/policy validation. For Phase 2, the exact main-branch workflow identity was authorized in the DEV registries and `release/environments/dev.json` enables a separately reviewed DEV canary dispatch. This flag does not relax the repository, ref, source-SHA, package-identity, or registry-origin gates.

## Release lifecycle and trust boundaries

`platform-release.yml` accepts only a strict `X.Y.Z` version and the exact dispatched `main` SHA in `MichaelTrueX/omnilyzer-platform`. The committed release-plan template is materialized and checked with a closed schema, repository-confined source paths, fixed DEV origins, bounded package identities, fixed filenames, and pinned tool versions.

The `build` job is the sole build boundary. With `contents: read` and no OIDC authority it creates a wheel, npm tarball, executable OCI layout archive, CycloneDX 1.6 SBOMs, pinned-Grype results, and the deterministic build manifest. Docker Buildx 0.36.1 and BuildKit 0.24.0 are selected through commit-pinned actions; the BuildKit image and Python runtime base are digest-pinned. The short-retention Actions artifact is transport only: it is not a registry, provenance authority, or retention system. Each publisher downloads that handoff and verifies its exact file allowlist, version, source SHA, hashes, schema, identities, SBOM format, and vulnerability-policy PASS before it requests OIDC.

Only publisher jobs have `id-token: write`. They use short-lived GitHub OIDC and no long-lived registry or signing credential. The intended identity is exactly:

`MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main`

The zot publisher uploads the already-built OCI blobs and manifest directly, refuses a pre-existing tag, requires manifest publication HTTP 201, and proves both tag and exact-digest retrieval. The deployment identity recorded in the final manifest is `repository@sha256:...`, never the tag. Its future zot identity is limited to read/create, without update/delete.

After zot supplies and confirms the digest, the Forgejo publisher creates a custom, deterministic provenance statement and release manifest, signs evidence keylessly through Sigstore/Fulcio/Rekor, signs the exact OCI digest, and publishes the already-built wheel, npm tarball, and Generic evidence through `https://registry-dev.omnilyzer.ai`. That protected Nginx origin is the only Forgejo destination; no bypass address or workflow-selectable URL exists.

The final `release-manifest.json` binds schema and platform version, source SHA, wheel/npm identity and hash, OCI repository/tag and immutable digest, all SBOM hashes, the vulnerability-policy hash, provenance hash, and signing references. Registry-derived values are limited to the verified OCI digest. `release-provenance.json` intentionally states that it is build-once release evidence and does not assert a formal SLSA level.

## Vulnerability policy

`vulnerability-policy.json` carries forward the Task 008 semantics: Critical and High findings block a release. Exceptions must name an exact vulnerability, package, and version; include a reason; and have an explicit future ISO expiry date. Unknown fields, duplicates, malformed/expired exceptions, and wildcard-like identities fail closed. The release manifest binds the exact policy hash.

## Task 013 canary

Until real package boundaries are reviewed, the production engine is exercised with harmless sources under `fixtures/task013-canary/`:

- Python: `omnilyzer-release-canary`
- npm: `@omnilyzer/release-canary`
- OCI: `omnilyzer/task013-release-canary`

These are synthetic validation fixtures, not production APIs. Python and npm package validation does not import or install those packages. The OCI fixture is a deliberately executable Task 014 deployment canary, not Omnilyzer product code. It uses only the Python standard library and exposes `/livez`, `/readyz`, and `/metadata` on internal port 8080. `/readyz` requires a bounded runtime configuration identifier, an explicitly generated checksum-bound migration marker, and optional configured TCP dependency reachability. Startup never executes migration code.

The OCI image runs as UID/GID 10001, writes no application state, and supports a read-only root filesystem. Its explicit migration command writes only to a narrow runtime mount at `/run/omnilyzer-canary`, using an exclusive file lock and atomic owner-only marker replacement. The image embeds no credentials. The release version and source SHA are injected as build metadata, validated in the final OCI configuration, and returned by `/metadata`; neither is derived from a mutable tag.

The workflow builds the final OCI image exactly once and emits it directly as an OCI archive. A strict verifier checks every referenced blob digest and size, requires one linux/amd64 image, and enforces the reviewed non-root user, entrypoint, port, labels, and release metadata before Syft and Grype scan that same archive. Existing zot publication, exact-digest readback, Sigstore, provenance, and Forgejo package publication remain downstream of the immutable handoff.

The engine continues to derive identities and source paths from the validated plan rather than hard-coding canary names in its generic plan/handoff logic. Future packages plug in by adding reviewed repository-relative source paths, bounded registry identities, and filenames to a committed plan that satisfies the same closed contract.

For an offline deterministic check (which creates explicitly synthetic local scanner evidence because Syft/Grype need not be installed):

```bash
tmp_dir="$(mktemp -d)"
python3 -m release.release_plan materialize \
  release/fixtures/task013-canary/release-plan-template.json 0.1.0 \
  f2575b9a90c0f3a03ec0730c2a5ff7fea1ed17e5 "$tmp_dir/plan.json"
python3 -m release.build_release local-canary --plan "$tmp_dir/plan.json" \
  --output "$tmp_dir/handoff" --policy release/vulnerability-policy.json \
  --evaluation-date 2026-09-04
python3 -m release.verify_handoff --handoff "$tmp_dir/handoff" \
  --expected-version 0.1.0 \
  --expected-sha f2575b9a90c0f3a03ec0730c2a5ff7fea1ed17e5
```

Publishers explicitly reject this local evidence mode. It uses a deterministic synthetic OCI layout and does not validate the Docker-built runtime image. A workflow handoff must contain the contract-checked executable OCI archive plus SBOM and vulnerability evidence produced by the reviewed pinned Syft and Grype versions.

## Phase 1 non-claims

Phase 1 did not prove live publishing. Phase 2 enables only the reviewed DEV canary path; until its live run succeeds, it establishes no live round-trip result. Neither phase proves actual production package boundaries, PROD registry deployment, product consumption, or DEV-to-STAGING-to-PROD promotion. Those remain later acceptance work.
