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

The final `release-manifest.json` binds schema and platform version, source SHA, wheel/npm identity and hash, OCI repository/tag and immutable digest, all SBOM hashes, the vulnerability-policy hash, provenance hash, and signing references. Registry-derived values are limited to the verified OCI digest. Evidence schema 2 adds a closed `execution` object to `release-provenance.json`: exact GitHub repository name and numeric ID, approved workflow ref, workflow SHA, positive run ID and attempt, `workflow_dispatch` event, and source commit. The reviewed Forgejo publisher passes these GitHub context values before both evidence blobs are signed. The workflow SHA must equal the dispatched source commit. Manifest schema 2 hashes the exact provenance bytes. Earlier schema 1 evidence remains published history but is ineligible for Task 014 promotion. The provenance still states that it is build-once release evidence and does not assert a formal SLSA level.

## Vulnerability policy

`vulnerability-policy.json` carries forward the Task 008 semantics: Critical and High findings block a release. Exceptions must name an exact vulnerability, package, and version; include a reason; and have an explicit future ISO expiry date. Unknown fields, duplicates, malformed/expired exceptions, and wildcard-like identities fail closed. The release manifest binds the exact policy hash.

Before policy evaluation, the build creates a separate, owner-only diagnostic directory containing a canonical artifact identity and only the reviewed SBOM, Grype, sanitized database, and policy files. A policy denial remains a failed build and skips finalization, publisher OIDC, and publication, but a failure-only Actions artifact retains those diagnostics and the generated blocked-findings result. Publishers reference only the successful immutable handoff artifact; denial evidence is never publication or promotion input.

## Task 013 canary

Until real package boundaries are reviewed, the production engine is exercised with harmless sources under `fixtures/task013-canary/`:

- Python: `omnilyzer-release-canary`
- npm: `@omnilyzer/release-canary`
- OCI: `omnilyzer/task013-release-canary`

These are synthetic validation fixtures, not production APIs. Python and npm package validation does not import or install those packages. The OCI fixture is a deliberately executable Task 014 deployment canary, not Omnilyzer product code. It uses only the Python standard library and exposes `/livez`, `/readyz`, and `/metadata` on internal port 8080. `/readyz` requires a bounded runtime configuration identifier, an explicitly generated checksum-bound migration marker, and optional configured TCP dependency reachability. Startup never executes migration code.

The OCI image runs as UID/GID 10001, writes no application state, and supports a read-only root filesystem. Its explicit migration command writes only to a narrow runtime mount at `/run/omnilyzer-canary`, using an exclusive file lock and atomic owner-only marker replacement. The image embeds no credentials. The release version and source SHA are injected as build metadata, validated in the final OCI configuration, and returned by `/metadata`; neither is derived from a mutable tag.

The Task 014 synthetic canary uses `cgr.dev/chainguard/python@sha256:bbdc4d1e20995d9bb9f9935188844c824b40969de4bb1f0eaadacda4c8d4121e`, the separately qualified linux/amd64 manifest containing Python 3.14.7. Its shell-less Dockerfile has no `RUN` instructions or package installation. The executable command is `["/usr/bin/python", "/app/canary_runtime.py"]`; explicit migration uses `/usr/bin/python /app/migration.py` with the container entrypoint overridden. Numeric `USER 10001:10001` and COPY ownership override the supplier's default UID 65532. Removing shell-form build-argument checks does not remove release identity validation: the release plan supplies the expected identity and the post-build OCI verifier rejects missing, empty, or mismatched version, source SHA, repository/title, and required environment metadata before scanning or publication.

Read-only qualification on 2026-09-07 verified anonymous exact-digest access, stable discovery-tag resolution, and the supplier signature and signed SPDX attestation with Cosign 3.1.2 (Fulcio certificate, SCT, and Rekor transparency verification). The required issuer was `https://token.actions.githubusercontent.com` and identity was `https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`. Grype 0.118.0 and the unchanged Critical/High policy passed with zero Critical/High findings and no exceptions. The report SHA-256 was `42ff39886c1569bc62b823717d1c63b2f5a43a77e5419ffd652dd30ae491b5ee`; policy SHA-256 was `475ad38ef4ae8d89dcf7d4e03eeb76701085fdcd4ebdb8ae9aa41a7bce2cde8f`. The valid DB was schema `v6.1.9`, built `2026-09-07T06:38:20Z`, checksum `sha256:73fb33bdf73a355ff5d4e6d86cb3671ced44437d1579524d8d7874c93ba23a44`. Supplier verification is qualification provenance, not a new per-release workflow step; each final canary still passes the existing SBOM/Grype/policy gates.

Chainguard Free provides no sufficient old-digest retention guarantee. Task 014 accepts this risk only because the build uses the exact reviewed manifest and must fail if it becomes unavailable, with no mutable-tag fallback. After successful release, the final Omnilyzer OCI image is retained in zot; DEV/STAGING/PROD promotion uses that final digest without rebuilding from the supplier base. This does not claim independently reproducible future rebuilds or enable deployment environments. Production base retention requires separate mirroring, versioned-supplier, or other retention review; no mirroring is implemented here. This qualification selects neither the production Django/Python base nor a general Chainguard/Wolfi platform direction, and does not change ADR 0001. Release `0.14.2` is reserved for separate authorization after this change merges; `0.14.0` and `0.14.1` must not be reused.

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
