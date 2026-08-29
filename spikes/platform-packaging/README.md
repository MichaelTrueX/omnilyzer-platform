# Platform packaging spike

## Hypothesis and model

Omnilyzer can release shared capabilities from this repository as immutable, standard package artifacts. A coordinated platform release set gives all shared packages one SemVer version; products pin an exact release and adopt it independently. The fixtures prove Alpha can remain on 1.0.0 while Beta uses 1.1.0, without copying platform source. Package names and tiny APIs are representative packaging fixtures, not a final production package decomposition.

Each 1.0.0 or 1.1.0 release contains a PEP 517/518 pure-Python wheel (`omnilyzer-platform-core`, Hatchling backend) and two ESM npm tarballs (`@omnilyzer/platform-web-contract` and `@omnilyzer/design-governance`). Python requires 3.12 or newer; npm packages declare Node `>=24.15.0 <25`. Validation uses the installed Python 3.12 patch release, Node 24.20.0, `build==1.6.0`, and `hatchling==1.32.0`; the results record exact observed versions.

## Evidence produced

For each coordinated release, a deterministic manifest identifies all three artifacts, their exact package versions and formats, artifact SHA-256, deterministic source-tree SHA-256, and build runtime/tool identity. Two controlled builds must produce byte-identical wheels, tarballs, and manifests. Archive allowlists reject traversal, source paths, tests, caches, credentials, environment files, keys, unexpected files, lifecycle scripts, and runtime dependencies. A one-byte mutation must fail manifest verification.

Consumers are copied beneath `/tmp/omnilyzer-platform-packaging`, as are the artifacts that substitute for a future registry. Each backend uses a clean virtual environment and `pip --no-index`; each frontend installs exact `.tgz` files with npm `--offline --ignore-scripts`, creates lockfile integrity data, and receives real `node_modules` directories rather than links. Source-reference scanning prohibits copied platform implementation. Python exports only its declared top-level API, while npm `exports` blocks private deep imports.

Alpha starts on exact 1.0.0 pins, upgrades all selected packages to 1.1.0 without source changes, and rolls back to 1.0.0. Beta uses additive 1.1.0 APIs, so a package-only downgrade to 1.0.0 intentionally fails. Once product code adopts a new API, rollback generally requires restoring the product commit and exact package pins together. Products may consume a subset, but every selected platform artifact must share the same release version; a mixed set is rejected before execution.

The same-major gate preserves public APIs, command names, baseline governance behavior, and baseline consumers. It rejects a simulated 1.1.0 API removal while allowing a simulated 2.0.0 to declare a break. The installed `omnilyzer-semantic-lint` accepts compliant frontend fixtures and rejects hard-coded colors, color functions, raw Tailwind palettes, arbitrary bracket styling, and inline React styles. It never calls Task 005 or release-source scripts.

## Run

From this directory:

```bash
python3 scripts/run_validation.py
```

Generated wheels, tarballs, virtual environments, product copies, Node runtimes, and tooling environments are temporary or ignored. The local artifact repository is only a registry-neutral spike substitute, not a recommendation for manual production copying. The intended direction is platform source → versioned immutable artifacts → private registry/release service → exact product dependency pin → product CI.

## Scope and limitations

This spike validates standard package boundaries, exact independent adoption, deterministic integrity hashes, source-to-artifact traceability, compatibility policy, and package-level upgrade/rollback mechanics. A SHA-256 manifest is integrity evidence, not a trusted signature; it does not prove authenticity.

Task 006 does **not** validate registry credentials, authentication/authorization, availability, retention, replication, disaster recovery, organization billing, GitHub Packages, private PyPI, an npm private registry, or registry-specific provenance. It also does not validate signed provenance, Sigstore, SLSA attestations, trusted publishing, a protected signing identity, production CI, real product repositories, Django reusable-app behavior, React component packaging, database migrations, independent package versioning, large dependency graphs, or very large fleets.

