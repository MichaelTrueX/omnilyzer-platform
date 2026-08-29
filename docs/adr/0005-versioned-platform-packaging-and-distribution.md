# ADR 0005: Versioned Platform Packaging and Independent Product Adoption

- Status: Accepted
- Date: 2026-08-29

## Context

Omnilyzer products must remain independent repositories while consuming reusable capabilities owned by the independent `omnilyzer-platform` repository. Products need explicit, testable upgrades and compatible rollback without copying or synchronizing platform implementation source.

Task 006 validated:

- standard pure-Python wheel distribution;
- standard npm `.tgz` distribution;
- Python PEP 517/518 packaging;
- exact product version pins;
- coordinated platform releases 1.0.0 and 1.1.0;
- different products simultaneously consuming different releases;
- deterministic artifacts and deterministic release manifests;
- artifact SHA-256 and deterministic source-tree SHA-256;
- archive allowlists and security inspection;
- artifact tamper rejection;
- public/private package boundaries;
- SemVer compatibility gates;
- unchanged-code Product Alpha upgrade and rollback from 1.0.0 to 1.1.0 to 1.0.0;
- Product Beta dependency-only downgrade failure after adopting 1.1.0 APIs;
- mixed coordinated-release rejection;
- installed design-governance package execution;
- product execution outside the platform repository;
- no source-copy dependency mechanism.

Reference evidence:

- [`spikes/platform-packaging/README.md`](../../spikes/platform-packaging/README.md)
- [`platform-packaging-validation.md`](../../spikes/platform-packaging/results/platform-packaging-validation.md)

## Decision

1. Shared platform capabilities are authored in the independent `omnilyzer-platform` repository.
2. Product repositories consume built, versioned package artifacts rather than copied platform source.
3. Python platform capabilities use standard Python package artifacts, primarily wheels.
4. JavaScript and design-system capabilities use standard npm package artifacts.
5. Custom Omnilyzer package formats are not required.
6. Products must pin explicit platform versions.
7. Product platform dependencies must not use floating `latest`, wildcards, unbounded compatible ranges, Git HEAD, workspace links, or direct platform-source links as the production adoption mechanism.
8. Omnilyzer initially uses a coordinated platform release-set model.
9. Packages belonging to one platform release set carry the same SemVer version.
10. Products may consume only the subset of platform packages they require, but platform packages selected for one coordinated release must come from the same release set.
11. Arbitrary mixing of package versions from different coordinated platform releases is not initially supported.
12. Different product repositories may remain on different platform releases simultaneously.
13. No global platform upgrade is required merely because a newer platform release exists.
14. Platform release versions use SemVer `MAJOR.MINOR.PATCH`.
15. PATCH releases preserve public compatibility.
16. MINOR releases may add public capabilities but preserve previously valid same-major public contracts.
17. MAJOR releases may intentionally introduce breaking public-contract changes.
18. Public-contract compatibility must be machine-testable where practical.
19. Governance behavior forming part of a product contract must not silently become incompatible within the same major release.
20. Product upgrades occur through explicit dependency changes, product CI, review, and staged release, not source synchronization.
21. Built platform artifacts should be immutable once released.
22. Release metadata must identify artifact package name, package version, artifact filename and type, artifact hash, source-tree hash, and relevant build-tool and runtime identity.
23. Deterministic builds are an architectural goal for platform packages.
24. Rebuilding the same package source with the same controlled toolchain should produce identical distributable artifacts where supported.
25. SHA-256 artifact hashes provide integrity verification.
26. Deterministic source-tree hashes provide source-to-artifact traceability evidence.
27. These hashes do not constitute trusted signatures, publisher identity, or cryptographic provenance.
28. Signed provenance, trusted publishing, Sigstore/SLSA-style attestations, and protected release identity remain **TO VALIDATE**.
29. Package archives must be inspectable and constrained to expected runtime files and package metadata.
30. Package artifacts must not contain repository paths, credentials, private keys, `.env`, VCS data, build caches, or traversal paths.
31. Platform package installation must not depend on lifecycle install scripts unless a future justified ADR permits them.
32. Product consumers must resolve installed package code from their dependency environment, not from the platform source repository.
33. Public/private package boundaries should be enforced technically where the packaging ecosystem permits it.
34. npm packages should use explicit `exports` boundaries.
35. Python package public APIs should be deliberately exported and contract-tested.
36. Shared design governance is itself a distributable, versioned platform capability.
37. Product repositories must receive governance through supported package distribution rather than copying lint implementation from the platform repository.
38. Package rollback is supported when product code remains compatible with the older platform contract.
39. Package rollback alone is not guaranteed after product code adopts APIs introduced by a newer platform release.
40. In that case, rollback normally restores the compatible product revision and its exact platform pins together.
41. A package release mechanism must support multiple retained platform versions so different products can upgrade independently and roll back where compatible.
42. Production platform distribution should eventually use a controlled private package or release service.
43. Task 006 deliberately does not select that registry or provider.
44. Manual `.whl` and `.tgz` movement used by the spike is not the intended production release workflow.
45. Actual registry selection, credentials, permissions, availability, retention, replication, disaster recovery, and provider-specific provenance remain **TO VALIDATE**.
46. Independent per-package versioning is not accepted by this ADR.
47. Independent versioning may be reconsidered later if coordinated releases create measurable product or operational problems.
48. Package decomposition demonstrated in Task 006 is representative; fixture package names and APIs do not freeze final production package boundaries.

## Architecture

```text
              omnilyzer-platform
                     |
               platform release
                  1.1.0
                     |
       +-------------+-------------+
       |             |             |
 Python package   web package   governance
    wheel           npm           npm
       |             |             |
       +-------------+-------------+
                     |
           immutable release set
            manifest + hashes
                     |
             private registry
              TO VALIDATE
              /         \
             /           \
       Product A       Product B
         1.0.0           1.1.0
```

Independent product adoption means products choose a coordinated platform release on their own cadence. It does not mean packages within one coordinated platform release use independent versions.

## Release flow

```text
platform source
      ↓
versioned build
      ↓
compatibility + security checks
      ↓
immutable standard artifacts
      ↓
release manifest / integrity metadata
      ↓
private package service
      ↓
exact product dependency pin
      ↓
product CI
      ↓
DEV → STAGING → PROD
```

The private package service remains **TO VALIDATE**.

## Source ownership boundary

Platform code is owned in:

```text
omnilyzer-platform
```

Product code is owned in independent repositories such as:

```text
valoria
omnilyzer-hr
other products
```

This names intended ownership boundaries; it does not assert that these product repositories have already been created or migrated. Product repositories must not contain synchronized copies of platform implementation. Products consume published public contracts.

## Compatibility implications

A same-major release must preserve previously supported public APIs relied upon by compliant consumers. Minor releases may add public APIs. A breaking public API change requires a major-version transition unless a separately accepted compatibility or migration mechanism applies.

Automated compatibility checks supplement but do not eliminate:

- product CI;
- integration testing;
- migration review;
- release notes;
- deployment validation.

Database migration compatibility was not validated by Task 006.

## Rollback implications

### Compatible consumer

```text
Product code A
Platform 1.0
    ↓
Platform 1.1
    ↓
Platform 1.0
```

This may be a valid package rollback if the product did not adopt newer APIs.

### Consumer adopted new API

```text
Product code B using 1.1 API
        +
Platform 1.1
```

Downgrading only the package to 1.0 may fail correctly. Rollback then generally means:

```text
product revision compatible with 1.0
                +
exact platform 1.0 pins
```

Dependency-only rollback is not universal.

## Integrity and provenance

Task 006 accepted deterministic SHA-256 manifests as integrity and traceability metadata. The distinction is explicit:

```text
hash verification
≠
trusted publisher identity
≠
signed provenance
```

The production release pipeline still requires validation of protected publishing identity, artifact signing or attestations where justified, trusted publishing, provenance, and registry permission controls. This ADR does not claim SLSA compliance.

## Registry boundary

The following remain non-decisions:

- GitHub Packages;
- PyPI or a private PyPI provider;
- an npm private registry or provider;
- a self-hosted registry;
- registry credentials;
- registry retention;
- registry replication;
- registry disaster recovery;
- provider billing;
- a trusted-publishing provider.

The architecture is intentionally registry-neutral because wheels and npm packages are standard formats. GitHub is already used for source control, but that does not select GitHub Packages.

## Security implications

- Products use exact versions and expect released artifacts to be immutable.
- Artifact hashes provide integrity checks.
- Archives require inspection and constrained contents.
- Archive validation rejects path traversal and prohibited embedded material.
- Package metadata requires dependency and lifecycle-script checks.
- Product execution remains isolated from platform source.
- Technical package export boundaries restrict unsupported entry points where possible.
- Credentials must not be embedded in artifacts.
- Package provenance remains incomplete until signed or trusted publishing is validated.

## Governance implications

ADR 0004 requires semantic design governance. This ADR establishes that semantic governance is distributed as a versioned platform capability rather than copied manually into products. Once production packaging is implemented, product repositories must execute the versioned governance package in their own CI and build processes.

## Consequences

Positive consequences:

- independent product release cadence;
- centralized platform ownership;
- explicit upgrades;
- no source copying;
- deterministic immutable artifacts;
- compatibility gates;
- multiple supported product platform versions;
- a realistic rollback boundary;
- versioned governance;
- standard packaging ecosystems;
- registry-provider portability.

Tradeoffs:

- coordinated platform releases can release unchanged packages together;
- exact pins require deliberate upgrade pull requests;
- old package versions require retention;
- same-major compatibility creates API-maintenance obligations;
- a release manifest is not signed provenance;
- actual registry operations remain unvalidated;
- Django reusable-app and migration packaging remains unvalidated;
- React and design-system production packages remain to be implemented.

## Explicit non-decisions

This ADR does not select or freeze:

- a private registry provider;
- independent package versioning;
- final package decomposition;
- final package names;
- signed provenance technology;
- CI release automation;
- Django reusable-app packaging mechanics;
- a database-migration compatibility process;
- React component package implementation;
- registry retention duration;
- supported platform-version lifetime.

