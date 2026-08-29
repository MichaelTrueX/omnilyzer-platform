# Platform packaging validation

Recommendation: **adopt**

| Evidence | Result |
|---|---|
| Python wheel result | PASS — `omnilyzer-platform-core` 1.0.0 and 1.1.0 pure-Python wheels installed with `pip --no-index` |
| npm package result | PASS — both npm packages built and installed as standard `.tgz` artifacts at 1.0.0 and 1.1.0 |
| Coordinated release-set result | PASS — manifests contain all three same-version artifacts; mixed selection rejected |
| Artifact determinism result | PASS — two builds produced identical wheels, tarballs, and manifests |
| Integrity/tamper result | PASS — SHA-256 verification rejected a modified artifact |
| Archive-content result | PASS — allowlists and path/content checks passed; no lifecycle scripts or runtime dependencies |
| Public-boundary result | PASS — Python private symbol is not exported; npm deep import is blocked by `exports` |
| SemVer compatibility result | PASS — additive 1.1.0 accepted, same-major removal rejected, simulated 2.0.0 break permitted |
| Product Alpha 1.0 result | PASS |
| Product Beta 1.1 result | PASS |
| Simultaneous adoption result | PASS — isolated Alpha 1.0.0 and Beta 1.1.0 installations coexisted |
| Alpha upgrade result | PASS — unchanged consumers accepted 1.1.0 |
| Alpha rollback result | PASS — unchanged consumers returned to 1.0.0 |
| Beta downgrade negative test | PASS — package-only downgrade failed because Beta uses 1.1.0 APIs |
| Mixed-version rejection result | PASS — rejected before consumer execution |
| Governance-distribution result | PASS — installed CLI accepted compliant fixtures and rejected a temporary violation |
| Source-copy isolation result | PASS — products executed under `/tmp` with artifact-only installs and no source references |

Tests: **39 passed, 0 failed**.

Runtime/tooling: Python 3.12.3; Node v24.20.0; npm 11.19.0; build 1.6.0; Hatchling 1.32.0.

Artifact SHA-256 values are recorded in deterministic per-release manifests. Representative first-build hashes: @omnilyzer/design-governance@1.0.0 `3eca0591c34b0bc73f6303576fd9863bb5b292bd1e3e2e60a3cee6b60c9453c4`, @omnilyzer/platform-web-contract@1.0.0 `a3c7dfd5fcbb8f78f5d413f1a9c2a594bb23d7c0ce544c4b72a668d62637412e`, omnilyzer-platform-core@1.0.0 `7f61511cc21003eb0b9a4e816f641ae61a67225ec9bc2978af8b3096106522e1`.

The hashes validate integrity and deterministic source-to-artifact traceability. They are not trusted signatures and do not prove artifact authenticity. Task 006 does not validate signed provenance, Sigstore, SLSA attestations, registry trusted publishing, or a protected signing identity.

## Rollback boundary

Package rollback works while consumer code remains compatible with the older public contract. Once a product adopts a newly introduced API, rollback generally requires restoring the product commit and exact package pins together; package downgrade alone is not universal rollback.

## Limitations

Not validated: an actual private registry; registry credentials, authentication, authorization, availability, retention, replication, or disaster recovery; GitHub Packages, private PyPI, npm private registry, or provider billing; signed provenance/Sigstore/SLSA or trusted publishing; production CI; real product repositories; Django reusable apps; React components; database migrations; independent package versioning; large dependency graphs; or very large product fleets.
