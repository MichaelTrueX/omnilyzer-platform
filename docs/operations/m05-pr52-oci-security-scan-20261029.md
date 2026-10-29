# M05 original Task013 PR52 OCI security acceptance - 2026-10-29

File: `docs/operations/m05-pr52-oci-security-scan-20261029.md`
Purpose: Record the genuine unsigned Task013 BuildKit/Syft/Grype scan of the exact reviewed Analytics source, linked to `release/products/analytics-source.json`, `deployment/analytics_signed_source_pin.py`, and `docs/operations/m05-pr52-oci-security-scan-20261029.json`.

- Product: `MichaelTrueX/omnilyzer` PR52 at `4cdda7faeba57abb3388f9be5c450fe6afb1140d`; tree `5c71020a6d9b66b5010386f2743111936a164daa`.
- Platform reviewed parent: `b315601e74b68096a0c887b54d7aebed35ab7ca0`.
- Source admission: 78 exact checked identities; 543 Git-only source files; deterministic TAR SHA256 `c4474ae71ac2acf58876c9ab502e009c866fbeb29862ce991374b8396abf092f`.
- Original pinned BuildKit v0.24.0 built a real linux/amd64 unsigned OCI; exact archive validated and original unsigned pre-sign external source claim passed.
- Unsigned local OCI manifest digest: `sha256:46331e904d7410c72597b91d48555886015f211bf27d227e30950243d33a9bab`.
- Unsigned local OCI archive SHA256: `e027cc9df9a7e8dbc918188eb2898c4b34798a0b11d705069a19bb3f4001875b`.
- Syft 1.51.0 CycloneDX 1.6: 1,060 components. Grype 0.118.0 DB schema v6.1.10 built 2026-10-29T06:23:34Z, valid.
- Actual findings: Critical **0**, High **0**, Medium **3**, Low **1**, others **0**. Unmodified `release/vulnerability-policy.json` **PASS**, blocked count **0**, zero policy exceptions.
- Focused existing Analytics release tests: 58 run, 47 pass, 11 optional skipped. Focused existing Analytics deployment tests: 30 run, 28 pass, 2 optional skipped. `git diff --check` PASS.
- Broad `release/tests` 195 tests had 3 Task014 cutover/source-generation setup errors; broad `deployment/tests` 2,313 tests had 10 failures and 92 errors, predominantly original platform immutable-cutover fixtures. These are **not** represented as passing; assess original Task014 baseline separately before hosted acceptance.
- RAM-backed dedicated builder and temporary scanner files were removed on exit. The source changes are review-only; no signed artifact, registry push, privileged broker/executor, installed DEV, rollback acceptance, or production deployment took place.
- **Decision:** Genuine original Task013 unsigned OCI vulnerability policy PASS. Release and installed DEV **not authorized**, pending independent M04 changed-boundary review, original protected signing and runtime acceptance, and owner approval.
