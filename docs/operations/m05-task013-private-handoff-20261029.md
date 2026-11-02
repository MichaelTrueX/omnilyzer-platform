<!--
FILE: docs/operations/m05-task013-private-handoff-20261029.md
PURPOSE: Correct the first signed Analytics release's private cross-repository checkout and prevent public Actions artifact exposure of the private source and OCI build.
LINKS: .github/workflows/platform-release.yml, release/analytics_private_handoff.py, release/analytics_handoff_recipient.asc, release/tests/test_analytics_private_handoff.py, release/tests/test_workflow_policy.py, GitHub Issue MichaelTrueX/omnilyzer#27.
SECURITY: Documents key references and verification only; never commit the private SSH/GPG keys or source TAR, and never publish unencrypted transport artifacts.
-->

# M05 Task013 — private cross-repository source and encrypted handoff

## Root cause and security boundary

- Protected `0.15.0` run `40874125154` checked out the public platform source successfully but private `MichaelTrueX/omnilyzer` returned HTTP **403**. The previous `ANALYTICS_SOURCE_READ_TOKEN` is present but has not provided the required private Git read access.
- The original workflow proposed uploading `$RUNNER_TEMP/analytics-task013-unsigned` using `actions/upload-artifact`. This directory contains `candidate/source.tar` and `candidate/analytics.oci.tar` from a **private repository**. Because `MichaelTrueX/omnilyzer-platform` is PUBLIC, its GitHub Actions artifacts must be treated as publicly downloadable. A one-day retention is NOT access control.
- Previous protected runs failed before the upload step; there is **no successful prior `analytics-task013-handoff` artifact** from these failures. Do not provision private source access without first fixing the artifact transfer.

## Scoped credentials, no broad personal access token

- Install a repository-specific, **read-only** Ed25519 GitHub deploy key on the private `MichaelTrueX/omnilyzer` repository. The corresponding SSH private key is an encrypted GitHub Actions repository secret on `MichaelTrueX/omnilyzer-platform` named `ANALYTICS_SOURCE_DEPLOY_KEY`. The source verification still pins exact PR52 Git SHA `4cdda7faeba57abb3388f9be5c450fe6afb1140d`, rejects source drift and checks 78 Git identities.
- Protect Analytics source artifacts with an exact, checked-in **public** GPG recipient `release/analytics_handoff_recipient.asc`, fingerprint `C831E132F855D5830AEE0FF7F2462BA6518AD974` (no private material). Store the matching **private** key as the protected `task013-dev-release` GitHub environment secret `ANALYTICS_HANDOFF_DECRYPT_KEY`. The source job has no access to this decryption key, signer identity or registry write capability.
- After real source validation, OCI build, Syft and Grype policy PASS, encrypt the entire handoff stream directly to `analytics-task013-transport.gpg`; remove the plaintext handoff before the `upload-artifact` step. The workflow uploads ONLY this `.gpg` file. In each protected publisher job decrypt into its isolated runner temp, applying safe tar member checks; then execute the original source/OCI binding, authenticated registry absence, immutability checks, Cosign and Zot/Forgejo publishing without bypass.
- The independently scoped Zot JSON receipt may be uploaded because it contains only publication metadata, not private source archives; do not add secrets or source bytes to that receipt.

## Checks and constraints

- Real GPG smoke: public recipient encrypt -> protected private key decrypt, matching required bytes; unauthorized ciphertext manipulation, missing key, link substitution and tar traversal fail closed.
- Existing original Task013/Task014 workflow, canary, CodeQL and cross-repo source-contract tests MUST pass; all GitHub checks on exact PR head must pass before protected `main` merge.
- Original no-waiver **0 Critical / 0 High** policy remains unchanged. The in-flight `0.15.0` run is already FAILED BEFORE any publication. Do not reuse `0.15.0` if any protected publication later succeeds only partially; respect existing fail-closed occupied-version preflight and immutable Zot recovery.
- Do not create a new deployment pipeline or change user-facing auth, CSP, CORS, PostgreSQL, Task014 executors, traffic, production or existing canary behavior.
- Private handoff GPG recipient currently expires in October 2027. Before expiry rotate the public key and protected private environment secret together, then validate the real encrypted/decrypted handoff on a new protected release SHA.

## Release acceptance

The owner-approved `0.15.0` Task013 release may be retried only from the new protected platform `main` SHA after reviewing the source-only deploy key and protected decryption secret. The new protected workflow must complete actual private checkout -> original immutable OCI BuildKit -> actual Syft/Grype zero Critical/High -> encrypted artifact transport -> protected source revalidation -> authenticated two-registry version absence -> Cosign sign/verify -> Zot digest readback -> Forgejo evidence publication/readback. Task014 installation and production activation remain separately unapproved.
