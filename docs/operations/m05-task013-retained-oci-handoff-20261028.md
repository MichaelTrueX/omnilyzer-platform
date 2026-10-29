<!--
FILE: docs/operations/m05-task013-retained-oci-handoff-20261028.md
PURPOSE: Deliver one original Task013 immutable, exact-byte source-to-OCI
         build handoff without publishing, signing or changing active DEV.
RELATED: release/analytics_task013_build_candidate.py (M01 PR232);
         release/tests/test_analytics_task013_artifact_handoff.py;
         release/analytics_oci_context.py; release/analytics_oci_archive.py;
         release/analytics_release_source_binding.py (M05 PR233);
         release/provenance.py (original and unchanged);
         deployment/promotion.py (M05 PR234);
         .github/workflows/platform-release.yml (original and unchanged).
-->

# M05 P0: retain the exact verified Task013 OCI image for original signing

**Date:** 28 October 2026. **Status:** isolated draft-only source integration.

## Why the change was necessary

M01's original Task013 Analytics source→OCI helper in platform PR232
correctly verifies a locally built OCI archive against the exact final
Analytics Git source (PR45), the committed-only source TAR, the pinned
Buildx/BuildKit versions and M05's OCI archive validator. Its old behavior
destroys the source TAR and OCI archive when the function exits. That is
correct for disposable QA, but a future original Task013 signer must
consume the **same exact verified archive bytes**, not rebuild an unrelated
image or trust a mutable checkout after local verification.

This patch extends the existing M01
`release/analytics_task013_build_candidate.py` with an **explicit,
optional, private, atomic and UNSIGNED verified-artifact handoff**.
It does not create a second OCI builder, registry, release signer, Task014
broker/executor or application runtime.

## Existing behavior is unchanged

With no `--retain-verified-artifacts`, the helper uses a temporary
directory and removes both archives after verification. With `--build`
omitted, only the source and original pinned builder identity are checked.
No registry, token, package publication, signing or deployment occurs.

## Opt-in private retained handoff

The new flag `--retain-verified-artifacts /private/path/new-handoff` is
accepted only with `--build`. The destination must be an absolute,
non-existing path under an **already existing, caller-owned, private
parent directory (mode with no group/other permissions)**. The parent
cannot be a symlink or any public shared directory such as `/tmp`.

When all original source/OCI checks PASS, the helper additionally checks
that the complete TAR and OCI hashes still equal the independently
validated hashes. It emits one closed unsigned receipt and transfers the
three files as one atomic directory rename under the private parent:

- `source.tar`: exact M01 deterministic Git-only build context, 0600.
- `analytics.oci.tar`: exact locally verified OCI archive, 0600.
- `unsigned-handoff.json`: canonical receipt with Git/OCI identity
  and SHA256, explicitly `release_authorized=false` and
  `deployment_authorized=false`, 0600.

The handoff directory has mode 0700. On builder failure, hash mismatch or
invalid destination the temporary files are removed and no handoff is
published. Existing output directories and files are never overwritten.
The helper creates and removes no live registry tags or Docker containers
other than what an authorized isolated developer test explicitly
provisions for Buildx.

### Example for authorized disposable local validation only

```bash
cd /path/to/isolated/omnilyzer-platform-source
private_dir="$(mktemp -d /tmp/m05-task013-test.XXXXXXXX)"
chmod 0700 "$private_dir"

# The developer first creates and boots an isolated pinned Buildx builder
# using the ORIGINAL Task013 pin in .github/workflows/platform-release.yml.
python3 -m release.analytics_task013_build_candidate \
  --analytics-checkout /path/to/exact-clean-pr45-git-source \
  --builder m05-isolated-pinned-builder \
  --build \
  --retain-verified-artifacts "$private_dir/verified-handoff"

# Revalidate the exact handoff bytes for future ORIGINAL Task013 signing.
python3 -m release.analytics_release_source_binding \
  --analytics-checkout /path/to/exact-clean-pr45-git-source \
  --immutable-context "$private_dir/verified-handoff/source.tar" \
  --oci-archive "$private_dir/verified-handoff/analytics.oci.tar"

# In review-only development, remove this complete unsigned test handoff.
rm -rf -- "$private_dir"
```

**The last cleanup example applies only to the explicitly created
disposable test path.** Do not remove operational release artifacts or
touch installed Task013/014 state.

## Test and activation boundaries

Unit tests cover successful exact-byte handoff, file modes, existing
transient behavior, builder nonzero exit, hash substitution, existing
destination, shared output parent, symlink, bad output name, and
`--retain` without explicit build. They mock only the local Docker
builder and no network, credentials or production state.

An actual developer build with pinned BuildKit remains **local unsigned
OCI proof**, not an authorized Zot digest or Sigstore-issued certificate.
The future ORIGINAL protected-main Task013 workflow must consume and
verify these exact files in its existing build/publish/signing sequence;
the current release plan, handoff schema, absence checks, registry
publishers and original Task014 installed release-policy/source-set
still target the historical synthetic canary.

M01 must review this patch against its canonical PR232 helper, and M04
must independently verify the exact retained archive SHA across builder,
handoff and intended original signer input. The separate original Task013
signer, Task014 product-scoped signed promotion, secret references,
private rootless Analytics blue/green runtime and signed digest rollback
remain P0 open until authorized implementation.

Do not merge, publish, dispatch signing, change protected-main,
live DEV/prod databases, canary0.14.6, Nginx, Cloudflare, DNS, secrets
or any other website without explicit separate owner approval.

## Actual complete integration run on truexdevelopment

**2026-10-28, actual source-executed, no registry credentials**:
Original exact Analytics PR45 Git commit
`8648adba2db884cc78274080b9836ca46bafd630` was admitted
with **51/51 exact file identities**. A temporary, bootstrapped original
BuildKit v0.24.0 docker-container builder built from M01's exact committed
532-file source TAR. A complete ~600 MB OCI archive and the ~9.8 MB
source TAR were verified, privately retained in the SAME new 0700 folder,
then reverified by `release.analytics_release_source_binding`. The three
handoff files had exact 0600 modes; a new receipt explicitly denied any
release/deployment authority. SHA256 of each retained file matched its
pre-retention verifier output, not merely a reconstructed file name.

- Source TAR SHA256:
  `d64d272944b775085ad62e9d8ef0f4be5b272fc87286f8f607d59105ccb4b818`
- Local OCI archive SHA256:
  `07b1d1387591048ff48f2f25345d8aac251feb56e50e1d0c4786576732c27cb7`
- Local OCI manifest digest:
  `sha256:40b5c62f7c0f1cfb2ce4f91931f36f9220f3e9496114b94ee8bbe7a288aff54e`

These values are one LOCAL ephemeral build and may differ from previous
local manifest digests without invalidating exact pinned source admission.
**They are not a signed registry manifest, authenticated GitHub Actions run,
Task014 promotion or running Analytics deployment.** The test source TAR,
OCI archive, receipt and isolated builder were removed by the verified cleanup
trap, leaving the original Docker builder and canary untouched.
