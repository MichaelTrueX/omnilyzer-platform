<!--
FILE: docs/operations/m05-task013-analytics-external-source-evidence-20261028.md
PURPOSE: Review the exact Analytics cross-repository OCI source evidence hook
         for the ORIGINAL protected-main Task013 signing mechanism.
LINKED FILES: release/analytics_release_source_binding.py;
              release/tests/test_analytics_release_source_binding.py;
              release/analytics_oci_context.py;
              release/analytics_task013_build_input.py;
              release/analytics_oci_archive.py;
              release/provenance.py; deployment/promotion.py;
              deployment/release_consumer.py;
              .github/workflows/platform-release.yml;
              docs/operations/m01-task013-immutable-oci-context-20261028.md.
STATUS: Local review-only original-signer input, no signed artifact or Task014 deployment.
-->

# M05 - Original Task013 Analytics external Git source evidence

**Date:** 28 October 2026, Manila

## What is actually integrated

This branch is stacked on M05 platform PR231 and cherry-picks the complete,
unchanged three-file M01 PR232 immutable Git-only Docker source context
implementation. This is a **single release source path**, not a second builder,
registry, signer, broker, executor or deployment framework.

`release/analytics_release_source_binding.py` performs three linked, actual
content checks before an Analytics source claim can enter future signed Task013
release provenance:

1. Re-run M01's existing 51-file final PR45 Git blob and closed profile gate.
   Read the exact platform Git HEAD, Analytics HEAD and Git tree identities.
2. Independently regenerate the deterministic M01 Git-only Docker build tar,
   then compare its entire SHA-256 and byte count with the *actual supplied*
   Docker/BuildKit build context. A mutable checkout, untracked source, symlink
   or different tar will be refused. This prevents a verified Git SHA from
   masking an unrelated local `COPY . .` build input.
3. Run M05's actual local OCI archive verifier over the complete OCI layers,
   config and manifest. Require the existing original Task013 pre-sign release
   evidence to identify **the same** OCI repository, full archive SHA-256,
   manifest digest and protected platform workflow source SHA.

The source claim includes complete Git/source manifest/profile/build-context
fingerprints and actual OCI archive/manifest hashes. The SAME source claim is
added to original `release-provenance.json` and `release-manifest.json`
**before** the original Cosign sign-blob step. The manifest's SHA-256 of the
new provenance bytes is recomputed in the original evidence layout. No
signature, OIDC token, registry publication or deployment is created by this
adapter.

## Reproducible validation

From an isolated original-platform checkout containing this candidate:

```bash
export OMNILYZER_ANALYTICS_CHECKOUT=/path/to/exact-clean-pr45-checkout
python3 -m unittest -q release.tests.test_analytics_release_source_binding
python3 -m unittest -q release.tests.test_analytics_oci_context \
  release.tests.test_analytics_oci_archive \
  release.tests.test_analytics_task013_build_input
```

To prepare original Task013-compatible **unsigned** pre-sign evidence, only
after an authorized original release job has already produced the verified
Task013 handoff, registry OCI publication identity and the original
`release.provenance.create` outputs:

```bash
python3 -m release.analytics_release_source_binding \
  --analytics-checkout "$OMNILYZER_ANALYTICS_CHECKOUT" \
  --immutable-context /private/immutable-analytics-context.tar \
  --oci-archive /private/verified-analytics.oci.tar \
  --original-evidence-dir /private/original-task013-pre-sign \
  --output-dir /private/analytics-task013-pre-sign
```

The original-evidence input directory must contain exactly two files:
`release-manifest.json` and `release-provenance.json`. The destination
must not exist. Output is created 0700, files 0600, and no existing evidence
is overwritten. Input/output mode must be explicitly paired. Calling the
adapter without both evidence arguments prints only an **unsigned source
claim** with `release_authorized=false` and `deployment_authorized=false`.

**Do not operate the above on existing DEV/prod services or use real production
credentials.** These are engineering steps for a protected-main future
release job after separate owner approval.

## Actual QA and trustworthy evidence limits

- M01 immutable Git-only Docker context PR232: original local Docker build
  accepted M01's generated tar; original source context tests already 5/5 PASS.
- M05 PR231: actual complete PR45 Node20 OCI archive produced on a pinned
  BuildKit 0.24.0 isolated builder and independently checked; 21/21 focused
  real-source and real-OCI tests PASS. Local manifest and archive hashes were
  reported separately in PR231. Local output was subsequently cleaned.
- New source-evidence adapter: actual clean PR45 Git HEAD and deterministic
  Git-only tar, **synthetic structurally valid test OCI**, both original
  Task013-shaped pre-sign documents, actual CLI filesystem protections, plus
  negative mutations PASS. These tests do not claim that the synthetic OCI
  represents a real built Analytics binary. The earlier PR231 actual OCI test
  remains independent evidence for genuine image format and runtime.
- The existing signed canary's protected release module, provenance code,
  original GitHub workflow, Task014 release consumer, broker/executor and
  installed application source-set remain byte-identical and UNCHANGED.

## Required original signer and consumer work, still NOT DONE

The future original protected-main Task013 workflow must consume M01's
verified Git-only tar as the exact BuildKit context, perform the same original
SBOM/Grype/release handoff/Forgejo/Zot publication and Cosign verification,
and invoke this adapter **between** the original evidence creator and original
Cosign signature command. It must obtain authorized read-only Git access to
the separate Analytics repository and refuse mismatched external source or
published manifest identity. The builder's trusted use of this context
must be governed by the protected workflow, not an unsigned caller assertion.

Task014's original signed release evidence validator currently has a closed
schema and the original policy/consumer/executor permits only the synthetic
no-secrets canary. It will correctly **reject** the Analytics evidence with
the new `external_source` field until an independently reviewed additive
product-specific verified-evidence contract is installed. This adapter
must NEVER be used to bypass the existing Task014 crypto, OIDC replay, approval,
runtime-secret-reference or slot controls.

A genuine signed Analytics DEV promotion additionally needs scoped database
roles and references, isolated Analytics blue/green runtime, exact private
`/livez` and `/readyz` checks and rollback to a **previously signed**
immutable Analytics OCI digest without rolling back persisted events.

**Owner permission required** before protected-main merges, release signing,
live DEV runtime or any service configuration activation. No auth/JSON Bearer
token, localStorage, tenant RLS, canary or other websites were changed.

**Verdict:** original Task013 pre-sign evidence adapter source-level implemented;
actual Task013-signed Analytics image, Task014 installation, DEV promotion and
verified rollback remain OPEN/NO-GO.
