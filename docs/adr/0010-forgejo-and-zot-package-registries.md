# ADR 0010: Use Forgejo and zot as the Package Registry Architecture

- Status: Accepted
- Date: 2026-09-04

## Context

Omnilyzer requires private, immutable release distribution for standard Python, npm, Generic, and OCI artifacts. CI publishing and consumption must use short-lived GitHub Actions OIDC workload identity rather than long-lived registry credentials. Publishers must be able to create and read releases without replacing or deleting them, consumers must be read-only, and previously published OCI digests must remain available for exact-digest deployment and rollback as required by [ADR 0006](0006-immutable-oci-deployment-and-promotion.md).

Tasks 008A/B technically validated Cloudsmith across all required formats, including trusted publishing, separate publisher and consumer identities, signing and provenance evidence, registry-only rollback, and retention after GitHub Actions handoff artifacts expired. The recurring commercial plan cost required for this project is unacceptable, so technical success does not make Cloudsmith the selected production direction.

Task 008C evaluated self-hosted Forgejo. Generic, PyPI, and npm passed when accessed through the protected Nginx ingress that denies public DELETE. Forgejo's native publisher authorization permits deletion, so this result depends on publishers having no route that bypasses the protected ingress. Forgejo OCI did not meet the immutable-release requirement under the tested configuration: a manifest PUT replaced an existing tag, after which the previously retrievable manifest digest returned `MANIFEST_UNKNOWN`. Blocking DELETE cannot prevent that destructive PUT transition.

Task 008D evaluated zot `v2.1.20` for OCI only. Publisher run `33814874276` demonstrated short-lived GitHub OIDC authentication, publisher create/read, exact HTTP 403 denial of same-tag update, exact HTTP 403 denial of manifest deletion by digest and tag, original digest retention, post-denial integrity, and standard Docker interoperability. Consumer run `33815051427` ran after an observed zot service restart and independently retrieved and verified the retained tag, manifest, config, and layer through a read-only OIDC identity, including Docker pulls by tag and exact digest.

The retained Task 008D baseline was:

- tag `task008d-33814874276-1`;
- manifest digest `sha256:869121fdf10de171eff2f2622fa4190939573abc1e5bb24e7502b8757d4f6059`;
- config digest `sha256:8ac6c44b9181a6d92469b5b701417f9ab13c5f0b8c462ffd68a7f4d098e9614d`;
- layer digest `sha256:6747a1b2afcb45cb4e398e8f08158b305575e98f78fefee20c14e415dccfc89b`.

Reference evidence:

- [`spikes/supply-chain/README.md`](../../spikes/supply-chain/README.md)
- [`spikes/supply-chain/zot/README.md`](../../spikes/supply-chain/zot/README.md)
- Task 008C Forgejo evidence maintained on branch `spike/008c-forgejo-registry`

## Options considered

### Cloudsmith for all formats

Cloudsmith passed the technical validation and remains a valid technical reference. It is not selected because the required recurring commercial cost is unacceptable for this project.

### Forgejo for all formats

A single self-hosted service would reduce component count, and Forgejo passed Generic, PyPI, and npm validation with the protected ingress. It is not selected for OCI because the tested same-tag replacement caused loss of the original digest, violating immutable deployment and rollback requirements.

### Forgejo for packages and zot for OCI

This split uses each validated service only for formats whose required behavior passed. It adds an operational component but satisfies the package-format, workload-identity, OCI immutability, and rollback requirements without the rejected commercial cost.

### Another OCI or multi-format registry

Other registries may also satisfy the requirements, but none is selected without equivalent dedicated validation. This decision does not claim zot is universally superior.

## Decision

Omnilyzer selects this open-source split registry architecture:

```text
GitHub Actions
short-lived OIDC workload identity
        |
        +--> Forgejo behind protected Nginx ingress
        |      Generic / PyPI / npm
        |
        +--> zot
               OCI
```

1. Forgejo, accessed through the protected Nginx ingress, hosts Generic, PyPI, and npm releases.
2. Publishers must not have a network path that bypasses the Forgejo ingress's append-only DELETE boundary.
3. zot hosts OCI releases.
4. GitHub Actions publishing and consumption use short-lived OIDC workload identity with exact issuer, audience, repository, and workflow identity restrictions.
5. CI uses no long-lived registry password, PAT, API key, or static bearer token.
6. Publisher and consumer identities remain separate and least-privileged. The validated zot publisher has `read` and `create` without `update` or `delete`; the consumer has `read` only.
7. OCI deployments and promotions reference immutable exact digests. Human-readable tags are discovery aids, not deployment identity.
8. Previously approved OCI digests must be retained for rollback.
9. zot garbage collection remains disabled for the Task 008D evidence. Production retention and lifecycle policy require a separate operational decision that preserves approved release and rollback digests.
10. Cloudsmith is not selected, while its technical validation evidence remains valid.
11. Forgejo is not used for OCI release storage under the tested configuration.

## Consequences

Positive consequences include:

- all four package formats use evidence-backed open-source services;
- CI does not require long-lived registry credentials;
- the OCI publisher cannot move an existing tag or delete a release under the tested zot policy;
- exact OCI digests remain the promotion and rollback identity;
- Generic, PyPI, and npm retain their validated standard-client behavior;
- commercial registry cost does not become a recurring project dependency.

Tradeoffs include:

- two registry services must be operated, monitored, backed up, and upgraded;
- Forgejo package immutability depends on the protected ingress remaining the only publisher-reachable path;
- storage grows while zot garbage collection is disabled;
- production lifecycle and capacity policy must preserve rollback material without treating the spike setting as a complete long-term storage design;
- the tested restart demonstrates persistence across that restart, not indefinite retention or disaster recovery.

## Security implications

GitHub Actions trusts only short-lived OIDC tokens bound to exact workload identity claims. Registry access policies must fail closed for unknown authenticated and anonymous identities. Tokens must not be stored in artifacts or logs, and sensitive direct clients must not forward authorization across origins or redirects.

Forgejo's Nginx DELETE boundary is a required security control for Generic, PyPI, and npm. Network policy must prevent publisher access to a bypass endpoint. zot's native ACL is the OCI immutability boundary: create/read is distinct from update/delete, and Nginx does not implement zot immutability.

Release signatures, SBOMs, vulnerability decisions, and provenance remain required supply-chain evidence. Digest identity, publisher authorization, and cryptographic provenance are related but distinct controls.

## Operational implications

Operations must own Forgejo, its protected Nginx ingress, zot, TLS, storage, upgrades, monitoring, backup, restore testing, and disaster recovery. zot remains loopback-bound behind HTTPS ingress in the intended topology. Production readiness requires explicit storage-capacity alerts and a validated retention policy that cannot collect approved current or rollback digests.

Disabling zot garbage collection was appropriate for the Task 008D correctness test because it isolated authorization and persistence from cleanup. It is not evidence that unlimited storage growth is an acceptable permanent production policy. Any future GC or retention configuration must receive independent validation against exact-digest rollback requirements.

## Migration and rollback implications

Adoption should preserve the validated namespace and identity separation while moving package publication to Forgejo and OCI publication to zot. Existing Cloudsmith releases and evidence must not be deleted merely because Cloudsmith is not selected; migration and any service termination need a separately reviewed preservation plan.

OCI promotion continues to use the same digest from DEV through STAGING to PROD. Rollback pulls a previously retained exact digest and does not rebuild or resolve a mutable tag. Registry configuration changes, upgrades, backup restoration, or lifecycle-policy changes must prove that retained digests, manifests, configs, and layers remain available before production reliance.

If the split architecture cannot meet its operational or recovery obligations, a replacement registry decision requires new evidence and a superseding ADR; it must not weaken ADR 0006's immutable-digest requirement.
