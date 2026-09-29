# ADR 0011: Use OIDC-Authenticated Restricted Deployment Authority

- Status: Accepted
- Date: 2026-09-08

## Context

ADR 0006 requires immutable exact-digest promotion, explicit migrations, readiness gates, blue/green traffic switching, durable state, and audit evidence. ADR 0010 requires short-lived workload identity, separate publisher and consumer authority, and least-privileged access to Forgejo and zot. Neither decision selects how an authorized GitHub promotion job reaches the environment-local Docker deployment boundary.

The decision question is:

> How may an authorized GitHub promotion job reach environment-local Docker deployment authority without granting arbitrary workflow code a general-purpose host or Docker login?

Task 014 Phase 2B2 discovery found no dedicated deployment identity, no self-hosted runner, no GitHub-to-DEV transport, and no read-only deployment consumer for the release evidence or OCI candidate. A personal host account has both Docker and sudo membership. Docker-group membership is effectively high privilege and is not a narrow deployment boundary. A workflow compromise must not become an unrestricted Docker daemon or host shell compromise merely because it reached a deployment endpoint.

On 2026-09-08, the private repository/account capability could not enforce the branch and GitHub environment protections required by this decision. That historical limitation restricted work to architecture and inert repository-side implementation until the protection capability prerequisite could be satisfied.

As of 2026-09-24, the repository is public, `main` is protected by the active repository ruleset `Protect main`, and the GitHub deployment environment `task014-dev` exists with `deployment_branch_policy.protected_branches=true` and `deployment_branch_policy.custom_branch_policies=false`. The branch/environment protection capability prerequisite is now satisfied for DEV.

This satisfied the protection capability prerequisite. C31 host provisioning and pinned recovery subsequently completed and converged under separate authorization; installed runtime assets remain inactive. A separate live-authority review is still required before deployment activation. `deployment/environments/dev.json` retains `activation.deployment_enabled=false`, which must remain false pending reviewed activation. PR names do not determine authority: the boundary is whether a change remains inert and repository-only or grants, installs, exposes, or exercises live deployment authority.

Pending that separate live-authority review, work remains limited to:

- closed verifier and authorization code;
- durable replay code;
- broker, transport, and executor code that cannot be activated;
- registry-consumer interfaces and deterministic mocked tests;
- audit schema 2 and complete identity projection (already implemented);
- inert systemd, Nginx, and layout fixtures, with C31-installed runtime assets inactive; and
- deterministic repository tests and static validation.

Until the live-authority change is separately reviewed, the following remain prohibited:

- `id-token: write` in a deployment workflow;
- GitHub environment attachment or a deployment job;
- live public broker ingress or listener;
- installation or enabling of host services or sockets;
- live registry credentials or token exchange;
- Docker or application execution;
- host, runtime, or infrastructure mutation;
- environment activation or populated live runtime references; and
- any static-key, personal-account, SSH, self-hosted-runner, or weakened-policy workaround.

This decision extends [ADR 0006](0006-immutable-oci-deployment-and-promotion.md). It does not replace ADR 0006 or [ADR 0010](0010-forgejo-and-zot-package-registries.md).

## Options considered

### A. GitHub-hosted runner to static SSH private key

This has a small initial service footprint but introduces a persistent CI credential. The likely SSH principal would need access to a Docker-capable operation, and a workflow compromise could reuse the key until revocation. A forced command can reduce exposure but does not remove the persistent-key cost. A personal SSH identity is not an acceptable final deployment identity.

### B. GitHub-hosted runner to short-lived SSH certificate through an OIDC broker

Short-lived certificates, exact principals, forced commands, and disabled forwarding can constrain SSH. This avoids a static CI key but requires a certificate authority, signer policy, SSH certificate lifecycle, and the same narrow privileged executor ultimately needed by the selected option. It is credible but adds an SSH-specific credential exchange without improving the final operation allowlist.

### C. GitHub-hosted runner to an OIDC-authenticated restricted deployment service

The service can validate short-lived GitHub workload identity and accept only a closed deployment request. An unprivileged broker can remain separate from a narrow privileged executor, so JWT/network parsing does not itself receive Docker authority. This directly represents the required operation without creating a host-login abstraction.

### D. Self-hosted GitHub Actions runner on DEV

A persistent runner would execute repository workflow code on the DEV host. Giving it Docker access would give accepted workflow code effectively host-level privilege, and withholding Docker would still require a separate executor boundary. Environment protections do not turn a persistent runner into an isolated or narrow authority. This option is rejected.

### E. Pull-based deployment agent

A local agent consuming signed desired state can be narrowly designed and may become appropriate at larger scale. For the private repository evaluated on 2026-09-08, it would normally have required a persistent GitHub credential, webhook trust, or an additional desired-state service. That added control plane is not justified for the initial DEV topology.

### F. Operator-mediated restricted deployment command

A closed human-operated command can provide an initial emergency or bootstrap path, but it does not establish GitHub workload identity and does not scale cleanly through DEV, STAGING, and PROD. It must not turn the current personal Docker-capable account into the final deployment identity.

## Decision

Omnilyzer selects:

```text
GitHub-hosted runner
        |
protected GitHub environment
        |
short-lived GitHub Actions OIDC
        |
unprivileged restricted deployment broker
        |
closed canonical request over a local Unix-domain socket
        |
narrow privileged executor
        |
Docker / Compose + deployment state and audit
```

For DEV, C32Q selects the ingress topology more precisely: the GitHub-hosted
runner sends HTTPS to the exact public origin
`https://deploy-dev.omnilyzer.ai`; root-controlled host Nginx terminates TLS
and proxies only `POST /task014/dev/promote` to an unprivileged broker bound
only to `127.0.0.1:3031`. That broker uses the existing C32P promotion handler
and the existing local Unix-domain socket to the privileged executor. The
broker never binds a public address. Local loopback access conveys no
deployment authority: exact signed deployment and registry workload identities
are still mandatory.

This selects an architecture and a repository-only request contract, not a
listener implementation. No broker HTTP listener, TLS certificate, DNS record,
host Nginx installation, service activation, or GitHub workflow permission is
created by C32Q. Deployment remains disabled.

C32R adds repository-only, explicit sequential HTTP/1.0 loopback listener
mechanics around that contract. It does not invoke them, compose a live broker,
or change the selected topology. The Nginx review reference requires the
post-1.23.0 combined duplicate-header behavior and a later real edge probe;
TLS/DNS/service installation and deployment activation remain separate work.

C32Z adds a separately pinned, uninstalled HTTPS Nginx activation candidate
for this same origin, endpoint, and loopback upstream. Its only certificate
authority is the expected Let's Encrypt full-chain and private-key paths under
`/etc/letsencrypt/live/deploy-dev.omnilyzer.ai/`. The actual host Nginx include
layout is not established by repository evidence, so no destination or
installer is selected. DNS, certificate issuance, installed-config and TLS
qualification, `nginx -t`, and real duplicate-header rejection probes remain
operational prerequisites. C32Z neither opens a listener nor activates the
workflow or deployment.

C32ZC supersedes the direct-public-IP C32Q/C32R/C32Z/C32ZA DEV edge
transport because the DEV host is behind CGNAT. The uncommitted Cloudflare
Tunnel candidate was not selected because its normal proxied HTTP response
timeout does not meet the reviewed synchronous Task 014 execution budget. The
repository-only final path is a GitHub-hosted runner joining the private tailnet
with pinned Tailscale Action and workload identity federation, an ephemeral
`tag:omnilyzer-task014-ci` node, private HTTPS at
`omnilyzerdev.tail52e570.ts.net`, Tailscale Serve to `127.0.0.1:3032`,
loopback-only Nginx, and the unchanged broker at `127.0.0.1:3031`. Funnel and
public inbound ingress are prohibited. Tailscale terminates tailnet HTTPS;
no host TLS is required on the loopback hop. Nginx enforces the exact incoming
Tailscale Host, strips Serve-added and arbitrary headers, and rewrites only the
logical broker Host to `deploy-dev.omnilyzer.ai`. The deployment, Zot and
Forgejo OIDC audiences and frozen broker parser remain unchanged. The old
direct-TLS candidate remains historical.

The pinned action verifies the official `1.102.4` Linux amd64 tarball digest,
disables its tool cache and subnet-route acceptance, retains MagicDNS, enables
shields-up, and makes one bounded connection attempt. Live WIF qualification
must prove the exact GitHub issuer and immutable subject
`repo:MichaelTrueX@130741173/omnilyzer-platform@1350104356:environment:task014-dev`,
`auth_keys`-only scope, CI-only tag, and supported exact GitHub workload claims
for repository, repository ID, main workflow ref, branch ref, environment,
manual event, and GitHub-hosted runner. WIF must not bind `workflow_sha`.
Tailnet policy must restrict that CI tag to omnilyzerdev TCP 443 without SSH,
unrelated ports or subnet-route authority.

The final workflow merge commit is independently supplied to a separate
root-only, locked, atomic broker-config rotation. It changes only
`expected_workflow_sha` after exact C32W/C32Y requalification. The merged source
must be staged under root control, the new broker authority qualified, and
all Tailscale/Serve/Nginx live checks completed before activation. C32ZC neither
configures the tailnet nor activates any service or deployment.

The broker must not have Docker socket access. Cryptographic JWT signature, issuer, and JWKS verification occurs before the pure authorization-claim policy. The authorization policy then requires the exact reviewed issuer, audience, numeric repository and owner identities, repository, workflow ref and revision, main ref, protected environment, manual event, GitHub-hosted runner, run identity, actor ID, temporal claims, and JTI.

The privileged executor must parse and revalidate the closed canonical request independently. Local broker provenance is not sufficient authorization. The executor exposes no shell execution, arbitrary command, arbitrary Compose file, arbitrary filesystem path, arbitrary repository, arbitrary image reference, or arbitrary environment. Its initial operation allowlist contains only DEV deployment. It accepts exact release evidence, an exact zot repository and digest reference, exact GitHub execution identity, and hash-bound runtime and ingress references.

OIDC alone does not prevent malicious code in an otherwise authorized workflow. Protected source and environment controls, exact workflow binding, replay prevention, a closed request, and the executor allowlist are distinct controls. The executor allowlist remains a second trust boundary even after successful OIDC authorization.

## Consequences

Positive consequences include:

- no CI SSH private key;
- no personal deployment SSH identity;
- no general-purpose GitHub-to-host login;
- no Docker socket in the broker;
- no persistent registry password;
- short-lived workload identity;
- exact GitHub workflow binding;
- replay protection;
- a closed operation schema;
- auditable actor, run, JTI, and request identity;
- a model applicable to future STAGING and PROD environments.

The deployment broker and privileged executor become security-critical components. OIDC verifier and JWKS handling, replay state, and Unix-socket ownership and permissions also become security-critical. The additional separation creates more implementation and operational work than a static SSH key, but avoids treating a general-purpose credential or host login as deployment policy.

No live authority is created by accepting this direction. JWT library selection, network handling, service installation, registry authentication, and runtime execution require later review and validation.

## Security implications

The broker must cryptographically verify the JWT before authorization policy is evaluated. It must validate the exact audience and all reviewed GitHub identity claims, enforce bounded token lifetime and receipt time, and atomically consume each JTI once. Replay state must remain available through token expiry plus allowed clock skew and must fail closed if unavailable or corrupt.

The broker forwards only deterministic canonical bytes. The local transport must use a Unix-domain socket with dedicated ownership and restrictive permissions and must not expose shell or arbitrary command semantics. The executor independently enforces stage, operation, registry, repository, digest/reference equality, GitHub repository and workflow identity, and configuration/reference allowlists.

Publisher authority must not be reused. Later implementation needs distinct read-only deployment consumers for the zot OCI candidate and Forgejo release evidence. Short-lived registry tokens must not reach application containers, state, audit records, or persistent Docker configuration.

Branch and environment protection are necessary but do not replace runtime authorization. No pull-request workflow, self-hosted runner job, branch name, actor login, repository name, or environment name alone grants deployment authority.

## Operational implications

Live operation requires all of the following; the protected GitHub environment now exists for DEV, while the remaining operational requirements still require separate review and validation:

- a dedicated non-login host deployment identity;
- a deployment broker service;
- a privileged executor service or narrowly privileged helper;
- root-owned deployment configuration;
- a TLS endpoint and DNS;
- a protected GitHub environment (`task014-dev` now satisfies the DEV protection capability prerequisite);
- OIDC signature and JWKS validation, including rotation and error handling;
- durable replay-state persistence;
- logging, monitoring, restart, and recovery behavior;
- a zot read-only deployment consumer;
- a Forgejo read-only release-evidence consumer.

Operational validation must cover concurrent replay attempts, unavailable or corrupt replay state, JWKS rotation and retrieval failure, broker/executor restarts, Unix-socket permissions, service hardening, exact registry token use, and recovery without widening authority.

## Migration and rollback implications

Adoption proceeds through inert repository-side implementation, non-live contracts, and deterministic tests before GitHub activation. This sequencing does not depend on a PR name. The DEV protection capability prerequisite is satisfied as of 2026-09-24; the protections must remain enforced. C31 provisioning completed under separate authorization. Further host/runtime mutation and live deployment remain prohibited until separately reviewed.

The authority can be withdrawn by disabling GitHub environment activation, revoking or disabling the broker's OIDC trust policy, stopping the broker and executor, and removing public broker ingress. Immutable release artifacts and deployment state and audit evidence must be retained.

A future pull agent or orchestrator may replace the transport and service implementation through a superseding decision. ADR 0006 immutable artifact, promotion, state, migration, and rollback semantics remain unchanged.
