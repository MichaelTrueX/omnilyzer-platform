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

C32ZF records inert host authority for one future dedicated rootless Docker
daemon owned by `omnilyzer-executor`. The executor will use only a private bind
of the daemon's `/run/user/991/docker.sock` at
`/run/omnilyzer/deployment/rootless-docker/docker.sock`, preserving its
`ProtectHome=yes` isolation; the broker has no Docker access. Rootful Docker,
Docker-group membership, sudo, a TCP API,
and a root executor remain prohibited. This extends the runtime transport
under the same restricted broker, executor socket, closed DEV Compose project,
and audit/replay controls. Rootless Docker requires a separately qualified
systemd **user** manager, subordinate UID/GID mappings, and delegated cgroup v2
CPU, memory and PID controllers. The repository adds inert authority only;
installation, migration of bind-mount ownership, service activation, and live
container behavior require separate host review.
RootlessKit must use the exact static `/etc/subuid` and `/etc/subgid` mapping
and the package-owned `/usr/bin/slirp4netns`, with vendor-managed crash-state
locking. Both user unit and launcher put `/usr/bin` first in their fixed PATH
for package-owned helper lookups. The launcher never unlinks an existing
Docker socket before the RootlessKit lock. The already-qualified private
tailnet-only Serve ingress remains
active and unchanged; Funnel remains prohibited. Broker, executor and
deployment activation are still prohibited. The exact package-owned
`dockerd-rootless.sh` performs RootlessKit and namespace bootstrap behind a
fixed no-input launcher. C32W remains the complete installed application
generation, including its unchanged Docker adapter; that adapter cannot use
the future rootless endpoint. A separately reviewed successor application
generation and host migration are mandatory before activation.

C32ZG updates the current repository runtime adapter to the selected rootless
transport without changing the installed C32W generation. Every Docker/Compose
operation uses the absolute `/usr/bin/docker` client with the root-owned client
configuration and exact executor-visible Unix endpoint; no ambient Docker
context or host selection is accepted. The adapter validates that projected
socket before command execution. This is still inert repository source: a
subsequent generation review must pin the merged Git object and explicitly
migrate the installed application before any runtime activation.

C32ZH pins that successor application generation to merge
`47a602d3f2b97fafd6fb8a18240fd5bbb3857ba9`. Git-object evidence proves the
selected 41-file application differs from C32W only in
`deployment/docker_runtime.py`; the canonical runtime configuration and all
ingress bytes remain unchanged. This evidence creates no host authority and
performs no migration. Root-only installation of the successor generation and
live rootless qualification remain separately reviewed gates.

C32ZI defines the pure successor configuration authority. It accepts only the
exact frozen C32W executor configuration as predecessor, projects only
`reviewed_commit` to the C32ZH generation, and derives the matching broker from
one explicit workflow SHA plus the existing Sigstore provenance. Shared
executor/broker identities, runtime/ingress hashes and installation authority
must remain identical. C32ZI performs no host I/O and does not migrate either
configuration file.

C32ZJ defines the pure successor host-migration state machine. It reconstructs
the exact frozen C32W executor/broker pair, derives the exact C32ZI successor
pair while preserving `expected_workflow_sha`, and accepts only four ordered
states: original C32W, successor application only, successor application plus
executor configuration, and complete aligned successor authority. Out-of-order
or mixed authority fails closed. C32ZJ performs no filesystem or service
operation; a separate root-only implementation is required to execute these
transitions.

C32ZK adds a root-only, read-only adapter for the installed broker
configuration. It reuses the hardened broker loader's descriptor traversal,
canonical parser and metadata revalidation while requiring exact real/effective
root identity and preserving the broker GID binding on the configuration
directory and file. It never invokes the live broker identity binder and has no
mutation or activation surface. This allows a later privileged migration to
carry forward the installed `expected_workflow_sha` without trusting a caller
input.

C32ZL adds the privileged read-only migration preflight. It requires exact
root identity and exact inactive systemd state for the broker service, executor
service, and executor socket; reads both protected configuration files through
the hardened root adapters; verifies the entire installed application as C32W
or C32ZH; and classifies the result through C32ZJ. The complete observation is
repeated and must remain byte-for-byte stable. The broker workflow SHA is
preserved from the installed broker authority rather than supplied by the
caller. C32ZL issues only closed `systemctl show` reads and cannot mutate or
activate host state.

C32ZM is the reviewed root-only migration runtime. Under the existing
privileged process lock it permits exactly three ordered publications: the
C32ZG runtime adapter, the C32ZI executor configuration, and finally the C32ZI
broker configuration carrying forward the installed workflow SHA. Each write
uses an exact destination-specific resumable stage, fsync, and atomic replace;
only a stage for the current C32ZJ operation is accepted. Root identity and the
inactive broker/executor systemd boundary are rechecked around mutation. C32ZM
does not install or start Docker, enable/start deployment services, alter
ingress, or activate deployment. Host execution must occur later from the
reviewed root-controlled source tree.

C32ZP adds only pure installation authority for the rootless Docker host
bootstrap. It preserves the seven C32ZF package/version/digest selections,
prohibits Buildx, fixes the rootful units that must be masked, and pins the
temporary maintainer-script start blocker. Docker package retrieval is limited
to a temporary signed Noble stable APT source using the pinned Docker release
key; the source and key are not permanent ambient package authority. Ubuntu
`uidmap` and `slirp4netns` remain under the signed Ubuntu archive boundary.
The currently absent Ubuntu dependency packages `libsubid4` and `libslirp0`
are separately pinned by exact version and package SHA-256, so the eventual
bootstrap cannot silently expand from seven reviewed direct packages to
unreviewed dependency payloads. C32ZP performs no host I/O or package/service
mutation.

C32ZQ adds the privileged read-only pre-install qualification. It requires the
successor host migration to be complete, exact root and executor identities,
all reviewed/new/conflicting Docker packages absent, rootful Docker/containerd
units/processes/sockets absent, temporary installation paths absent, the live
`omnigpt` subordinate range unchanged, the corrected executor range free, and
the required AppArmor/userns and cgroup controls. The complete observation must
match twice. It can run only fixed read-only host commands and cannot install,
mask, start, download or mutate anything.

C32ZR closes the package-byte selection before any download or install runtime
exists. The exact nine package payloads are bound to canonical filenames, byte
sizes, the reviewed package SHA-256s and structurally validated HTTPS URLs on
only `archive.ubuntu.com` or `download.docker.com`. No Buildx payload is
permitted. C32ZR performs no network or filesystem I/O; future staging must be
qualified as an exact bundle and rehashed by the privileged installer.

C32ZS provides that first exact-bundle qualification boundary. The fixed staging
directory must be root:root 0700 and contain only the nine C32ZR filenames as
root:root 0600 regular single-link files. Every package is hashed in bounded
chunks against its reviewed SHA-256 while retained descriptors are revalidated
before release. The entire observation is repeated and must remain identical
under unchanged root identity. C32ZS has no caller-selected path, network,
subprocess, package-manager, write, service, Docker, or activation capability.
The later installer must rehash the held bytes again before dpkg consumption.

C32ZT closes the preinstalled package dependency boundary. The ten host
dependencies required by the exact bundle are bound to package name, architecture
and the strongest minimum Debian-version floor present in the reviewed package
metadata. The pre-install qualifier requires installed `ii` state and uses only
a fixed `dpkg --compare-versions INSTALLED_VERSION ge MINIMUM_VERSION` read-only
comparison shape. Observed dependency versions are part of the repeated evidence.
`docker-cli` and `rootlesskit` are additionally prohibited because the selected
Docker CE packages conflict with them. C32ZT cannot configure, install, remove,
upgrade, repair or otherwise mutate packages or services.

C32ZU is the only reviewed package-byte staging runtime. It has no caller
arguments and runs under the existing privileged process lock. The fixed C32ZR
URLs are fetched directly with Python HTTPS using the system CA bundle and TLS
1.2 minimum; proxies, redirects, alternate hosts, shell execution and package
manager network resolution are absent. Response status, length and encoding are
checked before the exact C32ZR byte count and SHA-256 are accepted; transfer
encoding, ranges and redirects are rejected. The runtime uses one deterministic
root-only incoming directory and may rewrite only a
proved-safe root-owned 0600 partial reviewed file; ambiguous objects are never
removed or repaired. C32ZQ must match before and after network activity. Only a
fully rehashed incoming directory is atomically published with Linux
`RENAME_NOREPLACE`, after which C32ZS must independently qualify the exact
bundle. C32ZU has no package-install,
service, subordinate-ID, Docker-daemon or deployment-activation capability.

C32ZV is the read-only post-staging installation gate. Public C32ZQ keeps its
original pre-staging contract and requires the final bundle to be absent. C32ZV
reuses only the shared host observation, requires the interrupted C32ZU incoming
path to be absent, independently qualifies the exact C32ZS final bundle between
two identical host observations, and then repeats the complete combined
observation. No package installer may treat staging alone as installation
authority. C32ZV has no network, subprocess, filesystem-write, package, service,
Docker, subordinate-ID or activation capability.

C32ZW is the first reviewed package-mutation runtime. A clean invocation consumes
C32ZV under the shared privileged mutation lock before creating the exact
maintainer-script blocker and the three persistent rootful `/dev/null` masks.
Systemd must report those units masked and inactive, the blocker must return its
reviewed denial result, masked starts must fail, and no Docker/containerd process
or socket may exist before package consumption. The nine C32ZR files remain open
through retained descriptors and are rehashed immediately before one fixed
offline `/usr/bin/dpkg --install` invocation using only `/proc/self/fd/N` paths.
No APT/network/repository resolution or caller-selected package/path exists.

Interruption recovery accepts only an exact C32ZW-owned prefix: the exact blocker,
an ordered prefix or complete set of the three exact masks, exact reviewed target
package versions/architecture in install-desired dpkg states, unchanged staged
bundle, absent conflicting packages, and the unchanged non-package host authority.
The blocker remains on every failed or partial path and is removed only after all
nine packages are exact `ii`, rootful runtime remains impossible, and both the
static host observation and C32ZS bundle requalify. Because dpkg may create
`unknown`/`not-installed` (`un`) database stubs for reviewed conflict names while
processing the install, the post-install/resume conflict gate accepts only either
no record or an exact `un` record with empty version and architecture; every
other dpkg state remains rejected. C32ZQ/C32ZV continue to require no record at
all before mutation. The masks remain. C32ZW does
not allocate subordinate IDs, provision rootless assets, enable/start services,
start Docker, expose a Docker socket, alter ingress, or activate deployment.
Those steps require later independently reviewed qualification and bootstrap.

C32ZX supplies the independent read-only post-install gate before any rootless
host bootstrap. It requires all nine exact target packages fully installed, the
three persistent rootful masks exact/effective/inactive, the temporary blocker
and installer-only paths absent, no rootful Docker/containerd process or socket,
and the C32ZS bundle unchanged. It reuses the unchanged successor, dependency,
executor, subordinate-ID, AppArmor/userns and cgroup authority, while keeping the
executor subordinate range free for the later bootstrap. Every critical C32ZF
executable is rebound to its exact package owner and reviewed mode and hashed
into the repeated evidence; the vendor rootless script must additionally match
its pinned SHA-256. RootlessKit/Compose shadow paths and all Buildx plugin paths
are rejected unless an alternate Compose lookup resolves to the identical
reviewed plugin object. Two complete observations must match. C32ZX has no
mutation, network, service-start, Docker, subordinate-ID, or activation surface.

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


C32ZZ is the static privileged bootstrap following the independent C32ZX
package proof. It assigns only the reviewed executor subordinate-ID range,
installs the byte-pinned persistent rootless directories/assets, and reloads the
system manager while every deployment/rootless runtime remains inactive. The
executor's private Docker projection directory is explicitly systemd runtime
state, created by `RuntimeDirectory=omnilyzer/deployment/rootless-docker` with
mode `0700` when the executor later starts; C32ZZ does not persist that `/run`
path. Linger, the UID-991 user manager and the rootless Docker daemon remain
separate reviewed transitions.


C33A is the independent read-only qualification after C32ZZ. It intentionally
does not import the C32ZZ mutation module. It binds the exact subordinate-ID
authority, persistent rootless directories and assets, package/runtime proof,
systemd drop-in visibility and inactivity into two identical observations,
while also requiring that linger, `/run/user/991`, and the executor projection
directory remain absent. User-manager and daemon startup remain separately
reviewed transitions.


C33B records that `user@991.service` inherits package-owned `user@.service`
template drop-ins in addition to the reviewed instance-specific cgroup drop-in.
The authority therefore pins the exact composed four-path baseline and the
three inherited files by package, exact version/architecture, dpkg ownership,
root metadata and SHA-256. This is a compatibility correction, not a relaxation:
unknown or modified drop-ins remain prohibited.


C33C separates UID-991 user-manager lifecycle from Docker-daemon lifecycle.
After the independently qualified static host state, the only privileged
mutations are enabling linger for `omnilyzer-executor` and starting
`user@991.service`. The resulting `/run/user/991` is accepted only as
logind/systemd-owned ephemeral runtime authority with UID/GID 991 mode 0700 and
reviewed cgroup delegation. The rootless Docker user service remains disabled
and inactive; Docker startup and deployment activation remain separate reviewed
transitions.


C33D independently qualifies the C33C linger/user-manager state without
importing the mutator. It requires two identical complete observations of the
static rootless authority plus exact logind/systemd runtime ownership and cgroup
delegation, while proving the dedicated rootless Docker user service remains
disabled/inactive and no Docker socket or process exists. Daemon startup remains
a separate reviewed transition.


C33E starts only the reviewed rootless Docker user unit after the independently
qualified C33D user-manager state. It does not enable that unit. Success binds
the active unit to the exact UID-991 private Unix socket, Docker 29.8.1 rootless
server identity, overlay2, systemd cgroups v2, reviewed data root and exact
dockerd command line with an empty pre-workload inventory. Rootful Docker stays
masked and the broker/executor/deployment path remains inactive. Reboot
persistence and workload execution require later reviewed transitions.


C33F independently proves the running rootless daemon after C33E. The proof
requires the active user unit to remain disabled, binds its MainPID to the
UID-991 RootlessKit process with the reviewed static-subid/slirp/detached-netns
authority, binds exactly one UID-991 dockerd to the reviewed argv and private
Unix socket, and verifies Docker 29.8.1 rootless overlay2/systemd-cgroup-v2
identity with an empty pre-workload inventory. No executor projection, rootful
Docker activation or deployment activation is permitted.

C33F independently qualifies the running rootless Docker daemon after C33E. It does not import the daemon-start mutator. The proof binds the active-but-disabled user unit to RootlessKit and the exact dockerd command line, validates the private UID-991 Unix socket and rootless Docker server properties, and requires two identical observations while broker/executor/deployment remain inactive. Enabling the user unit for reboot persistence is a later reviewed transition.


C33G records the live rootless runtime semantics discovered during the first
C33E daemon start. RootlessKit/Docker expose the private daemon socket with mode
`01660`, PID file `01644`, exec-root `01700`, and RootlessKit state `0700`; the
extra sticky bit does not broaden read/write permission and is now pinned as
part of the reviewed host contract. The active user manager reports the unit via
the `/etc/xdg/systemd/user` alias, which is accepted only when the root-owned
symlink target is exactly `../../systemd/user` and both alias and reviewed unit
resolve to the same root-owned mode-0644 inode.
