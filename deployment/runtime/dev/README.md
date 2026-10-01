# Task 014 DEV runtime (reviewed, non-live)

This directory defines the production-owned synthetic Task 014 DEV deployment boundary. C31 installed runtime assets, but no service or deployment is activated. DEV remains disabled; activation must bind these bytes to a reviewed merge SHA. This Nginx selection is only for the synthetic Task 014 DEV deployment boundary, not a production-wide base-image decision.

## Qualified deployment Nginx

Read-only qualification on 2026-09-08 used `cgr.dev/chainguard/nginx:latest` for discovery only. It resolved to index `sha256:b91cf888522ed0cc1b6bddadfa8320ac2a131a1003b103ae340217a421f12fcc` both before and after qualification. Anonymous exact-digest retrieval passed. Active configuration uses only linux/amd64 manifest `sha256:af16298b4fd38b12be52aa913c158b530b83d85d567752f611508593d542b20a`, config `sha256:e8f6995729991de523ce7e0193cb184044d6e7a161711c8faa6eb980963d1a8a`. It runs as user `65532`, with entrypoint `[/usr/sbin/nginx]`, command `[-c,/etc/nginx/nginx.conf,-e,/dev/stderr,-g,daemon off;]`, and no declared exposed port. This deployment explicitly listens on container port 8080.

Cosign 3.1.2 supplier signature verification passed, including Fulcio and transparency-log checks, for issuer `https://token.actions.githubusercontent.com` and identity `https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`. The signed SPDX 2.3 supplier SBOM passed and bound the exact amd64 manifest (86 packages). Grype **0.118.0** report SHA-256 `4fa048a9501015334d586b55352255145b0a687240a74cbe59f0f643b90f25c6` passed the unchanged policy SHA-256 `475ad38ef4ae8d89dcf7d4e03eeb76701085fdcd4ebdb8ae9aa41a7bce2cde8f`: Critical/High block, exceptions `[]`, `blocked_findings=[]` (one Medium). The valid DB was schema `v6.1.9`, built `2026-09-08T06:30:10Z`, checksum `sha256:3564b57fd65da3cba50174d9fdab8b4e8dab6f7f7b798ebd3cec3085ea10c7e6`.

Selected compressed layers (digest, bytes):

```text
sha256:60bbc66affbe44cdd34712c99032071b0e606fa682c4948c08e644d05153e851 2939084
sha256:62444e89bd1466da92757774fcc18ad8efbd77aab88a618547a2dbe745536364 3357623
sha256:7fbd4ff13dcf9ed438edfd61415c0022fe63766640739fd44b77c80cc8beae46 639541
sha256:c7d5351d313832b8536cdeb914ff607c0b4842f7c48894f296cdda41ab86f95c 307589
sha256:0e3a84f7427f59342d7be4787e01fad97fb26e0f084e961d1527e7ed1810a0a5 97913
sha256:b10d4a946640307a04381e8ff5b3dc262f7332586acb67ba29838d9b1d239cbc 95801
sha256:ed4725379a22e41b02806192aff768a5e11226d9511b806bf6138e8dfba5f24e 108111
sha256:bc0f2d8a7aba66a519a774a09300dc32043cd2a7483c19b9efef2345dd4cf48e 64401
sha256:086ef90c41ce61a410fa90c32b6c22550ec6ea96ae7ae1d44204e86d2201f709 11873
sha256:944f369a066cb187845bdf322c0a606fb52867bcbde8f51ec9bbee22f5c2220a 11724
```

Chainguard Free does not provide a sufficient old-digest retention guarantee. Exact-digest unavailability must fail closed; there is no mutable-tag fallback. No mirroring is implemented. Production retention/mirroring or a versioned supplier remains a separate decision.

## Runtime, migration, and switching

Compose project `omnilyzer-task014-dev` has exactly `canary-blue`, `canary-green`, and `deployment-nginx`, and no build directive. `CANARY_IMAGE` must be exactly `oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:<64 lowercase hex>`. Each adapter instance is constructed with one validated exact candidate and places that immutable reference in its minimal controlled environment for every command, including Compose-only Nginx validation and reload operations. Pull, local RepoDigest inspection, candidate start, and migration reject any different digest, even another syntactically valid Task 014 digest. PR B neither pulls nor runs release 0.14.2.

Application slots run as `10001:10001`, read-only, cap-drop ALL, no-new-privileges, hardened 16 MiB `/tmp`, 128 PID, 0.5 CPU and 128 MiB limits, bounded json-file logs, and no host port. The only network is internal `task014_frontend`; there is no backend network, Docker socket, registry credential, or application port publication. Deployment Nginx is likewise non-root/read-only/hardened and alone publishes `127.0.0.1:3020` to 8080.

C32ZF adds inert host authority for a future dedicated rootless daemon while
retaining these exact Compose bytes and hashes. C32ZG changes only the current
repository adapter source to use the exact `/usr/bin/docker` client, root-owned
client config, and executor-visible private rootless socket. It validates that
projected socket before each Docker/Compose operation and does not inherit
`DOCKER_HOST` or `DOCKER_CONTEXT`. The installed C32W application remains
unchanged and cannot use that daemon; a separately reviewed successor
application generation must pin the merged C32ZG source and migrate the host
before activation. C32ZH now pins merge
`47a602d3f2b97fafd6fb8a18240fd5bbb3857ba9` as that successor generation and
proves that only `deployment/docker_runtime.py` changes among the 41 selected
application files; runtime configuration and ingress bytes remain unchanged.
C32ZH is evidence only and does not perform the host migration. C32ZI derives
the aligned successor executor/broker configuration pair and changes only the
reviewed application commit while preserving runtime/ingress authority and all
existing identities. It is pure repository authority and performs no host
configuration change. C32ZJ adds the pure four-phase migration state machine:
C32W, successor application, successor executor configuration, then successor
broker configuration. It preserves the broker workflow SHA and rejects every
other partial or reordered state. No root mutation is implemented in C32ZJ.
C32ZL is the read-only root preflight for that state machine. It requires the
broker/executor services and executor socket to remain inactive, rereads both
root-owned configurations, verifies the complete installed application against
C32W or C32ZH, and rejects concurrent change. C32ZM implements only the fixed
root migration order - adapter, executor config, broker config - using exact
resumable stages and atomic replacement while rechecking the inactive service
boundary. It still performs no Docker installation or deployment activation.
With the reviewed 493216 subordinate UID/GID
start, container 10001 maps to host 503216 and Nginx 65532 maps to host 558747.
The canary runtime bind source must be 991:503216 mode 0770 so the daemon can
resolve it and mapped GID 10001 can write during the explicit migration;
migration files created by UID 10001 map to host UID 503216. The Nginx runtime
source stays executor-owned 0755 with 0644 generated fragments. This mapping and enforcement of all three
cgroup limits require live proof before deployment activation. C32ZP now pins
the temporary signed-APT installation authority, including the exact Docker
release key bytes/fingerprints, seven direct package selections, and the two
currently absent Ubuntu dependency packages. C32ZQ adds the root-only read-only
pre-install qualification of the migrated host, package/runtime absence,
corrected subordinate-ID availability, executor identity, AppArmor/userns and
cgroup controls. Both remain repository-only and mutate no package or service.
C32ZR additionally pins the exact nine `.deb` payload filenames, byte sizes,
SHA-256 values and HTTPS source URLs for a future offline staging bundle. It
still performs no download or host mutation. C32ZS defines the root-only
read-only exact-bundle qualifier: private root:root 0700 staging, root:root 0600
package files, exact nine-entry set, bounded SHA-256 of every payload, retained-
descriptor revalidation, and two identical observations. It still performs no
package, service, Docker, network, or deployment mutation. See the
C32ZF/C32ZP/C32ZQ/C32ZR/C32ZS sections of
[deployment/README.md](../../README.md). C32ZT additionally closes the
preinstalled package dependency boundary with exact package names, architectures,
minimum Debian versions, `ii` status, closed `dpkg --compare-versions` checks,
and explicit absence of `docker-cli` and `rootlesskit`. The dependency versions
join the repeated pre-install evidence; no package or service mutation is added.
C32ZU adds the root-only exact package stager: fixed Python HTTPS with no proxy
or redirect path, a deterministic private incoming directory, safe resume only
for exact root-owned partial files, two C32ZQ observations around download,
Linux no-replace atomic publication, and final independent C32ZS qualification.
It stages bytes
only and still performs no package installation or service activation. C32ZV
adds the post-staging read-only gate: public C32ZQ still requires no final bundle,
while C32ZV allows only the exact C32ZS final bundle, rejects any C32ZU incoming
object, brackets the bundle with identical host-only observations, and repeats
the combined evidence. It performs no installation or activation. C32ZW then
adds the first package-mutation runtime: exact temporary `policy-rc.d`, persistent
rootful Docker/containerd masks before `dpkg`, denied-start verification, held
and immediately rehashed staged descriptors, one fixed offline `dpkg --install`
shape, exact-prefix interruption recovery, and removal of the start blocker only
after all nine packages are exact `ii` and the unchanged host/bundle boundary
requalifies. Post-install conflict checks accept only no dpkg record or the exact
`un` not-installed stub that dpkg may create while processing Conflicts/Replaces;
C32ZQ/C32ZV keep their stricter no-record pre-install rule. C32ZW still does not
allocate subordinate IDs, provision rootless
assets, start Docker, expose its socket, or activate deployment. C32ZX adds an
independent read-only post-install proof before rootless bootstrap: exact `ii`
package versions, exact persistent masks/inactivity, unchanged host/sub-ID/kernel
authority and C32ZS bundle, exact package ownership/mode for every critical
executable, repeated executable SHA-256 evidence, pinned vendor-script digest,
and rejection of RootlessKit/Compose shadowing and Buildx. It mutates nothing.

`/var/lib/omnilyzer/deployment/dev/canary-runtime` is mounted read-only at `/run/omnilyzer-canary` in application slots. The explicit migration operation alone mounts it read-write and runs `/app/migration.py`; migration is never startup behavior. Identity is `task014-executable-canary-v1`, definition checksum is `b25e7d2d55bce3e233f58f9607e715daebc2a1a69c37603adbb569604ef76421`, and durable files are `migration.lock` and `migration.json`.

The Nginx base is valid with an empty directory-mounted `/var/lib/omnilyzer/deployment/dev/nginx-runtime` and returns JSON 503 maintenance. A generated `active.conf` can name only blue or green. The adapter atomically fsync/replaces it, validates deployment Nginx syntax, then reloads only `deployment-nginx`. Candidate routing follows separate `/livez`, `/readyz`, and exact `/metadata` gates. Validation/reload failure restores, validates, and reloads the previous fragment; running routing remains unchanged on failed reload. The adapter never modifies host Nginx. `host-nginx.conf` is review-only and uninstalled; PR C selects TLS.

### Closed candidate probing

C14 adds the reviewed concrete candidate HTTP client without changing these
runtime assets. A probe selects only the exact `canary-blue` or `canary-green`
Compose service and runs one fixed, bounded `/usr/bin/python` helper there. The
helper performs one GET to that candidate's own `127.0.0.1:8080` loopback and
accepts only `/livez`, `/readyz`, or `/metadata`. It has no proxy, DNS hostname,
arbitrary target, shell, or retry path, and returns only a bounded status/body
envelope to the host-side parser.

Neither candidate publishes a host probe port; `deployment-nginx` remains the
only service with the `127.0.0.1:3020:8080` host mapping. C14 is repository-only
and did not activate or execute a real probe. C15 now wires the reviewed client
into `DevExecutorComposition`, sharing its one command runner and exact image
binding with the Docker runtime. Candidate ports remain unpublished and probes
remain exact-service, same-container loopback operations. C15 activates no
deployment and changes no runtime asset. `compose.yaml` is unchanged and its
SHA-256 remains
`ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc`.

The canonical runtime configuration is exactly 99 bytes, SHA-256 `8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f`, and has a closed schema. No runtime secret exists. The accepted no-secrets reference remains `{"schema_version":1,"kind":"none","required":[],"reason":"task014-synthetic-canary-has-no-runtime-secrets"}`. OIDC/zot/Forgejo tokens are deployment credentials, never application configuration.

## Durable state and audit

State remains schema v1 at `/var/lib/omnilyzer/deployment/dev/state.json`, with directory/file modes 0700/0600, same-directory temporary creation, file fsync, atomic replace, and directory fsync; no container mounts it. The closed executor request already binds operation, actor ID, workflow ref/SHA, run ID/attempt, promotion-request hash, OIDC JTI, and timestamps. No state migration or duplicate authority fields are added; no Task 014 state is deployed.

PR B supplies the durable filesystem audit sink. It writes canonical one-record-per-line JSON to `/var/lib/omnilyzer/deployment/audit/events.jsonl`, modes 0700/0600, using serialized `O_APPEND` and fsync. It rejects malformed, partial, noncanonical, duplicate, oversized (over 16 KiB), or chain-invalid history. `previous_event_sha256` links full records. This is tamper-evident and owner-controlled, not root-tamper-resistant; remote/WORM audit is deferred.

The complete broker/executor OIDC execution identity is in the closed executor-request contract. Audit schema 2 and its complete identity projection are implemented in the repository. Live broker/executor wiring and deployment activation remain separately reviewed work.

Rotation occurs before crossing 10 MiB or on a new UTC day, uses atomic rename and never copytruncate, retains 14 rotations, and delays gzip until the following rotation. The next active record links to the renamed file's final record. After retention deletes old history, the oldest retained predecessor is an explicit anchor; continuity is verified across all retained files, not deleted history. Host ownership and live rotation/restart validation remain PR C work.

## Exact reference hashes

The future references require the real reviewed merge SHA; no placeholder `reviewed_commit` is accepted.

| Path | SHA-256 |
|---|---|
| `deployment/runtime/dev/canary-runtime.json` | `8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f` |
| `deployment/runtime/dev/compose.yaml` | `ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc` |
| `deployment/runtime/dev/host-nginx.conf` | `bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb` |
| `deployment/runtime/dev/nginx/nginx.conf` | `cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b` |

The ingress file set is exactly the final three paths.

### C32ZZ static rootless host bootstrap

After C32ZX has proved the package-only state, C32ZZ may assign the exact
executor subordinate-ID range and publish the reviewed persistent rootless
directories/assets. Its only systemd mutation is `daemon-reload`; linger, the
UID-991 user manager, rootless Docker, executor, broker and deployment remain
inactive. The executor socket drop-in now owns
`RuntimeDirectory=omnilyzer/deployment/rootless-docker` with mode `0700`, so the
private projection directory is recreated by systemd after reboot instead of
being treated as durable `/run` bootstrap state.

### C33A static bootstrap qualification

C33A independently rechecks the complete C32ZZ static host state twice without
importing the bootstrap mutator. It requires exact sub-UID/sub-GID records,
closed persistent directory contents and asset hashes, loaded reviewed drop-ins,
all deployment services inactive, no linger marker, no UID-991 runtime, and no
rootless Docker projection directory. Passing C33A authorizes only the next
reviewed user-manager bootstrap step; it does not start or enable anything.

### C33B composed systemd drop-in baseline

The UID-991 user-manager proof accounts for systemd's normal composition of
instance and template drop-ins. C32ZZ/C33A accept only the reviewed instance
cgroup drop-in plus the three exact Ubuntu package-owned template drop-ins
(`10-login-barrier.conf`, `10-oomd-user-service-defaults.conf`, and
`timeout.conf`). Their hashes, package versions and ownership are pinned; any
additional or changed drop-in fails closed.

### C33C user-manager bootstrap

C33C enables linger only for `omnilyzer-executor` and starts only
`user@991.service`. It proves the resulting logind/systemd-owned
`/run/user/991` runtime and CPU/memory/PID delegation while keeping the reviewed
rootless Docker user unit disabled/inactive and every deployment service
inactive. No Docker daemon or socket is created in this phase.

### C33D user-manager qualification

C33D is the independent read-only gate after C33C. Two identical observations
must prove exact linger and `/run/user/991`, UID-991 cgroup delegation, all
static bootstrap/package invariants, and a loaded but disabled/inactive rootless
Docker user unit. Passing C33D authorizes only a future separately reviewed
rootless-Docker daemon startup phase.

### C33E rootless daemon start

After C33D, C33E may start only the reviewed rootless Docker user service through
UID 991's active user manager. The unit remains disabled. C33E proves the exact
private socket, Docker 29.8.1 rootless identity, overlay2/systemd-cgroup-v2
configuration, empty pre-workload inventory and exact dockerd argv while the
projected executor socket and all deployment units remain inactive. Reboot
enablement and workload activation are later review boundaries.

### C33F daemon qualification

C33F independently rechecks the running rootless Docker daemon twice without
importing C33E. It binds the active-but-disabled user unit to the UID-991
RootlessKit MainPID, exact RootlessKit authority, exact dockerd argv, private
mode-01660 Unix socket, Docker 29.8.1 rootless/overlay2/systemd-cgroup-v2 server
identity and empty pre-workload inventory. Rootful Docker and all deployment
services remain inactive, and the executor projection directory remains absent.

### C33F running daemon qualification

C33F independently proves the live C33E daemon without importing the mutator. It binds systemd MainPID to the UID-991 RootlessKit process, verifies the reviewed RootlessKit bootstrap tokens and exact dockerd argv, then validates the private Unix socket and Docker 29.8.1 rootless engine configuration. The engine must still have zero containers/images and the user unit must remain disabled while deployment services remain inactive.

### C33G runtime semantics correction

The first live C33E start established the reviewed rootless runtime semantics:
`docker.sock` is host-visible as UID/GID 991 mode `01660`, `docker.pid` as
`01644`, `docker-exec` as `01700`, and the RootlessKit state directory as
`0700`. C33G pins and verifies those exact modes. It also treats systemd's
`/etc/xdg/systemd/user` FragmentPath only as an exact symlink alias of the
reviewed `/etc/systemd/user` unit, requiring the same inode and root-owned
mode-0644 bytes.

### C33H post-daemon data-root authority

C33H makes the data-root phase transition explicit. Before daemon start,
`rootless-docker-data` is the C32ZZ-owned empty mode-0700 directory. After C33E,
Docker owns its managed state and the root becomes mode `0710`. C33E/C33F allow
only that directory to transition, require the exact reviewed empty-engine
top-level names/types/modes and UID/GID 991 ownership, and keep all other
provisioned directories under the original closed static-asset checks.

### C33I process proof and mandatory live preflight

C33F no longer borrows C32ZQ's pre-install `pgrep` allowlist for live runtime
process discovery. It enumerates `/proc` directly for exactly `rootlesskit`,
`dockerd`, `containerd`, and `slirp4netns`, then enforces UID 991 and the
reviewed command-line authority. The pre-install allowlist is unchanged. Before
a live fail-closed C33F run, `rootless_docker_daemon_preflight.py` must execute
the full component matrix non-fail-fast and report all assertion failures in one
pass; C33F is run only after that preflight is fully green.

C33I restart safety hold:

C33I restart safety hold: the installed launcher still carries the earlier
`0660` pre-existing-socket assumption. The current daemon remains running; do
not intentionally stop/restart it or reboot the host until the launcher is
separately corrected to the reviewed `01660` runtime authority and requalified.

### C33K launcher restart-authority correction

C33K removes the current restart safety hold without restarting the daemon as
part of the correction. The candidate launcher accepts the exact empty `0700`
data-root state used for first start and the exact Docker-managed `0710` state
used after the daemon has initialized its data root. It also validates an
existing rootless socket as UID/GID 991 mode `01660`, never `0660`.

The live transition is preflight-first: run the four-check read-only candidate
preflight, replace only the exact predecessor launcher asset, then run the full
six-check post-replacement restart preflight. The replacement function also
enforces the candidate check under the shared lock and requires the full
post-replacement matrix before returning success. The daemon remains active and
the user unit remains disabled during this asset correction. Restart/reboot
remains prohibited until the post-replacement preflight is fully green.

### C33L vendor-transformed runtime environment

The C33K candidate preflight validates the live RootlessKit environment after the
pinned vendor wrapper has transformed it. The launcher input still contains the
reviewed `DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS` without `--detach-netns`; the vendor
wrapper prepends that flag when detach mode is enabled and exports
`_DOCKERD_ROOTLESS_CHILD=1` before executing RootlessKit. These are the only
reviewed runtime transformations.

### C33M reviewed daemon restart

C33M performs one intentional rootless Docker user-unit restart only after the
C33L launcher replacement and independent restart-authority closure are green.
The transition runs under the deployment process lock, performs a six-check
restart preflight plus public C33F before mutation, records all four runtime
process IDs, executes one exact user-unit `restart`, then requires a disjoint new
process set, two identical post-restart six-check observations, and public C33F.
All stable C33F evidence must be unchanged across the restart and Docker
inventory must remain zero. The unit remains disabled; no broker/executor or
deployment activation is part of this step.

### C33N persistence enablement

C33N changes only the rootless Docker user's install state from disabled to
enabled. Because the executor's NSS home remains `/nonexistent`, persistence is
expressed as the global user-unit `default.target.wants` link. The reviewed unit's
exact `ConditionUser=omnilyzer-executor` remains the hard activation guard. The
transition runs `systemctl --global enable` without `--now`; the running daemon
must keep the same MainPID, RootlessKit/dockerd PIDs and all C33F-observed state.
No broker/executor or deployment activation is part of this step.
