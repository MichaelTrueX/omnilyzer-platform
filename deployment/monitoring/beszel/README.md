# File: deployment/monitoring/beszel/README.md
# Purpose: Run private Omnilyzer container CPU/RAM/network monitoring in Beszel.
# Related: metrics_proxy.py, test_metrics_proxy.py, install.py, test_install.py,
#          beszel-omnilyzer-proxy.service, beszel-omnilyzer-agent.service,
#          Omnilyzer Task014 rootless Docker and Sumlaude Beszel PR #260.

# Omnilyzer rootless Docker container monitoring

## User outcome and deployment boundary

Create a **separate** system named `omnilyzer-containers` inside the existing
Tailnet-only Beszel dashboard at
`https://omnilyzerdev.tail52e570.ts.net:8443/`. Target agent host:
`127.0.0.1`, TCP port `45878`. The existing `omnilyzerdev` host system
retains CPU/RAM/disk and the existing `sumlaude-containers` remains separate.

The engine is Omnilyzer's dedicated **rootless** Docker daemon at
`/run/user/991/docker.sock`, owned by `omnilyzer-executor` (UID/GID 991).
This monitoring feature neither changes the daemon nor attaches to the private
deployment socket projection used by Task 014. The user has authorized this
feature as an independent monitoring service. Any root installation still
requires the authorized local operator and the exact reviewed source.

## Reused mechanism, minimal interface

This uses the narrowly filtered Python standard-library adapter already
accepted for Sumlaude's monitoring in PR #260. A **separate copy** is committed
to this repository to avoid runtime cross-product dependency. Only four GET
routes are accepted: `/version`, `/info`, `/containers/json`, and
`/containers/<known-id>/stats?stream=0&one-shot=1`. The adapter strips
environment variables, labels, commands, images, mounts, private IPs,
interface names, secret data and nonessential Docker API fields. All mutations,
logs, inspect and arbitrary requests are rejected before forwarding.

### First-install correction (2026-10-31)

The initial owner-authorized installation passed preflight but its proxy exited
with `PermissionError` on `/run/user/991` because `ProtectHome=yes` in a
systemd **system** service hides `/run/user` as well as home directories.
The manifest-scoped failure rollback removed both new monitor services and
all new installation files, while original Docker, Task014 and Beszel stayed
online. This revision uses `ProtectHome=no` **only** for the two dedicated
monitoring units and explicitly makes `/home`, `/root` and protected
deployment directories inaccessible. The owner-private UID991 runtime
remains 0700 and the filtered socket remains 0600. The agent still receives
only a filtered socket in its independent Bubblewrap mount namespace.
A regression check rejects reintroduction of `ProtectHome=yes` on either
unit. The installer now reports a bounded, specific proxy-socket startup
error instead of a raw `FileNotFoundError` if the proxy cannot start.

The proxy process runs **as UID 991** with a Unix socket at
`/run/user/991/beszel-metrics.sock` mode `0600`. The separate Beszel v0.21.1
agent also runs as UID 991, but **inside a fresh bubblewrap filesystem and
PID namespace** with no visible engine Docker socket, private Task 014 data,
home directories or host processes. It can reach only the filtered metrics
socket and listens on `127.0.0.1:45878`. The proxy is constrained by
systemd system-unit sandboxing and filesystem protection.

Root-owned deployment files are located only under:
- `/opt/omnilyzer-beszel-monitor/` (read-only program files).
- `/var/lib/omnilyzer-beszel-monitor/data/` (UID991-owned private agent state).
- `/etc/systemd/system/beszel-omnilyzer-{proxy,agent}.service`.
The agent uses the **public** hub SSH key from the existing installation.
No private hub key is copied.

## Installation and acceptance

The `install.py` command is a **one-time root operation**. It refuses unknown
user/host identities, mismatched pinned file SHA256s, an unverified Beszel agent
binary/public key, an unsafe Docker socket or runtime directory, occupied port
45878, existing target files or nonempty conflicting services. It only creates
two new systemd services and distinct monitoring directories. It never changes
existing Omnilyzer Task 014 units, Docker settings, deployment state, secrets,
Sumlaude or network ingress.

Install is authorized only after exact-source tests and local operator review:

```bash
sudo python3 /home/trust/.local/share/beszel/install-staging/omnilyzer-20261031/install.py install
```

Expected installer evidence: `PREFLIGHT PASS`, `LIVE SECURITY PASS`,
`LIVE AGENT PASS`, `SUCCESS`. Register Beszel system
`omnilyzer-containers` using host `127.0.0.1`, port `45878`, protocol SSH.
Then verify current container names and CPU/RAM measurements through the
authenticated HTTPS dashboard. Do not claim it is installed or working merely
because this source is merged.

## Focused tests and rollback

Run `python3 -m unittest -q test_metrics_proxy.py test_install.py` in this
directory to cover allowed/denied Docker HTTP methods, metadata redaction,
path spoofing, first-run directory creation, safe cleanup and rollback.
Run `systemd-analyze verify` on the two new unit files. Real acceptance
must also inspect positive metrics and forbidden operations on the **live**
filtered Unix socket with no root/credential leakage.

Authorized rollback if installed:

```bash
sudo python3 /home/trust/.local/share/beszel/install-staging/omnilyzer-20261031/install.py rollback
```

Rollback stops/disables only the two **new** Beszel services and removes only
their new data/files, preserving the six-or-more evolving Omnilyzer containers,
Docker daemon, Task 014, host Beszel system, Sumlaude, identity, family backups,
Tailscale, release audit and tenant data.

## Disk capacity

Omnilyzer's rootless Docker files live on the host `/` filesystem.
**Disk capacity is already monitored on the original `omnilyzerdev` Beszel
system.** The new per-container system measures CPU, RAM and network only.
A misleading per-container total including shared image layers and volumes
must not be inferred from these counters. The existing disk-alert automation
continues unchanged.
