# One-time owner bootstrap for permanent Sumlaude agent

**HOLD pending independent security review of PR #297** and unchanged exact
source SHA verification. This is a permanent agent installation, NOT a
one-time cleanup operator or permission for unattended production changes.
These blocks are **NOT EXECUTED** on production at time of authoring.

Target: truexmainserver, login: trusthansen. Separate Omnilyzerdev onboarding
is HOLD because actual root /dev/sda2 is mounted ext4 read-only as observed
on November 15, 2026, and no supported Node 22+ runtime is verified there.
Never remount or fsck a live disk as an incidental part of this setup.

## A. READ ONLY operator/source/host preflight

~~~bash
set -Eeuo pipefail
test "$(hostname)" = truexmainserver
test "$(id -un)" = trusthansen
d=/home/trusthansen/shared-ai-ops-source-20261115
test -d "$d" && test ! -L "$d"
test "$(stat -c '%U:%G:%a' "$d")" = trusthansen:trusthansen:700
test "$(sha256sum "$d/install-root.py" | cut -d' ' -f1)" = dcb5eacc173c49940be727714ecdf1502f720ae3f223d1922ab1f64801c912a7
python3 - "$d" <<'PY'
import ast, hashlib, os, stat, sys
from pathlib import Path
d=Path(sys.argv[1])
tree=ast.parse((d / "install-root.py").read_text())
jobs=next(ast.literal_eval(n.value) for n in tree.body
  if isinstance(n, ast.Assign)
  and any(isinstance(t, ast.Name) and t.id == "FILES" for t in n.targets))
assert len(jobs)==10
for name, digest in jobs.items():
 p=d/name;st=p.lstat()
 assert stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600
 assert hashlib.sha256(p.read_bytes()).hexdigest()==digest,name
print("SHARED_AGENT_SOURCE_10_SHA_MATCH_PASS")
PY
test "$(sha256sum /home/trusthansen/.nvm/versions/node/v24.22.0/bin/node | cut -d' ' -f1)" = 67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c
test "$(/home/trusthansen/.nvm/versions/node/v24.22.0/bin/node --version)" = v24.22.0
test ! -e /usr/local/libexec/shared-ai-ops
test ! -e /etc/shared-ai-ops
test ! -e /etc/polkit-1/rules.d/50-shared-ai-ops.rules
test ! -e /etc/systemd/system/sumlaude-agent-remote.service
! getent passwd sumlaude-agent >/dev/null
echo SUM_AGENT_OWNER_BEFORE_BOOTSTRAP_READONLY_PASS
~~~

## B. ROOT SYSTEM INSTALLATION (MUTATING, DO NOT RUN BEFORE REVIEW PASS)

Exact root-owned copy from the reviewed SHA-pinned source. No generalized
sudo rules or root shell access are delegated to the AI account.

~~~bash
sudo bash <<'SUM_AGENT_BOOTSTRAP'
set -Eeuo pipefail
test "$(hostname)" = truexmainserver
test "$(id -un)" = root
source=/home/trusthansen/shared-ai-ops-source-20261115/install-root.py
target=/usr/local/sbin/shared-ai-ops-bootstrap-20261115.py
expected=dcb5eacc173c49940be727714ecdf1502f720ae3f223d1922ab1f64801c912a7
test -f "$source" && test ! -L "$source"
test "$(stat -c '%U:%G:%a' "$source")" = trusthansen:trusthansen:600
test "$(sha256sum "$source" | cut -d' ' -f1)" = "$expected"
test ! -e "$target" && test ! -L "$target"
test "$(stat -c '%U:%G:%a' /usr/local/sbin)" = root:root:755
install -o root -g root -m 0500 "$source" "$target"
test "$(stat -c '%U:%G:%a' "$target")" = root:root:500
test "$(sha256sum "$target" | cut -d' ' -f1)" = "$expected"
/usr/bin/python3 -I "$target"
echo SUM_AGENT_ROOT_SYSTEM_BOOTSTRAP_PASS
SUM_AGENT_BOOTSTRAP
~~~

## C. Dedicated root-owned Node.js 24 runtime (MUTATING)

Run only after B succeeds. The service never replaces or upgrades system Node18
or Omnilyzer runtime. It uses only the private root-owned copy.

~~~bash
sudo bash <<'SUM_AGENT_NODE24'
set -Eeuo pipefail
test "$(hostname)" = truexmainserver
test "$(id -un)" = root
source=/home/trusthansen/.nvm/versions/node/v24.22.0/bin/node
target=/usr/local/libexec/shared-ai-ops/node
expected=67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c
test -f "$source" && test ! -L "$source"
test "$(sha256sum "$source" | cut -d' ' -f1)" = "$expected"
test ! -e "$target" && test ! -L "$target"
test "$(stat -c '%U:%G:%a' /usr/local/libexec/shared-ai-ops)" = root:root:755
install -o root -g root -m 0555 "$source" "$target"
test "$(stat -c '%U:%G:%a' "$target")" = root:root:555
test "$(sha256sum "$target" | cut -d' ' -f1)" = "$expected"
test "$("$target" --version)" = v24.22.0
echo SUM_AGENT_ROOT_ISOLATED_NODE24_SHA_PASS
SUM_AGENT_NODE24
~~~

## D. Unprivileged agent package, device pairing and boot activation

This is NOT an automatic OAuth flow. The owner must connect the **new**
sumlaude-agent device to Desktop Commander using its own device login.
No pairing code, password or tokens should be entered into this repository.

The existing system /usr/lib/node_modules/npm/bin/npm-cli.js is present.
The root-owned Node24 executable from C starts npm as the non-admin agent:

~~~bash
sudo -u sumlaude-agent -H env PATH=/usr/local/libexec/shared-ai-ops:/usr/bin:/bin \
 /usr/local/libexec/shared-ai-ops/node \
 /usr/lib/node_modules/npm/bin/npm-cli.js install \
 --prefix /home/sumlaude-agent/.local/share/sumlaude-agent \
 --no-audit --no-fund --save-exact @wonderwhy-er/desktop-commander@0.3.1
~~~

After the pinned package is installed, execute one remote pairing session
under the dedicated OS user, verify device in the Desktop Commander web UI,
then stop its foreground session. No root process should perform OAuth.

~~~bash
sudo -u sumlaude-agent -H env PATH=/usr/local/libexec/shared-ai-ops:/usr/bin:/bin \
 /usr/local/libexec/shared-ai-ops/node \
 /home/sumlaude-agent/.local/share/sumlaude-agent/node_modules/@wonderwhy-er/desktop-commander/dist/index.js remote
~~~

Only after pairing is complete, enable the dedicated OS-user service:

~~~bash
sudo systemctl enable --now sumlaude-agent-remote.service
~~~

The first ChatGPT agent-device test should run the dedicated job
sumlaude-ai-ops@status.service and verify journald markers, then separately
approve the cleanup-108-110 job. Existing privileged user device and its
blocked sudo list remain unchanged.

## Reversal and incident policy

If a step HOLDs, stop without blind replay. The root bootstrap installs
root-owned policy and services but never runs SQL, analytics release, backup,
restore or cleanup. Do not delete a new agent home, erase valid prior database
receipts, modify existing auth/login, reboot, remount or change DNS.
The user may disable the new remote device and revoke the dedicated polkit
rule in a separate owner-controlled rollback. Preserve diagnostics.
