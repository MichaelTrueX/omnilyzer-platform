#!/usr/bin/env bash
# Full root bootstrap in a disposable offline OS sandbox; NO host root mutations.
set -Eeuo pipefail
test "$(hostname)" = truexdevelopment
test "$(id -un)" = trusthansen
src=$(cd "$(dirname "$0")/.." && pwd)
target_host=${1:-truexmainserver}
case "$target_host" in
 truexmainserver) srcuser=trusthansen; agent=sumlaude-agent; product=sumlaude; other=omnilyzer-agent;;
 omnilyzerdev) srcuser=omnigpt; agent=omnilyzer-agent; product=omnilyzer; other=sumlaude-agent;;
 *) echo INVALID_FIXTURE_HOST;exit 61;;
esac
name=shared-agent-bootstrap-test-$$
cleanup(){ code=$?; trap - EXIT; docker rm -f "$name" >/dev/null 2>&1 || :; echo "AI_OPS_BOOTSTRAP_FIXTURE_CLEANUP_RC=$code";exit "$code"; }
trap cleanup EXIT
docker run -d --rm --pull never --network none --hostname "$target_host" \
 --name "$name" python:3.12-slim sleep 180 >/dev/null
for i in $(seq 1 12);do
 if docker exec "$name" python3 --version >/dev/null 2>&1;then break;fi
 sleep .1
done
docker exec -u root "$name" /usr/sbin/useradd -m -s /bin/bash "$srcuser"
docker exec -u root "$name" ln -s /usr/local/bin/python3 /usr/bin/python3
docker exec -u root "$name" mkdir -p /etc/polkit-1/rules.d /etc/systemd/system /home/$srcuser/shared-ai-ops-source-20261115
docker exec -u root "$name" chown "$srcuser:$srcuser" /home/$srcuser/shared-ai-ops-source-20261115
docker exec -u root "$name" chmod 0700 /home/$srcuser/shared-ai-ops-source-20261115
for f in dispatcher.py jobs/sumlaude/status.py jobs/sumlaude/cleanup-108-110.py jobs/omnilyzer/status.py \
 policy.json 50-shared-ai-ops.rules sumlaude-ai-ops@.service omnilyzer-ai-ops@.service \
 sumlaude-agent-remote.service omnilyzer-agent-remote.service;do
 docker exec -u root "$name" mkdir -p "/home/$srcuser/shared-ai-ops-source-20261115/$(dirname "$f")"
 docker cp "$src/$f" "$name:/home/$srcuser/shared-ai-ops-source-20261115/$f"
 docker exec -u root "$name" chown "$srcuser:$srcuser" "/home/$srcuser/shared-ai-ops-source-20261115/$f"
done
docker cp "$src/install-root.py" "$name:/tmp/install-root.py"
docker exec -u root "$name" chmod 0500 /tmp/install-root.py
# The Python test image has no active systemd; mock ONLY daemon-reload.
docker exec -u root "$name" sh -c 'printf "#!/bin/sh\nexit 0\n" > /usr/bin/systemctl; chmod 0755 /usr/bin/systemctl'
docker exec -u root "$name" /usr/local/bin/python3 -I /tmp/install-root.py
docker exec -u root "$name" test -f "/etc/systemd/system/$agent-remote.service"
docker exec -u root "$name" test ! -e "/etc/systemd/system/$other-remote.service"
docker exec -u root "$name" stat -c 'INSTALL=%U:%G:%a %n' /usr/local/libexec/shared-ai-ops/dispatcher.py /etc/shared-ai-ops/policy.json /etc/polkit-1/rules.d/50-shared-ai-ops.rules
docker exec -u root "$name" /usr/local/bin/python3 -I /usr/local/libexec/shared-ai-ops/dispatcher.py "$product" status
if docker exec -u root "$name" /usr/local/bin/python3 -I /tmp/install-root.py >/dev/null 2>&1;then echo INSTALL_REPLAY_FALSE_PASS; exit 70;fi
if docker exec -u root "$name" /usr/local/bin/python3 -I /usr/local/libexec/shared-ai-ops/dispatcher.py "$product" arbitrary-root-shell >/dev/null 2>&1;then echo UNREGISTERED_JOB_FALSE_PASS; exit 71;fi
docker exec "$name" sh -c "id '$agent'; test \"\$(stat -c %a /home/$agent)\" = 700; ! id -nG '$agent' | grep -qw sudo"
docker exec -u root "$name" test ! -e "/etc/systemd/system/$other-remote.service"
echo SHARED_AGENT_BOOTSTRAP_AND_NONADMIN_PERMANENT_DISPATCHER_OFFLINE_PASS