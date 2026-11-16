#!/usr/bin/env bash
# Actual root-owned dispatcher and success-only cleanup in isolated no-network Docker.
set -Eeuo pipefail
test "$(hostname)" = truexdevelopment
test "$(id -un)" = trusthansen
root=$(cd "$(dirname "$0")/.." && pwd)
sql=/home/trusthansen/s03-current35-forward-only-108-110-review-20261115
original=/home/trusthansen/s03-pr389-protected-operator-20261115/scripts/production/s03-current35-108-110-owner-operator.sh
test "$(sha256sum "$original"|cut -d' ' -f1)" = 72b4c9d1ee3f8bc195b12cf15b8f64ddadc2658264636c67e7d6c599bf564475
name=shared-ai-ops-test-$$
cleanup(){
 code=$?
 trap - EXIT
 docker rm -f "$name" >/dev/null 2>&1 || :
 echo "SHARED_OPS_DEV_DISPOSABLE_CLEANUP_EXIT=$code"
 exit "$code"
}
trap cleanup EXIT
docker image inspect python:3.12-slim >/dev/null
docker run -d --rm --pull never --name "$name" --hostname truexmainserver \
 --network none --tmpfs /var/lib/pgscratch:rw,noexec,nosuid,size=32m \
 python:3.12-slim sleep 180 >/dev/null
for i in $(seq 1 15);do
 if docker exec "$name" python3 --version >/dev/null 2>&1;then break;fi
 sleep 0.1
done
docker exec -u root "$name" groupadd postgres
docker exec -u root "$name" ln -s /usr/local/bin/python3 /usr/bin/python3
docker exec -u root "$name" mkdir -p /usr/local/libexec/shared-ai-ops/jobs/sumlaude /usr/local/libexec/shared-ai-ops/jobs/omnilyzer /etc/shared-ai-ops
for f in dispatcher.py jobs/sumlaude/status.py jobs/sumlaude/cleanup-108-110.py jobs/omnilyzer/status.py;do
 docker cp "$root/$f" "$name:/usr/local/libexec/shared-ai-ops/$f"
 docker exec -u root "$name" chown root:root "/usr/local/libexec/shared-ai-ops/$f"
 docker exec -u root "$name" chmod 0500 "/usr/local/libexec/shared-ai-ops/$f"
done
docker cp "$root/policy.json" "$name:/etc/shared-ai-ops/policy.json"
docker exec -u root "$name" chown root:root /etc/shared-ai-ops/policy.json
docker exec -u root "$name" chmod 0600 /etc/shared-ai-ops/policy.json
docker exec -u root "$name" bash -c '
set -eu
base=/var/lib/sumlaude-s03-current35-108-110-once
install -d -o root -g postgres -m 0710 "$base" "$base/protected"
install -d -o root -g root -m 0700 "$base/receipts"
'
base=/var/lib/sumlaude-s03-current35-108-110-once
for file in s03-current35-readonly-preflight.sql s03-current35-atomic-108-109-110-NOT_APPROVED.sql s03-current35-readonly-postcheck.sql;do
 docker cp "$sql/$file" "$name:$base/protected/$file"
 docker exec -u root "$name" chown root:postgres "$base/protected/$file"
 docker exec -u root "$name" chmod 0440 "$base/protected/$file"
done
docker cp "$original" "$name:/usr/local/sbin/s03-current35-108-110-owner-operator"
docker exec -u root "$name" chown root:root /usr/local/sbin/s03-current35-108-110-owner-operator
docker exec -u root "$name" chmod 0500 /usr/local/sbin/s03-current35-108-110-owner-operator
docker exec -u root "$name" bash -c '
set -eu
base=/var/lib/sumlaude-s03-current35-108-110-once/receipts
printf "%s\n" "UTC=2026-11-15T13:04:00Z" > "$base/commit-attempted"
printf "%s\n" "STATUS=POSTCOMMIT_SCHEMA_ONLY_PASS" "SQL_SHA256=526ba40b9bbdb592a69f41b20c003a541a46fee6ab5dd0fa55fad531cc5591a7" > "$base/schema-verified.txt"
printf "%s\n" "S03_CURRENT35_LEDGERLESS_ATOMIC_COMMIT_AND_POSTCHECK_PASS" > "$base/install.log"
printf "%s\n" "S03_CURRENT35_LEDGERLESS_READONLY_POSTCHECK_PASS" > "$base/postcheck.log"
chmod 0600 "$base"/*
'
run() { docker exec -u root "$name" python3 -I /usr/local/libexec/shared-ai-ops/dispatcher.py "$@"; }
docker exec -u root "$name" stat -c 'FIXTURE_META=%U:%G:%a %n' /etc/shared-ai-ops/policy.json /usr/local/libexec/shared-ai-ops/jobs/sumlaude/status.py /usr/local/libexec/shared-ai-ops/jobs/sumlaude/cleanup-108-110.py
run sumlaude status
if run sumlaude arbitrary-root-shell >/dev/null 2>&1;then echo UNREGISTERED_JOB_FALSE_PASS;exit 71;fi
if run omnilyzer status >/dev/null 2>&1;then echo CROSS_PRODUCT_HOST_FALSE_PASS;exit 72;fi
docker exec -u root "$name" chmod 0666 /etc/shared-ai-ops/policy.json
if run sumlaude status >/dev/null 2>&1;then echo USER_WRITABLE_POLICY_FALSE_PASS;exit 73;fi
docker exec -u root "$name" chmod 0600 /etc/shared-ai-ops/policy.json
docker exec -u root "$name" bash -c "printf '%s\n' 'WRONG' > '$base/receipts/install.log'"
if run sumlaude cleanup-108-110 >/dev/null 2>&1;then echo FALSE_COMMIT_RECEIPT_FALSE_PASS;exit 74;fi
docker exec -u root "$name" bash -c "printf '%s\n' 'S03_CURRENT35_LEDGERLESS_ATOMIC_COMMIT_AND_POSTCHECK_PASS' > '$base/receipts/install.log'"
echo SHARED_OPS_NEGATIVE_HOST_JOB_POLICY_RECEIPT_CHECKS_PASS
run sumlaude cleanup-108-110
docker exec -u root "$name" test -d "$base/receipts"
if docker exec -u root "$name" test -e "$base/protected";then echo PROTECTED_STAGE_NOT_CLEANED;exit 75;fi
if docker exec -u root "$name" test -e /usr/local/sbin/s03-current35-108-110-owner-operator;then echo TEMP_OPERATOR_NOT_CLEANED;exit 76;fi
run sumlaude status
if run sumlaude cleanup-108-110 >/dev/null 2>&1;then echo REPLAY_FALSE_PASS;exit 77;fi
echo SHARED_OPS_ORIGINAL_ROOT_DISPATCH_AND_BOUNDED_CLEANUP_ISOLATED_PASS
