#!/usr/bin/env bash
set -euo pipefail

docker rm -f omnilyzer-auth-spike-keycloak >/dev/null 2>&1 || true
PG_DATA="/tmp/omnilyzer-platform-auth-spike-pgdata"
if [[ -s "$PG_DATA/PG_VERSION" ]] && /usr/lib/postgresql/16/bin/pg_ctl -D "$PG_DATA" status >/dev/null 2>&1; then
    /usr/lib/postgresql/16/bin/pg_ctl -D "$PG_DATA" stop -m fast >/dev/null
fi
rm -f /tmp/omnilyzer-auth-spike-runtime.env
echo "Authentication spike services stopped; runtime secret file removed."
