#!/usr/bin/env bash
set -euo pipefail

PG_BIN="/usr/lib/postgresql/16/bin"
PG_DATA="/tmp/omnilyzer-platform-tenancy-spike-pgdata"

if [[ -s "$PG_DATA/PG_VERSION" ]] && "$PG_BIN/pg_ctl" -D "$PG_DATA" status >/dev/null 2>&1; then
    "$PG_BIN/pg_ctl" -D "$PG_DATA" -m fast stop
else
    echo "PostgreSQL tenancy spike cluster is not running."
fi
