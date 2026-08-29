#!/usr/bin/env bash
# File: spikes/api/scripts/stop-postgres.sh
# Purpose: Stop the isolated Task 002 PostgreSQL cluster without deleting its data.
# Related: spikes/api/scripts/init-postgres.sh
set -eu

spike_pg_bin="${SPIKE_PG_BIN:-/usr/lib/postgresql/16/bin}"
spike_pg_data="${SPIKE_PG_DATA:-/tmp/omnilyzer-platform-api-spike-pgdata}"

if "$spike_pg_bin/pg_ctl" --pgdata="$spike_pg_data" status >/dev/null 2>&1; then
    "$spike_pg_bin/pg_ctl" --pgdata="$spike_pg_data" stop --mode=fast
else
    printf '%s\n' "Isolated PostgreSQL cluster is already stopped."
fi
