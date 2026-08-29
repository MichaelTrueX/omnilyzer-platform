#!/usr/bin/env bash
# File: spikes/api/scripts/init-postgres.sh
# Purpose: Initialize and start a wholly isolated PostgreSQL cluster for Task 002.
# Related: spikes/api/config/settings.py, spikes/api/scripts/stop-postgres.sh
set -eu

spike_pg_bin="${SPIKE_PG_BIN:-/usr/lib/postgresql/16/bin}"
spike_pg_data="${SPIKE_PG_DATA:-/tmp/omnilyzer-platform-api-spike-pgdata}"
spike_pg_socket="${SPIKE_DATABASE_HOST:-/tmp/omnilyzer-platform-api-spike-socket}"
spike_pg_port="${SPIKE_DATABASE_PORT:-55434}"
spike_pg_log="${SPIKE_PG_LOG:-/tmp/omnilyzer-platform-api-spike-postgres.log}"
spike_db_name="${SPIKE_DATABASE_NAME:-omnilyzer_platform_api_spike}"
spike_db_role="${SPIKE_DATABASE_USER:-omnilyzer_api_spike_owner}"
spike_cluster_admin="omnilyzer_api_spike_cluster_admin"
spike_pg_start_options="-k $spike_pg_socket -p $spike_pg_port"
spike_pg_start_options="$spike_pg_start_options -c listen_addresses=''"
spike_pg_start_options="$spike_pg_start_options -c unix_socket_permissions=0700"

install -d -m 0700 "$spike_pg_socket"
chmod 0700 "$spike_pg_socket"

if [ ! -f "$spike_pg_data/PG_VERSION" ]; then
    "$spike_pg_bin/initdb" \
        --pgdata="$spike_pg_data" \
        --username="$spike_cluster_admin" \
        --auth-local=trust \
        --auth-host=reject \
        --no-locale \
        --encoding=UTF8
fi

if ! "$spike_pg_bin/pg_ctl" --pgdata="$spike_pg_data" status >/dev/null 2>&1; then
    "$spike_pg_bin/pg_ctl" \
        --pgdata="$spike_pg_data" \
        --log="$spike_pg_log" \
        --options="$spike_pg_start_options" \
        start
fi

"$spike_pg_bin/psql" \
    --host="$spike_pg_socket" \
    --port="$spike_pg_port" \
    --username="$spike_cluster_admin" \
    --dbname=postgres \
    --set=ON_ERROR_STOP=1 \
    --set=spike_db_role="$spike_db_role" <<'SQL'
SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER CREATEDB NOCREATEROLE NOREPLICATION',
    :'spike_db_role'
)
WHERE NOT EXISTS (
    SELECT FROM pg_catalog.pg_roles WHERE rolname = :'spike_db_role'
)\gexec
SQL

"$spike_pg_bin/psql" \
    --host="$spike_pg_socket" \
    --port="$spike_pg_port" \
    --username="$spike_cluster_admin" \
    --dbname=postgres \
    --set=ON_ERROR_STOP=1 \
    --set=spike_db_name="$spike_db_name" \
    --set=spike_db_role="$spike_db_role" <<'SQL'
SELECT format('CREATE DATABASE %I OWNER %I', :'spike_db_name', :'spike_db_role')
WHERE NOT EXISTS (
    SELECT FROM pg_catalog.pg_database WHERE datname = :'spike_db_name'
)\gexec
SQL

actual_listen_addresses="$(
    "$spike_pg_bin/psql" \
        --host="$spike_pg_socket" \
        --port="$spike_pg_port" \
        --username="$spike_cluster_admin" \
        --dbname=postgres \
        --tuples-only \
        --no-align \
        --command="SHOW listen_addresses"
)"
socket_directory_mode="$(stat --format=%a "$spike_pg_socket")"
test -z "$actual_listen_addresses"
test "$socket_directory_mode" = "700"

printf '%s\n' \
    "Validation: listen_addresses is empty; socket directory mode is $socket_directory_mode."
printf '%s\n' "Isolated PostgreSQL is ready at $spike_pg_socket:$spike_pg_port."
printf '%s\n' "Database: $spike_db_name; non-superuser owner: $spike_db_role."
