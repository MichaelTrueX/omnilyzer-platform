#!/usr/bin/env bash
set -euo pipefail

PG_BIN="/usr/lib/postgresql/16/bin"
PG_DATA="/tmp/omnilyzer-platform-tenancy-spike-pgdata"
PG_SOCKET="/tmp/omnilyzer-platform-tenancy-spike-socket"
PG_PORT="55435"
BOOTSTRAP_ROLE="omnilyzer_tenancy_bootstrap"
OWNER_ROLE="omnilyzer_tenancy_owner"
RUNTIME_ROLE="omnilyzer_tenancy_runtime"
DATABASE="omnilyzer_platform_tenancy_spike"

install -d -m 700 "$PG_SOCKET"

if [[ ! -s "$PG_DATA/PG_VERSION" ]]; then
    install -d -m 700 "$PG_DATA"
    "$PG_BIN/initdb" -D "$PG_DATA" -U "$BOOTSTRAP_ROLE" --auth-local=trust --auth-host=reject --no-instructions
fi

if ! "$PG_BIN/pg_ctl" -D "$PG_DATA" status >/dev/null 2>&1; then
    "$PG_BIN/pg_ctl" -D "$PG_DATA" -l "$PG_DATA/postgresql.log" -o "-k $PG_SOCKET -p $PG_PORT -c listen_addresses='' -c unix_socket_permissions=0700" start
fi

psql_base=("$PG_BIN/psql" -h "$PG_SOCKET" -p "$PG_PORT" -U "$BOOTSTRAP_ROLE" -v ON_ERROR_STOP=1)

if ! "${psql_base[@]}" -d postgres -Atqc "SELECT 1 FROM pg_roles WHERE rolname = '$OWNER_ROLE'" | grep -qx 1; then
    "${psql_base[@]}" -d postgres -c "CREATE ROLE $OWNER_ROLE LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;"
fi
if ! "${psql_base[@]}" -d postgres -Atqc "SELECT 1 FROM pg_roles WHERE rolname = '$RUNTIME_ROLE'" | grep -qx 1; then
    "${psql_base[@]}" -d postgres -c "CREATE ROLE $RUNTIME_ROLE LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;"
fi
if ! "${psql_base[@]}" -d postgres -Atqc "SELECT 1 FROM pg_database WHERE datname = '$DATABASE'" | grep -qx 1; then
    "$PG_BIN/createdb" -h "$PG_SOCKET" -p "$PG_PORT" -U "$BOOTSTRAP_ROLE" -O "$OWNER_ROLE" "$DATABASE"
fi

"${psql_base[@]}" -d postgres <<SQL
REVOKE ALL ON DATABASE $DATABASE FROM PUBLIC;
GRANT CONNECT ON DATABASE $DATABASE TO $OWNER_ROLE, $RUNTIME_ROLE;
SQL

"${psql_base[@]}" -d "$DATABASE" <<SQL
ALTER SCHEMA public OWNER TO $OWNER_ROLE;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO $OWNER_ROLE;
GRANT USAGE ON SCHEMA public TO $RUNTIME_ROLE;
SQL

echo "PostgreSQL tenancy spike cluster is ready on Unix socket $PG_SOCKET, port $PG_PORT."
