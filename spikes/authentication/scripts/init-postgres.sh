#!/usr/bin/env bash
set -euo pipefail

PG_BIN="/usr/lib/postgresql/16/bin"
PG_DATA="/tmp/omnilyzer-platform-auth-spike-pgdata"
PG_SOCKET="/tmp/omnilyzer-platform-auth-spike-socket"
PG_PORT="55436"
BOOTSTRAP_ROLE="omnilyzer_auth_bootstrap"
OWNER_ROLE="omnilyzer_auth_owner"
RUNTIME_ROLE="omnilyzer_auth_runtime"
DATABASE="omnilyzer_platform_auth_spike"

install -d -m 700 "$PG_SOCKET"
if [[ ! -s "$PG_DATA/PG_VERSION" ]]; then
    install -d -m 700 "$PG_DATA"
    "$PG_BIN/initdb" -D "$PG_DATA" -U "$BOOTSTRAP_ROLE" \
        --auth-local=trust --auth-host=reject --no-instructions
fi
if ! "$PG_BIN/pg_ctl" -D "$PG_DATA" status >/dev/null 2>&1; then
    "$PG_BIN/pg_ctl" -D "$PG_DATA" -l "$PG_DATA/postgresql.log" \
        -o "-k $PG_SOCKET -p $PG_PORT -c listen_addresses='' -c unix_socket_permissions=0700" start
fi

psql=("$PG_BIN/psql" -h "$PG_SOCKET" -p "$PG_PORT" -U "$BOOTSTRAP_ROLE" -v ON_ERROR_STOP=1)
if ! "${psql[@]}" -d postgres -Atqc "SELECT 1 FROM pg_roles WHERE rolname='$OWNER_ROLE'" | grep -qx 1; then
    "${psql[@]}" -d postgres -c "CREATE ROLE $OWNER_ROLE LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;"
fi
if ! "${psql[@]}" -d postgres -Atqc "SELECT 1 FROM pg_roles WHERE rolname='$RUNTIME_ROLE'" | grep -qx 1; then
    "${psql[@]}" -d postgres -c "CREATE ROLE $RUNTIME_ROLE LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;"
fi
if ! "${psql[@]}" -d postgres -Atqc "SELECT 1 FROM pg_database WHERE datname='$DATABASE'" | grep -qx 1; then
    "$PG_BIN/createdb" -h "$PG_SOCKET" -p "$PG_PORT" -U "$BOOTSTRAP_ROLE" -O "$OWNER_ROLE" "$DATABASE"
fi

"${psql[@]}" -d postgres <<SQL
REVOKE ALL ON DATABASE $DATABASE FROM PUBLIC;
GRANT CONNECT ON DATABASE $DATABASE TO $OWNER_ROLE, $RUNTIME_ROLE;
SQL
"${psql[@]}" -d "$DATABASE" <<SQL
ALTER SCHEMA public OWNER TO $OWNER_ROLE;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO $OWNER_ROLE;
GRANT USAGE ON SCHEMA public TO $RUNTIME_ROLE;
SQL

if [[ "${1:-}" == "--grant-runtime" ]]; then
    "${psql[@]}" -d "$DATABASE" <<SQL
REVOKE ALL ON TABLE django_session FROM PUBLIC;
ALTER TABLE django_session OWNER TO $OWNER_ROLE;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE django_session TO $RUNTIME_ROLE;
SQL
fi

echo "PostgreSQL auth spike cluster ready on private Unix socket port $PG_PORT."
