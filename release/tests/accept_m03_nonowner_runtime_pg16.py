#!/usr/bin/env python3
# File: release/tests/accept_m03_nonowner_runtime_pg16.py
# Purpose: Reproduce actual non-owner Analytics Workspace/Website RLS and
#          misleading green readiness against fresh isolated PostgreSQL16+Next14.
# Links: docs/operations/m03-nonowner-runtime-readiness-20261028.md;
#        Analytics PR45 prisma/schema.prisma,
#        prisma/multiwebsite-expand-backfill.sql,
#        prisma/rls/m01-runtime.install.sql,
#        prisma/rls/analytics-app-events.install.sql,
#        app/api/v1/workspaces/route.ts and lib/server-api-auth.ts.
# REVIEW ONLY: no production or existing DEV database/role is touched.

"""Reproduce the product-runtime RLS gap with real PG16, not mocked SQL."""

from __future__ import annotations
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import json
import time
import urllib.request
import signal

ROOT = pathlib.Path("/home/trusthansen/workspaces/omnilyzer-m03-m05-oci-source-20261028")
NEXTROOT = pathlib.Path("/home/trusthansen/workspaces/omnilyzer-m01-platform-consolidated-20261028")
DEPS = pathlib.Path("/home/trusthansen/workspaces/omnilyzer-m01-backend-20261023/node_modules")
PG = pathlib.Path("/usr/lib/postgresql/16/bin")
SOURCE_SHA = "8648adba2db884cc78274080b9836ca46bafd630"


def run(args, *, env=None, input_text=None, timeout=100, must_pass=True, cwd=None):
    """Run bounded, shell-free subprocesses and redact arbitrary failures."""
    result = subprocess.run(args, input=input_text, text=True, capture_output=True,
                            env=env, cwd=cwd, timeout=timeout, check=False)
    if must_pass and result.returncode:
        raise RuntimeError(f"Test subprocess failed: {args[0]} exit {result.returncode}")
    return result


def psql(socket_dir, port, statement, *, success=True):
    """Execute real PostgreSQL SQL against this test's private socket only."""
    return run(["psql", "-X", "-q", "-A", "-t", "-h", str(socket_dir),
                "-p", str(port), "-U", "omni_owner", "-d", "m03_runtime_accept",
                "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"],
               input_text=statement, must_pass=success)


def main():
    """Build disposable schema and prove app role cannot see/write existing tenant."""
    assert os.geteuid() != 0
    assert run(["hostname", "-s"]).stdout.strip() == "truexdevelopment"
    assert run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.strip() == SOURCE_SHA
    assert run(["git", "-C", str(NEXTROOT), "rev-parse", "HEAD"]).stdout.strip() == "597a3415dfee76cc63f6ba70d3660f287a09b0c8"
    assert not (ROOT / "node_modules").exists()
    assert DEPS.is_dir()

    # A temporary local port, not the live SaaS/DEV PostgreSQL service.
    with socket.socket() as port_probe:
        port_probe.bind(("127.0.0.1", 0))
        port = port_probe.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="m03_pg16_nonowner_") as folder:
        root = pathlib.Path(folder)
        data = root / "pgdata"
        sock = root / "socket"
        sock.mkdir(mode=0o700)
        pw_file = root / "pw"
        pw = secrets.token_urlsafe(32)
        pw_file.write_text(pw + "\n")
        pw_file.chmod(0o600)
        started = False
        server = None
        try:
            run([str(PG / "initdb"), "-D", str(data), "-U", "omni_owner",
                 "--pwfile=" + str(pw_file),
                 "--auth-local=trust", "--auth-host=scram-sha-256", "--no-sync"])
            run([str(PG / "pg_ctl"), "-D", str(data), "-l", str(root / "pg.log"),
                 "-o", "-c listen_addresses=127.0.0.1 -c port=" + str(port) +
                       " -c unix_socket_directories=" + str(sock),
                 "-w", "start"])
            started = True
            run(["createdb", "-h", str(sock), "-p", str(port),
                 "-U", "omni_owner", "m03_runtime_accept"])
            env = {**os.environ,
                   "DATABASE_URL": f"postgresql://omni_owner:{pw}@127.0.0.1:{port}/m03_runtime_accept",
                   "COLLECTOR_DATABASE_URL": f"postgresql://omni_owner:{pw}@127.0.0.1:{port}/m03_runtime_accept"}
            (ROOT / "node_modules").symlink_to(DEPS)
            run([str(DEPS / ".bin/prisma"), "db", "push", "--skip-generate"],
                env=env, cwd=ROOT, timeout=110)
            psql(sock, port, """CREATE ROLE omni_runtime NOLOGIN NOINHERIT
                  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
                  GRANT USAGE ON SCHEMA public TO omni_runtime;
                  GRANT SELECT, INSERT, UPDATE, DELETE
                    ON ALL TABLES IN SCHEMA public TO omni_runtime;
                  GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO omni_runtime;
                  GRANT omni_runtime TO omni_owner;""")
            for sql_path in ["prisma/multiwebsite-expand-backfill.sql",
                             "prisma/rls/m01-runtime.install.sql",
                             "prisma/rls/analytics-app-events.install.sql"]:
                psql(sock, port, (ROOT / sql_path).read_text())
            psql(sock, port, """INSERT INTO public."Workspace"("id","name","kind")
               VALUES ('11111111-1111-4111-8111-111111111111','M03 tenant','organization');
               INSERT INTO public."Website"
               ("id","workspaceId","name","origin","ingestKey",
                "trackingEnabled","createdAt","updatedAt")
               VALUES ('22222222-2222-4222-8222-222222222222',
               '11111111-1111-4111-8111-111111111111','M03 site',
               'https://m03.invalid','m03_testing_only',true,now(),now());""")
            for table in ["Workspace", "Website"]:
                admin = psql(sock, port, f'SELECT count(*) FROM public."{table}"').stdout.strip()
                app = psql(sock, port,
                    f'SET ROLE omni_runtime; SELECT count(*) FROM public."{table}"; RESET ROLE').stdout.strip()
                assert admin == "1", (table, admin)
                assert app == "0", (table, app)
                print(f"CONFIRMED {table}: seeded row visible as DB owner (1), "
                      f"invisible under restricted application role (0)", flush=True)
            denied = psql(sock, port,
                """SET ROLE omni_runtime;
                   INSERT INTO public."Workspace" ("id","name","kind")
                   VALUES ('33333333-3333-4333-8333-333333333333',
                           'Cannot create workspace','organization');""",
                success=False)
            assert denied.returncode != 0
            assert "42501" in denied.stderr, "Expected PostgreSQL RLS SQLSTATE 42501"
            print("CONFIRMED restricted application role Workspace INSERT refused by PG16 RLS (42501)",flush=True)
            # Probe real compiled PR42 Next14 against separate non-owner app and
            # collector credentials: /readyz can be 200 although the app role
            # cannot see/create Workspaces (a missing product readiness gate).
            assert NEXTROOT.joinpath(".next/BUILD_ID").exists()
            assert not NEXTROOT.joinpath("node_modules").exists()
            psql(sock, port, """ALTER ROLE omni_runtime LOGIN PASSWORD 'm03-only-auth-test-secret';
                    ALTER ROLE collector_runtime PASSWORD 'm03-only-collector-test-secret';""")
            with socket.socket() as http_probe:
                http_probe.bind(("127.0.0.1", 0))
                http_port = http_probe.getsockname()[1]
            NEXTROOT.joinpath("node_modules").symlink_to(DEPS)
            runtime = {**os.environ, "NODE_ENV":"production", "NEXT_TELEMETRY_DISABLED":"1",
                       "DATABASE_URL":f"postgresql://omni_runtime:m03-only-auth-test-secret@127.0.0.1:{port}/m03_runtime_accept",
                       "COLLECTOR_DATABASE_URL":f"postgresql://collector_runtime:m03-only-collector-test-secret@127.0.0.1:{port}/m03_runtime_accept",
                       "JWT_SECRET":"m03-review-only-synthetic-access-secret-20261028",
                       "JWT_REFRESH_SECRET":"m03-review-only-synthetic-refresh-secret-20261028"}
            server = subprocess.Popen(
                [str(DEPS / ".bin/next"), "start", "-H", "127.0.0.1", "-p", str(http_port)],
                env=runtime, cwd=NEXTROOT, stdout=(root/"next.log").open("w"),
                stderr=subprocess.STDOUT, start_new_session=True)
            for _ in range(80):
                try:
                    if server.poll() is not None:
                        raise RuntimeError("Private test-only Next server exited")
                    with urllib.request.urlopen(f"http://127.0.0.1:{http_port}/readyz", timeout=1) as resp:
                        status = resp.status
                        payload = json.loads(resp.read(1000).decode("utf-8"))
                        break
                except Exception:
                    time.sleep(0.25)
            else:
                raise AssertionError("Private /readyz did not return in time")
            assert status == 200 and payload == {"status":"ready"}, (status,payload)
            print("CONFIRMED Next14 /readyz HTTP 200 with non-owner DB role even while Workspace and Website remain invisible to that role",flush=True)
            print("M03_NONOWNER_RUNTIME_P0_GAP_REPRODUCED",flush=True)
        finally:
            if server is not None and server.poll() is None:
                os.killpg(server.pid, signal.SIGTERM)
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(server.pid, signal.SIGKILL)
                    server.wait(timeout=5)
            next_link = NEXTROOT / "node_modules"
            if next_link.is_symlink():
                next_link.unlink()
            link = ROOT / "node_modules"
            if link.is_symlink():
                link.unlink()
            if started:
                run([str(PG / "pg_ctl"), "-D", str(data), "-m", "immediate",
                     "-w", "stop"], timeout=15)


if __name__ == "__main__":
    main()
