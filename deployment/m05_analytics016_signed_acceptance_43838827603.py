#!/usr/bin/env python3
"""File: /home/omnigpt/repos/omnilyzer-platform/.m05-14-release-review/m05_analytics016_signed_acceptance_43838827603.py
Purpose: One owner-approved synthetic sign-in, isolation, collector and cleanup
         journey against signed Analytics 0.16.0 after Task014 run 43838827603 succeeds.
Related: task014-dev-cleanup-diagnostic-v4-20261101.py (preflight lineage),
         GitHub MichaelTrueX/omnilyzer Issue #27, signed product
         app/api/v1/{auth,admin,workspaces,collect} and prisma/schema.prisma.
Security: Run only as owner-authorized root with exact hash from /run. No
          permanent user accounts, password/token logging, external network,
          production contact, application rebuild or auth configuration change.
          Pre-creates persistent root-only non-secret marker ledger. Every created object
          is uniquely tagged. Cleanup uses the already-approved local PG16
          superuser, transactionally, only for exact test-owned users/workspaces.
          On unexpected memberships cleanup fails closed and leaves the ledger
          for controlled recovery. No table-wide deletes or DROP operations.
"""

from __future__ import annotations

import bcrypt
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
from urllib.parse import quote

# Section 1: Exact signed DEV and PostgreSQL authority pin and test limits.
HOST = "omnilyzerdev"
RUN_DIR = Path("/var/lib/omnilyzer")
DATABASE = "omnilyzer_analytics_dev"
APP = "omnilyzer-analytics-dev-analytics-blue-1"
NETWORK = "omnilyzer-analytics-backend-dev"
SIGNED = ("oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
          "6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1")
PIN = Path("/etc/omnilyzer/deployment/analytics-loopback.env")
DOCKER = ["/usr/bin/sudo", "-n", "-u", "omnilyzer-executor",
          "/usr/bin/docker", "--host", "unix:///run/user/991/docker.sock"]
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TAG = re.compile(r"[0-9a-f]{16}\Z")
NO_SECRET_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
HTTP_HOST, HTTP_PORT = "127.0.0.1", 3141


# Section 2: Restricted subprocesses and immutable installed runtime checks.
def run(argv: list[str], payload: str | None = None) -> str:
    """Run a fixed command, bound output, suppress untrusted subprocess errors."""
    result = subprocess.run(
        argv, input=payload, text=True, capture_output=True,
        timeout=18, check=False, env=NO_SECRET_ENV,
    )
    if result.returncode or len(result.stdout.encode()) > 30000:
        raise RuntimeError("restricted subprocess failure")
    return result.stdout.strip()


def docker(*argv: str, payload: str | None = None) -> str:
    """Use only the approved existing UID991 private rootless Docker engine."""
    return run([*DOCKER, *argv], payload)


def signed_private_runtime() -> tuple[str, str]:
    """Revalidate root, signed digest, root-owned pin and private PG16 network."""
    import pwd
    import socket
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST:
        raise RuntimeError("unapproved execution context")
    user = pwd.getpwnam("omnilyzer-executor")
    if (user.pw_uid, user.pw_gid) != (991, 991):
        raise RuntimeError("rootless user authority mismatch")
    f = os.open(PIN, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(f)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0
                or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) != 0o600
                or s.st_size > 128):
            raise RuntimeError("signed container pin untrusted")
        value = os.read(f, 129).decode("ascii")
    finally:
        os.close(f)
    prefix = "ANALYTICS_APPROVED_CONTAINER_ID="
    if not value.startswith(prefix) or not value.endswith("\n"):
        raise RuntimeError("signed container pin invalid")
    app_id = value[len(prefix):].strip()
    if not HEX64.fullmatch(app_id):
        raise RuntimeError("signed container ID invalid")
    expected = f'"{app_id}"|"{SIGNED}"|"healthy"'
    metadata = docker("inspect", "--format",
                      "{{json .Id}}|{{json .Config.Image}}|{{json .State.Health.Status}}",
                      APP)
    if metadata != expected:
        raise RuntimeError("signed OCI runtime not admitted")
    if run(["/usr/bin/systemctl", "is-active",
            "omnilyzer-analytics-loopback.service"]) != "active":
        raise RuntimeError("signed loopback ingress inactive")
    containers = [json.loads(row) for row in docker(
        "ps", "--filter", "network=" + NETWORK, "--format", "{{json .}}"
    ).splitlines()]
    if len(containers) != 3 or any(type(x) is not dict for x in containers):
        raise RuntimeError("private network topology changed")
    app_list = [x for x in containers
                if x.get("Names") == APP and type(x.get("ID")) is str
                and app_id.startswith(x["ID"])]
    if len(app_list) != 1:
        raise RuntimeError("approved signed app not on network")
    # The old blue pin above remains unchanged and proves the retained rollback.
    green_name = "omnilyzer-analytics-dev-analytics-green-1"
    signed016 = "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1"
    green_raw = docker("inspect", "--format",
        "{{json .Id}}|{{json .Config.Image}}|{{json .State.Health.Status}}", green_name)
    green_id, image, health = [json.loads(v) for v in green_raw.split("|")]
    if not HEX64.fullmatch(green_id) or image != signed016 or health != "healthy":
        raise RuntimeError("signed 0.16 runtime mismatch")
    green_list = [x for x in containers if x.get("Names") == green_name
                  and type(x.get("ID")) is str and green_id.startswith(x["ID"])]
    if len(green_list) != 1:
        raise RuntimeError("signed 0.16 network mismatch")
    # Bind the successful signed request from the protected replay authority,
    # never authorize a candidate from journal fields or an unsigned archive.
    import sqlite3
    with sqlite3.connect("file:/var/lib/omnilyzer/deployment/authority/replay.sqlite3?mode=ro", uri=True) as c:
        c.execute("PRAGMA query_only=ON")
        rows = c.execute("SELECT executor_request_sha256,status FROM consumptions "
                         "WHERE github_run_id=? AND github_run_attempt=1", (43838827603,)).fetchall()
    if len(rows) != 1 or rows[0][1] != "finished" or not HEX64.fullmatch(rows[0][0]):
        raise RuntimeError("signed Task014 execution not finished")
    installed_root = "/opt/omnilyzer/deployment/analytics-app-candidate"
    for folder in ("/opt", "/opt/omnilyzer", "/opt/omnilyzer/deployment", installed_root):
        st = Path(folder).lstat()
        if not stat.S_ISDIR(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0, 0o755):
            raise RuntimeError("installed source root untrusted")
    qualification = run(["/usr/bin/setpriv", "--reuid", "991", "--regid", "991",
        "--groups", "992", "--no-new-privs", "/usr/bin/python3", "-I", "-B", "-c",
        "import sys;sys.path.insert(0," + repr(installed_root) + ");"
        "from deployment.analytics_executor_service_config import load_analytics_executor_service_config;"
        "_,identity=load_analytics_executor_service_config(require_successor=True);"
        "print(identity['expected_workflow_sha'])"])
    if qualification != "c6d6b067f932e60d82f8b7a9d75a2629a62606c8":
        raise RuntimeError("installed signed workflow authority mismatch")
    sys.path.insert(0, installed_root)
    from deployment.analytics_active_state_review import inspect_committed_analytics_route
    from deployment.analytics_route_journal import AnalyticsRouteJournal
    state = inspect_committed_analytics_route(journal=AnalyticsRouteJournal(),
        reviewed_image=signed016, reviewed_slot="green", reviewed_container_id=green_id,
        reviewed_request_sha256=rows[0][0])
    if state.active_container_id != green_id:
        raise RuntimeError("0.16 traffic identity mismatch")
    print("SIGNED_DEV_E2E_PASS signed016_route_and_retained015", flush=True)
    other = [x for x in containers if x is not app_list[0] and x is not green_list[0]]
    if len(other) != 1 or type(other[0].get("ID")) is not str:
        raise RuntimeError("ambiguous DEV database")
    candidate = other[0]["ID"]
    if not re.fullmatch(r"[0-9a-f]{12,64}", candidate):
        raise RuntimeError("unexpected PG container ID")
    raw = docker("inspect", "--format",
                 "{{json .Id}}|{{json .Config.Image}}|{{json .Config.Entrypoint}}|"
                 "{{json .Config.Cmd}}|{{json .State.Running}}|"
                 "{{json .NetworkSettings.Networks}}", candidate)
    fields = [json.loads(v) for v in raw.split("|")]
    if len(fields) != 6:
        raise RuntimeError("database metadata incomplete")
    cid, image, entry, command, running, networks = fields
    if (type(cid) is not str or not HEX64.fullmatch(cid)
            or not cid.startswith(candidate) or cid == app_id
            or type(image) is not str
            or re.search(r"(?:^|/)postgres(?=[:@])", image) is None
            or type(entry) is not list
            or not any(type(x) is str and x.endswith("docker-entrypoint.sh")
                       for x in entry)
            or type(command) is not list or not command or command[0] != "postgres"
            or running is not True or type(networks) is not dict
            or set(networks) != {NETWORK}):
        raise RuntimeError("unexpected PostgreSQL identity")
    return green_id, cid


def sql_literal(value: str) -> str:
    """Quote only internally generated bounded identifiers, never user input."""
    if not re.fullmatch(r"[A-Za-z0-9@._ -]{1,120}", value):
        raise ValueError("unsafe fixture literal")
    return "'" + value + "'"


def postgres_principal(db: str) -> str:
    """Use original POSTGRES_USER privately, never expose passwords or roles."""
    raw = docker("exec", "--user", "postgres", db, "printenv", "POSTGRES_USER")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", raw):
        raise RuntimeError("configured DBA identity unavailable")
    return raw


def sql(db: str, principal: str, statement: str) -> str:
    """Send reviewed SQL through stdin, not Docker command line or host logs."""
    if not statement.endswith("\n"):
        raise ValueError("SQL payload must be terminated")
    return docker("exec", "-i", "--user", "postgres", db, "psql",
                  "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                  "-U", principal, "-d", DATABASE, payload=statement)


# Section 3: Durable within-session root-only ledger and clean recovery marker.
def new_ledger(tag: str, emails: tuple[str, str, str],
               workspaces: tuple[str, str]) -> Path:
    """Write a durable private fixture marker before the first SQL mutation."""
    assert TAG.fullmatch(tag)
    if list(RUN_DIR.glob("task014-signed-dev-fixture-*.json")):
        raise RuntimeError("prior QA ledger exists; review before new run")
    p = RUN_DIR / f"task014-signed-dev-fixture-{tag}.json"
    contents = json.dumps({"tag": tag, "emails": emails,
                           "workspaces": workspaces}, sort_keys=True).encode()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if os.fstat(fd).st_uid != 0:
            raise RuntimeError("fixture ledger not root-owned")
        os.write(fd, contents)
        os.fsync(fd)
    finally:
        os.close(fd)
    return p


def read_pending_ledger() -> tuple[Path, tuple[str, str, str], tuple[str, str]]:
    """Recover exactly one root-owned marker with strictly rederived QA IDs."""
    candidates = list(RUN_DIR.glob("task014-signed-dev-fixture-*.json"))
    if len(candidates) != 1:
        raise RuntimeError("expected exactly one outstanding QA ledger")
    p = candidates[0]
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or (
                stat.S_IMODE(st.st_mode) != 0o600) or st.st_size > 1024:
            raise RuntimeError("QA ledger ownership or size mismatch")
        data = json.loads(os.read(fd, 1025))
    finally:
        os.close(fd)
    if type(data) is not dict or set(data) != {"tag", "emails", "workspaces"}:
        raise RuntimeError("unexpected QA ledger fields")
    tag = data["tag"]
    if type(tag) is not str or not TAG.fullmatch(tag) or p.name != (
            f"task014-signed-dev-fixture-{tag}.json"):
        raise RuntimeError("unexpected QA recovery identifier")
    emails = (f"qa-admin-{tag}@example.invalid",
              f"qa-a-{tag}@example.invalid",
              f"qa-b-{tag}@example.invalid")
    workspaces = (f"Task014 QA A {tag}", f"Task014 QA B {tag}")
    if data["emails"] != list(emails) or data["workspaces"] != list(workspaces):
        raise RuntimeError("QA ledger not self-consistent")
    return p, emails, workspaces


# Section 4: Fixed loopback HTTP client. Never follow redirects or transmit secrets.
def request(method: str, path: str, data: dict | None = None,
            token: str | None = None, origin: str | None = None) -> tuple[int, dict, dict]:
    """Perform real JSON/Bearer HTTP over local signed DEV listener only."""
    if not path.startswith("/") or "//" in path or len(path) > 256:
        raise ValueError("invalid private API path")
    if method not in ("GET", "POST", "PATCH"):
        raise ValueError("unexpected HTTP method")
    headers = {"Accept": "application/json", "User-Agent": "Task014-Signed-DEV-QA/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if origin:
        headers["Origin"] = origin
    payload = json.dumps(data, separators=(",", ":")).encode() if data is not None else None
    if payload is not None:
        headers["Content-Type"] = "application/json"
    c = http.client.HTTPConnection(HTTP_HOST, HTTP_PORT, timeout=7)
    try:
        c.request(method, path, body=payload, headers=headers)
        r = c.getresponse()
        body = r.read(32769)
        if len(body) > 32768:
            raise RuntimeError("HTTP body over budget")
        header = {key.lower(): value for key, value in r.getheaders()}
        parsed = json.loads(body) if body else {}
        if type(parsed) is not dict:
            raise RuntimeError("unexpected signed API JSON")
        if "set-cookie" in header:
            raise RuntimeError("signed API unexpectedly set authentication cookie")
        return r.status, parsed, header
    finally:
        c.close()


def expect(name: str, method: str, path: str, expected: int,
           data: dict | None = None, token: str | None = None,
           origin: str | None = None) -> tuple[dict, dict]:
    """Print only fixed checkpoint name and success, never HTTP token/body."""
    status, body, headers = request(method, path, data, token, origin)
    if status != expected:
        print("SIGNED_DEV_E2E_MISMATCH " + name + " actual=" + str(status) + " expected=" + str(expected), flush=True)
        raise RuntimeError("HTTP status mismatch at " + name)
    if expected in (200, 201) and body.get("success") is not True:
        raise RuntimeError("HTTP success contract mismatch at " + name)
    print("SIGNED_DEV_E2E_PASS " + name, flush=True)
    return body, headers


# Section 5: Bootstrap only one synthetic first Admin and run authentic APIs.
def fixture_flow(db: str, principal: str, tag: str,
                 emails: tuple[str, str, str],
                 names: tuple[str, str]) -> tuple[str, str]:
    """Exercise signup ban, real local login, two tenants, event and revocation."""
    owner, a, b = emails
    ws_a, ws_b = names
    raw = sql(db, principal,
              "BEGIN READ ONLY;\n"
              "SELECT COUNT(*) FROM public.\"User\" WHERE \"role\"='Admin';\n"
              "ROLLBACK;\n")
    if raw.strip() != "0":
        raise RuntimeError("existing Admin state changed; no bootstrap")
    pw_admin = secrets.token_urlsafe(32)
    pw_a, pw_b = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    hashed = bcrypt.hashpw(pw_admin.encode(), bcrypt.gensalt(rounds=12)).decode()
    if not re.fullmatch(r"\$2[aby]\$12\$[./0-9A-Za-z]{53}", hashed):
        raise RuntimeError("bcrypt hash contract mismatch")
    insert = (
        "BEGIN;\n"
        "SET LOCAL lock_timeout='3s';\n"
        "SET LOCAL statement_timeout='12s';\n"
        "INSERT INTO public.\"User\""
        "(\"email\",\"name\",\"password\",\"role\",\"provider\",\"emailVerified\","
        "\"createdAt\",\"updatedAt\") VALUES ("
        f"{sql_literal(owner)},{sql_literal('Task014 QA Admin '+tag)},"
        f"'{hashed}','Admin','local',true,now(),now()) "
        "RETURNING \"id\";\n"
        "COMMIT;\n"
    )
    inserted = sql(db, principal, insert).strip()
    if not inserted.isdecimal() or int(inserted) <= 0:
        raise RuntimeError("first Admin INSERT did not return an ID")
    print("SIGNED_DEV_E2E_PASS temporary_first_admin_bootstrap", flush=True)
    blocked, _ = expect("invitation_only", "POST", "/api/v1/auth/register",
                        403, {"email": a, "password": pw_a})
    logged, headers = expect("real_admin_login", "POST",
                             "/api/v1/auth/login", 200,
                             {"email": owner, "password": pw_admin})
    if (logged.get("user", {}).get("role") != "Admin"
            or headers.get("cache-control") != "no-store"
            or not isinstance(logged.get("accessToken"), str)
            or not isinstance(logged.get("refreshToken"), str)):
        raise RuntimeError("signed admin JSON token contract mismatch")
    admin_token = logged["accessToken"]
    admin_users, _ = expect("admin_only_list", "GET",
                            "/api/v1/admin/auth-users", 200,
                            token=admin_token)
    for label, email, password in (("tenant_a", a, pw_a),
                                   ("tenant_b", b, pw_b)):
        record, _ = expect("invited_" + label, "POST",
                           "/api/v1/admin/auth-users", 201,
                           {"email": email, "name": "Task014 QA " + label,
                            "password": password, "role": "Guest"},
                           token=admin_token)
        if record.get("user", {}).get("email") != email:
            raise RuntimeError("admin provisioning user mismatch")
    ta, ha = expect("tenant_a_login", "POST", "/api/v1/auth/login",
                    200, {"email": a, "password": pw_a})
    tb, hb = expect("tenant_b_login", "POST", "/api/v1/auth/login",
                    200, {"email": b, "password": pw_b})
    token_a, token_b = ta.get("accessToken"), tb.get("accessToken")
    if not isinstance(token_a, str) or not isinstance(token_b, str):
        raise RuntimeError("missing signed user access tokens")
    for label, token, ws_name in (("a", token_a, ws_a),
                                  ("b", token_b, ws_b)):
        made, _ = expect("workspace_" + label + "_create",
                         "POST", "/api/v1/workspaces", 201,
                         {"name": ws_name, "kind": "personal"}, token)
        w = made.get("workspace")
        if not isinstance(w, dict) or not isinstance(w.get("id"), str):
            raise RuntimeError("workspace identity missing")
        if not UUID.fullmatch(w["id"]):
            raise RuntimeError("workspace ID format mismatch")
        if label == "a":
            id_a = w["id"]
        else:
            id_b = w["id"]
    own, _ = expect("tenant_a_own_workspaces", "GET",
                    "/api/v1/workspaces", 200, token=token_a)
    foreign, _ = expect("tenant_b_own_workspaces", "GET",
                        "/api/v1/workspaces", 200, token=token_b)
    if ({x.get("id") for x in own.get("workspaces", [])} != {id_a}
            or {x.get("id") for x in foreign.get("workspaces", [])} != {id_b}):
        raise RuntimeError("tenant-scoped list mismatch")
    expect("foreign_workspace_summary_denied", "GET",
           "/api/v1/workspaces/" + id_a + "/summary", 403, token=token_b)
    expect("foreign_website_list_denied", "GET",
           "/api/v1/workspaces/" + id_a + "/sites", 403, token=token_b)
    origin = "https://qa-" + tag + ".example.invalid"
    created, _ = expect("website_create", "POST",
                        "/api/v1/workspaces/" + id_a + "/sites", 201,
                        {"name": "Task014 QA " + tag, "origin": origin},
                        token=token_a)
    site = created.get("site", {})
    key = site.get("ingestKey")
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32}", key):
        raise RuntimeError("real website collector key invalid")
    # Exercise the existing owner tracking switch only on this new QA site.
    site_id = site.get("id")
    if not isinstance(site_id, str) or not UUID.fullmatch(site_id):
        raise RuntimeError("QA site identity missing")
    site_path = "/api/v1/workspaces/" + id_a + "/sites/" + site_id
    expect("anonymous_website_denied", "GET", site_path, 401)
    expect("foreign_website_update_denied", "PATCH", site_path, 403,
           {"trackingEnabled": False}, token_b)
    expect("owner_tracking_disabled", "PATCH", site_path, 200,
           {"trackingEnabled": False}, token_a)
    expect("disabled_collector_denied", "POST", "/api/v1/collect/" + key, 403,
           {"eventType": "pageview", "path": "/qa-disabled-" + tag}, origin=origin)
    empty, no_cache = expect("disabled_site_no_event_persisted", "GET",
           "/api/v1/workspaces/" + id_a + "/summary?timeframe=24h", 200, token=token_a)
    if empty.get("pageviews") != 0 or no_cache.get("cache-control") != "no-store":
        raise RuntimeError("disabled collector persistence or report caching mismatch")
    expect("owner_tracking_enabled", "PATCH", site_path, 200,
           {"trackingEnabled": True}, token_a)
    expect("collector_wrong_origin_denied", "POST",
           "/api/v1/collect/" + key, 403,
           {"eventType": "pageview", "path": "/qa-" + tag,
            "sessionId": "Task014QASession01"},
           origin="https://wrong-" + tag + ".example.invalid")
    accepted, cors = expect("collector_event_accepted", "POST",
                            "/api/v1/collect/" + key, 202,
                            {"eventType": "pageview", "path": "/qa-" + tag,
                             "sessionId": "Task014QASession01"},
                            origin=origin)
    if cors.get("access-control-allow-origin") != origin:
        raise RuntimeError("collector CORS response unexpected")
    summary, _ = expect("persisted_workspace_summary", "GET",
                        "/api/v1/workspaces/" + id_a + "/summary?timeframe=24h",
                        200, token=token_a)
    if (summary.get("pageviews") != 1
            or summary.get("uniqueSessions") != 1):
        raise RuntimeError("persisted analytics counts do not match")
    refreshed, _ = expect("signed_refresh_token", "POST",
                          "/api/v1/auth/refresh-token", 200,
                          {"refreshToken": tb["refreshToken"]})
    if not isinstance(refreshed.get("accessToken"), str):
        raise RuntimeError("refresh JSON response lacks access token")
    for label, token in (("tenant_a", token_a), ("tenant_b", token_b),
                         ("admin", admin_token)):
        expect("logout_" + label, "POST", "/api/v1/auth/logout",
               200, token=token)
        expect("revoked_" + label, "GET", "/api/v1/auth/me",
               401, token=token)
    return id_a, id_b


# Section 6: Exact marker-scoped cleanup, guarded SQL transaction, no CASCADE.
def cleanup_sql(emails: tuple[str, str, str], names: tuple[str, str]) -> str:
    """Build a fixed deletion script limited to matching fixture identities."""
    e = ",".join(sql_literal(x) for x in emails)
    w = ",".join(sql_literal(x) for x in names)
    user = '(SELECT "id" FROM public."User" WHERE "email" IN (' + e + '))'
    work = '(SELECT "id" FROM public."Workspace" WHERE "name" IN (' + w + '))'
    # DO block rejects any unexpected membership; never erase other identities.
    guard = (
        "DO $guard$ BEGIN\n"
        "IF EXISTS (SELECT 1 FROM public.\"WorkspaceMembership\" m "
        "WHERE m.\"workspaceId\" IN " + work +
        " AND m.\"userId\" NOT IN " + user + ") THEN "
        "RAISE EXCEPTION 'Foreign membership on test Workspace'; END IF;\n"
        "IF EXISTS (SELECT 1 FROM public.\"WorkspaceMembership\" m "
        "WHERE m.\"userId\" IN " + user +
        " AND m.\"workspaceId\" NOT IN " + work + ") THEN "
        "RAISE EXCEPTION 'Test user linked to foreign Workspace'; END IF;\n"
        "IF (SELECT COUNT(*) FROM public.\"Workspace\" WHERE \"name\" IN (" + w +
        ")) > 2 THEN RAISE EXCEPTION 'Ambiguous QA Workspace'; END IF;\n"
        "END $guard$;\n"
    )
    statements = [
        'DELETE FROM public."WebsiteAnalyticsDaily" WHERE "workspaceId" IN ' + work,
        'DELETE FROM public."WorkspaceAnalyticsDaily" WHERE "workspaceId" IN ' + work,
        'DELETE FROM public."WorkspaceAnalyticsEvent" WHERE "workspaceId" IN ' + work,
        'DELETE FROM public."Website" WHERE "workspaceId" IN ' + work,
        'DELETE FROM public."WorkspaceMembership" WHERE "workspaceId" IN ' + work,
        'DELETE FROM public."Workspace" WHERE "name" IN (' + w + ')',
        'DELETE FROM public."Session" WHERE "userId" IN ' + user,
        'DELETE FROM public."User" WHERE "email" IN (' + e + ')',
    ]
    # Double-verification uses exact email/name only, no full-table cleanup.
    verify = (
        'SELECT (SELECT COUNT(*) FROM public."User" WHERE "email" IN (' + e +
        ')),(SELECT COUNT(*) FROM public."Workspace" WHERE "name" IN (' + w +
        '));\n'
    )
    return ("BEGIN;\nSET LOCAL lock_timeout='3s';\n"
            "SET LOCAL statement_timeout='20s';\n"
            + guard + "\n".join(s + ";" for s in statements)
            + "\n" + verify + "COMMIT;\n")


def cleanup(db: str, principal: str, emails: tuple[str, str, str],
            workspaces: tuple[str, str], ledger: Path) -> None:
    """Delete only fixture-owned records atomically and remove recovery ledger."""
    statements = cleanup_sql(emails, workspaces)
    result = sql(db, principal, statements)
    if result.splitlines()[-1].strip() != "0|0":
        raise RuntimeError("fixture cleanup verification failed")
    ledger.unlink()
    print("SIGNED_DEV_E2E_CLEANUP_PASS users=0 workspaces=0", flush=True)


def recovery_only() -> int:
    """Operator-mode cleanup for an interrupted owner-approved test run."""
    try:
        ledger, emails, names = read_pending_ledger()
        _, database = signed_private_runtime()
        principal = postgres_principal(database)
        cleanup(database, principal, emails, names, ledger)
        print("SIGNED_DEV_E2E_RECOVERY_CLEAN_PASS", flush=True)
        return 0
    except Exception as error:
        print("SIGNED_DEV_E2E_RECOVERY_HOLD error_type=" +
              type(error).__name__, flush=True)
        return 3


def interrupt_for_cleanup(signal_number: int, _frame: object) -> None:
    """Convert ordinary interactive interruption into caught finally cleanup."""
    raise InterruptedError("signed fixture interrupted")


# Section 7: Preflight then one approved test plus unconditional cleanup.
def main() -> int:
    """Execute one approved QA journey, refuse retries and always clean up."""
    signal.signal(signal.SIGTERM, interrupt_for_cleanup)
    signal.signal(signal.SIGINT, interrupt_for_cleanup)
    stage = "signed_release_preflight"
    ledger: Path | None = None
    db = principal = ""
    emails: tuple[str, str, str] | None = None
    names: tuple[str, str] | None = None
    failed = False
    try:
        app_id, db = signed_private_runtime()
        principal = postgres_principal(db)
        print("SIGNED_DEV_E2E_PREFLIGHT_PASS", flush=True)
        # Root SQL guard checks DBA and intended DB before creating fixture.
        before = sql(db, principal,
                     "BEGIN READ ONLY;\n"
                     "SELECT current_database(), current_setting('server_version_num'),"
                     " coalesce((SELECT rolsuper FROM pg_catalog.pg_roles"
                     " WHERE rolname=current_user),false);\nROLLBACK;\n")
        if not re.fullmatch(r"omnilyzer_analytics_dev\|16[0-9]{4}\|t", before.strip()):
            raise RuntimeError("authorized PG16 DBA mismatch")
        status, _, _ = request("GET", "/readyz")
        if status != 200:
            raise RuntimeError("signed private readiness failed")
        tag = secrets.token_hex(8)
        emails = (f"qa-admin-{tag}@example.invalid",
                  f"qa-a-{tag}@example.invalid",
                  f"qa-b-{tag}@example.invalid")
        names = (f"Task014 QA A {tag}", f"Task014 QA B {tag}")
        # The ledger exists *before* any fixture creation; it contains no token.
        stage = "create_recovery_ledger"
        once = RUN_DIR / ".m05-analytics016-43838827603-acceptance-consumed"
        fd = os.open(once, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, b"Task014 43838827603; one acceptance only; no automatic retry\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(RUN_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        ledger = new_ledger(tag, emails, names)
        stage = "signed_http_end_to_end"
        fixture_flow(db, principal, tag, emails, names)
    except Exception as error:
        failed = True
        # No exception message: it could contain secrets from a lower layer.
        print("SIGNED_DEV_E2E_HOLD stage=" + stage +
              " error_type=" + type(error).__name__, flush=True)
    finally:
        if ledger is not None and emails is not None and names is not None:
            try:
                stage = "fixture_cleanup"
                cleanup(db, principal, emails, names, ledger)
            except Exception as error:
                print("SIGNED_DEV_CLEANUP_HOLD error_type=" +
                      type(error).__name__, flush=True)
                return 3
    # Recheck signed application readiness after verified database cleanup.
    try:
        status, _, _ = request("GET", "/readyz")
        if status != 200:
            raise RuntimeError("signed readiness after cleanup failed")
        print("SIGNED_DEV_E2E_POST_CLEANUP_READY_PASS", flush=True)
    except Exception:
        print("SIGNED_DEV_E2E_POST_CLEANUP_READY_HOLD", flush=True)
        return 2
    if failed:
        return 2
    print("SIGNED_DEV_E2E_COMPLETE_PASS test_data_removed=true", flush=True)
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--cleanup-pending"]:
        raise SystemExit(recovery_only())
    if sys.argv[1:]:
        raise SystemExit("Unsupported action")
    raise SystemExit(main())
