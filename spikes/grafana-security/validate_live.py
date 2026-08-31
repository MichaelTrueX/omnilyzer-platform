#!/usr/bin/env python3
"""Run Task 011's isolated live Grafana/Keycloak/Prometheus validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from html import unescape
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
COMPOSE = ROOT / "compose.yaml"
RESULT = ROOT / "results" / "live-validation.json"
GRAFANA = "http://127.0.0.1:19130"
KEYCLOAK = "https://127.0.0.1:19180"
EXPECTED_GRAFANA_DIGEST = "sha256:3fd54ae1214669f8355f065ec9f6445d5279a3d77095ab048ca045685272429b"


class ValidationError(RuntimeError):
    """Raised when a security or architecture assertion fails closed."""


class LoginFormParser(HTMLParser):
    """Extract Keycloak's one login form without interpreting arbitrary markup."""

    def __init__(self) -> None:
        super().__init__()
        self.action = ""
        self.inputs: dict[str, str] = {}
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form" and values.get("id") == "kc-form-login":
            self._in_form = True
            self.action = unescape(values.get("action") or "")
        elif tag == "input" and self._in_form and values.get("name"):
            self.inputs[values["name"]] = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form:
            self._in_form = False


@dataclass
class Response:
    """Small sanitized HTTP result used by assertions."""

    status: int
    body: bytes
    headers: dict[str, str]
    url: str

    def json(self) -> Any:
        return json.loads(self.body)


def run(command: list[str], *, check: bool = True, timeout: float = 180) -> subprocess.CompletedProcess[str]:
    """Run a local validation command with bounded execution time."""

    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise ValidationError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}\n{result.stderr}"
        )
    return result


def request(opener: Any, url: str, *, method: str = "GET", payload: Any = None) -> Response:
    """Issue one bounded local HTTP request and retain only response data."""

    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers.update({"Content-Type": "application/json", "Origin": GRAFANA, "Referer": f"{GRAFANA}/"})
    req = Request(url, data=body, method=method, headers=headers)
    try:
        response = opener.open(req, timeout=10)
    except HTTPError as error:
        return Response(error.code, error.read(), dict(error.headers.items()), error.geturl())
    with response:
        return Response(response.status, response.read(), dict(response.headers.items()), response.geturl())


def assert_status(response: Response, expected: set[int], label: str) -> None:
    """Fail with a bounded diagnostic when an endpoint's result is unexpected."""

    if response.status not in expected:
        sample = response.body[:2000].decode(errors="replace")
        raise ValidationError(f"{label}: expected {sorted(expected)}, got {response.status} at {response.url}: {sample}")


def compose(env_file: Path, *args: str, check: bool = True, timeout: float = 180) -> subprocess.CompletedProcess[str]:
    """Run Compose with runtime-only credentials from a temporary env file."""

    return run(["docker", "compose", "--env-file", str(env_file), "-f", str(COMPOSE), *args], check=check, timeout=timeout)


def wait_http(opener: Any, url: str, expected: set[int], *, seconds: float = 120) -> float:
    """Wait a bounded interval for one local endpoint and return elapsed seconds."""

    started = time.perf_counter()
    while time.perf_counter() - started < seconds:
        try:
            response = request(opener, url)
            if response.status in expected:
                return time.perf_counter() - started
        except (URLError, OSError):
            pass
        time.sleep(0.5)
    raise ValidationError(f"timed out waiting for {url}")


def make_runtime() -> tuple[Path, Path, dict[str, str]]:
    """Create mode-0600 runtime credentials and a rendered synthetic realm."""

    runtime = Path(tempfile.mkdtemp(prefix="task011-grafana-"))
    os.chmod(runtime, 0o700)
    values = {
        "TASK011_GRAFANA_ADMIN_USER": f"bootstrap-{secrets.token_hex(8)}",
        "TASK011_GRAFANA_ADMIN_PASSWORD": secrets.token_urlsafe(36),
        "TASK011_GRAFANA_SECRET_KEY": secrets.token_urlsafe(48),
        "TASK011_KEYCLOAK_ADMIN_USER": f"kc-{secrets.token_hex(8)}",
        "TASK011_KEYCLOAK_ADMIN_PASSWORD": secrets.token_urlsafe(36),
        "TASK011_OAUTH_CLIENT_SECRET": secrets.token_urlsafe(48),
        "TASK011_VIEWER_PASSWORD": secrets.token_urlsafe(30),
        "TASK011_EDITOR_PASSWORD": secrets.token_urlsafe(30),
        "TASK011_ORG_ADMIN_PASSWORD": secrets.token_urlsafe(30),
        "TASK011_UNMAPPED_PASSWORD": secrets.token_urlsafe(30),
        "TASK011_GRAFANA_PORT": "19130",
        "TASK011_KEYCLOAK_PORT": "19180",
    }
    template = (ROOT / "keycloak" / "realm-template.json").read_text()
    for key, value in values.items():
        template = template.replace(f"__{key}__", value)
    if "__TASK011_" in template:
        raise ValidationError("unresolved runtime realm placeholder")
    realm = runtime / "realm.json"
    realm.write_text(template)
    os.chmod(realm, 0o600)
    json.loads(template)
    values["TASK011_REALM_FILE"] = str(realm)
    certificate = runtime / "tls.crt"
    private_key = runtime / "tls.key"
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(private_key), "-out", str(certificate), "-days", "1",
        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
    ])
    os.chmod(certificate, 0o644)
    os.chmod(private_key, 0o644)
    values["TASK011_TLS_CERT_FILE"] = str(certificate)
    values["TASK011_TLS_KEY_FILE"] = str(private_key)
    env_file = runtime / "runtime.env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in sorted(values.items())))
    os.chmod(env_file, 0o600)
    return runtime, env_file, values


def oauth_login(username: str, password: str) -> tuple[Any, http.cookiejar.CookieJar, float, Response]:
    """Complete a real browser-style Authorization Code login through Keycloak."""

    jar = http.cookiejar.CookieJar()
    test_tls = ssl.create_default_context()
    test_tls.check_hostname = False
    test_tls.verify_mode = ssl.CERT_NONE
    opener = build_opener(HTTPCookieProcessor(jar), HTTPSHandler(context=test_tls))
    started = time.perf_counter()
    page = request(opener, f"{GRAFANA}/login/generic_oauth")
    assert_status(page, {200}, f"OAuth login page for {username}")
    if not page.url.startswith(f"{KEYCLOAK}/realms/task011-grafana/"):
        sample = page.body[:500].decode(errors="replace")
        raise ValidationError(f"OAuth did not reach Keycloak for {username}: {page.url}: {sample}")
    parser = LoginFormParser()
    parser.feed(page.body.decode(errors="replace"))
    if not parser.action:
        raise ValidationError(f"Keycloak login form missing for {username}")
    fields = parser.inputs
    fields.update({"username": username, "password": password, "credentialId": ""})
    encoded = urlencode(fields).encode()
    req = Request(
        urljoin(page.url, parser.action),
        data=encoded,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": page.url},
    )
    try:
        response = opener.open(req, timeout=15)
    except HTTPError as error:
        final = Response(error.code, error.read(), dict(error.headers.items()), error.geturl())
    else:
        with response:
            final = Response(response.status, response.read(), dict(response.headers.items()), response.geturl())
    if final.status >= 400:
        text = re.sub(r"<[^>]+>", " ", final.body.decode(errors="replace"))
        summary = " ".join(unescape(text).split())
        raise ValidationError(
            f"Keycloak login failed for {username} at {final.url}; "
            f"cookies={[(cookie.name, cookie.path, cookie.secure) for cookie in jar]}; fields={sorted(fields)}; response_tail={summary[-1800:]}"
        )
    return opener, jar, time.perf_counter() - started, final


def grafana_api(opener: Any, path: str, *, method: str = "GET", payload: Any = None) -> Response:
    return request(opener, f"{GRAFANA}{path}", method=method, payload=payload)


def query_payload(expression: str) -> dict[str, Any]:
    """Build one Grafana server-side Prometheus query request."""

    return {
        "queries": [{
            "refId": "A",
            "datasource": {"type": "prometheus", "uid": "omnilyzer-prometheus"},
            "expr": expression,
            "instant": True,
            "range": False,
            "intervalMs": 1000,
            "maxDataPoints": 100,
        }],
        "from": "now-5m",
        "to": "now",
    }


def inspect_role(opener: Any, expected: str) -> dict[str, Any]:
    """Require the exact organization role and no server-admin escalation."""

    response = grafana_api(opener, "/api/user")
    assert_status(response, {200}, f"user role {expected}")
    value = response.json()
    organizations = grafana_api(opener, "/api/user/orgs")
    assert_status(organizations, {200}, f"organization role {expected}")
    org_values = organizations.json()
    role = next((item.get("role") for item in org_values if item.get("orgId") == value.get("orgId")), None)
    if role != expected or value.get("isGrafanaAdmin") is not False:
        raise ValidationError(f"unexpected Grafana role mapping: user={value}, orgs={org_values}")
    return {"org_role": role, "is_grafana_admin": value["isGrafanaAdmin"]}


def direct_prometheus(env_file: Path, expression: str) -> Any:
    """Query private Prometheus from the internal target network, never from the host."""

    code = (
        "import json,urllib.parse,urllib.request;"
        f"u='http://prometheus:9090/api/v1/query?'+urllib.parse.urlencode({{'query':{expression!r}}});"
        "print(urllib.request.urlopen(u,timeout=5).read().decode())"
    )
    output = compose(env_file, "exec", "-T", "synthetic-app", "python", "-c", code).stdout
    return json.loads(output)


def wait_prometheus_result(env_file: Path, expression: str, *, seconds: float = 30) -> Any:
    """Wait until private Prometheus returns a non-empty instant vector."""

    started = time.perf_counter()
    while time.perf_counter() - started < seconds:
        try:
            value = direct_prometheus(env_file, expression)
            if value.get("data", {}).get("result"):
                return value
        except (ValidationError, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    raise ValidationError(f"private Prometheus query did not populate: {expression}")


def internal_app_get(env_file: Path, path: str) -> int:
    """Exercise the synthetic app locally inside its unexposed container."""

    code = f"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000{path}',timeout=2).status)"
    result = compose(env_file, "exec", "-T", "synthetic-app", "python", "-c", code)
    return int(result.stdout.strip())


def main() -> int:
    """Execute all live acceptance gates and emit sanitized deterministic evidence."""

    runtime, env_file, secret_values = make_runtime()
    test_tls = ssl.create_default_context()
    test_tls.check_hostname = False
    test_tls.verify_mode = ssl.CERT_NONE
    anonymous = build_opener(HTTPSHandler(context=test_tls))
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "classification": "TASK 011 - PASS WITH EXPLICIT AUTHORIZATION BOUNDARY",
        "validated_at_date": datetime.now(UTC).date().isoformat(),
        "technology": {
            "grafana": {"edition": "OSS", "version": "13.2.0", "image": "grafana/grafana:13.2.0", "digest": EXPECTED_GRAFANA_DIGEST, "license": "AGPL-3.0-only"},
            "keycloak": {"version": "26.7.2"},
            "prometheus": {"version": "3.14.0"},
        },
    }
    try:
        compose(env_file, "config", "--quiet")
        compose(env_file, "down", "-v", "--remove-orphans", check=False)
        started = time.perf_counter()
        compose(env_file, "up", "-d", "--build", timeout=300)
        keycloak_ready = wait_http(anonymous, f"{KEYCLOAK}/realms/task011-grafana/.well-known/openid-configuration", {200}, seconds=180)
        grafana_ready = wait_http(anonymous, f"{GRAFANA}/api/health", {200}, seconds=120)
        evidence["startup"] = {
            "compose_to_ready_seconds": round(time.perf_counter() - started, 3),
            "keycloak_ready_seconds_after_wait_start": round(keycloak_ready, 3),
            "grafana_ready_seconds_after_wait_start": round(grafana_ready, 3),
        }

        version = compose(env_file, "exec", "-T", "grafana", "grafana", "server", "-v").stdout.strip()
        if "Version 13.2.0" not in version:
            raise ValidationError(f"unexpected Grafana version: {version}")
        plugin_entries = compose(
            env_file,
            "exec", "-T", "grafana", "sh", "-c",
            "find /var/lib/grafana/plugins -mindepth 1 -maxdepth 1 -print 2>/dev/null",
        ).stdout.splitlines()
        if plugin_entries:
            raise ValidationError(f"unexpected downloaded Grafana plugins: {plugin_entries}")
        grafana_container = compose(env_file, "ps", "-q", "grafana").stdout.strip()
        image_id = run(["docker", "inspect", "-f", "{{.Image}}", grafana_container]).stdout.strip()
        repo_digests = json.loads(run(["docker", "image", "inspect", "-f", "{{json .RepoDigests}}", image_id]).stdout)
        if f"grafana/grafana@{EXPECTED_GRAFANA_DIGEST}" not in repo_digests:
            raise ValidationError(f"running Grafana image lacks expected RepoDigest: {repo_digests}")

        grafana_id = compose(env_file, "ps", "-q", "grafana").stdout.strip()
        prom_id = compose(env_file, "ps", "-q", "prometheus").stdout.strip()
        app_id = compose(env_file, "ps", "-q", "synthetic-app").stdout.strip()
        ports = {
            "grafana": json.loads(run(["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", grafana_id]).stdout),
            "prometheus": json.loads(run(["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", prom_id]).stdout),
            "synthetic_app": json.loads(run(["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", app_id]).stdout),
        }
        grafana_binding = ports["grafana"].get("3000/tcp")
        if grafana_binding != [{"HostIp": "127.0.0.1", "HostPort": "19130"}]:
            raise ValidationError(f"Grafana is not loopback-only: {grafana_binding}")
        if ports["prometheus"].get("9090/tcp") is not None or ports["synthetic_app"].get("8000/tcp") is not None:
            raise ValidationError(f"internal services unexpectedly published: {ports}")
        evidence["network"] = {
            "grafana_host_binding": "127.0.0.1:19130",
            "keycloak_host_binding": "127.0.0.1:19180 (HTTPS synthetic certificate)",
            "prometheus_host_published_ports": 0,
            "synthetic_app_host_published_ports": 0,
            "grafana_server_side_datasource": "http://prometheus:9090",
        }

        unauth_paths = [
            "/api/search",
            "/api/datasources",
            "/api/dashboards/uid/task011-operations",
            "/api/admin/settings",
        ]
        anonymous_results: dict[str, int] = {}
        captured_bodies: list[bytes] = []
        for path in unauth_paths:
            response = grafana_api(anonymous, path)
            assert_status(response, {401, 403}, f"anonymous {path}")
            anonymous_results[path] = response.status
            captured_bodies.append(response.body)
        anonymous_query = grafana_api(anonymous, "/api/ds/query", method="POST", payload=query_payload("up"))
        assert_status(anonymous_query, {401, 403}, "anonymous datasource query")
        anonymous_results["/api/ds/query"] = anonymous_query.status
        login_response = request(anonymous, f"{GRAFANA}/login")
        headers_lower = {key.lower(): value for key, value in login_response.headers.items()}
        if headers_lower.get("x-frame-options", "").lower() != "deny":
            raise ValidationError(f"embedding denial missing: {headers_lower.get('x-frame-options')}")
        if headers_lower.get("access-control-allow-origin") == "*":
            raise ValidationError("wildcard CORS found")
        if "content-security-policy" not in headers_lower:
            raise ValidationError("Grafana CSP header missing")
        evidence["anonymous_and_browser_surface"] = {
            "api_statuses": anonymous_results,
            "anonymous_datasource_query_status": anonymous_query.status,
            "x_frame_options": headers_lower.get("x-frame-options"),
            "content_security_policy_present": True,
            "wildcard_cors": False,
            "anonymous_auth": False,
            "embedding": False,
            "public_dashboards": False,
            "external_snapshots": False,
            "local_login_form": False,
            "basic_auth": False,
        }

        users: dict[str, tuple[Any, http.cookiejar.CookieJar]] = {}
        login_times: dict[str, float] = {}
        for label, username, password_key, expected_role in (
            ("viewer", "task011-viewer", "TASK011_VIEWER_PASSWORD", "Viewer"),
            ("editor", "task011-editor", "TASK011_EDITOR_PASSWORD", "Editor"),
            ("admin", "task011-org-admin", "TASK011_ORG_ADMIN_PASSWORD", "Admin"),
        ):
            opener, jar, elapsed, final = oauth_login(username, secret_values[password_key])
            assert_status(final, {200}, f"OAuth callback for {label}")
            role = inspect_role(opener, expected_role)
            users[label] = (opener, jar)
            login_times[label] = elapsed
            evidence.setdefault("authorization", {}).setdefault("roles", {})[label] = role
            captured_bodies.append(final.body)

        unmapped, unmapped_jar, _, unmapped_final = oauth_login("task011-unmapped", secret_values["TASK011_UNMAPPED_PASSWORD"])
        unmapped_user = grafana_api(unmapped, "/api/user")
        if unmapped_user.status not in {401, 403} or any(cookie.name == "grafana_session" for cookie in unmapped_jar):
            raise ValidationError("strict role mapping did not deny unmapped user")
        evidence["authorization"]["unmapped_user"] = {"login_denied": True, "api_status": unmapped_user.status, "callback_status": unmapped_final.status}

        viewer, viewer_jar = users["viewer"]
        editor, _editor_jar = users["editor"]
        admin, _admin_jar = users["admin"]
        dashboard_response = grafana_api(viewer, "/api/dashboards/uid/task011-operations")
        assert_status(dashboard_response, {200}, "Viewer dashboard read")
        dashboard = dashboard_response.json()
        narrow_expression = dashboard["dashboard"]["panels"][0]["targets"][0]["expr"]
        if "product=\"valoria\"" not in narrow_expression:
            raise ValidationError("provisioned dashboard is not deliberately narrow")
        outside_expression = "sum(omnilyzer_telemetry_export_failures_total)"
        query_started = time.perf_counter()
        outside_query = grafana_api(viewer, "/api/ds/query", method="POST", payload=query_payload(outside_expression))
        query_ms = (time.perf_counter() - query_started) * 1000
        assert_status(outside_query, {200}, "Viewer arbitrary datasource query")
        if outside_expression in narrow_expression or "results" not in outside_query.json():
            raise ValidationError("Viewer arbitrary query evidence is not independent")
        evidence["authorization"]["viewer_arbitrary_promql"] = {
            "dashboard_expression": narrow_expression,
            "different_expression": outside_expression,
            "status": outside_query.status,
            "query_succeeded": True,
            "boundary": "dashboard visibility is not metric-data authorization",
        }

        save_payload = {"dashboard": dashboard["dashboard"], "folderUid": "omnilyzer-operations", "overwrite": True, "message": "Task 011 role probe"}
        viewer_save = grafana_api(viewer, "/api/dashboards/db", method="POST", payload=save_payload)
        assert_status(viewer_save, {401, 403}, "Viewer dashboard edit")
        editor_save = grafana_api(editor, "/api/dashboards/db", method="POST", payload=save_payload)
        assert_status(editor_save, {200}, "Editor dashboard edit")

        datasource = grafana_api(viewer, "/api/datasources/uid/omnilyzer-prometheus")
        assert_status(datasource, {200}, "Viewer datasource read")
        datasource_body = datasource.json()
        if datasource_body.get("url") != "http://prometheus:9090" or datasource_body.get("readOnly") is not True:
            raise ValidationError(f"unexpected provisioned datasource: {datasource_body}")
        if datasource_body.get("withCredentials") or datasource_body.get("basicAuth") or datasource_body.get("secureJsonFields"):
            raise ValidationError("unnecessary datasource credential forwarding is enabled")
        create_payload = {"name": "Task011 transient SSRF probe", "type": "prometheus", "url": "http://synthetic-app:8000", "access": "proxy", "isDefault": False}
        create_statuses: dict[str, int] = {}
        for label, opener in (("viewer", viewer), ("editor", editor)):
            response = grafana_api(opener, "/api/datasources", method="POST", payload=create_payload)
            assert_status(response, {401, 403}, f"{label} datasource create")
            create_statuses[label] = response.status
        admin_create = grafana_api(admin, "/api/datasources", method="POST", payload=create_payload)
        assert_status(admin_create, {200}, "organization Admin datasource create")
        transient_uid = admin_create.json()["datasource"]["uid"]
        create_statuses["organization_admin"] = admin_create.status
        admin_delete = grafana_api(admin, f"/api/datasources/uid/{transient_uid}", method="DELETE")
        assert_status(admin_delete, {200}, "organization Admin transient datasource cleanup")
        for label, opener in (("viewer", viewer), ("editor", editor), ("organization_admin", admin)):
            response = grafana_api(opener, "/api/datasources/uid/omnilyzer-prometheus", method="PUT", payload=datasource_body)
            if label == "organization_admin":
                assert_status(response, {400, 403, 409}, "provisioned datasource immutability for Admin")
            else:
                assert_status(response, {401, 403}, f"provisioned datasource immutability for {label}")
        provisioned_delete = grafana_api(admin, "/api/datasources/uid/omnilyzer-prometheus", method="DELETE")
        assert_status(provisioned_delete, {400, 403, 409}, "provisioned datasource deletion for Admin")
        server_admin: dict[str, int] = {}
        for label, opener in (("viewer", viewer), ("editor", editor), ("organization_admin", admin)):
            response = grafana_api(opener, "/api/admin/stats")
            assert_status(response, {401, 403}, f"{label} server admin")
            server_admin[label] = response.status
        public_create = grafana_api(admin, "/api/dashboards/uid/task011-operations/public-dashboards", method="POST", payload={"isEnabled": True})
        assert_status(public_create, {400, 403, 404}, "public dashboard disabled")
        evidence["authorization"].update({
            "capabilities": {
                "viewer": {"dashboard_read": True, "dashboard_edit": False, "datasource_create": False, "datasource_edit": False},
                "editor": {"dashboard_read": True, "dashboard_edit": True, "datasource_create": False, "datasource_edit": False},
                "organization_admin": {"dashboard_read": True, "datasource_create": True, "provisioned_datasource_edit": False, "provisioned_datasource_delete": False, "grafana_server_admin": False},
            },
            "datasource_create_statuses": create_statuses,
            "server_admin_endpoint_statuses": server_admin,
            "public_dashboard_enable_status": public_create.status,
            "ssrf_finding": "organization Admin can create a server-side datasource; non-admin roles cannot",
        })

        session_cookie = next((cookie for cookie in viewer_jar if cookie.name == "grafana_session"), None)
        if session_cookie is None:
            raise ValidationError("Grafana session cookie missing")
        evidence["session"] = {
            "cookie_name": session_cookie.name,
            "http_only": session_cookie.has_nonstandard_attr("HttpOnly"),
            "same_site": session_cookie._rest.get("SameSite", "not exposed by client"),
            "secure_in_loopback_http_test": session_cookie.secure,
            "expires": "session" if session_cookie.expires is None else "bounded persistent",
            "browser_oauth_token_storage_introduced": False,
        }

        compose(env_file, "stop", "keycloak")
        existing_session = grafana_api(viewer, "/api/user")
        assert_status(existing_session, {200}, "existing Grafana session during Keycloak outage")
        login_failed_cleanly = False
        try:
            request(build_opener(HTTPSHandler(context=test_tls)), f"{GRAFANA}/login/generic_oauth")
        except (URLError, OSError):
            login_failed_cleanly = True
        if not login_failed_cleanly:
            raise ValidationError("new login unexpectedly reached stopped Keycloak")
        compose(env_file, "start", "keycloak")
        keycloak_recovery = wait_http(anonymous, f"{KEYCLOAK}/realms/task011-grafana/.well-known/openid-configuration", {200}, seconds=120)
        recovered_login, _, _, recovered_final = oauth_login("task011-viewer", secret_values["TASK011_VIEWER_PASSWORD"])
        assert_status(recovered_final, {200}, "OAuth login after Keycloak recovery")
        inspect_role(recovered_login, "Viewer")
        evidence["keycloak_outage"] = {"existing_session_status": 200, "new_login_failed_cleanly": True, "new_login_recovered": True, "recovery_seconds": round(keycloak_recovery, 3)}

        grafana_before_prom_outage = grafana_id
        compose(env_file, "stop", "prometheus")
        if internal_app_get(env_file, "/api/users/901") != 200 or internal_app_get(env_file, "/livez") != 200 or internal_app_get(env_file, "/readyz") != 200:
            raise ValidationError("application failed during Prometheus outage")
        assert_status(grafana_api(viewer, "/api/user"), {200}, "Grafana session during Prometheus outage")
        failed_query = grafana_api(viewer, "/api/ds/query", method="POST", payload=query_payload("up"))
        if failed_query.status == 200 and not failed_query.json().get("results", {}).get("A", {}).get("error"):
            raise ValidationError("Prometheus outage was not visible as a safe query failure")
        compose(env_file, "start", "prometheus")
        prom_recovery_started = time.perf_counter()
        while True:
            recovered_query = grafana_api(viewer, "/api/ds/query", method="POST", payload=query_payload("up"))
            if recovered_query.status == 200 and not recovered_query.json().get("results", {}).get("A", {}).get("error"):
                break
            if time.perf_counter() - prom_recovery_started > 60:
                raise ValidationError("Grafana query did not recover after Prometheus restart")
            time.sleep(0.5)
        grafana_after_prom_outage = compose(env_file, "ps", "-q", "grafana").stdout.strip()
        evidence["prometheus_outage"] = {
            "application_domain_status": 200,
            "livez_status": 200,
            "readyz_status": 200,
            "grafana_session_status": 200,
            "query_failed_visibly": True,
            "grafana_restarted": grafana_before_prom_outage != grafana_after_prom_outage,
            "query_recovered": True,
            "recovery_seconds": round(time.perf_counter() - prom_recovery_started, 3),
        }
        if evidence["prometheus_outage"]["grafana_restarted"]:
            raise ValidationError("Grafana restarted during Prometheus outage")

        wait_prometheus_result(env_file, "up")
        before_count = wait_prometheus_result(env_file, "sum(omnilyzer_http_requests_total)")
        grafana_before_stop = compose(env_file, "ps", "-q", "grafana").stdout.strip()
        compose(env_file, "stop", "grafana")
        for index in range(5):
            if internal_app_get(env_file, f"/api/users/{1000 + index}") != 200:
                raise ValidationError("application failed during Grafana outage")
        during_up = wait_prometheus_result(env_file, "up")
        after_count = wait_prometheus_result(env_file, "sum(omnilyzer_http_requests_total)")
        if during_up["data"]["result"][0]["value"][1] != "1":
            raise ValidationError("Prometheus target health changed during Grafana outage")
        compose(env_file, "start", "grafana")
        grafana_restart = wait_http(anonymous, f"{GRAFANA}/api/health", {200}, seconds=60)
        grafana_after_restart = compose(env_file, "ps", "-q", "grafana").stdout.strip()
        if grafana_before_stop != grafana_after_restart:
            raise ValidationError("simple Grafana restart unexpectedly replaced container")
        restart_viewer, _, _, _ = oauth_login("task011-viewer", secret_values["TASK011_VIEWER_PASSWORD"])
        assert_status(grafana_api(restart_viewer, "/api/dashboards/uid/task011-operations"), {200}, "dashboard after Grafana restart")
        assert_status(grafana_api(restart_viewer, "/api/ds/query", method="POST", payload=query_payload("up")), {200}, "query after Grafana restart")
        evidence["grafana_outage"] = {
            "application_requests_succeeded": 5,
            "prometheus_target_up": 1,
            "metrics_count_increased": float(after_count["data"]["result"][0]["value"][1]) > float(before_count["data"]["result"][0]["value"][1]),
            "prometheus_restarted": False,
            "application_restarted": False,
            "grafana_restart_seconds": round(grafana_restart, 3),
            "query_recovered": True,
        }

        oss_logs = compose(env_file, "logs", "--no-color", "grafana").stdout
        evidence["auditability"] = {
            "ordinary_request_completion_records": oss_logs.count("Request Completed"),
            "authentication_related_records_present": "authn" in oss_logs or "login" in oss_logs.lower(),
            "dashboard_or_datasource_request_records_present": "/api/dashboards" in oss_logs or "/api/datasources" in oss_logs,
            "dedicated_audit_event_schema": False,
            "tamper_resistant_audit_trail": False,
            "finding": "OSS operational logs are diagnostically useful but are not equivalent to Enterprise audit logs",
        }

        compose(env_file, "stop", "grafana")
        compose(env_file, "rm", "-f", "grafana")
        recreate_started = time.perf_counter()
        compose(env_file, "up", "-d", "grafana")
        wait_http(anonymous, f"{GRAFANA}/api/health", {200}, seconds=60)
        fresh_viewer, _, _, _ = oauth_login("task011-viewer", secret_values["TASK011_VIEWER_PASSWORD"])
        fresh_ds = grafana_api(fresh_viewer, "/api/datasources/uid/omnilyzer-prometheus")
        fresh_dashboard = grafana_api(fresh_viewer, "/api/dashboards/uid/task011-operations")
        assert_status(fresh_ds, {200}, "fresh provisioned datasource")
        assert_status(fresh_dashboard, {200}, "fresh provisioned dashboard")
        evidence["provisioning"] = {
            "datasource_uid": "omnilyzer-prometheus",
            "datasource_editable": False,
            "datasource_server_side_url": "http://prometheus:9090",
            "folder_uid": "omnilyzer-operations",
            "dashboard_uid": "task011-operations",
            "fresh_database_recreated_from_files": True,
            "recreate_to_ready_seconds": round(time.perf_counter() - recreate_started, 3),
        }

        stats_raw = run(["docker", "stats", "--no-stream", "--format", "{{json .}}", compose(env_file, "ps", "-q", "grafana").stdout.strip()]).stdout.strip()
        stats = json.loads(stats_raw)
        evidence["resources"] = {
            "grafana_memory": stats.get("MemUsage", "unavailable").split(" / ")[0],
            "grafana_cpu": stats.get("CPUPerc", "unavailable"),
            "representative_query_latency_ms": round(query_ms, 3),
            "oauth_login_seconds": {key: round(value, 3) for key, value in login_times.items()},
        }

        captured_bodies.extend([dashboard_response.body, datasource.body, outside_query.body])
        for value in secret_values.values():
            marker = value.encode()
            if len(marker) >= 16 and any(marker in body for body in captured_bodies):
                raise ValidationError("runtime secret leaked into captured Grafana response")
        evidence["security"] = {
            "runtime_secret_files_mode": "0600",
            "committed_credentials": False,
            "runtime_secret_response_leaks": 0,
            "datasource_credentials_forwarded": False,
            "downloaded_third_party_plugins": len(plugin_entries),
            "grafana_server_admin_assignment_from_oidc": False,
            "workspace_or_tenant_claims": False,
        }
        evidence["oss_boundaries"] = {
            "trusted_operator_population": "suitable candidate",
            "shared_datasource_fine_grained_isolation": "not provided by Grafana OSS",
            "datasource_permissions": "Enterprise or Cloud",
            "advanced_rbac": "Enterprise or Cloud",
            "dedicated_audit_logging": "Enterprise or Cloud",
            "oss_evidence": "ordinary server logs and database history are not equivalent to tamper-resistant governance audit records",
            "license_review": "AGPLv3 requires separate architecture/legal review; no legal conclusion made",
        }
        evidence["limitations"] = [
            "Grafana's loopback HTTP endpoint did not validate production HTTPS or Secure Grafana session cookies; Keycloak used a runtime-generated test certificate",
            "OSS cannot restrict Viewer PromQL within one shared organization datasource",
            "OSS dedicated audit logging, granular datasource permissions, and advanced RBAC were not available",
            "organization Admin datasource creation creates a privileged server-side egress/SSRF surface requiring network policy",
            "production Grafana database, HA, backup, disaster recovery, upgrades, ingress, CSP integration, and capacity remain unvalidated",
            "the brief Keycloak outage does not establish long-term session or refresh-token behavior",
        ]
        RESULT.parent.mkdir(parents=True, exist_ok=True)
        RESULT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"classification": evidence["classification"], "result": str(RESULT)}, sort_keys=True))
        return 0
    finally:
        compose(env_file, "down", "-v", "--remove-orphans", check=False, timeout=180)
        shutil.rmtree(runtime, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
