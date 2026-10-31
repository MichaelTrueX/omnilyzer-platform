"""Test-only real Keycloak 26 against the permanent BFF, never production."""
import os
import sys
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse, parse_qs

from cryptography.fernet import Fernet

FIXTURE = Path("/tmp/sumlaude-keycloak-https-handoff-20261028")
sys.path.insert(0, str(FIXTURE))
from tests.browser_harness import complete_keycloak_login
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

runtime = dict(line.split("=", 1) for line in
               Path("/tmp/omnilyzer-auth-spike-runtime.env").read_text().splitlines()
               if "=" in line)
os.environ["SSL_CERT_FILE"] = str(FIXTURE / "tls/local.crt")
os.environ.update({
    "DJANGO_SETTINGS_MODULE": "config.settings",
    "DJANGO_SECRET_KEY": "test_only_" + "a"*60,
    "TOKEN_FERNET_KEY": Fernet.generate_key().decode(),
    "PRODUCT_ORIGIN": "https://testserver",
    "OIDC_ISSUER": "https://127.0.0.1:18443/realms/omnilyzer-auth-spike",
    "OIDC_CLIENT_ID": "omnilyzer-bff-spike",
    "OIDC_CLIENT_SECRET": runtime["OMNILYZER_BFF_SECRET"],
    "SUMLAUDE_ISSUER_DSN": "postgresql://qa-unreachable",
    "IDENTITY_PG_DATABASE": "qa-unused",
    "IDENTITY_PG_USER": "qa-unused",
    "IDENTITY_PG_PASSWORD": "qa-unused",
    "IDENTITY_PG_HOST": "127.0.0.1",
})
import django
django.setup()
from django.conf import settings
from django.test import Client
from identity_bff import issuer
import psycopg

socket = os.environ.get("S03_QA_PG_SOCKET")
if socket:
    assert socket.startswith("/tmp/sumlaude-str013-production-sql.")
    settings.SUMLAUDE_ISSUER_DSN = (
        "host=" + socket + " dbname=sumlaude_learning "
        "user=sumlaude_identity_issuer connect_timeout=5")
actual_issue, actual_revoke = issuer.issue, issuer.revoke
if socket:
    from django.core.management import call_command
    settings.SESSION_ENGINE = "django.contrib.sessions.backends.db"
    settings.DATABASES["default"].update({
        "NAME": "identity_disposable", "USER": "postgres",
        "PASSWORD": "", "HOST": socket, "PORT": ""})
    with psycopg.connect(host=socket, dbname="postgres", user="postgres", autocommit=True) as setup:
        setup.execute("CREATE DATABASE identity_disposable")
    call_command("migrate", interactive=False, verbosity=0)
    print("REAL_POSTGRESQL_SEPARATE_IDENTITY_SESSION_DATABASE_MIGRATED")
else:
    settings.SESSION_ENGINE = "django.contrib.sessions.backends.cache"
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
browser=Client(enforce_csrf_checks=True, HTTP_HOST="testserver")
issued=[]
revoked=[]

def issue(principal):
    assert principal["issuer"] == settings.OIDC_ISSUER
    assert isinstance(principal["sub"], str) and len(principal["sub"]) >= 8
    if socket and issued:
        # Refresh must reuse the same independently approved identity row.
        cookie, digest = actual_issue(principal)
        issued.append(principal)
        return cookie, digest
    if socket:
        # Genuine Keycloak-verified sub, but synthetic admission fixture only.
        with psycopg.connect(host=socket, dbname="sumlaude_learning", user="postgres") as db:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO public.users(email,password_hash,is_active,email_verified,account_status)"
                    " VALUES ('keycloak-real-qa@example.invalid','no-login',true,true,'active') RETURNING id")
                user_id = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO sumlaude_private.external_identity_links"
                    " (user_id,issuer,subject) VALUES (%s,%s,%s)",
                    (user_id, principal["issuer"], principal["sub"]))
                cur.execute(
                    "INSERT INTO sumlaude_private.learner_admission"
                    " (user_id,age_class,assurance,jurisdiction,decision_reference,"
                    " policy_version,approved_at,expires_at)"
                    " VALUES (%s,'adult','verified_adult','PH','synthetic-qa-only',"
                    " 'v1',clock_timestamp()-interval '1 day',"
                    " clock_timestamp()+interval '2 days')", (user_id,))
        cookie, digest = actual_issue(principal)
        issued.append(principal)
        return cookie, digest
    issued.append(principal)
    return "a"*64, "b"*64

def revoke(digest):
    if socket:
        result = actual_revoke(digest)
    else:
        assert digest == "b"*64
        result = True
    revoked.append(digest)
    return result

with mock.patch.object(issuer, "issue", side_effect=issue), mock.patch.object(issuer, "revoke", side_effect=revoke):
    start=browser.get("/auth/login", secure=True)
    assert start.status_code==302, start.status_code
    q=parse_qs(urlparse(start["Location"]).query)
    assert q["code_challenge_method"]==["S256"]
    redirect=complete_keycloak_login(start["Location"], "auth-spike-user",
             runtime["OMNILYZER_TEST_PASSWORD"], settings.OIDC_REDIRECT_URI)
    url=urlparse(redirect)
    result=browser.get(url.path+"?"+url.query, secure=True)
    assert result.status_code==302, (result.status_code, result.content[:120])
    assert result["Location"]=="/start"
    assert len(issued)==1
    assert browser.get("/auth/session", secure=True).json()["authenticated"] is True
    assert browser.cookies["__Host-omnilyzer_identity"]["secure"]
    assert browser.cookies["__Host-sumlaude_session"]["httponly"]
    if socket:
        another = Client(enforce_csrf_checks=True, HTTP_HOST="testserver")
        another.cookies.update(browser.cookies)
        assert another.get("/auth/session", secure=True).json()["authenticated"] is True
        with psycopg.connect(host=socket,dbname="identity_disposable",user="postgres") as db:
            assert db.execute("SELECT count(*) FROM django_session").fetchone()[0] == 1
        print("REAL_POSTGRESQL_DJANGO_SESSION_RECOVERY_PASS")
    print("REAL_KEYCLOAK_NEW_PERSISTENT_BFF_CALLBACK_PASS")
    old_browser_cookies = None
    if socket and os.environ.get("S01_QA_PRIVATE_BUILD_ROOT"):
        from qa_s01_browser_gate import verify
        old_browser_cookies = verify(browser)
    token=browser.get("/auth/csrf", secure=True).json()["csrf_token"]
    first_cookie = browser.cookies["__Host-sumlaude_session"].value
    refreshed=browser.post("/auth/refresh", secure=True, HTTP_ORIGIN="https://testserver",
                           HTTP_X_CSRFTOKEN=token)
    assert refreshed.status_code==200, (refreshed.status_code, refreshed.content[:150])
    assert len(issued)==2 and len(revoked)==1
    assert browser.cookies["__Host-sumlaude_session"].value != first_cookie
    assert browser.get("/auth/session",secure=True).json()["authenticated"] is True
    print("REAL_KEYCLOAK_NEW_PERSISTENT_BFF_REFRESH_ROTATION_PASS")
    token=browser.get("/auth/csrf", secure=True).json()["csrf_token"]
    logout=browser.post("/auth/logout", secure=True, HTTP_ORIGIN="https://testserver",
                        HTTP_X_CSRFTOKEN=token)
    assert logout.status_code==200, logout.status_code
    assert len(revoked)==2
    assert browser.get("/auth/session", secure=True).json()["authenticated"] is False
    if old_browser_cookies is not None:
        verify(browser,authenticated=False,old_cookies=old_browser_cookies)
    if socket:
        with psycopg.connect(host=socket, dbname="sumlaude_learning", user="postgres") as db:
            record = db.execute(
                "SELECT revoked_at FROM sumlaude_private.learner_sessions "
                "WHERE jti_sha256=%s", (bytes.fromhex(revoked[1]),)).fetchone()
            assert record and record[0] is not None
        with psycopg.connect(host=socket,dbname="identity_disposable",user="postgres") as db:
            assert db.execute("SELECT count(*) FROM django_session").fetchone()[0] == 0
        print("REAL_KEYCLOAK_FULL_S03_NATIVE_PG16_SESSION_REVOKE_PASS")
        print("REAL_POSTGRESQL_DJANGO_LOGOUT_SESSION_REMOVAL_PASS")
    else:
        print("REAL_KEYCLOAK_NEW_PERSISTENT_BFF_LOGOUT_PASS")
print("NOTE: all adult/guardian admissions in this isolated test are synthetic QA-only.")
