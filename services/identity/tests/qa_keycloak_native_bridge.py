"""Disposable ONLY: verified Keycloak Django session -> independent S03 QA LC1.
Modes: bootstrap, status, logout. No production DB, network listener or real learner.
The QA product digest is materialized by S03's existing self-cleaning test script,
not the production restricted issuer; production issuer tested independently.
"""
import hashlib
import json
import os
import secrets
import sys
from http.cookies import SimpleCookie
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse,parse_qs

from cryptography.fernet import Fernet
import psycopg

socket=Path(os.environ["S03_QA_PG_SOCKET"]).resolve()
database=os.environ["S03_QA_PG_DATABASE"]
assert str(socket).startswith("/tmp/sumlaude-s03-pg16-qa.")
assert database.startswith("sumlaude_native_qa_disposable_")
mode=sys.argv[1]
assert mode in ("bootstrap","status","logout")
qa_dir=socket.parent
bundle_path=qa_dir/"keycloak-native-bridge.json"
fernet_path=qa_dir/"identity-bridge-fernet.key"
if mode=="bootstrap":
    assert not bundle_path.exists()
    key=Fernet.generate_key()
    fd=os.open(fernet_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as f:f.write(key)
else:
    key=fernet_path.read_bytes()
test_root=Path("/tmp/sumlaude-keycloak-https-handoff-20261028")
runtime=dict(x.split("=",1) for x in Path("/tmp/omnilyzer-auth-spike-runtime.env").read_text().splitlines() if "=" in x)
os.environ["SSL_CERT_FILE"]=str(test_root/"tls/local.crt")
os.environ.update({
    "DJANGO_SETTINGS_MODULE":"config.settings",
    "DJANGO_SECRET_KEY":"TESTONLY_KEYCLOAK_NATIVE_BROWSER_"+"x"*60,
    "TOKEN_FERNET_KEY":key.decode(),
    "PRODUCT_ORIGIN":"https://testserver",
    "OIDC_ISSUER":"https://127.0.0.1:18443/realms/omnilyzer-auth-spike",
    "OIDC_CLIENT_ID":"omnilyzer-bff-spike",
    "OIDC_CLIENT_SECRET":runtime["OMNILYZER_BFF_SECRET"],
    "SUMLAUDE_ISSUER_DSN":"dbname=QA_NEVER_USE_FOR_PRODUCTION_ISSUE",
    "IDENTITY_PG_DATABASE":"identity_disposable",
    "IDENTITY_PG_USER":"postgres",
    "IDENTITY_PG_PASSWORD":"TEST_ONLY_LOCAL_TRUST",
    "IDENTITY_PG_HOST":str(socket),
})
sys.path.insert(0,str(test_root))
from tests.browser_harness import complete_keycloak_login
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import django
django.setup()
from django.conf import settings
from django.test import Client
from identity_bff import issuer

def client_with_cookies():
    client=Client(enforce_csrf_checks=True,HTTP_HOST="testserver")
    raw=os.environ.get("S03_QA_BROWSER_COOKIE_HEADER","")
    jar=SimpleCookie()
    jar.load(raw)
    for k,v in jar.items():client.cookies[k]=v.value
    return client

if mode=="bootstrap":
    with psycopg.connect(host=str(socket),dbname="postgres",user="postgres",autocommit=True) as db:
        db.execute("CREATE DATABASE identity_disposable")
    from django.core.management import call_command
    call_command("migrate",verbosity=0,interactive=False)
    cookie=secrets.token_hex(32)
    recorded=[]
    def issue(principal):
        assert principal["issuer"]==settings.OIDC_ISSUER
        assert isinstance(principal["sub"],str) and len(principal["sub"])>=8
        recorded.append(principal)
        return cookie,hashlib.sha256(cookie.encode("ascii")).hexdigest()
    browser=client_with_cookies()
    with mock.patch.object(issuer,"issue",side_effect=issue):
        start=browser.get("/auth/login",secure=True)
        assert start.status_code==302
        q=parse_qs(urlparse(start["Location"]).query)
        assert q["code_challenge_method"]==["S256"]
        redirected=complete_keycloak_login(start["Location"],"auth-spike-user",
            runtime["OMNILYZER_TEST_PASSWORD"],settings.OIDC_REDIRECT_URI)
        u=urlparse(redirected)
        done=browser.get(u.path+"?"+u.query,secure=True)
        assert done.status_code==302 and done["Location"]=="/start"
    assert len(recorded)==1
    assert browser.get("/auth/session",secure=True).json()["authenticated"] is True
    assert browser.cookies["__Host-omnilyzer_identity"]["secure"]
    assert browser.cookies["__Host-omnilyzer_identity"]["httponly"]
    assert browser.cookies["__Host-sumlaude_session"]["httponly"]
    payload={"issuer":recorded[0]["issuer"],"sub":recorded[0]["sub"],
        "identityCookie":browser.cookies["__Host-omnilyzer_identity"].value,
        "productCookie":browser.cookies["__Host-sumlaude_session"].value}
    fd=os.open(bundle_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as f:json.dump(payload,f)
    print("REAL_KEYCLOAK_26_SIGNED_IDENTITY_DJANGO_PG_SESSION_QA_BOOTSTRAP_PASS")
elif mode=="status":
    client=client_with_cookies()
    response=client.get("/auth/session",secure=True)
    assert response.status_code==200
    # Print only nonsecret auth status; no tokens, cookies or identities.
    sys.stdout.write(response.content.decode())
elif mode=="logout":
    client=client_with_cookies()
    payload=json.loads(bundle_path.read_text())
    digest=hashlib.sha256(payload["productCookie"].encode("ascii")).digest()
    def revoke(value):
        assert bytes.fromhex(value)==digest
        with psycopg.connect(host=str(socket),dbname=database,user="postgres") as db:
            row=db.execute(
                "UPDATE sumlaude_private.learner_sessions SET revoked_at=clock_timestamp() "
                "WHERE jti_sha256=%s AND revoked_at IS NULL RETURNING user_id",
                (digest,)).fetchone()
            return bool(row)
    token=client.get("/auth/csrf",secure=True).json()["csrf_token"]
    with mock.patch.object(issuer,"revoke",side_effect=revoke):
        response=client.post("/auth/logout",secure=True,
            HTTP_ORIGIN="https://testserver",HTTP_X_CSRFTOKEN=token)
    assert response.status_code==200,(response.status_code,response.content[:150])
    assert client.get("/auth/session",secure=True).json()["authenticated"] is False
    with psycopg.connect(host=str(socket),dbname="identity_disposable",user="postgres") as db:
        assert db.execute("SELECT count(*) FROM django_session").fetchone()[0]==0
    print("REAL_KEYCLOAK_DJANGO_POSTGRES_LOGOUT_QA_PASS")
