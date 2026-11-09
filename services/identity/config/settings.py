"""File: services/identity/config/settings.py
Purpose: Fail-closed configuration of the dedicated Sumlaude browser BFF using
    the shared Keycloak issuer, separate PostgreSQL sessions and S03 admission.
Related: services/identity/config/urls.py, services/identity/identity_bff/views.py,
    services/identity/tests/test_identity.py, services/identity/omnilyzer-identity.service.
"""
import os
from pathlib import Path
from urllib.parse import urlparse
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent


def required(name):
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError("required identity configuration missing: " + name)
    return value


SECRET_KEY = required("DJANGO_SECRET_KEY")
if len(SECRET_KEY) < 50:
    raise RuntimeError("Django signing key too short")
TOKEN_FERNET_KEY = required("TOKEN_FERNET_KEY").encode()
try:
    Fernet(TOKEN_FERNET_KEY)
except (ValueError, TypeError) as exc:
    raise RuntimeError("invalid token encryption key") from exc

DEBUG = False
# Section: This first product BFF may mint cookies and an OIDC redirect ONLY
# for its owner-approved exact public HTTPS origin. Never permit a second host,
# a nonstandard port, credentials in the URL or a lookalike hostname.
PRODUCT_ORIGIN = required("PRODUCT_ORIGIN").rstrip("/")
if PRODUCT_ORIGIN != "https://app.sumlaude.com":
    raise RuntimeError("product origin must equal approved Sumlaude HTTPS origin")
parsed = urlparse(PRODUCT_ORIGIN)
if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
    raise RuntimeError("product origin must be exact HTTPS host")
ALLOWED_HOSTS = [parsed.hostname]
CSRF_TRUSTED_ORIGINS = [PRODUCT_ORIGIN]
OIDC_ISSUER = required("OIDC_ISSUER").rstrip("/")
if urlparse(OIDC_ISSUER).scheme != "https":
    raise RuntimeError("OIDC issuer must be HTTPS")
OIDC_CLIENT_ID = required("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = required("OIDC_CLIENT_SECRET")
OIDC_REDIRECT_URI = PRODUCT_ORIGIN + "/auth/callback"
SUMLAUDE_ISSUER_DSN = required("SUMLAUDE_ISSUER_DSN")
SUMLAUDE_ISSUE_FUNCTION = os.environ.get(
    "SUMLAUDE_ISSUE_FUNCTION", "sumlaude_auth.issue_admitted_oidc_session")
SUMLAUDE_REVOKE_FUNCTION = os.environ.get(
    "SUMLAUDE_REVOKE_FUNCTION", "sumlaude_auth.revoke_issued_oidc_session")
IDENTITY_IDLE_SECONDS = 1800
IDENTITY_ABSOLUTE_SECONDS = 28800
PRODUCT_SESSION_SECONDS = 600
# Production-first GTM pilot: no product cookie until an authenticated
# account holder explicitly declares 18+ through the CSRF-protected BFF.
# Ordinary adult declaration is NOT age verification. Existing S03 secure
# issuer remains the only authorization authority after this choice.
REQUIRE_GTM_ADULT_CHOICE = True

ROOT_URLCONF = "config.urls"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
INSTALLED_APPS = ["django.contrib.contenttypes", "django.contrib.sessions", "identity_bff"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
X_FRAME_OPTIONS = "DENY"
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "__Host-omnilyzer_identity"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_PATH = "/"
SESSION_COOKIE_AGE = IDENTITY_IDLE_SECONDS
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_PATH = "/"
# Store the CSRF secret in the same server-side Django session as the
# confidential Keycloak principal. Existing /auth/csrf returns a masked token
# to S01; no browser-readable standalone CSRF secret or bearer token is used.
CSRF_USE_SESSIONS = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
# Front proxy MUST overwrite and strip client-supplied X-Forwarded-Proto.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
DATABASES = {"default": {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": required("IDENTITY_PG_DATABASE"),
    "USER": required("IDENTITY_PG_USER"),
    "PASSWORD": required("IDENTITY_PG_PASSWORD"),
    "HOST": required("IDENTITY_PG_HOST"),
    "PORT": os.environ.get("IDENTITY_PG_PORT", "5432"),
    "CONN_MAX_AGE": 0,
    "OPTIONS": {"connect_timeout": 5},
}}
