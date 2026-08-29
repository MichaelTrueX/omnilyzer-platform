from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = "authentication-spike-only-not-for-production"
DEBUG = False
ALLOWED_HOSTS = ["testserver"]
ROOT_URLCONF = "config.urls"
USE_TZ = True
TIME_ZONE = "UTC"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "authspike",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

_DATABASE = {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": "omnilyzer_platform_auth_spike",
    "HOST": "/tmp/omnilyzer-platform-auth-spike-socket",
    "PORT": "55436",
    "CONN_MAX_AGE": 0,
}
DATABASES = {
    "default": {**_DATABASE, "USER": "omnilyzer_auth_runtime"},
    "migration": {**_DATABASE, "USER": "omnilyzer_auth_owner"},
}
DATABASE_ROUTERS = ["config.database_router.SessionDatabaseRouter"]

SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "__Host-omnilyzer_session"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_PATH = "/"
SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_PATH = "/"
CSRF_COOKIE_SAMESITE = "Lax"

OIDC_ISSUER = "http://127.0.0.1:18080/realms/omnilyzer-auth-spike"
OIDC_BFF_CLIENT_ID = "omnilyzer-bff-spike"
OIDC_API_AUDIENCE = "omnilyzer-api-spike"
OIDC_REDIRECT_URI = "http://testserver/auth/callback"
OIDC_RUNTIME_ENV = Path("/tmp/omnilyzer-auth-spike-runtime.env")
