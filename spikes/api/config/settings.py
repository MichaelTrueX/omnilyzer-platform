"""spikes/api/config/settings.py: Configure the isolated Django API spike.

Related modules: config.urls, config.middleware, and domain.models.
The defaults point only at the dedicated local PostgreSQL spike cluster. SQLite is
available solely through an explicit environment opt-in and is never a silent fallback.
"""
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get(
    "SPIKE_DJANGO_SECRET_KEY",
    "task-002-spike-only-not-a-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
)
DEBUG = os.environ.get("SPIKE_DEBUG", "0") == "1"
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "testserver"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "domain",
    "drf_api",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "config.middleware.RequestSizeLimitMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]

database_engine = os.environ.get("SPIKE_DATABASE_ENGINE", "postgresql")
if database_engine == "sqlite":
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "api-spike.sqlite3",
    }}
elif database_engine == "postgresql":
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("SPIKE_DATABASE_NAME", "omnilyzer_platform_api_spike"),
        "USER": os.environ.get("SPIKE_DATABASE_USER", "omnilyzer_api_spike_owner"),
        "PASSWORD": os.environ.get("SPIKE_DATABASE_PASSWORD", ""),
        "HOST": os.environ.get(
            "SPIKE_DATABASE_HOST", "/tmp/omnilyzer-platform-api-spike-socket"
        ),
        "PORT": os.environ.get("SPIKE_DATABASE_PORT", "55434"),
        "CONN_MAX_AGE": 0,
        "OPTIONS": {},
    }}
else:
    raise RuntimeError("SPIKE_DATABASE_ENGINE must be 'postgresql' or 'sqlite'.")

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DATA_UPLOAD_MAX_MEMORY_SIZE = 1_048_576
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "drf_api.errors.normalized_exception_handler",
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "UNAUTHENTICATED_USER": None,
}
SPECTACULAR_SETTINGS = {
    "TITLE": "Omnilyzer API Spike - DRF",
    "DESCRIPTION": "Experimental DRF contract; not a production API.",
    "VERSION": "1.0.0-spike",
    "ENUM_NAME_OVERRIDES": {
        "ProjectStatusEnum": "domain.models.Project.Status",
    },
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
}
