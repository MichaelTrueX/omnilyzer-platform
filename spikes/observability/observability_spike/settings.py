"""Minimal, synthetic-only Django settings for the observability spike."""

from __future__ import annotations

SECRET_KEY = "task009-synthetic-not-production"
DEBUG = False
ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
ROOT_URLCONF = "observability_spike.urls"
INSTALLED_APPS = ["contract.apps.ContractConfig"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "contract.middleware.ObservabilityMiddleware",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
TEST_RUNNER = "tests.runner.QuietObservabilityRunner"

# A deployment proxy should expose /metrics only on an internal monitoring network.
# This application fixture deliberately does not add browser auth or a bespoke token.
