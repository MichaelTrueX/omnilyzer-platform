SECRET_KEY = "tenancy-spike-not-for-production"
DEBUG = False
USE_TZ = True
TIME_ZONE = "UTC"
INSTALLED_APPS = ["tenancy"]
DATABASE_ROUTERS = ["config.database_router.TenancyDatabaseRouter"]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

_COMMON_DATABASE = {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": "omnilyzer_platform_tenancy_spike",
    "HOST": "/tmp/omnilyzer-platform-tenancy-spike-socket",
    "PORT": "55435",
    "CONN_MAX_AGE": None,
}

DATABASES = {
    "default": {**_COMMON_DATABASE, "USER": "omnilyzer_tenancy_runtime"},
    "migration": {**_COMMON_DATABASE, "USER": "omnilyzer_tenancy_owner"},
}
