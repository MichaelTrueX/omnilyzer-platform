"""spikes/api/config/urls.py: Mount admin and both versioned API adapters.

Related modules: drf_api.urls and ninja_api.api.
"""
from django.contrib import admin
from django.urls import include, path
from ninja_api.api import api as ninja_api

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/drf/", include("drf_api.urls")),
    path("api/v1/ninja/", ninja_api.urls),
]
