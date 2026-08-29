"""spikes/api/drf_api/urls.py: Route the versioned DRF experiment.

Related modules: drf_api.views and config.urls.
"""
from django.urls import path
from drf_api.views import HealthView, ProjectDetailView, ProjectListCreateView

urlpatterns = [
    path("health/", HealthView.as_view(), name="drf-health"),
    path("projects/", ProjectListCreateView.as_view(), name="drf-project-list"),
    path(
        "projects/<str:project_id>/",
        ProjectDetailView.as_view(),
        name="drf-project-detail",
    ),
]
