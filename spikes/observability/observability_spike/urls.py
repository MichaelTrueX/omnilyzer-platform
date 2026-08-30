"""Synthetic routes used to validate the observability contract."""

from django.urls import path

from contract import views


urlpatterns = [
    path("livez", views.livez, name="livez"),
    path("readyz", views.readyz, name="readyz"),
    path("metrics", views.metrics, name="metrics"),
    path("api/work/<int:item_id>", views.work, name="work"),
    path("api/outbound", views.outbound, name="outbound"),
    path("api/secure", views.secure_boundary, name="secure-boundary"),
]
