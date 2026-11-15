"""File: services/identity/config/urls.py
Purpose: Existing confidential OIDC routes, exact CSRF-checked formative POST
    and authenticated, source-protected Native media disclosure GETs.
Related: services/identity/identity_bff/{views,formative}.py,
    services/identity/config/settings.py, Sumlaude S01 NGINX ingress,
    Sumlaude S03 PR #366 source-pinned student reveals.
"""
from django.urls import path
from identity_bff import views, formative

urlpatterns = [
    path("auth/login", views.login),
    path("auth/callback", views.callback),
    path("auth/session", views.session_state),
    path("auth/csrf", views.csrf),
    path("auth/age-choice", views.age_choice),
    path("auth/refresh", views.refresh),
    path("auth/logout", views.logout),
    # Math/Science progress is routed here by the exact NGINX override, never directly to Native.
    path("api/valoria/learning/courses/<uuid:course_id>/formative/<slug:lesson_id>/progress",
         formative.formative_progress),
    # Only these GETs additionally pass the verified Django/S03 session pair.
    # S01 must route them to BFF before generic /api/ Native forwarding.
    path("api/valoria/learning/courses/<uuid:course_id>/formative/<slug:lesson_id>/reveals",
         formative.formative_reveals),
    path("api/valoria/learning/courses/<uuid:course_id>/formative/<slug:lesson_id>/reveals/<slug:asset_id>",
         formative.formative_reveal_asset),
]
