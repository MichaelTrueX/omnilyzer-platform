"""File: services/identity/config/urls.py
Purpose: Existing confidential OIDC routes, exact CSRF-checked formative POST
    and signed-session Native lesson, stage-help and protected-media GETs.
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
    # Canonical same-page public lesson gate requires a signed, paired Native
    # context. The old app-host /api/valoria/context path remains unchanged.
    path("api/valoria/context", formative.canonical_context),
    # Math/Science progress is routed here by the exact NGINX override, never directly to Native.
    path("api/valoria/learning/courses/<uuid:course_id>/formative/<slug:lesson_id>/progress",
         formative.formative_progress),
    # Exact learner-stage, help, and media GETs must all pass the verified
    # Django/S03 session pair before Native receives them. S01 must route the
    # same four paths to BFF before generic /api/ forwarding.
    path("api/valoria/learning/courses/<uuid:course_id>/formative/<slug:lesson_id>",
         formative.formative_lesson),
    path("api/valoria/learning/courses/<uuid:course_id>/formative/<slug:lesson_id>/help/<slug:stage_id>",
         formative.formative_help),
    path("api/valoria/learning/courses/<uuid:course_id>/formative/<slug:lesson_id>/reveals",
         formative.formative_reveals),
    path("api/valoria/learning/courses/<uuid:course_id>/formative/<slug:lesson_id>/reveals/<slug:asset_id>",
         formative.formative_reveal_asset),
]
