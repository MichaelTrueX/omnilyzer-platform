"""File: services/identity/config/urls.py
Purpose: Existing confidential OIDC routes and exact CSRF-checked formative POST.
Related: services/identity/identity_bff/{views,formative}.py,
    services/identity/config/settings.py, Sumlaude S01 NGINX vhost.
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
]
