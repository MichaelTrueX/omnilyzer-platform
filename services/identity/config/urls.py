from django.urls import path
from identity_bff import views

urlpatterns = [
    path("auth/login", views.login),
    path("auth/callback", views.callback),
    path("auth/session", views.session_state),
    path("auth/csrf", views.csrf),
    path("auth/refresh", views.refresh),
    path("auth/logout", views.logout),
]
