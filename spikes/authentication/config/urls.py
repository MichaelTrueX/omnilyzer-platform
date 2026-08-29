from django.urls import path

from authspike import views

urlpatterns = [
    path("auth/login", views.login),
    path("auth/callback", views.callback),
    path("auth/session", views.session_state),
    path("auth/csrf", views.csrf_token),
    path("auth/refresh", views.refresh),
    path("auth/logout", views.logout),
    path("api/browser-private", views.browser_private),
    path("api/browser-private-write", views.browser_private_write),
    path("api/mobile-private", views.mobile_private),
]
