"""spikes/api/config/middleware.py: Enforce a small request limit for spike APIs.

Related modules: config.settings, drf_api.errors, and ninja_api.api.
"""
from collections.abc import Callable
from django.http import HttpRequest, HttpResponse, JsonResponse

MAX_API_REQUEST_BYTES = 1_048_576


class RequestSizeLimitMiddleware:
    """Reject oversized API requests with the normalized experimental contract."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Store the next middleware callable."""
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Return 413 before parsing when Content-Length exceeds the spike limit."""
        if request.path.startswith("/api/"):
            raw_length = request.META.get("CONTENT_LENGTH", "")
            try:
                content_length = int(raw_length or 0)
            except ValueError:
                content_length = 0
            if content_length > MAX_API_REQUEST_BYTES:
                return JsonResponse({
                    "error": {
                        "code": "request_too_large",
                        "message": "Request body exceeds the spike limit.",
                        "details": {},
                    }
                }, status=413)
        response = self.get_response(request)
        if (
            request.path.startswith("/api/")
            and response.status_code == 405
            and "application/json" not in response.get("Content-Type", "")
        ):
            return JsonResponse({
                "error": {
                    "code": "method_not_allowed",
                    "message": "HTTP method is not allowed.",
                    "details": {},
                }
            }, status=405)
        return response
