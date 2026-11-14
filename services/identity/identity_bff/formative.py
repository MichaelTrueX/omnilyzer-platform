"""File: services/identity/identity_bff/formative.py
Purpose: Validate Django session-bound CSRF and the paired S03 learner cookie
    before forwarding only approved Math/Science formative progress writes.
Related: services/identity/config/{settings,urls}.py,
    services/identity/identity_bff/{views,issuer}.py,
    services/identity/tests/test_formative_csrf.py,
    Sumlaude apps/sumlaude-learner/ops/nginx-app-sumlaude-production.review.conf.
No new login, bearer token, learner admission, or broad API forwarding.
"""
import hashlib
import hmac
import http.client
import json
import re

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from .views import _active

# Section: Fixed Native destination and narrowly approved source-bound lessons.
# Browser-supplied hostname, path prefix, query and upstream URL are not used.
_NATIVE_HOST = "127.0.0.1"
_NATIVE_PORT = 18741
_ALLOWED_LESSONS = frozenset(("square-root-function", "why-earth-supports-life"))
_COOKIE_RE = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_LIMIT = 65536
_RESPONSE_LIMIT = 262144
_NATIVE_STATUSES = frozenset((200, 400, 401, 403, 404, 409, 422))


def _paired_product_cookie(request):
    """Accept only the S03 cookie issued for this exact active Django session.

    S03 hashes the 64-character opaque learner cookie with SHA256 before
    persisting its digest; use that existing digest rather than a new identity.
    """
    if not _active(request):
        return None
    cookie = request.COOKIES.get("__Host-sumlaude_session", "")
    digest = request.session.get("s03_digest")
    if (not isinstance(cookie, str) or not _COOKIE_RE.fullmatch(cookie)
            or not isinstance(digest, str) or not _COOKIE_RE.fullmatch(digest)):
        return None
    candidate = hashlib.sha256(cookie.encode("ascii")).hexdigest()
    return cookie if hmac.compare_digest(candidate, digest) else None


def _forward_native(path, content, cookie, validated_csrf):
    """Forward one bounded JSON POST to the fixed loopback Native runtime.

    Do not proxy Django cookies, Keycloak secrets or inbound browser headers.
    Native independently authorizes the existing product session and course.
    """
    headers = {
        "Host": "app.sumlaude.com",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Cookie": "__Host-sumlaude_session=" + cookie,
        "Origin": settings.PRODUCT_ORIGIN,
        "Sec-Fetch-Site": "same-origin",
        "X-CSRF-Token": validated_csrf,
    }
    connection = http.client.HTTPConnection(_NATIVE_HOST, _NATIVE_PORT, timeout=6)
    try:
        connection.request("POST", path, body=content, headers=headers)
        native = connection.getresponse()
        response = native.read(_RESPONSE_LIMIT + 1)
        if (native.status not in _NATIVE_STATUSES
                or len(response) > _RESPONSE_LIMIT
                or "application/json" not in native.getheader("Content-Type", "").lower()):
            return None
        parsed = json.loads(response)
        return (native.status, parsed) if isinstance(parsed, dict) else None
    except (OSError, TimeoutError, http.client.HTTPException, ValueError,
            UnicodeError, json.JSONDecodeError):
        return None
    finally:
        connection.close()


@never_cache
@require_POST
def formative_progress(request, course_id, lesson_id):
    """Require signed identity, session-bound Django CSRF and paired S03 cookie.

    Django's existing CsrfViewMiddleware runs before this view and, with
    CSRF_USE_SESSIONS, rejects absent, stale, other-session and cross-Origin
    X-CSRFToken values before any forwarding. The source-specific Native
    course/learner/RLS constraints remain independently enforced downstream.
    """
    if lesson_id not in _ALLOWED_LESSONS:
        return JsonResponse({"error": "lesson unavailable"}, status=404)
    cookie = _paired_product_cookie(request)
    if cookie is None:
        return JsonResponse({"error": "learner session unavailable"}, status=401)
    if request.content_type != "application/json":
        return JsonResponse({"error": "JSON required"}, status=415)
    content = request.body
    if not content or len(content) > _REQUEST_LIMIT:
        return JsonResponse({"error": "invalid request size"}, status=413)
    # Never trust a browser-supplied alternate X-CSRF-Token header. Django
    # already validated precisely X-CSRFToken against the server-side session.
    csrf = request.META.get("HTTP_X_CSRFTOKEN", "")
    if not isinstance(csrf, str) or not csrf:
        return JsonResponse({"error": "CSRF required"}, status=403)
    path = ("/api/valoria/learning/courses/" + str(course_id) +
            "/formative/" + lesson_id + "/progress")
    forwarded = _forward_native(path, content, cookie, csrf)
    if forwarded is None:
        return JsonResponse({"error": "learning unavailable"}, status=503)
    status, result = forwarded
    return JsonResponse(result, status=status)
