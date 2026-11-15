"""File: services/identity/identity_bff/formative.py
Purpose: Validate Django session-bound CSRF on approved formative POSTs,
    and signed identity/session-paired S03 cookies on all approved formative
    learner-stage, stage-help and source-protected media GETs.
Related: services/identity/config/{settings,urls}.py,
    services/identity/identity_bff/{views,issuer}.py,
    services/identity/tests/{test_formative_csrf,test_formative_reveals}.py,
    Sumlaude PR #366 Native source-bound Read-first and media API,
    Sumlaude S01 exact same-origin NGINX ingress (requires separate QA/GO).
No new login, bearer token, learner admission, public media or general proxy.
"""
import hashlib
import hmac
import http.client
import json
import re

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .views import _active

# Section: Fixed Native destination and narrowly approved source-bound lessons.
# Browser-supplied hostname, path prefix, query and upstream URL are not used.
_NATIVE_HOST = "127.0.0.1"
_NATIVE_PORT = 18741
_ALLOWED_LESSONS = frozenset(("square-root-function", "why-earth-supports-life"))
_COOKIE_RE = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_LIMIT = 65536
_RESPONSE_LIMIT = 262144
# Section: Only short source-bound IDs and approved passive student MIME types.
# A GET cannot address arbitrary Native paths, URLs, teacher assets or query.
_ASSET_RE = re.compile(r"[a-z][a-z0-9_-]{0,79}\Z")
_MEDIA_LIMIT = 2 * 1024 * 1024
_MEDIA_TYPES = frozenset(("image/png", "image/webp", "text/plain"))
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


# Section: Read-only source-gated disclosure through the existing private
# Django/OIDC and S03 session pair. Native makes the final per-student,
# per-course, immutable-release and first-answer/Read-first decision.
def _forward_native_get(path, cookie, *, asset=False):
    """Read only one bounded fixed-loopback Native index or student asset.

    No inbound Host/Origin/Authorization/CSRF/request cookies are forwarded.
    Redirects, unexpected MIME, oversized bodies and unsupported response
    statuses fail closed; the origin is not supplied by the browser.
    """
    headers = {
        "Host": "app.sumlaude.com",
        "Cookie": "__Host-sumlaude_session=" + cookie,
        "Accept": ("image/png, image/webp, text/plain, application/json"
                   if asset else "application/json"),
    }
    connection = http.client.HTTPConnection(_NATIVE_HOST, _NATIVE_PORT, timeout=6)
    try:
        connection.request("GET", path, headers=headers)
        native = connection.getresponse()
        limit = _MEDIA_LIMIT if asset and native.status == 200 else _RESPONSE_LIMIT
        body = native.read(limit + 1)
        if native.status not in _NATIVE_STATUSES or len(body) > limit:
            return None
        media_type = native.getheader("Content-Type", "").split(";", 1)[0].lower().strip()
        if not asset or native.status != 200:
            if media_type != "application/json":
                return None
            parsed = json.loads(body)
            return (native.status, parsed, "application/json") if isinstance(parsed, dict) else None
        if media_type not in _MEDIA_TYPES or not body:
            return None
        if media_type == "image/png" and not body.startswith(b"\x89PNG\r\n\x1a\n"):
            return None
        if media_type == "image/webp" and not (body.startswith(b"RIFF")
                and len(body) >= 12 and body[8:12] == b"WEBP"):
            return None
        if media_type == "text/plain":
            try:
                if body.decode("utf-8").encode("utf-8") != body:
                    return None
            except UnicodeDecodeError:
                return None
        return (native.status, body, media_type)
    except (OSError, TimeoutError, http.client.HTTPException, ValueError,
            UnicodeError, json.JSONDecodeError):
        return None
    finally:
        connection.close()


def _private_get_response(forwarded):
    """Prevent CDN/browser caching or cross-origin embedding of any result."""
    if forwarded is None:
        response = JsonResponse({"error": "learning unavailable"}, status=503)
    else:
        status, content, media_type = forwarded
        if media_type == "application/json":
            response = JsonResponse(content, status=status)
        else:
            response = HttpResponse(
                content, status=status,
                content_type=("text/plain; charset=utf-8" if media_type == "text/plain"
                              else media_type),
            )
            response["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response["Cache-Control"] = "private, no-store"
    response["Vary"] = "Cookie"
    response["X-Content-Type-Options"] = "nosniff"
    response["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


def _reveals_access(request, lesson_id, asset_id=None):
    """Restrict GET to an OIDC-backed, same-browser, active S03 cookie pair."""
    if lesson_id not in _ALLOWED_LESSONS:
        return JsonResponse({"error": "lesson unavailable"}, status=404)
    if asset_id is not None and not _ASSET_RE.fullmatch(asset_id):
        return JsonResponse({"error": "asset unavailable"}, status=404)
    # Native's z.object({}).strict() likewise rejects any query parameters.
    if request.META.get("QUERY_STRING", ""):
        return JsonResponse({"error": "query unavailable"}, status=400)
    cookie = _paired_product_cookie(request)
    if cookie is None:
        return JsonResponse({"error": "learner session unavailable"}, status=401)
    return cookie


@never_cache
@require_GET
def formative_reveals(request, course_id, lesson_id):
    """Return only Native-approved metadata, ALT and own released media URLs.

    No first-answer/Read-first decision is inferred client-side. When not
    unlocked, Native responds with a denial or with approved neutral-only
    media; we never create fallback public URLs.
    """
    cookie = _reveals_access(request, lesson_id)
    if not isinstance(cookie, str):
        return _private_get_response((cookie.status_code,
            json.loads(cookie.content), "application/json"))
    path = ("/api/valoria/learning/courses/" + str(course_id)
            + "/formative/" + lesson_id + "/reveals")
    return _private_get_response(_forward_native_get(path, cookie))


@never_cache
@require_GET
def formative_reveal_asset(request, course_id, lesson_id, asset_id):
    """Deliver only S03-authorized passive image/text bytes to this learner.

    The Native service separately checks exact approved source SHA, S02
    classification, own first submission or server-persisted Read-first and
    current course/lesson release on EVERY direct asset GET. Browser-visible
    HTML/SVG/executable content and unknown upstream redirects are blocked.
    """
    cookie = _reveals_access(request, lesson_id, asset_id)
    if not isinstance(cookie, str):
        return _private_get_response((cookie.status_code,
            json.loads(cookie.content), "application/json"))
    path = ("/api/valoria/learning/courses/" + str(course_id)
            + "/formative/" + lesson_id + "/reveals/" + asset_id)
    return _private_get_response(_forward_native_get(path, cookie, asset=True))

# Section: Exact source-bound lesson/stage-help read routes also require the
# existing confidential identity AND digest-paired Native session cookie.
# These GETs never mutate Read-first; the only Read-first mutation continues
# through the unchanged Django-CSRF POST /progress above.
@never_cache
@require_GET
def formative_lesson(request, course_id, lesson_id):
    """Return only the Native-authorized learner stage and saved progression.

    This is a JSON-only, fixed-origin GET for the same two reviewed sources.
    S03 independently verifies learner, course, current release and stage.
    """
    cookie = _reveals_access(request, lesson_id)
    if not isinstance(cookie, str):
        return _private_get_response(
            (cookie.status_code, json.loads(cookie.content), "application/json"))
    path = ("/api/valoria/learning/courses/" + str(course_id)
            + "/formative/" + lesson_id)
    return _private_get_response(_forward_native_get(path, cookie))


@never_cache
@require_GET
def formative_help(request, course_id, lesson_id, stage_id):
    """Return only help unlocked for this exact learner's current stage.

    The stable source stage identifier is bounded before forwarding. Native
    alone decides whether the own first response / voluntary persisted
    Read-first authorizes this particular help stage.
    """
    cookie = _reveals_access(request, lesson_id, stage_id)
    if not isinstance(cookie, str):
        return _private_get_response(
            (cookie.status_code, json.loads(cookie.content), "application/json"))
    path = ("/api/valoria/learning/courses/" + str(course_id)
            + "/formative/" + lesson_id + "/help/" + stage_id)
    return _private_get_response(_forward_native_get(path, cookie))
