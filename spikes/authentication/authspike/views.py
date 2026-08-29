import secrets

from authlib.jose.errors import JoseError
from django.conf import settings
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from django.views.decorators.http import require_GET, require_POST

from .bearer import BearerValidationError, validate_access_token
from .oidc import (
    OIDCError,
    authorization_url,
    exchange_bff_code,
    pkce_material,
    refresh_bff_token,
    validate_id_token,
)


def _error(status=400):
    return JsonResponse({"error": "authentication failed"}, status=status)


def _identity(request):
    return request.session.get("identity")


@require_GET
def login(request):
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = pkce_material()
    correlations = request.session.get("oidc_correlations", {})
    correlations[state] = {"nonce": nonce, "verifier": verifier}
    request.session["oidc_correlations"] = correlations
    return redirect(
        authorization_url(
            client_id=settings.OIDC_BFF_CLIENT_ID,
            redirect_uri=settings.OIDC_REDIRECT_URI,
            state=state,
            nonce=nonce,
            challenge=challenge,
        )
    )


@require_GET
def callback(request):
    state = request.GET.get("state", "")
    correlations = request.session.get("oidc_correlations", {})
    correlation = correlations.pop(state, None)
    request.session["oidc_correlations"] = correlations
    if correlation is None or request.GET.get("error") or not request.GET.get("code"):
        return _error()
    if request.GET.get("iss") not in (None, settings.OIDC_ISSUER):
        return _error()
    try:
        tokens = exchange_bff_code(request.GET["code"], correlation["verifier"])
        claims = validate_id_token(
            tokens["id_token"],
            nonce=correlation["nonce"],
            access_token=tokens["access_token"],
            client_id=settings.OIDC_BFF_CLIENT_ID,
        )
    except (OIDCError, JoseError, KeyError, ValueError):
        return _error()
    request.session.cycle_key()
    request.session["oauth_tokens"] = tokens
    request.session["identity"] = {
        "issuer": settings.OIDC_ISSUER,
        "subject": claims["sub"],
        "username": claims.get("preferred_username"),
        "email": claims.get("email"),
        "email_verified": claims.get("email_verified"),
    }
    return redirect("/auth/session")


@require_GET
def session_state(request):
    identity = _identity(request)
    if not identity:
        return JsonResponse({"authenticated": False})
    return JsonResponse(
        {
            "authenticated": True,
            "subject": identity["subject"],
            "username": identity["username"],
            "email": identity["email"],
            "email_verified": identity["email_verified"],
        }
    )


@require_GET
def csrf_token(request):
    return JsonResponse({"csrf_token": get_token(request)})


@require_GET
def browser_private(request):
    identity = _identity(request)
    if not identity:
        return _error(401)
    return JsonResponse({"subject": identity["subject"], "auth": "session"})


@require_POST
def browser_private_write(request):
    identity = _identity(request)
    if not identity:
        return _error(401)
    return JsonResponse({"written": True})


@require_POST
def refresh(request):
    if not _identity(request):
        return _error(401)
    old_tokens = request.session.get("oauth_tokens", {})
    try:
        new_tokens = refresh_bff_token(old_tokens["refresh_token"])
        if "refresh_token" not in new_tokens:
            new_tokens["refresh_token"] = old_tokens["refresh_token"]
        request.session["oauth_tokens"] = new_tokens
    except (OIDCError, KeyError):
        request.session.flush()
        return _error(401)
    return JsonResponse({"authenticated": True, "refreshed": True})


@require_POST
def logout(request):
    request.session.flush()
    return JsonResponse({"authenticated": False})


@require_GET
def mobile_private(request):
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return _error(401)
    try:
        principal = validate_access_token(authorization[7:])
    except BearerValidationError:
        return _error(401)
    return JsonResponse(
        {"subject": principal.subject, "issuer": principal.issuer, "auth": "bearer"}
    )
