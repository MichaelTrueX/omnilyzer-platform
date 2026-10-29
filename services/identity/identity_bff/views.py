"""Product-origin OIDC routes. S03 retains sole authority for private learning APIs."""
import hmac
import secrets
import time

from django.conf import settings
from django.http import JsonResponse, HttpResponseRedirect
from django.middleware.csrf import get_token
from django.views.decorators.http import require_GET, require_POST

from . import issuer, oidc


def _fail(status=401):
    return JsonResponse({"error": "authentication unavailable"}, status=status)


def _product_cookie(response, cookie):
    response.set_cookie("__Host-sumlaude_session", cookie,
        max_age=settings.PRODUCT_SESSION_SECONDS, secure=True, httponly=True,
        samesite="Lax", path="/")
    return response


def _clear_product_cookie(response):
    response.delete_cookie("__Host-sumlaude_session", path="/", samesite="Lax")
    return response


def _active(request):
    value = request.session.get("principal")
    now = int(time.time())
    if not isinstance(value, dict) or not value.get("sub"):
        return None
    if now >= request.session.get("absolute_deadline", 0):
        return None
    if now - request.session.get("last_seen", 0) > settings.IDENTITY_IDLE_SECONDS:
        return None
    if not request.session.get("s03_digest") or not request.session.get("sealed_tokens"):
        return None
    return value


def _revoke_existing(request):
    old_digest = request.session.get("s03_digest")
    if old_digest:
        issuer.revoke(old_digest)


@require_GET
def login(request):
    # One pending transaction per browser, 5-minute state lifetime.
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = oidc.pkce()
    request.session["transaction"] = {
        "state": state, "nonce": nonce, "verifier": verifier,
        "deadline": int(time.time()) + 300,
    }
    try:
        return HttpResponseRedirect(oidc.authorize(state, nonce, challenge))
    except oidc.IdentityError:
        return _fail(503)


@require_GET
def callback(request):
    transaction = request.session.pop("transaction", None)
    request.session.modified = True
    if not isinstance(transaction, dict):
        return _fail(400)
    if (int(time.time()) > transaction.get("deadline", 0)
            or not hmac.compare_digest(request.GET.get("state", ""), transaction.get("state", ""))
            or request.GET.get("error") or not request.GET.get("code")
            or request.GET.get("iss", settings.OIDC_ISSUER) != settings.OIDC_ISSUER):
        return _fail(400)
    try:
        tokens = oidc.exchange(request.GET["code"], transaction["verifier"])
        principal = oidc.verify_id(tokens["id_token"], tokens["access_token"],
                                   nonce=transaction["nonce"])
        # No product session is issued on unaudited identity/guardian data.
        # Existing session is revoked before another cookie is minted.
        _revoke_existing(request)
        product_cookie, digest = issuer.issue(principal)
        sealed = oidc.seal(tokens)
        deadline = oidc.deadline(tokens)
    except (issuer.AdmissionError, oidc.IdentityError, KeyError, TypeError, ValueError):
        return _fail(403)
    request.session.cycle_key()
    now = int(time.time())
    request.session.update({
        "principal": principal, "s03_digest": digest, "sealed_tokens": sealed,
        "oauth_deadline": deadline, "absolute_deadline": now + settings.IDENTITY_ABSOLUTE_SECONDS,
        "last_seen": now,
    })
    request.session.set_expiry(settings.IDENTITY_IDLE_SECONDS)
    return _product_cookie(HttpResponseRedirect("/start"), product_cookie)


@require_GET
def session_state(request):
    principal = _active(request)
    if not principal:
        return JsonResponse({"authenticated": False})
    # Authentication status does not confer enrollment/guardian authorization.
    return JsonResponse({"authenticated": True, "productAuthorized": "check-S03"})


@require_GET
def csrf(request):
    return JsonResponse({"csrf_token": get_token(request)})


@require_POST
def refresh(request):
    principal = _active(request)
    if not principal:
        return _fail(401)
    try:
        old = oidc.unseal(request.session["sealed_tokens"])
        new = oidc.refresh(old["refresh_token"])
        if not new.get("refresh_token"):
            new["refresh_token"] = old["refresh_token"]
        verified = oidc.verify_id(new["id_token"], new["access_token"],
                                  previous_sub=principal["sub"])
        if verified != principal:
            raise oidc.IdentityError("changed identity")
        sealed = oidc.seal(new)
        deadline = oidc.deadline(new)
        # Revoke before minting to avoid leaving two concurrently active cookies.
        _revoke_existing(request)
        product_cookie, digest = issuer.issue(principal)
    except (issuer.AdmissionError, oidc.IdentityError, KeyError, TypeError, ValueError):
        try:
            _revoke_existing(request)
        except issuer.AdmissionError:
            return _fail(503)
        request.session.flush()
        return _clear_product_cookie(_fail(401))
    request.session["s03_digest"] = digest
    request.session["sealed_tokens"] = sealed
    request.session["oauth_deadline"] = deadline
    request.session["last_seen"] = int(time.time())
    request.session.set_expiry(settings.IDENTITY_IDLE_SECONDS)
    return _product_cookie(JsonResponse({"authenticated": True, "refreshed": True,
        "csrfResetRequired": True}), product_cookie)


@require_POST
def logout(request):
    try:
        _revoke_existing(request)
    except issuer.AdmissionError:
        # Never report successful logout while the S03 cookie is still valid.
        return _fail(503)
    try:
        old = oidc.unseal(request.session["sealed_tokens"])
        provider_revoked = oidc.revoke_provider(old.get("refresh_token"))
    except (oidc.IdentityError, KeyError, TypeError):
        provider_revoked = False
    request.session.flush()
    return _clear_product_cookie(JsonResponse({
        "authenticated": False, "providerTokenRevoked": provider_revoked,
    }))
