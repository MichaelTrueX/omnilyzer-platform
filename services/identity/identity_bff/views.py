"""File: services/identity/identity_bff/views.py
Purpose: Product-origin confidential OIDC BFF routes with non-cacheable auth
    responses. S03 retains sole authority for private learner API admission.
Related: services/identity/config/{settings,urls}.py,
    services/identity/identity_bff/{oidc,issuer}.py,
    services/identity/tests/test_identity.py.
"""
import hmac
import json
import secrets
import time

from django.conf import settings
from django.contrib.sessions.backends.base import UpdateError
from django.db import DatabaseError
from django.http import JsonResponse, HttpResponseRedirect
from django.middleware.csrf import get_token
from django.views.decorators.cache import never_cache
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


def _unpaired_session_response():
    """Invalidate both browser cookies after session persistence has failed.

    The old S03 cookie has been revoked, or no new S03 session was issued.
    A Django cookie must not continue displaying that identity as logged in
    while its independent product authorization is no longer valid.
    """
    response = _clear_product_cookie(_fail(503))
    response.delete_cookie(
        settings.SESSION_COOKIE_NAME, path=settings.SESSION_COOKIE_PATH,
        samesite=settings.SESSION_COOKIE_SAMESITE)
    return response


def _identity_active(request):
    """Only a still-live server-held, signed confidential OIDC identity."""
    value = request.session.get("principal")
    now = int(time.time())
    if not isinstance(value, dict) or not value.get("sub"):
        return None
    if now >= request.session.get("absolute_deadline", 0):
        return None
    if now - request.session.get("last_seen", 0) > settings.IDENTITY_IDLE_SECONDS:
        return None
    if not request.session.get("sealed_tokens"):
        return None
    return value


def _active(request):
    value = _identity_active(request)
    if not value or not request.session.get("s03_digest"):
        return None
    if (settings.REQUIRE_GTM_ADULT_CHOICE and
            request.session.get("age_choice") != "adult"):
        return None
    return value


def _revoke_existing(request):
    """Revoke the previously admitted S03 cookie before replacement."""
    old_digest = request.session.get("s03_digest")
    if old_digest:
        issuer.revoke(old_digest)


def _persist_issued_session(request, digest):
    """Persist the matching Django session before returning an S03 cookie.

    Django's SessionMiddleware normally persists after a view returns.
    Explicit persistence here prevents a newly issued S03 token from being
    delivered if the independent Django session database cannot be updated.
    Compensate by revoking the new S03 digest on persistence failure.
    """
    try:
        request.session.save()
    except (DatabaseError, UpdateError):
        try:
            issuer.revoke(digest)
        except issuer.AdmissionError:
            # Do not return a newly minted cookie even if revocation fails.
            # S03's independently limited session will expire by itself.
            pass
        return False
    return True


@never_cache
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


@never_cache
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
        # Validate and encrypt *all* OAuth data before creating an S03
        # database session: a missing refresh token or invalid expiry
        # must never leave an orphan, unrecoverable learner session.
        sealed = oidc.seal(tokens)
        deadline = oidc.deadline(tokens)
        # No product session is issued on unaudited identity/guardian data.
        # Existing session is revoked before another cookie is minted.
        _revoke_existing(request)
        # Rotate the Django key BEFORE product authorization. Pending
        # 18+ users receive only a Django identity cookie, never Native.
        request.session.cycle_key()
        if settings.REQUIRE_GTM_ADULT_CHOICE:
            request.session.clear()
            now = int(time.time())
            request.session.update({
                "principal": principal, "sealed_tokens": sealed,
                "oauth_deadline": deadline,
                "absolute_deadline": now + settings.IDENTITY_ABSOLUTE_SECONDS,
                "last_seen": now, "age_choice": "pending",
            })
            request.session.set_expiry(settings.IDENTITY_IDLE_SECONDS)
            try:
                request.session.save()
            except (DatabaseError, UpdateError):
                return _unpaired_session_response()
            return _clear_product_cookie(HttpResponseRedirect("/professional/gtm-001"))
        product_cookie, digest = issuer.issue(principal)
    except (issuer.AdmissionError, oidc.IdentityError, KeyError, TypeError, ValueError):
        return _fail(403)
    except (DatabaseError, UpdateError):
        return _unpaired_session_response()
    now = int(time.time())
    request.session.update({
        "principal": principal, "s03_digest": digest, "sealed_tokens": sealed,
        "oauth_deadline": deadline, "absolute_deadline": now + settings.IDENTITY_ABSOLUTE_SECONDS,
        "last_seen": now,
    })
    request.session.set_expiry(settings.IDENTITY_IDLE_SECONDS)
    if not _persist_issued_session(request, digest):
        return _unpaired_session_response()
    return _product_cookie(HttpResponseRedirect("/start"), product_cookie)


@never_cache
@require_GET
def session_state(request):
    principal = _active(request)
    if not principal:
        if settings.REQUIRE_GTM_ADULT_CHOICE:
            identity = _identity_active(request)
            if identity:
                state = request.session.get("age_choice")
                if state == "pending":
                    return JsonResponse({"authenticated": True,
                        "productAuthorized": "adult-choice-required"})
                if state == "under18":
                    return JsonResponse({"authenticated": True,
                        "productAuthorized": "adult-pilot-denied"})
        return JsonResponse({"authenticated": False})
    # Authentication status does not confer enrollment/guardian authorization.
    return JsonResponse({"authenticated": True, "productAuthorized": "check-S03"})


@never_cache
@require_GET
def csrf(request):
    return JsonResponse({"csrf_token": get_token(request)})


@never_cache
@require_POST
def age_choice(request):
    """CSRF-checked 18+ choice, tied only to the signed OIDC Django session.

    This DOES NOT register an adult admission and does not accept a browser
    email, issuer, subject or entitlement. The restricted S03 issuer
    independently denies absent declared_adult / known-minor / course role.
    """
    if not settings.REQUIRE_GTM_ADULT_CHOICE:
        return _fail(404)
    principal = _identity_active(request)
    if not principal or request.session.get("age_choice") != "pending":
        return _fail(403)
    try:
        if request.content_type != "application/json" or len(request.body) > 128:
            return _fail(400)
        payload = json.loads(request.body)
        if (not isinstance(payload, dict) or
                set(payload) != {"ageBand"} or
                payload["ageBand"] not in ("adult", "under18")):
            return _fail(400)
    except (ValueError, UnicodeError, TypeError):
        return _fail(400)
    if payload["ageBand"] == "under18":
        request.session["age_choice"] = "under18"
        try:
            request.session.save()
        except (DatabaseError, UpdateError):
            return _unpaired_session_response()
        return JsonResponse({"authenticated": True,
            "productAuthorized": "adult-pilot-denied"})
    # Even after initial signed OIDC verification, do not mint the
    # S03 cookie based solely on stale provider session claims.
    try:
        old = oidc.unseal(request.session["sealed_tokens"])
        new = oidc.refresh(old["refresh_token"])
        if not new.get("refresh_token"):
            new["refresh_token"] = old["refresh_token"]
        verified = oidc.verify_id(
            new["id_token"], new["access_token"], previous_sub=principal["sub"])
        if verified != principal:
            raise oidc.IdentityError("changed identity")
        sealed = oidc.seal(new)
        deadline = oidc.deadline(new)
        product_cookie, digest = issuer.issue(principal)
    except (issuer.AdmissionError, oidc.IdentityError, KeyError, TypeError, ValueError):
        return _fail(403)
    request.session.update({
        "s03_digest": digest, "sealed_tokens": sealed,
        "oauth_deadline": deadline, "age_choice": "adult",
        "last_seen": int(time.time()),
    })
    request.session.set_expiry(settings.IDENTITY_IDLE_SECONDS)
    if not _persist_issued_session(request, digest):
        return _unpaired_session_response()
    return _product_cookie(JsonResponse({
        "authenticated": True, "productAuthorized": "check-S03",
        "adultDeclared": True, "csrfResetRequired": True,
    }), product_cookie)


@never_cache
@require_POST
def refresh(request):
    principal = _active(request)
    if not principal:
        # A stale Django identity must not leave the browser holding a
        # still-admitted S03 learner cookie. Revoke before local cleanup.
        try:
            _revoke_existing(request)
        except issuer.AdmissionError:
            # Preserve the server-side digest for a future retry.
            return _fail(503)
        request.session.flush()
        return _clear_product_cookie(_fail(401))
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
    if not _persist_issued_session(request, digest):
        return _unpaired_session_response()
    return _product_cookie(JsonResponse({"authenticated": True, "refreshed": True,
        "csrfResetRequired": True}), product_cookie)


@never_cache
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
