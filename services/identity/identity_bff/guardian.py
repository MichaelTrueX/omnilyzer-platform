"""Sumlaude guardian email confirmation; Native remains admission authority.

Tokens are single-use capabilities, not OIDC credentials. Only their digest
crosses into PostgreSQL. Recipient addresses remain encrypted at rest.
"""
import hashlib
import json
import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage

import psycopg
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse, JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .issuer import AdmissionError

TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
POLICY = "sumlaude-guardian-email-v1"


def recipient(value):
    if not isinstance(value, str) or len(value) > 254 or any(
            c in value for c in "\r\n\x00"):
        raise ValueError("invalid guardian email")
    value = value.strip()
    try:
        validate_email(value)
    except ValidationError:
        raise ValueError("invalid guardian email") from None
    # Native compares this normalized address with the learner's own address.
    return value.casefold()


def digest(token):
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise ValueError("invalid confirmation link")
    return hashlib.sha256(token.encode("ascii")).digest()


def _call(name, args):
    # Names are internal literals, never browser or environment input.
    if name not in {"guardian_request", "guardian_confirm", "guardian_state",
                    "declare_minor", "declare_adult"}:
        raise ValueError("unsupported admission operation")
    placeholders = ",".join(["%s"] * len(args))
    try:
        with psycopg.connect(settings.SUMLAUDE_ISSUER_DSN, connect_timeout=5) as db:
            with db.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout='5s'")
                cur.execute("SET LOCAL lock_timeout='1s'")
                cur.execute(f"SELECT sumlaude_auth.{name}({placeholders})", args)
                row = cur.fetchone()
                if not row:
                    raise AdmissionError("admission unavailable")
                return row[0]
    except (psycopg.Error, OSError) as exc:
        raise AdmissionError("admission unavailable") from exc


def principal_args(principal):
    if (not isinstance(principal, dict)
            or principal.get("issuer") != settings.OIDC_ISSUER
            or not isinstance(principal.get("sub"), str)
            or not 8 <= len(principal["sub"]) <= 255):
        raise AdmissionError("signed identity required")
    return principal["issuer"], principal["sub"]


def declare_minor(principal):
    return _call("declare_minor", principal_args(principal))


def declare_adult(principal, country):
    if country is not None and (not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country)):
        raise ValueError("country required")
    return _call("declare_adult", (*principal_args(principal), country))


def state(principal):
    result = _call("guardian_state", principal_args(principal))
    if result not in ("unknown", "required", "pending", "confirmed"):
        raise AdmissionError("invalid admission state")
    return result


def request_confirmation(principal, address):
    address = recipient(address)
    token = secrets.token_urlsafe(32)
    sealed = Fernet(settings.TOKEN_FERNET_KEY).encrypt(address.encode()).decode()
    # Commit a bounded request BEFORE SMTP. A timeout must not permit unlimited
    # retry mail; an undelivered request expires or may be replaced after cooldown.
    accepted = _call("guardian_request", (*principal_args(principal), address,
                     sealed, digest(token)))
    if accepted is not True:
        raise AdmissionError("guardian request unavailable")
    message = EmailMessage()
    message["From"] = "Sumlaude <no-reply@sumlaude.com>"
    message["To"] = address
    message["Subject"] = "Confirm parent or guardian consent for Sumlaude"
    message.set_content(
        "A learner has asked you to approve their Sumlaude account.\n\n"
        "If you are their parent or legal guardian, open this link and confirm "
        "your responsibility and consent. Opening the link alone grants no access.\n\n"
        "https://sumlaude.com/auth/guardian#" + token + "\n\n"
        "The link expires in 24 hours and works once. If you did not expect "
        "this request, ignore it. No learner answers or account details are included.\n")
    try:
        # Reuse the approved production Google Workspace IP relay, TLS and
        # sender. No arbitrary SMTP destination, credentials or new service.
        with smtplib.SMTP_SSL("smtp-relay.gmail.com", 465, timeout=8,
                              context=ssl.create_default_context()) as smtp:
            if smtp.send_message(message):
                raise AdmissionError("guardian mail unavailable")
    except (OSError, smtplib.SMTPException) as exc:
        raise AdmissionError("guardian mail unavailable") from exc


def confirm(token, consent, country):
    if consent is not True or not isinstance(country, str) or not re.fullmatch(
            r"[A-Z]{2}", country):
        raise ValueError("guardian consent and country required")
    if _call("guardian_confirm", (digest(token), country, POLICY)) is not True:
        raise AdmissionError("confirmation unavailable")


def _payload(request, keys):
    if request.content_type != "application/json" or len(request.body) > 2048:
        raise ValueError("invalid request")
    payload = json.loads(request.body)
    if not isinstance(payload, dict) or set(payload) != keys:
        raise ValueError("invalid request")
    return payload


def _enabled():
    return getattr(settings, "GUARDIAN_EMAIL_ENABLED", False)


@never_cache
@require_POST
def request_email(request):
    from .views import _identity_active
    if not _enabled():
        return JsonResponse({"error": "unavailable"}, status=404)
    principal = _identity_active(request)
    if not principal or request.session.get("age_choice") != "under18":
        return JsonResponse({"error": "sign in first"}, status=403)
    try:
        payload = _payload(request, {"guardianEmail"})
        request_confirmation(principal, payload["guardianEmail"])
    except (ValueError, UnicodeError):
        return JsonResponse({"error": "Enter a valid guardian email."}, status=400)
    except AdmissionError:
        # Never claim successful SMTP delivery on quota/transport failure.
        return JsonResponse({"error": "Email could not be sent. Wait five minutes before retrying."}, status=503)
    return JsonResponse({"sent": True, "productAuthorized": "guardian-pending"})


@never_cache
@require_POST
def confirm_email(request):
    if not _enabled():
        return JsonResponse({"error": "unavailable"}, status=404)
    try:
        payload = _payload(request, {"token", "guardianConsent", "country"})
        confirm(payload["token"], payload["guardianConsent"], payload["country"])
    except (ValueError, UnicodeError, AdmissionError):
        return JsonResponse({"error": "Confirmation is invalid, expired or already used. Ask the learner for a new email."}, status=400)
    return JsonResponse({"confirmed": True})


_PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sumlaude parent or guardian confirmation</title>
<main><h1>Parent or guardian confirmation</h1>
<p>A learner has asked you to approve their Sumlaude account for 30 days.
Confirm only if you are their parent or legal guardian. You may ignore an unexpected request.</p>
<form id="guardian-form"><label>Your country (two-letter country code)
<input name="country" required pattern="[A-Za-z]{2}" maxlength="2" autocomplete="country"></label>
<p><label><input type="checkbox" name="consent" required>
I am 18 or older, I am this learner's parent or legal guardian, and I consent to their
Sumlaude learning account and storage of their learning progress for 30 days.</label></p>
<button type="submit">Confirm consent</button><p id="status" role="status" aria-live="polite"></p>
</form><p>No learner password is needed. This does not sign you into the learner's account.</p>
</main><script src="/auth/guardian-script" defer></script></html>"""

_SCRIPT = r"""'use strict';
(() => {
  const token = window.location.hash.slice(1);
  window.history.replaceState(null, '', window.location.pathname);
  const form = document.getElementById('guardian-form');
  const status = document.getElementById('status');
  const button = form.querySelector('button');
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    button.disabled = true; status.textContent = 'This confirmation link is incomplete. Ask the learner for a new email.';
    return;
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); if (button.disabled || !form.reportValidity()) return;
    button.disabled = true; status.textContent = 'Confirming…';
    try {
      const options = {credentials:'same-origin', mode:'same-origin', cache:'no-store', redirect:'error'};
      const csrf = await fetch('/auth/csrf', {...options, headers:{Accept:'application/json'}});
      if (!csrf.ok) throw new Error();
      const secret = (await csrf.json()).csrf_token;
      if (typeof secret !== 'string' || !/^[A-Za-z0-9]{32,128}$/.test(secret)) throw new Error();
      const response = await fetch('/auth/guardian-confirm', {...options, method:'POST',
        headers:{'Content-Type':'application/json', 'X-CSRFToken':secret, Accept:'application/json'},
        body:JSON.stringify({token,guardianConsent:form.elements.consent.checked,
          country:form.elements.country.value.trim().toUpperCase()})});
      const result = await response.json();
      if (!response.ok || result.confirmed !== true) throw new Error();
      form.replaceChildren(); status.textContent = 'Consent confirmed. The learner can return to Sumlaude and select Continue.';
      form.append(status);
    } catch (_) {
      status.textContent = 'Confirmation failed or this link has expired or already been used. Try again, or ask the learner for a new email.';
      button.disabled = false;
    }
  });
})();"""


def _public_response(content, content_type):
    response = HttpResponse(content, content_type=content_type)
    response["Referrer-Policy"] = "no-referrer"
    response["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@never_cache
@require_GET
def page(request):
    if not _enabled() or request.GET:
        return JsonResponse({"error": "unavailable"}, status=404)
    return _public_response(_PAGE, "text/html; charset=utf-8")


@never_cache
@require_GET
def script(request):
    if not _enabled() or request.GET:
        return JsonResponse({"error": "unavailable"}, status=404)
    return _public_response(_SCRIPT, "application/javascript; charset=utf-8")
