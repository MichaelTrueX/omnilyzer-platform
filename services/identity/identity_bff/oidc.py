"""Production-bound adaptation of the ORIGINAL Task004 Django/Authlib protocol."""
import base64
import hashlib
import json
import secrets
import time
from urllib import parse, request
from urllib.error import HTTPError, URLError

from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from joserfc.errors import JoseError as RFCJoseError
from authlib.oidc.core import CodeIDToken
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

_JWT = JsonWebToken(["RS256"])
_META, _JWKS, _KEYS_AT = None, None, 0


class IdentityError(Exception):
    """Generic exception: never log secrets or raw provider response."""


class _NoProviderRedirect(request.HTTPRedirectHandler):
    """Never forward confidential OAuth Authorization headers on a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IdentityError("OIDC endpoint redirect refused")


def _provider(url, *, form=None, authenticated=False, empty_ok=False):
    if not isinstance(url, str) or not url.startswith("https://"):
        raise IdentityError("insecure endpoint")
    body = parse.urlencode(form).encode() if form is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if authenticated:
        pair = f"{settings.OIDC_CLIENT_ID}:{settings.OIDC_CLIENT_SECRET}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(pair).decode()
    try:
        opener = request.build_opener(_NoProviderRedirect())
        with opener.open(request.Request(url, data=body, headers=headers), timeout=8) as response:
            if response.status != 200 or not response.url.startswith("https://"):
                raise IdentityError("invalid provider HTTP response")
            data = response.read(1048577)
            if len(data) > 1048576:
                raise IdentityError("provider response too large")
            if empty_ok and not data:
                return {}
            parsed = json.loads(data)
            if not isinstance(parsed, dict):
                raise IdentityError("invalid provider JSON")
            return parsed
    except (HTTPError, URLError, OSError, UnicodeError, ValueError) as exc:
        raise IdentityError("provider unavailable") from exc


def metadata():
    global _META
    if _META is None:
        value = _provider(settings.OIDC_ISSUER + "/.well-known/openid-configuration")
        if value.get("issuer") != settings.OIDC_ISSUER:
            raise IdentityError("issuer mismatch")
        for k in ("authorization_endpoint", "token_endpoint", "jwks_uri", "revocation_endpoint"):
            if not str(value.get(k, "")).startswith("https://"):
                raise IdentityError("missing HTTPS provider endpoint")
        if "S256" not in value.get("code_challenge_methods_supported", []):
            raise IdentityError("missing PKCE S256")
        _META = value
    return _META


def jwks(force=False):
    global _JWKS, _KEYS_AT
    if force or _JWKS is None or time.monotonic() - _KEYS_AT > 300:
        result = _provider(metadata()["jwks_uri"])
        if not isinstance(result.get("keys"), list) or not result["keys"]:
            raise IdentityError("empty signing keys")
        _JWKS, _KEYS_AT = result, time.monotonic()
    return _JWKS


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize(state, nonce, challenge):
    query = parse.urlencode({
        "response_type": "code", "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": settings.OIDC_REDIRECT_URI, "scope": "openid profile email",
        "state": state, "nonce": nonce, "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return metadata()["authorization_endpoint"] + "?" + query


def exchange(code, verifier):
    return _provider(metadata()["token_endpoint"], form={
        "grant_type": "authorization_code", "code": code,
        "code_verifier": verifier, "redirect_uri": settings.OIDC_REDIRECT_URI,
    }, authenticated=True)


def refresh(refresh_secret):
    return _provider(metadata()["token_endpoint"], form={
        "grant_type": "refresh_token", "refresh_token": refresh_secret,
    }, authenticated=True)


def revoke_provider(refresh_secret):
    if not refresh_secret:
        return False
    try:
        _provider(metadata()["revocation_endpoint"], form={
            "token": refresh_secret, "token_type_hint": "refresh_token",
        }, authenticated=True, empty_ok=True)
    except IdentityError:
        return False
    return True


def verify_id(token, access, *, nonce=None, previous_sub=None):
    if not isinstance(token, str) or not isinstance(access, str):
        raise IdentityError("missing signed identity")
    options = {
        "iss": {"essential": True, "value": settings.OIDC_ISSUER},
        "aud": {"essential": True, "value": settings.OIDC_CLIENT_ID},
        "exp": {"essential": True}, "iat": {"essential": True},
        "sub": {"essential": True},
    }
    for force in (False, True):
        try:
            claims = _JWT.decode(token, jwks(force), claims_cls=CodeIDToken,
                claims_options=options, claims_params={
                    "nonce": nonce, "client_id": settings.OIDC_CLIENT_ID,
                    "access_token": access,
                })
            claims.validate()
            if nonce is not None and claims.get("nonce") != nonce:
                raise IdentityError("nonce mismatch")
            sub = claims.get("sub")
            if not isinstance(sub, str) or not 8 <= len(sub) <= 255:
                raise IdentityError("invalid subject")
            if previous_sub is not None and sub != previous_sub:
                raise IdentityError("refresh changed subject")
            return {"issuer": claims["iss"], "sub": sub}
        except (JoseError, RFCJoseError, ValueError, KeyError, TypeError) as exc:
            if force:
                raise IdentityError("invalid signed OIDC token") from exc
    raise IdentityError("signed identity invalid")


def seal(tokens):
    if not isinstance(tokens, dict) or not all(isinstance(tokens.get(k), str)
            for k in ("access_token", "id_token", "refresh_token")):
        raise IdentityError("incomplete OAuth token response")
    return Fernet(settings.TOKEN_FERNET_KEY).encrypt(json.dumps(tokens).encode()).decode()


def unseal(ciphertext):
    try:
        value = json.loads(Fernet(settings.TOKEN_FERNET_KEY).decrypt(ciphertext.encode()))
        if not isinstance(value, dict) or not isinstance(value.get("refresh_token"), str):
            raise IdentityError("invalid sealed session")
        return value
    except (InvalidToken, ValueError, TypeError, AttributeError) as exc:
        raise IdentityError("sealed token invalid") from exc


def deadline(tokens):
    try:
        duration = int(tokens["expires_in"])
    except (KeyError, ValueError, TypeError) as exc:
        raise IdentityError("OAuth expiry missing") from exc
    if not 30 <= duration <= 86400:
        raise IdentityError("OAuth expiry outside allowed range")
    return int(time.time()) + duration
