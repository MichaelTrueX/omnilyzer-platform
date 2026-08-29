import base64
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache

from authlib.jose import JsonWebToken
from authlib.oidc.core import CodeIDToken
from django.conf import settings

ALLOWED_SIGNING_ALGORITHMS = ["RS256"]


class OIDCError(Exception):
    pass


def _http_json(url, *, data=None, headers=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as exc:
        raise OIDCError("provider request failed") from exc


@lru_cache(maxsize=1)
def discovery():
    metadata = _http_json(
        f"{settings.OIDC_ISSUER}/.well-known/openid-configuration"
    )
    required = {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "end_session_endpoint",
    }
    if not required.issubset(metadata):
        raise OIDCError("provider metadata is incomplete")
    if metadata["issuer"] != settings.OIDC_ISSUER:
        raise OIDCError("provider issuer mismatch")
    if "S256" not in metadata.get("code_challenge_methods_supported", []):
        raise OIDCError("provider does not advertise PKCE S256")
    return metadata


@lru_cache(maxsize=1)
def jwks():
    return _http_json(discovery()["jwks_uri"])


def runtime_value(name):
    try:
        lines = settings.OIDC_RUNTIME_ENV.read_text().splitlines()
    except OSError as exc:
        raise OIDCError("runtime credentials unavailable") from exc
    values = dict(line.split("=", 1) for line in lines if "=" in line)
    try:
        return values[name]
    except KeyError as exc:
        raise OIDCError("runtime credential unavailable") from exc


def pkce_material():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def authorization_url(*, client_id, redirect_uri, state, nonce, challenge):
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{discovery()['authorization_endpoint']}?{query}"


def exchange_bff_code(code, verifier):
    client_id = settings.OIDC_BFF_CLIENT_ID
    secret = runtime_value("OMNILYZER_BFF_SECRET")
    basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return _http_json(
        discovery()["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.OIDC_REDIRECT_URI,
            "code_verifier": verifier,
        },
        headers={"Authorization": f"Basic {basic}"},
    )


def refresh_bff_token(refresh_token):
    client_id = settings.OIDC_BFF_CLIENT_ID
    secret = runtime_value("OMNILYZER_BFF_SECRET")
    basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return _http_json(
        discovery()["token_endpoint"],
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        headers={"Authorization": f"Basic {basic}"},
    )


def validate_id_token(token, *, nonce, access_token, client_id):
    claims = JsonWebToken(ALLOWED_SIGNING_ALGORITHMS).decode(
        token,
        jwks(),
        claims_cls=CodeIDToken,
        claims_options={
            "iss": {"essential": True, "value": settings.OIDC_ISSUER},
            "aud": {"essential": True, "value": client_id},
            "exp": {"essential": True},
            "sub": {"essential": True},
        },
        claims_params={
            "nonce": nonce,
            "client_id": client_id,
            "access_token": access_token,
        },
    )
    claims.validate()
    return claims
