from dataclasses import dataclass

from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from authlib.jose.rfc7519 import JWTClaims
from django.conf import settings

from .oidc import ALLOWED_SIGNING_ALGORITHMS, OIDCError, jwks


class BearerValidationError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    issuer: str
    subject: str

    @property
    def external_identity_key(self):
        return (self.issuer, self.subject)


def validate_access_token(token):
    try:
        claims = JsonWebToken(ALLOWED_SIGNING_ALGORITHMS).decode(
            token,
            jwks(),
            claims_cls=JWTClaims,
            claims_options={
                "iss": {"essential": True, "value": settings.OIDC_ISSUER},
                "aud": {
                    "essential": True,
                    "value": settings.OIDC_API_AUDIENCE,
                },
                "exp": {"essential": True},
                "sub": {"essential": True},
                "nbf": {"validate": True},
            },
        )
        claims.validate()
        return Principal(claims["iss"], claims["sub"])
    except (JoseError, OIDCError, KeyError, ValueError) as exc:
        raise BearerValidationError("invalid bearer token") from exc
