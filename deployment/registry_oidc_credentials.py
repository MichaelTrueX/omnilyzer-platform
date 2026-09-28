"""C32O inert request-scoped verification of two GitHub registry read JWTs.

No handler wiring, token request, registry I/O, persistence, replay mutation or
deployment activation occurs here. The public verifier owns only closed DEV
audiences and a reviewed workflow revision; its input deployment identity must
already have been cryptographically authorized by the deployment verifier.
"""

from . import identity as _identity
from . import oidc_verifier as _oidc
from .broker import IDENTITY_FIELDS as _IDENTITY_FIELDS, _normalize_identity
from .jwks import (
    GitHubJWKSCache as _GitHubJWKSCache,
    OIDCVerificationError as _OIDCVerificationError,
    OIDCVerificationUnavailable as _OIDCVerificationUnavailable,
)
from .identity import OIDCAuthorizationError as _OIDCAuthorizationError
from .release_consumer import (
    ForgejoReadCredential as _ForgejoReadCredential,
    ReleaseConsumerError as _ReleaseConsumerError,
    ZotReadCredential as _ZotReadCredential,
    _credential,
)

__all__ = (
    "GitHubRegistryCredentialVerifier", "VerifiedRegistryCredentials",
    "RegistryCredentialVerificationError", "RegistryCredentialRejectedError",
    "RegistryCredentialUnavailableError",
)

_ERROR = "DEV registry credential verification is unavailable or invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_CROSS_BOUND_FIELDS = (
    "issuer", "repository", "repository_id", "repository_owner_id",
    "workflow_ref", "workflow_sha", "ref", "environment", "event_name",
    "runner_environment", "run_id", "run_attempt", "actor_id",
)


class RegistryCredentialVerificationError(Exception):
    """One fixed external failure; token, claims and JWKS diagnostics are hidden."""


class RegistryCredentialRejectedError(RegistryCredentialVerificationError):
    """The signed credential or its closed policy definitely failed."""


class RegistryCredentialUnavailableError(RegistryCredentialVerificationError):
    """Cryptographic verification authority is unavailable."""


class VerifiedRegistryCredentials:
    """Opaque, immutable request-scoped provider for the two read credentials.

    Only the verifier constructs an instance. Provider operations may be called
    repeatedly within one broker request, including two zot reads.
    """

    __slots__ = ("_zot", "_forgejo")

    def __init__(self) -> None:
        raise TypeError("verified registry credentials cannot be constructed directly")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("registry credential authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("registry credential authority is immutable")

    def __repr__(self) -> str:
        return "<VerifiedRegistryCredentials redacted>"

    def __reduce__(self) -> object:
        raise TypeError("registry credentials are not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("registry credentials are not serializable")

    def zot_read_credential(self) -> _ZotReadCredential:
        return object.__getattribute__(self, "_zot")

    def forgejo_read_credential(self) -> _ForgejoReadCredential:
        return object.__getattribute__(self, "_forgejo")


def _result(zot: _ZotReadCredential, forgejo: _ForgejoReadCredential) -> VerifiedRegistryCredentials:
    """Internal construction after signature, policy and cross-run proof."""

    if type(zot) is not _ZotReadCredential or type(forgejo) is not _ForgejoReadCredential:
        raise ValueError
    value = object.__new__(VerifiedRegistryCredentials)
    object.__setattr__(value, "_zot", zot)
    object.__setattr__(value, "_forgejo", forgejo)
    return value


class GitHubRegistryCredentialVerifier:
    """Immutable DEV zot/Forgejo JWT authority with no public audience input."""

    __slots__ = ("_expected_workflow_sha", "_jwks_cache")

    def __init__(self, *, expected_workflow_sha: str,
                 jwks_cache: _GitHubJWKSCache | None = None) -> None:
        try:
            reviewed_sha = _identity.validate_expected_workflow_sha(expected_workflow_sha)
            selected_cache = _GitHubJWKSCache() if jwks_cache is None else jwks_cache
        except _CONTROL:
            raise
        except Exception:
            raise RegistryCredentialUnavailableError(_ERROR) from None
        object.__setattr__(self, "_expected_workflow_sha", reviewed_sha)
        object.__setattr__(self, "_jwks_cache", selected_cache)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("registry credential verifier authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("registry credential verifier authority is immutable")

    def verify(
        self, deployment_identity: _identity.AuthorizedGitHubIdentity, *,
        zot_token: str, forgejo_token: str, received_at: int,
    ) -> VerifiedRegistryCredentials:
        """Bind two independently signed read JWTs to one normalized run."""

        try:
            if (type(zot_token) is not str or type(forgejo_token) is not str
                    or type(received_at) is not int or received_at < 0):
                raise ValueError
            reviewed_sha = object.__getattribute__(self, "_expected_workflow_sha")
            deployment = _normalize_identity(
                deployment_identity, received_at=received_at,
                expected_workflow_sha=reviewed_sha,
                authorization=_identity.authorize_verified_github_oidc,
                expected_fields=_IDENTITY_FIELDS,
            )
            cache = object.__getattribute__(self, "_jwks_cache")
            identities = []
            for token, audience, policy in (
                (zot_token, _identity.DEV_ZOT_READ_AUDIENCE,
                 _identity._ZOT_AUTHORIZATION_POLICY),
                (forgejo_token, _identity.DEV_FORGEJO_READ_AUDIENCE,
                 _identity._FORGEJO_AUTHORIZATION_POLICY),
            ):
                claims = _oidc._verify_bounded_github_oidc_claims(
                    token, received_at=received_at, audience=audience,
                    jwks_cache=cache,
                )
                authorized = _identity._authorize_verified_github_oidc(
                    claims, policy=policy, received_at=received_at,
                    expected_workflow_sha=reviewed_sha,
                )
                if any(getattr(authorized, field) != getattr(deployment, field)
                       for field in _CROSS_BOUND_FIELDS):
                    raise ValueError
                identities.append(authorized)
            zot = _ZotReadCredential(zot_token, identities[0].expires_at)
            forgejo = _ForgejoReadCredential(forgejo_token, identities[1].expires_at)
            # C32B's consumer policy is stricter than OIDC clock skew for
            # actual read credentials: they must still be usable at receipt.
            _credential(zot, _ZotReadCredential, received_at)
            _credential(forgejo, _ForgejoReadCredential, received_at)
            return _result(zot, forgejo)
        except _CONTROL:
            raise
        except _OIDCVerificationUnavailable:
            raise RegistryCredentialUnavailableError(_ERROR) from None
        except (_OIDCVerificationError, _OIDCAuthorizationError,
                _ReleaseConsumerError, ValueError):
            raise RegistryCredentialRejectedError(_ERROR) from None
        except Exception:
            raise RegistryCredentialUnavailableError(_ERROR) from None
