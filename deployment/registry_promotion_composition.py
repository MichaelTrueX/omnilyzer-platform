"""C32P repository-only composition of request-scoped registry authority.

This module remains outside the installed 31-file generation. Construction is
inert; no token request, registry access, Cosign execution or host mutation.
"""

from __future__ import annotations

from .broker import (
    BrokerRejectedError, BrokerUnavailableError, REJECTED_MESSAGE,
    UNAVAILABLE_MESSAGE, _bound_operation,
)
from .broker_integration import (
    InertDevPromotionHandler, _CapturedSignature, _RegistryOIDCTokens,
    _ReleaseRequestBuilder,
)
from .broker_service_config import DevBrokerServiceConfiguration
from .execution import IngressReference, RuntimeConfigurationReference
from .identity import AuthorizedGitHubIdentity
from .oci_verifier import CosignOCISignatureVerifier
from .registry_oidc_credentials import (
    GitHubRegistryCredentialVerifier, RegistryCredentialRejectedError,
    RegistryCredentialUnavailableError, RegistryCredentialVerificationError,
    VerifiedRegistryCredentials,
)
from .release_consumer import (
    ForgejoEvidenceConsumer, ReleaseBlobSignatureVerifier, ZotCandidateConsumer,
    _connection,
)


class _RegistryContextVerifier:
    """Map C32O's fixed secret-safe errors to the broker's two failure classes."""

    __slots__ = ("_verify",)

    def __init__(self, verifier: GitHubRegistryCredentialVerifier) -> None:
        if type(verifier) is not GitHubRegistryCredentialVerifier:
            raise TypeError("registry verifier authority is invalid")
        object.__setattr__(self, "_verify", _bound_operation(verifier, "verify"))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("registry context verifier is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("registry context verifier is immutable")

    def verify(
        self, deployment_identity: AuthorizedGitHubIdentity,
        private_context: _RegistryOIDCTokens, *, received_at: int,
    ) -> VerifiedRegistryCredentials:
        if type(private_context) is not _RegistryOIDCTokens:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        try:
            result = object.__getattribute__(self, "_verify")(
                deployment_identity,
                zot_token=object.__getattribute__(private_context, "zot_token"),
                forgejo_token=object.__getattribute__(private_context, "forgejo_token"),
                received_at=received_at,
            )
        except RegistryCredentialRejectedError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except (RegistryCredentialUnavailableError, RegistryCredentialVerificationError):
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        if type(result) is not VerifiedRegistryCredentials:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        return result


class _RequestScopedReleaseAuthority:
    """Capture only static authority; create credential users inside each call."""

    __slots__ = ("_cosign", "_zot_connection", "_forgejo_connection", "_oci_runner")

    def __init__(
        self, configuration: DevBrokerServiceConfiguration, *,
        zot_connection_factory: object, forgejo_connection_factory: object,
        oci_runner: object | None,
    ) -> None:
        if type(configuration) is not DevBrokerServiceConfiguration:
            raise TypeError("broker configuration authority is invalid")
        authority = dict(configuration.blob_verifier_kwargs())
        if set(authority) != {
            "expected_cosign_version", "expected_binary_sha256",
            "expected_trusted_root_sha256", "broker_uid", "broker_gid",
        } or not callable(zot_connection_factory) or not callable(forgejo_connection_factory):
            raise TypeError("release authority is invalid")
        object.__setattr__(self, "_cosign", tuple(authority.items()))
        object.__setattr__(self, "_zot_connection", zot_connection_factory)
        object.__setattr__(self, "_forgejo_connection", forgejo_connection_factory)
        object.__setattr__(self, "_oci_runner", oci_runner)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("release authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("release authority is immutable")

    def create(self, credentials: VerifiedRegistryCredentials) -> tuple[object, object, object]:
        if type(credentials) is not VerifiedRegistryCredentials:
            raise TypeError("verified registry context type is invalid")
        zot = ZotCandidateConsumer(credentials, object.__getattribute__(self, "_zot_connection"))
        forgejo = ForgejoEvidenceConsumer(
            credentials, object.__getattribute__(self, "_forgejo_connection"),
        )
        oci = CosignOCISignatureVerifier(
            **dict(object.__getattribute__(self, "_cosign")),
            zot_credential_provider=credentials,
            runner=object.__getattribute__(self, "_oci_runner"),
        )
        return zot, forgejo, _CapturedSignature(oci)


def compose_inert_dev_promotion_handler(
    *, configuration: DevBrokerServiceConfiguration, verifier: object,
    replay_guard: object, transport: object,
    blob_signatures: ReleaseBlobSignatureVerifier,
    runtime: RuntimeConfigurationReference, ingress: IngressReference,
    jwks_cache: object | None = None,
    zot_connection_factory: object = _connection,
    forgejo_connection_factory: object = _connection,
    oci_runner: object | None = None,
) -> InertDevPromotionHandler:
    """Revalidate closed C32H authority; bind only nonsecret collaborators."""

    if type(configuration) is not DevBrokerServiceConfiguration:
        raise TypeError("broker configuration authority is invalid")
    configuration = DevBrokerServiceConfiguration.from_dict(configuration.to_dict())
    workflow = configuration.oidc_authorization_kwargs()["expected_workflow_sha"]
    registry = GitHubRegistryCredentialVerifier(
        expected_workflow_sha=workflow, jwks_cache=jwks_cache,
    )
    factory = _RequestScopedReleaseAuthority(
        configuration, zot_connection_factory=zot_connection_factory,
        forgejo_connection_factory=forgejo_connection_factory, oci_runner=oci_runner,
    )
    builder = _ReleaseRequestBuilder(
        factory=factory, verified_context_type=VerifiedRegistryCredentials,
        blob_signatures=blob_signatures,
        runtime=runtime, ingress=ingress, expected_workflow_sha=workflow,
    )
    return InertDevPromotionHandler(
        expected_workflow_sha=workflow, verifier=verifier,
        replay_guard=replay_guard, transport=transport,
        request_builder=builder,
        promotion_context_verifier=_RegistryContextVerifier(registry),
    )


__all__ = ("compose_inert_dev_promotion_handler",)
