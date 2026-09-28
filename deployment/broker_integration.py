"""Inert DEV promotion handler; request authority is constructor-bound.

The installed source selection stays closed. C32P's repository-only concrete
registry/Cosign composition lives outside that historical application set.
"""

from __future__ import annotations

from .broker import (
    BrokerRejectedError, REJECTED_MESSAGE, RestrictedDeploymentBroker,
    _bound_operation,
)
from .execution import ExecutorRequest, IngressReference, RuntimeConfigurationReference
from .identity import AuthorizedGitHubIdentity, validate_expected_workflow_sha
from .jwks import OIDCVerificationError, parse_bounded_json
from .oidc_verifier import MAX_COMPACT_TOKEN_BYTES
from .policy import DeploymentPolicyError
from .promotion import PromotionRequest
from .release_consumer import (
    ReleaseBlobSignatureVerifier, acquire_and_construct_dev_request,
)


MAX_PROMOTION_REQUEST_BYTES = 4096


class _RegistryOIDCTokens:
    """Private, noncanonical raw-token envelope for only one active call."""

    __slots__ = ("zot_token", "forgejo_token")

    def __init__(self, zot_token: str, forgejo_token: str) -> None:
        object.__setattr__(self, "zot_token", zot_token)
        object.__setattr__(self, "forgejo_token", forgejo_token)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("registry token context is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("registry token context is immutable")

    def __repr__(self) -> str:
        return "<_RegistryOIDCTokens redacted>"

    def __reduce__(self) -> object:
        raise TypeError("registry token context is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("registry token context is not serializable")


class _CapturedSignature:
    """Capture a non-property bound operation without invoking it."""

    __slots__ = ("_verify",)

    def __init__(self, collaborator: object) -> None:
        object.__setattr__(self, "_verify", _bound_operation(collaborator, "verify"))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("signature authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("signature authority is immutable")

    def verify(self, *args: object) -> object:
        return object.__getattribute__(self, "_verify")(*args)


class _ReleaseRequestBuilder:
    """Keep only nonsecret static authority; require a reviewed context type."""

    __slots__ = ("_create", "_verified_context_type", "_blob_signatures",
                 "_runtime", "_ingress", "_expected_workflow_sha")

    def __init__(
        self, *, factory: object, verified_context_type: type,
        blob_signatures: ReleaseBlobSignatureVerifier,
        expected_workflow_sha: str,
        runtime: RuntimeConfigurationReference, ingress: IngressReference,
    ) -> None:
        if type(verified_context_type) is not type:
            raise TypeError("verified context type authority is invalid")
        object.__setattr__(self, "_create", _bound_operation(factory, "create"))
        object.__setattr__(self, "_verified_context_type", verified_context_type)
        object.__setattr__(self, "_blob_signatures", _CapturedSignature(blob_signatures))
        object.__setattr__(self, "_expected_workflow_sha",
                           validate_expected_workflow_sha(expected_workflow_sha))
        object.__setattr__(self, "_runtime", runtime)
        object.__setattr__(self, "_ingress", ingress)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("DEV release builder collaborators are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("DEV release builder collaborators are immutable")

    def build(
        self, promotion: PromotionRequest, identity: AuthorizedGitHubIdentity,
        verified_context: object, *, received_at: int,
    ) -> ExecutorRequest:
        if type(verified_context) is not object.__getattribute__(
                self, "_verified_context_type"):
            raise TypeError("verified registry context type is invalid")
        zot, forgejo, oci = object.__getattribute__(self, "_create")(
            verified_context)
        return acquire_and_construct_dev_request(
            promotion, identity, self._runtime, self._ingress,
            zot, forgejo, self._blob_signatures, oci,
            received_at=received_at,
            expected_workflow_sha=object.__getattribute__(self, "_expected_workflow_sha"),
        )


class InertDevPromotionHandler:
    """Handle three separate compact JWTs and canonical token-free promotion bytes."""

    __slots__ = ("_forward",)

    def __init__(
        self, *, expected_workflow_sha: str, verifier: object, replay_guard: object,
        transport: object, request_builder: object,
        promotion_context_verifier: object,
    ) -> None:
        broker = RestrictedDeploymentBroker(
            expected_workflow_sha=expected_workflow_sha,
            verifier=verifier, replay_guard=replay_guard, transport=transport,
            request_builder=request_builder,
            promotion_context_verifier=promotion_context_verifier,
        )
        object.__setattr__(self, "_forward", broker.authorize_promotion_and_forward)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("DEV promotion handler collaborators are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("DEV promotion handler collaborators are immutable")

    def handle(
        self, *, compact_token: str, zot_token: str, forgejo_token: str,
        promotion_request: bytes, received_at: int,
    ) -> bytes:
        if (any(type(token) is not str or not token.isascii()
                or not 1 <= len(token) <= MAX_COMPACT_TOKEN_BYTES
                for token in (compact_token, zot_token, forgejo_token))
                or type(promotion_request) is not bytes
                or not 1 <= len(promotion_request) <= MAX_PROMOTION_REQUEST_BYTES
                or type(received_at) is not int or received_at < 0):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        try:
            data = parse_bounded_json(
                promotion_request, maximum_bytes=MAX_PROMOTION_REQUEST_BYTES,
                maximum_root_members=11, maximum_depth=2,
                maximum_nodes=32, maximum_array=0, maximum_string=2048,
            )
            promotion = PromotionRequest.from_dict(data)
            if promotion.canonical_bytes() != promotion_request:
                raise DeploymentPolicyError("promotion request is not canonical")
        except (OIDCVerificationError, DeploymentPolicyError, UnicodeError, ValueError):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        return object.__getattribute__(self, "_forward")(
            compact_token=compact_token, promotion=promotion,
            promotion_context=_RegistryOIDCTokens(zot_token, forgejo_token),
            received_at=received_at,
        )


__all__ = ("InertDevPromotionHandler", "MAX_PROMOTION_REQUEST_BYTES")
