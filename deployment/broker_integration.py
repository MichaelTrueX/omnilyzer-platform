"""Inert C32C DEV promotion handler; no listener or production composition.

Only a later reviewed environment-local broker may supply the credential,
signature, release-run, replay, and transport implementations. Construction
does not call any collaborator or create installation/activation authority.
"""

from __future__ import annotations

from .broker import BrokerRejectedError, REJECTED_MESSAGE, RestrictedDeploymentBroker
from .execution import ExecutorRequest, IngressReference, RuntimeConfigurationReference
from .identity import AuthorizedGitHubIdentity
from .jwks import OIDCVerificationError, parse_bounded_json
from .oidc_verifier import MAX_COMPACT_TOKEN_BYTES
from .policy import DeploymentPolicyError
from .promotion import PromotionRequest
from .release_consumer import (
    ForgejoEvidenceConsumer, ReleaseRunVerifier, ReleaseSignatureVerifier,
    ZotCandidateConsumer, acquire_and_construct_dev_request,
)


MAX_PROMOTION_REQUEST_BYTES = 4096


class _ReleaseRequestBuilder:
    __slots__ = ("_zot", "_forgejo", "_signatures", "_release_run", "_runtime", "_ingress")

    def __init__(
        self, *, zot: ZotCandidateConsumer, forgejo: ForgejoEvidenceConsumer,
        signatures: ReleaseSignatureVerifier, release_run: ReleaseRunVerifier,
        runtime: RuntimeConfigurationReference, ingress: IngressReference,
    ) -> None:
        object.__setattr__(self, "_zot", zot)
        object.__setattr__(self, "_forgejo", forgejo)
        object.__setattr__(self, "_signatures", signatures)
        object.__setattr__(self, "_release_run", release_run)
        object.__setattr__(self, "_runtime", runtime)
        object.__setattr__(self, "_ingress", ingress)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("DEV release builder collaborators are immutable")

    def build(
        self, promotion: PromotionRequest, identity: AuthorizedGitHubIdentity,
        *, received_at: int,
    ) -> ExecutorRequest:
        return acquire_and_construct_dev_request(
            promotion, identity, self._runtime, self._ingress,
            self._zot, self._forgejo, self._signatures, self._release_run,
            received_at=received_at,
        )


class InertDevPromotionHandler:
    """Handle supplied token and canonical promotion bytes exactly once."""

    __slots__ = ("_forward",)

    def __init__(
        self, *, verifier: object, replay_guard: object, transport: object,
        zot: ZotCandidateConsumer, forgejo: ForgejoEvidenceConsumer,
        signatures: ReleaseSignatureVerifier, release_run: ReleaseRunVerifier,
        runtime: RuntimeConfigurationReference, ingress: IngressReference,
    ) -> None:
        builder = _ReleaseRequestBuilder(
            zot=zot, forgejo=forgejo, signatures=signatures,
            release_run=release_run, runtime=runtime, ingress=ingress,
        )
        broker = RestrictedDeploymentBroker(
            verifier=verifier, replay_guard=replay_guard, transport=transport,
            request_builder=builder,
        )
        object.__setattr__(self, "_forward", broker.authorize_promotion_and_forward)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("DEV promotion handler collaborators are immutable")

    def handle(
        self, *, compact_token: str, promotion_request: bytes, received_at: int,
    ) -> bytes:
        if (type(compact_token) is not str or not compact_token.isascii()
                or not 1 <= len(compact_token) <= MAX_COMPACT_TOKEN_BYTES
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
            compact_token=compact_token, promotion=promotion, received_at=received_at,
        )


__all__ = ("InertDevPromotionHandler", "MAX_PROMOTION_REQUEST_BYTES")
