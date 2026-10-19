"""Inert restricted deployment broker orchestration core.

This module has no listener, socket implementation, installation, runtime
adapter, registry client, or deployment activation.  It composes only the
constructor-bound security collaborators supplied by a future reviewed host.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import time
import types
from typing import Any, Callable

from .execution import (
    MAX_CANONICAL_REQUEST_BYTES,
    ExecutorRequest,
    ExecutorRequestError,
    ExecutorTransport,
    bind_request_to_identity,
    parse_canonical_request,
)
from .identity import (
    AuthorizedGitHubIdentity,
    OIDCAuthorizationError,
    ReplayError,
    ReplayGuard,
    ReplayUnavailableError,
    authorize_verified_github_oidc,
    validate_expected_workflow_sha,
)
from .jwks import OIDCVerificationError, OIDCVerificationUnavailable
from .private_registry_fd import create_sealed_credential


MAX_EXECUTOR_RESPONSE_BYTES = 64 * 1024
REJECTED_MESSAGE = "deployment request is not accepted"
UNAVAILABLE_MESSAGE = "deployment authority is unavailable"
IDENTITY_FIELDS = frozenset({
    "issuer", "audience", "repository", "repository_id", "repository_owner_id",
    "workflow_ref", "workflow_sha", "ref", "environment", "event_name",
    "runner_environment", "run_id", "run_attempt", "actor_id", "issued_at",
    "not_before", "expires_at", "jti",
})


class BrokerRejectedError(Exception):
    """The supplied token/request or replay identity is definitely rejected."""


class BrokerUnavailableError(Exception):
    """Deployment authority cannot produce a trustworthy result."""


def _bound_operation(dependency: object, name: str) -> Callable[..., Any]:
    """Capture one non-property operation without invoking the collaborator."""

    if dependency is None:
        raise TypeError("broker collaborator is invalid")
    try:
        operation = inspect.getattr_static(dependency, name)
    except AttributeError:
        raise TypeError("broker collaborator is invalid") from None
    if isinstance(operation, types.FunctionType):
        return types.MethodType(operation, dependency)
    if isinstance(operation, staticmethod):
        operation = operation.__func__
    if not callable(operation):
        raise TypeError("broker collaborator is invalid")
    return operation


def _normalize_identity(
    identity: AuthorizedGitHubIdentity, *, received_at: int,
    expected_workflow_sha: str,
    authorization: Callable[..., AuthorizedGitHubIdentity],
    expected_fields: frozenset[str],
) -> AuthorizedGitHubIdentity:
    """Reauthorize one exact base identity using non-virtual explicit fields."""

    if type(identity) is not AuthorizedGitHubIdentity:
        raise OIDCAuthorizationError("verified identity type is invalid")
    try:
        fields = object.__getattribute__(identity, "__dict__")
    except AttributeError:
        raise OIDCAuthorizationError("verified identity fields are unavailable") from None
    if (type(fields) is not dict or len(fields) != len(expected_fields)
            or not all(type(name) is str for name in fields)
            or set(fields) != expected_fields):
        raise OIDCAuthorizationError("verified identity fields are invalid")
    values = dict.copy(fields)
    string_fields = (
        "issuer", "audience", "repository", "workflow_ref", "workflow_sha",
        "ref", "environment", "event_name", "runner_environment", "jti",
    )
    integer_fields = (
        "repository_id", "repository_owner_id", "run_id", "run_attempt",
        "actor_id", "issued_at", "not_before", "expires_at",
    )
    for name in string_fields:
        value = values[name]
        if type(value) is not str:
            raise OIDCAuthorizationError("verified identity field type is invalid")
    for name in integer_fields:
        value = values[name]
        if type(value) is not int:
            raise OIDCAuthorizationError("verified identity field type is invalid")
    claims = {
        "iss": values["issuer"],
        "aud": values["audience"],
        "repository": values["repository"],
        "repository_id": str(values["repository_id"]),
        "repository_owner_id": str(values["repository_owner_id"]),
        "workflow_ref": values["workflow_ref"],
        "workflow_sha": values["workflow_sha"],
        "ref": values["ref"],
        "environment": values["environment"],
        "event_name": values["event_name"],
        "runner_environment": values["runner_environment"],
        "run_id": str(values["run_id"]),
        "run_attempt": str(values["run_attempt"]),
        "actor_id": str(values["actor_id"]),
        "iat": values["issued_at"],
        "nbf": values["not_before"],
        "exp": values["expires_at"],
        "jti": values["jti"],
    }
    return authorization(
        claims, received_at=received_at,
        expected_workflow_sha=expected_workflow_sha,
    )


class RestrictedDeploymentBroker:
    """Closed verifier -> request -> replay -> opaque-transport sequence."""

    __slots__ = ("_operations", "_expected_workflow_sha")

    def __init__(
        self, *, expected_workflow_sha: str, verifier: object, replay_guard: ReplayGuard,
        transport: ExecutorTransport, request_builder: object | None = None,
        promotion_context_verifier: object | None = None,
        private_registry_transport: bool = False,
    ) -> None:
        if type(private_registry_transport) is not bool or (
            private_registry_transport
            and (request_builder is None or promotion_context_verifier is None)
        ):
            raise TypeError("private registry transport requires verified authority")
        object.__setattr__(self, "_expected_workflow_sha",
                           validate_expected_workflow_sha(expected_workflow_sha))
        object.__setattr__(self, "_operations", (
            _bound_operation(verifier, "verify"),
            _bound_operation(replay_guard, "consume"),
            _bound_operation(transport, "send"),
            None if request_builder is None else _bound_operation(request_builder, "build"),
            None if promotion_context_verifier is None else _bound_operation(
                promotion_context_verifier, "verify"),
            (_bound_operation(transport, "_send_private")
             if private_registry_transport else None),
        ))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("broker collaborators are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("broker collaborators are immutable")

    def authorize_and_forward(
        self, *, compact_token: str, canonical_request: bytes, received_at: int,
    ) -> bytes:
        if (type(canonical_request) is not bytes or not canonical_request
                or len(canonical_request) > MAX_CANONICAL_REQUEST_BYTES):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        return self._authorize(
            compact_token=compact_token, received_at=received_at,
            canonical_request=canonical_request, promotion=None, promotion_context=None,
        )

    def authorize_promotion_and_forward(
        self, *, compact_token: str, promotion: object, promotion_context: object,
        received_at: int,
    ) -> bytes:
        """Build the final request after verification, before replay and transport."""

        return self._authorize(
            compact_token=compact_token, received_at=received_at,
            canonical_request=None, promotion=promotion,
            promotion_context=promotion_context,
        )

    def _authorize(
        self, *, compact_token: str, received_at: int,
        canonical_request: bytes | None, promotion: object | None,
        promotion_context: object | None,
    ) -> bytes:
        if (type(compact_token) is not str
                or type(received_at) is not int
                or received_at < 0
                or (canonical_request is not None and (
                    type(canonical_request) is not bytes or not canonical_request
                    or len(canonical_request) > MAX_CANONICAL_REQUEST_BYTES))):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None

        verify, consume, send, build, verify_context, send_private = (
            object.__getattribute__(self, "_operations")
        )
        expected_workflow_sha = object.__getattribute__(self, "_expected_workflow_sha")
        if canonical_request is None and (build is None or verify_context is None
                                          or promotion is None or promotion_context is None):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        if send_private is not None and canonical_request is not None:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        normalize_identity = _normalize_identity
        authorization = authorize_verified_github_oidc
        expected_identity_fields = IDENTITY_FIELDS
        parse_request = parse_canonical_request
        bind_identity = bind_request_to_identity
        sha256 = hashlib.sha256

        try:
            returned_identity = verify(compact_token, received_at=received_at)
        except OIDCVerificationUnavailable:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        except OIDCVerificationError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        try:
            identity = normalize_identity(
                returned_identity, received_at=received_at,
                expected_workflow_sha=expected_workflow_sha,
                authorization=authorization, expected_fields=expected_identity_fields,
            )
        except OIDCAuthorizationError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        if canonical_request is None:
            try:
                verified_context = verify_context(
                    identity, promotion_context, received_at=received_at,
                )
            except BrokerRejectedError:
                raise BrokerRejectedError(REJECTED_MESSAGE) from None
            except BrokerUnavailableError:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
            except Exception:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        try:
            if canonical_request is None:
                constructed = build(promotion, identity, verified_context,
                                    received_at=received_at)
                if type(constructed) is not ExecutorRequest:
                    raise ExecutorRequestError("constructed executor request type is invalid")
                canonical_request = constructed.canonical_bytes()
                if (type(canonical_request) is not bytes or not canonical_request
                        or len(canonical_request) > MAX_CANONICAL_REQUEST_BYTES):
                    raise ExecutorRequestError("constructed executor request bytes are invalid")
            request = parse_request(canonical_request)
            bind_identity(request, identity)
        except (OIDCAuthorizationError, ExecutorRequestError):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        try:
            request_hash = sha256(canonical_request).hexdigest()
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        if (type(request_hash) is not str or len(request_hash) != 64
                or any(character not in "0123456789abcdef" for character in request_hash)):
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        # The private credential is checked and sealed BEFORE consuming broker
        # replay. It stays outside canonical request bytes, hashes and audit.
        descriptor: int | None = None
        try:
            if send_private is not None:
                try:
                    credential_provider = _bound_operation(
                        verified_context, "zot_read_credential",
                    )
                    credential = credential_provider()
                    token = credential.token
                    expiry = credential.expires_at
                    descriptor = create_sealed_credential(
                        token, expires_at=expiry,
                        image=request.exact_image_reference,
                        canonical_request=canonical_request,
                        now=int(time.time()),
                    )
                except (KeyboardInterrupt, SystemExit, GeneratorExit):
                    raise
                except Exception:
                    raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

            try:
                consume_result = consume(
                    identity.jti,
                    expires_at=identity.expires_at,
                    request_hash=request_hash,
                    run_id=identity.run_id,
                    run_attempt=identity.run_attempt,
                )
            except ReplayUnavailableError:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
            except ReplayError:
                raise BrokerRejectedError(REJECTED_MESSAGE) from None
            except Exception:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
            if consume_result is not None:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

            try:
                response = (
                    send_private(canonical_request, credential_fd=descriptor)
                    if send_private is not None else send(canonical_request)
                )
            except Exception:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
            if type(response) is not bytes or len(response) > MAX_EXECUTOR_RESPONSE_BYTES:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
            return response
        finally:
            if descriptor is not None:
                os.close(descriptor)


__all__ = (
    "BrokerRejectedError",
    "BrokerUnavailableError",
    "MAX_EXECUTOR_RESPONSE_BYTES",
    "RestrictedDeploymentBroker",
)
