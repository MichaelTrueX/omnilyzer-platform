"""Inert restricted deployment broker orchestration core.

This module has no listener, socket implementation, installation, runtime
adapter, registry client, or deployment activation.  It composes only the
constructor-bound security collaborators supplied by a future reviewed host.
"""

from __future__ import annotations

import hashlib
import inspect
import types
from typing import Any, Callable

from .execution import (
    MAX_CANONICAL_REQUEST_BYTES,
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
)
from .jwks import OIDCVerificationError, OIDCVerificationUnavailable


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
    return authorization(claims, received_at=received_at)


class RestrictedDeploymentBroker:
    """Closed verifier -> request -> replay -> opaque-transport sequence."""

    __slots__ = ("_operations",)

    def __init__(
        self, *, verifier: object, replay_guard: ReplayGuard,
        transport: ExecutorTransport,
    ) -> None:
        object.__setattr__(self, "_operations", (
            _bound_operation(verifier, "verify"),
            _bound_operation(replay_guard, "consume"),
            _bound_operation(transport, "send"),
        ))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("broker collaborators are immutable")

    def authorize_and_forward(
        self, *, compact_token: str, canonical_request: bytes, received_at: int,
    ) -> bytes:
        if (type(compact_token) is not str
                or type(canonical_request) is not bytes
                or type(received_at) is not int
                or received_at < 0
                or not canonical_request
                or len(canonical_request) > MAX_CANONICAL_REQUEST_BYTES):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None

        verify, consume, send = object.__getattribute__(self, "_operations")
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
                authorization=authorization, expected_fields=expected_identity_fields,
            )
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
        try:
            consume(
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

        try:
            response = send(canonical_request)
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        if type(response) is not bytes or len(response) > MAX_EXECUTOR_RESPONSE_BYTES:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        return response


__all__ = (
    "BrokerRejectedError",
    "BrokerUnavailableError",
    "MAX_EXECUTOR_RESPONSE_BYTES",
    "RestrictedDeploymentBroker",
)
