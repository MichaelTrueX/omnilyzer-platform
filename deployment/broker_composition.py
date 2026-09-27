"""deployment/broker_composition.py — inert GitHub DEV broker composition.

Purpose: compose ``deployment.oidc_verifier.GitHubOIDCVerifier``,
``deployment.replay_sqlite.SQLiteReplayGuard``,
``deployment.unix_transport.UnixExecutorTransport``, and
``deployment.broker.RestrictedDeploymentBroker`` as the specific
GitHub-authorized DEV broker profile. Import and construction are inert: this
module creates no listener, initializes no replay storage, performs no HTTP or
network request, does not connect to the executor socket, and performs no
deployment during construction.
"""

from __future__ import annotations

from .broker import RestrictedDeploymentBroker as _RestrictedDeploymentBroker
from .oidc_verifier import GitHubOIDCVerifier as _GitHubOIDCVerifier
from .replay_sqlite import (
    PRODUCTION_REPLAY_DATABASE as _PRODUCTION_REPLAY_DATABASE,
    SQLiteReplayGuard as _SQLiteReplayGuard,
)
from .unix_transport import UnixExecutorTransport as _UnixExecutorTransport


__all__ = ("GitHubDevBrokerComposition",)


class GitHubDevBrokerComposition:
    """Own the closed GitHub-authorized DEV broker graph and operation."""

    __slots__ = ("_authorize_and_forward",)

    def __init__(
        self, *, expected_workflow_sha: str, expected_replay_directory_uid: int,
        expected_replay_directory_gid: int, expected_broker_uid: int,
        expected_executor_uid: int,
        expected_executor_gid: int, expected_socket_group_gid: int,
    ) -> None:
        """Construct the reviewed broker graph without invoking any operation."""

        verifier = _GitHubOIDCVerifier(expected_workflow_sha=expected_workflow_sha)
        replay_guard = _SQLiteReplayGuard(
            _PRODUCTION_REPLAY_DATABASE,
            expected_directory_uid=expected_replay_directory_uid,
            expected_directory_gid=expected_replay_directory_gid,
            expected_broker_uid=expected_broker_uid,
            expected_executor_uid=expected_executor_uid,
        )
        transport = _UnixExecutorTransport(
            expected_executor_uid=expected_executor_uid,
            expected_executor_gid=expected_executor_gid,
            expected_socket_group_gid=expected_socket_group_gid,
        )
        broker = _RestrictedDeploymentBroker(
            expected_workflow_sha=expected_workflow_sha,
            verifier=verifier, replay_guard=replay_guard, transport=transport,
        )
        object.__setattr__(
            self, "_authorize_and_forward", broker.authorize_and_forward,
        )

    def __setattr__(self, name: str, value: object) -> None:
        """Reject supported-API replacement of the captured broker operation."""

        raise AttributeError("GitHub DEV broker composition is immutable")

    def __delattr__(self, name: str) -> None:
        """Reject supported-API removal of the captured broker operation."""

        raise AttributeError("GitHub DEV broker composition is immutable")

    def authorize_and_forward(
        self, *, compact_token: str, canonical_request: bytes, received_at: int,
    ) -> bytes:
        """Delegate exactly once to the composed restricted broker operation."""

        response = object.__getattribute__(self, "_authorize_and_forward")(
            compact_token=compact_token,
            canonical_request=canonical_request,
            received_at=received_at,
        )
        if type(response) is not bytes:
            raise TypeError("GitHub DEV broker returned an invalid result")
        return response
