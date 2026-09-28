"""Closed, explicit C32T DEV broker process composition; import is inert.

The caller supplies only an in-process stop controller. Authority is loaded from
the fixed root-controlled broker configuration, and the replay store must
already exist. No listener is constructed until replay validation succeeds.
"""

from __future__ import annotations

from .blob_verifier import CosignReleaseBlobVerifier as _CosignReleaseBlobVerifier
from .broker_loopback_listener import (
    BrokerStopController, DevBrokerLoopbackListener as _DevBrokerLoopbackListener,
)
from .broker_service_config import DevBrokerServiceConfiguration
from .broker_service_config_loader import (
    load_dev_broker_service_configuration as _load_configuration,
)
from .jwks import GitHubJWKSCache as _GitHubJWKSCache
from .oidc_verifier import GitHubOIDCVerifier as _GitHubOIDCVerifier
from .registry_promotion_composition import (
    compose_inert_dev_promotion_handler as _compose_handler,
)
from .replay_sqlite import (
    PRODUCTION_REPLAY_DATABASE, SQLiteReplayGuard as _SQLiteReplayGuard,
)
from .unix_transport import UnixExecutorTransport as _UnixExecutorTransport


__all__ = ("BrokerServiceBootstrapError", "run_dev_broker_service")
_ERROR = "DEV broker service bootstrap is unavailable"


class BrokerServiceBootstrapError(Exception):
    """The closed DEV broker service could not start or continue."""


def run_dev_broker_service(*, stop_controller: BrokerStopController) -> None:
    """Validate existing authority, then serve sequentially until stopped."""

    if type(stop_controller) is not BrokerStopController:
        raise BrokerServiceBootstrapError(_ERROR) from None
    try:
        configuration = _load_configuration()
        if type(configuration) is not DevBrokerServiceConfiguration:
            raise TypeError
        configuration = DevBrokerServiceConfiguration.from_dict(configuration.to_dict())
        identity = configuration.installation_contract().broker_composition_kwargs()
        cache = _GitHubJWKSCache()
        verifier = _GitHubOIDCVerifier(
            expected_workflow_sha=configuration.oidc_authorization_kwargs()[
                "expected_workflow_sha"
            ],
            jwks_cache=cache,
        )
        replay = _SQLiteReplayGuard(
            PRODUCTION_REPLAY_DATABASE,
            expected_directory_uid=identity["expected_replay_directory_uid"],
            expected_directory_gid=identity["expected_replay_directory_gid"],
            expected_broker_uid=identity["expected_broker_uid"],
            expected_executor_uid=identity["expected_executor_uid"],
        )
        replay.validate()  # read-only; initialization is separate reviewed work
        transport = _UnixExecutorTransport(
            expected_executor_uid=identity["expected_executor_uid"],
            expected_executor_gid=identity["expected_executor_gid"],
            expected_socket_group_gid=identity["expected_socket_group_gid"],
        )
        blob = _CosignReleaseBlobVerifier(**configuration.blob_verifier_kwargs())
        handler = _compose_handler(
            configuration=configuration, verifier=verifier,
            replay_guard=replay, transport=transport, blob_signatures=blob,
            jwks_cache=cache,
        )
        listener = _DevBrokerLoopbackListener(handler)
        if listener.serve_until_stopped(stop_controller) is not None:
            raise TypeError
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise BrokerServiceBootstrapError(_ERROR) from None
