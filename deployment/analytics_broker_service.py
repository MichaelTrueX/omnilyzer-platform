"""File: deployment/analytics_broker_service.py

Purpose: Product-only addition to the EXISTING Task014 DEV broker, reusing the
         original port 3031 HTTPS ingress, OIDC, registry verifier, original
         replay, Cosign/Sigstore and original canary handler without a second
         network listener or service.
Related: deployment/broker_service_bootstrap.py (unchanged until explicitly
         reviewed root-owned installation), deployment/broker_service_config_loader.py,
         deployment/analytics_executor_service_config.py (closed SHA source
         schema and O_NOFOLLOW installed file verifier),
         deployment/analytics_broker_router.py, deployment/analytics_unix_boundary.py,
         deployment/analytics_registry_review_composition.py,
         deployment/tests/test_analytics_broker_service.py.

Sections: exact read-only protected broker config, optional product admission
          only on missing approved root-controlled file, closed existing broker
          composition, existing HTTP handler selection.

SECURITY: A missing Analytics config returns the EXISTING canary handler; a
present but malformed/unauthorized config fails CLOSED (never silently
falls back). This module is not installed in original C32V source selection.
It neither creates a listening port nor deploys/starts Docker or modifies
existing canary. Root must separately approve/configure the product capability.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path

from . import broker_service_config_loader as _original
from .analytics_broker_router import AnalyticsDEVPromotionRouter
from .analytics_executor_service_config import (
    parse_analytics_executor_service_config, _verify_source_bytes,
    _PRODUCT_PATH, _RUNTIME_PATH, _COMPOSE_PATH,
    _SOURCE_CLAIM_PATH, _SOURCE_CLAIM_SHA256,
)
from .analytics_promotion_broker import AnalyticsPrivatePromotionBroker
from .analytics_registry_review_composition import (
    InertAnalyticsSignedReleaseReviewHandler,
)
from .analytics_unix_boundary import AnalyticsUnixExecutorTransport
from .broker_integration import InertDevPromotionHandler
from .broker_service_config import DevBrokerServiceConfiguration
from .oidc_verifier import GitHubOIDCVerifier
from .jwks import GitHubJWKSCache
from .replay_sqlite import SQLiteReplayGuard
from .blob_verifier import CosignReleaseBlobVerifier

_CONFIG_NAME = "analytics.json"
_CONFIG_PATH = Path("/etc/omnilyzer/deployment/broker/analytics.json")
_ERROR = "Analytics Task014 broker source is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsBrokerSourceError(Exception):
    """One root-checked broker product admission failed closed."""


def load_analytics_broker_installed_source(
    config: DevBrokerServiceConfiguration,
) -> dict[str, str] | None:
    """Read only exact root-owned broker product source; missing means canary.

    Reuse original C32H broker's hardened ancestor, process, file metadata
    and bounded-reader helpers. No user-created path, symlink or partial
    config can cause an Analytics promotion.
    """
    if type(config) is not DevBrokerServiceConfiguration:
        raise AnalyticsBrokerSourceError(_ERROR)
    owned: list[int] = []
    missing = False
    try:
        initial = _original._process_identity()
        directories, file_flags = _original._required_flags()
        opened, parent = _original._open_directories(owned, directories)
        try:
            named_stat = os.stat(
                _CONFIG_NAME, dir_fd=parent, follow_symlinks=False,
            )
        except FileNotFoundError as error:
            if error.errno != errno.ENOENT:
                raise
            missing = True
        if not missing:
            named = _original._configuration_file(named_stat)
            file_fd = _original._claim_descriptor(
                os.open(_CONFIG_NAME, file_flags, dir_fd=parent), owned,
            )
            current = _original._configuration_file(os.fstat(file_fd))
            if current != named or current[5] != config.broker_gid:
                raise ValueError("wrong protected broker file")
            raw = _original._bounded_read(file_fd, current[6])
            parsed = parse_analytics_executor_service_config(raw)
            if (
                _original._configuration_file(os.fstat(file_fd)) != current
                or _original._configuration_file(os.stat(
                    _CONFIG_NAME, dir_fd=parent, follow_symlinks=False,
                )) != current
                or parsed["reviewed_installed_commit"] != config.reviewed_commit
            ):
                raise ValueError("wrong reviewed source")
        final_directory = _original._revalidate_directories(opened)
        if (
            _original._process_identity() != initial
            or final_directory[5] != config.broker_gid
            or initial[0] != config.broker_uid
            or initial[1] != config.broker_uid
            or initial[2] != config.broker_gid
            or initial[3] != config.broker_gid
            or set(initial[4]) - {config.broker_gid}
            != set(config.installation_contract().broker_required_group_gids)
        ):
            raise ValueError("wrong broker identity")
        if missing:
            result = None
        else:
            _verify_source_bytes((
                *parsed["source_sha256"],
                (_PRODUCT_PATH, parsed["reviewed_product_profile_sha256"]),
                (_RUNTIME_PATH, parsed["reviewed_runtime_profile_sha256"]),
                (_COMPOSE_PATH, parsed["reviewed_compose_sha256"]),
                (_SOURCE_CLAIM_PATH, _SOURCE_CLAIM_SHA256),
            ))
            result = {
                key: parsed[key] for key in (
                    "reviewed_installed_commit", "reviewed_compose_sha256",
                    "reviewed_product_profile_sha256",
                    "reviewed_runtime_profile_sha256",
                )
            }
    except _CONTROL:
        _original._close_owned(owned)
        raise
    except Exception:
        _original._close_owned(owned)
        raise AnalyticsBrokerSourceError(_ERROR) from None
    failed, control = _original._close_owned(owned)
    if control is not None:
        raise control
    if failed:
        raise AnalyticsBrokerSourceError(_ERROR)
    return result


def compose_approved_analytics_broker_router(
    *, configuration: DevBrokerServiceConfiguration,
    canary_handler: InertDevPromotionHandler,
    verifier: GitHubOIDCVerifier,
    replay_guard: SQLiteReplayGuard,
    blob_signatures: CosignReleaseBlobVerifier,
    jwks_cache: GitHubJWKSCache,
    reviewed_installed_source: dict[str, str],
) -> AnalyticsDEVPromotionRouter:
    """Reuse the original service's already-verified OIDC/JWKS/replay context.

    Product source must be returned by load_analytics_broker_installed_source
    in the root-controlled service. This constructor alone does not prove it.
    """
    if (
        type(configuration) is not DevBrokerServiceConfiguration
        or type(canary_handler) is not InertDevPromotionHandler
        or type(verifier) is not GitHubOIDCVerifier
        or type(replay_guard) is not SQLiteReplayGuard
        or type(blob_signatures) is not CosignReleaseBlobVerifier
        or type(jwks_cache) is not GitHubJWKSCache
    ):
        raise TypeError(_ERROR)
    workflow = configuration.oidc_authorization_kwargs()["expected_workflow_sha"]
    identity = configuration.installation_contract().broker_composition_kwargs()
    transport = AnalyticsUnixExecutorTransport(
        expected_executor_uid=identity["expected_executor_uid"],
        expected_executor_gid=identity["expected_executor_gid"],
        expected_socket_group_gid=identity["expected_socket_group_gid"],
        reviewed_installed_source=reviewed_installed_source,
    )
    review = InertAnalyticsSignedReleaseReviewHandler(
        configuration=configuration, verifier=verifier,
        blob_signatures=blob_signatures, jwks_cache=jwks_cache,
    )
    analytics = AnalyticsPrivatePromotionBroker(
        expected_workflow_sha=workflow, verifier=verifier,
        signed_review_handler=review, replay_guard=replay_guard,
        analytics_transport=transport, jwks_cache=jwks_cache,
        reviewed_installed_source=reviewed_installed_source,
    )
    return AnalyticsDEVPromotionRouter(
        canary=canary_handler, analytics=analytics,
        reviewed_installed_source=reviewed_installed_source,
    )


def run_approved_analytics_broker_service(*, stop_controller: object) -> None:
    """Opt-in substitute for the existing C32T service on SAME loopback port.

    Only a separately approved root-owned systemd drop-in may replace the
    original service ExecStart with this module. Absence/mismatch of the
    protected Analytics broker product config is a HARD NO-GO here, NOT a
    fallback to the canary service. Original broker_service_bootstrap.py and
    existing Task014 source import closure remain byte-identical to main.
    """
    from . import broker_service_bootstrap as original
    from .broker_loopback_listener import BrokerStopController

    if type(stop_controller) is not BrokerStopController:
        raise AnalyticsBrokerSourceError(_ERROR)
    try:
        configuration = original._load_configuration()
        if type(configuration) is not DevBrokerServiceConfiguration:
            raise TypeError("invalid original C32H config")
        configuration = DevBrokerServiceConfiguration.from_dict(
            configuration.to_dict()
        )
        source = load_analytics_broker_installed_source(configuration)
        if type(source) is not dict:
            raise ValueError("Analytics service opt-in configuration absent")
        ids = configuration.installation_contract().broker_composition_kwargs()
        cache = original._GitHubJWKSCache()
        verifier = original._GitHubOIDCVerifier(
            expected_workflow_sha=configuration.expected_workflow_sha,
            jwks_cache=cache,
        )
        replay = original._SQLiteReplayGuard(
            original.PRODUCTION_REPLAY_DATABASE,
            expected_directory_uid=ids["expected_replay_directory_uid"],
            expected_directory_gid=ids["expected_replay_directory_gid"],
            expected_broker_uid=ids["expected_broker_uid"],
            expected_executor_uid=ids["expected_executor_uid"],
        )
        replay.validate()  # original durable store, NO implicit init/migration
        transport = original._UnixExecutorTransport(
            expected_executor_uid=ids["expected_executor_uid"],
            expected_executor_gid=ids["expected_executor_gid"],
            expected_socket_group_gid=ids["expected_socket_group_gid"],
        )
        blob = original._CosignReleaseBlobVerifier(
            **configuration.blob_verifier_kwargs()
        )
        canary = original._compose_handler(
            configuration=configuration, verifier=verifier,
            replay_guard=replay, transport=transport, blob_signatures=blob,
            jwks_cache=cache, private_registry_transport=True,
        )
        router = compose_approved_analytics_broker_router(
            configuration=configuration, canary_handler=canary,
            verifier=verifier, replay_guard=replay,
            blob_signatures=blob, jwks_cache=cache,
            reviewed_installed_source=source,
        )
        listener = original._DevBrokerLoopbackListener(router)
        if listener.serve_until_stopped(stop_controller) is not None:
            raise TypeError("unexpected private broker listener outcome")
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsBrokerSourceError(_ERROR) from None


__all__ = (
    "AnalyticsBrokerSourceError", "load_analytics_broker_installed_source",
    "compose_approved_analytics_broker_router",
    "run_approved_analytics_broker_service",
)
