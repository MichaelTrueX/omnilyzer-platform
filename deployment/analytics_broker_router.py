"""File: deployment/analytics_broker_router.py

Purpose: Reuse original Task014 HTTPS/loopback broker ingress for ONE additional
         signed Analytics 0.15.0 DEV first-install request without modifying
         the original canary broker, HTTP parser, listener or Nginx endpoint.
Related: deployment/broker_https_ingress.py (original closed three-JWT ingress),
         deployment/broker_loopback_listener.py (existing port 3031),
         deployment/broker_integration.py (unchanged canary handler),
         deployment/analytics_promotion_broker.py (independent signature+FD),
         deployment/analytics_execution.py (exact Analytics schema 2),
         deployment/tests/test_analytics_broker_router.py.

Sections: exact install-authority capture, strict canonical product routing,
          independent signed Analytics broker adapter and closed canary fallback.

SECURITY: The router only chooses among two already-verified, constructor-bound
operations. It never supplies OIDC/Sigstore/Cosign authority, installation
permission, registry tokens, replay grant or product identity on its own.
The Analytics broker MUST be built behind a separate root-owned installed
source/identity proof; do not enable this router in existing canary runtime
until that privileged source is approved and verified. Import is inert.
"""
from __future__ import annotations

from .analytics_execution import (
    AnalyticsRequestError, parse_analytics_request,
)
from .analytics_promotion_broker import AnalyticsPrivatePromotionBroker
from .broker import BrokerRejectedError, REJECTED_MESSAGE, _bound_operation
from .broker_integration import InertDevPromotionHandler, MAX_PROMOTION_REQUEST_BYTES
from .jwks import OIDCVerificationError, parse_bounded_json
from .policy import canonical_bytes

_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_ANALYTICS_SCHEMA = 2
_ANALYTICS_PRODUCT = "analytics"


class AnalyticsDEVPromotionRouter:
    """Exact two-path Task014 handler for original broker HTTPS ingress."""

    __slots__ = ("_canary", "_analytics", "_reviewed_source")

    def __init__(
        self, *, canary: InertDevPromotionHandler,
        analytics: AnalyticsPrivatePromotionBroker,
        reviewed_installed_source: dict[str, str],
    ) -> None:
        """Require original canary handler and the explicit signed Analytics one.

        The reviewed source MUST originate from a separately root-verified
        installed config; a public mapping never becomes release authority.
        """
        if (type(canary) is not InertDevPromotionHandler
                or type(analytics) is not AnalyticsPrivatePromotionBroker):
            raise TypeError("Analytics Task014 router configuration is invalid")
        try:
            from .analytics_unix_boundary import _root_reviewed_source
            source = _root_reviewed_source(reviewed_installed_source)
            if object.__getattribute__(analytics, "_reviewed_source") != source:
                raise ValueError("Analytics source mismatch")
            object.__setattr__(self, "_canary", _bound_operation(canary, "handle"))
            object.__setattr__(
                self, "_analytics",
                _bound_operation(analytics, "authorize_and_forward"),
            )
            object.__setattr__(self, "_reviewed_source", source)
        except _CONTROL:
            raise
        except Exception:
            raise TypeError("Analytics Task014 router configuration is invalid") from None

    def __setattr__(self, name: str, value: object) -> None:
        """Do not permit runtime operation or installed-source replacement."""
        raise AttributeError("Analytics Task014 router is immutable")

    def __delattr__(self, name: str) -> None:
        """Do not permit deletion of constructor-authorized routing targets."""
        raise AttributeError("Analytics Task014 router is immutable")

    def handle(
        self, *, compact_token: str, zot_token: str, forgejo_token: str,
        promotion_request: bytes, received_at: int,
    ) -> bytes:
        """Dispatch one canonical bounded request, then original OIDC/security.

        All token/framing checks belong to the ORIGINAL ingress. This layer
        makes a distinct, closed product decision BEFORE any signed-repository
        read or replay mutation. No malformed schema-2 request falls through
        to the canary route, and no schema-1 request enters Analytics.
        """
        if (type(promotion_request) is not bytes
                or not 0 < len(promotion_request) <= MAX_PROMOTION_REQUEST_BYTES):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        try:
            data = parse_bounded_json(
                promotion_request, maximum_bytes=MAX_PROMOTION_REQUEST_BYTES,
                maximum_root_members=40, maximum_depth=4,
                maximum_nodes=100, maximum_array=4, maximum_string=2048,
            )
            if canonical_bytes(data) != promotion_request:
                raise ValueError("noncanonical promotion")
            schema = data.get("schema_version")
            product = data.get("product_id")
            if schema == _ANALYTICS_SCHEMA or product == _ANALYTICS_PRODUCT:
                if (type(schema) is not int or schema != _ANALYTICS_SCHEMA
                        or type(product) is not str or product != _ANALYTICS_PRODUCT):
                    raise ValueError("inconsistent product schema")
                parse_analytics_request(
                    promotion_request,
                    **dict(object.__getattribute__(self, "_reviewed_source")),
                )
                analytics_selected = True
            else:
                analytics_selected = False
            # The original promotion schema does not have product_id.
            # Any unrelated product_id or schema 2 is a DENY, not canary.
            if not analytics_selected and (
                product is not None or type(schema) is not int or schema != 1
            ):
                raise ValueError("unrecognized Task014 product")
        except (OIDCVerificationError, AnalyticsRequestError, ValueError, TypeError):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        # The routing-validation exception boundary ends HERE. Original
        # broker REJECTED versus UNAVAILABLE must pass through unchanged so
        # the existing ingress emits 403 versus 503 correctly; never turn a
        # signer outage into a claim that the user supplied a bad identity.
        if analytics_selected:
            return object.__getattribute__(self, "_analytics")(
                compact_token=compact_token, zot_token=zot_token,
                forgejo_token=forgejo_token,
                canonical_request=promotion_request, received_at=received_at,
            )
        return object.__getattribute__(self, "_canary")(
            compact_token=compact_token, zot_token=zot_token,
            forgejo_token=forgejo_token,
            promotion_request=promotion_request, received_at=received_at,
        )


__all__ = ("AnalyticsDEVPromotionRouter",)
