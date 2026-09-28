"""Pure C32Z authority for the future DEV host HTTPS deployment edge.

This pins repository bytes and future observations, not an installed Nginx
include location or a claim that TLS, DNS, or edge behavior has been qualified.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields

from .broker_https_ingress import (
    BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT, PROMOTION_PATH,
    PUBLIC_HOST, PUBLIC_ORIGIN,
)

__all__ = ("DevBrokerEdgeContract", "DevBrokerEdgeQualificationPlan")

_ERROR = "DEV broker HTTPS edge contract is invalid"
_SOURCE = "deployment/ingress/dev-broker-https.nginx.conf"
_SHA256 = "6981832d3efe9979fbbc58188a37f933bb059876228310fd3783acb6117aff86"
_CERTIFICATE = "/etc/letsencrypt/live/" + PUBLIC_HOST + "/fullchain.pem"
_PRIVATE_KEY = "/etc/letsencrypt/live/" + PUBLIC_HOST + "/privkey.pem"
_CHECKS = (
    "host-nginx-include-layout-proven",
    "reviewed-nginx-version-at-least-1.23.0-and-combined-header-capability-proven",
    "pinned-config-installed-and-loaded",
    "nginx-configuration-test-passed",
    "dns-resolves-to-intended-dev-ingress-host",
    "certificate-hostname-current-validity-and-public-trust-proven",
    "private-key-not-group-or-world-readable",
    "public-origin-https-negotiation-proven",
    "plaintext-deployment-endpoint-unavailable-without-redirect",
    "exact-valid-shaped-request-reaches-loopback-broker",
    "alternate-path-and-method-rejected",
    "authorization-zot-and-forgejo-duplicate-headers-each-rejected-at-edge",
    "oversized-chunked-and-cookie-requests-rejected",
    "no-redirect-cors-cookie-or-location-leakage",
    "deployment-access-logging-secret-free",
)


@dataclass(frozen=True, slots=True)
class DevBrokerEdgeQualificationPlan:
    """Required later live observations; no successful evidence is asserted."""

    status: str = field(init=False, default="pending-live-qualification")
    checks: tuple[str, ...] = field(init=False, default=_CHECKS)

    def __post_init__(self) -> None:
        if (type(self.status) is not str or self.status != "pending-live-qualification"
                or type(self.checks) is not tuple or self.checks != _CHECKS
                or any(type(check) is not str for check in self.checks)):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class DevBrokerEdgeContract:
    """One no-input exact edge projection, with no invented host include path."""

    public_origin: str = field(init=False, default=PUBLIC_ORIGIN)
    host: str = field(init=False, default=PUBLIC_HOST)
    https_port: int = field(init=False, default=443)
    endpoint: str = field(init=False, default=PROMOTION_PATH)
    method: str = field(init=False, default="POST")
    upstream_host: str = field(init=False, default=BROKER_LOOPBACK_HOST)
    upstream_port: int = field(init=False, default=BROKER_LOOPBACK_PORT)
    certificate_path: str = field(init=False, default=_CERTIFICATE)
    private_key_path: str = field(init=False, default=_PRIVATE_KEY)
    nginx_source_path: str = field(init=False, default=_SOURCE)
    nginx_source_sha256: str = field(init=False, default=_SHA256)
    nginx_include_destination: None = field(init=False, default=None)

    def __post_init__(self) -> None:
        for item in fields(self):
            expected = item.default
            actual = getattr(self, item.name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError(_ERROR)
        if (self.public_origin != "https://" + self.host
                or self.certificate_path != "/etc/letsencrypt/live/" + self.host + "/fullchain.pem"
                or self.private_key_path != "/etc/letsencrypt/live/" + self.host + "/privkey.pem"):
            raise ValueError(_ERROR)

    def qualification_plan(self) -> DevBrokerEdgeQualificationPlan:
        self.__post_init__()
        return DevBrokerEdgeQualificationPlan()
