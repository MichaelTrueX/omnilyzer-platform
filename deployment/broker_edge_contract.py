"""Pure C32ZC authority for a future private Tailscale Serve DEV ingress.

The asset and pending observations are repository authority only. Constructing
this contract performs no host, tailnet, DNS, or process operation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields

from .broker_integration import MAX_PROMOTION_REQUEST_BYTES
from .broker_https_ingress import (
    BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT, PROMOTION_PATH,
    PUBLIC_HOST, PUBLIC_ORIGIN,
)

__all__ = ("DevBrokerEdgeContract", "DevBrokerEdgeQualificationPlan")

_ERROR = "DEV broker private edge contract is invalid"
_SOURCE = "deployment/ingress/dev-broker-tailscale-origin.nginx.conf"
_SHA256 = "3508d56ac408c966df0cea24ec8f33e85524af429c7f7009efa5d0246dc26518"
_TAILSCALE_HOST = "omnilyzerdev.tail52e570.ts.net"
_CHECKS = (
    "tailscale-package-version-1.102.4-proven",
    "tailscaled-enabled-and-active",
    "host-online-in-intended-tailnet",
    "host-magicdns-fqdn-exact",
    "no-funnel-configuration",
    "serve-configuration-exact-hostname-https-and-loopback-target",
    "serve-private-tailnet-only",
    "tailscale-https-certificate-valid-for-exact-hostname",
    "github-workload-identity-federation-configured",
    "wif-issuer-exact-github-actions",
    "wif-subject-exact-task014-dev-environment",
    "wif-scope-auth-keys-only",
    "wif-permitted-tag-task014-ci-only",
    "wif-supported-custom-claims-exact-github-workload-no-workflow-sha-binding",
    "ephemeral-ci-node-tag-exact",
    "tailnet-policy-ci-tag-only-omnilyzerdev-tcp-443",
    "tailnet-policy-no-ssh-unrelated-ports-or-subnet-route-authority",
    "no-public-inbound-or-router-forwarding-for-80-443-3031-3032",
    "no-non-loopback-host-listener-on-3031-or-3032",
    "host-nginx-include-layout-proven",
    "pinned-local-nginx-config-installed-and-loaded-exactly",
    "nginx-configuration-test-passed",
    "local-nginx-exact-tailscale-host-only",
    "exact-valid-shaped-private-request-reaches-broker",
    "alternate-path-method-and-query-rejected",
    "local-nginx-rewrites-logical-broker-host-exactly",
    "serve-added-and-arbitrary-headers-cannot-reach-broker",
    "nginx-duplicate-header-combination-proven-by-live-probes",
    "duplicate-authorization-zot-forgejo-rejected-locally",
    "oversized-chunked-content-encoded-and-cookie-requests-rejected",
    "no-redirect-cors-cookie-or-location-leakage",
    "deployment-access-logging-secret-free",
    "loaded-upstream-connect-send-read-timeouts-3-30-900",
    "workflow-exact-tailscale-https-endpoint",
    "workflow-no-automatic-promotion-retry",
    "broker-workflow-sha-rotated-to-final-merge-before-activation",
    "frozen-c32w-application-authority-unchanged",
    "c32y-static-resource-authority-otherwise-unchanged",
)


@dataclass(frozen=True, slots=True)
class DevBrokerEdgeQualificationPlan:
    """Required future live observations; none is asserted as complete."""

    status: str = field(init=False, default="pending-live-qualification")
    checks: tuple[str, ...] = field(init=False, default=_CHECKS)

    def __post_init__(self) -> None:
        if (type(self.status) is not str or self.status != "pending-live-qualification"
                or type(self.checks) is not tuple or self.checks != _CHECKS
                or any(type(check) is not str for check in self.checks)):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class DevBrokerEdgeContract:
    """One closed, no-input private transport and logical-broker projection."""

    transport: str = field(init=False, default="tailscale-private-serve")
    tailscale_https_host: str = field(init=False, default=_TAILSCALE_HOST)
    tailscale_https_port: int = field(init=False, default=443)
    transport_endpoint: str = field(
        init=False, default="https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote")
    serve_origin_target: str = field(init=False, default="http://127.0.0.1:3032")
    nginx_listen_host: str = field(init=False, default="127.0.0.1")
    nginx_listen_port: int = field(init=False, default=3032)
    logical_broker_host: str = field(init=False, default=PUBLIC_HOST)
    logical_authorization_origin: str = field(init=False, default=PUBLIC_ORIGIN)
    endpoint: str = field(init=False, default=PROMOTION_PATH)
    method: str = field(init=False, default="POST")
    promotion_request_max_bytes: int = field(init=False, default=4096)
    automatic_retry_allowed: bool = field(init=False, default=False)
    upstream_host: str = field(init=False, default=BROKER_LOOPBACK_HOST)
    upstream_port: int = field(init=False, default=BROKER_LOOPBACK_PORT)
    upstream_connect_timeout_seconds: int = field(init=False, default=3)
    upstream_send_timeout_seconds: int = field(init=False, default=30)
    upstream_response_timeout_seconds: int = field(init=False, default=900)
    expected_tailscale_version: str = field(init=False, default="1.102.4")
    github_action_sha: str = field(
        init=False, default="d1b6cd204f8dceda5b3eaad7f1f767be390056cd")
    tailscale_static_tarball_sha256: str = field(
        init=False, default="50748df1045e60b5b695f19f4c56b0da36c019948b440fb456b6584a50f0d8b9")
    github_action_connection_timeout: str = field(init=False, default="2m")
    github_action_connection_attempts: int = field(init=False, default=1)
    github_action_args: str = field(
        init=False, default="--accept-routes=false --accept-dns=true --shields-up=true")
    ci_tag: str = field(init=False, default="tag:omnilyzer-task014-ci")
    wif_issuer: str = field(init=False, default="https://token.actions.githubusercontent.com")
    wif_subject: str = field(
        init=False, default="repo:MichaelTrueX@130741173/omnilyzer-platform@1350104356:environment:task014-dev")
    wif_scopes: tuple[str, ...] = field(init=False, default=("auth_keys",))
    wif_permitted_tags: tuple[str, ...] = field(
        init=False, default=("tag:omnilyzer-task014-ci",))
    wif_custom_claims: tuple[tuple[str, str], ...] = field(init=False, default=(
        ("repository", "MichaelTrueX/omnilyzer-platform"),
        ("repository_id", "1350104356"),
        ("workflow_ref", "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-promote.yml@refs/heads/main"),
        ("ref", "refs/heads/main"),
        ("environment", "task014-dev"),
        ("event_name", "workflow_dispatch"),
        ("runner_environment", "github-hosted"),
    ))
    nginx_source_path: str = field(init=False, default=_SOURCE)
    nginx_source_sha256: str = field(init=False, default=_SHA256)
    nginx_include_destination: None = field(init=False, default=None)

    def __post_init__(self) -> None:
        for item in fields(self):
            expected = item.default
            actual = getattr(self, item.name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError(_ERROR)
        if (self.transport_endpoint
                != f"https://{self.tailscale_https_host}{self.endpoint}"
                or self.serve_origin_target
                != f"http://{self.nginx_listen_host}:{self.nginx_listen_port}"
                or self.logical_authorization_origin != "https://" + self.logical_broker_host
                or self.promotion_request_max_bytes != MAX_PROMOTION_REQUEST_BYTES):
            raise ValueError(_ERROR)

    def qualification_plan(self) -> DevBrokerEdgeQualificationPlan:
        self.__post_init__()
        return DevBrokerEdgeQualificationPlan()
