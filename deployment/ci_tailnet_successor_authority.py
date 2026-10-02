"""deployment/ci_tailnet_successor_authority.py - C33AP CI tailnet authority.

Purpose:
- define the repository-side successor transport used by the DEV promotion
  workflow after the frozen C32W Tailscale GitHub Action contract;
- preserve the reviewed Tailscale version, package digest, WIF identity, tag,
  no-route-acceptance posture, and no-retry semantics;
- keep this CI-only authority outside the installed 41-file application set.

Links:
- .github/workflows/platform-promote.yml implements this authority.
- deployment/state_store_successor_live_authority.py defines the separate
  post-merge broker workflow-SHA rotation required before the next DEV dispatch.
- deployment/broker_edge_contract.py remains frozen historical C32W evidence.
- deployment/tests/test_ci_tailnet_successor_authority.py proves this authority
  is exact, closed, pure, and reflected by the workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields


__all__ = ("DevCiTailnetSuccessorAuthority",)

_ERROR = "DEV CI tailnet successor authority is invalid"


@dataclass(frozen=True, slots=True)
class DevCiTailnetSuccessorAuthority:
    """Closed C33AP authority for direct GitHub-OIDC Tailscale bootstrap."""

    workflow_path: str = field(
        init=False,
        default=".github/workflows/platform-promote.yml",
    )
    environment: str = field(init=False, default="task014-dev")
    bootstrap: str = field(
        init=False,
        default="direct-github-oidc-tailscale-cli",
    )
    tailscale_version: str = field(init=False, default="1.102.4")
    tailscale_tarball_url: str = field(
        init=False,
        default="https://pkgs.tailscale.com/stable/tailscale_1.102.4_amd64.tgz",
    )
    tailscale_tarball_sha256: str = field(
        init=False,
        default="50748df1045e60b5b695f19f4c56b0da36c019948b440fb456b6584a50f0d8b9",
    )
    connection_attempts: int = field(init=False, default=1)
    connection_timeout: str = field(init=False, default="2m")
    tailscale_up_args: tuple[str, ...] = field(
        init=False,
        default=(
            "--accept-routes=false",
            "--accept-dns=true",
            "--shields-up=true",
        ),
    )
    ci_tag: str = field(init=False, default="tag:omnilyzer-task014-ci")
    oidc_token_transport: str = field(
        init=False,
        default="private-mode-0600-file",
    )
    oidc_request_scheme: str = field(init=False, default="https")
    oidc_request_host_suffix: str = field(
        init=False,
        default=".actions.githubusercontent.com",
    )
    runner_cache_allowed: bool = field(init=False, default=False)
    redirect_allowed: bool = field(init=False, default=False)
    token_in_process_arguments_allowed: bool = field(init=False, default=False)
    automatic_connection_retry_allowed: bool = field(init=False, default=False)
    automatic_promotion_retry_allowed: bool = field(init=False, default=False)
    wif_issuer: str = field(
        init=False,
        default="https://token.actions.githubusercontent.com",
    )
    wif_subject: str = field(
        init=False,
        default=(
            "repo:MichaelTrueX@130741173/"
            "omnilyzer-platform@1350104356:environment:task014-dev"
        ),
    )
    wif_scopes: tuple[str, ...] = field(
        init=False,
        default=("auth_keys",),
    )
    wif_permitted_tags: tuple[str, ...] = field(
        init=False,
        default=("tag:omnilyzer-task014-ci",),
    )
    wif_custom_claims: tuple[tuple[str, str], ...] = field(
        init=False,
        default=(
            ("repository", "MichaelTrueX/omnilyzer-platform"),
            ("repository_id", "1350104356"),
            (
                "workflow_ref",
                "MichaelTrueX/omnilyzer-platform/"
                ".github/workflows/platform-promote.yml@refs/heads/main",
            ),
            ("ref", "refs/heads/main"),
            ("environment", "task014-dev"),
            ("event_name", "workflow_dispatch"),
            ("runner_environment", "github-hosted"),
        ),
    )

    def __post_init__(self) -> None:
        """Reject any forged value outside the reviewed no-input authority."""

        for item in fields(self):
            expected = item.default
            actual = getattr(self, item.name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError(_ERROR)

        if (
            self.connection_attempts != 1
            or self.connection_timeout != "2m"
            or self.tailscale_up_args
            != (
                "--accept-routes=false",
                "--accept-dns=true",
                "--shields-up=true",
            )
            or self.ci_tag not in self.wif_permitted_tags
            or self.oidc_request_scheme != "https"
            or self.oidc_request_host_suffix != ".actions.githubusercontent.com"
            or self.runner_cache_allowed
            or self.redirect_allowed
            or self.token_in_process_arguments_allowed
            or self.automatic_connection_retry_allowed
            or self.automatic_promotion_retry_allowed
        ):
            raise ValueError(_ERROR)
