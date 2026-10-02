"""deployment/tests/test_ci_tailnet_successor_authority.py - C33AP tests.

Purpose:
- prove the direct GitHub-OIDC Tailscale bootstrap is exact and fail closed;
- prove the frozen historical broker edge contract is not repurposed;
- prove the successor authority remains repository-only and outside the
  installed application source set.

Links:
- deployment/ci_tailnet_successor_authority.py defines the reviewed successor.
- .github/workflows/platform-promote.yml implements the successor transport.
- deployment/broker_edge_contract.py remains historical C32W authority.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from pathlib import Path
import unittest
from unittest.mock import patch

import yaml

from deployment.application_source_set import DevApplicationSourceSet
from deployment.ci_tailnet_successor_authority import (
    DevCiTailnetSuccessorAuthority,
)


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/platform-promote.yml"


class DevCiTailnetSuccessorAuthorityTests(unittest.TestCase):
    """Exercise the closed repository-side C33AP CI transport authority."""

    def test_authority_is_closed_pure_and_exact(self) -> None:
        """Require exact reviewed values and no host I/O during construction."""

        with patch("builtins.open", side_effect=AssertionError("host I/O")), patch(
            "subprocess.run",
            side_effect=AssertionError("host I/O"),
        ):
            authority = DevCiTailnetSuccessorAuthority()

        self.assertEqual(
            authority.bootstrap,
            "direct-github-oidc-tailscale-cli",
        )
        self.assertEqual(authority.tailscale_version, "1.102.4")
        self.assertEqual(
            authority.tailscale_tarball_url,
            "https://pkgs.tailscale.com/stable/tailscale_1.102.4_amd64.tgz",
        )
        self.assertEqual(
            authority.tailscale_tarball_sha256,
            "50748df1045e60b5b695f19f4c56b0da36c019948b440fb456b6584a50f0d8b9",
        )
        self.assertEqual(authority.connection_attempts, 1)
        self.assertEqual(authority.connection_timeout, "2m")
        self.assertEqual(
            authority.tailscale_up_args,
            (
                "--accept-routes=false",
                "--accept-dns=true",
                "--shields-up=true",
            ),
        )
        self.assertEqual(authority.ci_tag, "tag:omnilyzer-task014-ci")
        self.assertEqual(authority.oidc_token_transport, "private-mode-0600-file")
        self.assertEqual(authority.oidc_request_scheme, "https")
        self.assertEqual(
            authority.oidc_request_host_suffix,
            ".actions.githubusercontent.com",
        )
        self.assertFalse(authority.runner_cache_allowed)
        self.assertFalse(authority.redirect_allowed)
        self.assertFalse(authority.token_in_process_arguments_allowed)
        self.assertFalse(authority.automatic_connection_retry_allowed)
        self.assertFalse(authority.automatic_promotion_retry_allowed)
        self.assertEqual(
            authority.wif_issuer,
            "https://token.actions.githubusercontent.com",
        )
        self.assertEqual(
            authority.wif_subject,
            (
                "repo:MichaelTrueX@130741173/"
                "omnilyzer-platform@1350104356:environment:task014-dev"
            ),
        )
        self.assertEqual(authority.wif_scopes, ("auth_keys",))
        self.assertEqual(
            authority.wif_permitted_tags,
            ("tag:omnilyzer-task014-ci",),
        )
        self.assertFalse(hasattr(authority, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            authority.bootstrap = "forged"
        with self.assertRaises(TypeError):
            DevCiTailnetSuccessorAuthority(bootstrap="forged")

        for item in fields(authority):
            forged = object.__new__(DevCiTailnetSuccessorAuthority)
            for candidate in fields(authority):
                value = getattr(authority, candidate.name)
                if candidate.name == item.name:
                    if type(value) is bool:
                        value = not value
                    elif type(value) is int:
                        value += 1
                    elif type(value) is str:
                        value += "-forged"
                    elif type(value) is tuple:
                        value = value + ("forged",)
                object.__setattr__(forged, candidate.name, value)
            with self.subTest(field=item.name), self.assertRaises(ValueError):
                forged.__post_init__()

    def test_workflow_implements_exact_successor_transport(self) -> None:
        """Bind the direct bootstrap to exact workflow bytes and arguments."""

        authority = DevCiTailnetSuccessorAuthority()
        raw = WORKFLOW.read_text(encoding="utf-8")
        workflow = yaml.load(raw, Loader=yaml.BaseLoader)
        dev = workflow["jobs"]["deploy_dev"]
        join = next(
            step
            for step in dev["steps"]
            if step["name"]
            == "Join private Task 014 tailnet with direct federated identity"
        )
        cleanup = next(
            step
            for step in dev["steps"]
            if step["name"] == "Leave private Task 014 tailnet"
        )

        self.assertNotIn("uses", join)
        self.assertEqual(join["env"], {
            "TS_OAUTH_CLIENT_ID": "${{ secrets.TS_OAUTH_CLIENT_ID }}",
            "TS_AUDIENCE": "${{ secrets.TS_AUDIENCE }}",
        })
        script = join["run"]
        self.assertIn(f'TS_VERSION="{authority.tailscale_version}"', script)
        self.assertIn(
            f'TS_SHA256="{authority.tailscale_tarball_sha256}"',
            script,
        )
        self.assertIn(
            '"https://pkgs.tailscale.com/stable/"',
            script,
        )
        self.assertEqual(script.count("--accept-routes=false"), 1)
        self.assertNotIn("--accept-routes ", script)
        for argument in (
            *authority.tailscale_up_args[1:],
            "--advertise-tags=" + authority.ci_tag,
            "--timeout=" + authority.connection_timeout,
        ):
            with self.subTest(argument=argument):
                self.assertEqual(script.count(argument), 1)

        self.assertEqual(script.count('sudo -n "$TS_DIR/tailscale" up'), 1)
        self.assertIn('chown "$SUDO_UID:$SUDO_GID" "$1"', script)
        self.assertIn('chmod 0600 "$1"', script)
        self.assertIn('--id-token="file:$TS_ROOT/id-token"', script)
        self.assertIn("token_path.chmod(0o600)", script)
        self.assertIn("request.ProxyHandler({})", script)
        self.assertIn("redirect rejected", script)
        self.assertIn(
            'request_host.endswith(".actions.githubusercontent.com")',
            script,
        )
        self.assertIn('parsed.scheme != "https"', script)
        self.assertIn('request_port not in (None, 443)', script)
        self.assertIn(
            'any(key == "audience" for key, _value in query)',
            script,
        )
        self.assertNotIn("tailscale/github-action", raw)
        self.assertNotIn("retry:", raw)
        self.assertNotIn("authkey", script.lower())
        self.assertNotIn("oauth-secret", script.lower())
        self.assertNotIn("sudo -E", script)
        self.assertNotIn('ID_TOKEN="$(cat', script)
        self.assertIn('read -r daemon_pid <"$TS_ROOT/tailscaled.pid"', cleanup["run"])
        self.assertIn('readlink -f "/proc/$daemon_pid/exe"', cleanup["run"])
        self.assertIn('sudo -n kill -TERM "$daemon_pid"', cleanup["run"])
        self.assertNotIn("pkill", cleanup["run"])
        self.assertEqual(cleanup["if"], "${{ always() }}")

    def test_successor_is_repository_only_and_historical_contract_stays_frozen(self) -> None:
        """Keep C33AP transport authority outside the installed application."""

        selected = {
            item.repository_path
            for item in DevApplicationSourceSet().files
        }
        self.assertNotIn(
            "deployment/ci_tailnet_successor_authority.py",
            selected,
        )
        self.assertNotIn(
            "deployment/broker_edge_contract.py",
            selected,
        )

        historical = (
            ROOT / "deployment/broker_edge_contract.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'github_action_sha: str = field(',
            historical,
        )
        self.assertIn(
            'default="d1b6cd204f8dceda5b3eaad7f1f767be390056cd"',
            historical,
        )


if __name__ == "__main__":
    unittest.main()
