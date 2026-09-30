"""deployment/tests/test_rootless_docker_installation_authority.py.

Purpose:
- prove the C32ZP installation plan is immutable, closed, and aligned with
  C32ZF;
- ensure the corrected subordinate-ID range and no-Buildx boundary remain
  explicit before privileged installation exists.
"""

from dataclasses import FrozenInstanceError
from pathlib import Path
import inspect
import unittest

from deployment.rootless_docker_authority import AUTHORITY
from deployment.rootless_docker_installation_authority import (
    INSTALLATION_AUTHORITY,
    RootlessDockerInstallationAuthority,
)


ROOT = Path(__file__).resolve().parents[2]


class RootlessDockerInstallationAuthorityTests(unittest.TestCase):
    """Repository-only checks for the closed rootless installation plan."""

    def test_exact_signed_apt_authority(self) -> None:
        authority = INSTALLATION_AUTHORITY
        self.assertEqual(
            authority.docker_key_url,
            "https://download.docker.com/linux/ubuntu/gpg",
        )
        self.assertEqual(
            authority.docker_key_sha256,
            "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570",
        )
        self.assertEqual(
            authority.docker_primary_fingerprint,
            "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
        )
        self.assertEqual(
            authority.docker_signing_fingerprint,
            "D3306A018370199E527AE7997EA0A9C3F273FCD8",
        )
        self.assertEqual(
            authority.docker_key_path,
            "/etc/apt/keyrings/omnilyzer-task014-docker.asc",
        )
        self.assertEqual(
            authority.docker_source_path,
            "/etc/apt/sources.list.d/omnilyzer-task014-docker.sources",
        )
        self.assertEqual(
            authority.docker_source_bytes,
            (
                b"Types: deb\n"
                b"URIs: https://download.docker.com/linux/ubuntu\n"
                b"Suites: noble\n"
                b"Components: stable\n"
                b"Architectures: amd64\n"
                b"Signed-By: /etc/apt/keyrings/omnilyzer-task014-docker.asc\n"
            ),
        )

    def test_exact_seven_package_specs_match_c32zf(self) -> None:
        authority = INSTALLATION_AUTHORITY
        self.assertEqual(authority.packages, AUTHORITY.packages)
        self.assertEqual(len(authority.packages), 7)
        self.assertEqual(
            authority.package_specs(),
            tuple(
                f"{item.name}={item.apt_version}"
                for item in AUTHORITY.packages
            ),
        )
        names = {item.name for item in authority.packages}
        self.assertNotIn("docker-buildx-plugin", names)
        self.assertIn("docker-buildx-plugin", authority.conflicting_packages)
        expected_origins = {item.name: item.origin for item in AUTHORITY.packages}
        for item in authority.packages:
            with self.subTest(item=item.name):
                self.assertEqual(len(item.deb_sha256), 64)
                self.assertEqual(item.deb_sha256, item.deb_sha256.lower())
                self.assertEqual(item.origin, expected_origins[item.name])

    def test_start_suppression_and_staging_are_fixed(self) -> None:
        authority = INSTALLATION_AUTHORITY
        self.assertEqual(
            authority.rootful_units,
            ("docker.service", "docker.socket", "containerd.service"),
        )
        self.assertEqual(authority.policy_rc_d_path, "/usr/sbin/policy-rc.d")
        self.assertEqual(
            authority.policy_rc_d_bytes,
            b"#!/usr/bin/python3\nraise SystemExit(101)\n",
        )
        self.assertNotIn(b"/bin/sh", authority.policy_rc_d_bytes)
        self.assertEqual(
            authority.staging_directory,
            "/var/lib/omnilyzer/deployment/.rootless-docker-install",
        )

    def test_corrected_subordinate_range_is_the_only_install_target(self) -> None:
        self.assertEqual(
            (AUTHORITY.subuid_start, AUTHORITY.subgid_start),
            (493216, 493216),
        )
        self.assertEqual(AUTHORITY.subordinate_count, 65536)
        self.assertEqual(
            (AUTHORITY.canary_host_uid, AUTHORITY.canary_host_gid),
            (503216, 503216),
        )
        self.assertEqual(
            (AUTHORITY.nginx_host_uid, AUTHORITY.nginx_host_gid),
            (558747, 558747),
        )
        self.assertNotEqual(AUTHORITY.subuid_start, 427680)
        self.assertNotEqual(AUTHORITY.subgid_start, 427680)

    def test_authority_has_no_caller_inputs_or_mutation_surface(self) -> None:
        signature = inspect.signature(RootlessDockerInstallationAuthority)
        self.assertEqual(tuple(signature.parameters), ())
        authority = RootlessDockerInstallationAuthority()
        with self.assertRaises(FrozenInstanceError):
            authority.staging_directory = "/tmp"
        source = (
            ROOT / "deployment/rootless_docker_installation_authority.py"
        ).read_text()
        for forbidden in (
            "subprocess",
            "urllib",
            "requests",
            "socket.",
            "os.environ",
            "os.getenv",
            "apt-get",
            "systemctl ",
            "docker ",
            "__main__",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
