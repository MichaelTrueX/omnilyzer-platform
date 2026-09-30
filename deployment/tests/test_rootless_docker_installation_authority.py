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
    PackagePayloadAuthority,
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

    def test_two_new_ubuntu_dependencies_are_exact(self) -> None:
        authority = INSTALLATION_AUTHORITY
        self.assertEqual(
            authority.supplemental_package_specs(),
            (
                "libsubid4=1:4.13+dfsg1-4ubuntu3.2",
                "libslirp0=4.7.0-1ubuntu3.1",
            ),
        )
        self.assertEqual(
            tuple(item.deb_sha256 for item in authority.supplemental_packages),
            (
                "ba97fd28c53560a8d2a2261e8f75a7ab4112535b12f9fe1d50970c30051da0da",
                "4efa2d1c509de4d10fe965e86a3d864bf542996caf476d9111fd882c73857164",
            ),
        )
        self.assertTrue(all(
            item.origin == "Ubuntu signed noble-updates/main amd64"
            and item.required_executables == ()
            for item in authority.supplemental_packages
        ))
        self.assertEqual(len(authority.all_package_specs()), 9)

    def test_exact_nine_package_payloads_are_pinned(self) -> None:
        authority = INSTALLATION_AUTHORITY
        expected = (
            (
                "libsubid4",
                "libsubid4_4.13+dfsg1-4ubuntu3.2_amd64.deb",
                23442,
                "ba97fd28c53560a8d2a2261e8f75a7ab4112535b12f9fe1d50970c30051da0da",
                "https://archive.ubuntu.com/ubuntu/pool/main/s/shadow/"
                "libsubid4_4.13%2bdfsg1-4ubuntu3.2_amd64.deb",
            ),
            (
                "uidmap",
                "uidmap_4.13+dfsg1-4ubuntu3.2_amd64.deb",
                26006,
                "a80cb7f72dd18c73cbb0b07b7fbe855504f26bfafae072a9b3d125c89d499b9e",
                "https://archive.ubuntu.com/ubuntu/pool/main/s/shadow/"
                "uidmap_4.13%2bdfsg1-4ubuntu3.2_amd64.deb",
            ),
            (
                "libslirp0",
                "libslirp0_4.7.0-1ubuntu3.1_amd64.deb",
                63830,
                "4efa2d1c509de4d10fe965e86a3d864bf542996caf476d9111fd882c73857164",
                "https://archive.ubuntu.com/ubuntu/pool/main/libs/libslirp/"
                "libslirp0_4.7.0-1ubuntu3.1_amd64.deb",
            ),
            (
                "slirp4netns",
                "slirp4netns_1.2.1-1build2_amd64.deb",
                34894,
                "3fc72a72a376a3ad3b439434bc87d89d245f9d54a1d540e8a06b74d4e2385e0a",
                "https://archive.ubuntu.com/ubuntu/pool/universe/s/slirp4netns/"
                "slirp4netns_1.2.1-1build2_amd64.deb",
            ),
            (
                "containerd.io",
                "containerd.io_2.3.6-1~ubuntu.24.04~noble_amd64.deb",
                23155464,
                "2eb8c6e244fe6886f2fa2eee9ec418c4b9bb44eb44fca748504f57c23341aed2",
                "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
                "containerd.io_2.3.6-1~ubuntu.24.04~noble_amd64.deb",
            ),
            (
                "docker-ce-cli",
                "docker-ce-cli_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
                17550136,
                "e26e6770fab41256cf16c09c24a0b75e70bf72465ef2688f85d1f7d3fdb9b99c",
                "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
                "docker-ce-cli_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
            ),
            (
                "docker-ce-rootless-extras",
                "docker-ce-rootless-extras_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
                10177712,
                "02897501837b7ff4fec8248decdd5828b7d40d7f591021a91f29673e02d0f982",
                "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
                "docker-ce-rootless-extras_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
            ),
            (
                "docker-compose-plugin",
                "docker-compose-plugin_5.5.1-1~ubuntu.24.04~noble_amd64.deb",
                8012228,
                "82ff966149ca2c62e1a4e1fdebdf65fda8c3a8bea80b32deda6903b40afc2347",
                "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
                "docker-compose-plugin_5.5.1-1~ubuntu.24.04~noble_amd64.deb",
            ),
            (
                "docker-ce",
                "docker-ce_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
                24309816,
                "607bcf63bf85c5a245b73229c2797fda5c5a430343c02ebf80f32f6db7513eb9",
                "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
                "docker-ce_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
            ),
        )
        self.assertEqual(
            tuple(
                (item.package, item.filename, item.size, item.sha256, item.url)
                for item in authority.payloads
            ),
            expected,
        )
        self.assertEqual(authority.payload_filenames(), tuple(item[1] for item in expected))
        self.assertEqual(len(set(authority.payload_filenames())), 9)
        self.assertEqual(sum(item.size for item in authority.payloads), 83_353_528)
        self.assertNotIn("docker-buildx-plugin", {item.package for item in authority.payloads})

    def test_package_payload_metadata_rejects_url_and_filename_substitution(self) -> None:
        good = INSTALLATION_AUTHORITY.payloads[0]
        with self.assertRaises(ValueError):
            PackagePayloadAuthority(
                good.package, "../" + good.filename, good.size, good.sha256, good.url,
            )
        with self.assertRaises(ValueError):
            PackagePayloadAuthority(
                good.package, good.filename, good.size, good.sha256,
                "http://archive.ubuntu.com/ubuntu/unsafe.deb",
            )
        with self.assertRaises(ValueError):
            PackagePayloadAuthority(
                good.package, good.filename, good.size, good.sha256,
                "https://archive.ubuntu.com.evil.example/ubuntu/unsafe.deb",
            )
        with self.assertRaises(ValueError):
            PackagePayloadAuthority(
                good.package, good.filename, good.size, good.sha256,
                "https://user@archive.ubuntu.com/ubuntu/unsafe.deb",
            )

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
            "urllib.request",
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
