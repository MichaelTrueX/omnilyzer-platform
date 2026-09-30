"""deployment/rootless_docker_installation_authority.py - C32ZP install plan.

Purpose:
- bind the reviewed C32ZF rootless Docker package authority to one closed,
  temporary signed-APT installation plan;
- keep package retrieval, rootful-service suppression, subordinate-ID
  allocation, and asset installation deterministic before any privileged
  runtime is implemented.

Linked files:
- deployment/rootless_docker_authority.py
- deployment/systemd/rootless/*
- deployment/README.md
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .rootless_docker_authority import AUTHORITY, PackageAuthority


__all__ = (
    "PackagePayloadAuthority",
    "RootlessDockerInstallationAuthority",
    "INSTALLATION_AUTHORITY",
)

_DOCKER_KEY_URL = "https://download.docker.com/linux/ubuntu/gpg"
_DOCKER_KEY_SHA256 = (
    "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570"
)
_DOCKER_PRIMARY_FINGERPRINT = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
_DOCKER_SIGNING_FINGERPRINT = "D3306A018370199E527AE7997EA0A9C3F273FCD8"
_DOCKER_KEY_PATH = "/etc/apt/keyrings/omnilyzer-task014-docker.asc"
_DOCKER_SOURCE_PATH = (
    "/etc/apt/sources.list.d/omnilyzer-task014-docker.sources"
)
_DOCKER_SOURCE_BYTES = (
    b"Types: deb\n"
    b"URIs: https://download.docker.com/linux/ubuntu\n"
    b"Suites: noble\n"
    b"Components: stable\n"
    b"Architectures: amd64\n"
    b"Signed-By: /etc/apt/keyrings/omnilyzer-task014-docker.asc\n"
)
_POLICY_RC_D_PATH = "/usr/sbin/policy-rc.d"
_POLICY_RC_D_BYTES = b"#!/usr/bin/python3\nraise SystemExit(101)\n"
_STAGING_DIRECTORY = "/var/lib/omnilyzer/deployment/.rootless-docker-install"
_ROOTFUL_UNITS = ("docker.service", "docker.socket", "containerd.service")
_SUPPLEMENTAL_PACKAGES = (
    PackageAuthority(
        "libsubid4",
        "1:4.13+dfsg1-4ubuntu3.2",
        "Ubuntu signed noble-updates/main amd64",
        "ba97fd28c53560a8d2a2261e8f75a7ab4112535b12f9fe1d50970c30051da0da",
        (),
    ),
    PackageAuthority(
        "libslirp0",
        "4.7.0-1ubuntu3.1",
        "Ubuntu signed noble-updates/main amd64",
        "4efa2d1c509de4d10fe965e86a3d864bf542996caf476d9111fd882c73857164",
        (),
    ),
)

@dataclass(frozen=True, slots=True)
class PackagePayloadAuthority:
    """One exact package payload that may enter the C32ZR staging bundle."""

    package: str
    filename: str
    size: int
    sha256: str
    url: str

    def __post_init__(self) -> None:
        """Reject malformed payload metadata before it can become install authority."""

        if (
            type(self.package) is not str or not self.package
            or type(self.filename) is not str or not self.filename
            or "/" in self.filename or "\\" in self.filename or "\0" in self.filename
            or type(self.size) is not int or not 0 < self.size <= 100_000_000
            or type(self.sha256) is not str or len(self.sha256) != 64
            or any(c not in "0123456789abcdef" for c in self.sha256)
            or type(self.url) is not str
        ):
            raise ValueError("rootless Docker package payload authority is invalid")
        parsed = urlsplit(self.url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"download.docker.com", "archive.ubuntu.com"}
            or parsed.username is not None or parsed.password is not None
            or parsed.port is not None
            or parsed.query or parsed.fragment
            or (
                not parsed.path.startswith("/linux/ubuntu/")
                and not parsed.path.startswith("/ubuntu/")
            )
        ):
            raise ValueError("rootless Docker package payload authority is invalid")


_PAYLOADS = (
    PackagePayloadAuthority(
        "libsubid4",
        "libsubid4_4.13+dfsg1-4ubuntu3.2_amd64.deb",
        23442,
        "ba97fd28c53560a8d2a2261e8f75a7ab4112535b12f9fe1d50970c30051da0da",
        "https://archive.ubuntu.com/ubuntu/pool/main/s/shadow/"
        "libsubid4_4.13%2bdfsg1-4ubuntu3.2_amd64.deb",
    ),
    PackagePayloadAuthority(
        "uidmap",
        "uidmap_4.13+dfsg1-4ubuntu3.2_amd64.deb",
        26006,
        "a80cb7f72dd18c73cbb0b07b7fbe855504f26bfafae072a9b3d125c89d499b9e",
        "https://archive.ubuntu.com/ubuntu/pool/main/s/shadow/"
        "uidmap_4.13%2bdfsg1-4ubuntu3.2_amd64.deb",
    ),
    PackagePayloadAuthority(
        "libslirp0",
        "libslirp0_4.7.0-1ubuntu3.1_amd64.deb",
        63830,
        "4efa2d1c509de4d10fe965e86a3d864bf542996caf476d9111fd882c73857164",
        "https://archive.ubuntu.com/ubuntu/pool/main/libs/libslirp/"
        "libslirp0_4.7.0-1ubuntu3.1_amd64.deb",
    ),
    PackagePayloadAuthority(
        "slirp4netns",
        "slirp4netns_1.2.1-1build2_amd64.deb",
        34894,
        "3fc72a72a376a3ad3b439434bc87d89d245f9d54a1d540e8a06b74d4e2385e0a",
        "https://archive.ubuntu.com/ubuntu/pool/universe/s/slirp4netns/"
        "slirp4netns_1.2.1-1build2_amd64.deb",
    ),
    PackagePayloadAuthority(
        "containerd.io",
        "containerd.io_2.3.6-1~ubuntu.24.04~noble_amd64.deb",
        23155464,
        "2eb8c6e244fe6886f2fa2eee9ec418c4b9bb44eb44fca748504f57c23341aed2",
        "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
        "containerd.io_2.3.6-1~ubuntu.24.04~noble_amd64.deb",
    ),
    PackagePayloadAuthority(
        "docker-ce-cli",
        "docker-ce-cli_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
        17550136,
        "e26e6770fab41256cf16c09c24a0b75e70bf72465ef2688f85d1f7d3fdb9b99c",
        "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
        "docker-ce-cli_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
    ),
    PackagePayloadAuthority(
        "docker-ce-rootless-extras",
        "docker-ce-rootless-extras_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
        10177712,
        "02897501837b7ff4fec8248decdd5828b7d40d7f591021a91f29673e02d0f982",
        "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
        "docker-ce-rootless-extras_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
    ),
    PackagePayloadAuthority(
        "docker-compose-plugin",
        "docker-compose-plugin_5.5.1-1~ubuntu.24.04~noble_amd64.deb",
        8012228,
        "82ff966149ca2c62e1a4e1fdebdf65fda8c3a8bea80b32deda6903b40afc2347",
        "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
        "docker-compose-plugin_5.5.1-1~ubuntu.24.04~noble_amd64.deb",
    ),
    PackagePayloadAuthority(
        "docker-ce",
        "docker-ce_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
        24309816,
        "607bcf63bf85c5a245b73229c2797fda5c5a430343c02ebf80f32f6db7513eb9",
        "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
        "docker-ce_29.8.1-1~ubuntu.24.04~noble_amd64.deb",
    ),
)

_CONFLICTING_PACKAGES = (
    "docker.io",
    "docker-compose",
    "docker-compose-v2",
    "docker-doc",
    "docker-buildx",
    "podman-docker",
    "containerd",
    "runc",
    "docker-buildx-plugin",
)


@dataclass(frozen=True, slots=True)
class RootlessDockerInstallationAuthority:
    """One immutable installation plan derived from the C32ZF host authority."""

    packages: tuple[PackageAuthority, ...] = field(
        init=False, default=AUTHORITY.packages
    )
    supplemental_packages: tuple[PackageAuthority, ...] = field(
        init=False, default=_SUPPLEMENTAL_PACKAGES
    )
    docker_key_url: str = field(init=False, default=_DOCKER_KEY_URL)
    docker_key_sha256: str = field(init=False, default=_DOCKER_KEY_SHA256)
    docker_primary_fingerprint: str = field(
        init=False, default=_DOCKER_PRIMARY_FINGERPRINT
    )
    docker_signing_fingerprint: str = field(
        init=False, default=_DOCKER_SIGNING_FINGERPRINT
    )
    docker_key_path: str = field(init=False, default=_DOCKER_KEY_PATH)
    docker_source_path: str = field(init=False, default=_DOCKER_SOURCE_PATH)
    docker_source_bytes: bytes = field(init=False, default=_DOCKER_SOURCE_BYTES)
    policy_rc_d_path: str = field(init=False, default=_POLICY_RC_D_PATH)
    policy_rc_d_bytes: bytes = field(init=False, default=_POLICY_RC_D_BYTES)
    staging_directory: str = field(init=False, default=_STAGING_DIRECTORY)
    rootful_units: tuple[str, ...] = field(init=False, default=_ROOTFUL_UNITS)
    conflicting_packages: tuple[str, ...] = field(
        init=False, default=_CONFLICTING_PACKAGES
    )
    payloads: tuple[PackagePayloadAuthority, ...] = field(
        init=False, default=_PAYLOADS
    )

    def __post_init__(self) -> None:
        """Fail closed if any installation choice drifts from reviewed authority."""

        expected_origins = {
            "docker-ce": AUTHORITY.packages[0].origin,
            "docker-ce-cli": AUTHORITY.packages[1].origin,
            "docker-ce-rootless-extras": AUTHORITY.packages[2].origin,
            "docker-compose-plugin": AUTHORITY.packages[3].origin,
            "containerd.io": AUTHORITY.packages[4].origin,
            "uidmap": AUTHORITY.packages[5].origin,
            "slirp4netns": AUTHORITY.packages[6].origin,
        }
        names = tuple(item.name for item in self.packages)
        package_digests = {
            item.name: item.deb_sha256
            for item in (*self.packages, *self.supplemental_packages)
        }
        payload_names = tuple(item.package for item in self.payloads)
        if (
            len(self.packages) != 7
            or len(self.supplemental_packages) != 2
            or len(set(names)) != 7
            or set(names) != set(expected_origins)
            or any(type(item) is not PackageAuthority for item in self.packages)
            or any(
                item.origin != expected_origins.get(item.name)
                for item in self.packages
            )
            or "docker-buildx-plugin" in names
            or self.supplemental_packages != _SUPPLEMENTAL_PACKAGES
            or any(
                type(item) is not PackageAuthority
                or item.required_executables != ()
                or item.origin != "Ubuntu signed noble-updates/main amd64"
                for item in self.supplemental_packages
            )
            or self.payloads != _PAYLOADS
            or len(self.payloads) != 9
            or len(set(payload_names)) != 9
            or set(payload_names) != set(package_digests)
            or any(
                type(item) is not PackagePayloadAuthority
                or item.sha256 != package_digests.get(item.package)
                for item in self.payloads
            )
            or self.rootful_units != _ROOTFUL_UNITS
            or len(set(self.conflicting_packages)) != len(self.conflicting_packages)
            or "docker-buildx-plugin" not in self.conflicting_packages
            or self.docker_key_url != _DOCKER_KEY_URL
            or self.docker_key_sha256 != _DOCKER_KEY_SHA256
            or self.docker_primary_fingerprint != _DOCKER_PRIMARY_FINGERPRINT
            or self.docker_signing_fingerprint != _DOCKER_SIGNING_FINGERPRINT
            or self.docker_key_path != _DOCKER_KEY_PATH
            or self.docker_source_path != _DOCKER_SOURCE_PATH
            or self.docker_source_bytes != _DOCKER_SOURCE_BYTES
            or self.policy_rc_d_path != _POLICY_RC_D_PATH
            or self.policy_rc_d_bytes != _POLICY_RC_D_BYTES
            or self.staging_directory != _STAGING_DIRECTORY
            or AUTHORITY.subuid_start != 493216
            or AUTHORITY.subgid_start != 493216
            or AUTHORITY.subordinate_count != 65536
        ):
            raise ValueError("rootless Docker installation authority is invalid")

    def package_specs(self) -> tuple[str, ...]:
        """Return the exact apt package=version selections in reviewed order."""

        return tuple(
            f"{item.name}={item.apt_version}" for item in self.packages
        )

    def supplemental_package_specs(self) -> tuple[str, ...]:
        """Return exact new Ubuntu dependency package selections."""

        return tuple(
            f"{item.name}={item.apt_version}"
            for item in self.supplemental_packages
        )

    def all_package_specs(self) -> tuple[str, ...]:
        """Return all nine packages that the bootstrap may newly install."""

        return self.package_specs() + self.supplemental_package_specs()

    def payload_filenames(self) -> tuple[str, ...]:
        """Return the exact nine package filenames in safe install order."""

        return tuple(item.filename for item in self.payloads)


INSTALLATION_AUTHORITY = RootlessDockerInstallationAuthority()
