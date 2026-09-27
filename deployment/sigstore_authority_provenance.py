"""Closed immutable C32I Sigstore verification authority provenance.

These values were independently reviewed from the official pinned repositories
and release APIs. GitHub's tag verification status is retained review evidence,
not an offline signature verification claim. Import/construction/projection do
no I/O, fetch/update no trust state, and supply no workflow revision or activation.
Git blob IDs are externally reviewed upstream provenance identifiers, not content
integrity authority. Exact byte length and SHA-256 bind retained evidence; C32I
does not recompute Git's legacy SHA-1 object identifiers. Retained signed targets
metadata is not a complete TUF trust-chain verification.
"""

from dataclasses import dataclass as _dataclass, field as _field
from types import MappingProxyType as _MappingProxyType
from typing import Mapping as _Mapping

__all__ = (
    "CosignReleaseProvenance",
    "SigstoreTrustedRootProvenance",
    "DevSigstoreVerificationProvenance",
)

_ERROR = "DEV Sigstore verification authority provenance is invalid"


def _closed(value: object, expected: object) -> None:
    """Require the exact reviewed built-in type and value without coercion."""
    if type(value) is not type(expected):
        raise TypeError(_ERROR)
    if value != expected:
        raise ValueError(_ERROR)


@_dataclass(frozen=True, slots=True)
class CosignReleaseProvenance:
    """Exact Linux/amd64 binary and bounded evidence from one official release."""

    repository: str = _field(init=False, default='sigstore/cosign')
    version: str = _field(init=False, default='3.1.2')
    release_tag: str = _field(init=False, default='v3.1.2')
    release_id: int = _field(init=False, default=355751884)
    tag_object_sha: str = _field(init=False, default='dc80df70da727f4abdd843640594025584a270ae')
    source_commit_sha: str = _field(init=False, default='193d2153431f8bb0d945a4c1ee721872f73add67')
    tag_verification: str = _field(init=False, default='GitHub verified: valid')
    platform: str = _field(init=False, default='linux')
    architecture: str = _field(init=False, default='amd64')
    asset_name: str = _field(init=False, default='cosign-linux-amd64')
    asset_id: int = _field(init=False, default=480496709)
    asset_size: int = _field(init=False, default=141150460)
    asset_sha256: str = _field(init=False, default='f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf')
    bundle_name: str = _field(init=False, default='cosign-linux-amd64.sigstore.json')
    bundle_id: int = _field(init=False, default=480498776)
    bundle_size: int = _field(init=False, default=6433)
    bundle_sha256: str = _field(init=False, default='fdaa1c168d67041cd0d8f5782f8136ac5d148827b6911ba8bb577cbc7e13de2c')
    retained_bundle_path: str = _field(init=False, default='deployment/provenance/cosign-v3.1.2-linux-amd64.sigstore.json')
    checksums_name: str = _field(init=False, default='cosign_checksums.txt')
    checksums_id: int = _field(init=False, default=480498558)
    checksums_size: int = _field(init=False, default=3906)
    checksums_sha256: str = _field(init=False, default='3ef5d389c3f508b96025fd1b92744a305c46e95951c91242b57467567d5622db')
    retained_checksums_path: str = _field(init=False, default='deployment/provenance/cosign-v3.1.2-checksums.txt')
    checksums_bundle_name: str = _field(init=False, default='cosign_checksums.txt.sigstore.json')
    checksums_bundle_id: int = _field(init=False, default=480498856)
    checksums_bundle_size: int = _field(init=False, default=6578)
    checksums_bundle_sha256: str = _field(init=False, default='be73ee422be126a70190ee24bf88a1b078cde1f954f076ddf9c0901de4136362')
    retained_checksums_bundle_path: str = _field(init=False, default='deployment/provenance/cosign-v3.1.2-checksums.txt.sigstore.json')

    def __post_init__(self) -> None:
        """Revalidate every exact closed reviewed value, including forged objects."""
        try:
            for value, expected in (
                (self.repository, 'sigstore/cosign'),
                (self.version, '3.1.2'),
                (self.release_tag, 'v3.1.2'),
                (self.release_id, 355751884),
                (self.tag_object_sha, 'dc80df70da727f4abdd843640594025584a270ae'),
                (self.source_commit_sha, '193d2153431f8bb0d945a4c1ee721872f73add67'),
                (self.tag_verification, 'GitHub verified: valid'),
                (self.platform, 'linux'),
                (self.architecture, 'amd64'),
                (self.asset_name, 'cosign-linux-amd64'),
                (self.asset_id, 480496709),
                (self.asset_size, 141150460),
                (self.asset_sha256, 'f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf'),
                (self.bundle_name, 'cosign-linux-amd64.sigstore.json'),
                (self.bundle_id, 480498776),
                (self.bundle_size, 6433),
                (self.bundle_sha256, 'fdaa1c168d67041cd0d8f5782f8136ac5d148827b6911ba8bb577cbc7e13de2c'),
                (self.retained_bundle_path, 'deployment/provenance/cosign-v3.1.2-linux-amd64.sigstore.json'),
                (self.checksums_name, 'cosign_checksums.txt'),
                (self.checksums_id, 480498558),
                (self.checksums_size, 3906),
                (self.checksums_sha256, '3ef5d389c3f508b96025fd1b92744a305c46e95951c91242b57467567d5622db'),
                (self.retained_checksums_path, 'deployment/provenance/cosign-v3.1.2-checksums.txt'),
                (self.checksums_bundle_name, 'cosign_checksums.txt.sigstore.json'),
                (self.checksums_bundle_id, 480498856),
                (self.checksums_bundle_size, 6578),
                (self.checksums_bundle_sha256, 'be73ee422be126a70190ee24bf88a1b078cde1f954f076ddf9c0901de4136362'),
                (self.retained_checksums_bundle_path, 'deployment/provenance/cosign-v3.1.2-checksums.txt.sigstore.json'),
            ):
                _closed(value, expected)
        except AttributeError:
            raise TypeError(_ERROR) from None


@_dataclass(frozen=True, slots=True)
class SigstoreTrustedRootProvenance:
    """Exact reviewed target and retained signed targets metadata identities."""

    repository: str = _field(init=False, default='sigstore/root-signing')
    reviewed_commit: str = _field(init=False, default='829e81ca3db59ce8e8393f942795061b5fc0be30')
    target_path: str = _field(init=False, default='targets/trusted_root.json')
    target_name: str = _field(init=False, default='trusted_root.json')
    target_git_blob_sha: str = _field(init=False, default='effb0a19e6a0b3f69b3f0a2c72b5c2a02a0ddeea')
    target_size: int = _field(init=False, default=6787)
    target_sha256: str = _field(init=False, default='6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66')
    retained_target_path: str = _field(init=False, default='deployment/provenance/sigstore-public-good-trusted-root.json')
    metadata_path: str = _field(init=False, default='metadata/targets.json')
    metadata_git_blob_sha: str = _field(init=False, default='5ad0d090f7f08da0031a10ef57c0de21a25b3244')
    metadata_size: int = _field(init=False, default=4942)
    metadata_sha256: str = _field(init=False, default='6a697f7f8908c8ab26c11786ecb490b54acec97fa8c802e399f065f8a0cc1acd')
    retained_metadata_path: str = _field(init=False, default='deployment/provenance/sigstore-public-good-targets.json')
    targets_role_version: int = _field(init=False, default=14)
    metadata_expiration: str = _field(init=False, default='2036-05-09T09:00:52Z')
    media_type: str = _field(init=False, default='application/vnd.dev.sigstore.trustedroot+json;version=0.1')

    def __post_init__(self) -> None:
        """Revalidate every exact closed reviewed value, including forged objects."""
        try:
            for value, expected in (
                (self.repository, 'sigstore/root-signing'),
                (self.reviewed_commit, '829e81ca3db59ce8e8393f942795061b5fc0be30'),
                (self.target_path, 'targets/trusted_root.json'),
                (self.target_name, 'trusted_root.json'),
                (self.target_git_blob_sha, 'effb0a19e6a0b3f69b3f0a2c72b5c2a02a0ddeea'),
                (self.target_size, 6787),
                (self.target_sha256, '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66'),
                (self.retained_target_path, 'deployment/provenance/sigstore-public-good-trusted-root.json'),
                (self.metadata_path, 'metadata/targets.json'),
                (self.metadata_git_blob_sha, '5ad0d090f7f08da0031a10ef57c0de21a25b3244'),
                (self.metadata_size, 4942),
                (self.metadata_sha256, '6a697f7f8908c8ab26c11786ecb490b54acec97fa8c802e399f065f8a0cc1acd'),
                (self.retained_metadata_path, 'deployment/provenance/sigstore-public-good-targets.json'),
                (self.targets_role_version, 14),
                (self.metadata_expiration, '2036-05-09T09:00:52Z'),
                (self.media_type, 'application/vnd.dev.sigstore.trustedroot+json;version=0.1'),
            ):
                _closed(value, expected)
        except AttributeError:
            raise TypeError(_ERROR) from None


@_dataclass(frozen=True, slots=True)
class DevSigstoreVerificationProvenance:
    """Zero-input authority for one reviewed Sigstore verification generation."""

    cosign: CosignReleaseProvenance = _field(
        init=False, default_factory=CosignReleaseProvenance,
    )
    trusted_root: SigstoreTrustedRootProvenance = _field(
        init=False, default_factory=SigstoreTrustedRootProvenance,
    )

    def __post_init__(self) -> None:
        """Require exact nested models and revalidate their closed authorities."""
        try:
            if (type(self.cosign) is not CosignReleaseProvenance
                    or type(self.trusted_root) is not SigstoreTrustedRootProvenance):
                raise TypeError(_ERROR)
            CosignReleaseProvenance.__post_init__(self.cosign)
            SigstoreTrustedRootProvenance.__post_init__(self.trusted_root)
        except AttributeError:
            raise TypeError(_ERROR) from None

    def broker_service_configuration_kwargs(self) -> _Mapping[str, str]:
        """Project only C32H's three Sigstore toolchain authority fields."""
        self.__post_init__()
        return _MappingProxyType({
            "cosign_version": self.cosign.version,
            "cosign_binary_sha256": self.cosign.asset_sha256,
            "sigstore_trusted_root_sha256": self.trusted_root.target_sha256,
        })
