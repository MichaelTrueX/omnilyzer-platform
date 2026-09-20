"""Pure, immutable C27 CPython 3.12 archive provenance evidence.

The repository-retained Ubuntu Archive key is accepted only because its
computed full fingerprint was matched to Canonical's independently published
fingerprint.  That key verified one exact Noble Security InRelease, whose
signed SHA-256 and size identify the Packages index from which the closed four
package records were reviewed.  Package artifact hashes are not installed-file
hashes.  Import and construction perform no I/O, verification, installation,
host inspection, venv creation or activation.
"""

from dataclasses import dataclass as _dataclass, field as _field
from re import fullmatch as _fullmatch

__all__ = (
    "ArchiveSigningKeyEvidence",
    "SignedPackagesIndexEvidence",
    "PythonPackageArtifactEvidence",
    "DevPythonInterpreterProvenance",
)

_ERROR = "DEV Python interpreter provenance evidence is invalid"


def _text(value: object) -> None:
    if type(value) is not str:
        raise TypeError(_ERROR)


def _closed(value: object, expected: object) -> None:
    if type(value) is not type(expected):
        raise TypeError(_ERROR)
    if value != expected:
        raise ValueError(_ERROR)


def _digest(value: object) -> None:
    _text(value)
    if _fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(_ERROR)


def _fingerprint(value: object) -> None:
    _text(value)
    if _fullmatch(r"[0-9A-F]{40}", value) is None:
        raise ValueError(_ERROR)


def _size(value: object) -> None:
    if type(value) is not int:
        raise TypeError(_ERROR)
    if value <= 0:
        raise ValueError(_ERROR)


def _relative_path(value: object, suffix: str = "") -> None:
    _text(value)
    if (
        not value
        or "\\" in value
        or "\0" in value
        or any(part in ("", ".", "..") for part in value.split("/"))
        or (suffix and not value.endswith(suffix))
    ):
        raise ValueError(_ERROR)


def _https_url(value: object) -> None:
    _text(value)
    if (
        len(value) > 512
        or _fullmatch(r"https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~:/?=&%+@-]*)?", value) is None
    ):
        raise ValueError(_ERROR)


@_dataclass(frozen=True, slots=True)
class ArchiveSigningKeyEvidence:
    """Repository-retained public-key bytes and independent identity sources."""

    repository_path: str
    sha256: str
    size: int
    fingerprint: str
    key_type: str
    uid: str
    canonical_references: tuple[str, ...]

    def __post_init__(self) -> None:
        _relative_path(self.repository_path, ".asc")
        _digest(self.sha256)
        _size(self.size)
        _fingerprint(self.fingerprint)
        _text(self.key_type)
        _text(self.uid)
        if not self.key_type or not self.uid:
            raise ValueError(_ERROR)
        if (
            type(self.canonical_references) is not tuple
            or not self.canonical_references
            or any(type(item) is not str for item in self.canonical_references)
        ):
            raise TypeError(_ERROR)
        for reference in self.canonical_references:
            _https_url(reference)


@_dataclass(frozen=True, slots=True)
class SignedPackagesIndexEvidence:
    """One verified InRelease and its signed amd64 Packages identities."""

    archive: str
    release: str
    suite: str
    component: str
    architecture: str
    snapshot_timestamp: str
    snapshot_base_url: str
    repository_inrelease_path: str
    inrelease_path: str
    inrelease_sha256: str
    inrelease_size: int
    inrelease_date: str
    signature_created: str
    signing_key_fingerprint: str
    packages_path: str
    packages_sha256: str
    packages_size: int
    compressed_packages_path: str
    compressed_packages_sha256: str
    compressed_packages_size: int

    def __post_init__(self) -> None:
        for value in (
            self.archive, self.release, self.suite, self.component,
            self.architecture,
        ):
            _text(value)
            if not value:
                raise ValueError(_ERROR)
        for value in (self.snapshot_timestamp, self.inrelease_date, self.signature_created):
            _text(value)
            if _fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
                raise ValueError(_ERROR)
        _https_url(self.snapshot_base_url)
        _relative_path(self.repository_inrelease_path, ".InRelease")
        _relative_path(self.inrelease_path, "InRelease")
        _relative_path(self.packages_path, "Packages")
        _relative_path(self.compressed_packages_path, "Packages.xz")
        for digest in (
            self.inrelease_sha256, self.packages_sha256,
            self.compressed_packages_sha256,
        ):
            _digest(digest)
        for size in (
            self.inrelease_size, self.packages_size,
            self.compressed_packages_size,
        ):
            _size(size)
        _fingerprint(self.signing_key_fingerprint)


@_dataclass(frozen=True, slots=True)
class PythonPackageArtifactEvidence:
    """Selected exact fields from one verified Packages-index record."""

    package: str
    version: str
    architecture: str
    suite: str
    component: str
    filename: str
    size: int
    sha256: str
    depends: str

    def __post_init__(self) -> None:
        for value in (
            self.package, self.version, self.architecture,
            self.suite, self.component, self.depends,
        ):
            _text(value)
            if not value:
                raise ValueError(_ERROR)
        if _fullmatch(r"[a-z0-9][a-z0-9+.-]*", self.package) is None:
            raise ValueError(_ERROR)
        _relative_path(self.filename, ".deb")
        _size(self.size)
        _digest(self.sha256)


_KEY = ArchiveSigningKeyEvidence(
    "deployment/provenance/ubuntu-archive-key-2018.asc",
    "2a3cc57ab6b47626b496a101c29af6dfe54d54d03d613f2326b9f2a30a15c39b",
    1660,
    "F6ECB3762474EDA9D21B7022871920D1991BC93C",
    "OpenPGP v4 RSA 4096",
    "Ubuntu Archive Automatic Signing Key (2018) <ftpmaster@ubuntu.com>",
    (
        "https://wiki.ubuntu.com/SecurityTeam/FAQ",
        "https://documentation.ubuntu.com/security/software-integrity/image-verification/",
        "https://ubuntu.com/chisel/docs/latest/reference/chisel-releases/chisel.yaml/",
    ),
)

_INDEX = SignedPackagesIndexEvidence(
    "Ubuntu", "24.04", "noble-security", "main", "amd64",
    "2026-09-19T00:46:15Z",
    "https://snapshot.ubuntu.com/ubuntu/20260919T004615Z",
    "deployment/provenance/noble-security-20260919T004615Z.InRelease",
    "dists/noble-security/InRelease",
    "603d902fbcedd1666b0897c005771162a7b36288a56aac6a5f557556d53d66de",
    126127,
    "2026-09-19T00:46:15Z",
    "2026-09-19T00:47:09Z",
    _KEY.fingerprint,
    "main/binary-amd64/Packages",
    "f8fca2bdd59ee4de64a30fc88df870356c6f43e19372b0dbc7caf8b1f2bb2536",
    5476895,
    "main/binary-amd64/Packages.xz",
    "7068ebb5e7f7f862612a63d66e1178de0d136086ae02bc7fe95947ab09d8b6a1",
    1009196,
)

_PACKAGES = (
    PythonPackageArtifactEvidence(
        "libpython3.12-minimal", "3.12.3-1ubuntu0.17", "amd64",
        "noble-security", "main",
        "pool/main/p/python3.12/libpython3.12-minimal_3.12.3-1ubuntu0.17_amd64.deb",
        838536,
        "d646ad7112b5adec21ba0e1af015f04ae8ca7f5efdc619622547dd6673c4c14b",
        "libc6 (>= 2.14), libssl3t64 (>= 3.0.0)",
    ),
    PythonPackageArtifactEvidence(
        "libpython3.12-stdlib", "3.12.3-1ubuntu0.17", "amd64",
        "noble-security", "main",
        "pool/main/p/python3.12/libpython3.12-stdlib_3.12.3-1ubuntu0.17_amd64.deb",
        2070530,
        "45d3f530ba1f9d6e879ad46b92046fabab13fe50a82450e4f65557a3bbad1489",
        "libpython3.12-minimal (= 3.12.3-1ubuntu0.17), media-types | mime-support, netbase, tzdata, libbz2-1.0, libc6 (>= 2.38), libcrypt1 (>= 1:4.1.0), libdb5.3t64, libffi8 (>= 3.4), liblzma5 (>= 5.1.1alpha+20120614), libncursesw6 (>= 6.1), libreadline8t64 (>= 7.0~beta), libsqlite3-0 (>= 3.36.0), libtinfo6 (>= 6)",
    ),
    PythonPackageArtifactEvidence(
        "python3.12", "3.12.3-1ubuntu0.17", "amd64",
        "noble-security", "main",
        "pool/main/p/python3.12/python3.12_3.12.3-1ubuntu0.17_amd64.deb",
        650732,
        "6745c9463432e619d7402b117ad4ac86c31dcd3999ba20daa9e395f6f9909d86",
        "python3.12-minimal (= 3.12.3-1ubuntu0.17), libpython3.12-stdlib (= 3.12.3-1ubuntu0.17), media-types | mime-support, tzdata",
    ),
    PythonPackageArtifactEvidence(
        "python3.12-minimal", "3.12.3-1ubuntu0.17", "amd64",
        "noble-security", "main",
        "pool/main/p/python3.12/python3.12-minimal_3.12.3-1ubuntu0.17_amd64.deb",
        2334634,
        "d452689b9660845345a4c3e05e4ad82c082d5474e04031b7aa47f1a6d5610a6e",
        "libpython3.12-minimal (= 3.12.3-1ubuntu0.17), libexpat1 (>= 2.6.0), zlib1g (>= 1:1.2.0)",
    ),
)


@_dataclass(frozen=True, slots=True)
class DevPythonInterpreterProvenance:
    """Closed zero-input C27 evidence compatible with C24's Python target."""

    implementation: str = _field(init=False, default="CPython")
    python_series: str = _field(init=False, default="3.12")
    operating_system: str = _field(init=False, default="Linux")
    distribution: str = _field(init=False, default="Ubuntu 24.04")
    architecture: str = _field(init=False, default="x86_64")
    archive_architecture: str = _field(init=False, default="amd64")
    libc: str = _field(init=False, default="glibc")
    archive_key: ArchiveSigningKeyEvidence = _field(init=False, default=_KEY)
    packages_index: SignedPackagesIndexEvidence = _field(init=False, default=_INDEX)
    packages: tuple[PythonPackageArtifactEvidence, ...] = _field(
        init=False, default=_PACKAGES,
    )

    def __post_init__(self) -> None:
        """Revalidate every nested value and the exact closed C27 record set."""
        for value, expected in (
            (self.implementation, "CPython"),
            (self.python_series, "3.12"),
            (self.operating_system, "Linux"),
            (self.distribution, "Ubuntu 24.04"),
            (self.architecture, "x86_64"),
            (self.archive_architecture, "amd64"),
            (self.libc, "glibc"),
        ):
            _closed(value, expected)
        if type(self.archive_key) is not ArchiveSigningKeyEvidence:
            raise TypeError(_ERROR)
        if type(self.packages_index) is not SignedPackagesIndexEvidence:
            raise TypeError(_ERROR)
        if (
            type(self.packages) is not tuple
            or any(type(item) is not PythonPackageArtifactEvidence for item in self.packages)
        ):
            raise TypeError(_ERROR)
        try:
            ArchiveSigningKeyEvidence.__post_init__(self.archive_key)
            SignedPackagesIndexEvidence.__post_init__(self.packages_index)
            for package in self.packages:
                PythonPackageArtifactEvidence.__post_init__(package)
        except AttributeError:
            raise TypeError(_ERROR) from None
        _closed(self.archive_key, _KEY)
        _closed(self.packages_index, _INDEX)
        _closed(self.packages, _PACKAGES)
        if (
            self.packages_index.signing_key_fingerprint != self.archive_key.fingerprint
            or tuple(package.package for package in self.packages)
            != tuple(sorted(package.package for package in self.packages))
            or any(
                package.version != "3.12.3-1ubuntu0.17"
                or package.architecture != self.archive_architecture
                or package.suite != self.packages_index.suite
                or package.component != self.packages_index.component
                for package in self.packages
            )
        ):
            raise ValueError(_ERROR)
