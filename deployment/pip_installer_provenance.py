"""Immutable C31P provenance for the provisioning-only pip installer.

PyPI's release metadata and Integrity API were reviewed to bind one exact pip
wheel to its Trusted Publishing identity.  The retained values are compact
reviewed evidence; this module does not claim to perform offline Sigstore
verification.  Import and construction perform no I/O and grant no package
installation or host-provisioning authority.
"""

from dataclasses import dataclass as _dataclass, field as _field
from re import fullmatch as _fullmatch

__all__ = (
    "PipInstallerArtifactEvidence",
    "PipInstallerPublicationEvidence",
    "PipInstallerInvocationRequirement",
    "DevPipInstallerProvenance",
)

_ERROR = "DEV pip installer provenance evidence is invalid"
_VERSION = "26.2.1"
_FILENAME = "pip-26.2.1-py3-none-any.whl"
_SHA256 = "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"
_BOOTSTRAP = """import runpy, sys
wheel = sys.argv.pop(1)
sys.path.insert(0, wheel)
import pip
if pip.__version__ != "26.2.1" or pip.__file__ != wheel + "/pip/__init__.py":
    raise SystemExit(86)
runpy.run_module("pip", run_name="__main__", alter_sys=True)
"""


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


def _https_url(value: object) -> None:
    _text(value)
    if (
        len(value) > 1024
        or _fullmatch(r"https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~:/?=&%+@-]*)?", value)
        is None
    ):
        raise ValueError(_ERROR)


@_dataclass(frozen=True, slots=True)
class PipInstallerArtifactEvidence:
    """Exact PyPI wheel identity reviewed for provisioning-tool use."""

    package: str
    version: str
    filename: str
    size: int
    sha256: str
    wheel_tags: tuple[str, ...]
    requires_python: str
    release_date: str
    uploaded_at: str
    release_url: str
    json_url: str
    file_url: str

    def __post_init__(self) -> None:
        for value in (self.package, self.version, self.filename, self.requires_python):
            _text(value)
            if not value:
                raise ValueError(_ERROR)
        if (
            self.filename != f"{self.package}-{self.version}-py3-none-any.whl"
            or "/" in self.filename
            or "\\" in self.filename
            or "\0" in self.filename
        ):
            raise ValueError(_ERROR)
        if type(self.size) is not int:
            raise TypeError(_ERROR)
        if self.size <= 0:
            raise ValueError(_ERROR)
        _digest(self.sha256)
        if (
            type(self.wheel_tags) is not tuple
            or not self.wheel_tags
            or any(type(value) is not str or not value for value in self.wheel_tags)
        ):
            raise TypeError(_ERROR)
        _text(self.uploaded_at)
        _text(self.release_date)
        if _fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", self.release_date) is None:
            raise ValueError(_ERROR)
        timestamp = (
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
            r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"
        )
        if _fullmatch(timestamp, self.uploaded_at) is None:
            raise ValueError(_ERROR)
        for value in (self.release_url, self.json_url, self.file_url):
            _https_url(value)


@_dataclass(frozen=True, slots=True)
class PipInstallerPublicationEvidence:
    """Reviewed PyPI-verified publication and Sigstore-log identity."""

    publication_method: str
    provenance_service: str
    publisher_environment: str
    publisher_kind: str
    repository: str
    source_commit: str
    release_tag: str
    workflow_path: str
    certificate_identity: str
    sigstore_log_index: int
    authoritative_references: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (
            self.publication_method, self.provenance_service,
            self.publisher_environment, self.publisher_kind, self.repository,
            self.release_tag, self.workflow_path, self.certificate_identity,
        ):
            _text(value)
            if not value:
                raise ValueError(_ERROR)
        _text(self.source_commit)
        if _fullmatch(r"[0-9a-f]{40}", self.source_commit) is None:
            raise ValueError(_ERROR)
        if type(self.sigstore_log_index) is not int:
            raise TypeError(_ERROR)
        if self.sigstore_log_index < 0:
            raise ValueError(_ERROR)
        if (
            type(self.authoritative_references) is not tuple
            or not self.authoritative_references
            or any(type(value) is not str for value in self.authoritative_references)
        ):
            raise TypeError(_ERROR)
        for value in self.authoritative_references:
            _https_url(value)


@_dataclass(frozen=True, slots=True)
class PipInstallerInvocationRequirement:
    """Fixed direct-wheel bootstrap shape for later C31 orchestration."""

    implementation: str
    python_series: str
    python_executable: str
    isolation_argument: str
    bootstrap_source: str
    installer_module: str
    expected_version: str
    execution_model: str

    def __post_init__(self) -> None:
        for value in (
            self.implementation, self.python_series, self.python_executable,
            self.isolation_argument,
            self.bootstrap_source, self.installer_module,
            self.expected_version, self.execution_model,
        ):
            _text(value)
            if not value:
                raise ValueError(_ERROR)
        if (
            not self.python_executable.startswith("/")
            or "\\" in self.python_executable
            or "\0" in self.python_executable
            or any(part in ("", ".", "..") for part in self.python_executable[1:].split("/"))
        ):
            raise ValueError(_ERROR)


_ARTIFACT = PipInstallerArtifactEvidence(
    "pip",
    _VERSION,
    _FILENAME,
    1816632,
    _SHA256,
    ("py3-none-any",),
    ">=3.10",
    "2026-08-04",
    "2026-08-04T22:51:12.472093Z",
    "https://pypi.org/project/pip/26.2.1/",
    "https://pypi.org/pypi/pip/26.2.1/json",
    "https://files.pythonhosted.org/packages/f3/6e/"
    "1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/"
    "pip-26.2.1-py3-none-any.whl",
)

_PUBLICATION = PipInstallerPublicationEvidence(
    "PyPI Trusted Publishing",
    "PyPI Integrity API v1",
    "pypi",
    "GitHub",
    "pypa/pip",
    "634a6ec1a5d9dcc2433571cdb2f4c58a4bb29caf",
    "refs/tags/26.2.1",
    ".github/workflows/release.yml",
    "https://github.com/pypa/pip/.github/workflows/release.yml@refs/tags/26.2.1",
    2341605236,
    (
        "https://pypi.org/project/pip/26.2.1/",
        "https://pypi.org/pypi/pip/26.2.1/json",
        "https://pypi.org/integrity/pip/26.2.1/pip-26.2.1-py3-none-any.whl/provenance",
        "https://pip.pypa.io/en/stable/news/",
        "https://github.com/pypa/pip/blob/"
        "634a6ec1a5d9dcc2433571cdb2f4c58a4bb29caf/"
        ".github/workflows/release.yml",
        "https://search.sigstore.dev/?logIndex=2341605236",
    ),
)

_INVOCATION = PipInstallerInvocationRequirement(
    "CPython",
    "3.12",
    "/opt/omnilyzer/deployment/venv/bin/python",
    "-I",
    _BOOTSTRAP,
    "pip",
    _VERSION,
    "isolated direct wheel zip import",
)


@_dataclass(frozen=True, slots=True)
class DevPipInstallerProvenance:
    """Closed zero-input C31P installer provenance and invocation model."""

    artifact: PipInstallerArtifactEvidence = _field(init=False, default=_ARTIFACT)
    publication: PipInstallerPublicationEvidence = _field(
        init=False, default=_PUBLICATION,
    )
    invocation: PipInstallerInvocationRequirement = _field(
        init=False, default=_INVOCATION,
    )

    def __post_init__(self) -> None:
        for value, kind in (
            (self.artifact, PipInstallerArtifactEvidence),
            (self.publication, PipInstallerPublicationEvidence),
            (self.invocation, PipInstallerInvocationRequirement),
        ):
            if type(value) is not kind:
                raise TypeError(_ERROR)
            try:
                kind.__post_init__(value)
            except AttributeError:
                raise TypeError(_ERROR) from None
        _closed(self.artifact, _ARTIFACT)
        _closed(self.publication, _PUBLICATION)
        _closed(self.invocation, _INVOCATION)
        if (
            self.artifact.version != self.invocation.expected_version
            or self.publication.release_tag != f"refs/tags/{self.artifact.version}"
            or not self.publication.certificate_identity.endswith(
                "@" + self.publication.release_tag
            )
        ):
            raise ValueError(_ERROR)
