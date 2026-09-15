"""deployment/installation_integrity_contract.py — pure inert C24 requirements.

C17 reviewed_commit binds future application evidence to reviewed source. C21
owns the application, venv and Python paths; C23 retains provisioning metadata
and directory requirements. C1 owns the reviewed dependency lock and closure.
Task 013 synthetic canary artifacts are not installation integrity authority.
No production wheelhouse is claimed, no application manifest is currently
approved, and no interpreter artifact is currently approved. Import and
construction perform no host I/O, host mutation, installation or deployment
activation. This contract defines qualification requirements, not evidence.
"""

from dataclasses import dataclass as _dataclass, field as _field, fields as _fields, is_dataclass as _is_dataclass
from re import fullmatch as _fullmatch

from .executor_service_config import (
    DevExecutorServiceConfiguration as _DevExecutorServiceConfiguration,
    parse_canonical_executor_service_configuration as _parse_configuration,
)
from .host_service_layout import DevHostServiceLayout as _DevHostServiceLayout

__all__ = (
    "RepositoryFileIntegrityRequirement",
    "WheelIntegrityRequirement",
    "ApplicationIntegrityRequirement",
    "PythonEnvironmentIntegrityRequirement",
    "DevInstallationIntegrityContract",
)

# Reviewed static C1 pins are requirements; no file is read or hashed here.
_ERROR = "DEV installation integrity contract is invalid"
_LOCK = (
    "deployment/requirements-linux-x86_64-py312.lock",
    "13c7b3f0050f9aff0a94ab324a66276638f8b1b9dd0c62232ec205b24d874d0d",
)
_WHEELS = (
    ("pyjwt-2.13.0-py3-none-any.whl",
     "66adcc2aff09b3f1bbd95fc1e1577df8ac8723c978552fd43304c8a290ac5728"),
    ("cryptography-50.0.1-cp311-abi3-manylinux_2_34_x86_64.whl",
     "51afcfceb15597cf2635068e4ac9a56b2abde622edde17f37d85fd7b5306497a"),
    ("cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
     "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf"),
    ("pycparser-3.0-py3-none-any.whl",
     "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992"),
)


def _layout_default(name: str) -> str:
    """Project a C21 declared path default without constructing another layout."""
    return next(item.default for item in _fields(_DevHostServiceLayout) if item.name == name)


def _text(value: object) -> None:
    """Require exact built-in text without coercion."""
    if type(value) is not str:
        raise TypeError(_ERROR)


def _digest(value: object) -> None:
    """Require a canonical lowercase SHA-256 requirement."""
    _text(value)
    if _fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(_ERROR)


def _closed(value: object, expected: object) -> None:
    """Separate wrong shape from a typed value outside the closed domain."""
    if type(value) is not type(expected):
        raise TypeError(_ERROR)
    if type(expected) is tuple:
        if len(value) != len(expected) or any(type(a) is not type(b) for a, b in zip(value, expected)):
            raise TypeError(_ERROR)
    if value != expected:
        raise ValueError(_ERROR)


def _same_value(supplied: object, restored: object) -> bool:
    """Compare exact types recursively against a purely reconstructed C17 object."""
    if type(supplied) is not type(restored):
        return False
    if type(restored) is tuple:
        return len(supplied) == len(restored) and all(
            _same_value(a, b) for a, b in zip(supplied, restored)
        )
    if _is_dataclass(restored):
        return all(_same_value(getattr(supplied, item.name), getattr(restored, item.name))
                   for item in _fields(restored))
    return supplied == restored


# Immutable value requirements validate syntax and closed semantics only.
@_dataclass(frozen=True, slots=True)
class RepositoryFileIntegrityRequirement:
    """Describe a repository-relative regular-file integrity pin without reading it."""

    path: str
    sha256: str

    def __post_init__(self) -> None:
        """Reject noncanonical relative POSIX paths and malformed SHA-256 text."""
        _text(self.path)
        if ("\\" in self.path or "\0" in self.path
                or any(part in ("", ".", "..") for part in self.path.split("/"))):
            raise ValueError(_ERROR)
        _digest(self.sha256)


@_dataclass(frozen=True, slots=True)
class WheelIntegrityRequirement:
    """Describe one bounded ASCII wheel filename and its reviewed byte digest."""

    filename: str
    sha256: str

    def __post_init__(self) -> None:
        """Validate a plain wheel filename without downloading or inspecting metadata."""
        _text(self.filename)
        if (len(self.filename) > 255
                or _fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*\.whl", self.filename) is None):
            raise ValueError(_ERROR)
        _digest(self.sha256)


@_dataclass(frozen=True, slots=True)
class ApplicationIntegrityRequirement:
    """Require a future complete manifest; select no packaging or manifest bytes."""

    root: str
    reviewed_commit: str
    manifest_kind: str
    digest_algorithm: str
    manifest_required: bool
    manifest_entry_fields: tuple[str, str, str]
    regular_files_only: bool
    sorted_unique_paths: bool
    symlinks_allowed: bool
    unlisted_paths_allowed: bool

    def __post_init__(self) -> None:
        """Enforce the C21 root and the closed future file-manifest semantics."""
        _closed(self.root, _layout_default("application_root"))
        _text(self.reviewed_commit)
        if (_fullmatch(r"[0-9a-f]{40}", self.reviewed_commit) is None
                or self.reviewed_commit == "0" * 40):
            raise ValueError(_ERROR)
        for value, expected in (
            (self.manifest_kind, "canonical-relative-file-set-v1"),
            (self.digest_algorithm, "sha256"), (self.manifest_required, True),
            (self.manifest_entry_fields, ("path", "sha256", "mode")),
            (self.regular_files_only, True), (self.sorted_unique_paths, True),
            (self.symlinks_allowed, False), (self.unlisted_paths_allowed, False),
        ):
            _closed(value, expected)


@_dataclass(frozen=True, slots=True)
class PythonEnvironmentIntegrityRequirement:
    """Require the C21 environment, C1 wheel closure and future interpreter evidence."""

    root: str
    python_executable: str
    implementation: str
    python_series: str
    operating_system: str
    distribution: str
    architecture: str
    libc: str
    dependency_lock: RepositoryFileIntegrityRequirement
    wheels: tuple[WheelIntegrityRequirement, ...]
    interpreter_integrity_required: bool
    source_builds_allowed: bool
    network_install_allowed: bool
    extra_wheels_allowed: bool

    def __post_init__(self) -> None:
        """Enforce the fixed target and exact ordered binary-only dependency inputs."""
        for value, expected in (
            (self.root, _layout_default("virtualenv_root")),
            (self.python_executable, _layout_default("python_executable")),
            (self.implementation, "CPython"), (self.python_series, "3.12"),
            (self.operating_system, "Linux"), (self.distribution, "Ubuntu 24.04"),
            (self.architecture, "x86_64"), (self.libc, "glibc"),
            (self.interpreter_integrity_required, True),
            (self.source_builds_allowed, False), (self.network_install_allowed, False),
            (self.extra_wheels_allowed, False),
        ):
            _closed(value, expected)
        if (type(self.dependency_lock) is not RepositoryFileIntegrityRequirement
                or type(self.wheels) is not tuple
                or not all(type(wheel) is WheelIntegrityRequirement for wheel in self.wheels)):
            raise TypeError(_ERROR)
        try:
            # Revalidate nested exact-type objects as they too can be forged.
            RepositoryFileIntegrityRequirement(self.dependency_lock.path, self.dependency_lock.sha256)
            for wheel in self.wheels:
                WheelIntegrityRequirement(wheel.filename, wheel.sha256)
            _closed((self.dependency_lock.path, self.dependency_lock.sha256), _LOCK)
            if tuple((wheel.filename, wheel.sha256) for wheel in self.wheels) != _WHEELS:
                raise ValueError(_ERROR)
        except AttributeError:
            raise TypeError(_ERROR) from None


# The sole authority input is C17; cached projections carry no qualification claim.
@_dataclass(frozen=True, slots=True, kw_only=True)
class DevInstallationIntegrityContract:
    """Project one exact revalidated C17 configuration into inert C24 requirements."""

    configuration: _DevExecutorServiceConfiguration
    _layout: _DevHostServiceLayout = _field(init=False, repr=False)
    _application: ApplicationIntegrityRequirement = _field(init=False, repr=False)
    _python_environment: PythonEnvironmentIntegrityRequirement = _field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Revalidate C17 in memory and construct exactly one cached C21 layout."""
        configuration = self.configuration
        if type(configuration) is not _DevExecutorServiceConfiguration:
            raise TypeError(_ERROR)
        try:
            raw = configuration.canonical_bytes()
            if type(raw) is not bytes:
                raise TypeError(_ERROR)
            reparsed = _parse_configuration(raw)
            if type(reparsed) is not _DevExecutorServiceConfiguration:
                raise TypeError(_ERROR)
            if not _same_value(configuration, reparsed):
                raise TypeError(_ERROR)
        except Exception:
            raise TypeError(_ERROR) from None
        layout = _DevHostServiceLayout()
        application = ApplicationIntegrityRequirement(
            layout.application_root, configuration.reviewed_commit,
            "canonical-relative-file-set-v1", "sha256", True,
            ("path", "sha256", "mode"), True, True, False, False,
        )
        environment = PythonEnvironmentIntegrityRequirement(
            layout.virtualenv_root, layout.python_executable, "CPython", "3.12",
            "Linux", "Ubuntu 24.04", "x86_64", "glibc",
            RepositoryFileIntegrityRequirement(*_LOCK),
            tuple(WheelIntegrityRequirement(*entry) for entry in _WHEELS),
            True, False, False, False,
        )
        object.__setattr__(self, "_layout", layout)
        object.__setattr__(self, "_application", application)
        object.__setattr__(self, "_python_environment", environment)

    def service_layout(self) -> _DevHostServiceLayout:
        """Return the exact cached immutable C21 layout."""
        return self._layout

    def application_requirement(self) -> ApplicationIntegrityRequirement:
        """Return the immutable future application qualification requirement."""
        return self._application

    def python_environment_requirement(self) -> PythonEnvironmentIntegrityRequirement:
        """Return the immutable future environment qualification requirement."""
        return self._python_environment
