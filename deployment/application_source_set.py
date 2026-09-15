"""deployment/application_source_set.py — closed inert C25 source selection.

Define the exact reviewed repository source set and repository-to-application
relative-path mapping for the future DEV deployment-control-plane installation.
C20 executor_service_entrypoint.py owns the executor entrypoint; C21
host_service_layout.py owns the application root; C24
installation_integrity_contract.py defines complete manifest requirements.
Future C26 manifest/evidence work may consume this selection.

Import and construction perform no hashing, manifest generation, packaging,
archive generation, copying, filesystem inspection, host installation, venv
creation, dependency installation, systemd action, Docker action or deployment
activation. This selection proves no source bytes or installed host state.
"""

from dataclasses import dataclass as _dataclass, field as _field, fields as _fields

from .host_service_layout import DevHostServiceLayout as _DevHostServiceLayout

__all__ = (
    "ApplicationSourceFile",
    "DevApplicationSourceSet",
)

_ERROR = "DEV application source file is invalid"


def _relative_path(value: object) -> None:
    """Validate canonical POSIX relative text without filesystem operations."""
    if type(value) is not str:
        raise TypeError(_ERROR)
    if not value or "\\" in value or "\0" in value or any(
        component in ("", ".", "..") for component in value.split("/")
    ):
        raise ValueError(_ERROR)


@_dataclass(frozen=True, slots=True)
class ApplicationSourceFile:
    """One source selection with an identical future application-relative path."""

    repository_path: str
    target_relative_path: str
    kind: str

    def __post_init__(self) -> None:
        _relative_path(self.repository_path)
        _relative_path(self.target_relative_path)
        if type(self.kind) is not str:
            raise TypeError(_ERROR)
        if (
            self.repository_path != self.target_relative_path
            or self.kind not in ("python-module", "runtime-data")
            or (self.kind == "python-module" and not self.repository_path.endswith(".py"))
        ):
            raise ValueError(_ERROR)


# Explicit reviewed allowlist: never discover, glob, read or hash source files.
_PYTHON_PATHS = (
    "deployment/__init__.py",
    "deployment/audit.py",
    "deployment/broker.py",
    "deployment/controller.py",
    "deployment/deployment_operation.py",
    "deployment/docker_runtime.py",
    "deployment/execution.py",
    "deployment/executor.py",
    "deployment/executor_composition.py",
    "deployment/executor_listener.py",
    "deployment/executor_server.py",
    "deployment/executor_service_bootstrap.py",
    "deployment/executor_service_config.py",
    "deployment/executor_service_config_loader.py",
    "deployment/executor_service_entrypoint.py",
    "deployment/identity.py",
    "deployment/installation_contract.py",
    "deployment/jwks.py",
    "deployment/policy.py",
    "deployment/promotion.py",
    "deployment/replay_sqlite.py",
    "deployment/state.py",
    "deployment/state_store.py",
    "deployment/systemd_socket_activation.py",
    "deployment/unix_transport.py",
)
_RUNTIME_PATHS = (
    "deployment/runtime/dev/canary-runtime.json",
    "deployment/runtime/dev/compose.yaml",
    "deployment/runtime/dev/nginx/nginx.conf",
)
_FILES = tuple(sorted(
    tuple(ApplicationSourceFile(path, path, "python-module") for path in _PYTHON_PATHS)
    + tuple(ApplicationSourceFile(path, path, "runtime-data") for path in _RUNTIME_PATHS),
    key=lambda source: source.repository_path,
))


def _layout_default(name: str) -> str:
    """Project C21 metadata without constructing or inspecting a host layout."""
    return next(item.default for item in _fields(_DevHostServiceLayout) if item.name == name)


@_dataclass(frozen=True, slots=True)
class DevApplicationSourceSet:
    """The fixed C25 selection, with no caller-selected paths or files."""

    application_root: str = _field(init=False, default=_layout_default("application_root"))
    entrypoint_module: str = _field(init=False, default=_layout_default("executor_module"))
    files: tuple[ApplicationSourceFile, ...] = _field(init=False, default=_FILES)
