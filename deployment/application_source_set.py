"""deployment/application_source_set.py — closed inert current DEV source selection.

Define the exact reviewed repository source set and repository-to-application
relative-path mapping for the future DEV deployment-control-plane installation.
C20 executor_service_entrypoint.py and C32T broker_service_entrypoint.py own
the two service entrypoints; C21
host_service_layout.py owns the application root; C24
installation_integrity_contract.py defines complete manifest requirements.
C26 manifest generation consumes this current selection; historical C31/C32D
path sets remain separately pinned in application_manifest.py.

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
    "deployment/blob_verifier.py",
    "deployment/broker.py",
    "deployment/broker_https_ingress.py",
    "deployment/broker_integration.py",
    "deployment/broker_loopback_listener.py",
    "deployment/broker_service_bootstrap.py",
    "deployment/broker_service_config.py",
    "deployment/broker_service_config_loader.py",
    "deployment/broker_service_entrypoint.py",
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
    "deployment/oci_verifier.py",
    "deployment/oidc_verifier.py",
    "deployment/policy.py",
    "deployment/promotion.py",
    "deployment/registry_oidc_credentials.py",
    "deployment/registry_promotion_composition.py",
    "deployment/replay_sqlite.py",
    "deployment/release_consumer.py",
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
    """The fixed current selection, with no caller-selected paths or files."""

    application_root: str = _field(init=False, default=_layout_default("application_root"))
    entrypoint_modules: tuple[str, str] = _field(init=False, default=(
        _layout_default("executor_module"), "deployment.broker_service_entrypoint"))
    files: tuple[ApplicationSourceFile, ...] = _field(init=False, default=_FILES)
