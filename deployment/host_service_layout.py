"""deployment/host_service_layout.py — fixed inert C21 DEV host-service layout.

Describe future installation paths, symbolic principals and reserved unit names.
C13 installation_contract retains numeric identities and resource ownership;
C17 executor_service_config retains exact runtime numeric identities. C20
executor_service_entrypoint retains module execution and process exit behavior.
The existing Unix transport constant remains the executor socket-path authority.
Symbolic principal names do not provision users/groups or select numeric IDs.
Import and construction are pure and inert: no filesystem or host inspection
occurs. No systemd unit exists, installs or starts here; no Docker/sudo privilege
is granted. Deployment authority remains disabled pending GitHub protections.
"""

from dataclasses import dataclass as _dataclass, field as _field
from pathlib import PurePosixPath as _PurePosixPath
from re import fullmatch as _fullmatch

from .unix_transport import (
    PRODUCTION_EXECUTOR_SOCKET_PATH as _PRODUCTION_EXECUTOR_SOCKET_PATH,
)

__all__ = (
    "DevHostServiceLayout",
)


# Pure textual validation never resolves a path or principal on the host.
def _valid_path(value: object) -> bool:
    """Require a canonical absolute POSIX path outside temporary/home trees."""
    if type(value) is not str or not value or "\0" in value:
        return False
    path = _PurePosixPath(value)
    return (
        path.is_absolute()
        and not value.startswith("//")
        and not value.endswith("/")
        and str(path) == value
        and not any(part in (".", "..") for part in value.split("/"))
        and not any(path.is_relative_to(root) for root in ("/home", "/tmp", "/var/tmp"))
    )


def _valid_principal(value: object) -> bool:
    """Validate a symbolic lowercase ASCII system-principal name only."""
    return type(value) is str and _fullmatch(r"[a-z][a-z0-9-]{0,30}", value) is not None


def _valid_unit(value: object, suffix: str) -> bool:
    """Require the reserved exact unit stem and the appropriate suffix."""
    return type(value) is str and value == "omnilyzer-deployment-executor" + suffix


# All reviewed defaults are immutable and excluded from constructor inputs.
@_dataclass(frozen=True, slots=True)
class DevHostServiceLayout:
    """Describe one closed future DEV service layout with zero caller inputs."""

    installation_root: str = _field(init=False, default="/opt/omnilyzer/deployment")
    application_root: str = _field(init=False, default="/opt/omnilyzer/deployment/app")
    virtualenv_root: str = _field(init=False, default="/opt/omnilyzer/deployment/venv")
    python_executable: str = _field(init=False, default="/opt/omnilyzer/deployment/venv/bin/python")
    working_directory: str = _field(init=False, default="/opt/omnilyzer/deployment/app")
    executor_module: str = _field(init=False, default="deployment.executor_service_entrypoint")
    executor_exec_argv: tuple[str, str, str] = _field(init=False, default=(
        "/opt/omnilyzer/deployment/venv/bin/python", "-m", "deployment.executor_service_entrypoint",
    ))
    broker_user: str = _field(init=False, default="omnilyzer-broker")
    broker_group: str = _field(init=False, default="omnilyzer-broker")
    executor_user: str = _field(init=False, default="omnilyzer-executor")
    executor_group: str = _field(init=False, default="omnilyzer-executor")
    replay_group: str = _field(init=False, default="omnilyzer-replay")
    socket_group: str = _field(init=False, default="omnilyzer-deployment")
    executor_socket_path: str = _field(init=False, default=_PRODUCTION_EXECUTOR_SOCKET_PATH)
    executor_service_unit_name: str = _field(init=False, default="omnilyzer-deployment-executor.service")
    executor_socket_unit_name: str = _field(init=False, default="omnilyzer-deployment-executor.socket")

    def __post_init__(self) -> None:
        """Fail closed with a fixed error if the repository contract is defective."""
        paths = (
            self.installation_root, self.application_root, self.virtualenv_root,
            self.python_executable, self.working_directory, self.executor_socket_path,
        )
        principals = (
            self.broker_user, self.broker_group, self.executor_user,
            self.executor_group, self.replay_group, self.socket_group,
        )
        valid = (
            all(_valid_path(value) for value in paths)
            and _PurePosixPath(self.application_root).parent == _PurePosixPath(self.installation_root)
            and _PurePosixPath(self.virtualenv_root).parent == _PurePosixPath(self.installation_root)
            and self.python_executable == self.virtualenv_root + "/bin/python"
            and self.working_directory == self.application_root
            and type(self.executor_module) is str
            and self.executor_module == "deployment.executor_service_entrypoint"
            and type(self.executor_exec_argv) is tuple
            and len(self.executor_exec_argv) == 3
            and all(type(value) is str for value in self.executor_exec_argv)
            and self.executor_exec_argv == (self.python_executable, "-m", self.executor_module)
            and all(_valid_principal(value) for value in principals)
            and self.broker_user == self.broker_group
            and self.executor_user == self.executor_group
            and len(frozenset((self.broker_group, self.executor_group, self.replay_group, self.socket_group))) == 4
            and self.executor_socket_path == _PRODUCTION_EXECUTOR_SOCKET_PATH
            and _valid_unit(self.executor_service_unit_name, ".service")
            and _valid_unit(self.executor_socket_unit_name, ".socket")
        )
        if not valid:
            raise ValueError("DEV host service layout is invalid")
