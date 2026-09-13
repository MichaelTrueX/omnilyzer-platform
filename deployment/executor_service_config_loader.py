"""deployment/executor_service_config_loader.py — hardened C17 loader.

Purpose: read the fixed C17 DEV executor configuration through a hardened,
descriptor-relative path and bind it to C13's numeric process identities.  The
loader is read-only: it never creates, provisions, or modifies ``/etc``.  It
does not acquire C16 socket activation or construct the C15 executor
composition.  Import is inert; only an explicit load performs host I/O.
"""

from __future__ import annotations

import os as _os
import stat as _stat

from .executor_service_config import (
    DevExecutorServiceConfiguration as _DevExecutorServiceConfiguration,
    EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE as _DIRECTORY_MODE,
    EXECUTOR_SERVICE_CONFIG_FILE_MODE as _FILE_MODE,
    MAX_EXECUTOR_SERVICE_CONFIG_BYTES as _MAX_BYTES,
    PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH as _CONFIG_PATH,
    parse_canonical_executor_service_configuration as _parse_configuration,
)
from .replay_sqlite import MAX_UID_GID as _MAX_UID_GID


__all__ = (
    "ExecutorServiceConfigurationUnavailableError",
    "load_dev_executor_service_configuration",
)

_ERROR = "DEV executor service configuration is unavailable"
_DIRECTORY_COMPONENTS = ("etc", "omnilyzer", "deployment", "dev")
_FILE_NAME = "executor.json"
_MAX_CONFIG_READ_CALLS = 64
_CONTROL_EXCEPTIONS = (KeyboardInterrupt, SystemExit, GeneratorExit)


class ExecutorServiceConfigurationUnavailableError(Exception):
    """The fixed DEV executor configuration could not be trusted."""


def _status(value: object) -> tuple[int, int, int, int, int, int, int]:
    """Return strictly typed security metadata from one stat result."""

    if type(value) is not _os.stat_result or tuple.__len__(value) < 7:
        raise OSError
    fields = tuple(tuple.__getitem__(value, index) for index in range(7))
    if any(type(item) is not int for item in fields):
        raise OSError
    mode, inode, device, links, uid, gid, size = fields
    if (
        mode < 0
        or uid > _MAX_UID_GID
        or inode < 0
        or device < 0
        or links < 1
        or uid < 0
        or gid < 0
        or gid > _MAX_UID_GID
        or size < 0
    ):
        raise OSError
    return mode, inode, device, links, uid, gid, size


def _standard_directory(value: object) -> tuple[int, ...]:
    """Validate a root-owned, non-writable standard configuration ancestor."""

    status = _status(value)
    mode, _inode, _device, _links, uid, _gid, _size = status
    permissions = _stat.S_IMODE(mode)
    if (
        not _stat.S_ISDIR(mode)
        or _stat.S_ISLNK(mode)
        or uid != 0
        or permissions & 0o022
    ):
        raise OSError
    return status


def _configuration_directory(value: object) -> tuple[int, ...]:
    """Validate the final root-owned C17 configuration directory policy."""

    status = _status(value)
    mode, _inode, _device, _links, uid, _gid, _size = status
    if (
        not _stat.S_ISDIR(mode)
        or _stat.S_ISLNK(mode)
        or uid != 0
        or _stat.S_IMODE(mode) != _DIRECTORY_MODE
    ):
        raise OSError
    return status


def _configuration_file(value: object) -> tuple[int, ...]:
    """Validate the bounded, single-link, root-owned C17 regular file."""

    status = _status(value)
    mode, _inode, _device, links, uid, _gid, size = status
    if (
        not _stat.S_ISREG(mode)
        or _stat.S_ISLNK(mode)
        or uid != 0
        or _stat.S_IMODE(mode) != _FILE_MODE
        or links != 1
        or not 0 < size <= _MAX_BYTES
    ):
        raise OSError
    return status


def _identity_value(value: object) -> int:
    """Validate one process UID or GID without coercion."""

    if type(value) is not int or not 0 <= value <= _MAX_UID_GID:
        raise OSError
    return value


def _process_identity() -> tuple[int, int, int, int, tuple[int, ...]]:
    """Capture one strict numeric process identity snapshot."""

    uid = _identity_value(_os.getuid())
    euid = _identity_value(_os.geteuid())
    gid = _identity_value(_os.getgid())
    egid = _identity_value(_os.getegid())
    groups_value = _os.getgroups()
    if type(groups_value) is not list:
        raise OSError
    groups = tuple(_identity_value(value) for value in groups_value)
    if len(set(groups)) != len(groups):
        raise OSError
    return uid, euid, gid, egid, groups


def _required_flags() -> tuple[int, int]:
    """Build the closed read-only directory and file flag sets."""

    names = ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if any(type(getattr(_os, name, None)) is not int for name in names):
        raise OSError
    directory_flags = (
        _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    )
    file_flags = _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK
    return directory_flags, file_flags


def _claim_descriptor(value: object, owned: list[int]) -> int:
    """Claim one new non-inheritable descriptor without accepting aliases."""

    if type(value) is not int or value < 0 or value in owned:
        raise OSError
    owned.append(value)
    if _os.get_inheritable(value) is not False:
        raise OSError
    return value


def _open_directories(
    owned: list[int], directory_flags: int,
) -> tuple[list[tuple[int, str | None, int | None, tuple[int, ...], bool]], int]:
    """Open and validate the fixed directory chain from the filesystem root."""

    root_named = _standard_directory(_os.stat("/", follow_symlinks=False))
    root_fd = _claim_descriptor(_os.open("/", directory_flags), owned)
    root_opened = _standard_directory(_os.fstat(root_fd))
    if root_named[1:3] != root_opened[1:3]:
        raise OSError
    opened = [(root_fd, None, None, root_opened, False)]
    parent_fd = root_fd
    for index, component in enumerate(_DIRECTORY_COMPONENTS):
        final = index == len(_DIRECTORY_COMPONENTS) - 1
        validator = _configuration_directory if final else _standard_directory
        named = validator(
            _os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
        )
        child_fd = _claim_descriptor(
            _os.open(component, directory_flags, dir_fd=parent_fd), owned,
        )
        descriptor = validator(_os.fstat(child_fd))
        if named[1:3] != descriptor[1:3]:
            raise OSError
        opened.append((child_fd, component, parent_fd, descriptor, final))
        parent_fd = child_fd
    return opened, parent_fd


def _open_configuration_file(
    directory_fd: int, file_flags: int, owned: list[int],
) -> tuple[int, tuple[int, ...]]:
    """Open the fixed filename relative to the validated final directory."""

    named = _configuration_file(
        _os.stat(_FILE_NAME, dir_fd=directory_fd, follow_symlinks=False)
    )
    descriptor = _claim_descriptor(
        _os.open(_FILE_NAME, file_flags, dir_fd=directory_fd), owned,
    )
    opened = _configuration_file(_os.fstat(descriptor))
    if named != opened:
        raise OSError
    return descriptor, opened


def _bounded_read(descriptor: int, expected_size: int) -> bytes:
    """Read the validated file with a byte ceiling and finite call count."""

    pieces: list[bytes] = []
    total = 0
    for _index in range(_MAX_CONFIG_READ_CALLS):
        remaining = _MAX_BYTES + 1 - total
        value = _os.read(descriptor, remaining)
        if type(value) is not bytes or len(value) > remaining:
            raise OSError
        if not value:
            raw = b"".join(pieces)
            if not raw or len(raw) != expected_size:
                raise OSError
            return raw
        pieces.append(value)
        total += len(value)
        if total > _MAX_BYTES:
            raise OSError
    raise OSError


def _revalidate_file(
    descriptor: int, directory_fd: int, expected: tuple[int, ...],
) -> None:
    """Revalidate opened and named file metadata after the complete read."""

    opened = _configuration_file(_os.fstat(descriptor))
    named = _configuration_file(
        _os.stat(_FILE_NAME, dir_fd=directory_fd, follow_symlinks=False)
    )
    if opened != expected or named != expected:
        raise OSError


def _revalidate_directories(
    opened: list[tuple[int, str | None, int | None, tuple[int, ...], bool]],
) -> tuple[int, ...]:
    """Revalidate the complete named and opened directory chain after reading."""

    for descriptor, component, parent_fd, expected, final in opened:
        validator = _configuration_directory if final else _standard_directory
        current = validator(_os.fstat(descriptor))
        if component is None:
            named = validator(_os.stat("/", follow_symlinks=False))
        else:
            named = validator(
                _os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            )
        if current[1:3] != expected[1:3] or named[1:3] != expected[1:3]:
            raise OSError
    return current


def _bind_configuration(
    configuration: _DevExecutorServiceConfiguration,
    identity: tuple[int, int, int, int, tuple[int, ...]],
    directory_status: tuple[int, ...],
    file_status: tuple[int, ...],
) -> None:
    """Bind C17 authority to file groups and the exact process identity."""

    uid, euid, gid, egid, groups = identity
    if (
        directory_status[5] != configuration.executor_gid
        or file_status[5] != configuration.executor_gid
        or uid != configuration.executor_uid
        or euid != configuration.executor_uid
        or gid != configuration.executor_gid
        or egid != configuration.executor_gid
    ):
        raise OSError
    required = configuration.installation_contract().executor_required_group_gids
    if (
        type(required) is not tuple
        or any(type(value) is not int for value in required)
        or set(groups) - {configuration.executor_gid} != set(required)
    ):
        raise OSError


def _close_owned(owned: list[int]) -> tuple[bool, BaseException | None]:
    """Close every owned descriptor once, recording cleanup failures."""

    failed = False
    control: BaseException | None = None
    for descriptor in reversed(owned):
        try:
            if _os.close(descriptor) is not None:
                failed = True
        except _CONTROL_EXCEPTIONS as exc:
            if control is None:
                control = exc
        except Exception:
            failed = True
    owned.clear()
    return failed, control


def _load(owned: list[int]) -> _DevExecutorServiceConfiguration:
    """Perform one complete hardened load while the caller owns cleanup."""

    if (
        type(_CONFIG_PATH) is not str
        or tuple(_CONFIG_PATH.split("/"))
        != ("", *_DIRECTORY_COMPONENTS, _FILE_NAME)
    ):
        raise OSError
    initial_identity = _process_identity()
    directory_flags, file_flags = _required_flags()
    directories, final_directory_fd = _open_directories(owned, directory_flags)
    file_fd, file_status = _open_configuration_file(
        final_directory_fd, file_flags, owned,
    )
    raw = _bounded_read(file_fd, file_status[6])
    configuration = _parse_configuration(raw)
    if type(configuration) is not _DevExecutorServiceConfiguration:
        raise OSError
    _revalidate_file(file_fd, final_directory_fd, file_status)
    final_directory_status = _revalidate_directories(directories)
    final_identity = _process_identity()
    if final_identity != initial_identity:
        raise OSError
    _bind_configuration(
        configuration, final_identity, final_directory_status, file_status,
    )
    return configuration


def load_dev_executor_service_configuration() -> _DevExecutorServiceConfiguration:
    """Read and validate the fixed C17 configuration during early bootstrap."""

    owned: list[int] = []
    try:
        result = _load(owned)
    except _CONTROL_EXCEPTIONS:
        _close_owned(owned)
        raise
    except Exception:
        _failed, cleanup_control = _close_owned(owned)
        if cleanup_control is not None:
            raise cleanup_control
        raise ExecutorServiceConfigurationUnavailableError(_ERROR) from None
    cleanup_failed, cleanup_control = _close_owned(owned)
    if cleanup_control is not None:
        raise cleanup_control
    if cleanup_failed:
        raise ExecutorServiceConfigurationUnavailableError(_ERROR) from None
    return result
