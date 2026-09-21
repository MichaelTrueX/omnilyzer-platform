"""deployment/state_store.py — hardened fixed-path DEV state persistence.

Purpose: implement the inert ``load``/``save`` collaborator consumed by
``deployment/deployment_operation.py`` while retaining the authoritative model
and canonical format from ``deployment/state.py`` and ``deployment/policy.py``.
This module never initializes the production directory or state file.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import json
import os
import stat
import sys
import threading
from typing import Any, Callable

from .policy import canonical_bytes
from .state import DeploymentState, MigrationState


PRODUCTION_DEV_STATE_PATH = "/var/lib/omnilyzer/deployment/dev/state.json"
STATE_STORE_UNAVAILABLE_MESSAGE = "deployment state storage is unavailable"
STATE_DIRECTORY_MODE = 0o700
STATE_FILE_MODE = 0o600
MAX_STATE_BYTES = 16 * 1024
MAX_READ_CALLS = 64
MAX_WRITE_CALLS = 64
MAX_IDENTITY_VALUE = 2**32 - 2
_TEMPORARY_NAME = ".state.json.tmp"
_CONFIGURATION_MESSAGE = "deployment state store configuration is invalid"


class StateStoreUnavailableError(Exception):
    """The persisted DEV state could not be used trustworthily."""


def _unavailable(
    error_type: type[StateStoreUnavailableError] = StateStoreUnavailableError,
    message: str = STATE_STORE_UNAVAILABLE_MESSAGE,
) -> StateStoreUnavailableError:
    return error_type(message)


def _make_operation_gate() -> tuple[
    Callable[[str], bool], Callable[[str], None],
]:
    active: set[str] = set()
    lock = threading.Lock()

    def enter(key: str) -> bool:
        with lock:
            if key in active:
                return False
            active.add(key)
            return True

    def leave(key: str) -> None:
        with lock:
            active.remove(key)

    return enter, leave


_ENTER_OPERATION, _LEAVE_OPERATION = _make_operation_gate()


@dataclass(frozen=True)
class _Configuration:
    path: str
    components: tuple[str, ...]
    state_name: str
    temporary_name: str
    owned_start: int
    owner_uid: int
    group_gid: int
    state_file_mode: int
    state_type: type[DeploymentState]
    directory_flags: int
    read_flags: int
    create_flags: int
    lock_exclusive_nonblocking: int
    lock_unlock: int
    open_file: Callable[..., object]
    close_file: Callable[[int], object]
    get_inheritable: Callable[[int], object]
    stat_at: Callable[..., object]
    fstat: Callable[[int], object]
    read: Callable[[int, int], object]
    write: Callable[[int, object], object]
    fsync: Callable[[int], object]
    replace: Callable[..., object]
    unlink: Callable[..., object]
    scandir: Callable[[int], object]
    flock: Callable[[int, int], object]
    state_parser: Callable[[Any], DeploymentState]
    canonicalizer: Callable[[Any], bytes]
    enter_operation: Callable[[str], bool]
    leave_operation: Callable[[str], None]
    open_chain: Callable[..., Any]
    revalidate_chain: Callable[..., Any]
    close_owned: Callable[..., Any]
    read_validated_state: Callable[..., Any]
    write_all: Callable[..., Any]
    cleanup_temporary: Callable[..., Any]
    open_state: Callable[..., Any]
    bounded_read: Callable[..., Any]
    parse_persisted: Callable[..., Any]
    snapshot_state: Callable[..., Any]
    status_parser: Callable[..., Any]
    state_file_validator: Callable[..., Any]
    temporary_file_validator: Callable[..., Any]
    entries: Callable[..., Any]
    load_action: Callable[..., Any]
    save_action: Callable[..., Any]
    unavailable: Callable[[], StateStoreUnavailableError]


def _configuration_integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_IDENTITY_VALUE:
        raise TypeError(_CONFIGURATION_MESSAGE)
    return value


def _build_configuration(
    *, path: str, owner_uid: int, group_gid: int, owned_start: int,
    state_file_mode: int = STATE_FILE_MODE,
) -> _Configuration:
    if type(path) is not str or not path.startswith("/") or path.startswith("//"):
        raise TypeError(_CONFIGURATION_MESSAGE)
    parts = path.split("/")
    if len(parts) < 3 or parts[0] != "" or any(
        type(part) is not str or part in {"", ".", ".."} or "\x00" in part
        for part in parts[1:]
    ):
        raise TypeError(_CONFIGURATION_MESSAGE)
    components = tuple(parts[1:-1])
    if type(owned_start) is not int or not 0 <= owned_start < len(components):
        raise TypeError(_CONFIGURATION_MESSAGE)
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(type(getattr(os, name, None)) is not int for name in required):
        raise TypeError(_CONFIGURATION_MESSAGE)
    if any(type(getattr(fcntl, name, None)) is not int for name in ("LOCK_EX", "LOCK_NB", "LOCK_UN")):
        raise TypeError(_CONFIGURATION_MESSAGE)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    read_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    create_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    return _Configuration(
        path, components, parts[-1], _TEMPORARY_NAME, owned_start,
        owner_uid, group_gid, state_file_mode, DeploymentState,
        directory_flags, read_flags, create_flags,
        fcntl.LOCK_EX | fcntl.LOCK_NB, fcntl.LOCK_UN,
        os.open, os.close, os.get_inheritable, os.stat, os.fstat,
        os.read, os.write, os.fsync,
        os.replace, os.unlink, os.scandir, fcntl.flock,
        DeploymentState.from_dict, canonical_bytes,
        _ENTER_OPERATION, _LEAVE_OPERATION,
        _open_chain, _revalidate_chain, _close_owned, _read_validated_state,
        _write_all, _cleanup_temporary, _open_state, _bounded_read,
        _parse_persisted, _snapshot_state,
        _status, _validate_state_file, _validate_temporary_file, _entries,
        FilesystemDeploymentStateStore._load_action,
        FilesystemDeploymentStateStore._save_action,
        _unavailable,
    )


def _status(
    value: object, stat_result_type: type[os.stat_result] = os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    if type(value) is not stat_result_type or tuple.__len__(value) < 7:
        raise OSError("invalid state metadata")
    fields = tuple(tuple.__getitem__(value, index) for index in range(7))
    if not all(type(item) is int for item in fields):
        raise OSError("invalid state metadata")
    mode, inode, device, links, uid, gid, size = fields
    if inode < 0 or device < 0 or links < 1 or uid < 0 or gid < 0 or size < 0:
        raise OSError("invalid state metadata")
    return mode, inode, device, links, uid, gid, size


def _validate_standard_directory(
    value: object, status_parser: Callable[..., tuple[int, ...]] = _status,
    is_directory: Callable[[int], bool] = stat.S_ISDIR,
    is_symlink: Callable[[int], bool] = stat.S_ISLNK,
    file_mode: Callable[[int], int] = stat.S_IMODE,
) -> tuple[int, int]:
    mode, inode, device, _links, uid, _gid, _size = status_parser(value)
    writable = file_mode(mode) & 0o022
    sticky_root = uid == 0 and bool(file_mode(mode) & stat.S_ISVTX)
    if (
        not is_directory(mode)
        or is_symlink(mode)
        or uid != 0
        or (writable and not sticky_root)
    ):
        raise OSError("unsafe standard ancestor")
    return device, inode


def _validate_owned_directory(
    value: object, *, uid: int, gid: int, final: bool,
    status_parser: Callable[..., tuple[int, ...]] = _status,
    is_directory: Callable[[int], bool] = stat.S_ISDIR,
    is_symlink: Callable[[int], bool] = stat.S_ISLNK,
    file_mode: Callable[[int], int] = stat.S_IMODE,
    required_final_mode: int = STATE_DIRECTORY_MODE,
) -> tuple[int, int]:
    mode, inode, device, _links, actual_uid, actual_gid, _size = status_parser(value)
    permissions = file_mode(mode)
    if (
        not is_directory(mode)
        or is_symlink(mode)
        or actual_uid != uid
        or actual_gid != gid
        or permissions & 0o022
        or permissions & 0o700 != 0o700
        or (final and permissions != required_final_mode)
    ):
        raise OSError("unsafe deployment ancestor")
    return device, inode


def _validate_state_file(
    value: object, *, uid: int, gid: int,
    maximum: int = MAX_STATE_BYTES,
    status_parser: Callable[..., tuple[int, ...]] = _status,
    is_regular: Callable[[int], bool] = stat.S_ISREG,
    is_symlink: Callable[[int], bool] = stat.S_ISLNK,
    file_mode: Callable[[int], int] = stat.S_IMODE,
    required_mode: int = STATE_FILE_MODE,
) -> tuple[int, int, int]:
    mode, inode, device, links, actual_uid, actual_gid, size = status_parser(value)
    if (
        not is_regular(mode)
        or is_symlink(mode)
        or file_mode(mode) != required_mode
        or links != 1
        or actual_uid != uid
        or actual_gid != gid
        or not 0 < size <= maximum
    ):
        raise OSError("invalid deployment state file")
    return device, inode, size


def _validate_temporary_file(
    value: object, *, uid: int, gid: int,
    maximum: int = MAX_STATE_BYTES,
    status_parser: Callable[..., tuple[int, ...]] = _status,
    is_regular: Callable[[int], bool] = stat.S_ISREG,
    is_symlink: Callable[[int], bool] = stat.S_ISLNK,
    file_mode: Callable[[int], int] = stat.S_IMODE,
    required_mode: int = STATE_FILE_MODE,
) -> tuple[int, int]:
    mode, inode, device, links, actual_uid, actual_gid, size = status_parser(value)
    if (
        not is_regular(mode)
        or is_symlink(mode)
        or file_mode(mode) != required_mode
        or links != 1
        or actual_uid != uid
        or actual_gid != gid
        or size > maximum
    ):
        raise OSError("invalid temporary state file")
    return device, inode


def _state_mapping(
    state: DeploymentState,
    state_type: type[DeploymentState] = DeploymentState,
    migration_type: type[MigrationState] = MigrationState,
) -> dict[str, object]:
    if type(state) is not state_type:
        raise TypeError("invalid deployment state")
    migration = object.__getattribute__(state, "migration_state")
    if type(migration) is not migration_type:
        raise TypeError("invalid deployment state")
    names = (
        "schema_version", "stage", "active_release", "active_source_sha",
        "active_digest", "active_slot", "previous_release",
        "previous_source_sha", "previous_digest", "previous_slot",
        "candidate_release", "candidate_source_sha", "candidate_digest",
        "candidate_slot", "updated_at", "event_id",
    )
    result = {name: object.__getattribute__(state, name) for name in names}
    if type(result["schema_version"]) is not int:
        raise TypeError("invalid deployment state")
    for name in names[1:]:
        if result[name] is not None and type(result[name]) is not str:
            raise TypeError("invalid deployment state")
    migration_names = (
        "status", "identity", "checksum", "serialized_lock_required",
    )
    migration_value = {
        name: object.__getattribute__(migration, name) for name in migration_names
    }
    for name in migration_names[:3]:
        if migration_value[name] is not None and type(migration_value[name]) is not str:
            raise TypeError("invalid deployment state")
    if migration_value["serialized_lock_required"] is not True:
        raise TypeError("invalid deployment state")
    result["migration_state"] = migration_value
    return result


def _snapshot_state(
    state: DeploymentState, parser: Callable[[Any], DeploymentState],
    canonicalizer: Callable[[Any], bytes],
    mapping: Callable[[DeploymentState], dict[str, object]] = _state_mapping,
    loads: Callable[[str | bytes], Any] = json.loads,
    maximum: int = MAX_STATE_BYTES,
    state_type: type[DeploymentState] = DeploymentState,
) -> tuple[DeploymentState, bytes]:
    first = mapping(state)
    first_bytes = canonicalizer(first)
    second = mapping(state)
    second_bytes = canonicalizer(second)
    if type(first_bytes) is not bytes or first_bytes != second_bytes:
        raise TypeError("invalid deployment state")
    rebuilt = parser(loads(first_bytes))
    if (
        type(rebuilt) is not state_type
        or object.__getattribute__(rebuilt, "stage") != "dev"
    ):
        raise TypeError("invalid deployment state")
    rebuilt_bytes = canonicalizer(mapping(rebuilt))
    if type(rebuilt_bytes) is not bytes or rebuilt_bytes != first_bytes:
        raise TypeError("invalid deployment state")
    if not 0 < len(first_bytes) <= maximum:
        raise TypeError("invalid deployment state")
    return rebuilt, first_bytes


def _parse_persisted(
    raw: bytes, parser: Callable[[Any], DeploymentState],
    canonicalizer: Callable[[Any], bytes],
    loads: Callable[..., Any] = json.loads,
    mapping: Callable[[DeploymentState], dict[str, object]] = _state_mapping,
    maximum: int = MAX_STATE_BYTES,
    state_type: type[DeploymentState] = DeploymentState,
) -> DeploymentState:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise OSError("invalid persisted state")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if type(key) is not str or key in result:
                raise ValueError("invalid persisted state")
            result[key] = value
        return result

    def constant(_value: str) -> Any:
        raise ValueError("invalid persisted state")

    try:
        decoded = loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant,
        )
        if type(decoded) is not dict:
            raise ValueError("invalid persisted state")
        state = parser(decoded)
        if (
            type(state) is not state_type
            or object.__getattribute__(state, "stage") != "dev"
        ):
            raise ValueError("invalid persisted state")
        normalized = canonicalizer(mapping(state))
    except (UnicodeDecodeError, ValueError, TypeError, OverflowError):
        raise OSError("invalid persisted state") from None
    if type(normalized) is not bytes or normalized != raw:
        raise OSError("noncanonical persisted state")
    return state


def _entries(
    configuration: _Configuration, directory_fd: int,
    current_exception: Callable[[], BaseException | None] = sys.exception,
) -> frozenset[str]:
    iterator = configuration.scandir(directory_fd)
    values: list[str] = []
    try:
        for _index in range(3):
            try:
                entry = next(iterator)  # type: ignore[arg-type]
            except StopIteration:
                break
            name = object.__getattribute__(entry, "name")
            if type(name) is not str:
                raise OSError("invalid state directory entry")
            values.append(name)
    finally:
        active = current_exception()
        try:
            close = object.__getattribute__(iterator, "close")
            if not callable(close) or close() is not None:
                raise OSError("state directory scan cleanup failed")
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            if not isinstance(active, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
        except BaseException:
            if not isinstance(active, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
    if len(values) > 2 or len(values) != len(set(values)):
        raise OSError("invalid state directory entries")
    return frozenset(values)


def _open_chain(
    configuration: _Configuration, owned: dict[int, bool],
    standard_validator: Callable[[object], tuple[int, int]] = _validate_standard_directory,
    owned_validator: Callable[..., tuple[int, int]] = _validate_owned_directory,
) -> tuple[list[tuple[int, tuple[int, int], int]], int]:
    opened: list[tuple[int, tuple[int, int], int]] = []
    root = configuration.open_file("/", configuration.directory_flags)
    if type(root) is not int or root < 0:
        raise OSError("invalid directory descriptor")
    owned[root] = True
    if configuration.get_inheritable(root) is not False:
        raise OSError("inheritable directory descriptor")
    root_status = configuration.fstat(root)
    root_named = configuration.stat_at("/", follow_symlinks=False)
    root_identity = standard_validator(root_status)
    if root_identity != standard_validator(root_named):
        raise OSError("root directory changed")
    opened.append((root, root_identity, -1))
    parent = root
    for index, component in enumerate(configuration.components):
        named = configuration.stat_at(
            component, dir_fd=parent, follow_symlinks=False,
        )
        child = configuration.open_file(
            component, configuration.directory_flags, dir_fd=parent,
        )
        if type(child) is not int or child < 0 or child in owned:
            raise OSError("invalid directory descriptor")
        owned[child] = True
        if configuration.get_inheritable(child) is not False:
            raise OSError("inheritable directory descriptor")
        opened_status = configuration.fstat(child)
        final = index == len(configuration.components) - 1
        if index < configuration.owned_start:
            named_identity = standard_validator(named)
            opened_identity = standard_validator(opened_status)
        else:
            named_identity = owned_validator(
                named, uid=configuration.owner_uid,
                gid=configuration.group_gid, final=final,
            )
            opened_identity = owned_validator(
                opened_status, uid=configuration.owner_uid,
                gid=configuration.group_gid, final=final,
            )
        if named_identity != opened_identity:
            raise OSError("directory identity mismatch")
        opened.append((child, opened_identity, index))
        parent = child
    return opened, parent


def _revalidate_chain(
    configuration: _Configuration,
    opened: list[tuple[int, tuple[int, int], int]],
    standard_validator: Callable[[object], tuple[int, int]] = _validate_standard_directory,
    owned_validator: Callable[..., tuple[int, int]] = _validate_owned_directory,
) -> None:
    for position, (descriptor, expected, index) in enumerate(opened):
        opened_status = configuration.fstat(descriptor)
        if index == -1:
            named = configuration.stat_at("/", follow_symlinks=False)
            actual = standard_validator(opened_status)
            named_identity = standard_validator(named)
        else:
            parent = opened[position - 1][0]
            component = configuration.components[index]
            named = configuration.stat_at(
                component, dir_fd=parent, follow_symlinks=False,
            )
            final = index == len(configuration.components) - 1
            if index < configuration.owned_start:
                actual = standard_validator(opened_status)
                named_identity = standard_validator(named)
            else:
                actual = owned_validator(
                    opened_status, uid=configuration.owner_uid,
                    gid=configuration.group_gid, final=final,
                )
                named_identity = owned_validator(
                    named, uid=configuration.owner_uid,
                    gid=configuration.group_gid, final=final,
                )
        if actual != expected or named_identity != expected:
            raise OSError("directory identity changed")


def _open_state(
    configuration: _Configuration, directory_fd: int,
    owned: dict[int, bool],
    file_validator: Callable[..., tuple[int, int, int]] = _validate_state_file,
) -> tuple[int, tuple[int, int, int]]:
    named = configuration.stat_at(
        configuration.state_name, dir_fd=directory_fd, follow_symlinks=False,
    )
    named_identity = file_validator(
        named, uid=configuration.owner_uid, gid=configuration.group_gid,
    )
    descriptor = configuration.open_file(
        configuration.state_name, configuration.read_flags, dir_fd=directory_fd,
    )
    if type(descriptor) is not int or descriptor < 0 or descriptor in owned:
        raise OSError("invalid state descriptor")
    owned[descriptor] = True
    if configuration.get_inheritable(descriptor) is not False:
        raise OSError("inheritable state descriptor")
    opened_identity = file_validator(
        configuration.fstat(descriptor),
        uid=configuration.owner_uid, gid=configuration.group_gid,
    )
    if opened_identity != named_identity:
        raise OSError("state descriptor identity mismatch")
    return descriptor, opened_identity


def _bounded_read(
    configuration: _Configuration, descriptor: int,
    maximum: int = MAX_STATE_BYTES, maximum_calls: int = MAX_READ_CALLS,
) -> bytes:
    pieces: list[bytes] = []
    total = 0
    for _index in range(maximum_calls):
        value = configuration.read(descriptor, maximum + 1 - total)
        if type(value) is not bytes:
            raise OSError("invalid state read")
        if not value:
            return b"".join(pieces)
        if len(value) > maximum + 1 - total:
            raise OSError("invalid state read")
        pieces.append(value)
        total += len(value)
        if total > maximum:
            raise OSError("oversized state")
    raise OSError("excessive state reads")


def _read_validated_state(
    configuration: _Configuration, directory_fd: int,
    opened_chain: list[tuple[int, tuple[int, int], int]],
    owned: dict[int, bool],
    file_validator: Callable[..., tuple[int, int, int]] = _validate_state_file,
) -> tuple[DeploymentState, tuple[int, int, int], int, bytes]:
    if configuration.entries(configuration, directory_fd) != frozenset({
        configuration.state_name,
    }):
        raise OSError("invalid state directory contents")
    descriptor, identity = configuration.open_state(
        configuration, directory_fd, owned,
    )
    raw = configuration.bounded_read(configuration, descriptor)
    if len(raw) != identity[2]:
        raise OSError("state size changed")
    opened_identity = file_validator(
        configuration.fstat(descriptor),
        uid=configuration.owner_uid, gid=configuration.group_gid,
    )
    named_identity = file_validator(
        configuration.stat_at(
            configuration.state_name, dir_fd=directory_fd,
            follow_symlinks=False,
        ),
        uid=configuration.owner_uid, gid=configuration.group_gid,
    )
    if opened_identity != identity or named_identity != identity:
        raise OSError("state identity changed")
    configuration.revalidate_chain(configuration, opened_chain)
    if configuration.entries(configuration, directory_fd) != frozenset({
        configuration.state_name,
    }):
        raise OSError("state directory contents changed")
    state = configuration.parse_persisted(
        raw, configuration.state_parser, configuration.canonicalizer,
    )
    return state, identity, descriptor, raw


def _write_all(
    configuration: _Configuration, descriptor: int, value: bytes,
    maximum_calls: int = MAX_WRITE_CALLS,
) -> None:
    offset = 0
    view = memoryview(value)
    for _index in range(maximum_calls):
        if offset == len(value):
            return
        written = configuration.write(descriptor, view[offset:])
        if type(written) is not int or not 1 <= written <= len(value) - offset:
            raise OSError("invalid state write")
        offset += written
    raise OSError("excessive state writes")


def _close_owned(
    configuration: _Configuration, owned: dict[int, bool], descriptor: int,
) -> None:
    if not owned.get(descriptor, False):
        return
    owned[descriptor] = False
    if configuration.close_file(descriptor) is not None:
        raise OSError("descriptor cleanup failed")


def _cleanup_temporary(
    configuration: _Configuration, directory_fd: int,
    temporary_identity: tuple[int, int] | None,
    temporary_validator: Callable[..., tuple[int, int]] = _validate_temporary_file,
) -> None:
    if temporary_identity is None:
        return
    try:
        named = configuration.stat_at(
            configuration.temporary_name, dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    actual = temporary_validator(
        named, uid=configuration.owner_uid, gid=configuration.group_gid,
    )
    if actual != temporary_identity:
        raise OSError("temporary identity changed")
    if configuration.unlink(
        configuration.temporary_name, dir_fd=directory_fd,
    ) is not None:
        raise OSError("temporary cleanup failed")
    if configuration.fsync(directory_fd) is not None:
        raise OSError("temporary cleanup durability failed")


class FilesystemDeploymentStateStore:
    """Load and atomically save only the provisioned DEV state file."""

    __slots__ = ("_configuration",)

    def __init__(self, *, expected_owner_uid: int, expected_group_gid: int) -> None:
        owner_uid = _configuration_integer(expected_owner_uid)
        group_gid = _configuration_integer(expected_group_gid)
        configuration = _build_configuration(
            path="/var/lib/omnilyzer/deployment/dev/state.json",
            owner_uid=owner_uid, group_gid=group_gid, owned_start=4,
        )
        object.__setattr__(self, "_configuration", configuration)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("deployment state store configuration is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("deployment state store configuration is immutable")

    def _operate(self, action: Callable[..., Any], *arguments: object) -> Any:
        configuration = object.__getattribute__(self, "_configuration")
        owned: dict[int, bool] = {}
        opened_chain: list[tuple[int, tuple[int, int], int]] = []
        directory_fd: int | None = None
        lock_attempted = False
        entered = False
        result: object = None
        completed = False
        failed = False
        control: tuple[BaseException, object] | None = None
        try:
            entered = configuration.enter_operation(configuration.path)
            if not entered:
                raise OSError("state operation already active")
            opened_chain, directory_fd = configuration.open_chain(
                configuration, owned,
            )
            lock_attempted = True
            if configuration.flock(
                directory_fd, configuration.lock_exclusive_nonblocking,
            ) is not None:
                raise OSError("state lock failed")
            configuration.revalidate_chain(configuration, opened_chain)
            result = action(
                configuration, directory_fd, opened_chain, owned, *arguments,
            )
            completed = True
        except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
            control = (exc, exc.__traceback__)
        except BaseException:
            failed = True
        finally:
            for descriptor in reversed(tuple(owned)):
                if descriptor == directory_fd:
                    continue
                try:
                    configuration.close_owned(configuration, owned, descriptor)
                except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                    if control is None:
                        control = (exc, exc.__traceback__)
                except BaseException:
                    failed = True
            if lock_attempted and directory_fd is not None:
                try:
                    if configuration.flock(directory_fd, configuration.lock_unlock) is not None:
                        failed = True
                except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                    if control is None:
                        control = (exc, exc.__traceback__)
                except BaseException:
                    failed = True
            for descriptor in reversed(tuple(owned)):
                try:
                    configuration.close_owned(configuration, owned, descriptor)
                except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                    if control is None:
                        control = (exc, exc.__traceback__)
                except BaseException:
                    failed = True
            if entered:
                configuration.leave_operation(configuration.path)
        if control is not None:
            error, traceback = control
            raise error.with_traceback(traceback)
        if failed or not completed:
            raise configuration.unavailable() from None
        return result

    @staticmethod
    def _load_action(
        configuration: _Configuration, directory_fd: int,
        opened_chain: list[tuple[int, tuple[int, int], int]],
        owned: dict[int, bool],
    ) -> DeploymentState:
        state, _identity, _descriptor, _raw = configuration.read_validated_state(
            configuration, directory_fd, opened_chain, owned,
        )
        return state

    def load(self) -> DeploymentState:
        """Return one exact canonical base DeploymentState or fail closed."""

        configuration = object.__getattribute__(self, "_configuration")
        action = configuration.load_action
        result = self._operate(action)
        if type(result) is not configuration.state_type:
            raise configuration.unavailable() from None
        return result

    @staticmethod
    def _save_action(
        configuration: _Configuration, directory_fd: int,
        opened_chain: list[tuple[int, tuple[int, int], int]],
        owned: dict[int, bool], canonical: bytes,
        current_exception: Callable[[], BaseException | None] = sys.exception,
    ) -> None:
        _existing, original_identity, _original_fd, _raw = configuration.read_validated_state(
            configuration, directory_fd, opened_chain, owned,
        )
        temporary_fd: int | None = None
        temporary_identity: tuple[int, int] | None = None
        replaced = False
        try:
            temporary_fd_value = configuration.open_file(
                configuration.temporary_name, configuration.create_flags,
                configuration.state_file_mode, dir_fd=directory_fd,
            )
            if (
                type(temporary_fd_value) is not int
                or temporary_fd_value < 0
                or temporary_fd_value in owned
            ):
                raise OSError("invalid temporary descriptor")
            temporary_fd = temporary_fd_value
            owned[temporary_fd] = True
            if configuration.get_inheritable(temporary_fd) is not False:
                raise OSError("inheritable temporary descriptor")
            temporary_identity = configuration.temporary_file_validator(
                configuration.fstat(temporary_fd),
                uid=configuration.owner_uid, gid=configuration.group_gid,
            )
            named_temporary = configuration.temporary_file_validator(
                configuration.stat_at(
                    configuration.temporary_name, dir_fd=directory_fd,
                    follow_symlinks=False,
                ),
                uid=configuration.owner_uid, gid=configuration.group_gid,
            )
            if named_temporary != temporary_identity:
                raise OSError("temporary descriptor identity mismatch")
            if configuration.entries(configuration, directory_fd) != frozenset({
                configuration.state_name, configuration.temporary_name,
            }):
                raise OSError("invalid temporary directory contents")
            configuration.write_all(configuration, temporary_fd, canonical)
            if configuration.fsync(temporary_fd) is not None:
                raise OSError("temporary state fsync failed")
            if configuration.status_parser(configuration.fstat(temporary_fd))[6] != len(canonical):
                raise OSError("temporary state size mismatch")
            if configuration.status_parser(configuration.stat_at(
                configuration.temporary_name, dir_fd=directory_fd,
                follow_symlinks=False,
            ))[6] != len(canonical):
                raise OSError("temporary state size mismatch")
            temporary_after = configuration.temporary_file_validator(
                configuration.fstat(temporary_fd),
                uid=configuration.owner_uid, gid=configuration.group_gid,
            )
            named_after = configuration.temporary_file_validator(
                configuration.stat_at(
                    configuration.temporary_name, dir_fd=directory_fd,
                    follow_symlinks=False,
                ),
                uid=configuration.owner_uid, gid=configuration.group_gid,
            )
            if temporary_after != temporary_identity or named_after != temporary_identity:
                raise OSError("temporary state changed")
            current_original = configuration.state_file_validator(
                configuration.stat_at(
                    configuration.state_name, dir_fd=directory_fd,
                    follow_symlinks=False,
                ),
                uid=configuration.owner_uid, gid=configuration.group_gid,
            )
            if current_original != original_identity:
                raise OSError("original state changed")
            if configuration.state_file_validator(
                configuration.fstat(_original_fd),
                uid=configuration.owner_uid, gid=configuration.group_gid,
            ) != original_identity:
                raise OSError("original state descriptor changed")
            confirmation_fd, confirmation_identity = configuration.open_state(
                configuration, directory_fd, owned,
            )
            confirmation = configuration.bounded_read(
                configuration, confirmation_fd,
            )
            if confirmation_identity != original_identity or confirmation != _raw:
                raise OSError("original state content changed")
            configuration.parse_persisted(
                confirmation, configuration.state_parser,
                configuration.canonicalizer,
            )
            configuration.revalidate_chain(configuration, opened_chain)
            if configuration.replace(
                configuration.temporary_name, configuration.state_name,
                src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
            ) is not None:
                raise OSError("state replacement failed")
            replaced = True
            if configuration.fsync(directory_fd) is not None:
                raise OSError("state directory fsync failed")
            resulting = configuration.state_file_validator(
                configuration.stat_at(
                    configuration.state_name, dir_fd=directory_fd,
                    follow_symlinks=False,
                ),
                uid=configuration.owner_uid, gid=configuration.group_gid,
            )
            if resulting[:2] != temporary_identity:
                raise OSError("replacement identity mismatch")
            if configuration.entries(configuration, directory_fd) != frozenset({configuration.state_name}):
                raise OSError("invalid resulting directory contents")
            verify_fd, verify_identity = configuration.open_state(
                configuration, directory_fd, owned,
            )
            verified = configuration.bounded_read(configuration, verify_fd)
            if verify_identity != resulting or verified != canonical:
                raise OSError("state verification failed")
            configuration.parse_persisted(
                verified, configuration.state_parser, configuration.canonicalizer,
            )
            configuration.revalidate_chain(configuration, opened_chain)
        finally:
            if not replaced:
                active = current_exception()
                try:
                    configuration.cleanup_temporary(
                        configuration, directory_fd, temporary_identity,
                    )
                except (KeyboardInterrupt, SystemExit, GeneratorExit):
                    if not isinstance(active, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                        raise
                except BaseException:
                    if not isinstance(active, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                        raise
        return None

    def save(self, state: DeploymentState) -> None:
        """Atomically persist one exact validated DEV state snapshot."""

        configuration = object.__getattribute__(self, "_configuration")
        try:
            _snapshot, canonical = configuration.snapshot_state(
                state, configuration.state_parser, configuration.canonicalizer,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except BaseException:
            raise configuration.unavailable() from None
        result = self._operate(configuration.save_action, canonical)
        if result is not None:
            raise configuration.unavailable() from None
        return None


__all__ = (
    "FilesystemDeploymentStateStore",
    "PRODUCTION_DEV_STATE_PATH",
    "STATE_STORE_UNAVAILABLE_MESSAGE",
    "StateStoreUnavailableError",
)
