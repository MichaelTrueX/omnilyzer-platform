"""Closed, inert C31C DEV persistent-state prerequisite mechanics."""

from dataclasses import dataclass as _dataclass
import gzip as _gzip
import hashlib as _hashlib
import io as _io
import json as _json
import os as _os
import stat as _stat
import sys as _sys
import threading as _threading
import time as _time

from . import audit as _audit
from . import executor_service_config as _c17
from . import host_provisioning_contract as _c23
from . import privileged_host_runtime as _c30
from . import replay_sqlite as _replay
from . import state_store as _store
from .policy import SCHEMA_VERSION as _SCHEMA_VERSION
from .state import DeploymentState as _DeploymentState, MigrationState as _MigrationState

__all__ = (
    "PersistentStatePrerequisiteError",
    "DevInitialStateEvidence",
    "PersistentPrerequisiteEvidence",
    "dev_initial_state",
    "DevPersistentStatePrerequisites",
)

_ERROR = "DEV persistent state prerequisites are unavailable"
_MODEL_ERROR = "DEV persistent state prerequisite evidence is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_BOOTSTRAP_TIMESTAMP = "1970-01-01T00:00:00Z"
_BOOTSTRAP_EVENT_ID = "bootstrap-initial-state-v1"
_STATE_PATH = "/var/lib/omnilyzer/deployment/dev/state.json"
_REPLAY_PATH = "/var/lib/omnilyzer/deployment/authority/replay.sqlite3"
_AUDIT_PATH = "/var/log/omnilyzer/deployment/dev/events.jsonl"
_MAX_AUDIT_ENTRIES = _audit.ROTATION_RETENTION + 2
_AUDIT_HISTORY_LIMIT = _audit.ROTATE_BYTES + _audit.MAX_EVENT_BYTES
# gzip's DEFLATE framing overhead is far below this conservative finite bound.
# Keeping twice the maximum legitimate expanded history plus 64 KiB admits every
# file emitted by FilesystemAuditSink while bounding attacker-controlled input.
_AUDIT_COMPRESSED_INPUT_LIMIT = 2 * _AUDIT_HISTORY_LIMIT + 65_536
_READ_CHUNK = 64 * 1024


class PersistentStatePrerequisiteError(Exception):
    """One closed C31C prerequisite could not be established or verified."""


def _initial_mapping() -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "stage": "dev",
        "active_release": None,
        "active_source_sha": None,
        "active_digest": None,
        "active_slot": None,
        "previous_release": None,
        "previous_source_sha": None,
        "previous_digest": None,
        "previous_slot": None,
        "candidate_release": None,
        "candidate_source_sha": None,
        "candidate_digest": None,
        "candidate_slot": None,
        "migration_state": {
            "status": "none",
            "identity": None,
            "checksum": None,
            "serialized_lock_required": True,
        },
        "updated_at": _BOOTSTRAP_TIMESTAMP,
        "event_id": _BOOTSTRAP_EVENT_ID,
    }


@_dataclass(frozen=True, slots=True)
class DevInitialStateEvidence:
    """Repository-owned canonical bootstrap state and byte identity."""

    state: _DeploymentState
    canonical_bytes: bytes
    sha256: str

    def __post_init__(self) -> None:
        try:
            if type(self.state) is not _DeploymentState:
                raise ValueError
            if type(self.state.migration_state) is not _MigrationState:
                raise ValueError
            expected = _DeploymentState.from_dict(_initial_mapping())
            canonical = expected.canonical_bytes()
            if (
                self.state != expected
                or type(self.canonical_bytes) is not bytes
                or self.canonical_bytes != canonical
                or type(self.sha256) is not str
                or self.sha256 != _hashlib.sha256(canonical).hexdigest()
            ):
                raise ValueError
        except _CONTROL:
            raise
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


def dev_initial_state() -> DevInitialStateEvidence:
    """Return the exact zero-input no-active DEV bootstrap state."""

    state = _DeploymentState.from_dict(_initial_mapping())
    canonical = state.canonical_bytes()
    return DevInitialStateEvidence(
        state, canonical, _hashlib.sha256(canonical).hexdigest(),
    )


@_dataclass(frozen=True, slots=True)
class PersistentPrerequisiteEvidence:
    """One explicit persistent-resource observation."""

    resource: str
    kind: str
    outcome: str
    entry_count: int

    def __post_init__(self) -> None:
        allowed = {
            (_STATE_PATH, "deployment_state", "initialized"),
            (_STATE_PATH, "deployment_state", "unchanged"),
            (_STATE_PATH, "deployment_state", "existing"),
            (_STATE_PATH, "deployment_state", "verified-initial"),
            (_STATE_PATH, "deployment_state", "verified-existing"),
            (_REPLAY_PATH, "replay_database", "initialized"),
            (_REPLAY_PATH, "replay_database", "existing"),
            (_REPLAY_PATH, "replay_database", "verified"),
            (_AUDIT_PATH, "audit_history", "pristine"),
            (_AUDIT_PATH, "audit_history", "existing"),
        }
        if (
            type(self.resource) is not str
            or type(self.kind) is not str
            or type(self.outcome) is not str
            or (self.resource, self.kind, self.outcome) not in allowed
            or type(self.entry_count) is not int
            or not 0 <= self.entry_count <= _MAX_AUDIT_ENTRIES
            or (self.kind != "audit_history" and self.entry_count != 1)
            or (self.outcome == "pristine" and self.entry_count != 0)
            or (self.kind == "audit_history" and self.outcome == "existing"
                and self.entry_count < 1)
        ):
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class _Resource:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    lifecycle: str


@_dataclass(frozen=True, slots=True)
class _Authority:
    configuration: _c17.DevExecutorServiceConfiguration
    runtime: _c30.DevPrivilegedHostRuntime
    state_directory: _Resource
    state_file: _Resource
    replay_directory: _Resource
    replay_database: _Resource
    audit_directory: _Resource
    audit_file: _Resource
    replay_clock: object


def _resource(value: object) -> _Resource:
    return _Resource(
        object.__getattribute__(value, "path"),
        object.__getattribute__(value, "kind"),
        object.__getattribute__(value, "mode"),
        object.__getattribute__(value, "owner_uid"),
        object.__getattribute__(value, "group_gid"),
        object.__getattribute__(value, "lifecycle"),
    )


def _build_authority(configuration: object) -> _Authority:
    if type(configuration) is not _c17.DevExecutorServiceConfiguration:
        raise TypeError(_MODEL_ERROR)
    try:
        installation = configuration.installation_contract()
        provisioning = _c23.DevHostProvisioningContract(installation=installation)
        values = {
            item.path: _resource(item)
            for item in provisioning.runtime_resource_requirements()
        }
        expected = {
            "/var/lib/omnilyzer/deployment/dev": (
                "directory", 0o700, installation.executor_uid,
                installation.executor_gid, "must-exist-before-activation",
            ),
            _STATE_PATH: (
                "regular_file", 0o600, installation.executor_uid,
                installation.executor_gid,
                "must-contain-canonical-no-active-state-before-activation",
            ),
            "/var/lib/omnilyzer/deployment/authority": (
                "directory", 0o770, 0, installation.replay_group_gid,
                "must-exist-before-replay-initialization",
            ),
            _REPLAY_PATH: (
                "sqlite_database", 0o660, 0, installation.replay_group_gid,
                "future-reviewed-replay-initialization-only",
            ),
            "/var/log/omnilyzer/deployment/dev": (
                "directory", 0o700, installation.executor_uid,
                installation.executor_gid, "must-exist-before-activation",
            ),
            _AUDIT_PATH: (
                "regular_file", 0o600, installation.executor_uid,
                installation.executor_gid, "may-be-created-on-first-audit-append",
            ),
        }
        if set(expected) - set(values):
            raise ValueError
        for path, required in expected.items():
            item = values[path]
            if (item.kind, item.mode, item.uid, item.gid, item.lifecycle) != required:
                raise ValueError
        return _Authority(
            configuration, _c30.DevPrivilegedHostRuntime(configuration=configuration),
            values["/var/lib/omnilyzer/deployment/dev"], values[_STATE_PATH],
            values["/var/lib/omnilyzer/deployment/authority"], values[_REPLAY_PATH],
            values["/var/log/omnilyzer/deployment/dev"], values[_AUDIT_PATH],
            lambda: int(_time.time()),
        )
    except _CONTROL:
        raise
    except Exception:
        raise TypeError(_MODEL_ERROR) from None


def _state_configuration(authority: _Authority) -> _store._Configuration:
    components = authority.state_file.path.split("/")[1:-1]
    return _store._build_configuration(
        path=authority.state_file.path,
        owner_uid=authority.state_file.uid,
        group_gid=authority.state_file.gid,
        owned_start=len(components) - 1,
    )


def _state_store(authority: _Authority) -> _store.FilesystemDeploymentStateStore:
    value = _store.FilesystemDeploymentStateStore(
        expected_owner_uid=authority.state_file.uid,
        expected_group_gid=authority.state_file.gid,
    )
    object.__setattr__(value, "_configuration", _state_configuration(authority))
    return value


def _same_initial(state: _DeploymentState, raw: bytes) -> bool:
    initial = dev_initial_state()
    return state == initial.state and raw == initial.canonical_bytes


def _cleanup_created_state(
    configuration: _store._Configuration, directory: int,
    identity: tuple[int, int] | None,
) -> None:
    if identity is None:
        return
    named = configuration.stat_at(
        configuration.state_name, dir_fd=directory, follow_symlinks=False,
    )
    fields = configuration.status_parser(named)
    if (
        (fields[2], fields[1]) != identity
        or not _stat.S_ISREG(fields[0])
        or _stat.S_ISLNK(fields[0])
        or fields[3] != 1
    ):
        raise OSError
    if configuration.unlink(configuration.state_name, dir_fd=directory) is not None:
        raise OSError
    if configuration.fsync(directory) is not None:
        raise OSError


def _initialize_state_action(
    configuration: _store._Configuration, directory: int,
    chain: list[tuple[int, tuple[int, int], int]], owned: dict[int, bool],
    canonical: bytes,
) -> tuple[_DeploymentState, str]:
    entries = configuration.entries(configuration, directory)
    if entries == frozenset({configuration.state_name}):
        state, _identity, _descriptor, raw = configuration.read_validated_state(
            configuration, directory, chain, owned,
        )
        return state, "unchanged" if _same_initial(state, raw) else "existing"
    if entries:
        raise OSError
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    completed = False
    try:
        descriptor = configuration.open_file(
            configuration.state_name, configuration.create_flags,
            configuration.state_file_mode, dir_fd=directory,
        )
        if type(descriptor) is not int or descriptor < 0 or descriptor in owned:
            raise OSError
        owned[descriptor] = True
        if configuration.get_inheritable(descriptor) is not False:
            raise OSError
        status = configuration.fstat(descriptor)
        fields = configuration.status_parser(status)
        identity = (fields[2], fields[1])
        if not _stat.S_ISREG(fields[0]) or fields[3] != 1:
            raise OSError
        _os.fchown(descriptor, configuration.owner_uid, configuration.group_gid)
        _os.fchmod(descriptor, configuration.state_file_mode)
        configuration.write_all(configuration, descriptor, canonical)
        if configuration.fsync(descriptor) is not None:
            raise OSError
        resulting = configuration.state_file_validator(
            configuration.fstat(descriptor),
            uid=configuration.owner_uid, gid=configuration.group_gid,
        )
        if resulting[:2] != identity or resulting[2] != len(canonical):
            raise OSError
        named = configuration.state_file_validator(
            configuration.stat_at(
                configuration.state_name, dir_fd=directory, follow_symlinks=False,
            ),
            uid=configuration.owner_uid, gid=configuration.group_gid,
        )
        if named != resulting:
            raise OSError
        if configuration.fsync(directory) is not None:
            raise OSError
        state, read_identity, _reader, raw = configuration.read_validated_state(
            configuration, directory, chain, owned,
        )
        if read_identity != resulting or raw != canonical or not _same_initial(state, raw):
            raise OSError
        completed = True
        return state, "initialized"
    finally:
        if not completed:
            active = _sys.exception()
            try:
                _cleanup_created_state(configuration, directory, identity)
            except _CONTROL:
                if not isinstance(active, _CONTROL):
                    raise
            except BaseException:
                if active is None:
                    raise


def _initialize_state(authority: _Authority) -> PersistentPrerequisiteEvidence:
    initial = dev_initial_state()
    store = _state_store(authority)
    configuration = object.__getattribute__(store, "_configuration")
    result = store._operate(
        _initialize_state_action, initial.canonical_bytes,
    )
    if (
        type(result) is not tuple or len(result) != 2
        or type(result[0]) is not _DeploymentState
        or result[1] not in ("initialized", "unchanged", "existing")
    ):
        raise OSError
    loaded = store.load()
    if loaded != result[0]:
        raise OSError
    return PersistentPrerequisiteEvidence(
        _STATE_PATH, "deployment_state", result[1], 1,
    )


def _verify_state(authority: _Authority) -> PersistentPrerequisiteEvidence:
    store = _state_store(authority)
    loaded = store.load()
    canonical = loaded.canonical_bytes()
    reparsed = _DeploymentState.from_dict(_json.loads(canonical))
    if reparsed != loaded or reparsed.canonical_bytes() != canonical:
        raise OSError
    return PersistentPrerequisiteEvidence(
        _STATE_PATH, "deployment_state",
        "verified-initial" if _same_initial(loaded, canonical) else "verified-existing",
        1,
    )


def _replay_guard(authority: _Authority) -> _replay.SQLiteReplayGuard:
    return _replay.SQLiteReplayGuard(
        authority.replay_database.path,
        expected_directory_uid=authority.replay_directory.uid,
        expected_directory_gid=authority.replay_directory.gid,
        current_time=authority.replay_clock,  # type: ignore[arg-type]
    )


def _replay_present(guard: _replay.SQLiteReplayGuard) -> bool:
    descriptor = guard._open_directory()
    try:
        entries = guard._bounded_entries(descriptor)
        guard._validate_directory_descriptor(descriptor, expected_entries=entries)
        if not entries:
            return False
        if _replay.REPLAY_FILENAME not in entries or not entries <= {
            _replay.REPLAY_FILENAME, _replay.REPLAY_FILENAME + "-journal",
        }:
            raise OSError
        return True
    finally:
        _os.close(descriptor)


def _initialize_replay(authority: _Authority) -> PersistentPrerequisiteEvidence:
    guard = _replay_guard(authority)
    present = _replay_present(guard)
    if present:
        guard.validate()
        outcome = "existing"
    else:
        guard.initialize()
        outcome = "initialized"
    guard.validate()
    return PersistentPrerequisiteEvidence(
        _REPLAY_PATH, "replay_database", outcome, 1,
    )


def _verify_replay(authority: _Authority) -> PersistentPrerequisiteEvidence:
    guard = _replay_guard(authority)
    if not _replay_present(guard):
        raise OSError
    guard.validate()
    return PersistentPrerequisiteEvidence(
        _REPLAY_PATH, "replay_database", "verified", 1,
    )


def _directory_identity(value: _os.stat_result) -> tuple[int, ...]:
    return value.st_mode, value.st_ino, value.st_dev, value.st_uid, value.st_gid


def _file_fingerprint(value: _os.stat_result) -> tuple[int, ...]:
    return (
        value.st_mode, value.st_ino, value.st_dev, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _open_audit_directory(
    authority: _Authority,
) -> tuple[list[int], list[tuple[int, int | None, str | None, tuple[int, ...]]]]:
    directory_path = authority.audit_directory.path
    parts = directory_path.split("/")[1:]
    flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    owned: list[int] = []
    chain = []
    parent = _os.open("/", flags)
    owned.append(parent)
    root = _os.fstat(parent)
    chain.append((parent, None, None, _directory_identity(root)))
    for index, component in enumerate(parts):
        named = _os.stat(component, dir_fd=parent, follow_symlinks=False)
        child = _os.open(component, flags, dir_fd=parent)
        owned.append(child)
        opened = _os.fstat(child)
        final = index == len(parts) - 1
        if (
            not _stat.S_ISDIR(opened.st_mode)
            or _stat.S_ISLNK(opened.st_mode)
            or _directory_identity(opened) != _directory_identity(named)
        ):
            raise OSError
        if final:
            if (
                _stat.S_IMODE(opened.st_mode) != authority.audit_directory.mode
                or (opened.st_uid, opened.st_gid)
                != (authority.audit_directory.uid, authority.audit_directory.gid)
            ):
                raise OSError
        elif opened.st_uid != 0 or (
            _stat.S_IMODE(opened.st_mode) & 0o022
            and not (opened.st_uid == 0 and opened.st_mode & _stat.S_ISVTX)
        ):
            raise OSError
        chain.append((child, parent, component, _directory_identity(opened)))
        parent = child
    return owned, chain


def _audit_observation(authority: _Authority) -> PersistentPrerequisiteEvidence:
    owned: list[int] = []
    file_descriptors: list[tuple[int, str, tuple[int, ...]]] = []
    try:
        owned, chain = _open_audit_directory(authority)
        directory = owned[-1]
        with _os.scandir(directory) as iterator:
            names = tuple(sorted(entry.name for entry in iterator))
        if len(names) > _MAX_AUDIT_ENTRIES or len(names) != len(set(names)):
            raise OSError
        history_names = []
        for name in names:
            if name == ".events.lock":
                maximum = 0
            elif (
                name == authority.audit_file.path.rsplit("/", 1)[1]
                or _audit.ROTATED_RE.fullmatch(name)
            ):
                maximum = (
                    _AUDIT_COMPRESSED_INPUT_LIMIT
                    if name.endswith(".gz") else _AUDIT_HISTORY_LIMIT
                )
                history_names.append(name)
            else:
                raise OSError
            named = _os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                not _stat.S_ISREG(named.st_mode)
                or _stat.S_ISLNK(named.st_mode)
                or named.st_nlink != 1
                or _stat.S_IMODE(named.st_mode) != authority.audit_file.mode
                or (named.st_uid, named.st_gid)
                != (authority.audit_file.uid, authority.audit_file.gid)
                or (maximum > 0 and named.st_size == 0)
                or named.st_size > maximum
            ):
                raise OSError
            descriptor = _os.open(
                name, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                dir_fd=directory,
            )
            owned.append(descriptor)
            opened = _os.fstat(descriptor)
            fingerprint = _file_fingerprint(opened)
            if fingerprint != _file_fingerprint(named):
                raise OSError
            file_descriptors.append((descriptor, name, fingerprint))
        _validate_audit_history_descriptors(
            file_descriptors,
            current_name=authority.audit_file.path.rsplit("/", 1)[1],
        )
        for descriptor, name, expected in file_descriptors:
            if (
                _file_fingerprint(_os.fstat(descriptor)) != expected
                or _file_fingerprint(
                    _os.stat(name, dir_fd=directory, follow_symlinks=False)
                ) != expected
            ):
                raise OSError
        for descriptor, parent, name, expected in chain:
            opened = _os.fstat(descriptor)
            named = (
                _os.stat("/", follow_symlinks=False)
                if parent is None
                else _os.stat(name, dir_fd=parent, follow_symlinks=False)
            )
            if _directory_identity(opened) != expected or _directory_identity(named) != expected:
                raise OSError
        return PersistentPrerequisiteEvidence(
            _AUDIT_PATH, "audit_history",
            "existing" if history_names else "pristine", len(history_names),
        )
    finally:
        active = _sys.exception()
        control = None
        failed = False
        for descriptor in reversed(owned):
            try:
                _os.close(descriptor)
            except _CONTROL as error:
                if control is None:
                    control = error
            except Exception:
                failed = True
        if control is not None and not isinstance(active, _CONTROL):
            raise control
        if failed and active is None:
            raise OSError


def _read_audit_descriptor(
    descriptor: int, name: str, expected: tuple[int, ...],
) -> bytes:
    compressed = name.endswith(".gz")
    physical_limit = (
        _AUDIT_COMPRESSED_INPUT_LIMIT if compressed else _AUDIT_HISTORY_LIMIT
    )
    before = _os.fstat(descriptor)
    if _file_fingerprint(before) != expected or before.st_size > physical_limit:
        raise OSError
    _os.lseek(descriptor, 0, _os.SEEK_SET)
    remaining = before.st_size
    chunks: list[bytes] = []
    while remaining:
        chunk = _os.read(descriptor, min(_READ_CHUNK, remaining))
        if not chunk:
            raise OSError
        chunks.append(chunk)
        remaining -= len(chunk)
    if _os.read(descriptor, 1) != b"":
        raise OSError
    if _file_fingerprint(_os.fstat(descriptor)) != expected:
        raise OSError
    raw = b"".join(chunks)
    if not compressed:
        return raw
    try:
        with _gzip.GzipFile(fileobj=_io.BytesIO(raw), mode="rb") as stream:
            expanded = stream.read(_AUDIT_HISTORY_LIMIT + 1)
            if len(expanded) > _AUDIT_HISTORY_LIMIT or stream.read(1) != b"":
                raise OSError
    except (OSError, EOFError):
        raise OSError from None
    return expanded


def _validate_audit_history_descriptors(
    values: list[tuple[int, str, tuple[int, ...]]], *, current_name: str,
) -> None:
    history = [item for item in values if item[1] != ".events.lock"]
    rotations = sorted(
        (item for item in history if item[1] != current_name),
        key=lambda item: item[1],
    )
    current = [item for item in history if item[1] == current_name]
    ordered = rotations + current
    previous: str | None = None
    event_ids: set[str] = set()
    anchored_retained_history = bool(ordered and ordered[0][1] != current_name)
    first = True
    for descriptor, name, expected in ordered:
        raw = _read_audit_descriptor(descriptor, name, expected)
        records = _audit.FilesystemAuditSink._decode_lines(raw, name)
        for record in records:
            if first and anchored_retained_history:
                previous = record.previous_event_sha256
            if record.previous_event_sha256 != previous:
                raise OSError
            if record.event.event_id in event_ids:
                raise OSError
            event_ids.add(record.event.event_id)
            previous = record.sha256()
            first = False


def _directory_result(
    authority: _Authority, resource: _Resource,
) -> _c30.HostMutationEvidence:
    result = authority.runtime.create_required_directory(resource.path)
    if type(result) is not _c30.HostMutationEvidence:
        raise OSError
    _c30.HostMutationEvidence.__post_init__(result)
    if result.resource_kind != "directory" or result.resource != resource.path:
        raise OSError
    return result


class DevPersistentStatePrerequisites:
    """Closed C31C state/replay/audit mechanics with no arbitrary authority."""

    __slots__ = ("_authority", "_lock")

    def __init__(self, *, configuration: _c17.DevExecutorServiceConfiguration) -> None:
        object.__setattr__(self, "_authority", _build_authority(configuration))
        object.__setattr__(self, "_lock", _threading.Lock())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_MODEL_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_MODEL_ERROR)

    def _operate(self, operation: str) -> PersistentPrerequisiteEvidence | tuple[PersistentPrerequisiteEvidence, ...]:
        lock = object.__getattribute__(self, "_lock")
        if not lock.acquire(blocking=False):
            raise PersistentStatePrerequisiteError(_ERROR) from None
        try:
            authority = object.__getattribute__(self, "_authority")
            if operation == "state":
                _directory_result(authority, authority.state_directory)
                return _initialize_state(authority)
            if operation == "replay":
                _directory_result(authority, authority.replay_directory)
                return _initialize_replay(authority)
            if operation == "audit":
                _directory_result(authority, authority.audit_directory)
                return _audit_observation(authority)
            if operation == "verify":
                return (
                    _verify_state(authority), _verify_replay(authority),
                    _audit_observation(authority),
                )
            raise TypeError
        except _CONTROL:
            raise
        except Exception:
            raise PersistentStatePrerequisiteError(_ERROR) from None
        finally:
            lock.release()

    def initialize_deployment_state(self) -> PersistentPrerequisiteEvidence:
        """Create only the absent canonical state, or preserve valid history."""
        result = self._operate("state")
        if type(result) is not PersistentPrerequisiteEvidence:
            raise PersistentStatePrerequisiteError(_ERROR) from None
        return result

    def initialize_replay(self) -> PersistentPrerequisiteEvidence:
        """Compose exact C30 directory handling and SQLite replay lifecycle."""
        result = self._operate("replay")
        if type(result) is not PersistentPrerequisiteEvidence:
            raise PersistentStatePrerequisiteError(_ERROR) from None
        return result

    def prepare_audit(self) -> PersistentPrerequisiteEvidence:
        """Prepare only the audit directory and preserve all existing history."""
        result = self._operate("audit")
        if type(result) is not PersistentPrerequisiteEvidence:
            raise PersistentStatePrerequisiteError(_ERROR) from None
        return result

    def verify_persistent_prerequisites(self) -> tuple[PersistentPrerequisiteEvidence, ...]:
        """Read-only verify state, replay and pristine-or-existing audit state."""
        result = self._operate("verify")
        if type(result) is not tuple or len(result) != 3 or any(
            type(item) is not PersistentPrerequisiteEvidence for item in result
        ):
            raise PersistentStatePrerequisiteError(_ERROR) from None
        return result
