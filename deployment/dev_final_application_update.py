"""Explicit root-only C32W migration of complete C31/C32D to the C32V tree.

No import, construction, or ordinary qualification mutates the host. The two
zero-argument public operations have no CLI, service entry point, or network.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, replace
import hashlib
import os
import stat

from . import application_manifest as c26
from . import dev_host_provisioning_mechanics as c31b
from . import dev_host_provisioning_orchestration as c31
from . import dev_post_c31_application_update as c32d
from . import dev_post_provision_qualification as c31d
from . import dev_host_qualification as c29
from . import executor_service_config as c17
from . import final_application_generation as frozen


__all__ = ("FinalApplicationUpdateError", "FinalApplicationUpdateState",
           "qualify_final_application_update", "update_final_application")

_ERROR = "final DEV application update is unavailable"
_CONFIG = c17.PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH
_APP_ROOT = "/opt/omnilyzer/deployment/app"
_APP_UID = 0
_APP_GID = 0
_CONFIG_UID = 0
_APP_STAGE = ".omnilyzer-c32w-application.tmp"
_CONFIG_STAGE = ".omnilyzer-c32w-configuration.tmp"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class FinalApplicationUpdateError(Exception):
    """One fixed non-diagnostic public failure."""


@dataclass(frozen=True, slots=True)
class FinalApplicationUpdateState:
    selected_commit: str
    advanced_count: int
    plan_count: int
    application_stage_length: int | None
    configuration_stage_length: int | None
    configuration_current: bool

    def __post_init__(self) -> None:
        if (type(self.selected_commit) is not str
                or self.selected_commit not in (c32d.PREDECESSOR, c32d.TARGET,
                                                frozen.TARGET_REVIEWED_COMMIT)
                or type(self.advanced_count) is not int or not 0 <= self.advanced_count <= 16
                or type(self.plan_count) is not int or self.plan_count != 16
                or (self.application_stage_length is not None
                    and (type(self.application_stage_length) is not int
                         or self.application_stage_length < 0))
                or (self.configuration_stage_length is not None
                    and (type(self.configuration_stage_length) is not int
                         or self.configuration_stage_length < 0))
                or type(self.configuration_current) is not bool
                or (self.configuration_current
                    and (self.selected_commit != frozen.TARGET_REVIEWED_COMMIT
                         or self.advanced_count != self.plan_count
                         or self.application_stage_length is not None
                         or self.configuration_stage_length is not None))):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class _Entries:
    entries: tuple[c26.ApplicationManifestEntry, ...]


def _configuration() -> tuple[c17.DevExecutorServiceConfiguration, bytes, bytes]:
    """Select generation from the installed canonical executor configuration."""
    raw = c29._read_small_regular(_CONFIG, c17.MAX_EXECUTOR_SERVICE_CONFIG_BYTES)
    installed = c17.parse_canonical_executor_service_configuration(raw)
    if installed.reviewed_commit not in (c32d.PREDECESSOR, c32d.TARGET,
                                          frozen.TARGET_REVIEWED_COMMIT):
        raise OSError
    if (installed.canonical_bytes() != raw
            or installed.runtime_configuration_sha256 != frozen.TARGET_RUNTIME_SHA256
            or installed.ingress_file_sha256 != frozen.TARGET_INGRESS_SHA256):
        raise OSError
    original = replace(installed, reviewed_commit=c32d.PREDECESSOR)
    if hashlib.sha256(original.canonical_bytes()).hexdigest() != c32d.PREDECESSOR_C17:
        raise OSError
    target = replace(installed, reviewed_commit=frozen.TARGET_REVIEWED_COMMIT)
    before = installed.to_dict()
    after = target.to_dict()
    if {key for key in before if before[key] != after[key]} - {"reviewed_commit"}:
        raise OSError
    return installed, raw, target.canonical_bytes()


def _evidence(selected: str):
    target, blobs = frozen._reviewed_target()
    c31_manifest, c32d_manifest, _c32d_blobs = c32d._evidence()
    previous = c31_manifest if selected == c32d.PREDECESSOR else c32d_manifest
    if selected not in (c32d.PREDECESSOR, c32d.TARGET):
        raise OSError
    old_bytes = dict(c32d._git_blobs(selected, tuple(item.path for item in previous.entries)))
    target_bytes = dict(blobs)
    old_paths = tuple(item.path for item in previous.entries)
    target_paths = tuple(item.path for item in target.entries)
    if (not set(old_paths) < set(target_paths)
            or len(target_paths) != frozen.TARGET_PATH_COUNT
            or len(old_paths) != (28 if selected == c32d.PREDECESSOR else 31)):
        raise OSError
    plan = tuple(path for path in target_paths
                 if path not in old_bytes or old_bytes[path] != target_bytes[path])
    added = sum(path not in old_bytes for path in plan)
    if (len(plan) != 16
            or (added, len(plan) - added) != ((13, 3) if selected == c32d.PREDECESSOR
                                               else (10, 6))
            or hashlib.sha256(("\n".join(plan) + "\n").encode()).hexdigest()
            != frozen.TARGET_PLAN_SHA256):
        raise OSError
    return previous, target, target_bytes, plan, frozenset(old_paths)


def _mixed(previous: c26.DevApplicationManifest, target: c26.DevApplicationManifest,
           plan: tuple[str, ...], count: int) -> _Entries:
    selected = {entry.path: entry for entry in previous.entries}
    future = {entry.path: entry for entry in target.entries}
    for path in plan[:count]:
        selected[path] = future[path]
    return _Entries(tuple(selected[path] for path in sorted(selected)))


def _app_directory(owned: list[int]):
    root, chain = c31b._open_directory(_APP_ROOT, owned)
    root_status = os.fstat(root)
    if (stat.S_IMODE(root_status.st_mode), root_status.st_uid, root_status.st_gid) != (0o755, _APP_UID, _APP_GID):
        raise OSError
    directory = c31b._claim(os.open("deployment", _DIRECTORY_FLAGS, dir_fd=root), owned)
    opened = os.fstat(directory)
    if (not stat.S_ISDIR(opened.st_mode)
            or (stat.S_IMODE(opened.st_mode), opened.st_uid, opened.st_gid) != (0o755, _APP_UID, _APP_GID)
            or c31b._directory_fingerprint(opened) != c31b._directory_fingerprint(
                os.stat("deployment", dir_fd=root, follow_symlinks=False))):
        raise OSError
    return root, directory, chain


def _revalidate_app_directory(root: int, directory: int) -> None:
    opened = os.fstat(directory)
    named = os.stat("deployment", dir_fd=root, follow_symlinks=False)
    if (not stat.S_ISDIR(opened.st_mode)
            or (stat.S_IMODE(opened.st_mode), opened.st_uid, opened.st_gid)
            != (0o755, _APP_UID, _APP_GID)
            or c31b._directory_fingerprint(opened)
            != c31b._directory_fingerprint(named)):
        raise OSError


def _application_state(previous, target, blobs, plan):
    owned: list[int] = []
    try:
        root, directory, chain = _app_directory(owned)
        for count in range(len(plan) + 1):
            try:
                payload = blobs[plan[count]] if count < len(plan) else None
                stage = c32d._stage(directory, _APP_STAGE, payload, 0o644, _APP_UID, _APP_GID)
                c31b._verify_application(root, _mixed(previous, target, plan, count), _APP_UID, _APP_GID,
                                          ("deployment/" + _APP_STAGE, stage[2]) if stage else None)
                if c32d._stage(directory, _APP_STAGE, payload, 0o644, _APP_UID, _APP_GID) != stage:
                    raise OSError
                _revalidate_app_directory(root, directory)
                c31b._revalidate_chain(chain)
                return count, stage
            except OSError:
                continue
        raise OSError
    finally:
        c31b._finish_close(owned)


def _target_application_state(target: c26.DevApplicationManifest) -> None:
    owned: list[int] = []
    try:
        root, _directory, chain = _app_directory(owned)
        c31b._verify_application(root, target, _APP_UID, _APP_GID)
        _revalidate_app_directory(root, _directory)
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def _inspect(previous, target, blobs, plan, old_raw, target_raw) -> FinalApplicationUpdateState:
    count, app_stage = _application_state(previous, target, blobs, plan)
    current, config_stage, _gid = c32d._config_state(old_raw, target_raw, count == len(plan))
    if current and count != len(plan):
        raise OSError
    return FinalApplicationUpdateState(
        previous.reviewed_commit, count, len(plan),
        app_stage[0] if app_stage else None,
        config_stage[0] if config_stage else None, False,
    )


def _qualify_state(configuration, raw, target_raw, previous, target, blobs, plan):
    if configuration.reviewed_commit == frozen.TARGET_REVIEWED_COMMIT:
        _target_application_state(target)
        c32d._config_state(replace(configuration, reviewed_commit=c32d.TARGET).canonical_bytes(),
                           target_raw, True)
        evidence = c31d.qualify_dev_provisioned_host(
            configuration=configuration, application_manifest=target)
        if type(evidence) is not c31d.DevPostProvisionEvidence:
            raise OSError
        _target_application_state(target)
        return FinalApplicationUpdateState(frozen.TARGET_REVIEWED_COMMIT, 16, 16,
                                           None, None, True)
    state = _inspect(previous, target, blobs, plan, raw, target_raw)
    if (state.advanced_count == 0 and state.application_stage_length is None
            and state.configuration_stage_length is None):
        evidence = c31d.qualify_dev_provisioned_host(
            configuration=configuration, application_manifest=previous)
        if type(evidence) is not c31d.DevPostProvisionEvidence:
            raise OSError
    else:
        c32d._qualify_non_application(configuration, previous, raw)
    if _inspect(previous, target, blobs, plan, raw, target_raw) != state:
        raise OSError
    return state


def _load():
    configuration, raw, target_raw = _configuration()
    if configuration.reviewed_commit == frozen.TARGET_REVIEWED_COMMIT:
        target, _blobs = frozen._reviewed_target()
        return configuration, raw, target_raw, None, target, None, None, None
    previous, target, blobs, plan, old_paths = _evidence(configuration.reviewed_commit)
    return configuration, raw, target_raw, previous, target, blobs, plan, old_paths


def qualify_final_application_update() -> FinalApplicationUpdateState:
    """Read-only proof of complete predecessor, exact prefix, or final target."""
    try:
        configuration, raw, target_raw, previous, target, blobs, plan, _old = _load()
        return _qualify_state(configuration, raw, target_raw, previous, target, blobs, plan)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise FinalApplicationUpdateError(_ERROR) from None


def _rename_noreplace(directory: int, source: str, destination: str) -> None:
    """Linux atomic exclusive publication for newly added application files."""
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.renameat2
    operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    operation.restype = ctypes.c_int
    if operation(directory, source.encode("ascii"), directory,
                 destination.encode("ascii"), 1) != 0:  # RENAME_NOREPLACE
        raise OSError(ctypes.get_errno())


def _write_add_stage(directory: int, destination: str, payload: bytes,
                     stage: tuple[int, int, tuple[int, ...]] | None) -> None:
    """Write a prefix and atomically publish without replacing any target."""
    try:
        os.stat(destination, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise OSError
    if stage is None:
        descriptor = os.open(_APP_STAGE, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        length = 0
    else:
        descriptor = os.open(_APP_STAGE, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK, dir_fd=directory)
        length = stage[0]
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_uid, opened.st_gid) != (_APP_UID, _APP_GID)
                or opened.st_size != length
                or stat.S_IMODE(opened.st_mode) != (stage[1] if stage else 0o600)
                or (stage is not None and c31b._fingerprint(opened) != stage[2])
                or c31b._fingerprint(opened) != c31b._fingerprint(
                    os.stat(_APP_STAGE, dir_fd=directory, follow_symlinks=False))):
            raise OSError
        if length:
            check = os.open(_APP_STAGE, _FILE_FLAGS, dir_fd=directory)
            try:
                before = os.fstat(check)
                content, _digest = c31b._read_hash(check, length, c31b._MAX_BLOB)
                if (content != payload[:length]
                        or c31b._fingerprint(before) != c31b._fingerprint(os.fstat(check))
                        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
                    raise OSError
            finally:
                os.close(check)
        if length < len(payload):
            if stat.S_IMODE(opened.st_mode) != 0o600:
                raise OSError
            os.lseek(descriptor, length, os.SEEK_SET)
            c31b._write_all(descriptor, payload[length:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        if (staged.st_size != len(payload) or staged.st_nlink != 1
                or (staged.st_uid, staged.st_gid, stat.S_IMODE(staged.st_mode)) != (_APP_UID, _APP_GID, 0o644)):
            raise OSError
        check = os.open(_APP_STAGE, _FILE_FLAGS, dir_fd=directory)
        try:
            before = os.fstat(check)
            content, digest = c31b._read_hash(check, len(payload), c31b._MAX_BLOB)
            if (content != payload or digest != hashlib.sha256(payload).hexdigest()
                    or c31b._fingerprint(before) != c31b._fingerprint(staged)
                    or c31b._fingerprint(os.fstat(check)) != c31b._fingerprint(staged)
                    or c31b._fingerprint(os.stat(_APP_STAGE, dir_fd=directory,
                                                follow_symlinks=False)) != c31b._fingerprint(staged)):
                raise OSError
        finally:
            os.close(check)
        _rename_noreplace(directory, _APP_STAGE, destination)
        os.fsync(directory)
        if c31b._fingerprint(os.stat(destination, dir_fd=directory,
                                    follow_symlinks=False)) != c31b._fingerprint(os.fstat(descriptor)):
            raise OSError
    finally:
        os.close(descriptor)


def _advance_application(previous, target, blobs, plan, old_paths, old_raw, target_raw,
                         state: FinalApplicationUpdateState) -> None:
    if state.advanced_count:
        c32d._sync_directory(_APP_ROOT + "/deployment", 0o755, _APP_UID, _APP_GID)
        if _inspect(previous, target, blobs, plan, old_raw, target_raw) != state:
            raise OSError
    relative = plan[state.advanced_count]
    payload = blobs[relative]
    owned: list[int] = []
    try:
        root, directory, chain = _app_directory(owned)
        stage = c32d._stage(directory, _APP_STAGE, payload, 0o644, _APP_UID, _APP_GID)
        if (stage[0] if stage else None) != state.application_stage_length:
            raise OSError
        c31b._verify_application(root, _mixed(previous, target, plan, state.advanced_count),
                                  _APP_UID, _APP_GID, ("deployment/" + _APP_STAGE, stage[2]) if stage else None)
        c31b._revalidate_chain(chain)
        destination = relative.split("/", 1)[1]
        if relative in old_paths:
            c32d._write_replace_stage(directory, _APP_STAGE, destination,
                                      payload, 0o644, _APP_UID, _APP_GID, stage)
        else:
            _write_add_stage(directory, destination, payload, stage)
        _revalidate_app_directory(root, directory)
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def _advance_configuration(configuration, previous, target, blobs, plan, old_raw,
                           target_raw, state: FinalApplicationUpdateState) -> None:
    c32d._sync_directory(_APP_ROOT + "/deployment", 0o755, _APP_UID, _APP_GID)
    if _inspect(previous, target, blobs, plan, old_raw, target_raw) != state:
        raise OSError
    owned: list[int] = []
    try:
        parent, name, chain = c31b._open_parent(_CONFIG, owned)
        opened_parent = os.fstat(parent)
        if (stat.S_IMODE(opened_parent.st_mode), opened_parent.st_uid,
                opened_parent.st_gid) != (0o750, _CONFIG_UID, configuration.executor_gid):
            raise OSError
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = c31b._claim(os.open(name, _FILE_FLAGS, dir_fd=parent), owned)
        opened = os.fstat(descriptor)
        if (c31b._fingerprint(named) != c31b._fingerprint(opened)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode))
                != (_CONFIG_UID, configuration.executor_gid, 0o640)
                or opened.st_size != len(old_raw)):
            raise OSError
        content, _digest = c31b._read_hash(descriptor, opened.st_size,
                                           c17.MAX_EXECUTOR_SERVICE_CONFIG_BYTES)
        if (content != old_raw or c31b._fingerprint(os.fstat(descriptor)) != c31b._fingerprint(opened)
                or c31b._fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False))
                != c31b._fingerprint(opened)):
            raise OSError
        stage = c32d._stage(parent, _CONFIG_STAGE, target_raw, 0o640,
                           _CONFIG_UID, configuration.executor_gid, _CONFIG_UID)
        if (stage[0] if stage else None) != state.configuration_stage_length:
            raise OSError
        c31b._revalidate_chain(chain)
        c32d._write_replace_stage(parent, _CONFIG_STAGE, name, target_raw,
                                  0o640, _CONFIG_UID, configuration.executor_gid, stage)
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def update_final_application() -> FinalApplicationUpdateState:
    """Explicit future mutation, serialized by the existing process lock."""
    lock = None
    try:
        effective_uid, effective_gid = os.geteuid(), os.getegid()
        if (type(effective_uid) is not int or effective_uid != 0
                or type(effective_gid) is not int or effective_gid != 0):
            raise OSError
        lock = c31._acquire_process_lock()
        configuration, raw, target_raw, previous, target, blobs, plan, old_paths = _load()
        while True:
            state = _qualify_state(configuration, raw, target_raw,
                                   previous, target, blobs, plan)
            if state.configuration_current:
                c32d._sync_directory(os.path.dirname(_CONFIG), 0o750,
                                     _CONFIG_UID, configuration.executor_gid)
                return state
            if state.advanced_count < len(plan):
                _advance_application(previous, target, blobs, plan, old_paths,
                                     raw, target_raw, state)
            else:
                _advance_configuration(configuration, previous, target, blobs,
                                       plan, raw, target_raw, state)
                configuration, raw, target_raw, previous, target, blobs, plan, old_paths = _load()
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise FinalApplicationUpdateError(_ERROR) from None
    finally:
        if lock is not None:
            try:
                c31._release_process_lock(lock)
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                raise FinalApplicationUpdateError(_ERROR) from None
