"""C33K narrow replacement of the reviewed rootless Docker launcher asset.

This transition changes exactly one installed regular file while the already
qualified rootless Docker daemon remains running. It performs no systemd,
Docker, network, package, sub-ID, or deployment action.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_restart_preflight as restart_preflight
from .rootless_docker_authority import AUTHORITY


__all__ = (
    "RootlessDockerLauncherReplacementError",
    "RootlessDockerLauncherReplacementEvidence",
    "replace_rootless_docker_launcher",
)

_ERROR = "rootless Docker launcher replacement is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)

_PREDECESSOR_SHA256 = "34d5557a068e030c75e063cf6b6106ef118ec7ff87de1d953d900dfbd1eaefff"
_TARGET_SHA256 = next(
    item[2]
    for item in AUTHORITY.installed_assets
    if item[1] == AUTHORITY.launcher
)
_SOURCE = (
    Path(__file__).resolve().parent
    / "systemd"
    / "rootless"
    / "rootless-docker-launcher.py"
)
_PARENT = os.path.dirname(AUTHORITY.launcher)
_NAME = os.path.basename(AUTHORITY.launcher)
_TEMPORARY = ".launch.py.c33k.tmp"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_MAX_BYTES = 256 * 1024


class RootlessDockerLauncherReplacementError(Exception):
    """The exact C33K launcher transition is unavailable."""


@dataclass(frozen=True, slots=True)
class RootlessDockerLauncherReplacementEvidence:
    operation: str
    predecessor_sha256: str
    target_sha256: str
    installed_sha256: str

    def __post_init__(self) -> None:
        if (
            self.operation not in {"replaced", "already-replaced"}
            or self.predecessor_sha256 != _PREDECESSOR_SHA256
            or self.target_sha256 != _TARGET_SHA256
            or self.installed_sha256 != _TARGET_SHA256
        ):
            raise ValueError("invalid rootless Docker launcher replacement evidence")


def _root_identity() -> tuple[int, int]:
    value = (os.geteuid(), os.getegid())
    if value != (0, 0):
        raise OSError
    return value


def _fingerprint(status: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        status.st_mode,
        status.st_dev,
        status.st_ino,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _regular(status: os.stat_result, *, mode: int = 0o644) -> os.stat_result:
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or (status.st_uid, status.st_gid) != (0, 0)
        or stat.S_IMODE(status.st_mode) != mode
    ):
        raise OSError
    return status


def _read_exact_fd(descriptor: int, *, mode: int = 0o644) -> bytes:
    opened = _regular(os.fstat(descriptor), mode=mode)
    if opened.st_size <= 0 or opened.st_size > _MAX_BYTES:
        raise OSError
    chunks: list[bytes] = []
    remaining = opened.st_size
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            raise OSError
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise OSError
    if _fingerprint(os.fstat(descriptor)) != _fingerprint(opened):
        raise OSError
    return b"".join(chunks)


def _source_bytes() -> bytes:
    descriptor = os.open(_SOURCE, _READ_FLAGS)
    try:
        payload = _read_exact_fd(descriptor)
    finally:
        os.close(descriptor)
    if hashlib.sha256(payload).hexdigest() != _TARGET_SHA256:
        raise OSError
    return payload


def _installed(parent: int) -> tuple[tuple[int, int, int, int, int, int], bytes, str]:
    descriptor = os.open(_NAME, _READ_FLAGS, dir_fd=parent)
    try:
        opened = _regular(os.fstat(descriptor))
        payload = _read_exact_fd(descriptor)
        named = _regular(os.stat(_NAME, dir_fd=parent, follow_symlinks=False))
        fingerprint = (
            opened.st_mode,
            opened.st_dev,
            opened.st_ino,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
        )
        named_fingerprint = (
            named.st_mode,
            named.st_dev,
            named.st_ino,
            named.st_nlink,
            named.st_uid,
            named.st_gid,
        )
        if named_fingerprint != fingerprint:
            raise OSError
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(payload).hexdigest()
    if digest not in {_PREDECESSOR_SHA256, _TARGET_SHA256}:
        raise OSError
    return fingerprint, payload, digest


def _parent() -> int:
    descriptor = os.open(_PARENT, _DIRECTORY_FLAGS)
    status = os.fstat(descriptor)
    named = os.stat(_PARENT, follow_symlinks=False)
    if (
        not stat.S_ISDIR(status.st_mode)
        or (status.st_uid, status.st_gid) != (0, 0)
        or stat.S_IMODE(status.st_mode) != 0o755
        or (status.st_dev, status.st_ino) != (named.st_dev, named.st_ino)
    ):
        os.close(descriptor)
        raise OSError
    return descriptor


def _temporary_state(parent: int, payload: bytes) -> tuple[str, int]:
    try:
        status = os.stat(_TEMPORARY, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return "absent", 0
    mode = stat.S_IMODE(status.st_mode)
    if mode not in {0o600, 0o644}:
        raise OSError
    _regular(status, mode=mode)
    descriptor = os.open(_TEMPORARY, _READ_FLAGS, dir_fd=parent)
    try:
        current = _read_exact_fd(descriptor, mode=mode)
    finally:
        os.close(descriptor)
    if mode == 0o644:
        if current != payload:
            raise OSError
        return "exact", len(payload)
    if len(current) > len(payload) or current != payload[:len(current)]:
        raise OSError
    return "prefix", len(current)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        count = os.write(descriptor, payload[offset:])
        if type(count) is not int or count <= 0:
            raise OSError
        offset += count


def _replace_under_lock() -> RootlessDockerLauncherReplacementEvidence:
    payload = _source_bytes()
    parent = _parent()
    temporary_descriptor = None
    try:
        before_fingerprint, before_payload, before_digest = _installed(parent)
        temporary, staged_length = _temporary_state(parent, payload)

        if before_digest == _TARGET_SHA256:
            if before_payload != payload:
                raise OSError
            if temporary == "exact":
                os.unlink(_TEMPORARY, dir_fd=parent)
                os.fsync(parent)
            elif temporary == "absent":
                os.fsync(parent)
            else:
                raise OSError
            _installed(parent)
            return RootlessDockerLauncherReplacementEvidence(
                "already-replaced",
                _PREDECESSOR_SHA256,
                _TARGET_SHA256,
                _TARGET_SHA256,
            )

        if before_digest != _PREDECESSOR_SHA256:
            raise OSError

        if temporary != "exact":
            if temporary == "absent":
                temporary_descriptor = os.open(
                    _TEMPORARY,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent,
                )
                created = os.fstat(temporary_descriptor)
                if (
                    not stat.S_ISREG(created.st_mode)
                    or created.st_nlink != 1
                    or (created.st_uid, created.st_gid) != (0, 0)
                    or stat.S_IMODE(created.st_mode) != 0o600
                ):
                    raise OSError
                staged_length = 0
            elif temporary == "prefix":
                temporary_descriptor = os.open(
                    _TEMPORARY,
                    os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
                resumed = _regular(os.fstat(temporary_descriptor), mode=0o600)
                if resumed.st_size != staged_length:
                    raise OSError
            else:
                raise OSError

            if staged_length < len(payload):
                if staged_length:
                    os.lseek(temporary_descriptor, staged_length, os.SEEK_SET)
                _write_all(temporary_descriptor, payload[staged_length:])
            os.fsync(temporary_descriptor)
            os.fchmod(temporary_descriptor, 0o644)
            os.fsync(temporary_descriptor)
            exact = _regular(os.fstat(temporary_descriptor))
            if exact.st_size != len(payload):
                raise OSError
            os.close(temporary_descriptor)
            temporary_descriptor = None
            if _temporary_state(parent, payload) != ("exact", len(payload)):
                raise OSError

        current_fingerprint, current_payload, current_digest = _installed(parent)
        if (
            current_digest != _PREDECESSOR_SHA256
            or current_payload != before_payload
            or current_fingerprint != before_fingerprint
        ):
            raise OSError

        os.replace(_TEMPORARY, _NAME, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)

        _fingerprint, installed_payload, installed_digest = _installed(parent)
        if installed_payload != payload or installed_digest != _TARGET_SHA256:
            raise OSError

        return RootlessDockerLauncherReplacementEvidence(
            "replaced",
            _PREDECESSOR_SHA256,
            _TARGET_SHA256,
            installed_digest,
        )
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        os.close(parent)


def replace_rootless_docker_launcher() -> RootlessDockerLauncherReplacementEvidence:
    """Atomically replace only the exact predecessor launcher asset."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        candidate = restart_preflight.preflight_rootless_docker_restart_candidate()
        if not candidate.passed:
            raise OSError
        result = _replace_under_lock()
        qualified = restart_preflight.preflight_rootless_docker_restart()
        if not qualified.passed:
            raise OSError
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        if lock is not None:
            try:
                orchestration._release_process_lock(lock)
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise RootlessDockerLauncherReplacementError(_ERROR) from None
    return result
