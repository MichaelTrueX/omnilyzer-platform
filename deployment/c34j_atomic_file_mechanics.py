"""File: deployment/c34j_atomic_file_mechanics.py

Purpose: Descriptor-scoped, crash-resumable single-file backup and atomic
replacement mechanics for a future reviewed Task 014 DEV source transition.
Related: deployment/c34i_merged_migration_authority.py,
deployment/dev_post_c31_application_update.py,
deployment/state_store_successor_host_migration_runtime.py,
deployment/tests/test_c34j_atomic_file_mechanics.py.

Not a host installer: all operations require independently prequalified
directory FDs and explicit closed file identity, owner, mode and byte hashes.
This module has NO default host paths, service actions, root entrypoint,
GitHub access, token logic or deployment dispatcher. In particular, it does
not acquire the root deployment lock or choose a final main commit.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat


# Section 1: Closed scope, bounded I/O, and fixed failure surface.
_MAX = 1024 * 1024
_BACKUPS = frozenset((
    "00-broker.py", "01-broker_https_ingress.py",
    "02-broker_integration.py", "03-executor.json", "04-broker.json",
))
_TARGET_TO_BACKUP = {
    "broker.py": "00-broker.py",
    "broker_https_ingress.py": "01-broker_https_ingress.py",
    "broker_integration.py": "02-broker_integration.py",
    "executor.json": "03-executor.json",
    "dev.json": "04-broker.json",
}
_TARGETS = frozenset(_TARGET_TO_BACKUP)
_ERR = "C34J atomic file transition is unavailable"
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_WRITE = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CREATE = _WRITE | os.O_CREAT | os.O_EXCL
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class C34JAtomicFileError(Exception):
    """Report a fixed error instead of filesystem paths or private bytes."""


@dataclass(frozen=True, slots=True)
class C34JFileIdentity:
    """Bind one permitted filename to exact original bytes and destination metadata."""

    name: str
    original_sha256: str
    target_sha256: str
    uid: int
    gid: int
    mode: int

    def __post_init__(self) -> None:
        """Reject unlisted files, malformed digests and invalid owner/mode values."""
        if (
            type(self.name) is not str or self.name not in _TARGETS
            or type(self.original_sha256) is not str
            or type(self.target_sha256) is not str
            or len(self.original_sha256) != 64
            or len(self.target_sha256) != 64
            or any(ch not in "0123456789abcdef"
                   for ch in self.original_sha256 + self.target_sha256)
            or type(self.uid) is not int or self.uid < 0
            or type(self.gid) is not int or self.gid < 0
            or self.mode != (0o640 if self.name.endswith(".json") else 0o644)
        ):
            raise ValueError(_ERR)


@dataclass(frozen=True, slots=True)
class C34JFileReceipt:
    """Nonsecret digest and publication state of one exact file operation."""

    original_sha256: str
    target_sha256: str
    backup_sealed: bool
    target_published: bool


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    """Compare durable identity/metadata without access-time side effects."""
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def _directory(fd: int, *, uid: int, gid: int, mode: int) -> os.stat_result:
    """Require one already-open trusted regular directory descriptor."""
    if type(fd) is not int or fd < 0:
        raise ValueError
    value = os.fstat(fd)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != uid or value.st_gid != gid
        or stat.S_IMODE(value.st_mode) != mode
    ):
        raise ValueError
    return value


def _regular(fd: int, *, uid: int, gid: int,
             modes: tuple[int, ...]) -> os.stat_result:
    """Check a regular, single-link file without following a symlink."""
    s = os.fstat(fd)
    if (
        not stat.S_ISREG(s.st_mode) or s.st_nlink != 1
        or (s.st_uid, s.st_gid) != (uid, gid)
        or stat.S_IMODE(s.st_mode) not in modes
        or s.st_size > _MAX or s.st_size < 0
    ):
        raise ValueError
    return s


def _read_file(parent_fd: int, name: str, *,
               uid: int, gid: int, modes: tuple[int, ...]) -> tuple[bytes, os.stat_result]:
    """Read and revalidate one named bounded file through a trusted dirfd."""
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    fd = os.open(name, _READ, dir_fd=parent_fd)
    try:
        opened = _regular(fd, uid=uid, gid=gid, modes=modes)
        if _fingerprint(named) != _fingerprint(opened):
            raise ValueError
        chunks = bytearray()
        while len(chunks) <= _MAX:
            block = os.read(fd, min(65536, _MAX + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if (
            len(chunks) != opened.st_size
            or _fingerprint(os.fstat(fd)) != _fingerprint(opened)
            or _fingerprint(os.stat(
                name, dir_fd=parent_fd, follow_symlinks=False,
            )) != _fingerprint(opened)
        ):
            raise ValueError
        return bytes(chunks), opened
    finally:
        os.close(fd)


def _write_all(fd: int, raw: bytes) -> None:
    """Append all bounded bytes with explicit short-write detection."""
    remaining = memoryview(raw)
    while remaining:
        count = os.write(fd, remaining)
        if not 0 < count <= len(remaining):
            raise ValueError
        remaining = remaining[count:]


def seal_original_backup(*, backup_dir_fd: int, backup_name: str,
                         original: bytes, uid: int, gid: int) -> str:
    """Create/resume and fsync a private exact original-byte backup.

    The future root orchestrator must first qualify and lock the backup
    directory, create it root-owned mode 0700 and never expose its path.
    Existing backup content is accepted only if it is an exact source prefix;
    a complete existing backup is checked again without being overwritten.
    This function deliberately does not write or delete the target file.
    """
    try:
        if (
            type(backup_name) is not str or backup_name not in _BACKUPS
            or type(original) is not bytes
            or not 0 < len(original) <= _MAX
        ):
            raise ValueError
        _directory(backup_dir_fd, uid=uid, gid=gid, mode=0o700)
        try:
            fd = os.open(backup_name, _CREATE, 0o600, dir_fd=backup_dir_fd)
        except FileExistsError:
            fd = os.open(backup_name, _WRITE, dir_fd=backup_dir_fd)
        try:
            opened = _regular(fd, uid=uid, gid=gid, modes=(0o600,))
            observed, named = _read_file(
                backup_dir_fd, backup_name, uid=uid, gid=gid, modes=(0o600,),
            )
            if (
                _fingerprint(opened) != _fingerprint(named)
                or len(observed) > len(original)
                or observed != original[:len(observed)]
            ):
                raise ValueError
            if len(observed) < len(original):
                os.lseek(fd, len(observed), os.SEEK_SET)
                _write_all(fd, original[len(observed):])
            os.fsync(fd)
            if (
                os.fstat(fd).st_size != len(original)
                or _read_file(
                    backup_dir_fd, backup_name, uid=uid, gid=gid, modes=(0o600,),
                )[0] != original
            ):
                raise ValueError
            os.fsync(backup_dir_fd)
            return hashlib.sha256(original).hexdigest()
        finally:
            os.close(fd)
    except _CONTROL:
        raise
    except Exception:
        raise C34JAtomicFileError(_ERR) from None


def publish_exact_file(*, parent_fd: int, backup_dir_fd: int,
                       backup_uid: int, backup_gid: int,
                       backup_name: str, identity: C34JFileIdentity,
                       original: bytes, target: bytes, stage_name: str) -> C34JFileReceipt:
    """Publish one backed-up, exact file using same-directory atomic replace.

    Caller must hold the established global deployment lock, verify all 41
    current installed source hashes and both canonical configs as the exact
    current migration prefix, and prove all three services are stopped.
    This primitive does NOT perform any of those external qualifications.

    Existing staged content must be an exact prefix of the target, including
    partial writes interrupted before fsync. Revalidate original destination
    immediately before rename; detect unexpected target mutation and refuse.
    After rename, the caller must reclassify the entire installed generation
    before any further operation.
    """
    try:
        if (
            type(identity) is not C34JFileIdentity
            or type(original) is not bytes or type(target) is not bytes
            or not 0 < len(original) <= _MAX or not 0 < len(target) <= _MAX
            or hashlib.sha256(original).hexdigest() != identity.original_sha256
            or hashlib.sha256(target).hexdigest() != identity.target_sha256
            or type(stage_name) is not str
            or stage_name != ".omnilyzer-c34j-" + identity.name + ".stage"
            or backup_name != _TARGET_TO_BACKUP[identity.name]
        ):
            raise ValueError
        # Source parent is expected mode 0755 for Python modules and 0750 for
        # canonical configurations. Its owner must be root or the test fixture
        # identity explicitly supplied by the root-owned orchestrator.
        mode = 0o750 if identity.name.endswith(".json") else 0o755
        _directory(parent_fd, uid=identity.uid, gid=identity.gid,
                   mode=mode)
        _directory(
            backup_dir_fd, uid=backup_uid, gid=backup_gid, mode=0o700,
        )
        backup, _ = _read_file(
            backup_dir_fd, backup_name, uid=backup_uid,
            gid=backup_gid, modes=(0o600,),
        )
        installed, before = _read_file(
            parent_fd, identity.name, uid=identity.uid,
            gid=identity.gid, modes=(identity.mode,),
        )
        if backup != original or installed != original:
            raise ValueError

        try:
            fd = os.open(stage_name, _CREATE, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            fd = os.open(stage_name, _WRITE, dir_fd=parent_fd)
        try:
            opened = _regular(
                fd, uid=identity.uid, gid=identity.gid,
                modes=(0o600, identity.mode),
            )
            stage, staged_meta = _read_file(
                parent_fd, stage_name, uid=identity.uid,
                gid=identity.gid, modes=(0o600, identity.mode),
            )
            if (
                _fingerprint(opened) != _fingerprint(staged_meta)
                or len(stage) > len(target)
                or stage != target[:len(stage)]
                or (len(stage) < len(target)
                    and stat.S_IMODE(opened.st_mode) != 0o600)
            ):
                raise ValueError
            if len(stage) < len(target):
                os.lseek(fd, len(stage), os.SEEK_SET)
                _write_all(fd, target[len(stage):])
            os.fsync(fd)
            os.fchmod(fd, identity.mode)
            os.fsync(fd)
            if (
                os.fstat(fd).st_size != len(target)
                or _read_file(
                    parent_fd, stage_name, uid=identity.uid, gid=identity.gid,
                    modes=(identity.mode,),
                )[0] != target
            ):
                raise ValueError
            if _read_file(
                parent_fd, identity.name, uid=identity.uid,
                gid=identity.gid, modes=(identity.mode,),
            )[0] != original or _fingerprint(os.stat(
                identity.name, dir_fd=parent_fd, follow_symlinks=False
            )) != _fingerprint(before):
                raise ValueError
            os.replace(
                stage_name, identity.name,
                src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
        finally:
            os.close(fd)
        installed_after, _ = _read_file(
            parent_fd, identity.name, uid=identity.uid,
            gid=identity.gid, modes=(identity.mode,),
        )
        if installed_after != target:
            raise ValueError
        return C34JFileReceipt(
            original_sha256=identity.original_sha256,
            target_sha256=identity.target_sha256,
            backup_sealed=True, target_published=True,
        )
    except _CONTROL:
        raise
    except Exception:
        raise C34JAtomicFileError(_ERR) from None


__all__ = (
    "C34JAtomicFileError", "C34JFileIdentity", "C34JFileReceipt",
    "seal_original_backup", "publish_exact_file",
)
