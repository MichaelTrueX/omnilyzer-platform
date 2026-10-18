"""File: deployment/c34k_five_file_backup_barrier.py

Purpose: Require the complete, exact five-file original backup cohort before
any Task 014 broker source/config transition may be considered.
Related: deployment/c34j_atomic_file_mechanics.py,
deployment/c34i_merged_migration_authority.py,
deployment/c34g_migration_authority.py,
deployment/tests/test_c34k_five_file_backup_barrier.py.

This file implements a backup-only primitive. It has no host locator, service
controller, migration/rollback writer, GitHub token handling, deployment CLI,
or main-SHA selection. The independently reviewed root host orchestrator
must still qualify the directory descriptors, lock, source generation,
stopped services, persistence, and operator authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat

from . import c34j_atomic_file_mechanics as files


# Section: Exact ordered source/config and backup pairing, no extra names.
_ORDER = (
    "broker.py",
    "broker_https_ingress.py",
    "broker_integration.py",
    "executor.json",
    "dev.json",
)
_BACKUPS = tuple(files._TARGET_TO_BACKUP[name] for name in _ORDER)
_ERROR = "C34K original backup cohort is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class C34KBackupBarrierError(Exception):
    """A fixed, nonsecret failure for any incomplete or untrusted cohort."""


@dataclass(frozen=True, slots=True, kw_only=True)
class C34KOriginalSource:
    """One reviewed source identity and already-open, independently vetted FD."""

    identity: files.C34JFileIdentity
    source_dir_fd: int
    original: bytes

    def __post_init__(self) -> None:
        """Reject malformed sources before performing any filesystem reads."""
        if (
            type(self.identity) is not files.C34JFileIdentity
            or type(self.source_dir_fd) is not int
            or self.source_dir_fd < 0
            or type(self.original) is not bytes
            or not 0 < len(self.original) <= files._MAX
            or hashlib.sha256(self.original).hexdigest()
            != self.identity.original_sha256
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class C34KBackupReceipt:
    """Pure nonsecret evidence of five exact originals and private backups."""

    original_sha256: tuple[str, ...]
    all_five_sealed: bool

    def __post_init__(self) -> None:
        """Reject forged incomplete counts and noncanonical digest tuples."""
        if (
            type(self.original_sha256) is not tuple
            or len(self.original_sha256) != 5
            or any(type(x) is not str or len(x) != 64
                   or any(c not in "0123456789abcdef" for c in x)
                   for x in self.original_sha256)
            or self.all_five_sealed is not True
        ):
            raise ValueError(_ERROR)


def _validate_inputs(
    sources: tuple[C34KOriginalSource, ...],
    backup_dir_fd: int,
    backup_uid: int,
    backup_gid: int,
) -> None:
    """Check exact order, nonduplicate config roles, and 0700 backup FD."""
    if (
        type(sources) is not tuple
        or len(sources) != 5
        or type(backup_uid) is not int or backup_uid < 0
        or type(backup_gid) is not int or backup_gid < 0
        or tuple(
            x.identity.name if type(x) is C34KOriginalSource else None
            for x in sources
        ) != _ORDER
    ):
        raise ValueError
    files._directory(
        backup_dir_fd, uid=backup_uid, gid=backup_gid, mode=0o700,
    )
    # Before any backup write, reject a symlink or unknown entry in the
    # dedicated private backup directory, including subdirectories.
    if set(os.listdir(backup_dir_fd)) - set(_BACKUPS):
        raise ValueError


def _verify_originals(sources: tuple[C34KOriginalSource, ...]) -> None:
    """Prove every original installed file before writing *any* backup."""
    for source in sources:
        model = source.identity
        files._directory(
            source.source_dir_fd,
            uid=model.uid, gid=model.gid,
            mode=0o750 if model.name.endswith(".json") else 0o755,
        )
        data, _ = files._read_file(
            source.source_dir_fd, model.name,
            uid=model.uid, gid=model.gid,
            modes=(model.mode,),
        )
        if data != source.original:
            raise ValueError


def _verify_backups(
    sources: tuple[C34KOriginalSource, ...],
    backup_dir_fd: int,
    backup_uid: int,
    backup_gid: int,
) -> C34KBackupReceipt:
    """Require exactly five canonical single-link mode-0600 backup files."""
    files._directory(
        backup_dir_fd, uid=backup_uid, gid=backup_gid, mode=0o700,
    )
    if set(os.listdir(backup_dir_fd)) != set(_BACKUPS):
        raise ValueError
    digests: list[str] = []
    for item, name in zip(sources, _BACKUPS, strict=True):
        data, file_stat = files._read_file(
            backup_dir_fd, name, uid=backup_uid, gid=backup_gid,
            modes=(0o600,),
        )
        if data != item.original or not stat.S_ISREG(file_stat.st_mode):
            raise ValueError
        digests.append(hashlib.sha256(data).hexdigest())
    return C34KBackupReceipt(tuple(digests), True)


def seal_all_five_original_backups(
    *, sources: tuple[C34KOriginalSource, ...],
    backup_dir_fd: int,
    backup_uid: int,
    backup_gid: int,
) -> C34KBackupReceipt:
    """Seal all five originals before any source/config publication.

    Failures can leave exact partial backup prefixes for a later reviewed
    recovery attempt. No partial success is returned. The function never
    changes installed source/config files. It does not establish that
    services are stopped or that the caller owns the exclusive host lock.
    """
    try:
        _validate_inputs(sources, backup_dir_fd, backup_uid, backup_gid)
        _verify_originals(sources)
        for source, backup in zip(sources, _BACKUPS, strict=True):
            files.seal_original_backup(
                backup_dir_fd=backup_dir_fd,
                backup_name=backup,
                original=source.original,
                uid=backup_uid,
                gid=backup_gid,
            )
        return _verify_backups(
            sources, backup_dir_fd, backup_uid, backup_gid,
        )
    except _CONTROL:
        raise
    except Exception:
        raise C34KBackupBarrierError(_ERROR) from None


def require_complete_original_backups(
    *, sources: tuple[C34KOriginalSource, ...],
    backup_dir_fd: int,
    backup_uid: int,
    backup_gid: int,
) -> C34KBackupReceipt:
    """Recheck all five durable backup bytes without creating any file.

    A future one-prefix writer must call this gate before each publication
    and again after interruption recovery. Backups do not expire or reset.
    """
    try:
        _validate_inputs(sources, backup_dir_fd, backup_uid, backup_gid)
        return _verify_backups(
            sources, backup_dir_fd, backup_uid, backup_gid,
        )
    except _CONTROL:
        raise
    except Exception:
        raise C34KBackupBarrierError(_ERROR) from None


__all__ = (
    "C34KBackupBarrierError",
    "C34KOriginalSource",
    "C34KBackupReceipt",
    "seal_all_five_original_backups",
    "require_complete_original_backups",
)
