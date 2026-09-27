"""Read-only C32K identity qualification of two pre-install staged artifacts.

No acquisition, execution, signature/TUF verification or installation occurs.
All descriptors close before return: evidence describes a completed observation,
not continuing path trust or authority to reopen/install those paths later.
"""

from dataclasses import dataclass as _dataclass
import hashlib as _hashlib
import os as _os
import stat as _stat

from . import wheelhouse_qualification as _staging
from .broker_service_config import COSIGN_BINARY_SIZE as _BINARY_SIZE, COSIGN_VERSION as _VERSION
from .sigstore_authority_provenance import DevSigstoreVerificationProvenance as _Provenance

__all__ = (
    "SigstoreToolchainQualificationError",
    "SigstoreToolchainFileEvidence",
    "DevSigstoreToolchainEvidence",
    "qualify_dev_sigstore_toolchain",
)
_UNAVAILABLE = "DEV Sigstore toolchain qualification is unavailable"
_MODEL_ERROR = "DEV Sigstore toolchain qualification evidence is invalid"
_HASH_CHUNK_BYTES = 64 * 1024
_CONTROL_EXCEPTIONS = (KeyboardInterrupt, SystemExit, GeneratorExit)


class SigstoreToolchainQualificationError(Exception):
    """The staged files cannot establish the exact reviewed artifact identities."""


def _reviewed() -> _Provenance:
    value = _Provenance()
    if type(value) is not _Provenance:
        raise ValueError
    _Provenance.__post_init__(value)
    if (type(_BINARY_SIZE) is not int or _BINARY_SIZE != value.cosign.asset_size
            or type(_VERSION) is not str or _VERSION != value.cosign.version):
        raise ValueError
    return value


def _artifacts() -> tuple[tuple[str, int, str], ...]:
    value = _reviewed()
    return (
        (value.cosign.asset_name, value.cosign.asset_size, value.cosign.asset_sha256),
        (value.trusted_root.retained_target_path.rsplit("/", 1)[1],
         value.trusted_root.target_size, value.trusted_root.target_sha256),
    )


def _identity() -> tuple[int, int]:
    uid, euid, gid, egid = _os.getuid(), _os.geteuid(), _os.getgid(), _os.getegid()
    if (any(type(value) is not int or not 0 < value <= 2**32 - 2
            for value in (uid, euid, gid, egid)) or uid != euid or gid != egid):
        raise OSError
    return uid, gid


def _fingerprint(value: object) -> tuple[int, ...]:
    return _staging._fingerprint(_staging._status(value))


def _evidence_fingerprint(value: object) -> tuple[int, ...]:
    if (type(value) is not tuple or len(value) != 9
            or any(type(item) is not int for item in value)
            or any(item < 0 for item in value[:7])):
        raise ValueError
    return value


@_dataclass(frozen=True, slots=True)
class SigstoreToolchainFileEvidence:
    """One reviewed filename/size/digest and its observed descriptor metadata."""

    filename: str
    size: int
    sha256: str
    fingerprint: tuple[int, ...]

    def __post_init__(self) -> None:
        try:
            if (type(self.filename) is not str or type(self.size) is not int
                    or type(self.sha256) is not str
                    or (self.filename, self.size, self.sha256) not in _artifacts()):
                raise ValueError
            mode, _ino, _dev, links, _uid, _gid, size, *_times = (
                _evidence_fingerprint(self.fingerprint)
            )
            if (not _stat.S_ISREG(mode) or links != 1 or size != self.size
                    or _stat.S_IMODE(mode) not in (0o400, 0o600)):
                raise ValueError
        except _CONTROL_EXCEPTIONS:
            raise
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


@_dataclass(frozen=True, slots=True)
class DevSigstoreToolchainEvidence:
    """Immutable observation only; no live descriptors or install authorization."""

    staging_directory: str
    staging_uid: int
    staging_gid: int
    directory_fingerprint: tuple[int, ...]
    cosign_version: str
    cosign: SigstoreToolchainFileEvidence
    trusted_root: SigstoreToolchainFileEvidence

    def __post_init__(self) -> None:
        try:
            _staging._path(self.staging_directory, _MODEL_ERROR)
            if any(type(value) is not int or not 0 < value <= 2**32 - 2
                   for value in (self.staging_uid, self.staging_gid)):
                raise ValueError
            if type(self.cosign_version) is not str or self.cosign_version != _reviewed().cosign.version:
                raise ValueError
            fingerprint = _evidence_fingerprint(self.directory_fingerprint)
            if (not _stat.S_ISDIR(fingerprint[0])
                    or _stat.S_IMODE(fingerprint[0]) != 0o700
                    or fingerprint[3] < 1
                    or fingerprint[4:6] != (self.staging_uid, self.staging_gid)):
                raise ValueError
            for value, artifact in zip((self.cosign, self.trusted_root), _artifacts(), strict=True):
                if type(value) is not SigstoreToolchainFileEvidence:
                    raise ValueError
                SigstoreToolchainFileEvidence.__post_init__(value)
                if ((value.filename, value.size, value.sha256) != artifact
                        or value.fingerprint[4:6] != (self.staging_uid, self.staging_gid)):
                    raise ValueError
        except _CONTROL_EXCEPTIONS:
            raise
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


def _directory(value: object, owner: tuple[int, int], *, final: bool) -> tuple[int, ...]:
    status = _staging._directory(value)
    mode = _stat.S_IMODE(status.st_mode)
    if final:
        if (status.st_uid, status.st_gid) != owner or mode != 0o700:
            raise OSError
    elif (status.st_uid not in (0, owner[0])
          or (mode & 0o022 and not (status.st_uid == 0 and mode & _stat.S_ISVTX))):
        # Root-owned sticky shared parents (e.g. /tmp) protect owned children.
        # Other writable ancestors cannot protect this staging path.
        raise OSError
    return _fingerprint(status)


def _open_path(
    path: str, flags: int, owned: list[int], owner: tuple[int, int],
) -> tuple[list[tuple[int, str | None, int | None, tuple[int, ...]]], int]:
    named = _directory(_os.stat("/", follow_symlinks=False), owner, final=False)
    parent = _staging._claim(_os.open("/", flags), owned)
    current = _directory(_os.fstat(parent), owner, final=False)
    if named != current:
        raise OSError
    opened = [(parent, None, None, current)]
    components = path[1:].split("/")
    for index, component in enumerate(components):
        final = index == len(components) - 1
        named = _directory(_os.stat(component, dir_fd=parent, follow_symlinks=False), owner, final=final)
        descriptor = _staging._claim(_os.open(component, flags, dir_fd=parent), owned)
        current = _directory(_os.fstat(descriptor), owner, final=final)
        if named != current:
            raise OSError
        opened.append((descriptor, component, parent, current))
        parent = descriptor
    return opened, parent


def _entry_names(directory: int) -> tuple[str, ...]:
    names = []
    with _os.scandir(directory) as iterator:
        for entry in iterator:
            if (type(entry.name) is not str or not entry.name
                    or "/" in entry.name or "\0" in entry.name or len(names) == 2):
                raise OSError
            names.append(entry.name)
    return tuple(sorted(names))


def _file(value: object, size: int, owner: tuple[int, int]) -> tuple[int, ...]:
    status = _staging._regular_file(value)
    if (type(size) is not int or size <= 0 or type(status.st_size) is not int
            or status.st_size != size
            or status.st_nlink != 1 or (status.st_uid, status.st_gid) != owner
            or _stat.S_IMODE(status.st_mode) not in (0o400, 0o600)):
        raise OSError
    return _fingerprint(status)


def _hash_file(descriptor: int, size: int) -> str:
    """C28/C31P streaming pattern, with exact typed EOF and no content retention."""
    if type(size) is not int or size <= 0:
        raise OSError
    digest = _hashlib.sha256()
    remaining = size
    while remaining:
        maximum = min(_HASH_CHUNK_BYTES, remaining)
        chunk = _os.read(descriptor, maximum)
        if type(chunk) is not bytes or not chunk or len(chunk) > maximum:
            raise OSError
        digest.update(chunk)
        remaining -= len(chunk)
    eof = _os.read(descriptor, 1)
    if type(eof) is not bytes or eof != b"":
        raise OSError
    return digest.hexdigest()


def _qualify(path: str, owned: list[int]) -> DevSigstoreToolchainEvidence:
    owner = _identity()
    reviewed = _reviewed()
    artifacts = _artifacts()
    directory_flags, file_flags = _staging._flags()
    directories, directory = _open_path(path, directory_flags, owned, owner)
    expected_names = tuple(sorted(item[0] for item in artifacts))
    if _entry_names(directory) != expected_names:
        raise OSError
    observed = []
    opened_files = []
    for filename, size, sha256 in artifacts:
        named = _file(_os.stat(filename, dir_fd=directory, follow_symlinks=False), size, owner)
        descriptor = _staging._claim(_os.open(filename, file_flags, dir_fd=directory), owned)
        opened = _file(_os.fstat(descriptor), size, owner)
        if named != opened or _hash_file(descriptor, size) != sha256:
            raise OSError
        opened_files.append((descriptor, filename, opened))
        # Immediate checks plus a final pass catch earlier-file mutation while
        # the second artifact is being hashed.
        _staging._revalidate_files(directory, [opened_files[-1]])
        observed.append(SigstoreToolchainFileEvidence(filename, size, sha256, opened))
    if _entry_names(directory) != expected_names:
        raise OSError
    _staging._revalidate_files(directory, opened_files)
    _staging._revalidate_directories(directories)
    if _identity() != owner:
        raise OSError
    return DevSigstoreToolchainEvidence(
        path, *owner, directories[-1][3], reviewed.cosign.version, *observed,
    )


def qualify_dev_sigstore_toolchain(*, staging_directory: str) -> DevSigstoreToolchainEvidence:
    """Inspect a dedicated directory; return evidence only after successful cleanup."""
    owned: list[int] = []
    try:
        _staging._path(staging_directory, _UNAVAILABLE)
        result = _qualify(staging_directory, owned)
    except _CONTROL_EXCEPTIONS:
        _staging._close(owned)
        raise
    except Exception:
        _failed, cleanup_control = _staging._close(owned)
        if cleanup_control is not None:
            raise cleanup_control
        raise SigstoreToolchainQualificationError(_UNAVAILABLE) from None
    cleanup_failed, cleanup_control = _staging._close(owned)
    if cleanup_control is not None:
        raise cleanup_control
    if cleanup_failed:
        raise SigstoreToolchainQualificationError(_UNAVAILABLE) from None
    return result
