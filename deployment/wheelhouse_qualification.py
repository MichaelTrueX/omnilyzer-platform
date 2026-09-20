"""Closed, read-only C28 qualification of staged DEV wheel bytes.

C24 remains the sole authority for the exact wheel filenames and SHA-256
digests.  An explicit qualification traverses a caller-selected absolute path
without following symlinks, requires its complete entry set to be the C24
closure, and hashes retained regular-file descriptors.  Import and evidence
construction perform no filesystem or network I/O.  This module never creates,
populates, downloads into, installs from, or otherwise mutates a wheelhouse.
"""

from dataclasses import InitVar as _InitVar, dataclass as _dataclass
import hashlib as _hashlib
import os as _os
import stat as _stat

from . import installation_integrity_contract as _integrity

__all__ = (
    "WheelhouseQualificationError",
    "WheelhouseFileEvidence",
    "DevWheelhouseEvidence",
    "qualify_dev_wheelhouse",
)

_UNAVAILABLE = "DEV staged wheelhouse evidence is unavailable"
_MODEL_ERROR = "DEV staged wheelhouse evidence is invalid"
_HASH_CHUNK_BYTES = 64 * 1024
_CONTROL_EXCEPTIONS = (KeyboardInterrupt, SystemExit, GeneratorExit)


class WheelhouseQualificationError(Exception):
    """The staged directory cannot produce exact C24 wheel evidence."""


def _path(value: object, error: str) -> None:
    """Require a canonical absolute Linux path without touching the host."""
    if (
        type(value) is not str
        or value in ("", "/")
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or "\0" in value
        or any(part in ("", ".", "..") for part in value[1:].split("/"))
    ):
        raise ValueError(error)


def _requirement(
    value: object, error: str,
) -> "_integrity.PythonEnvironmentIntegrityRequirement":
    """Revalidate an exact C24 environment requirement, including its closure."""
    requirement_type = _integrity.PythonEnvironmentIntegrityRequirement
    if type(value) is not requirement_type:
        raise ValueError(error)
    try:
        requirement_type.__post_init__(value)
    except _CONTROL_EXCEPTIONS:
        raise
    except Exception:
        raise ValueError(error) from None
    return value


@_dataclass(frozen=True, slots=True)
class WheelhouseFileEvidence:
    """One exact staged wheel filename and the SHA-256 of its bytes."""

    filename: str
    sha256: str

    def __post_init__(self) -> None:
        """Reject malformed evidence fields without filesystem access."""
        try:
            _integrity.WheelIntegrityRequirement(self.filename, self.sha256)
        except _CONTROL_EXCEPTIONS:
            raise
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


@_dataclass(frozen=True, slots=True)
class DevWheelhouseEvidence:
    """Immutable exact-C24 evidence for one caller-selected staged directory."""

    wheelhouse_path: str
    digest_algorithm: str
    files: tuple[WheelhouseFileEvidence, ...]
    requirement: _InitVar["_integrity.PythonEnvironmentIntegrityRequirement"]

    def __post_init__(self, requirement: object) -> None:
        """Bind all evidence values to a revalidated exact C24 requirement."""
        try:
            _path(self.wheelhouse_path, _MODEL_ERROR)
            if type(self.digest_algorithm) is not str or self.digest_algorithm != "sha256":
                raise ValueError(_MODEL_ERROR)
            expected = _requirement(requirement, _MODEL_ERROR).wheels
            if type(self.files) is not tuple or len(self.files) != len(expected):
                raise ValueError(_MODEL_ERROR)
            for item in self.files:
                if type(item) is not WheelhouseFileEvidence:
                    raise ValueError(_MODEL_ERROR)
                WheelhouseFileEvidence.__post_init__(item)
            if tuple((item.filename, item.sha256) for item in self.files) != tuple(
                (wheel.filename, wheel.sha256) for wheel in expected
            ):
                raise ValueError(_MODEL_ERROR)
        except _CONTROL_EXCEPTIONS:
            raise
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


def _status(value: object) -> _os.stat_result:
    """Reject forged or nonsensical filesystem metadata."""
    if type(value) is not _os.stat_result or tuple.__len__(value) < 10:
        raise OSError
    values = tuple(tuple.__getitem__(value, index) for index in range(10))
    if any(type(item) not in (int, float) for item in values):
        raise OSError
    if any(type(values[index]) is not int or values[index] < 0 for index in range(7)):
        raise OSError
    if type(value.st_mtime_ns) is not int or type(value.st_ctime_ns) is not int:
        raise OSError
    return value


def _directory(value: object) -> _os.stat_result:
    """Require directory metadata; named symlinks fail this check."""
    result = _status(value)
    if not _stat.S_ISDIR(result.st_mode) or _stat.S_ISLNK(result.st_mode):
        raise OSError
    return result


def _regular_file(value: object) -> _os.stat_result:
    """Require a regular file with a live link and a representable size."""
    result = _status(value)
    if (
        not _stat.S_ISREG(result.st_mode)
        or _stat.S_ISLNK(result.st_mode)
        or result.st_nlink < 1
        or result.st_size < 0
    ):
        raise OSError
    return result


def _fingerprint(value: _os.stat_result) -> tuple[int, ...]:
    """Capture mutation-relevant metadata while deliberately ignoring atime."""
    return (
        value.st_mode, value.st_ino, value.st_dev, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _claim(value: object, owned: list[int]) -> int:
    """Claim one unique, non-inheritable descriptor for deterministic cleanup."""
    if type(value) is not int or value < 0 or value in owned:
        raise OSError
    owned.append(value)
    if _os.get_inheritable(value) is not False:
        raise OSError
    return value


def _flags() -> tuple[int, int]:
    """Build closed read-only Linux directory and file flag sets."""
    names = ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if any(type(getattr(_os, name, None)) is not int for name in names):
        raise OSError
    directory = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    regular = _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK
    return directory, regular


def _open_path(
    path: str, directory_flags: int, owned: list[int],
) -> tuple[list[tuple[int, str | None, int | None, tuple[int, ...]]], int]:
    """Traverse every absolute component with retained directory descriptors."""
    named_root = _directory(_os.stat("/", follow_symlinks=False))
    root = _claim(_os.open("/", directory_flags), owned)
    opened_root = _directory(_os.fstat(root))
    if (named_root.st_ino, named_root.st_dev) != (opened_root.st_ino, opened_root.st_dev):
        raise OSError
    opened = [(root, None, None, _fingerprint(opened_root))]
    parent = root
    for component in path[1:].split("/"):
        named = _directory(_os.stat(component, dir_fd=parent, follow_symlinks=False))
        descriptor = _claim(_os.open(component, directory_flags, dir_fd=parent), owned)
        current = _directory(_os.fstat(descriptor))
        if (named.st_ino, named.st_dev) != (current.st_ino, current.st_dev):
            raise OSError
        opened.append((descriptor, component, parent, _fingerprint(current)))
        parent = descriptor
    return opened, parent


def _entry_names(directory: int) -> tuple[str, ...]:
    """Return the complete directory entry-name set from the retained descriptor."""
    with _os.scandir(directory) as iterator:
        names = tuple(entry.name for entry in iterator)
    if any(type(name) is not str or not name or "/" in name or "\0" in name for name in names):
        raise OSError
    return tuple(sorted(names))


def _hash_file(descriptor: int, expected_size: int) -> str:
    """Hash exactly the initial file size in bounded chunks, then require EOF."""
    if type(expected_size) is not int or expected_size < 0:
        raise OSError
    digest = _hashlib.sha256()
    remaining = expected_size
    while remaining:
        maximum = min(_HASH_CHUNK_BYTES, remaining)
        chunk = _os.read(descriptor, maximum)
        if type(chunk) is not bytes or not chunk or len(chunk) > maximum:
            raise OSError
        digest.update(chunk)
        remaining -= len(chunk)
    if _os.read(descriptor, 1) != b"":
        raise OSError
    return digest.hexdigest()


def _hash_wheel(
    directory: int, filename: str, file_flags: int, owned: list[int],
) -> tuple[str, int, tuple[int, ...]]:
    """Open, hash and revalidate one exact wheel relative to the held directory."""
    named = _regular_file(_os.stat(filename, dir_fd=directory, follow_symlinks=False))
    descriptor = _claim(_os.open(filename, file_flags, dir_fd=directory), owned)
    opened = _regular_file(_os.fstat(descriptor))
    expected = _fingerprint(opened)
    if _fingerprint(named) != expected:
        raise OSError
    digest = _hash_file(descriptor, opened.st_size)
    if _fingerprint(_regular_file(_os.fstat(descriptor))) != expected:
        raise OSError
    current = _regular_file(_os.stat(filename, dir_fd=directory, follow_symlinks=False))
    if _fingerprint(current) != expected:
        raise OSError
    return digest, descriptor, expected


def _revalidate_files(
    directory: int,
    opened: list[tuple[int, str, tuple[int, ...]]],
) -> None:
    """Recheck every retained wheel after all four hashes are complete."""
    for descriptor, filename, expected in opened:
        if _fingerprint(_regular_file(_os.fstat(descriptor))) != expected:
            raise OSError
        named = _regular_file(
            _os.stat(filename, dir_fd=directory, follow_symlinks=False)
        )
        if _fingerprint(named) != expected:
            raise OSError


def _revalidate_directories(
    opened: list[tuple[int, str | None, int | None, tuple[int, ...]]],
) -> None:
    """Detect replacement or mutation of any component after wheel hashing."""
    for descriptor, component, parent, expected in opened:
        if _fingerprint(_directory(_os.fstat(descriptor))) != expected:
            raise OSError
        named = _directory(
            _os.stat("/", follow_symlinks=False)
            if component is None
            else _os.stat(component, dir_fd=parent, follow_symlinks=False)
        )
        if _fingerprint(named) != expected:
            raise OSError


def _close(owned: list[int]) -> tuple[bool, BaseException | None]:
    """Close every descriptor exactly once, retaining cleanup failure state."""
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


def _qualify(
    path: str,
    requirement: "_integrity.PythonEnvironmentIntegrityRequirement",
    owned: list[int],
) -> DevWheelhouseEvidence:
    """Perform one complete read-only qualification while descriptors are owned."""
    directory_flags, file_flags = _flags()
    opened, directory = _open_path(path, directory_flags, owned)
    expected_names = tuple(sorted(wheel.filename for wheel in requirement.wheels))
    if len(expected_names) != 4 or len(set(expected_names)) != 4:
        raise OSError
    if _entry_names(directory) != expected_names:
        raise OSError
    files = []
    opened_files = []
    for wheel in requirement.wheels:
        digest, descriptor, fingerprint = _hash_wheel(
            directory, wheel.filename, file_flags, owned,
        )
        if digest != wheel.sha256:
            raise OSError
        files.append(WheelhouseFileEvidence(wheel.filename, digest))
        opened_files.append((descriptor, wheel.filename, fingerprint))
    if _entry_names(directory) != expected_names:
        raise OSError
    _revalidate_files(directory, opened_files)
    _revalidate_directories(opened)
    return DevWheelhouseEvidence(path, "sha256", tuple(files), requirement)


def qualify_dev_wheelhouse(
    *, wheelhouse_path: str,
    integrity_contract: "_integrity.DevInstallationIntegrityContract",
) -> DevWheelhouseEvidence:
    """Return immutable exact-C24 evidence or one fixed qualification error."""
    owned: list[int] = []
    try:
        _path(wheelhouse_path, _UNAVAILABLE)
        if type(integrity_contract) is not _integrity.DevInstallationIntegrityContract:
            raise ValueError(_UNAVAILABLE)
        requirement = _requirement(
            integrity_contract.python_environment_requirement(), _UNAVAILABLE,
        )
        result = _qualify(wheelhouse_path, requirement, owned)
    except _CONTROL_EXCEPTIONS:
        _close(owned)
        raise
    except Exception:
        _failed, cleanup_control = _close(owned)
        if cleanup_control is not None:
            raise cleanup_control
        raise WheelhouseQualificationError(_UNAVAILABLE) from None
    cleanup_failed, cleanup_control = _close(owned)
    if cleanup_control is not None:
        raise cleanup_control
    if cleanup_failed:
        raise WheelhouseQualificationError(_UNAVAILABLE) from None
    return result
