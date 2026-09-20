"""Closed, read-only C31P qualification of one staged pip installer wheel."""

from dataclasses import dataclass as _dataclass
import hashlib as _hashlib
import os as _os
import stat as _stat

from . import pip_installer_provenance as _provenance

__all__ = (
    "PipInstallerQualificationError",
    "DevPipInstallerEvidence",
    "qualify_dev_pip_installer",
)

_UNAVAILABLE = "DEV pip installer qualification is unavailable"
_MODEL_ERROR = "DEV pip installer qualification evidence is invalid"
_HASH_CHUNK_BYTES = 64 * 1024
_CONTROL_EXCEPTIONS = (KeyboardInterrupt, SystemExit, GeneratorExit)


class PipInstallerQualificationError(Exception):
    """The staged directory cannot produce exact C31P installer evidence."""


def _path(value: object, error: str) -> None:
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


def _reviewed() -> _provenance.DevPipInstallerProvenance:
    value = _provenance.DevPipInstallerProvenance()
    _provenance.DevPipInstallerProvenance.__post_init__(value)
    return value


@_dataclass(frozen=True, slots=True)
class DevPipInstallerEvidence:
    """Immutable evidence for one exact wheel in one dedicated staging path."""

    staging_directory: str
    digest_algorithm: str
    artifact: _provenance.PipInstallerArtifactEvidence

    def __post_init__(self) -> None:
        try:
            _path(self.staging_directory, _MODEL_ERROR)
            if type(self.digest_algorithm) is not str or self.digest_algorithm != "sha256":
                raise ValueError(_MODEL_ERROR)
            expected = _reviewed().artifact
            if type(self.artifact) is not _provenance.PipInstallerArtifactEvidence:
                raise ValueError(_MODEL_ERROR)
            _provenance.PipInstallerArtifactEvidence.__post_init__(self.artifact)
            if self.artifact != expected:
                raise ValueError(_MODEL_ERROR)
        except _CONTROL_EXCEPTIONS:
            raise
        except Exception:
            raise ValueError(_MODEL_ERROR) from None


def _status(value: object) -> _os.stat_result:
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
    result = _status(value)
    if not _stat.S_ISDIR(result.st_mode) or _stat.S_ISLNK(result.st_mode):
        raise OSError
    return result


def _regular_file(value: object) -> _os.stat_result:
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
    return (
        value.st_mode, value.st_ino, value.st_dev, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _claim(value: object, owned: list[int]) -> int:
    if type(value) is not int or value < 0 or value in owned:
        raise OSError
    owned.append(value)
    if _os.get_inheritable(value) is not False:
        raise OSError
    return value


def _flags() -> tuple[int, int]:
    names = ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if any(type(getattr(_os, name, None)) is not int for name in names):
        raise OSError
    directory = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    regular = _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK
    return directory, regular


def _open_path(
    path: str, directory_flags: int, owned: list[int],
) -> tuple[list[tuple[int, str | None, int | None, tuple[int, ...]]], int]:
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
    with _os.scandir(directory) as iterator:
        names = tuple(entry.name for entry in iterator)
    if any(type(name) is not str or not name or "/" in name or "\0" in name for name in names):
        raise OSError
    return tuple(sorted(names))


def _hash_file(descriptor: int, expected_size: int) -> str:
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


def _revalidate_directories(
    opened: list[tuple[int, str | None, int | None, tuple[int, ...]]],
) -> None:
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


def _qualify_open(
    path: str, owned: list[int],
) -> tuple[
    DevPipInstallerEvidence,
    int,
    tuple[int, str, tuple[int, ...]],
    list[tuple[int, str | None, int | None, tuple[int, ...]]],
]:
    """Qualify while retaining the exact descriptor for private C31B composition."""
    reviewed = _reviewed()
    artifact = reviewed.artifact
    directory_flags, file_flags = _flags()
    opened_directories, directory = _open_path(path, directory_flags, owned)
    expected_names = (artifact.filename,)
    if _entry_names(directory) != expected_names:
        raise OSError
    named = _regular_file(
        _os.stat(artifact.filename, dir_fd=directory, follow_symlinks=False)
    )
    if named.st_size != artifact.size:
        raise OSError
    descriptor = _claim(
        _os.open(artifact.filename, file_flags, dir_fd=directory), owned,
    )
    opened = _regular_file(_os.fstat(descriptor))
    expected = _fingerprint(opened)
    if _fingerprint(named) != expected or opened.st_size != artifact.size:
        raise OSError
    if _hash_file(descriptor, artifact.size) != artifact.sha256:
        raise OSError
    if _fingerprint(_regular_file(_os.fstat(descriptor))) != expected:
        raise OSError
    current = _regular_file(
        _os.stat(artifact.filename, dir_fd=directory, follow_symlinks=False)
    )
    if _fingerprint(current) != expected or _entry_names(directory) != expected_names:
        raise OSError
    _revalidate_directories(opened_directories)
    evidence = DevPipInstallerEvidence(path, "sha256", artifact)
    return evidence, directory, (descriptor, artifact.filename, expected), opened_directories


def _qualify(path: str, owned: list[int]) -> DevPipInstallerEvidence:
    evidence, _directory, _file, _directories = _qualify_open(path, owned)
    return evidence


def _close(owned: list[int]) -> tuple[bool, BaseException | None]:
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


def qualify_dev_pip_installer(*, staging_directory: str) -> DevPipInstallerEvidence:
    """Return immutable exact-C31P evidence or one fixed qualification error."""
    owned: list[int] = []
    try:
        _path(staging_directory, _UNAVAILABLE)
        result = _qualify(staging_directory, owned)
    except _CONTROL_EXCEPTIONS:
        _close(owned)
        raise
    except Exception:
        _failed, cleanup_control = _close(owned)
        if cleanup_control is not None:
            raise cleanup_control
        raise PipInstallerQualificationError(_UNAVAILABLE) from None
    cleanup_failed, cleanup_control = _close(owned)
    if cleanup_control is not None:
        raise cleanup_control
    if cleanup_failed:
        raise PipInstallerQualificationError(_UNAVAILABLE) from None
    return result
