"""deployment/rootless_docker_package_bundle_qualification.py - C32ZS.

Purpose:
- qualify one exact, root-controlled nine-file C32ZR package bundle without
  network access or host mutation;
- retain and revalidate directory/file descriptors while hashing every staged
  package byte before a future privileged bootstrap may consume the bundle.

Linked files:
- deployment/rootless_docker_installation_authority.py
- deployment/rootless_docker_preinstall_qualification.py
- deployment/README.md
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
import sys

from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY


__all__ = (
    "RootlessDockerPackageBundleQualificationError",
    "PackageBundleFileEvidence",
    "RootlessDockerPackageBundleEvidence",
    "qualify_rootless_docker_package_bundle",
)

_ERROR = "rootless Docker package bundle qualification is unavailable"
_MODEL_ERROR = "rootless Docker package bundle evidence is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_CHUNK = 64 * 1024
_ROOT_UID = 0
_ROOT_GID = 0


class RootlessDockerPackageBundleQualificationError(Exception):
    """One fixed external failure for exact staged-package qualification."""


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    """Capture mutation-relevant metadata while deliberately ignoring atime."""

    if type(value) is not os.stat_result or tuple.__len__(value) < 10:
        raise OSError
    if any(
        type(tuple.__getitem__(value, index)) not in (int, float)
        for index in range(10)
    ):
        raise OSError
    return (
        value.st_mode,
        value.st_ino,
        value.st_dev,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory(
    value: os.stat_result,
    *,
    uid: int,
    gid: int,
) -> tuple[int, ...]:
    """Require the exact private staged-bundle directory metadata."""

    if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0:
        raise OSError
    current = _fingerprint(value)
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_nlink < 2
        or value.st_uid != uid
        or value.st_gid != gid
        or stat.S_IMODE(value.st_mode)
        != INSTALLATION_AUTHORITY.staging_directory_mode
    ):
        raise OSError
    return current


def _regular(
    value: os.stat_result,
    *,
    uid: int,
    gid: int,
    expected_size: int,
) -> tuple[int, ...]:
    """Require one exact private staged package file metadata shape."""

    current = _fingerprint(value)
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_nlink != 1
        or value.st_uid != uid
        or value.st_gid != gid
        or stat.S_IMODE(value.st_mode)
        != INSTALLATION_AUTHORITY.staged_package_mode
        or value.st_size != expected_size
    ):
        raise OSError
    return current


@dataclass(frozen=True, slots=True)
class PackageBundleFileEvidence:
    """One exact C32ZR package payload observed in the staged bundle."""

    package: str
    filename: str
    size: int
    sha256: str
    fingerprint: tuple[int, ...]

    def __post_init__(self) -> None:
        """Bind evidence to exactly one reviewed C32ZR payload."""

        matches = tuple(
            item
            for item in INSTALLATION_AUTHORITY.payloads
            if item.package == self.package
        )
        if len(matches) != 1:
            raise ValueError(_MODEL_ERROR)
        expected = matches[0]
        if (
            type(self.filename) is not str
            or self.filename != expected.filename
            or type(self.size) is not int
            or self.size != expected.size
            or type(self.sha256) is not str
            or self.sha256 != expected.sha256
            or type(self.fingerprint) is not tuple
            or len(self.fingerprint) != 9
            or any(type(item) is not int for item in self.fingerprint)
            or not stat.S_ISREG(self.fingerprint[0])
            or stat.S_ISLNK(self.fingerprint[0])
            or self.fingerprint[3] != 1
            or self.fingerprint[4] != _ROOT_UID
            or self.fingerprint[5] != _ROOT_GID
            or self.fingerprint[6] != expected.size
            or stat.S_IMODE(self.fingerprint[0])
            != INSTALLATION_AUTHORITY.staged_package_mode
        ):
            raise ValueError(_MODEL_ERROR)


@dataclass(frozen=True, slots=True)
class RootlessDockerPackageBundleEvidence:
    """Immutable complete observation of the exact C32ZR package bundle."""

    staging_directory: str
    digest_algorithm: str
    total_size: int
    directory_fingerprint: tuple[int, ...]
    files: tuple[PackageBundleFileEvidence, ...]

    def __post_init__(self) -> None:
        """Reject incomplete, reordered, or authority-divergent evidence."""

        expected = INSTALLATION_AUTHORITY.payloads
        if (
            type(self.staging_directory) is not str
            or self.staging_directory != INSTALLATION_AUTHORITY.staging_directory
            or self.digest_algorithm != "sha256"
            or type(self.total_size) is not int
            or self.total_size != INSTALLATION_AUTHORITY.bundle_size()
            or type(self.directory_fingerprint) is not tuple
            or len(self.directory_fingerprint) != 9
            or any(type(item) is not int for item in self.directory_fingerprint)
            or not stat.S_ISDIR(self.directory_fingerprint[0])
            or stat.S_ISLNK(self.directory_fingerprint[0])
            or self.directory_fingerprint[3] < 2
            or self.directory_fingerprint[4] != _ROOT_UID
            or self.directory_fingerprint[5] != _ROOT_GID
            or stat.S_IMODE(self.directory_fingerprint[0])
            != INSTALLATION_AUTHORITY.staging_directory_mode
            or type(self.files) is not tuple
            or len(self.files) != len(expected)
        ):
            raise ValueError(_MODEL_ERROR)
        for evidence, payload in zip(self.files, expected, strict=True):
            if type(evidence) is not PackageBundleFileEvidence:
                raise ValueError(_MODEL_ERROR)
            PackageBundleFileEvidence.__post_init__(evidence)
            if (
                evidence.package != payload.package
                or evidence.filename != payload.filename
                or evidence.size != payload.size
                or evidence.sha256 != payload.sha256
            ):
                raise ValueError(_MODEL_ERROR)


def _root_identity() -> tuple[int, int, int, int]:
    """Require unchanged real/effective root identity."""

    identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if any(type(item) is not int or item != 0 for item in identity):
        raise OSError
    return identity


def _entry_names(directory: int) -> tuple[str, ...]:
    """Return the complete staged-directory entry-name set."""

    with os.scandir(directory) as iterator:
        names = tuple(entry.name for entry in iterator)
    if any(
        type(name) is not str
        or not name
        or "/" in name
        or "\\" in name
        or "\0" in name
        for name in names
    ):
        raise OSError
    return tuple(sorted(names))


def _hash_exact(descriptor: int, expected_size: int) -> str:
    """Hash exactly the reviewed size in bounded chunks, then require EOF."""

    if (
        type(descriptor) is not int
        or descriptor < 0
        or type(expected_size) is not int
        or expected_size <= 0
    ):
        raise OSError
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        maximum = min(_CHUNK, remaining)
        chunk = os.read(descriptor, maximum)
        if type(chunk) is not bytes or not chunk or len(chunk) > maximum:
            raise OSError
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1) != b"":
        raise OSError
    return digest.hexdigest()


def _trusted_parent(value: os.stat_result, *, uid: int, gid: int) -> None:
    """Require a retained ancestor that cannot be replaced by arbitrary users."""

    mode = stat.S_IMODE(value.st_mode)
    writable = bool(mode & 0o022)
    sticky_root = bool(mode & stat.S_ISVTX) and value.st_uid == 0
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_uid not in {0, uid}
        or value.st_gid not in {0, gid}
        or writable and not sticky_root
    ):
        raise OSError


def _open_directory_chain(
    path: str,
    *,
    uid: int,
    gid: int,
    owned: list[int],
) -> tuple[int, tuple[tuple[int, str | None, int | None, tuple[int, ...], bool], ...]]:
    """Traverse every absolute component without following symlinks."""

    if (
        type(path) is not str
        or not path.startswith("/")
        or path in ("", "/")
        or path.startswith("//")
        or "\\" in path
        or "\0" in path
        or any(part in ("", ".", "..") for part in path[1:].split("/"))
    ):
        raise OSError
    if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0:
        raise OSError

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    named_root = os.stat("/", follow_symlinks=False)
    root = os.open("/", flags)
    owned.append(root)
    opened_root = os.fstat(root)
    root_fp = _fingerprint(opened_root)
    if (
        _fingerprint(named_root) != root_fp
        or not stat.S_ISDIR(opened_root.st_mode)
        or stat.S_ISLNK(opened_root.st_mode)
        or opened_root.st_uid != 0
        or opened_root.st_gid != 0
        or stat.S_IMODE(opened_root.st_mode) & 0o022
    ):
        raise OSError

    chain: list[tuple[int, str | None, int | None, tuple[int, ...], bool]] = [
        (root, None, None, root_fp, False)
    ]
    parent = root
    parts = path[1:].split("/")
    for index, component in enumerate(parts):
        leaf = index == len(parts) - 1
        named = os.stat(component, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(named.st_mode) or stat.S_ISLNK(named.st_mode):
            raise OSError
        descriptor = os.open(component, flags, dir_fd=parent)
        owned.append(descriptor)
        opened = os.fstat(descriptor)
        expected = _fingerprint(opened)
        if _fingerprint(named) != expected:
            raise OSError
        if leaf:
            _directory(opened, uid=uid, gid=gid)
        else:
            _trusted_parent(opened, uid=uid, gid=gid)
        chain.append((descriptor, component, parent, expected, leaf))
        parent = descriptor
    return parent, tuple(chain)


def _revalidate_directory_chain(
    chain: tuple[tuple[int, str | None, int | None, tuple[int, ...], bool], ...],
    *,
    uid: int,
    gid: int,
) -> None:
    """Recheck retained directory descriptors and their named identities."""

    if not chain:
        raise OSError
    for descriptor, component, parent, expected, leaf in chain:
        current = os.fstat(descriptor)
        if _fingerprint(current) != expected:
            raise OSError
        named = (
            os.stat("/", follow_symlinks=False)
            if component is None
            else os.stat(component, dir_fd=parent, follow_symlinks=False)
        )
        if _fingerprint(named) != expected:
            raise OSError
        if leaf:
            _directory(current, uid=uid, gid=gid)
        else:
            _trusted_parent(current, uid=uid, gid=gid)


def _qualify_at(
    path: str,
    *,
    uid: int,
    gid: int,
) -> RootlessDockerPackageBundleEvidence:
    """Qualify one directory while retaining every opened object for rechecks."""

    owned: list[int] = []
    files: list[PackageBundleFileEvidence] = []
    try:
        directory, chain = _open_directory_chain(
            path,
            uid=uid,
            gid=gid,
            owned=owned,
        )
        expected_directory = chain[-1][3]
        expected_names = tuple(
            sorted(item.filename for item in INSTALLATION_AUTHORITY.payloads)
        )
        if _entry_names(directory) != expected_names:
            raise OSError

        file_flags = (
            os.O_RDONLY
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
            | os.O_NONBLOCK
        )
        opened_files: list[tuple[int, object, tuple[int, ...]]] = []
        for payload in INSTALLATION_AUTHORITY.payloads:
            named = os.stat(
                payload.filename,
                dir_fd=directory,
                follow_symlinks=False,
            )
            expected_file = _regular(
                named,
                uid=uid,
                gid=gid,
                expected_size=payload.size,
            )
            descriptor = os.open(
                payload.filename,
                file_flags,
                dir_fd=directory,
            )
            owned.append(descriptor)
            opened = _regular(
                os.fstat(descriptor),
                uid=uid,
                gid=gid,
                expected_size=payload.size,
            )
            if opened != expected_file:
                raise OSError
            digest = _hash_exact(descriptor, payload.size)
            if digest != payload.sha256:
                raise OSError
            if _regular(
                os.fstat(descriptor),
                uid=uid,
                gid=gid,
                expected_size=payload.size,
            ) != expected_file:
                raise OSError
            if _regular(
                os.stat(
                    payload.filename,
                    dir_fd=directory,
                    follow_symlinks=False,
                ),
                uid=uid,
                gid=gid,
                expected_size=payload.size,
            ) != expected_file:
                raise OSError
            opened_files.append((descriptor, payload, expected_file))
            files.append(
                PackageBundleFileEvidence(
                    package=payload.package,
                    filename=payload.filename,
                    size=payload.size,
                    sha256=digest,
                    fingerprint=expected_file,
                )
            )

        if _entry_names(directory) != expected_names:
            raise OSError
        for descriptor, payload, expected_file in opened_files:
            if _regular(
                os.fstat(descriptor),
                uid=uid,
                gid=gid,
                expected_size=payload.size,
            ) != expected_file:
                raise OSError
            if _regular(
                os.stat(
                    payload.filename,
                    dir_fd=directory,
                    follow_symlinks=False,
                ),
                uid=uid,
                gid=gid,
                expected_size=payload.size,
            ) != expected_file:
                raise OSError
        _revalidate_directory_chain(chain, uid=uid, gid=gid)

        return RootlessDockerPackageBundleEvidence(
            staging_directory=INSTALLATION_AUTHORITY.staging_directory,
            digest_algorithm="sha256",
            total_size=INSTALLATION_AUTHORITY.bundle_size(),
            directory_fingerprint=expected_directory,
            files=tuple(files),
        )
    finally:
        failure = False
        control = None
        for descriptor in reversed(owned):
            try:
                if os.close(descriptor) is not None:
                    failure = True
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
        owned.clear()
        active = sys.exception()
        if control is not None and not isinstance(active, _CONTROL):
            raise control
        if failure and active is None:
            raise OSError


def qualify_rootless_docker_package_bundle() -> RootlessDockerPackageBundleEvidence:
    """Require two identical root-only observations of the exact staged bundle."""

    try:
        identity = _root_identity()
        first = _qualify_at(
            INSTALLATION_AUTHORITY.staging_directory,
            uid=_ROOT_UID,
            gid=_ROOT_GID,
        )
        if _root_identity() != identity:
            raise OSError
        second = _qualify_at(
            INSTALLATION_AUTHORITY.staging_directory,
            uid=_ROOT_UID,
            gid=_ROOT_GID,
        )
        if second != first or _root_identity() != identity:
            raise OSError
        return first
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerPackageBundleQualificationError(_ERROR) from None
