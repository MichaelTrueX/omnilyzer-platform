"""deployment/rootless_docker_package_staging.py - C32ZU exact bundle staging.

Purpose:
- stage the reviewed C32ZR nine-package bundle through fixed HTTPS URLs into
  one root-controlled private directory;
- support safe resume of exact root-owned partial package files without
  accepting caller paths, URLs, package names, redirects, proxies, or shell
  execution;
- atomically publish only a fully reverified bundle for C32ZS qualification.

Linked files:
- deployment/rootless_docker_installation_authority.py
- deployment/rootless_docker_preinstall_qualification.py
- deployment/rootless_docker_package_bundle_qualification.py
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import hashlib
import http.client
import os
import ssl
import stat
from urllib.parse import urlsplit

from . import dev_host_provisioning_orchestration as orchestration
from .rootless_docker_installation_authority import (
    INSTALLATION_AUTHORITY,
    PackagePayloadAuthority,
)
from .rootless_docker_package_bundle_qualification import (
    RootlessDockerPackageBundleEvidence,
    qualify_rootless_docker_package_bundle,
)
from .rootless_docker_preinstall_qualification import (
    qualify_rootless_docker_preinstall,
)


__all__ = (
    "RootlessDockerPackageStagingError",
    "RootlessDockerPackageStagingEvidence",
    "stage_rootless_docker_package_bundle",
)

_ERROR = "rootless Docker package staging is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_PARENT = "/var/lib/omnilyzer/deployment"
_FINAL_NAME = ".rootless-docker-install"
_INCOMING_NAME = ".rootless-docker-install.incoming"
_ROOT_UID = 0
_ROOT_GID = 0
_PARENT_MODE = 0o755
_NETWORK_TIMEOUT = 30.0
_CHUNK = 64 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_WRITE_FLAGS = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class RootlessDockerPackageStagingError(Exception):
    """One fixed external failure for exact package-bundle staging."""


@dataclass(frozen=True, slots=True)
class RootlessDockerPackageStagingEvidence:
    """Compact result of one completed or already-complete staging operation."""

    staging_directory: str
    total_size: int
    sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        """Bind returned evidence to the exact C32ZR payload set."""

        expected = INSTALLATION_AUTHORITY.payloads
        if (
            self.staging_directory != INSTALLATION_AUTHORITY.staging_directory
            or self.total_size != INSTALLATION_AUTHORITY.bundle_size()
            or self.sha256s != tuple(item.sha256 for item in expected)
        ):
            raise ValueError(_ERROR)

def _root_identity() -> tuple[int, int, int, int]:
    """Require exact real/effective root process identity."""

    identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if any(type(value) is not int or value != 0 for value in identity):
        raise OSError
    return identity


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    """Capture mutation-relevant metadata while ignoring access time."""

    if type(value) is not os.stat_result:
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


def _trusted_directory(
    value: os.stat_result,
    *,
    mode: int,
) -> tuple[int, ...]:
    """Require one root-owned non-symlink directory with exact mode."""

    current = _fingerprint(value)
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_nlink < 2
        or value.st_uid != _ROOT_UID
        or value.st_gid != _ROOT_GID
        or stat.S_IMODE(value.st_mode) != mode
    ):
        raise OSError
    return current


def _package_file(
    value: os.stat_result,
    *,
    maximum_size: int,
) -> tuple[int, ...]:
    """Require one private root-owned regular package file."""

    current = _fingerprint(value)
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_nlink != 1
        or value.st_uid != _ROOT_UID
        or value.st_gid != _ROOT_GID
        or stat.S_IMODE(value.st_mode)
        != INSTALLATION_AUTHORITY.staged_package_mode
        or value.st_size < 0
        or value.st_size > maximum_size
    ):
        raise OSError
    return current


def _open_parent(
    owned: list[int],
) -> tuple[
    int,
    tuple[tuple[int, str | None, int | None, tuple[int, ...]], ...],
]:
    """Open and retain the complete fixed parent chain without symlinks."""

    parent = None
    chain: list[tuple[int, str | None, int | None, tuple[int, ...]]] = []
    named_root = os.stat("/", follow_symlinks=False)
    root = os.open("/", _DIRECTORY_FLAGS)
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
    chain.append((root, None, None, root_fp))
    parent = root
    for component in ("var", "lib", "omnilyzer", "deployment"):
        named = os.stat(component, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
        owned.append(descriptor)
        opened = os.fstat(descriptor)
        current = _fingerprint(opened)
        if (
            _fingerprint(named) != current
            or not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise OSError
        chain.append((descriptor, component, parent, current))
        parent = descriptor
    if stat.S_IMODE(os.fstat(parent).st_mode) != _PARENT_MODE:
        raise OSError
    return parent, tuple(chain)
def _same_directory_identity(
    current: tuple[int, ...],
    expected: tuple[int, ...],
) -> bool:
    """Compare stable directory identity while allowing own child mutations."""

    return (
        len(current) == 9
        and len(expected) == 9
        and current[0] == expected[0]
        and current[1] == expected[1]
        and current[2] == expected[2]
        and current[4] == expected[4]
        and current[5] == expected[5]
    )


def _revalidate_chain(
    chain: tuple[
        tuple[int, str | None, int | None, tuple[int, ...]], ...
    ],
) -> None:
    """Revalidate retained parent identities after controlled child mutations."""

    if len(chain) != 5:
        raise OSError
    for index, (descriptor, component, parent, expected) in enumerate(chain):
        current = _fingerprint(os.fstat(descriptor))
        named = _fingerprint(
            os.stat("/", follow_symlinks=False)
            if component is None
            else os.stat(component, dir_fd=parent, follow_symlinks=False)
        )
        if index == len(chain) - 1:
            if (
                not _same_directory_identity(current, expected)
                or not _same_directory_identity(named, expected)
                or stat.S_IMODE(current[0]) != _PARENT_MODE
                or current[4] != _ROOT_UID
                or current[5] != _ROOT_GID
            ):
                raise OSError
        elif current != expected or named != expected:
            raise OSError


def _entry_names(directory: int) -> tuple[str, ...]:
    """Return a validated sorted entry-name list for the incoming directory."""
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
    """Hash exactly one reviewed payload size and require EOF."""
    if (
        type(descriptor) is not int
        or descriptor < 0
        or type(expected_size) is not int
        or expected_size <= 0
    ):
        raise OSError
    if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
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


def _write_all(descriptor: int, payload: bytes) -> None:
    """Write one response chunk completely to the secured package descriptor."""

    if type(descriptor) is not int or descriptor < 0 or type(payload) is not bytes:
        raise OSError
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if type(written) is not int or written <= 0 or written > len(view):
            raise OSError
        view = view[written:]


def _download_payload(payload: PackagePayloadAuthority, descriptor: int) -> None:
    """Fetch one reviewed HTTPS payload without proxies, redirects, or shell use."""

    if (
        type(payload) is not PackagePayloadAuthority
        or payload not in INSTALLATION_AUTHORITY.payloads
        or type(descriptor) is not int
        or descriptor < 0
    ):
        raise OSError
    parsed = urlsplit(payload.url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in {"archive.ubuntu.com", "download.docker.com"}
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise OSError

    context = ssl.create_default_context(
        cafile="/etc/ssl/certs/ca-certificates.crt"
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        443,
        timeout=_NETWORK_TIMEOUT,
        context=context,
    )
    response = None
    try:
        connection.request(
            "GET",
            parsed.path,
            headers={
                "Accept-Encoding": "identity",
                "Connection": "close",
                "User-Agent": "Omnilyzer-C32ZU/1",
            },
        )
        response = connection.getresponse()
        length = response.getheader("Content-Length")
        encoding = response.getheader("Content-Encoding")
        transfer_encoding = response.getheader("Transfer-Encoding")
        content_range = response.getheader("Content-Range")
        location = response.getheader("Location")
        if (
            response.status != 200
            or type(length) is not str
            or not length.isdecimal()
            or str(int(length)) != length
            or int(length) != payload.size
            or encoding not in (None, "identity")
            or transfer_encoding is not None
            or content_range is not None
            or location is not None
        ):
            raise OSError

        received = 0
        while received < payload.size:
            requested = min(_CHUNK, payload.size - received)
            chunk = response.read(requested)
            if (
                type(chunk) is not bytes
                or not chunk
                or len(chunk) > requested
            ):
                raise OSError
            _write_all(descriptor, chunk)
            received += len(chunk)
        if received != payload.size or response.read(1) != b"":
            raise OSError
    finally:
        if response is not None:
            response.close()
        connection.close()


def _open_incoming(parent: int) -> tuple[int, tuple[int, ...]]:
    """Create or securely reopen the deterministic private incoming directory."""

    created = False
    try:
        named = os.stat(
            _INCOMING_NAME,
            dir_fd=parent,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        os.mkdir(
            _INCOMING_NAME,
            INSTALLATION_AUTHORITY.staging_directory_mode,
            dir_fd=parent,
        )
        if os.fsync(parent) is not None:
            raise OSError
        created = True
        named = os.stat(
            _INCOMING_NAME,
            dir_fd=parent,
            follow_symlinks=False,
        )
    if not created:
        _trusted_directory(
            named,
            mode=INSTALLATION_AUTHORITY.staging_directory_mode,
        )
    directory = os.open(_INCOMING_NAME, _DIRECTORY_FLAGS, dir_fd=parent)
    if created:
        os.fchmod(directory, INSTALLATION_AUTHORITY.staging_directory_mode)
        os.fchown(directory, _ROOT_UID, _ROOT_GID)
    opened = os.fstat(directory)
    expected = _trusted_directory(
        opened,
        mode=INSTALLATION_AUTHORITY.staging_directory_mode,
    )
    if _fingerprint(
        os.stat(_INCOMING_NAME, dir_fd=parent, follow_symlinks=False)
    ) != expected:
        raise OSError
    return directory, expected


def _existing_payload(
    directory: int,
    payload: PackagePayloadAuthority,
) -> tuple[int, tuple[int, ...], bool]:
    """Open one absent, partial, or complete reviewed package file safely."""
    if (
        type(payload) is not PackagePayloadAuthority
        or payload not in INSTALLATION_AUTHORITY.payloads
    ):
        raise OSError
    try:
        named = os.stat(
            payload.filename,
            dir_fd=directory,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        descriptor = os.open(
            payload.filename,
            _WRITE_FLAGS | os.O_CREAT | os.O_EXCL,
            INSTALLATION_AUTHORITY.staged_package_mode,
            dir_fd=directory,
        )
        os.fchmod(descriptor, INSTALLATION_AUTHORITY.staged_package_mode)
        os.fchown(descriptor, _ROOT_UID, _ROOT_GID)
        current = _package_file(os.fstat(descriptor), maximum_size=payload.size)
        return descriptor, current, False

    expected = _package_file(named, maximum_size=payload.size)
    descriptor = os.open(payload.filename, _WRITE_FLAGS, dir_fd=directory)
    opened = _package_file(os.fstat(descriptor), maximum_size=payload.size)
    if opened != expected:
        os.close(descriptor)
        raise OSError
    if (
        opened[6] == payload.size
        and _hash_exact(descriptor, payload.size) == payload.sha256
        and _package_file(
            os.fstat(descriptor), maximum_size=payload.size
        ) == expected
    ):
        return descriptor, expected, True
    if os.ftruncate(descriptor, 0) is not None:
        os.close(descriptor)
        raise OSError
    if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
        os.close(descriptor)
        raise OSError
    return descriptor, _fingerprint(os.fstat(descriptor)), False


def _stage_payload(directory: int, payload: PackagePayloadAuthority) -> bool:
    """Reuse an exact payload or rewrite only its safe exact partial file."""
    descriptor = None
    try:
        descriptor, _before, complete = _existing_payload(directory, payload)
        if complete:
            return False
        _download_payload(payload, descriptor)
        if os.fsync(descriptor) is not None:
            raise OSError
        current = _package_file(os.fstat(descriptor), maximum_size=payload.size)
        if current[6] != payload.size:
            raise OSError
        if _hash_exact(descriptor, payload.size) != payload.sha256:
            raise OSError
        if _package_file(
            os.fstat(descriptor), maximum_size=payload.size
        ) != current:
            raise OSError
        return True
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _stage_incoming(parent: int, chain) -> tuple[str, ...]:
    """Complete the deterministic incoming directory and reverify every byte."""
    directory = None
    downloaded: list[str] = []
    try:
        directory, _initial_directory = _open_incoming(parent)
        expected_names = {
            item.filename for item in INSTALLATION_AUTHORITY.payloads
        }
        if not set(_entry_names(directory)).issubset(expected_names):
            raise OSError
        for payload in INSTALLATION_AUTHORITY.payloads:
            if _stage_payload(directory, payload):
                downloaded.append(payload.filename)
        if _entry_names(directory) != tuple(sorted(expected_names)):
            raise OSError
        for payload in INSTALLATION_AUTHORITY.payloads:
            descriptor = os.open(payload.filename, _READ_FLAGS, dir_fd=directory)
            try:
                current = _package_file(
                    os.fstat(descriptor), maximum_size=payload.size
                )
                if (
                    current[6] != payload.size
                    or _hash_exact(descriptor, payload.size) != payload.sha256
                ):
                    raise OSError
                if _package_file(
                    os.fstat(descriptor), maximum_size=payload.size
                ) != current:
                    raise OSError
                if _fingerprint(
                    os.stat(
                        payload.filename,
                        dir_fd=directory,
                        follow_symlinks=False,
                    )
                ) != current:
                    raise OSError
            finally:
                os.close(descriptor)
        if os.fsync(directory) is not None:
            raise OSError
        current_directory = _trusted_directory(
            os.fstat(directory),
            mode=INSTALLATION_AUTHORITY.staging_directory_mode,
        )
        if _trusted_directory(
            os.stat(
                _INCOMING_NAME,
                dir_fd=parent,
                follow_symlinks=False,
            ),
            mode=INSTALLATION_AUTHORITY.staging_directory_mode,
        ) != current_directory:
            raise OSError
        _revalidate_chain(chain)
        return tuple(downloaded)
    finally:
        if directory is not None:
            os.close(directory)


def _named_exists(parent: int, name: str) -> bool:
    """Return whether one fixed child name exists in any filesystem form."""

    if name not in {_FINAL_NAME, _INCOMING_NAME}:
        raise OSError
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _final_exists(parent: int) -> bool:
    """Return whether the fixed final staging directory exists at all."""

    return _named_exists(parent, _FINAL_NAME)


def _rename_incoming_noreplace(parent: int) -> None:
    """Publish the fixed incoming directory with Linux RENAME_NOREPLACE."""

    if type(parent) is not int or parent < 0:
        raise OSError
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.renameat2
    operation.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    operation.restype = ctypes.c_int
    ctypes.set_errno(0)
    if operation(
        parent,
        _INCOMING_NAME.encode("ascii"),
        parent,
        _FINAL_NAME.encode("ascii"),
        1,
    ) != 0:  # RENAME_NOREPLACE
        raise OSError(ctypes.get_errno())


def _publish(parent: int, chain) -> None:
    """Atomically publish the complete incoming directory without replacement."""

    if _final_exists(parent):
        raise OSError
    descriptor = None
    try:
        named = _trusted_directory(
            os.stat(
                _INCOMING_NAME,
                dir_fd=parent,
                follow_symlinks=False,
            ),
            mode=INSTALLATION_AUTHORITY.staging_directory_mode,
        )
        descriptor = os.open(_INCOMING_NAME, _DIRECTORY_FLAGS, dir_fd=parent)
        opened = _trusted_directory(
            os.fstat(descriptor),
            mode=INSTALLATION_AUTHORITY.staging_directory_mode,
        )
        if opened != named:
            raise OSError
        _revalidate_chain(chain)
        _rename_incoming_noreplace(parent)
        if os.fsync(parent) is not None:
            raise OSError
        try:
            os.stat(
                _INCOMING_NAME,
                dir_fd=parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise OSError
        current = _trusted_directory(
            os.fstat(descriptor),
            mode=INSTALLATION_AUTHORITY.staging_directory_mode,
        )
        published = _trusted_directory(
            os.stat(
                _FINAL_NAME,
                dir_fd=parent,
                follow_symlinks=False,
            ),
            mode=INSTALLATION_AUTHORITY.staging_directory_mode,
        )
        if (
            not _same_directory_identity(current, opened)
            or not _same_directory_identity(published, current)
        ):
            raise OSError
        _revalidate_chain(chain)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _result_from_bundle(
    bundle: RootlessDockerPackageBundleEvidence,
) -> RootlessDockerPackageStagingEvidence:
    """Reduce complete C32ZS evidence to stable public staging evidence."""
    if type(bundle) is not RootlessDockerPackageBundleEvidence:
        raise OSError
    return RootlessDockerPackageStagingEvidence(
        staging_directory=bundle.staging_directory,
        total_size=bundle.total_size,
        sha256s=tuple(item.sha256 for item in bundle.files),
    )


def stage_rootless_docker_package_bundle() -> RootlessDockerPackageStagingEvidence:
    """Download/resume and atomically publish the exact reviewed package bundle."""

    owned: list[int] = []
    lock = None
    failure = False
    control = None
    result = None
    try:
        identity = _root_identity()
        if (
            os.path.join(_PARENT, _FINAL_NAME)
            != INSTALLATION_AUTHORITY.staging_directory
            or _INCOMING_NAME != _FINAL_NAME + ".incoming"
        ):
            raise OSError
        lock = orchestration._acquire_process_lock()
        parent, chain = _open_parent(owned)
        if _final_exists(parent):
            if _named_exists(parent, _INCOMING_NAME):
                raise OSError
            bundle = qualify_rootless_docker_package_bundle()
            if _root_identity() != identity:
                raise OSError
            result = _result_from_bundle(bundle)
        else:
            before = qualify_rootless_docker_preinstall()
            if _root_identity() != identity:
                raise OSError
            _stage_incoming(parent, chain)
            after = qualify_rootless_docker_preinstall()
            if after != before or _root_identity() != identity:
                raise OSError
            _publish(parent, chain)
            bundle = qualify_rootless_docker_package_bundle()
            if _root_identity() != identity:
                raise OSError
            result = _result_from_bundle(bundle)
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        for descriptor in reversed(owned):
            try:
                if os.close(descriptor) is not None:
                    failure = True
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
        owned.clear()
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
        raise RootlessDockerPackageStagingError(_ERROR) from None
    return result

