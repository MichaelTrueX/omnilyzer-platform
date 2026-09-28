"""Explicit C32M root-only static installation; import is inert, with no CLI.

Requalify held sources, copy/hash in bounded chunks, independently verify the
destination and publish without replacement. Only exact Cosign-first prefixes
are resumable. No broker JSON, service, tool execution or activation occurs.
"""

from dataclasses import dataclass as _dataclass
import hashlib as _hashlib
import os as _os
import stat as _stat
import sys as _sys

from . import dev_host_provisioning_mechanics as _mechanics
from . import dev_host_provisioning_orchestration as _orchestration
from . import host_provisioning_contract as _historical
from . import sigstore_resource_contract as _resources
from . import sigstore_toolchain_qualification as _qualification
from . import wheelhouse_qualification as _staging
from .broker_service_config import DevBrokerServiceConfiguration as _Configuration

__all__ = (
    "SigstoreStaticInstallationError", "SigstoreStaticFileInstallationEvidence",
    "DevSigstoreStaticInstallationEvidence", "install_dev_sigstore_static_resources",
)
_ERROR = "DEV Sigstore static resource installation is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_TEMPORARY = ".omnilyzer-c32m-install.tmp"
_CHUNK = 64 * 1024


class SigstoreStaticInstallationError(Exception):
    """One fixed external failure without private source or syscall diagnostics."""


@_dataclass(frozen=True, slots=True)
class SigstoreStaticFileInstallationEvidence:
    """An exact final resource observation, without bytes or live descriptors."""

    path: str
    size: int
    sha256: str
    fingerprint: tuple[int, ...]

    def __post_init__(self) -> None:
        try:
            fp = _qualification._evidence_fingerprint(self.fingerprint)
            if (not _stat.S_ISREG(fp[0]) or fp[3] != 1 or fp[4] != 0
                    or not 0 < fp[5] <= 2**32 - 2):
                raise ValueError
            for path, mode, size, digest in _resources._artifacts():
                if (_resources._same((self.path, self.size, self.sha256), (path, size, digest))
                        and fp[6] == size and _stat.S_IMODE(fp[0]) == mode):
                    return
            raise ValueError
        except _CONTROL:
            raise
        except Exception:
            raise ValueError(_ERROR) from None


@_dataclass(frozen=True, slots=True)
class DevSigstoreStaticInstallationEvidence:
    """Complete immutable installation observation; no staging trust capability."""

    operation: str
    broker_gid: int
    cosign: SigstoreStaticFileInstallationEvidence
    trusted_root: SigstoreStaticFileInstallationEvidence

    def __post_init__(self) -> None:
        try:
            if (type(self.operation) is not str or self.operation not in ("installed", "already-installed")
                    or type(self.broker_gid) is not int or not 0 < self.broker_gid <= 2**32 - 2):
                raise ValueError
            for value, artifact in zip((self.cosign, self.trusted_root), _resources._artifacts(), strict=True):
                if type(value) is not SigstoreStaticFileInstallationEvidence:
                    raise ValueError
                SigstoreStaticFileInstallationEvidence.__post_init__(value)
                if value.path != artifact[0] or value.fingerprint[5] != self.broker_gid:
                    raise ValueError
        except _CONTROL:
            raise
        except Exception:
            raise ValueError(_ERROR) from None


@_dataclass(frozen=True, slots=True)
class _Source:
    directory: int
    chain: tuple[tuple[int, str | None, int | None, tuple[int, ...]], ...]
    files: tuple[tuple[int, str, tuple[int, ...]], ...]


@_dataclass(slots=True)
class _Destination:
    parent: int
    name: str
    directory: int | None
    chain: list[tuple[int, int | None, str | None, tuple[int, ...]]]
    requirement: _resources.HostResourceRequirement
    file: _resources.SigstoreStaticFileRequirement
    existing: tuple[int, ...] | None


def _root() -> None:
    values = (_os.getuid(), _os.geteuid(), _os.getgid(), _os.getegid())
    if any(type(value) is not int or value != 0 for value in values):
        raise OSError


def _none(value: object) -> None:
    if value is not None:
        raise OSError


def _source(path: str, requirements: tuple[_resources.SigstoreStaticFileRequirement, ...],
            owned: list[int]) -> _Source:
    flags, file_flags = _staging._flags()
    chain, directory = _staging._open_path(path, flags, owned)
    final = _staging._directory(_os.fstat(directory))
    owner = (final.st_uid, final.st_gid)
    if any(type(value) is not int or not 0 < value <= 2**32 - 2 for value in owner):
        raise OSError
    for index, (descriptor, _name, _parent, fingerprint) in enumerate(chain):
        if _qualification._directory(_os.fstat(descriptor), owner, final=index == len(chain) - 1) != fingerprint:
            raise OSError
    files = []
    artifacts = _qualification._artifacts()
    if _qualification._entry_names(directory) != tuple(sorted(item[0] for item in artifacts)):
        raise OSError
    for (filename, size, digest), requirement in zip(artifacts, requirements, strict=True):
        if (size, digest) != (requirement.size, requirement.sha256):
            raise OSError
        named = _qualification._file(_os.stat(filename, dir_fd=directory, follow_symlinks=False), size, owner)
        descriptor = _staging._claim(_os.open(filename, file_flags, dir_fd=directory), owned)
        opened = _qualification._file(_os.fstat(descriptor), size, owner)
        if named != opened or _qualification._hash_file(descriptor, size) != digest:
            raise OSError
        files.append((descriptor, filename, opened))
    source = _Source(directory, tuple(chain), tuple(files))
    _revalidate_source(source)
    return source


def _revalidate_source(source: _Source) -> None:
    if _qualification._entry_names(source.directory) != tuple(sorted(item[1] for item in source.files)):
        raise OSError
    _staging._revalidate_files(source.directory, source.files)
    _staging._revalidate_directories(source.chain)


def _directory(value: object, requirement: _resources.HostResourceRequirement | _historical.HostPathRequirement) -> tuple[int, ...]:
    current = _staging._directory(value)
    if (current.st_uid, current.st_gid, _stat.S_IMODE(current.st_mode)) != (
            requirement.owner_uid, requirement.group_gid, requirement.mode):
        raise OSError
    return _mechanics._directory_fingerprint(current)


def _file(value: object, requirement: _resources.SigstoreStaticFileRequirement, *, links: int = 1) -> tuple[int, ...]:
    current = _staging._regular_file(value)
    resource = requirement.resource
    if ((current.st_uid, current.st_gid, _stat.S_IMODE(current.st_mode), current.st_nlink, current.st_size)
            != (resource.owner_uid, resource.group_gid, resource.mode, links, requirement.size)):
        raise OSError
    return _staging._fingerprint(current)


def _verify_file(directory: int, name: str, requirement: _resources.SigstoreStaticFileRequirement,
                 owned: list[int], *, identity: tuple[int, int] | None = None,
                 durable: bool = False) -> tuple[int, ...]:
    named = _file(_os.stat(name, dir_fd=directory, follow_symlinks=False), requirement)
    if identity is not None and (named[2], named[1]) != identity:
        raise OSError
    _flags, file_flags = _staging._flags()
    descriptor = _staging._claim(_os.open(name, file_flags, dir_fd=directory), owned)
    opened = _file(_os.fstat(descriptor), requirement)
    if opened != named or _qualification._hash_file(descriptor, requirement.size) != requirement.sha256:
        raise OSError
    if durable:
        _none(_os.fsync(descriptor))
    if (_file(_os.fstat(descriptor), requirement) != opened
            or _file(_os.stat(name, dir_fd=directory, follow_symlinks=False), requirement) != opened):
        raise OSError
    return opened


def _destination(directory_requirement: _resources.HostResourceRequirement,
                 file_requirement: _resources.SigstoreStaticFileRequirement,
                 parent_requirements: dict[str, _historical.HostPathRequirement],
                 owned: list[int]) -> _Destination:
    parent_path, name = directory_requirement.path.rsplit("/", 1)
    parent, chain = _mechanics._open_directory(parent_path, owned)
    path = ""
    for descriptor, _parent, component, _expected in chain:
        path = path + "/" + component if component is not None else "/"
        if path.startswith("//"):
            path = path[1:]
        status = _staging._directory(_os.fstat(descriptor))
        requirement = parent_requirements.get(path)
        if requirement is not None:
            _directory(status, requirement)
        elif status.st_uid != 0 or _stat.S_IMODE(status.st_mode) & 0o022:
            raise OSError
    _mechanics._revalidate_chain(chain)
    directory = None
    existing = None
    try:
        named = _os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        expected = _directory(named, directory_requirement)
        flags, _file_flags = _staging._flags()
        directory = _staging._claim(_os.open(name, flags, dir_fd=parent), owned)
        if (_directory(_os.fstat(directory), directory_requirement) != expected
                or _qualification._fingerprint(named) != _qualification._fingerprint(_os.fstat(directory))):
            raise OSError
        chain.append((directory, parent, name, expected))
        _absent_temporary(directory)
        try:
            _os.stat(file_requirement.resource.path.rsplit("/", 1)[1], dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            existing = _verify_file(directory, file_requirement.resource.path.rsplit("/", 1)[1],
                                    file_requirement, owned)
    return _Destination(parent, name, directory, chain, directory_requirement, file_requirement, existing)


def _absent_temporary(directory: int) -> None:
    try:
        _os.stat(_TEMPORARY, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise OSError


def _ensure_leaf(destination: _Destination, owned: list[int]) -> None:
    if destination.directory is None:
        _root()
        requirement = destination.requirement
        descriptor, _created, _identity = _mechanics._ensure_exact_directory(
            destination.parent, destination.name, requirement.mode,
            requirement.owner_uid, requirement.group_gid,
        )
        _staging._claim(descriptor, owned)
        destination.directory = descriptor
        destination.chain.append((descriptor, destination.parent, destination.name,
                                  _directory(_os.fstat(descriptor), requirement)))
    _revalidate_destination(destination)
    _absent_temporary(destination.directory)


def _revalidate_destination(destination: _Destination) -> None:
    _mechanics._revalidate_chain(destination.chain)
    if destination.directory is not None:
        _directory(_os.fstat(destination.directory), destination.requirement)


def _cleanup_temporary(directory: int, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = _staging._regular_file(_os.stat(_TEMPORARY, dir_fd=directory, follow_symlinks=False))
    except FileNotFoundError:
        return
    if (current.st_dev, current.st_ino) != identity:
        raise OSError
    _none(_os.unlink(_TEMPORARY, dir_fd=directory))
    _none(_os.fsync(directory))


def _publish(source: _Source, source_descriptor: int, destination: _Destination,
             owned: list[int]) -> tuple[int, ...]:
    directory = destination.directory
    requirement = destination.file
    identity = None
    try:
        _root()
        _revalidate_source(source)
        _revalidate_destination(destination)
        temporary = _staging._claim(_os.open(
            _TEMPORARY, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | _os.O_NOFOLLOW | _os.O_CLOEXEC,
            0o600, dir_fd=directory,
        ), owned)
        created = _staging._regular_file(_os.fstat(temporary))
        identity = (created.st_dev, created.st_ino)
        if ((created.st_uid, created.st_gid, created.st_nlink, created.st_size) != (0, 0, 1, 0)
                or _stat.S_IMODE(created.st_mode) & ~0o600):
            raise OSError
        _os.lseek(source_descriptor, 0, _os.SEEK_SET)
        digest = _hashlib.sha256()
        remaining = requirement.size
        while remaining:
            maximum = min(_CHUNK, remaining)
            chunk = _os.read(source_descriptor, maximum)
            if type(chunk) is not bytes or not chunk or len(chunk) > maximum:
                raise OSError
            _mechanics._write_all(temporary, chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        eof = _os.read(source_descriptor, 1)
        if type(eof) is not bytes or eof != b"" or digest.hexdigest() != requirement.sha256:
            raise OSError
        _none(_os.fchown(temporary, requirement.resource.owner_uid, requirement.resource.group_gid))
        _none(_os.fchmod(temporary, requirement.resource.mode))
        _none(_os.fsync(temporary))
        ready = _file(_os.fstat(temporary), requirement)
        if (ready[2], ready[1]) != identity:
            raise OSError
        verified = _verify_file(directory, _TEMPORARY, requirement, owned, identity=identity)
        if verified != ready:
            raise OSError
        _revalidate_source(source)
        _revalidate_destination(destination)
        _root()
        if (_file(_os.fstat(temporary), requirement) != verified
                or _file(_os.stat(_TEMPORARY, dir_fd=directory, follow_symlinks=False), requirement) != verified):
            raise OSError
        name = requirement.resource.path.rsplit("/", 1)[1]
        _none(_os.link(_TEMPORARY, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False))
        linked = _file(_os.stat(name, dir_fd=directory, follow_symlinks=False), requirement, links=2)
        if ((linked[2], linked[1]) != identity
                or linked[:3] + linked[4:8] != verified[:3] + verified[4:8]
                or _file(_os.stat(_TEMPORARY, dir_fd=directory, follow_symlinks=False), requirement, links=2) != linked
                or _file(_os.fstat(temporary), requirement, links=2) != linked):
            raise OSError
        _none(_os.unlink(_TEMPORARY, dir_fd=directory))
        _none(_os.fsync(directory))
        result = _verify_file(directory, name, requirement, owned, identity=identity)
        _revalidate_destination(destination)
        return result
    finally:
        active = _sys.exception()
        try:
            _cleanup_temporary(directory, identity)
        except _CONTROL:
            if not isinstance(active, _CONTROL):
                raise
        except Exception:
            if active is None:
                raise


def _install(path: str, contract: _resources.DevSigstoreResourceContract,
             owned: list[int]) -> DevSigstoreStaticInstallationEvidence:
    files = contract.file_requirements()
    source = _source(path, files, owned)
    # Consume the unchanged C23 parents; never create/reconstruct them.
    historical = _historical.DevHostProvisioningContract(installation=contract.configuration.installation_contract())
    parents = {item.path: item for item in historical.path_requirements() if item.kind == "directory"}
    destinations = tuple(_destination(directory, file, parents, owned) for directory, file in
                         zip(contract.directory_requirements(), files, strict=True))
    if destinations[0].existing is None and destinations[1].existing is not None:
        raise OSError
    operation = "already-installed" if all(item.existing is not None for item in destinations) else "installed"
    for (source_descriptor, _name, _fingerprint), destination in zip(source.files, destinations, strict=True):
        _ensure_leaf(destination, owned)
        if destination.existing is None:
            destination.existing = _publish(source, source_descriptor, destination, owned)
    evidence = []
    for destination in destinations:
        _revalidate_source(source)
        _revalidate_destination(destination)
        name = destination.file.resource.path.rsplit("/", 1)[1]
        expected = destination.existing
        current = _verify_file(destination.directory, name, destination.file, owned,
                               identity=(expected[2], expected[1]), durable=True)
        if current != expected:
            raise OSError
        # Retry durability for exact prefixes left by an earlier fsync failure.
        _none(_os.fsync(destination.directory))
        _none(_os.fsync(destination.parent))
        evidence.append(SigstoreStaticFileInstallationEvidence(
            destination.file.resource.path, destination.file.size, destination.file.sha256, current,
        ))
    _revalidate_source(source)
    for destination in destinations:
        _revalidate_destination(destination)
        expected = destination.existing
        named = _file(_os.stat(destination.file.resource.path.rsplit("/", 1)[1],
                               dir_fd=destination.directory, follow_symlinks=False), destination.file)
        if named != expected:
            raise OSError
    _root()
    return DevSigstoreStaticInstallationEvidence(operation, contract.configuration.broker_gid, *evidence)


def _install_under_held_process_lock(*, staging_directory: str,
                                     configuration: _Configuration,
                                     held_lock: _orchestration._ProcessLock
                                     ) -> DevSigstoreStaticInstallationEvidence:
    """C32Y-only delegation to the same held-source installer under its lock.

    The caller already holds C31's deployment mutation lock. Reacquiring it
    through the public boundary would conflict with that nonblocking lock.
    """
    owned: list[int] = []
    failure = False
    control = None
    result = None
    try:
        _root()
        if (type(held_lock) is not _orchestration._ProcessLock
                or not held_lock.directory_chain
                or held_lock.directory_chain[-1][0] != held_lock.descriptor):
            raise OSError
        _staging._path(staging_directory, _ERROR)
        contract = _resources.DevSigstoreResourceContract(configuration=configuration)
        result = _install(staging_directory, contract, owned)
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        try:
            failed, cleanup_control = _mechanics._close(owned)
            failure = failure or failed
            control = control or cleanup_control
        except _CONTROL as error:
            control = control or error
        except Exception:
            failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise SigstoreStaticInstallationError(_ERROR) from None
    return result


def _qualify_installed(configuration: _Configuration) -> DevSigstoreStaticInstallationEvidence:
    """Read-only exact installed-state proof for C32Y's final qualification."""
    owned: list[int] = []
    failure = False
    control = None
    result = None
    try:
        contract = _resources.DevSigstoreResourceContract(configuration=configuration)
        historical = _historical.DevHostProvisioningContract(
            installation=contract.configuration.installation_contract())
        parents = {item.path: item for item in historical.path_requirements()
                   if item.kind == "directory"}
        destinations = tuple(_destination(directory, file, parents, owned)
                             for directory, file in zip(contract.directory_requirements(),
                                                        contract.file_requirements(), strict=True))
        if any(item.directory is None or item.existing is None for item in destinations):
            raise OSError
        evidence = []
        for item in destinations:
            _revalidate_destination(item)
            name = item.file.resource.path.rsplit("/", 1)[1]
            current = _verify_file(item.directory, name, item.file, owned)
            if current != item.existing:
                raise OSError
            evidence.append(SigstoreStaticFileInstallationEvidence(
                item.file.resource.path, item.file.size, item.file.sha256, current))
        result = DevSigstoreStaticInstallationEvidence(
            "already-installed", contract.configuration.broker_gid, *evidence)
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        try:
            failed, cleanup_control = _mechanics._close(owned)
            failure = failure or failed
            control = control or cleanup_control
        except _CONTROL as error:
            control = control or error
        except Exception:
            failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise SigstoreStaticInstallationError(_ERROR) from None
    return result


def install_dev_sigstore_static_resources(*, staging_directory: str,
                                         configuration: _Configuration) -> DevSigstoreStaticInstallationEvidence:
    """Explicit future mutation only; return complete evidence after cleanup/unlock."""
    owned: list[int] = []
    lock = None
    failure = False
    control = None
    try:
        _root()
        _staging._path(staging_directory, _ERROR)
        contract = _resources.DevSigstoreResourceContract(configuration=configuration)
        lock = _orchestration._acquire_process_lock()
        if type(lock) is not _orchestration._ProcessLock:
            raise OSError
        result = _install(staging_directory, contract, owned)
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        failed, cleanup_control = _mechanics._close(owned)
        failure = failure or failed
        control = control or cleanup_control
        if lock is not None:
            try:
                _none(_orchestration._release_process_lock(lock))
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
    if control is not None:
        raise control
    if failure:
        raise SigstoreStaticInstallationError(_ERROR) from None
    return result
