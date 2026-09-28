"""Explicit C32Y root-only broker prerequisites, with no import-time host work.

Privileged execution later requires separately reviewed root-controlled Python
source. An omnidev-writable checkout is never an acceptable execution source.
The application migration is a separate prerequisite; this module never runs it.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
import sys

from . import dev_host_provisioning_orchestration as lock_runtime
from . import dev_final_application_update as c32w_update
from . import privileged_host_runtime as host_runtime
from . import sigstore_static_installation as sigstore_installer
from .broker_host_service_contract import DevBrokerHostServiceContract
from .broker_service_config import parse_canonical_broker_service_configuration
from .final_application_generation import TARGET_REVIEWED_COMMIT
from .final_configuration_authority import DevFinalConfigurationAuthority, DevFinalConfigurationPair
from .replay_sqlite import PRODUCTION_REPLAY_DATABASE, SQLiteReplayGuard
from .root_executor_configuration_reader import read_root_dev_executor_configuration
from .unix_transport import PRODUCTION_EXECUTOR_SOCKET_PATH
from .wheelhouse_qualification import _path as _canonical_path

__all__ = ("FinalBrokerResourcesError", "FinalBrokerResourcesEvidence",
           "provision_final_dev_broker_resources", "qualify_final_dev_broker_resources")

_ERROR = "final DEV broker resources are unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_TEMPORARY = ".omnilyzer-c32y-install.tmp"
_UNIT_LIMIT = host_runtime._MAX_FILE_BYTES


class FinalBrokerResourcesError(Exception):
    """One non-diagnostic provisioning/qualification failure."""


@dataclass(frozen=True, slots=True)
class FinalBrokerResourcesEvidence:
    """No bytes or descriptors; outcomes order is broker dir, five runtime
    dirs, broker config, broker unit. Sigstore has separate exact C32M evidence.
    """

    operation: str
    reviewed_commit: str
    expected_workflow_sha: str
    broker_configuration_sha256: str
    unit_sha256: str
    sigstore: sigstore_installer.DevSigstoreStaticInstallationEvidence
    resource_outcomes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (type(self.operation) is not str
                or self.operation not in ("installed", "already-installed")
                or type(self.reviewed_commit) is not str
                or self.reviewed_commit != TARGET_REVIEWED_COMMIT
                or type(self.expected_workflow_sha) is not str
                or len(self.expected_workflow_sha) != 40
                or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
                or any(type(value) is not str or len(value) != 64
                       or any(c not in "0123456789abcdef" for c in value)
                       for value in (self.broker_configuration_sha256, self.unit_sha256))
                or type(self.sigstore) is not sigstore_installer.DevSigstoreStaticInstallationEvidence
                or type(self.resource_outcomes) is not tuple
                or len(self.resource_outcomes) != 8
                or any(type(value) is not str or value not in ("created", "unchanged")
                       for value in self.resource_outcomes)):
            raise ValueError(_ERROR)
        self.sigstore.__post_init__()


def _root() -> tuple[int, int, int, int]:
    identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if any(type(value) is not int or value != 0 for value in identity):
        raise OSError
    return identity


def _none(value: object) -> None:
    if value is not None:
        raise OSError


def _pair(workflow: str) -> tuple[DevFinalConfigurationPair, DevBrokerHostServiceContract]:
    installed = read_root_dev_executor_configuration()
    if installed.reviewed_commit != TARGET_REVIEWED_COMMIT:
        raise OSError
    authority = DevFinalConfigurationAuthority(executor_configuration=installed)
    pair = authority.configuration_pair(expected_workflow_sha=workflow)
    if type(pair) is not DevFinalConfigurationPair:
        raise OSError
    pair.__post_init__()
    host = DevBrokerHostServiceContract(configuration=pair.broker)
    state = c32w_update.qualify_final_application_update()
    if (type(state) is not c32w_update.FinalApplicationUpdateState
            or not state.configuration_current
            or state.selected_commit != TARGET_REVIEWED_COMMIT):
        raise OSError
    # C32W's separate read of the installed file must agree with our root read.
    if read_root_dev_executor_configuration().canonical_bytes() != pair.executor.canonical_bytes():
        raise OSError
    return pair, host


def _replay(host: DevBrokerHostServiceContract) -> None:
    directory, database = host.replay_requirements()
    if (directory.path != str(PRODUCTION_REPLAY_DATABASE.parent)
            or database.path != str(PRODUCTION_REPLAY_DATABASE)):
        raise OSError
    identity = host.configuration.installation_contract().broker_composition_kwargs()
    replay = SQLiteReplayGuard(
        PRODUCTION_REPLAY_DATABASE,
        expected_directory_uid=identity["expected_replay_directory_uid"],
        expected_directory_gid=identity["expected_replay_directory_gid"],
        expected_broker_uid=identity["expected_broker_uid"],
        expected_executor_uid=identity["expected_executor_uid"],
    )
    replay.validate()  # never initializes, resets or repairs the store
    socket = host.executor_socket_requirement()
    if (socket.path != PRODUCTION_EXECUTOR_SOCKET_PATH
            or socket.lifecycle != "future-reviewed-runtime-service-creation-only"
            or socket.group_gid not in host.configuration.installation_contract().broker_required_group_gids):
        raise OSError
    # The socket node is created by the existing socket unit only when active.


def _authorities(host: DevBrokerHostServiceContract) -> tuple[host_runtime._DirectoryAuthority, ...]:
    broker = host.broker_configuration_directory()
    runtime = host.runtime_directory_requirements()
    # Existing C23 parents are exact. The broker and runtime leaves are additive.
    from .host_provisioning_contract import DevHostProvisioningContract
    historical = DevHostProvisioningContract(
        installation=host.configuration.installation_contract())
    existing = tuple(host_runtime._DirectoryAuthority(
        item.path, item.mode, item.owner_uid, item.group_gid)
        for item in historical.path_requirements() if item.kind == "directory")
    added = tuple(host_runtime._DirectoryAuthority(
        item.path, item.mode, item.owner_uid, item.group_gid)
        for item in (broker, *runtime))
    merged = {item.path: item for item in existing}
    for item in added:
        if item.path in merged and merged[item.path] != item:
            raise OSError
        merged[item.path] = item
    return tuple(merged.values())


def _source_unit(root: str, host: DevBrokerHostServiceContract) -> bytes:
    _canonical_path(root, _ERROR)
    asset = host.installed_asset_requirement()
    path = root + "/" + asset.source_path
    owned: list[int] = []
    try:
        parent, name, chain = host_runtime._open_parent(path, (), owned)
        for descriptor, _parent, _name, _expected in chain:
            current = os.fstat(descriptor)
            if current.st_uid != 0 or stat.S_IMODE(current.st_mode) & 0o022:
                raise OSError
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        descriptor = host_runtime._claim(os.open(name, flags, dir_fd=parent), owned)
        opened = os.fstat(descriptor)
        if (host_runtime._fingerprint(named) != host_runtime._fingerprint(opened)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_uid != 0 or stat.S_IMODE(opened.st_mode) & 0o022
                or not 0 < opened.st_size <= _UNIT_LIMIT):
            raise OSError
        payload = host_runtime._read_exact(descriptor, opened.st_size)
        if hashlib.sha256(payload).hexdigest() != asset.sha256:
            raise OSError
        if (host_runtime._fingerprint(os.fstat(descriptor)) != host_runtime._fingerprint(opened)
                or host_runtime._fingerprint(os.stat(name, dir_fd=parent,
                                                   follow_symlinks=False)) != host_runtime._fingerprint(opened)):
            raise OSError
        host_runtime._revalidate_chain(chain)
        return payload
    finally:
        host_runtime._close(owned)


def _file_state(path: str, mode: int, uid: int, gid: int, payload: bytes,
                directories: tuple[host_runtime._DirectoryAuthority, ...]) -> bool:
    owned: list[int] = []
    try:
        requirement = host_runtime._FileAuthority(path, mode, uid, gid)
        parent, name, chain = host_runtime._open_parent(path, directories, owned)
        existing = host_runtime._existing_file(parent, name, requirement, owned)
        if existing is None:
            host_runtime._revalidate_chain(chain)
            return False
        if existing[1] != payload:
            raise OSError
        host_runtime._revalidate_chain(chain)
        return True
    finally:
        host_runtime._close(owned)


def _cleanup_temporary(parent: int, identity: tuple[int, int]) -> None:
    try:
        current = os.stat(_TEMPORARY, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != identity):
        raise OSError
    _none(os.unlink(_TEMPORARY, dir_fd=parent))
    _none(os.fsync(parent))


def _temporary_absent(path: str,
                      directories: tuple[host_runtime._DirectoryAuthority, ...]) -> None:
    owned: list[int] = []
    try:
        parent, _name, chain = host_runtime._open_parent(path, directories, owned)
        try:
            os.stat(_TEMPORARY, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            host_runtime._revalidate_chain(chain)
            return
        raise OSError
    finally:
        host_runtime._close(owned)


def _publish(path: str, mode: int, uid: int, gid: int, payload: bytes,
             directories: tuple[host_runtime._DirectoryAuthority, ...]) -> str:
    if type(payload) is not bytes or not 0 < len(payload) <= _UNIT_LIMIT:
        raise OSError
    owned: list[int] = []
    temporary_identity = None
    try:
        requirement = host_runtime._FileAuthority(path, mode, uid, gid)
        parent, name, chain = host_runtime._open_parent(path, directories, owned)
        existing = host_runtime._existing_file(parent, name, requirement, owned)
        if existing is not None:
            if existing[1] != payload:
                raise OSError
            host_runtime._revalidate_chain(chain)
            _none(os.fsync(parent))
            return "unchanged"
        temporary = host_runtime._claim(os.open(
            _TEMPORARY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent), owned)
        created = os.fstat(temporary)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise OSError
        temporary_identity = (created.st_dev, created.st_ino)
        if created.st_uid != uid or created.st_gid != gid:
            _none(os.fchown(temporary, uid, gid))
        _none(os.fchmod(temporary, mode))
        host_runtime._write_all(temporary, payload)
        _none(os.fsync(temporary))
        staged = host_runtime._existing_file(parent, _TEMPORARY, requirement, owned)
        if (staged is None or staged[1] != payload
                or (staged[0][2], staged[0][1]) != temporary_identity):
            raise OSError
        host_runtime._revalidate_chain(chain)
        _none(os.link(_TEMPORARY, name, src_dir_fd=parent, dst_dir_fd=parent,
                      follow_symlinks=False))
        # An unexpected name substitution must never be removed by name.
        current = os.stat(_TEMPORARY, dir_fd=parent, follow_symlinks=False)
        final = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if ((current.st_dev, current.st_ino) != temporary_identity
                or (final.st_dev, final.st_ino) != temporary_identity):
            raise OSError
        _none(os.unlink(_TEMPORARY, dir_fd=parent))
        temporary_identity = None
        _none(os.fsync(parent))
        confirmed = host_runtime._existing_file(parent, name, requirement, owned)
        if (confirmed is None or confirmed[1] != payload
                or (confirmed[0][2], confirmed[0][1]) != (final.st_dev, final.st_ino)):
            raise OSError
        host_runtime._revalidate_chain(chain)
        return "created"
    finally:
        active = sys.exception()
        try:
            if temporary_identity is not None and "parent" in locals():
                _cleanup_temporary(parent, temporary_identity)
        except _CONTROL:
            if not isinstance(active, _CONTROL):
                raise
        except Exception:
            if not isinstance(active, _CONTROL):
                raise
        finally:
            host_runtime._close(owned)


def _evidence(operation: str, pair: DevFinalConfigurationPair,
              host: DevBrokerHostServiceContract,
              sigstore: sigstore_installer.DevSigstoreStaticInstallationEvidence,
              outcomes: tuple[str, ...]) -> FinalBrokerResourcesEvidence:
    if type(sigstore) is not sigstore_installer.DevSigstoreStaticInstallationEvidence:
        raise OSError
    sigstore.__post_init__()
    if sigstore.broker_gid != pair.broker.broker_gid:
        raise OSError
    return FinalBrokerResourcesEvidence(
        operation, TARGET_REVIEWED_COMMIT, pair.broker.expected_workflow_sha,
        hashlib.sha256(host.canonical_configuration_bytes()).hexdigest(),
        host.installed_asset_requirement().sha256, sigstore, outcomes)


def _qualify(pair: DevFinalConfigurationPair, host: DevBrokerHostServiceContract,
             outcomes: tuple[str, ...]) -> FinalBrokerResourcesEvidence:
    directories = _authorities(host)
    for item in (host.broker_configuration_directory(), *host.runtime_directory_requirements()):
        if not _directory_exists(item, directories):
            raise OSError
    config = host.broker_configuration_file()
    raw = host.canonical_configuration_bytes()
    if not _file_state(config.path, config.mode, config.owner_uid, config.group_gid,
                       raw, directories):
        raise OSError
    if parse_canonical_broker_service_configuration(raw).to_dict() != pair.broker.to_dict():
        raise OSError
    asset = host.installed_asset_requirement()
    unit = _installed_unit(asset.sha256, asset.destination_path, asset.mode,
                           asset.owner_uid, asset.group_gid, directories)
    if not unit:
        raise OSError
    _replay(host)
    sigstore = sigstore_installer._qualify_installed(pair.broker)
    return _evidence("already-installed", pair, host, sigstore, outcomes)


def _installed_unit(digest: str, path: str, mode: int, uid: int, gid: int,
                    directories: tuple[host_runtime._DirectoryAuthority, ...]) -> bool:
    owned: list[int] = []
    try:
        parent, name, chain = host_runtime._open_parent(path, directories, owned)
        requirement = host_runtime._FileAuthority(path, mode, uid, gid)
        existing = host_runtime._existing_file(parent, name, requirement, owned)
        host_runtime._revalidate_chain(chain)
        return existing is not None and hashlib.sha256(existing[1]).hexdigest() == digest
    finally:
        host_runtime._close(owned)


def qualify_final_dev_broker_resources(*, expected_workflow_sha: str) -> FinalBrokerResourcesEvidence:
    """Read-only proof of the exact installed prerequisites; no source inputs."""
    try:
        pair, host = _pair(expected_workflow_sha)
        return _qualify(pair, host, ("unchanged",) * 8)
    except _CONTROL:
        raise
    except Exception:
        raise FinalBrokerResourcesError(_ERROR) from None


def provision_final_dev_broker_resources(*, expected_workflow_sha: str,
                                         reviewed_source_root: str,
                                         sigstore_staging_directory: str
                                         ) -> FinalBrokerResourcesEvidence:
    """Explicit future root mutation; all tests must patch paths into sandboxes."""
    lock = None
    failure = False
    control = None
    result = None
    try:
        first_identity = _root()
        _canonical_path(reviewed_source_root, _ERROR)
        _canonical_path(sigstore_staging_directory, _ERROR)
        lock = lock_runtime._acquire_process_lock()
        if type(lock) is not lock_runtime._ProcessLock:
            raise OSError
        pair, host = _pair(expected_workflow_sha)
        _replay(host)
        unit_bytes = _source_unit(reviewed_source_root, host)
        asset = host.installed_asset_requirement()
        directories = _authorities(host)
        config = host.broker_configuration_file()
        config_bytes = host.canonical_configuration_bytes()
        config_directory_exists = _directory_exists(
            host.broker_configuration_directory(), directories)
        if config_directory_exists:
            _temporary_absent(config.path, directories)
        _temporary_absent(asset.destination_path, directories)
        config_preexisting = _file_state(config.path, config.mode, config.owner_uid,
                                         config.group_gid, config_bytes, directories) if config_directory_exists else False
        unit_preexisting = _file_state(asset.destination_path, asset.mode, asset.owner_uid,
                                       asset.group_gid, unit_bytes, directories)
        if unit_preexisting and not config_preexisting:
            raise OSError
        if config_preexisting:
            # Canonical broker authority is published only after both C32M files.
            sigstore_installer._qualify_installed(pair.broker)
        outcomes = []
        for item in (host.broker_configuration_directory(), *host.runtime_directory_requirements()):
            req = host_runtime._DirectoryAuthority(item.path, item.mode,
                                                   item.owner_uid, item.group_gid)
            outcomes.append(host_runtime._ensure_directory(req, directories).outcome)
        _root()
        installed = sigstore_installer._install_under_held_process_lock(
            staging_directory=sigstore_staging_directory,
            configuration=pair.broker, held_lock=lock)
        if type(installed) is not sigstore_installer.DevSigstoreStaticInstallationEvidence:
            raise OSError
        installed.__post_init__()
        outcomes.append(_publish(config.path, config.mode, config.owner_uid,
                                 config.group_gid, config_bytes, directories))
        outcomes.append(_publish(asset.destination_path, asset.mode, asset.owner_uid,
                                 asset.group_gid, unit_bytes, directories))
        if _root() != first_identity:
            raise OSError
        final = _qualify(pair, host, tuple(outcomes))
        result = _evidence("installed" if any(item == "created" for item in outcomes)
                           or installed.operation == "installed" else "already-installed",
                           pair, host, final.sigstore, tuple(outcomes))
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        if lock is not None:
            try:
                _none(lock_runtime._release_process_lock(lock))
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise FinalBrokerResourcesError(_ERROR) from None
    return result


def _directory_exists(requirement, directories) -> bool:
    owned: list[int] = []
    try:
        parent, name, chain = host_runtime._open_parent(requirement.path, directories, owned)
        try:
            status = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            host_runtime._revalidate_chain(chain)
            return False
        host_runtime._directory(status, host_runtime._DirectoryAuthority(
            requirement.path, requirement.mode, requirement.owner_uid, requirement.group_gid))
        descriptor = host_runtime._claim(os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent), owned)
        opened = host_runtime._directory(os.fstat(descriptor),
            host_runtime._DirectoryAuthority(requirement.path, requirement.mode,
                                             requirement.owner_uid, requirement.group_gid))
        if host_runtime._fingerprint(status) != host_runtime._fingerprint(opened):
            raise OSError
        host_runtime._revalidate_chain(chain)
        return True
    finally:
        host_runtime._close(owned)
