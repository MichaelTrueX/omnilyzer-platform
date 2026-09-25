"""Pinned C32D C31-to-C32C application migration; never imported by runtime.

Only an explicitly authorized, later host operation may call ``update``.  The
module has no CLI, listener, workflow or service composition.  Its repository
input is the Git object database beside this reviewed module, and all source
and destination authority is fixed here.  Every target blob is retained in
memory before the first host write.
"""

from dataclasses import dataclass, replace
import hashlib
import os
import stat

from . import application_manifest as c26
from . import dev_host_provisioning_mechanics as c31b
from . import dev_host_qualification as c29
from . import dev_host_provisioning_orchestration as c31
from . import dev_post_provision_qualification as c31d
from . import dev_persistent_state_prerequisites as c31c
from . import executor_service_config as c17
from . import python_environment_qualification as python_environment


PREDECESSOR = "3ef02a6d61d20df3a1495b290c20807162b65b06"
TARGET = "c04e66008cff556315603a9de59dacb4679787d4"
_INTERMEDIATE = "f5a4a8661e87b5419a1a6f2b97928b814fcbe0e1"
PREDECESSOR_C17 = "2da08e1d83ae6baa007ca0f5b8492c7e9df30a6922007095fb129f76fc924762"
PREDECESSOR_C26 = "7a89fd0e7f67daa17c772ec9e9058863ff25041ed57b7828d7cce2329ccdb419"
TARGET_C26 = "4e0079a4528f3cba7669062b38e6b8d899be237dab51fb957d97331f09686c03"
PYTHON_MANIFEST = "3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b"
CHANGED = (
    "deployment/broker.py",
    "deployment/broker_integration.py",
    "deployment/oidc_verifier.py",
    "deployment/release_consumer.py",
)
_ADDED = CHANGED[1:]
APP_ROOT = "/opt/omnilyzer/deployment/app"
CONFIG = "/etc/omnilyzer/deployment/dev/executor.json"
APP_UID = 0
APP_GID = 0
CONFIG_UID = 0
_REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_APP_STAGE = ".omnilyzer-c32d-application.tmp"
_CONFIG_STAGE = ".omnilyzer-c32d-configuration.tmp"
_ROOT_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class PostC31UpdateError(Exception):
    """The pinned generation or a recognized resumable prefix is unavailable."""


@dataclass(frozen=True, slots=True)
class UpdateState:
    replaced_count: int
    application_stage_length: int | None
    application_stage_mode: int | None
    configuration_stage_length: int | None
    configuration_stage_mode: int | None
    configuration_current: bool


@dataclass(frozen=True, slots=True)
class _Mixed:
    entries: tuple[c26.ApplicationManifestEntry, ...]


def _git_blobs(commit: str, paths: tuple[str, ...]) -> tuple[tuple[str, bytes], ...]:
    """Read exact regular Git blobs from one pinned commit through C31B plumbing."""
    owned = []
    try:
        repository, chain = c31b._open_directory(_REPOSITORY, owned)
        if c31b._run_git(repository, ("cat-file", "-t", commit), 16) != b"commit\n":
            raise OSError
        records = c26._tree(c31b._run_git(repository, (
            "ls-tree", "-r", "-z", "--full-tree", commit, "--", *paths,
        ), 16384), paths)
        result = []
        total = 0
        for path, oid in records:
            data = c31b._run_git(repository, ("cat-file", "blob", oid), c31b._MAX_BLOB)
            total += len(data)
            if total > c31b._MAX_APPLICATION:
                raise OSError
            result.append((path, data))
        c31b._revalidate_chain(chain)
        return tuple(result)
    finally:
        c31b._finish_close(owned)


def _manifest(commit: str, blobs: tuple[tuple[str, bytes], ...]) -> c26.DevApplicationManifest:
    return c26.DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", commit,
        tuple(c26.ApplicationManifestEntry(path, hashlib.sha256(data).hexdigest(), "0644")
              for path, data in blobs),
    )


def _evidence():
    """No caller ref/path/file selection; pin both generations and first-parent lineage."""
    if tuple(c26._predecessor_paths()) != tuple(path for path in c26._paths() if path not in _ADDED):
        raise OSError
    if tuple(path for path in c26._paths() if path in CHANGED) != CHANGED:
        raise OSError
    owned = []
    try:
        repository, chain = c31b._open_directory(_REPOSITORY, owned)
        for commit, parent in ((TARGET, _INTERMEDIATE), (_INTERMEDIATE, PREDECESSOR)):
            raw = c31b._run_git(repository, ("cat-file", "commit", commit), 65536)
            headers, separator, _ = raw.partition(b"\n\n")
            if not separator or b"parent " + parent.encode() not in headers.split(b"\n"):
                raise OSError
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)
    old_blobs = _git_blobs(PREDECESSOR, c26._predecessor_paths())
    new_blobs = _git_blobs(TARGET, c26._paths())
    old = _manifest(PREDECESSOR, old_blobs)
    new = _manifest(TARGET, new_blobs)
    if (hashlib.sha256(old.canonical_bytes()).hexdigest() != PREDECESSOR_C26
            or hashlib.sha256(new.canonical_bytes()).hexdigest() != TARGET_C26):
        raise OSError
    prior = dict(old_blobs)
    future = dict(new_blobs)
    if (tuple(path for path in c26._paths() if path not in prior or prior[path] != future[path])
            != CHANGED):
        raise OSError
    return old, new, future


def _configuration() -> tuple[c17.DevExecutorServiceConfiguration, bytes, bytes]:
    raw = c29._read_small_regular(CONFIG, c17.MAX_EXECUTOR_SERVICE_CONFIG_BYTES)
    installed = c17.parse_canonical_executor_service_configuration(raw)
    if installed.reviewed_commit not in (PREDECESSOR, TARGET) or installed.canonical_bytes() != raw:
        raise OSError
    old = replace(installed, reviewed_commit=PREDECESSOR)
    old_raw = old.canonical_bytes()
    if hashlib.sha256(old_raw).hexdigest() != PREDECESSOR_C17:
        raise OSError
    current = replace(old, reviewed_commit=TARGET)
    return old, old_raw, current.canonical_bytes()


def _stage(directory: int, name: str, payload: bytes | None, mode: int,
           uid: int, gid: int, initial_gid: int | None = None) -> tuple[int, int, tuple[int, ...]] | None:
    try:
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if payload is None:
        raise OSError
    descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        fingerprint = c31b._fingerprint(opened)
        file_mode = stat.S_IMODE(opened.st_mode)
        if (fingerprint != c31b._fingerprint(named)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or not ((opened.st_uid, opened.st_gid) == (uid, gid)
                        or (file_mode == 0o600 and opened.st_uid == uid
                            and opened.st_gid == initial_gid))
                or file_mode not in (0o600, mode)
                or opened.st_size > len(payload)
                or (file_mode == mode and opened.st_size != len(payload))):
            raise OSError
        content, _ = c31b._read_hash(descriptor, opened.st_size, c31b._MAX_BLOB)
        if content != payload[:opened.st_size] or c31b._fingerprint(os.fstat(descriptor)) != fingerprint:
            raise OSError
        return opened.st_size, file_mode, fingerprint
    finally:
        os.close(descriptor)


def _mixed(previous: c26.DevApplicationManifest, target: c26.DevApplicationManifest,
           count: int) -> _Mixed:
    entries = {entry.path: entry for entry in previous.entries}
    future = {entry.path: entry for entry in target.entries}
    for path in CHANGED[:count]:
        entries[path] = future[path]
    return _Mixed(tuple(entries[path] for path in sorted(entries)))


def _application_state(previous: c26.DevApplicationManifest,
                       target: c26.DevApplicationManifest,
                       blobs: dict[str, bytes]) -> tuple[int, tuple[int, int, tuple[int, ...]] | None]:
    owned = []
    try:
        root, chain = c31b._open_directory(APP_ROOT, owned)
        root_status = os.fstat(root)
        if (stat.S_IMODE(root_status.st_mode), root_status.st_uid, root_status.st_gid) != (0o755, APP_UID, APP_GID):
            raise OSError
        directory = c31b._claim(os.open("deployment", _ROOT_FLAGS, dir_fd=root), owned)
        opened = os.fstat(directory)
        if (not stat.S_ISDIR(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o755
                or (opened.st_uid, opened.st_gid) != (APP_UID, APP_GID)
                or c31b._directory_fingerprint(opened) != c31b._directory_fingerprint(
                    os.stat("deployment", dir_fd=root, follow_symlinks=False))):
            raise OSError
        for count in range(len(CHANGED) + 1):
            payload = blobs[CHANGED[count]] if count < len(CHANGED) else None
            try:
                stage = _stage(directory, _APP_STAGE, payload, 0o644, APP_UID, APP_GID)
                c31b._verify_application(root, _mixed(previous, target, count), APP_UID, APP_GID,
                                          ("deployment/" + _APP_STAGE, stage[2]) if stage else None)
                if _stage(directory, _APP_STAGE, payload, 0o644, APP_UID, APP_GID) != stage:
                    raise OSError
                c31b._revalidate_chain(chain)
                return count, stage
            except OSError:
                continue
        raise OSError
    finally:
        c31b._finish_close(owned)


def _config_state(old_raw: bytes, target_raw: bytes, complete: bool):
    owned = []
    try:
        parent, name, chain = c31b._open_parent(CONFIG, owned)
        installed = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = c31b._claim(os.open(name, _FILE_FLAGS, dir_fd=parent), owned)
        opened = os.fstat(descriptor)
        if (c31b._fingerprint(opened) != c31b._fingerprint(installed)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_uid, opened.st_gid) != (
                    CONFIG_UID,
                    c17.parse_canonical_executor_service_configuration(old_raw).executor_gid,
                ) or stat.S_IMODE(opened.st_mode) != 0o640
                or opened.st_size > c17.MAX_EXECUTOR_SERVICE_CONFIG_BYTES):
            raise OSError
        data, _ = c31b._read_hash(descriptor, opened.st_size, c17.MAX_EXECUTOR_SERVICE_CONFIG_BYTES)
        if c31b._fingerprint(os.fstat(descriptor)) != c31b._fingerprint(opened):
            raise OSError
        if data == old_raw:
            current = False
        elif complete and data == target_raw:
            current = True
        else:
            raise OSError
        stage = _stage(parent, _CONFIG_STAGE, None if current or not complete else target_raw,
                       0o640, CONFIG_UID, opened.st_gid, 0)
        c31b._revalidate_chain(chain)
        return current, stage, opened.st_gid
    finally:
        c31b._finish_close(owned)


def _inspect(previous, target, blobs, old_raw: bytes, target_raw: bytes) -> UpdateState:
    count, app_stage = _application_state(previous, target, blobs)
    current, config_stage, _ = _config_state(old_raw, target_raw, count == len(CHANGED))
    if current and count != len(CHANGED):
        raise OSError
    return UpdateState(
        count, app_stage[0] if app_stage else None,
        app_stage[1] if app_stage else None,
        config_stage[0] if config_stage else None,
        config_stage[1] if config_stage else None, current,
    )


def _qualify_non_application(configuration, manifest, old_raw: bytes) -> None:
    """Reuse C29/C31D/C31C observers for every non-application C31 boundary."""
    _integrity, provisioning, provenance = c31d._authority(configuration, manifest)
    platform = c29._platform_observation()
    if (platform.system, platform.distribution, platform.version,
            platform.machine, platform.archive_architecture) != (
            "Linux", "Ubuntu", "24.04", "x86_64", "amd64") or not platform.libc.startswith("glibc "):
        raise OSError
    packages = c29._query_packages(provenance)
    if tuple((item.package, item.version, item.architecture, item.status) for item in packages) != tuple(
            (item.package, item.version, item.architecture, "installed") for item in provenance.packages):
        raise OSError
    payload = c29._load_payload(provenance)
    expected_payload = tuple(item["observation"] for item in payload)
    if c29._observe_payload(payload) != expected_payload:
        raise OSError
    groups, users = c29._observe_principals(provisioning)
    if (tuple((item.name, item.gid, item.state) for item in groups)
            != tuple((item.name, item.gid, "exact") for item in provisioning.group_requirements())
            or tuple((item.name, item.uid, item.primary_gid, item.supplementary_gids, item.state)
                     for item in users)
            != tuple((item.name, item.uid, item.primary_gid, item.supplementary_gids, "exact")
                     for item in provisioning.user_requirements())):
        raise OSError
    paths, directories, assets = c31d._managed_requirements(provisioning)
    for item in (*paths, *directories):
        observed = c29._observe_managed_path(
            item.path, item.kind, item.mode, item.owner_uid, item.group_gid,
            old_raw if item.path == CONFIG else None,
        )
        if observed.state != "exact":
            raise OSError
    for asset in assets:
        observed = c29._observe_managed_path(
            asset.destination_path, "regular_file", asset.mode,
            asset.owner_uid, asset.group_gid, expected_sha256=asset.sha256,
        )
        if observed.state != "exact":
            raise OSError
    python = python_environment.qualify_dev_python_environment(configuration=configuration)
    if (type(python) is not python_environment.DevPythonEnvironmentEvidence
            or python.payload_manifest_sha256 != PYTHON_MANIFEST):
        raise OSError
    persistent = c31c.DevPersistentStatePrerequisites(
        configuration=configuration).verify_persistent_prerequisites()
    if tuple(item.outcome for item in persistent) != ("verified-initial", "verified", "pristine"):
        raise OSError
    if c29._observe_managed_path(
        c31d._SNAPSHOT_PATH, "directory", 0o700, 0, 0,
    ).state != "absent":
        raise OSError


def _qualify_state(previous, target, blobs, configuration, old_raw, target_raw) -> UpdateState:
    state = _inspect(previous, target, blobs, old_raw, target_raw)
    evidence = None
    if state.configuration_current:
        if (state.replaced_count != len(CHANGED)
                or state.application_stage_length is not None
                or state.configuration_stage_length is not None):
            raise OSError
        evidence = c31d.qualify_dev_provisioned_host(
            configuration=replace(configuration, reviewed_commit=TARGET),
            application_manifest=target,
        )
    elif (state.replaced_count == 0 and state.application_stage_length is None
          and state.configuration_stage_length is None):
        evidence = c31d.qualify_dev_provisioned_host(
            configuration=configuration, application_manifest=previous,
        )
    else:
        _qualify_non_application(configuration, previous, old_raw)
    if evidence is not None:
        if (type(evidence) is not c31d.DevPostProvisionEvidence
                or evidence.python_environment.payload_manifest_sha256 != PYTHON_MANIFEST
                or tuple(item.outcome for item in evidence.persistent_prerequisites)
                != ("verified-initial", "verified", "pristine")):
            raise OSError
    if _inspect(previous, target, blobs, old_raw, target_raw) != state:
        raise OSError
    return state


def qualify_post_c31_update() -> UpdateState:
    """Read-only proof of old, exact recognized prefix or complete target."""
    try:
        previous, target, blobs = _evidence()
        configuration, old_raw, target_raw = _configuration()
        return _qualify_state(previous, target, blobs, configuration, old_raw, target_raw)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise PostC31UpdateError("pinned post-C31 application state is unavailable") from None


def _write_replace_stage(directory: int, name: str, destination: str,
                         payload: bytes, mode: int, uid: int, gid: int,
                         stage: tuple[int, int, tuple[int, ...]] | None) -> None:
    """Create/continue one exact prefix; fsync file, rename and parent."""
    if stage is None:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        length = 0
    else:
        descriptor = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK, dir_fd=directory)
        length = stage[0]
    try:
        opened = os.fstat(descriptor)
        if (stage is not None and c31b._fingerprint(opened) != stage[2]):
            raise OSError
        if (opened.st_uid, opened.st_gid) != (uid, gid):
            if (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode)) != (uid, 0, 0o600):
                raise OSError
            os.fchown(descriptor, uid, gid)
            opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_uid, opened.st_gid) != (uid, gid)
                or opened.st_size != length
                or stat.S_IMODE(opened.st_mode) != (stage[1] if stage else 0o600)
                or c31b._fingerprint(opened) != c31b._fingerprint(
                    os.stat(name, dir_fd=directory, follow_symlinks=False))):
            raise OSError
        if length:
            read_fd = os.open(name, _FILE_FLAGS, dir_fd=directory)
            try:
                current = os.fstat(read_fd)
                content, _ = c31b._read_hash(read_fd, length, c31b._MAX_BLOB)
                if content != payload[:length] or c31b._fingerprint(current) != c31b._fingerprint(
                        os.fstat(read_fd)) or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise OSError
            finally:
                os.close(read_fd)
        if length < len(payload):
            if stat.S_IMODE(opened.st_mode) != 0o600:
                raise OSError
            os.lseek(descriptor, length, os.SEEK_SET)
            c31b._write_all(descriptor, payload[length:])
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != len(payload):
            raise OSError
        os.replace(name, destination, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(descriptor)


def _sync_directory(path: str, mode: int, uid: int, gid: int) -> None:
    owned = []
    try:
        directory, chain = c31b._open_directory(path, owned)
        status = os.fstat(directory)
        if (stat.S_IMODE(status.st_mode), status.st_uid, status.st_gid) != (mode, uid, gid):
            raise OSError
        c31b._revalidate_chain(chain)
        os.fsync(directory)
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def _advance_application(previous, target, blobs, old_raw, target_raw, state: UpdateState) -> None:
    if state.replaced_count:
        _sync_directory(APP_ROOT + "/deployment", 0o755, APP_UID, APP_GID)
        if _inspect(previous, target, blobs, old_raw, target_raw) != state:
            raise OSError
    relative = CHANGED[state.replaced_count]
    payload = blobs[relative]
    owned = []
    try:
        root, chain = c31b._open_directory(APP_ROOT, owned)
        directory = c31b._claim(os.open("deployment", _ROOT_FLAGS, dir_fd=root), owned)
        root_status = os.fstat(root)
        directory_status = os.fstat(directory)
        if ((stat.S_IMODE(root_status.st_mode), root_status.st_uid, root_status.st_gid)
                != (0o755, APP_UID, APP_GID)
                or (stat.S_IMODE(directory_status.st_mode), directory_status.st_uid,
                    directory_status.st_gid) != (0o755, APP_UID, APP_GID)
                or c31b._directory_fingerprint(directory_status)
                != c31b._directory_fingerprint(os.stat(
                    "deployment", dir_fd=root, follow_symlinks=False))):
            raise OSError
        stage = _stage(directory, _APP_STAGE, payload, 0o644, APP_UID, APP_GID)
        if (stage[0] if stage else None) != state.application_stage_length:
            raise OSError
        c31b._verify_application(root, _mixed(previous, target, state.replaced_count), APP_UID, APP_GID,
                                  ("deployment/" + _APP_STAGE, stage[2]) if stage else None)
        c31b._revalidate_chain(chain)
        _write_replace_stage(directory, _APP_STAGE, relative.split("/", 1)[1],
                             payload, 0o644, APP_UID, APP_GID, stage)
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def _advance_configuration(previous, target, blobs, old_raw, target_raw, state: UpdateState) -> None:
    configuration = c17.parse_canonical_executor_service_configuration(old_raw)
    _sync_directory(APP_ROOT + "/deployment", 0o755, APP_UID, APP_GID)
    if _inspect(previous, target, blobs, old_raw, target_raw) != state:
        raise OSError
    owned = []
    try:
        parent, name, chain = c31b._open_parent(CONFIG, owned)
        parent_status = os.fstat(parent)
        if (stat.S_IMODE(parent_status.st_mode), parent_status.st_uid,
                parent_status.st_gid) != (0o750, CONFIG_UID, configuration.executor_gid):
            raise OSError
        installed = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = c31b._claim(os.open(name, _FILE_FLAGS, dir_fd=parent), owned)
        opened = os.fstat(descriptor)
        if (c31b._fingerprint(installed) != c31b._fingerprint(opened)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_uid, opened.st_gid) != (CONFIG_UID, configuration.executor_gid)
                or stat.S_IMODE(opened.st_mode) != 0o640
                or opened.st_size != len(old_raw)):
            raise OSError
        content, _ = c31b._read_hash(descriptor, opened.st_size,
                                     c17.MAX_EXECUTOR_SERVICE_CONFIG_BYTES)
        if (content != old_raw or c31b._fingerprint(os.fstat(descriptor)) != c31b._fingerprint(opened)
                or c31b._fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False))
                != c31b._fingerprint(opened)):
            raise OSError
        stage = _stage(parent, _CONFIG_STAGE, target_raw, 0o640, CONFIG_UID, configuration.executor_gid, 0)
        if (stage[0] if stage else None) != state.configuration_stage_length:
            raise OSError
        c31b._revalidate_chain(chain)
        _write_replace_stage(parent, _CONFIG_STAGE, name, target_raw, 0o640,
                             CONFIG_UID, configuration.executor_gid, stage)
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def update_post_c31_application() -> UpdateState:
    """Fixed, explicit future operation; no command-line or service entry point."""
    lock = None
    try:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise OSError
        lock = c31._acquire_process_lock()
        previous, target, blobs = _evidence()
        configuration, old_raw, target_raw = _configuration()
        while True:
            state = _qualify_state(previous, target, blobs, configuration, old_raw, target_raw)
            if state.configuration_current:
                _sync_directory(os.path.dirname(CONFIG), 0o750, CONFIG_UID, configuration.executor_gid)
                return state
            if state.replaced_count < len(CHANGED):
                _advance_application(previous, target, blobs, old_raw, target_raw, state)
            else:
                _advance_configuration(previous, target, blobs, old_raw, target_raw, state)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise PostC31UpdateError("pinned post-C31 application update failed closed") from None
    finally:
        if lock is not None:
            c31._release_process_lock(lock)
