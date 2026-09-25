"""Pinned, closed C31 step-20 recovery mechanics. Never part of the C25 runtime."""

from dataclasses import dataclass, replace
import hashlib
import os
import stat

from . import application_manifest as c26
from . import dev_host_provisioning_mechanics as c31b
from . import executor_service_config as c17
from . import replay_sqlite as replay


PREDECESSOR = "e386cc07708fcb0b94fae5a7b9422a15c9e2c792"
PREDECESSOR_C26 = "949bc8b001dc6e988fb0adc17b029b3c0899b94b864070a2053fb23c784ecc10"
PREDECESSOR_C17 = "10db1df70c3b60034fe679fa23ac06f4a506aa27beb9d7d6e937eec8de25ea95"
CHANGED = (
    "deployment/executor_composition.py",
    "deployment/installation_contract.py",
    "deployment/replay_sqlite.py",
)
APP_ROOT = "/opt/omnilyzer/deployment/app"
APP_UID = 0
APP_GID = 0
REPLAY_DIRECTORY = "/var/lib/omnilyzer/deployment/authority"
REPLAY_UID = 0
STAGE = ".omnilyzer-c31-step20.tmp"
STAGE_RELATIVE = "deployment/" + STAGE
OLD_REPLAY_MODE = 0o770
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True, slots=True)
class ApplicationState:
    replaced_count: int
    stage_length: int | None
    stage_mode: int | None


def verify_current_c17(configuration: c17.DevExecutorServiceConfiguration) -> None:
    """Bind every current C17 field except the future reviewed commit to e386."""
    if type(configuration) is not c17.DevExecutorServiceConfiguration:
        raise OSError
    c17.DevExecutorServiceConfiguration.__post_init__(configuration)
    predecessor = replace(configuration, reviewed_commit=PREDECESSOR)
    if hashlib.sha256(predecessor.canonical_bytes()).hexdigest() != PREDECESSOR_C17:
        raise OSError


def classify_installed_c17(configuration: c17.DevExecutorServiceConfiguration,
                           raw: bytes) -> str:
    """Accept only exact pinned predecessor or commit-only current C17 bytes."""
    verify_current_c17(configuration)
    if type(raw) is not bytes or len(raw) > c17.MAX_EXECUTOR_SERVICE_CONFIG_BYTES:
        raise OSError
    if raw == configuration.canonical_bytes():
        return "current"
    if hashlib.sha256(raw).hexdigest() != PREDECESSOR_C17:
        raise OSError
    installed = c17.parse_canonical_executor_service_configuration(raw)
    if installed.reviewed_commit != PREDECESSOR:
        raise OSError
    return "predecessor"


def manifests(repository_root: str, configuration, current: c26.DevApplicationManifest):
    """Bind old and new blobs to exact Git objects and a direct-parent edge."""
    verify_current_c17(configuration)
    owned = []
    try:
        repository, chain = c31b._open_directory(repository_root, owned)
        commit = configuration.reviewed_commit
        if c31b._run_git(repository, ("rev-parse", "--verify", "HEAD^{commit}"), 41) != commit.encode() + b"\n":
            raise OSError
        raw_commit = c31b._run_git(repository, ("cat-file", "commit", commit), 65536)
        headers, separator, _ = raw_commit.partition(b"\n\n")
        parents = [line for line in headers.split(b"\n") if line.startswith(b"parent ")]
        if not separator or b"parent " + PREDECESSOR.encode() not in parents:
            raise OSError
        paths = tuple(entry.path for entry in current.entries)
        old_tree = c31b._run_git(repository, ("ls-tree", "-r", "-z", "--full-tree", PREDECESSOR, "--", *paths), 16384)
        records = c26._tree(old_tree, paths)
        old_blobs = []
        old_entries = []
        for path, blob in records:
            value = c31b._run_git(repository, ("cat-file", "blob", blob), c31b._MAX_BLOB)
            old_blobs.append((path, value))
            old_entries.append(c26.ApplicationManifestEntry(path, hashlib.sha256(value).hexdigest(), "0644"))
        previous = c26.DevApplicationManifest("canonical-relative-file-set-v1", "sha256", PREDECESSOR, tuple(old_entries))
        if hashlib.sha256(previous.canonical_bytes()).hexdigest() != PREDECESSOR_C26:
            raise OSError
        differences = tuple(entry.path for old, entry in zip(previous.entries, current.entries)
                            if old.sha256 != entry.sha256)
        if differences != CHANGED:
            raise OSError
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)
    new_blobs = c31b._application_blobs(repository_root, configuration, current)
    return previous, dict(old_blobs), dict(new_blobs)


def _mixed(previous: c26.DevApplicationManifest, current: c26.DevApplicationManifest, count: int):
    changed = set(CHANGED[:count])
    entries = tuple(new if new.path in changed else old
                    for old, new in zip(previous.entries, current.entries))
    return c26.DevApplicationManifest("canonical-relative-file-set-v1", "sha256",
                                      current.reviewed_commit, entries)


def _stage(root: int, next_payload: bytes | None):
    directory = os.open("deployment", _FLAGS, dir_fd=root)
    try:
        try:
            named = os.stat(STAGE, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if next_payload is None:
            raise OSError
        descriptor = os.open(STAGE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=directory)
        try:
            opened = os.fstat(descriptor)
            fingerprint = c31b._fingerprint(opened)
            mode = stat.S_IMODE(opened.st_mode)
            if (fingerprint != c31b._fingerprint(named)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_uid, opened.st_gid) != (APP_UID, APP_GID)
                or mode not in (0o600, 0o644)
                or opened.st_size > len(next_payload)
                or (mode == 0o644 and opened.st_size != len(next_payload))):
                raise OSError
            content, _ = c31b._read_hash(descriptor, opened.st_size, c31b._MAX_BLOB)
            if content != next_payload[:opened.st_size] or c31b._fingerprint(os.fstat(descriptor)) != fingerprint:
                raise OSError
            return opened.st_size, mode, fingerprint
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def inspect_application(previous, current, new_blobs: dict[str, bytes]) -> ApplicationState:
    """Accept only exact old/current prefixes and one exact next-file stage."""
    owned = []
    try:
        root, chain = c31b._open_directory(APP_ROOT, owned)
        status = os.fstat(root)
        if stat.S_IMODE(status.st_mode) != 0o755 or (status.st_uid, status.st_gid) != (APP_UID, APP_GID):
            raise OSError
        for count in range(len(CHANGED) + 1):
            payload = new_blobs[CHANGED[count]] if count < len(CHANGED) else None
            try:
                stage = _stage(root, payload)
                c31b._verify_application(root, _mixed(previous, current, count), APP_UID, APP_GID,
                                         (STAGE_RELATIVE, stage[2]) if stage else None)
                if stage is not None and _stage(root, payload) != stage:
                    raise OSError
                c31b._revalidate_chain(chain)
                return ApplicationState(count, stage[0] if stage else None,
                                        stage[1] if stage else None)
            except OSError:
                continue
        raise OSError
    finally:
        c31b._finish_close(owned)


def migrate_application(repository_root: str, configuration,
                        current: c26.DevApplicationManifest) -> str:
    """Replace only the three changed files using bound reviewed Git blobs."""
    previous, _old_blobs, new_blobs = manifests(repository_root, configuration, current)
    return _migrate_application_bytes(previous, current, new_blobs)


def _sync_application_prefix() -> None:
    """Make observed completed C25 renames durable at the fixed deployment dir."""
    owned = []
    try:
        root, chain = c31b._open_directory(APP_ROOT, owned)
        root_status = os.fstat(root)
        if (stat.S_IMODE(root_status.st_mode) != 0o755
            or (root_status.st_uid, root_status.st_gid) != (APP_UID, APP_GID)):
            raise OSError
        named = os.stat("deployment", dir_fd=root, follow_symlinks=False)
        directory = c31b._claim(os.open("deployment", _FLAGS, dir_fd=root), owned)
        opened = os.fstat(directory)
        expected = c31b._directory_fingerprint(opened)
        if (not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o755
            or (opened.st_uid, opened.st_gid) != (APP_UID, APP_GID)
            or c31b._directory_fingerprint(named) != expected):
            raise OSError
        c31b._revalidate_chain(chain)
        os.fsync(directory)
        if (c31b._directory_fingerprint(os.fstat(directory)) != expected
            or c31b._directory_fingerprint(os.stat(
                "deployment", dir_fd=root, follow_symlinks=False)) != expected):
            raise OSError
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def _migrate_application_bytes(previous, current, new_blobs: dict[str, bytes]) -> str:
    replaced_here = False
    while True:
        state = inspect_application(previous, current, new_blobs)
        if state.replaced_count:
            _sync_application_prefix()
            if inspect_application(previous, current, new_blobs) != state:
                raise OSError
        if state.replaced_count == len(CHANGED):
            return "migrated" if replaced_here else "retained-exact"
        relative = CHANGED[state.replaced_count]
        payload = new_blobs[relative]
        owned = []
        try:
            root, chain = c31b._open_directory(APP_ROOT, owned)
            directory = c31b._claim(os.open("deployment", _FLAGS, dir_fd=root), owned)
            if state.stage_length is None:
                descriptor = c31b._claim(os.open(
                    STAGE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=directory), owned)
                length = 0
            else:
                descriptor = c31b._claim(os.open(
                    STAGE, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=directory), owned)
                length = state.stage_length
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_uid, opened.st_gid) != (APP_UID, APP_GID)
                or opened.st_size != length
                or stat.S_IMODE(opened.st_mode) != (state.stage_mode or 0o600)
                or c31b._fingerprint(opened) != c31b._fingerprint(
                    os.stat(STAGE, dir_fd=directory, follow_symlinks=False))):
                raise OSError
            if length < len(payload):
                if stat.S_IMODE(opened.st_mode) != 0o600:
                    raise OSError
                os.lseek(descriptor, length, os.SEEK_SET)
                c31b._write_all(descriptor, payload[length:])
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
            if os.fstat(descriptor).st_size != len(payload):
                raise OSError
            c31b._revalidate_chain(chain)
            os.replace(STAGE, relative.split("/", 1)[1], src_dir_fd=directory, dst_dir_fd=directory)
            replaced_here = True
            os.fsync(directory)
        finally:
            c31b._finish_close(owned)


def inspect_replay_directory(replay_gid: int) -> str:
    owned = []
    try:
        parent, name, chain = c31b._open_parent(REPLAY_DIRECTORY, owned)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        directory = c31b._claim(os.open(name, _FLAGS, dir_fd=parent), owned)
        opened = os.fstat(directory)
        mode = stat.S_IMODE(opened.st_mode)
        if (not stat.S_ISDIR(opened.st_mode)
            or c31b._directory_fingerprint(opened) != c31b._directory_fingerprint(named)
            or (opened.st_uid, opened.st_gid) != (REPLAY_UID, replay_gid)
            or mode not in (OLD_REPLAY_MODE, replay.DIRECTORY_MODE)):
            raise OSError
        if mode == OLD_REPLAY_MODE and c31b._names(directory):
            raise OSError
        c31b._revalidate_chain(chain)
        return "old" if mode == OLD_REPLAY_MODE else "current"
    finally:
        c31b._finish_close(owned)


def migrate_replay_directory(replay_gid: int) -> str:
    state = inspect_replay_directory(replay_gid)
    owned = []
    try:
        parent, name, chain = c31b._open_parent(REPLAY_DIRECTORY, owned)
        directory = c31b._claim(os.open(name, _FLAGS, dir_fd=parent), owned)
        before = os.fstat(directory)
        if (stat.S_IMODE(before.st_mode) != (
                OLD_REPLAY_MODE if state == "old" else replay.DIRECTORY_MODE)
            or (before.st_uid, before.st_gid) != (REPLAY_UID, replay_gid)
            or (state == "old" and c31b._names(directory))
            or c31b._directory_fingerprint(before) != c31b._directory_fingerprint(
                os.stat(name, dir_fd=parent, follow_symlinks=False))):
            raise OSError
        c31b._revalidate_chain(chain)
        if state == "old":
            os.fchmod(directory, replay.DIRECTORY_MODE)
        # A previous invocation may have changed the mode but failed before
        # syncing it.  Retry both syncs before allowing replay initialization.
        os.fsync(directory)
        os.fsync(parent)
        after = os.fstat(directory)
        if (stat.S_IMODE(after.st_mode) != replay.DIRECTORY_MODE
            or (after.st_dev, after.st_ino, after.st_uid, after.st_gid)
            != (before.st_dev, before.st_ino, REPLAY_UID, replay_gid)
            or c31b._directory_fingerprint(after) != c31b._directory_fingerprint(
                os.stat(name, dir_fd=parent, follow_symlinks=False))
            or (state == "old" and c31b._names(directory))):
            raise OSError
        c31b._revalidate_chain(chain)
        return "migrated" if state == "old" else "retained-exact"
    finally:
        c31b._finish_close(owned)
