"""File: deployment/analytics_isolated_source_install.py

Purpose: Prepare ONE approved Analytics Task014 root-owned source generation
         without modifying the original protected canary application.
Related: deployment/analytics_source_archive.py (31 exact review objects),
         deployment/analytics_source_handoff.py (39 historical inherited
         source hashes), deployment/dev_host_provisioning_mechanics.py (C31B
         protected FD/file verification), deployment/application_source_set.py,
         deployment/analytics_executor_service_config.py and
         deployment/tests/test_analytics_isolated_source_install.py.

Sections: root-only approval, 43 legacy source hash preflight, 70-file source
          assembly, secure private stage, original C31B final verification,
          atomic isolated publication and fail-closed pre-cutover cleanup.

SECURITY: NO service/route/broker imports or entrypoint, NO CLI/autostart.
The root-only operation is INERT until a separately authorized root actor
installs the exact approval and archive files and explicitly invokes it.
Neither a caller-created review receipt nor the TAR confers install authority.
Never writes the original canary root, legacy bytecode, original C17 files,
systemd, Docker, registry, secrets, PostgreSQL or replay.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tarfile
from types import SimpleNamespace

from . import dev_host_provisioning_mechanics as _original
from .application_manifest import ApplicationManifestEntry
from .application_source_set import DevApplicationSourceSet
from .analytics_source_archive import (
    _validate_manifest, verify_analytics_source_archive,
)
from .policy import canonical_bytes

_PARENT = "/opt/omnilyzer/deployment"
_LEGACY = _PARENT + "/app"
_DESTINATION = "analytics-app"
_STAGING = ".analytics-app-reviewed-staging"
_APPROVAL_PATH = "/etc/omnilyzer/deployment/dev/analytics-source-install.json"
_ARCHIVE_PATH = "/opt/omnilyzer/deployment/.analytics-source-review.tar"
_APPROVAL_FIELDS = {
    "schema_version", "product_id", "stage", "reviewed_commit",
    "manifest_sha256", "archive_sha256", "destination",
}
_MAX_APPROVAL = 1024
_MAX_ARCHIVE = 14 * 1024 * 1024
_MAX_FILE = 1024 * 1024
_MAX_GENERATION = 12 * 1024 * 1024
_ERROR = "Analytics isolated Task014 root source installation is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_FD_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_FD_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class AnalyticsIsolatedSourceInstallError(Exception):
    """One failed reviewed, root-only source preparation or publication."""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate approval fields before any root filesystem activity."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _approval(raw: bytes) -> dict[str, str]:
    """Require exact canonical approval previously installed by ROOT, not TAR."""
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_APPROVAL:
        raise ValueError
    obj = json.loads(
        raw.decode("ascii"), object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError),
    )
    if (
        type(obj) is not dict or set(obj) != _APPROVAL_FIELDS
        or type(obj["schema_version"]) is not int or obj["schema_version"] != 1
        or obj["product_id"] != "analytics" or obj["stage"] != "dev"
        or obj["destination"] != _PARENT + "/" + _DESTINATION
        or type(obj["reviewed_commit"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", obj["reviewed_commit"]) is None
        or obj["reviewed_commit"] == "0" * 40
        or any(type(obj[name]) is not str
               or re.fullmatch(r"[0-9a-f]{64}", obj[name]) is None
               for name in ("manifest_sha256", "archive_sha256"))
        or canonical_bytes(obj) != raw
    ):
        raise ValueError
    return obj


def _open_checked_root(path: str, owned: list[int], uid: int, gid: int) -> int:
    """Reuse original C31B openat chain; deny writable/symlink ancestors."""
    root, chain = _original._open_directory(path, owned)
    for fd, _prev, _name, _meta in chain:
        x = os.fstat(fd)
        if (x.st_uid, x.st_gid) != (uid, gid) or stat.S_IMODE(x.st_mode) & 0o022:
            raise OSError
    _original._revalidate_chain(chain)
    return root


def _read_protected_file(path: str, *, limit: int, mode: int) -> bytes:
    """Read exact root-owned 0600 config or archive through C31B descriptors."""
    owned: list[int] = []
    try:
        parent, name, chain = _original._open_parent(path, owned)
        for fd, _prev, _component, _meta in chain:
            x = os.fstat(fd)
            # Original C17 /etc/.../dev is root:GID991 mode0750.
            # Its group is harmless because it has NO group-write bit.
            if x.st_uid != 0 or stat.S_IMODE(x.st_mode) & 0o022:
                raise OSError
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(name, _FD_FILE, dir_fd=parent)
        owned.append(fd)
        meta = _original._regular(os.fstat(fd), limit)
        before = _original._fingerprint(meta)
        if (
            before != _original._fingerprint(named)
            or meta.st_uid != 0 or meta.st_gid != 0
            or stat.S_IMODE(meta.st_mode) != mode
            or not 0 < meta.st_size <= limit
        ):
            raise OSError
        blob, _digest = _original._read_hash(fd, meta.st_size, limit)
        if (
            before != _original._fingerprint(os.fstat(fd))
            or before != _original._fingerprint(os.stat(
                name, dir_fd=parent, follow_symlinks=False,
            ))
        ):
            raise OSError
        _original._revalidate_chain(chain)
        return blob
    finally:
        _original._finish_close(owned)


def _read_legacy_sources(
    old_root: str, expected: dict[str, str], *, uid: int, gid: int,
) -> dict[str, bytes]:
    """Verify all 43 real historical source files; never read/copy pycache.

    The original tree is opened READ-ONLY. Every selected original source is
    root-owned (in live operation), 0644, regular, single-link, bounded and
    hash-equal to its independently approved Git preimage. Unexpected cache
    files are deliberately NOT imported into the new isolated generation.
    """
    names = tuple(item.repository_path for item in DevApplicationSourceSet().files)
    if (
        len(names) != 43 or set(names) != set(expected)
        or any(type(expected[n]) is not str
               or re.fullmatch(r"[0-9a-f]{64}", expected[n]) is None
               for n in names)
    ):
        raise ValueError
    owned: list[int] = []
    try:
        root = _open_checked_root(old_root, owned, uid, gid)
        result: dict[str, bytes] = {}
        total = 0
        for path in names:
            parent = root
            for part in path.split("/")[:-1]:
                child = os.open(part, _FD_DIR, dir_fd=parent)
                owned.append(child)
                actual = os.fstat(child)
                named = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(actual.st_mode)
                    or (actual.st_uid, actual.st_gid) != (uid, gid)
                    or stat.S_IMODE(actual.st_mode) != 0o755
                    or _original._identity(actual) != _original._identity(named)
                ):
                    raise OSError
                parent = child
            file = path.rsplit("/", 1)[-1]
            named = os.stat(file, dir_fd=parent, follow_symlinks=False)
            fd = os.open(file, _FD_FILE, dir_fd=parent)
            owned.append(fd)
            actual = _original._regular(os.fstat(fd), _MAX_FILE)
            fingerprint = _original._fingerprint(actual)
            if (
                fingerprint != _original._fingerprint(named)
                or (actual.st_uid, actual.st_gid) != (uid, gid)
                or stat.S_IMODE(actual.st_mode) != 0o644
                or not 0 < actual.st_size <= _MAX_FILE
            ):
                raise OSError
            blob, digest = _original._read_hash(fd, actual.st_size, _MAX_FILE)
            total += len(blob)
            if (
                total > _MAX_GENERATION or digest != expected[path]
                or fingerprint != _original._fingerprint(os.fstat(fd))
                or fingerprint != _original._fingerprint(os.stat(
                    file, dir_fd=parent, follow_symlinks=False,
                ))
            ):
                raise OSError
            result[path] = blob
        return result
    finally:
        _original._finish_close(owned)


def _review_and_combine(
    old: dict[str, bytes], archive: bytes, *,
    manifest_sha: str, reviewed_commit: str,
) -> tuple[tuple[str, bytes], ...]:
    """Require exact 43 host preimages + 31 reviewed Git blobs, yielding 70."""
    updated = verify_analytics_source_archive(
        archive, expected_manifest_sha256=manifest_sha,
        reviewed_commit=reviewed_commit,
    )
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        manifest_file = tar.extractfile(".omnilyzer-analytics-source-review.json")
        if manifest_file is None:
            raise ValueError
        model = _validate_manifest(
            manifest_file.read(16385), manifest_sha, reviewed_commit,
        )
    baseline = dict(model["inherited_canary_sha256"])
    baseline.update(model["shared_preimage_sha256"])
    if len(old) != 43 or len(baseline) != 43 or set(old) != set(baseline):
        raise ValueError
    if any(hashlib.sha256(blob).hexdigest() != baseline[name]
           for name, blob in old.items()):
        raise ValueError
    union = {**old, **dict(updated)}
    if (
        len(union) != 70 or len(updated) != 31
        or sum(len(blob) for blob in union.values()) > _MAX_GENERATION
    ):
        raise ValueError
    return tuple(sorted(union.items()))


def _stage_new_generation(
    parentfd: int, selected: tuple[tuple[str, bytes], ...], *,
    uid: int, gid: int,
) -> None:
    """Build and verify one CLOSED 70-file root-owned private staging tree.

    The stage must not preexist. The old canary app is never opened for write.
    On pre-publication failure only the exact files/dirs created here are
    deleted; an unrecognized object forces manual remediation, not recursion.
    """
    paths = tuple(path for path, _ in selected)
    if len(paths) != 70 or paths != tuple(sorted(set(paths))):
        raise ValueError
    os.mkdir(_STAGING, 0o700, dir_fd=parentfd)
    stagefd = os.open(_STAGING, _FD_DIR, dir_fd=parentfd)
    owned: list[int] = [stagefd]
    created_files: list[tuple[int, str]] = []
    created_dirs: list[tuple[int, str]] = []
    ready = False
    try:
        if (os.fstat(stagefd).st_uid, os.fstat(stagefd).st_gid) != (uid, gid):
            raise OSError
        all_dirs = {
            "/".join(name.split("/")[:n])
            for name in paths
            for n in range(1, len(name.split("/")))
        }
        directories = sorted(all_dirs, key=lambda x: (x.count("/"), x))
        fds = {"": stagefd}
        for dirname in directories:
            parent_name, _slash, leaf = dirname.rpartition("/")
            directory_parent = fds[parent_name]
            os.mkdir(leaf, 0o700, dir_fd=directory_parent)
            created_dirs.append((directory_parent, leaf))
            childfd = os.open(leaf, _FD_DIR, dir_fd=directory_parent)
            owned.append(childfd)
            if (os.fstat(childfd).st_uid, os.fstat(childfd).st_gid) != (uid, gid):
                raise OSError
            os.fchmod(childfd, 0o755)
            fds[dirname] = childfd

        entries = []
        for path, payload in selected:
            relative, _slash, leaf = path.rpartition("/")
            directory = fds[relative]
            fd = os.open(
                leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600, dir_fd=directory,
            )
            created_files.append((directory, leaf))
            try:
                if (os.fstat(fd).st_uid, os.fstat(fd).st_gid) != (uid, gid):
                    raise OSError
                _original._write_all(fd, payload)
                os.fchmod(fd, 0o644)
                os.fsync(fd)
                current = os.fstat(fd)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_nlink != 1
                    or current.st_size != len(payload)
                    or stat.S_IMODE(current.st_mode) != 0o644
                ):
                    raise OSError
            finally:
                os.close(fd)
            entries.append(ApplicationManifestEntry(
                path, hashlib.sha256(payload).hexdigest(), "0644",
            ))
        # Reuse the ORIGINAL Task014 C31B exact directory/file hash audit.
        _original._verify_application(
            stagefd, SimpleNamespace(entries=tuple(entries)), uid, gid,
        )
        for fd in reversed(owned[1:]):
            os.fsync(fd)
        os.fchmod(stagefd, 0o755)
        os.fsync(stagefd)
        ready = True
    finally:
        if not ready:
            # This is NOT a recursive deletion or a reset of persistent data.
            for where, filename in reversed(created_files):
                os.unlink(filename, dir_fd=where)
            for where, dirname in reversed(created_dirs):
                os.rmdir(dirname, dir_fd=where)
            os.rmdir(_STAGING, dir_fd=parentfd)
        for fd in reversed(owned):
            os.close(fd)


def _remove_verified_stage(
    parentfd: int, selected: tuple[tuple[str, bytes], ...],
    *, uid: int, gid: int,
) -> None:
    """Rollback ONLY a previously verified, still-isolated source stage.

    Never perform recursive deletion or follow untrusted links. Reject any
    unexpected object or changed digest, and leave a suspicious staging tree
    untouched for authorized root inspection rather than hiding the problem.
    """
    stage = os.open(_STAGING, _FD_DIR, dir_fd=parentfd)
    try:
        status = os.fstat(stage)
        if (status.st_uid, status.st_gid) != (uid, gid):
            raise OSError
        entries = tuple(ApplicationManifestEntry(
            name, hashlib.sha256(blob).hexdigest(), "0644",
        ) for name, blob in selected)
        _original._verify_application(
            stage, SimpleNamespace(entries=entries), uid, gid,
        )
        for name, _blob in reversed(selected):
            os.unlink(name, dir_fd=stage)
        directories = {
            "/".join(name.split("/")[:n])
            for name, _blob in selected
            for n in range(1, len(name.split("/")))
        }
        for dirname in sorted(directories, key=lambda x: (x.count("/"), x),
                              reverse=True):
            os.rmdir(dirname, dir_fd=stage)
        os.fsync(stage)
    finally:
        os.close(stage)
    os.rmdir(_STAGING, dir_fd=parentfd)
    os.fsync(parentfd)


def _publish_isolated_generation(
    *, parent_root: str, original_root: str, archive: bytes,
    manifest_sha: str, reviewed_commit: str, uid: int, gid: int,
) -> str:
    """Private testable mechanics; publication is inert until service opt-in.

    Explicit roots are accepted ONLY here for isolated disposable tests. The
    public ROOT-ONLY function never forwards external paths; it uses the fixed
    original and isolated product roots above.
    """
    if (
        type(parent_root) is not str or type(original_root) is not str
        or type(archive) is not bytes or not 0 < len(archive) <= _MAX_ARCHIVE
        or type(uid) is not int or type(gid) is not int
    ):
        raise ValueError
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        handle = tar.extractfile(".omnilyzer-analytics-source-review.json")
        if handle is None:
            raise ValueError
        model = _validate_manifest(
            handle.read(16385), manifest_sha, reviewed_commit,
        )
    expected = dict(model["inherited_canary_sha256"])
    expected.update(model["shared_preimage_sha256"])
    old = _read_legacy_sources(
        original_root, expected, uid=uid, gid=gid,
    )
    combined = _review_and_combine(
        old, archive, manifest_sha=manifest_sha,
        reviewed_commit=reviewed_commit,
    )
    owned: list[int] = []
    try:
        parent = _open_checked_root(parent_root, owned, uid, gid)
        for name in (_DESTINATION, _STAGING):
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise OSError  # no existing source overwrite or stale stage
        _stage_new_generation(parent, combined, uid=uid, gid=gid)
        # The parent is root-controlled, unprivileged users cannot race
        # publication. The existing canary directory is NEVER the target.
        try:
            os.rename(
                _STAGING, _DESTINATION,
                src_dir_fd=parent, dst_dir_fd=parent,
            )
        except OSError:
            # The stage is verifiably isolated and unactivated. Remove ONLY
            # this exact source snapshot; never delete original canary files.
            _remove_verified_stage(parent, combined, uid=uid, gid=gid)
            raise
        os.fsync(parent)
        return parent_root + "/" + _DESTINATION
    finally:
        _original._finish_close(owned)


def install_approved_analytics_source_generation() -> str:
    """Perform one independently ROOT-authorized source-only installation.

    Requires these files already installed by the approved original Task014
    root-controlled release process, NOT by a public review or HTTP request:
      /etc/omnilyzer/deployment/dev/analytics-source-install.json
      /opt/omnilyzer/deployment/.analytics-source-review.tar

    No CLI, workflow, broker, executor, systemd or API currently calls this.
    A successful return means a root-owned source directory was verified and
    created. It does NOT mean signed release promotion or service activation.
    """
    try:
        if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
            raise PermissionError
        approval = _approval(_read_protected_file(
            _APPROVAL_PATH, limit=_MAX_APPROVAL, mode=0o600,
        ))
        archive = _read_protected_file(
            _ARCHIVE_PATH, limit=_MAX_ARCHIVE, mode=0o600,
        )
        if hashlib.sha256(archive).hexdigest() != approval["archive_sha256"]:
            raise ValueError
        return _publish_isolated_generation(
            parent_root=_PARENT, original_root=_LEGACY,
            archive=archive, manifest_sha=approval["manifest_sha256"],
            reviewed_commit=approval["reviewed_commit"],
            uid=0, gid=0,
        )
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsIsolatedSourceInstallError(_ERROR) from None


__all__ = (
    "AnalyticsIsolatedSourceInstallError",
    "install_approved_analytics_source_generation",
)
