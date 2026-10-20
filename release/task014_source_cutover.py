"""File: release/task014_source_cutover.py

Purpose: Reviewable, closed-set DEV application generation preparation and
atomic rollback capability. This is an OFFLINE MAINTENANCE LIBRARY, not an
installed runtime module and it has no CLI, service, workflow or automatic
activation. Callers must separately obtain explicit owner authorization.
Related: deployment/application_source_set.py, deployment/application_manifest.py,
deployment/installation_integrity_contract.py, PR #207 and Task 014 issue #182.

Sections: immutable source manifest and historical exact-tree verification;
candidate staging; Linux same-filesystem atomic exchange; fail-closed rollback.
Never touches broker config, state, replay, Docker, nginx or PROD.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from deployment.application_manifest import generate_dev_application_manifest
from deployment.application_source_set import DevApplicationSourceSet

# Section 1: one closed existing production path and reviewed prior source.
APP_PARENT = Path("/opt/omnilyzer/deployment")
APP_NAME = "app"
PRIOR_SOURCE_SHA = "875773c69b19220bd1059e7240dcd296bc3c19a9"
_NEW_MODULES = frozenset((
    "deployment/private_registry_fd.py",
    "deployment/private_registry_pull.py",
))
_EXPECTED_NEW_FILES = 43
_EXPECTED_OLD_FILES = 41
_REPLACEMENTS = frozenset((
    "deployment/broker.py",
    "deployment/broker_integration.py",
    "deployment/broker_service_bootstrap.py",
    "deployment/docker_runtime.py",
    "deployment/executor.py",
    "deployment/executor_composition.py",
    "deployment/executor_server.py",
    "deployment/registry_promotion_composition.py",
    "deployment/unix_transport.py",
))
_CHANGED_PATHS = _NEW_MODULES | _REPLACEMENTS
_SOURCE_LIMIT = 1 << 20
_PARENT_MODE = 0o755
_ROOT_MODE = 0o755
_FILE_MODE = 0o644
_REQUIRED_DOWN_UNITS = (
    "omnilyzer-deployment-broker.service",
    "omnilyzer-deployment-executor.socket",
    "omnilyzer-deployment-executor.service",
)
_EXCHANGE_FLAG = 2  # Linux renameat2 RENAME_EXCHANGE
_AT_FDCWD = -100


class CutoverHold(Exception):
    """Nonsecret failure; no unreviewed partial deployment is authorized."""


@dataclass(frozen=True)
class SourceGenerationPlan:
    """Exactly one verified source generation and expected previous tree."""

    reviewed_commit: str
    target_manifest_sha256: str
    target_entries: tuple[tuple[str, str], ...]
    prior_entries: tuple[tuple[str, str], ...]
    changed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject mutable, incomplete or unexpected application source sets."""
        current = dict(self.target_entries)
        old = dict(self.prior_entries)
        allowed = tuple(
            item.repository_path for item in DevApplicationSourceSet().files
        )
        historical = tuple(path for path in allowed if path not in _NEW_MODULES)
        checksums = tuple(hash for _, hash in self.target_entries + self.prior_entries)
        if (len(current) != _EXPECTED_NEW_FILES
                or len(old) != _EXPECTED_OLD_FILES
                or tuple(current) != allowed
                or tuple(old) != historical
                or any(len(h) != 64 or any(c not in "0123456789abcdef" for c in h)
                       for h in checksums)
                or set(current) - set(old) != _NEW_MODULES
                or tuple(sorted(current)) != tuple(current)
                or tuple(sorted(old)) != tuple(old)
                or tuple(path for path in sorted(current)
                         if old.get(path) != current[path]) != self.changed_paths
                or set(self.changed_paths) != _CHANGED_PATHS
                or len(self.reviewed_commit) != 40
                or any(c not in "0123456789abcdef" for c in self.reviewed_commit)
                or len(self.target_manifest_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.target_manifest_sha256)):

            raise ValueError("source generation authority unavailable")


# Section 2: Git bytes are read from exact immutable revisions, never HEAD.
def _git_blob(repository: Path, commit: str, path: str) -> bytes:
    """Read bounded Git objects for one allowlisted regular source file."""
    result = subprocess.run(
        ["git", "-C", str(repository), "show", f"{commit}:{path}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, timeout=8, check=False,
    )
    if result.returncode != 0 or len(result.stdout) > _SOURCE_LIMIT:
        raise CutoverHold("source generation unavailable")
    return result.stdout


def reviewed_plan(repository: Path, reviewed_commit: str) -> SourceGenerationPlan:
    """Build one immutable current/previous manifest without altering a host."""
    try:
        if (not isinstance(repository, Path) or type(reviewed_commit) is not str
                or len(reviewed_commit) != 40 or any(
                    letter not in "0123456789abcdef" for letter in reviewed_commit
                )):
            raise ValueError
        manifest = generate_dev_application_manifest(
            repository_root=str(repository), reviewed_commit=reviewed_commit,
        )
        selection = DevApplicationSourceSet()
        target = tuple((entry.path, entry.sha256) for entry in manifest.entries)
        expected_paths = tuple(item.repository_path for item in selection.files)
        if (len(target) != _EXPECTED_NEW_FILES
                or tuple(path for path, _ in target) != expected_paths
                or any(entry.mode != "0644" for entry in manifest.entries)):
            raise ValueError
        prior_paths = tuple(path for path in expected_paths if path not in _NEW_MODULES)
        if len(prior_paths) != _EXPECTED_OLD_FILES:
            raise ValueError
        old = tuple((
            path,
            hashlib.sha256(_git_blob(repository, PRIOR_SOURCE_SHA, path)).hexdigest(),
        ) for path in prior_paths)
        latest = dict(target)
        older = dict(old)
        return SourceGenerationPlan(
            reviewed_commit,
            hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
            target, old,
            tuple(path for path in expected_paths if older.get(path) != latest[path]),
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise CutoverHold("source generation unavailable") from None


# Section 3: exact regular root-owned application root, no hidden extra files.
def _require_root() -> None:
    """Require root ownership and no privilege bypass for host mutations."""
    if os.geteuid() != 0 or os.getuid() != 0:
        raise CutoverHold("root authorization required")


def _required_ownership() -> tuple[int, int]:
    """Require root:root for every app, directory and regular file."""
    return (0, 0)


def _checked_directory(path: Path, *, mode: int = _ROOT_MODE) -> None:
    """Reject missing/symlink/non-root-owned or writable directory objects."""
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or stat.S_IMODE(info.st_mode) != mode
            or (info.st_uid, info.st_gid) != _required_ownership()):
        raise CutoverHold("untrusted application directory")


def _observed_tree(root: Path) -> tuple[tuple[str, str], ...]:
    """Verify the complete source set, allowing only safe Python bytecode cache.

    The active Python interpreter may create deployment/__pycache__ with
    root-owned .pyc files. Those are derived artifacts, not application source
    authority. Verify their types, owner, permissions, file size and direct
    allowlisted module names, but exclude them from the source SHA set.
    """
    _checked_directory(root)
    fileset = DevApplicationSourceSet().files
    allowed_dirs = {""}
    cache_dir = "deployment/__pycache__"
    bytecode_modules = {
        Path(item.repository_path).stem
        for item in fileset
        if Path(item.repository_path).parent == Path("deployment")
        and Path(item.repository_path).suffix == ".py"
    }
    for item in fileset:
        rel = Path(item.repository_path).parent
        while str(rel) not in ("", "."):
            allowed_dirs.add(rel.as_posix())
            rel = rel.parent
    files = []
    seen_directories = set()
    for directory, directories, names in os.walk(root, topdown=True, followlinks=False):
        relative = Path(directory).relative_to(root)
        relative_text = "" if str(relative) == "." else relative.as_posix()
        if relative_text not in allowed_dirs and relative_text != cache_dir:
            raise CutoverHold("unlisted application directory")
        _checked_directory(Path(directory))
        seen_directories.add(relative_text)
        for name in directories:
            child = Path(directory) / name
            key = child.relative_to(root).as_posix()
            if key not in allowed_dirs and key != cache_dir:
                raise CutoverHold("unlisted application directory")
            _checked_directory(child)
        for name in names:
            child = Path(directory) / name
            metadata = child.lstat()
            if (not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != _FILE_MODE
                    or (metadata.st_uid, metadata.st_gid) != _required_ownership()
                    or metadata.st_nlink != 1
                    or metadata.st_size > _SOURCE_LIMIT):
                raise CutoverHold("untrusted application file")
            if relative_text == cache_dir:
                match = re.fullmatch(
                    r"([A-Za-z_][A-Za-z_0-9]*)\.cpython-[0-9]+(?:\.opt-[12])?\.pyc",
                    name,
                )
                if match is None or match.group(1) not in bytecode_modules:
                    raise CutoverHold("unlisted Python cache file")
                continue
            file_hash = hashlib.sha256(child.read_bytes()).hexdigest()
            files.append((child.relative_to(root).as_posix(), file_hash))
    if seen_directories - {cache_dir} != allowed_dirs:
        raise CutoverHold("incomplete application directories")
    return tuple(sorted(files))


def _require_exact(root: Path, expected: tuple[tuple[str, str], ...]) -> None:
    """Require one complete candidate or exact old generation, no extra paths."""
    if _observed_tree(root) != expected:
        raise CutoverHold("application generation mismatch")


def readonly_preflight(plan: SourceGenerationPlan) -> None:
    """Verify the existing 41 files without changing running services."""
    try:
        if type(plan) is not SourceGenerationPlan:
            raise ValueError
        _checked_directory(APP_PARENT, mode=_PARENT_MODE)
        _require_exact(APP_PARENT / APP_NAME, plan.prior_entries)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise CutoverHold("source cutover preflight unavailable") from None


# Section 4: build the new 43-file source beside, not inside, the running app.
def prepare_staging(plan: SourceGenerationPlan, repository: Path) -> Path:
    """Create an independently verified complete sibling before activation.

    Only a root operator with separately authorized change control should
    call this method. No service, configuration, replay or Docker mutation.
    """
    _require_root()
    readonly_preflight(plan)
    location: Path | None = None
    try:
        location = Path(tempfile.mkdtemp(
            prefix=".task014-source-ready-", dir=str(APP_PARENT),
        ))
        location.chmod(_ROOT_MODE)
        for relative, expected_hash in plan.target_entries:
            raw = _git_blob(repository, plan.reviewed_commit, relative)
            if hashlib.sha256(raw).hexdigest() != expected_hash:
                raise ValueError
            output = location / relative
            output.parent.mkdir(parents=True, exist_ok=True, mode=_ROOT_MODE)
            # Enforce the reviewed 0755 mode irrespective of root umask.
            cursor = output.parent
            while cursor != location:
                cursor.chmod(_ROOT_MODE)
                cursor = cursor.parent
            descriptor = os.open(
                output, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | os.O_CLOEXEC, _FILE_MODE,
            )
            try:
                os.fchmod(descriptor, _FILE_MODE)
                with os.fdopen(descriptor, "wb", closefd=False) as file:
                    file.write(raw)
                    file.flush()
                    os.fsync(file.fileno())
            finally:
                os.close(descriptor)
        _require_exact(location, plan.target_entries)
        # Preserve the complete staged directory structure across abrupt
        # power loss, before any later controlled atomic directory exchange.
        directories = [location]
        directories.extend(path for path in location.rglob("*") if path.is_dir())
        for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
            handle = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY
                | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                os.fsync(handle)
            finally:
                os.close(handle)
        if location.stat().st_dev != (APP_PARENT / APP_NAME).stat().st_dev:
            raise ValueError
        return location
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        # Fail closed: leave any partial staging for independent root review.
        # No destructive cleanup of unknown host files is ever attempted.
        raise CutoverHold("source staging unavailable") from None


# Section 5: Linux same-parent atomic exchange with full old-tree retention.
def _require_quiesced() -> None:
    """Reject activation while broker, executor socket or executor are active."""
    for unit in _REQUIRED_DOWN_UNITS:
        result = subprocess.run(
            ["/usr/bin/systemctl", "is-active", unit],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=False,
        )
        if result.stdout.strip() not in (b"inactive", b"failed"):
            raise CutoverHold("deployment control plane is not quiesced")


def _exchange(first: Path, second: Path) -> None:
    """Perform one Linux renameat2(RENAME_EXCHANGE) of complete sibling roots."""
    if first.parent != second.parent or first.name == second.name:
        raise CutoverHold("invalid atomic source exchange")
    directory = os.open(
        first.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        system = ctypes.CDLL(None, use_errno=True)
        syscall = system.renameat2
        syscall.argtypes = (
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_uint,
        )
        syscall.restype = ctypes.c_int
        first_name = os.fsencode(first.name)
        second_name = os.fsencode(second.name)
        result = syscall(
            directory, first_name, directory, second_name, _EXCHANGE_FLAG,
        )
        if result != 0:
            raise CutoverHold("atomic source exchange unavailable")
        try:
            os.fsync(directory)
        except OSError:
            # A successful exchange followed by failed directory fsync is not
            # a committed generation. Reverse the exchange before reporting
            # HOLD, leaving the original generation at the active path.
            undone = syscall(
                directory, first_name, directory, second_name, _EXCHANGE_FLAG,
            )
            if undone != 0:
                raise CutoverHold("source state requires manual recovery") from None
            try:
                os.fsync(directory)
            except OSError:
                raise CutoverHold("source state requires manual recovery") from None
            raise CutoverHold("atomic source exchange unavailable") from None
    finally:
        os.close(directory)


def activate_staging(plan: SourceGenerationPlan, staging: Path) -> None:
    """Exchange verified 43-file candidate for 41-file live tree atomically.

    Retains the old 41-file tree under the stage name for controlled rollback.
    Callers must stop relevant services and separately approve the operation.
    """
    _require_root()
    _require_quiesced()
    if (not isinstance(staging, Path) or staging.parent != APP_PARENT
            or not staging.name.startswith(".task014-source-ready-")):
        raise CutoverHold("unapproved source staging path")
    readonly_preflight(plan)
    _require_exact(staging, plan.target_entries)
    _exchange(APP_PARENT / APP_NAME, staging)
    try:
        _require_exact(APP_PARENT / APP_NAME, plan.target_entries)
        _require_exact(staging, plan.prior_entries)
    except Exception:
        _exchange(APP_PARENT / APP_NAME, staging)
        raise CutoverHold("source cutover rolled back") from None


def rollback_staging(plan: SourceGenerationPlan, staging: Path) -> None:
    """Atomically restore exact original files; never change replay or config."""
    _require_root()
    _require_quiesced()
    if (not isinstance(staging, Path) or staging.parent != APP_PARENT
            or not staging.name.startswith(".task014-source-ready-")):
        raise CutoverHold("unapproved rollback path")
    _require_exact(APP_PARENT / APP_NAME, plan.target_entries)
    _require_exact(staging, plan.prior_entries)
    _exchange(APP_PARENT / APP_NAME, staging)
    _require_exact(APP_PARENT / APP_NAME, plan.prior_entries)
    _require_exact(staging, plan.target_entries)
