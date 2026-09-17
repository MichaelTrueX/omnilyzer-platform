"""deployment/application_manifest.py — deterministic C26 application evidence.

Generate canonical application manifest evidence for the exact C25 DEV source
set from raw Git objects belonging to one exact checked-out commit. C17 owns
future installation reviewed_commit authority; C21 owns the application root;
C24 owns integrity semantics; C25 owns source selection. Future host
qualification/provisioning must compare this evidence to C17 and installed bytes.

Import and value-object construction are inert. Explicit generation is
repository-read-only work: Git object bytes, not working-tree bytes, are hashed.
C26 never persists the manifest, inspects the application root, installs the
host/application, creates a venv, installs dependencies, uses a network,
operates systemd/Docker or activates deployment authority.
"""

from dataclasses import dataclass as _dataclass, fields as _fields
import hashlib as _hashlib
import os as _os
import re as _re
import selectors as _selectors
import subprocess as _subprocess
import time as _time

from .application_source_set import (
    ApplicationSourceFile as _ApplicationSourceFile,
    DevApplicationSourceSet as _DevApplicationSourceSet,
)
from .policy import canonical_bytes as _canonical_bytes, validate_source_sha as _validate_source_sha

__all__ = (
    "ApplicationManifestEvidenceError",
    "ApplicationManifestEntry",
    "DevApplicationManifest",
    "generate_dev_application_manifest",
)

# Closed evidence limits and fixed, non-reflective errors.
_UNAVAILABLE = "DEV application manifest evidence is unavailable"
_MODEL_ERROR = "DEV application manifest model is invalid"
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_BLOB_BYTES = 1024 * 1024
_MAX_TOTAL_BYTES = 8 * 1024 * 1024
_TIMEOUT = 5.0


class ApplicationManifestEvidenceError(Exception):
    """Evidence cannot be produced within the closed C26 boundary."""


def _path(value: object) -> None:
    """Require exact canonical POSIX relative text without filesystem reads."""
    if (type(value) is not str or not value or "\\" in value or "\0" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError(_MODEL_ERROR)


def _commit(value: object) -> None:
    """Require a nonzero exact lowercase SHA-1 commit identifier."""
    if type(value) is not str:
        raise ValueError(_MODEL_ERROR)
    try:
        _validate_source_sha(value)
    except Exception:
        raise ValueError(_MODEL_ERROR) from None


def _paths() -> tuple[str, ...]:
    """Read C25 immutable dataclass metadata, never discover repository files."""
    files = next(field.default for field in _fields(_DevApplicationSourceSet) if field.name == "files")
    return tuple(item.repository_path for item in files)


@_dataclass(frozen=True, slots=True)
class ApplicationManifestEntry:
    """One canonical relative path, raw-blob SHA-256 and required installed mode."""

    path: str
    sha256: str
    mode: str

    def __post_init__(self) -> None:
        """Reject malformed fields using one fixed model validation error."""
        _path(self.path)
        if (type(self.sha256) is not str or _re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None
                or type(self.mode) is not str or self.mode != "0644"):
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class DevApplicationManifest:
    """Immutable exact-C25 manifest evidence bound to one checked-out commit."""

    manifest_kind: str
    digest_algorithm: str
    reviewed_commit: str
    entries: tuple[ApplicationManifestEntry, ...]

    def __post_init__(self) -> None:
        """Revalidate nested exact-type entries, including partially forged values."""
        try:
            _commit(self.reviewed_commit)
            if (type(self.manifest_kind) is not str
                    or self.manifest_kind != "canonical-relative-file-set-v1"
                    or type(self.digest_algorithm) is not str or self.digest_algorithm != "sha256"
                    or type(self.entries) is not tuple or len(self.entries) != 28):
                raise ValueError(_MODEL_ERROR)
            for entry in self.entries:
                if type(entry) is not ApplicationManifestEntry:
                    raise ValueError(_MODEL_ERROR)
                # Call validation directly: do not manufacture additional evidence entries.
                ApplicationManifestEntry.__post_init__(entry)
            if tuple(entry.path for entry in self.entries) != _paths():
                raise ValueError(_MODEL_ERROR)
        except Exception:
            raise ValueError(_MODEL_ERROR) from None

    def to_dict(self) -> dict:
        """Return fresh built-in JSON containers without exposing mutable state."""
        self.__post_init__()
        return {
            "manifest_kind": self.manifest_kind,
            "digest_algorithm": self.digest_algorithm,
            "reviewed_commit": self.reviewed_commit,
            "entries": [{"path": entry.path, "sha256": entry.sha256, "mode": entry.mode}
                        for entry in self.entries],
        }

    def canonical_bytes(self) -> bytes:
        """Encode bounded canonical evidence with the existing policy encoder."""
        result = _canonical_bytes(self.to_dict())
        if type(result) is not bytes or not result or len(result) > _MAX_MANIFEST_BYTES:
            raise ValueError(_MODEL_ERROR)
        return result


# The sole subprocess boundary: fixed read-only Git plumbing and bounded stdout.
def _git(root: str, arguments: tuple[str, ...], maximum: int) -> bytes:
    """Run one closed Git operation with bounded memory and a fixed deadline."""
    if arguments[0] not in ("rev-parse", "cat-file", "ls-tree"):
        raise ValueError(_UNAVAILABLE)
    environment = {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_LITERAL_PATHSPECS": "1",
    }
    if _TIMEOUT <= 0:
        raise TimeoutError(_UNAVAILABLE)
    deadline = _time.monotonic() + _TIMEOUT
    process = _subprocess.Popen(
        ("/usr/bin/git", "--no-replace-objects", "-C", root, *arguments),
        stdin=_subprocess.DEVNULL, stdout=_subprocess.PIPE, stderr=_subprocess.DEVNULL,
        env=environment, shell=False,
    )
    try:
        if process.stdout is None:
            raise ValueError(_UNAVAILABLE)
        output = bytearray()
        with _selectors.DefaultSelector() as selector:
            selector.register(process.stdout, _selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - _time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(_UNAVAILABLE)
                for key, _ in selector.select(remaining):
                    chunk = _os.read(key.fileobj.fileno(), min(65536, maximum + 1 - len(output)))
                    if type(chunk) is not bytes:
                        raise ValueError(_UNAVAILABLE)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > maximum:
                            raise ValueError(_UNAVAILABLE)
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            raise TimeoutError(_UNAVAILABLE)
        returncode = process.wait(timeout=remaining)
        if type(returncode) is not int or returncode != 0:
            raise ValueError(_UNAVAILABLE)
        return bytes(output)
    finally:
        try:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=_TIMEOUT)
        finally:
            if process.stdout is not None:
                process.stdout.close()


def _output(root: str, arguments: tuple[str, ...], maximum: int) -> bytes:
    """Defend the collaborator output contract even if the Git helper is replaced."""
    result = _git(root, arguments, maximum)
    if type(result) is not bytes or len(result) > maximum:
        raise ValueError(_UNAVAILABLE)
    return result


def _root(value: object) -> None:
    """Validate absolute Linux path text without coercing public input objects."""
    if (type(value) is not str or not value or value == "/" or "\0" in value or "\\" in value
            or not value.startswith("/") or value.startswith("//")
            or any(part in ("", ".", "..") for part in value[1:].split("/"))):
        raise ValueError(_UNAVAILABLE)


def _tree(raw: bytes, paths: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Require exact ordered regular non-executable blob records for all C25 paths."""
    if not raw.endswith(b"\0"):
        raise ValueError(_UNAVAILABLE)
    records = []
    for record in raw[:-1].split(b"\0"):
        match = _re.fullmatch(rb"100644 blob ([0-9a-f]{40})\t([^\0]+)", record)
        if match is None or match[1] == b"0" * 40:
            raise ValueError(_UNAVAILABLE)
        records.append((match[2].decode("ascii"), match[1].decode("ascii")))
    if tuple(path for path, _ in records) != paths:
        raise ValueError(_UNAVAILABLE)
    return tuple(records)


def generate_dev_application_manifest(*, repository_root: str, reviewed_commit: str) -> DevApplicationManifest:
    """Return exact-HEAD Git-blob evidence; expose only a fixed unavailable error."""
    try:
        _root(repository_root)
        _commit(reviewed_commit)
        top = _output(repository_root, ("rev-parse", "--show-toplevel"), 4096)
        if not top.endswith(b"\n"):
            raise ValueError(_UNAVAILABLE)
        top_path = top[:-1].decode("utf-8")
        _root(top_path)
        if _os.path.realpath(top_path) != _os.path.realpath(repository_root):
            raise ValueError(_UNAVAILABLE)
        head = _output(repository_root, ("rev-parse", "--verify", "HEAD^{commit}"), 41)
        if head != reviewed_commit.encode("ascii") + b"\n":
            raise ValueError(_UNAVAILABLE)
        if _output(repository_root, ("cat-file", "-t", reviewed_commit), 16) != b"commit\n":
            raise ValueError(_UNAVAILABLE)
        selection = _DevApplicationSourceSet()
        if type(selection) is not _DevApplicationSourceSet or type(selection.files) is not tuple:
            raise ValueError(_UNAVAILABLE)
        paths = tuple(item.repository_path for item in selection.files)
        if len(paths) != 28 or paths != _paths() or paths != tuple(sorted(set(paths))):
            raise ValueError(_UNAVAILABLE)
        for item in selection.files:
            if type(item) is not _ApplicationSourceFile:
                raise ValueError(_UNAVAILABLE)
            _ApplicationSourceFile.__post_init__(item)
        # Consume C24 only during explicit generation; its transitive runtime
        # imports are not needed for inert C26 model construction/import.
        from .installation_integrity_contract import ApplicationIntegrityRequirement
        requirement = ApplicationIntegrityRequirement(
            root=selection.application_root, reviewed_commit=reviewed_commit,
            manifest_kind="canonical-relative-file-set-v1", digest_algorithm="sha256",
            manifest_required=True, manifest_entry_fields=("path", "sha256", "mode"),
            regular_files_only=True, sorted_unique_paths=True,
            symlinks_allowed=False, unlisted_paths_allowed=False,
        )
        records = _tree(_output(repository_root, ("ls-tree", "-r", "-z", "--full-tree",
                                                reviewed_commit, "--", *paths), 16384), paths)
        sizes = []
        total = 0
        for _, blob in records:
            raw_size = _output(repository_root, ("cat-file", "-s", blob), 32)
            if _re.fullmatch(rb"(?:0|[1-9][0-9]*)\n", raw_size) is None:
                raise ValueError(_UNAVAILABLE)
            size = int(raw_size[:-1])
            total += size
            if size > _MAX_BLOB_BYTES or total > _MAX_TOTAL_BYTES:
                raise ValueError(_UNAVAILABLE)
            sizes.append(size)
        entries = []
        for (path, blob), size in zip(records, sizes):
            raw = _output(repository_root, ("cat-file", "blob", blob), size)
            if len(raw) != size:
                raise ValueError(_UNAVAILABLE)
            entries.append(ApplicationManifestEntry(path, _hashlib.sha256(raw).hexdigest(), "0644"))
        # Recheck HEAD after reading objects to detect concurrent revision changes.
        if _output(repository_root, ("rev-parse", "--verify", "HEAD^{commit}"), 41) != head:
            raise ValueError(_UNAVAILABLE)
        manifest = DevApplicationManifest(requirement.manifest_kind, requirement.digest_algorithm,
                                          reviewed_commit, tuple(entries))
        manifest.canonical_bytes()
        return manifest
    except Exception:
        raise ApplicationManifestEvidenceError(_UNAVAILABLE) from None
