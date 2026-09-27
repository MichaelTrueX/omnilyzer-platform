"""C32G repository-only Cosign blob boundary; import/construction are inert.

Fixed future resources are NOT provisioned by this module. A later root-controlled
installation must qualify the exact linux/amd64 3.1.2 binary, TrustedRoot and
private broker runtime. No OCI verification or service composition lives here.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from .broker import _bound_operation
from .broker_service_config import (
    BROKER_SERVICE_CONFIG_DIRECTORY_MODE,
    BROKER_SERVICE_CONFIG_FILE_MODE,
    COSIGN_VERSION,
    PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH as TRUSTED_ROOT_PATH,
)
from .policy import EXPECTED_CERTIFICATE_IDENTITY, EXPECTED_CERTIFICATE_ISSUER, validate_sha256
from .release_consumer import MAX_EVIDENCE_BYTES

COSIGN_PATH = "/opt/omnilyzer/deployment/tools/cosign-v3.1.2-linux-amd64"
RUNTIME_DIRECTORY = "/run/omnilyzer/deployment/dev/blob-verifier"
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_ROOT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
EXECUTION_TIMEOUT = 30.0
ERROR = "release blob signature verification is unavailable or invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class BlobVerificationError(Exception):
    """One fixed external failure, without untrusted process diagnostics."""


@dataclass(frozen=True, slots=True)
class _ProcessResult:
    returncode: int
    stdout_bytes: int
    stderr_bytes: int


class _CosignProcess:
    def run(self, argv: tuple[str, ...], blob: bytes, *, executable: str,
            descriptors: tuple[int, ...], home: str) -> _ProcessResult:
        """Drain both pipes while sending bounded stdin; retain no child output."""
        child = subprocess.Popen(
            argv, executable=executable, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            env={"HOME": home, "XDG_CACHE_HOME": home, "XDG_CONFIG_HOME": home,
                 "LANG": "C", "LC_ALL": "C"},
            cwd=home, close_fds=True, pass_fds=descriptors, start_new_session=True,
        )
        try:
            counts = {"stdout": 0, "stderr": 0}
            offset = 0
            deadline = time.monotonic() + EXECUTION_TIMEOUT
            with selectors.DefaultSelector() as selector:
                for stream, name, event in (
                    (child.stdin, "stdin", selectors.EVENT_WRITE),
                    (child.stdout, "stdout", selectors.EVENT_READ),
                    (child.stderr, "stderr", selectors.EVENT_READ),
                ):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event, name)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    for key, _event in selector.select(remaining):
                        descriptor = key.fileobj.fileno()
                        if key.data == "stdin":
                            offset += os.write(descriptor, blob[offset:offset + 65536])
                            if offset == len(blob):
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                        else:
                            chunk = os.read(descriptor, 65536)
                            counts[key.data] += len(chunk)
                            if counts[key.data] > MAX_OUTPUT_BYTES:
                                raise ValueError
                            if not chunk:
                                selector.unregister(key.fileobj)
                    if time.monotonic() >= deadline:
                        raise TimeoutError
            # Observe exit without reaping: the zombie leader pins its PID until
            # cleanup kills the group. This avoids killpg hitting a reused PID.
            while True:
                status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if status is not None:
                    returncode = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                time.sleep(min(0.01, remaining))
            if offset != len(blob):
                raise ValueError
            return _ProcessResult(returncode, counts["stdout"], counts["stderr"])
        finally:
            # Reviewed binary must not daemonize; kill its entire isolated process
            # group even on successful exit, so descendants cannot retain evidence.
            pending = sys.exception()
            cleanup_failed = False
            cleanup_control = None
            def terminate() -> None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for operation in (terminate, lambda: child.wait(timeout=1.0),
                              child.stdin.close, child.stdout.close, child.stderr.close):
                try:
                    operation()
                except _CONTROL as exc:
                    cleanup_control = cleanup_control or exc
                except Exception:
                    cleanup_failed = True
            if not isinstance(pending, _CONTROL):
                if cleanup_control is not None:
                    raise cleanup_control
                if cleanup_failed:
                    raise OSError


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_mode, value.st_ino, value.st_dev, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _directory(path: str, owned: list[int], *, broker: tuple[int, int] | None = None) -> int:
    """C17-style descriptor-relative no-follow traversal, including root."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    owned.append(descriptor)
    components = path.strip("/").split("/") if path != "/" else []
    for index in range(len(components) + 1):
        current = os.fstat(descriptor)
        final_private = broker is not None and index == len(components)
        if (not stat.S_ISDIR(current.st_mode)
                or (final_private and (current.st_uid, current.st_gid,
                    stat.S_IMODE(current.st_mode)) != (*broker, 0o700))
                or (not final_private and (current.st_uid != 0 or current.st_mode & 0o022))):
            raise OSError
        if index == len(components):
            return descriptor
        name = components[index]
        named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        child = os.open(name, flags, dir_fd=descriptor)
        owned.append(child)
        if _fingerprint(named) != _fingerprint(os.fstat(child)):
            raise OSError
        descriptor = child
    raise OSError


def _sealed(raw: bytes, owned: list[int], *, executable: bool = False) -> int:
    """Hash/use the same immutable Linux kernel file, never a reopened pathname."""
    descriptor = os.memfd_create("omnilyzer-evidence", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    owned.append(descriptor)
    os.fchmod(descriptor, 0o500 if executable else 0o600)
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:offset + 65536])
        if written <= 0:
            raise OSError
        offset += written
    os.lseek(descriptor, 0, os.SEEK_SET)
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
    if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != seals:
        raise OSError
    return descriptor


def _snapshot(path: str, digest: str, maximum: int, owned: list[int], *, executable: bool) -> int:
    parent, name = path.rsplit("/", 1)
    directory = _directory(parent, owned)
    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory)
    owned.append(descriptor)
    opened = os.fstat(descriptor)
    if not executable:
        authority_directory = os.fstat(directory)
        if (
            (authority_directory.st_uid, authority_directory.st_gid,
             stat.S_IMODE(authority_directory.st_mode))
            != (0, os.getegid(), BROKER_SERVICE_CONFIG_DIRECTORY_MODE)
            or (opened.st_gid, stat.S_IMODE(opened.st_mode))
            != (os.getegid(), BROKER_SERVICE_CONFIG_FILE_MODE)
        ):
            raise OSError
    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0
            or opened.st_nlink != 1 or opened.st_mode & 0o022
            or not 0 < opened.st_size <= maximum
            or (executable and not opened.st_mode & stat.S_IXUSR)
            or _fingerprint(named) != _fingerprint(opened)):
        raise OSError
    raw = _read(descriptor, opened.st_size)
    if (hashlib.sha256(raw).hexdigest() != digest
            or _fingerprint(os.fstat(descriptor)) != _fingerprint(opened)
            or _fingerprint(os.stat(name, dir_fd=directory, follow_symlinks=False))
            != _fingerprint(opened)):
        raise OSError
    # Copying into a sealed descriptor closes even root-file in-place-write
    # TOCTOU: the reviewed digest binds the exact immutable executed/read bytes.
    return _sealed(raw, owned, executable=executable)


def _read(descriptor: int, size: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    result = bytearray()
    while len(result) < size:
        chunk = os.read(descriptor, min(65536, size - len(result)))
        if not chunk:
            raise OSError
        result.extend(chunk)
    if os.read(descriptor, 1):
        raise OSError
    return bytes(result)


def _bundle(raw: bytes, workspace: str, owned: list[int]) -> int:
    """Exclusive private 0600 disk staging; Cosign consumes a sealed snapshot.

    The disk entry is removed before execution. /proc/self/fd exposes a regular
    immutable file to Cosign's --bundle reader, without a shared /tmp name.
    """
    descriptor, path = tempfile.mkstemp(prefix="bundle-", dir=workspace)
    owned.append(descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:offset + 65536])
            if written <= 0:
                raise OSError
            offset += written
        opened = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid) != (os.geteuid(), os.getegid())
                or stat.S_IMODE(named.st_mode) != 0o600
                or _fingerprint(named) != _fingerprint(opened)
                or _read(descriptor, len(raw)) != raw):
            raise OSError
        return _sealed(raw, owned)
    finally:
        pending = sys.exception()
        try:
            os.unlink(path)
        except BaseException:
            if not isinstance(pending, _CONTROL):
                raise


class CosignReleaseBlobVerifier:
    """Immutable future authority; no caller-selected executable/root paths.

    Expected version/digests and numeric broker identity must come from a later
    reviewed root-controlled authority, never promotion/evidence or HOME/TUF.
    A constructor-injected runner is an explicit trusted test/authority seam.
    """

    __slots__ = ("_binary_sha256", "_root_sha256", "_broker", "_run", "_authority")

    def __init__(self, *, expected_cosign_version: str, expected_binary_sha256: str,
                 expected_trusted_root_sha256: str, broker_uid: int, broker_gid: int,
                 runner: object | None = None) -> None:
        try:
            if type(expected_cosign_version) is not str or expected_cosign_version != COSIGN_VERSION:
                raise ValueError
            for value in (expected_binary_sha256, expected_trusted_root_sha256):
                if type(value) is not str or value == "0" * 64:
                    raise ValueError
                validate_sha256(value, "reviewed verification authority")
            if any(type(value) is not int or not 0 < value <= 2**32 - 2
                   for value in (broker_uid, broker_gid)):
                raise ValueError
            operation = _bound_operation(_CosignProcess() if runner is None else runner, "run")
        except Exception:
            raise BlobVerificationError(ERROR) from None
        object.__setattr__(self, "_binary_sha256", expected_binary_sha256)
        object.__setattr__(self, "_root_sha256", expected_trusted_root_sha256)
        object.__setattr__(self, "_broker", (broker_uid, broker_gid))
        object.__setattr__(self, "_run", operation)
        object.__setattr__(self, "_authority", (COSIGN_PATH, TRUSTED_ROOT_PATH,
                           RUNTIME_DIRECTORY, EXPECTED_CERTIFICATE_IDENTITY,
                           EXPECTED_CERTIFICATE_ISSUER, COSIGN_VERSION))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("blob verifier authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("blob verifier authority is immutable")

    def verify(self, manifest: bytes, provenance: bytes, manifest_bundle: bytes,
               provenance_bundle: bytes) -> dict[str, object]:
        if any(type(raw) is not bytes or not 0 < len(raw) <= MAX_EVIDENCE_BYTES
               for raw in (manifest, provenance, manifest_bundle, provenance_bundle)):
            raise BlobVerificationError(ERROR) from None
        owned: list[int] = []
        workspace = None
        failed = False
        control = None
        try:
            broker = object.__getattribute__(self, "_broker")
            if (os.getuid(), os.getgid()) != broker or (os.geteuid(), os.getegid()) != broker:
                raise OSError
            binary_path, root_path, runtime_path, identity, issuer, _version = (
                object.__getattribute__(self, "_authority")
            )
            binary = _snapshot(binary_path, object.__getattribute__(self, "_binary_sha256"),
                               MAX_BINARY_BYTES, owned, executable=True)
            root = _snapshot(root_path, object.__getattribute__(self, "_root_sha256"),
                             MAX_ROOT_BYTES, owned, executable=False)
            runtime = _directory(runtime_path, owned, broker=broker)
            # Anchor staging/cleanup to the validated directory descriptor.
            workspace = tempfile.mkdtemp(prefix="verify-", dir=f"/proc/self/fd/{runtime}")
            workspace_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            owned.append(workspace_fd)
            opened_workspace = os.fstat(workspace_fd)
            if ((opened_workspace.st_uid, opened_workspace.st_gid,
                 stat.S_IMODE(opened_workspace.st_mode)) != (*broker, 0o700)
                    or _fingerprint(os.stat(workspace, follow_symlinks=False))
                    != _fingerprint(opened_workspace)):
                raise OSError
            private_home = f"/proc/self/fd/{workspace_fd}"
            for blob, bundle in ((manifest, manifest_bundle), (provenance, provenance_bundle)):
                bundle_fd = _bundle(bundle, private_home, owned)
                argv = (binary_path, "verify-blob", "--bundle", f"/proc/self/fd/{bundle_fd}",
                        "--trusted-root", f"/proc/self/fd/{root}",
                        "--certificate-identity", identity,
                        "--certificate-oidc-issuer", issuer, "-")
                result = object.__getattribute__(self, "_run")(
                    argv, blob, executable=f"/proc/self/fd/{binary}",
                    descriptors=(binary, root, bundle_fd, runtime, workspace_fd), home=private_home,
                )
                if (type(result) is not _ProcessResult or type(result.returncode) is not int
                        or result.returncode != 0
                        or any(type(count) is not int or not 0 <= count <= MAX_OUTPUT_BYTES
                               for count in (result.stdout_bytes, result.stderr_bytes))):
                    raise ValueError
        except _CONTROL as exc:
            control = exc
        except Exception:
            failed = True
        finally:
            if workspace is not None:
                try:
                    if not shutil.rmtree.avoids_symlink_attacks:
                        raise OSError
                    shutil.rmtree(workspace)
                except _CONTROL as exc:
                    control = control or exc
                except Exception:
                    failed = True
            for descriptor in reversed(owned):
                try:
                    os.close(descriptor)
                except _CONTROL as exc:
                    control = control or exc
                except Exception:
                    failed = True
        if control is not None:
            raise control
        if failed:
            raise BlobVerificationError(ERROR) from None
        return {"release_manifest_verified": True, "provenance_verified": True,
                "certificate_identity": identity, "issuer": issuer}
