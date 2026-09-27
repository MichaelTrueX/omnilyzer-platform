"""C32N inert Cosign OCI boundary; only explicit verify calls use registry I/O.

Fixed future resources are not installed here. The injected provider supplies
read-only zot credentials; this boundary never mints them or chooses a clock.
Shared C32G snapshots/process cleanup execute only sealed, hashed tool bytes.
"""

import json as _json
import os as _os
import stat as _stat
import tempfile as _tempfile

from . import blob_verifier as _cosign
from .broker import _bound_operation
from .policy import (
    APPROVED_OCI_HOST as _HOST, APPROVED_OCI_REPOSITORIES as _REPOSITORIES,
    EXPECTED_CERTIFICATE_IDENTITY as _IDENTITY, EXPECTED_CERTIFICATE_ISSUER as _ISSUER,
    exact_image_reference as _reference, validate_digest as _digest,
    validate_sha256 as _sha256,
)
from .release_consumer import (
    ZotReadCredential as _Credential, ZotCredentialProvider as _CredentialProvider,
    _credential,
)

__all__ = ("CosignOCISignatureVerifier", "OCIVerificationError")
_RUNTIME_DIRECTORY = "/run/omnilyzer/deployment/dev/oci-verifier"
_ERROR = "OCI signature verification is unavailable or invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_DirectoryChain = tuple[tuple[int, int | None, str | None, tuple[int, ...]], ...]


class OCIVerificationError(Exception):
    """One fixed external error, without token or untrusted diagnostics."""


def _private(descriptor: int, broker: tuple[int, int], mode: int) -> tuple[int, ...]:
    status = _os.fstat(descriptor)
    fingerprint = _cosign._fingerprint(status)
    if (not _stat.S_ISDIR(status.st_mode)
            or (status.st_uid, status.st_gid, _stat.S_IMODE(status.st_mode)) != (*broker, mode)):
        raise OSError
    return fingerprint


def _process_identity(broker: tuple[int, int]) -> None:
    values = (_os.getuid(), _os.geteuid(), _os.getgid(), _os.getegid())
    if any(type(value) is not int for value in values) or values != (broker[0], broker[0], broker[1], broker[1]):
        raise OSError


def _stable(fingerprint: tuple[int, ...]) -> tuple[int, ...]:
    # Child creation changes directory size/timestamps, never its authority.
    return fingerprint[:3] + fingerprint[4:6]


def _chain(descriptors: list[int], path: str) -> _DirectoryChain:
    names = (None, *path.strip("/").split("/"))
    if len(descriptors) != len(names):
        raise OSError
    return tuple((fd, descriptors[index - 1] if index else None, name,
                  _stable(_cosign._fingerprint(_os.fstat(fd))))
                 for index, (fd, name) in enumerate(zip(descriptors, names, strict=True)))


def _revalidate_chain(chain: _DirectoryChain) -> None:
    for fd, parent, name, expected in chain:
        if _stable(_cosign._fingerprint(_os.fstat(fd))) != expected:
            raise OSError
        if parent is not None and _stable(_cosign._fingerprint(
                _os.stat(name, dir_fd=parent, follow_symlinks=False))) != expected:
            raise OSError


def _auth(directory: int, token: str, broker: tuple[int, int], owned: list[int],
          cleanup: list[tuple[int, str, tuple[int, ...], bool]]) -> tuple[int, ...]:
    # Reviewed DefaultKeychain -> Docker config.Load -> AuthConfig.RegistryToken.
    # Never load/merge ambient configuration or permit credential helper fields.
    raw = _json.dumps({"auths": {_HOST: {"registrytoken": token}}},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")
    descriptor = _os.open("config.json", _os.O_RDWR | _os.O_CREAT | _os.O_EXCL |
                          _os.O_NOFOLLOW | _os.O_CLOEXEC, 0o600, dir_fd=directory)
    owned.append(descriptor)
    status = _os.fstat(descriptor)
    if any(type(value) is not int for value in (status.st_dev, status.st_ino)):
        raise OSError
    # Capture our inode before rejecting any other malformed metadata; no token
    # is written until the complete file authority has passed validation.
    cleanup.append((directory, "config.json", (0, status.st_ino, status.st_dev), False))
    created = _cosign._fingerprint(status)
    if (not _stat.S_ISREG(status.st_mode) or status.st_nlink != 1
            or (status.st_uid, status.st_gid, _stat.S_IMODE(status.st_mode), status.st_size)
            != (*broker, 0o600, 0)):
        raise OSError
    offset = 0
    while offset < len(raw):
        count = _os.write(descriptor, raw[offset:offset + 65536])
        if type(count) is not int or not 0 < count <= len(raw) - offset:
            raise OSError
        offset += count
    current = _cosign._fingerprint(_os.fstat(descriptor))
    if (current[:6] != created[:6] or current[6] != len(raw)
            or _cosign._read(descriptor, len(raw)) != raw
            or _cosign._fingerprint(_os.fstat(descriptor)) != current
            or _cosign._fingerprint(_os.stat("config.json", dir_fd=directory,
                                            follow_symlinks=False)) != current):
        raise OSError
    return current


def _remove(parent: int, name: str, expected: tuple[int, ...], *, directory: bool) -> None:
    current = _cosign._fingerprint(_os.stat(name, dir_fd=parent, follow_symlinks=False))
    if (current[2], current[1]) != (expected[2], expected[1]):
        raise OSError
    if directory:
        _os.rmdir(name, dir_fd=parent)
    else:
        _os.unlink(name, dir_fd=parent)


class CosignOCISignatureVerifier:
    """Immutable static authority and captured provider/runner bound operations."""

    __slots__ = ("_binary_sha256", "_root_sha256", "_broker", "_run", "_credential", "_authority")

    def __init__(self, *, expected_cosign_version: str, expected_binary_sha256: str,
                 expected_trusted_root_sha256: str, broker_uid: int, broker_gid: int,
                 zot_credential_provider: _CredentialProvider, runner: object | None = None) -> None:
        try:
            if type(expected_cosign_version) is not str or expected_cosign_version != _cosign.COSIGN_VERSION:
                raise ValueError
            for value in (expected_binary_sha256, expected_trusted_root_sha256):
                if type(value) is not str or value == "0" * 64:
                    raise ValueError
                _sha256(value, "reviewed verification authority")
            if any(type(value) is not int or not 0 < value <= 2**32 - 2 for value in (broker_uid, broker_gid)):
                raise ValueError
            credential = _bound_operation(zot_credential_provider, "zot_read_credential")
            operation = _bound_operation(_cosign._CosignProcess() if runner is None else runner, "run")
        except Exception:
            raise OCIVerificationError(_ERROR) from None
        object.__setattr__(self, "_binary_sha256", expected_binary_sha256)
        object.__setattr__(self, "_root_sha256", expected_trusted_root_sha256)
        object.__setattr__(self, "_broker", (broker_uid, broker_gid))
        object.__setattr__(self, "_run", operation)
        object.__setattr__(self, "_credential", credential)
        object.__setattr__(self, "_authority", (_cosign.COSIGN_PATH, _cosign.TRUSTED_ROOT_PATH,
                           _RUNTIME_DIRECTORY, _HOST, _REPOSITORIES[0], _IDENTITY, _ISSUER))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("OCI verifier authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("OCI verifier authority is immutable")

    def verify(self, image_reference: str, now: int) -> dict[str, object]:
        owned: list[int] = []
        cleanup: list[tuple[int, str, tuple[int, ...], bool]] = []
        failed = False
        control = None
        token = credential = None
        try:
            binary_path, root_path, runtime_path, host, repository, identity, issuer = self._authority
            prefix = host + "/" + repository + "@"
            if (type(image_reference) is not str or not image_reference.startswith(prefix)
                    or type(now) is not int or now < 0):
                raise ValueError
            digest = _digest(image_reference[len(prefix):])
            if image_reference != _reference(repository, digest):
                raise ValueError
            broker = self._broker
            _process_identity(broker)
            binary = _cosign._snapshot(binary_path, self._binary_sha256, owned,
                                       executable=True, broker_gid=broker[1])
            root = _cosign._snapshot(root_path, self._root_sha256, owned,
                                     executable=False, broker_gid=broker[1])
            start = len(owned)
            runtime = _cosign._directory(runtime_path, owned, broker=broker)
            chain = _chain(owned[start:], runtime_path)
            workspace_path = _tempfile.mkdtemp(prefix="verify-", dir=f"/proc/self/fd/{runtime}")
            name = workspace_path.rsplit("/", 1)[1]
            named = _cosign._fingerprint(_os.stat(name, dir_fd=runtime, follow_symlinks=False))
            cleanup.append((runtime, name, named, True))
            flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
            workspace = _os.open(name, flags, dir_fd=runtime)
            owned.append(workspace)
            if _private(workspace, broker, 0o700) != named:
                raise OSError
            _os.mkdir(".docker", 0o700, dir_fd=workspace)
            docker_named = _cosign._fingerprint(_os.stat(".docker", dir_fd=workspace, follow_symlinks=False))
            cleanup.append((workspace, ".docker", docker_named, True))
            docker = _os.open(".docker", flags, dir_fd=workspace)
            owned.append(docker)
            if _private(docker, broker, 0o700) != docker_named:
                raise OSError
            # Acquire only after static resources/private directories are ready.
            credential = self._credential()
            token = _credential(credential, _Credential, now)
            # Record the created config immediately, even if writing/validation fails.
            try:
                auth = _auth(docker, token, broker, owned, cleanup)
            finally:
                token = credential = None
            home, docker_config = f"/proc/self/fd/{workspace}", f"/proc/self/fd/{docker}"
            _revalidate_chain(chain)
            _private(workspace, broker, 0o700)
            _private(docker, broker, 0o700)
            if _cosign._fingerprint(_os.stat("config.json", dir_fd=docker, follow_symlinks=False)) != auth:
                raise OSError
            _process_identity(broker)
            argv = (binary_path, "verify", "--offline", "--trusted-root", f"/proc/self/fd/{root}",
                    "--certificate-identity", identity, "--certificate-oidc-issuer", issuer, image_reference)
            result = self._run(argv, b"", executable=f"/proc/self/fd/{binary}",
                               descriptors=(binary, root, workspace, docker), home=home,
                               docker_config=docker_config)
            if (type(result) is not _cosign._ProcessResult or type(result.returncode) is not int
                    or result.returncode != 0 or any(type(count) is not int
                    or not 0 <= count <= _cosign.MAX_OUTPUT_BYTES
                    for count in (result.stdout_bytes, result.stderr_bytes))):
                raise ValueError
            _revalidate_chain(chain)
            _private(workspace, broker, 0o700)
            _private(docker, broker, 0o700)
            if _cosign._fingerprint(_os.stat("config.json", dir_fd=docker, follow_symlinks=False)) != auth:
                raise OSError
            _process_identity(broker)
        except _CONTROL as error:
            control = error
        except Exception:
            failed = True
        finally:
            token = credential = None
            # Unlink the token file through the held directory before closing any
            # descriptors. Never remove a substituted pathname by name alone.
            for parent, name, expected, directory in reversed(cleanup):
                try:
                    _remove(parent, name, expected, directory=directory)
                except _CONTROL as error:
                    control = control or error
                except Exception:
                    failed = True
            for descriptor in reversed(owned):
                try:
                    _os.close(descriptor)
                except _CONTROL as error:
                    control = control or error
                except Exception:
                    failed = True
        if control is not None:
            raise control
        if failed:
            raise OCIVerificationError(_ERROR) from None
        return {"verified": True, "repository": repository, "manifest_digest": digest,
                "certificate_identity": identity, "issuer": issuer}
