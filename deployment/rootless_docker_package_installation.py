"""deployment/rootless_docker_package_installation.py - C32ZW offline installer.

Purpose:
- consume C32ZV immediately before the first package/bootstrap mutation;
- keep the three rootful Docker/containerd units masked and maintainer-script
  starts blocked before dpkg can consume any package;
- install only the exact nine already-staged C32ZR payloads through held,
  rehashed descriptors with no package-manager network resolution;
- resume only an exact C32ZW-owned prefix after interruption.

C32ZW installs packages only. It does not allocate subordinate IDs, provision
rootless assets, enable linger/user services, start Docker, expose a socket, or
activate deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
import subprocess

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_preinstall_qualification as preinstall
from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from .rootless_docker_package_bundle_qualification import (
    RootlessDockerPackageBundleEvidence,
    qualify_rootless_docker_package_bundle,
)
from .rootless_docker_staged_preinstall_qualification import (
    RootlessDockerStagedPreinstallEvidence,
    qualify_rootless_docker_staged_preinstall,
)
from .successor_application_generation import TARGET_REVIEWED_COMMIT
from .successor_host_migration_qualification import qualify_successor_host_migration


__all__ = (
    "RootlessDockerPackageInstallationError",
    "RootlessDockerPackageInstallationEvidence",
    "install_rootless_docker_packages",
)

_ERROR = "rootless Docker package installation is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_DPKG = "/usr/bin/dpkg"
_SYSTEMCTL = "/usr/bin/systemctl"
_POLICY_MODE = 0o755
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CHUNK = 64 * 1024
_COMMAND_TIMEOUT = 30.0
_DPKG_TIMEOUT = 300.0
_OUTPUT_LIMIT = 1024 * 1024
_MASK_DIRECTORY = "/etc/systemd/system"
_POLICY_DIRECTORY = "/usr/sbin"
_RUNTIME_SOCKETS = (
    "/var/run/docker.sock",
    "/run/user/991/docker.sock",
    "/run/omnilyzer/deployment/rootless-docker/docker.sock",
)
_EXPECTED_APPLICATION_SHA256 = (
    "9bb162e1712a8ec76874c229ce1af1c8a88f527686d4a43376ca93a8b0d00b88"
)
_TARGET_VERSIONS = {
    item.name: item.apt_version
    for item in (
        *INSTALLATION_AUTHORITY.packages,
        *INSTALLATION_AUTHORITY.supplemental_packages,
    )
}
_ALLOWED_DPKG_STATES = frozenset("ncHUFWti")


class RootlessDockerPackageInstallationError(Exception):
    """One fixed external failure for the privileged C32ZW installer."""


@dataclass(frozen=True, slots=True)
class RootlessDockerPackageInstallationEvidence:
    """Compact exact evidence returned only after a safe installed state."""

    operation: str
    expected_workflow_sha: str
    packages: tuple[tuple[str, str, str], ...]
    masked_units: tuple[str, ...]
    staging_directory: str
    staged_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        expected_packages = tuple(
            (payload.package, _TARGET_VERSIONS[payload.package], "amd64")
            for payload in INSTALLATION_AUTHORITY.payloads
        )
        if (
            self.operation not in {"installed", "resumed", "already-installed"}
            or type(self.expected_workflow_sha) is not str
            or len(self.expected_workflow_sha) != 40
            or self.expected_workflow_sha == "0" * 40
            or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
            or self.packages != expected_packages
            or self.masked_units != INSTALLATION_AUTHORITY.rootful_units
            or self.staging_directory != INSTALLATION_AUTHORITY.staging_directory
            or self.staged_sha256s
            != tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads)
        ):
            raise ValueError(_ERROR)


def _root_identity() -> tuple[int, int, int, int]:
    return preinstall._root_identity()


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
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


def _none(value) -> None:
    if value is not None:
        raise OSError


def _run(
    argv: tuple[str, ...],
    *,
    timeout: float = _COMMAND_TIMEOUT,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    """Run one fixed mutating command shape under a closed environment."""

    if (
        type(argv) is not tuple
        or not argv
        or any(type(value) is not str or not value for value in argv)
        or type(pass_fds) is not tuple
        or any(type(value) is not int or value < 0 for value in pass_fds)
    ):
        raise OSError
    if argv == (_SYSTEMCTL, "daemon-reload"):
        pass
    elif len(argv) == 3 and argv[:2] == (_SYSTEMCTL, "start"):
        if argv[2] not in INSTALLATION_AUTHORITY.rootful_units:
            raise OSError
    elif argv == (INSTALLATION_AUTHORITY.policy_rc_d_path,):
        pass
    elif (
        len(argv) == 2 + len(INSTALLATION_AUTHORITY.payloads)
        and argv[:2] == (_DPKG, "--install")
        and len(pass_fds) == len(INSTALLATION_AUTHORITY.payloads)
        and argv[2:] == tuple(f"/proc/self/fd/{item}" for item in pass_fds)
        and len(set(pass_fds)) == len(pass_fds)
    ):
        timeout = _DPKG_TIMEOUT
    else:
        raise OSError

    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": "/root",
            "DEBIAN_FRONTEND": "noninteractive",
        },
        shell=False,
        timeout=timeout,
        check=False,
        pass_fds=pass_fds,
    )
    if (
        type(result.returncode) is not int
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > _OUTPUT_LIMIT
        or len(result.stderr) > _OUTPUT_LIMIT
    ):
        raise OSError
    return result


def _package_state(name: str) -> tuple[str, str, str] | None:
    """Return one exact target package state, or None when no record exists."""

    if name not in _TARGET_VERSIONS:
        raise OSError
    result = preinstall._run(
        (
            preinstall._DPKG_QUERY,
            "-W",
            preinstall._DPKG_FORMAT,
            name,
        )
    )
    if result.returncode == 1 and result.stdout == b"":
        return None
    if (
        result.returncode != 0
        or not result.stdout.endswith(b"\n")
        or result.stdout.count(b"\n") != 1
        or b"\r" in result.stdout
    ):
        raise OSError
    fields = result.stdout[:-1].split(b"\t")
    if len(fields) != 3 or len(fields[0]) != 3:
        raise OSError
    try:
        status = fields[0].decode("ascii")
        version = fields[1].decode("ascii")
        architecture = fields[2].decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None
    if (
        status[0] != "i"
        or status[1] not in _ALLOWED_DPKG_STATES
        or status[2] not in {" ", "R"}
        or version != _TARGET_VERSIONS[name]
        or architecture != "amd64"
    ):
        raise OSError
    return status, version, architecture


def _package_states() -> tuple[tuple[str, tuple[str, str, str] | None], ...]:
    return tuple(
        (payload.package, _package_state(payload.package))
        for payload in INSTALLATION_AUTHORITY.payloads
    )


def _all_absent(states) -> bool:
    return all(value is None for _name, value in states)


def _all_installed(states) -> bool:
    return all(value is not None and value[0] == "ii " for _name, value in states)


def _installed_evidence(states) -> tuple[tuple[str, str, str], ...]:
    if not _all_installed(states):
        raise OSError
    return tuple(
        (name, value[1], value[2])
        for name, value in states
        if value is not None
    )


def _policy_fingerprint() -> tuple[int, ...] | None:
    """Require the temporary policy blocker to be absent or exact."""

    path = INSTALLATION_AUTHORITY.policy_rc_d_path
    try:
        named = os.lstat(path)
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or (named.st_uid, named.st_gid) != (0, 0)
        or stat.S_IMODE(named.st_mode) != _POLICY_MODE
        or named.st_size != len(INSTALLATION_AUTHORITY.policy_rc_d_bytes)
    ):
        raise OSError
    descriptor = None
    try:
        descriptor = os.open(path, _FILE_FLAGS)
        opened = os.fstat(descriptor)
        if _fingerprint(opened) != _fingerprint(named):
            raise OSError
        chunks = bytearray()
        while len(chunks) <= len(INSTALLATION_AUTHORITY.policy_rc_d_bytes):
            chunk = os.read(
                descriptor,
                len(INSTALLATION_AUTHORITY.policy_rc_d_bytes) + 1 - len(chunks),
            )
            if not chunk:
                break
            chunks.extend(chunk)
        if bytes(chunks) != INSTALLATION_AUTHORITY.policy_rc_d_bytes:
            raise OSError
        if (
            _fingerprint(os.fstat(descriptor)) != _fingerprint(named)
            or _fingerprint(os.lstat(path)) != _fingerprint(named)
        ):
            raise OSError
        return _fingerprint(named)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _mask_prefix() -> int:
    """Accept only an exact ordered prefix of persistent /dev/null masks."""

    missing = False
    count = 0
    for unit in INSTALLATION_AUTHORITY.rootful_units:
        path = _MASK_DIRECTORY + "/" + unit
        try:
            value = os.lstat(path)
        except FileNotFoundError:
            missing = True
            continue
        if (
            missing
            or not stat.S_ISLNK(value.st_mode)
            or (value.st_uid, value.st_gid) != (0, 0)
            or os.readlink(path) != "/dev/null"
        ):
            raise OSError
        count += 1
    return count


def _open_root_directory(path: str, mode: int = 0o755) -> int:
    descriptor = os.open(path, _DIRECTORY_FLAGS)
    value = os.fstat(descriptor)
    named = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISDIR(value.st_mode)
        or (value.st_uid, value.st_gid) != (0, 0)
        or stat.S_IMODE(value.st_mode) != mode
        or _fingerprint(value) != _fingerprint(named)
    ):
        os.close(descriptor)
        raise OSError
    return descriptor


def _create_policy() -> None:
    if _policy_fingerprint() is not None:
        return
    directory = _open_root_directory(_POLICY_DIRECTORY)
    descriptor = None
    try:
        descriptor = os.open(
            "policy-rc.d",
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            _POLICY_MODE,
            dir_fd=directory,
        )
        _none(os.fchown(descriptor, 0, 0))
        _none(os.fchmod(descriptor, _POLICY_MODE))
        payload = INSTALLATION_AUTHORITY.policy_rc_d_bytes
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if type(count) is not int or count <= 0:
                raise OSError
            written += count
        _none(os.fsync(descriptor))
        _none(os.fsync(directory))
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)
    if _policy_fingerprint() is None:
        raise OSError


def _create_masks(prefix: int) -> None:
    if type(prefix) is not int or not 0 <= prefix <= len(INSTALLATION_AUTHORITY.rootful_units):
        raise OSError
    directory = _open_root_directory(_MASK_DIRECTORY)
    try:
        for unit in INSTALLATION_AUTHORITY.rootful_units[prefix:]:
            _none(os.symlink("/dev/null", unit, dir_fd=directory))
            _none(os.fsync(directory))
            value = os.stat(unit, dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISLNK(value.st_mode)
                or (value.st_uid, value.st_gid) != (0, 0)
                or os.readlink(unit, dir_fd=directory) != "/dev/null"
            ):
                raise OSError
    finally:
        os.close(directory)
    if _mask_prefix() != len(INSTALLATION_AUTHORITY.rootful_units):
        raise OSError


def _systemctl_value(unit: str, property_name: str) -> str:
    return preinstall._systemctl_value(unit, property_name)


def _require_masks_effective() -> None:
    if _mask_prefix() != len(INSTALLATION_AUTHORITY.rootful_units):
        raise OSError
    for unit in INSTALLATION_AUTHORITY.rootful_units:
        if (
            _systemctl_value(unit, "UnitFileState") != "masked"
            or _systemctl_value(unit, "ActiveState") != "inactive"
        ):
            raise OSError


def _require_no_runtime() -> None:
    for name in ("dockerd", "containerd"):
        result = preinstall._run((preinstall._PGREP, "-x", name))
        if result.returncode != 1 or result.stdout != b"":
            raise OSError
    for path in _RUNTIME_SOCKETS:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        raise OSError


def _verify_start_blockers() -> None:
    policy = _run((INSTALLATION_AUTHORITY.policy_rc_d_path,))
    if policy.returncode != 101 or policy.stdout != b"" or policy.stderr != b"":
        raise OSError
    for unit in INSTALLATION_AUTHORITY.rootful_units:
        result = _run((_SYSTEMCTL, "start", unit))
        if result.returncode == 0:
            raise OSError
        if _systemctl_value(unit, "ActiveState") != "inactive":
            raise OSError


def _qualify_static_host() -> tuple[str, tuple[tuple[str, str, str], ...], tuple[str, ...]]:
    """Require all pre-install invariants that package installation must not alter."""

    identity = _root_identity()
    migrated = qualify_successor_host_migration()
    if (
        migrated.phase != "complete"
        or migrated.next_operation != "complete"
        or migrated.application_sha256 != _EXPECTED_APPLICATION_SHA256
        or migrated.executor_reviewed_commit != TARGET_REVIEWED_COMMIT
        or migrated.broker_reviewed_commit != TARGET_REVIEWED_COMMIT
    ):
        raise OSError
    preinstall._require_executor_identity()
    dependencies = tuple(
        preinstall._require_host_dependency(item)
        for item in INSTALLATION_AUTHORITY.host_dependencies
    )
    for name in INSTALLATION_AUTHORITY.conflicting_packages:
        if name in _TARGET_VERSIONS:
            continue
        preinstall._require_package_not_installed(name)
    preinstall._require_subid_authority()
    controllers = preinstall._require_kernel_prerequisites()
    _require_no_runtime()
    if _root_identity() != identity:
        raise OSError
    return migrated.expected_workflow_sha, dependencies, controllers


def _open_bundle(
    bundle: RootlessDockerPackageBundleEvidence,
    owned: list[int],
) -> tuple[int, tuple[int, ...]]:
    if type(bundle) is not RootlessDockerPackageBundleEvidence:
        raise OSError
    if (
        bundle.staging_directory != INSTALLATION_AUTHORITY.staging_directory
        or tuple(item.package for item in bundle.files)
        != tuple(item.package for item in INSTALLATION_AUTHORITY.payloads)
    ):
        raise OSError
    directory = os.open(INSTALLATION_AUTHORITY.staging_directory, _DIRECTORY_FLAGS)
    owned.append(directory)
    if (
        _fingerprint(os.fstat(directory)) != bundle.directory_fingerprint
        or _fingerprint(
            os.stat(
                INSTALLATION_AUTHORITY.staging_directory,
                follow_symlinks=False,
            )
        )
        != bundle.directory_fingerprint
        or tuple(sorted(os.listdir(directory)))
        != tuple(sorted(INSTALLATION_AUTHORITY.payload_filenames()))
    ):
        raise OSError
    descriptors: list[int] = []
    for payload, evidence in zip(
        INSTALLATION_AUTHORITY.payloads, bundle.files, strict=True
    ):
        if (
            evidence.package != payload.package
            or evidence.filename != payload.filename
            or evidence.size != payload.size
            or evidence.sha256 != payload.sha256
        ):
            raise OSError
        descriptor = os.open(payload.filename, _FILE_FLAGS, dir_fd=directory)
        owned.append(descriptor)
        descriptors.append(descriptor)
        if (
            _fingerprint(os.fstat(descriptor)) != evidence.fingerprint
            or _fingerprint(
                os.stat(payload.filename, dir_fd=directory, follow_symlinks=False)
            )
            != evidence.fingerprint
        ):
            raise OSError
    return directory, tuple(descriptors)


def _rehash_bundle(
    directory: int,
    descriptors: tuple[int, ...],
    bundle: RootlessDockerPackageBundleEvidence,
) -> None:
    if (
        len(descriptors) != len(INSTALLATION_AUTHORITY.payloads)
        or _fingerprint(os.fstat(directory)) != bundle.directory_fingerprint
        or tuple(sorted(os.listdir(directory)))
        != tuple(sorted(INSTALLATION_AUTHORITY.payload_filenames()))
    ):
        raise OSError
    for descriptor, payload, evidence in zip(
        descriptors,
        INSTALLATION_AUTHORITY.payloads,
        bundle.files,
        strict=True,
    ):
        if _fingerprint(os.fstat(descriptor)) != evidence.fingerprint:
            raise OSError
        if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
            raise OSError
        digest = hashlib.sha256()
        remaining = payload.size
        while remaining:
            chunk = os.read(descriptor, min(_CHUNK, remaining))
            if type(chunk) is not bytes or not chunk:
                raise OSError
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) != b"" or digest.hexdigest() != payload.sha256:
            raise OSError
        if (
            _fingerprint(os.fstat(descriptor)) != evidence.fingerprint
            or _fingerprint(
                os.stat(payload.filename, dir_fd=directory, follow_symlinks=False)
            )
            != evidence.fingerprint
        ):
            raise OSError
    if _fingerprint(os.fstat(directory)) != bundle.directory_fingerprint:
        raise OSError


def _run_dpkg(descriptors: tuple[int, ...]) -> None:
    result = _run(
        (
            _DPKG,
            "--install",
            *(f"/proc/self/fd/{item}" for item in descriptors),
        ),
        pass_fds=descriptors,
    )
    if result.returncode != 0:
        raise OSError


def _remove_policy() -> None:
    if _policy_fingerprint() is None:
        raise OSError
    directory = _open_root_directory(_POLICY_DIRECTORY)
    try:
        _none(os.unlink("policy-rc.d", dir_fd=directory))
        _none(os.fsync(directory))
    finally:
        os.close(directory)
    if _policy_fingerprint() is not None:
        raise OSError


def _phase(
    policy: tuple[int, ...] | None,
    masks: int,
    states,
) -> str:
    if policy is None:
        if masks == 0 and _all_absent(states):
            return "initial"
        if masks == len(INSTALLATION_AUTHORITY.rootful_units) and _all_installed(states):
            return "complete"
        raise OSError
    if masks < len(INSTALLATION_AUTHORITY.rootful_units) and not _all_absent(states):
        raise OSError
    return "resume"


def _install_under_lock() -> RootlessDockerPackageInstallationEvidence:
    identity = _root_identity()
    policy = _policy_fingerprint()
    masks = _mask_prefix()
    states = _package_states()
    phase = _phase(policy, masks, states)

    if phase == "initial":
        staged = qualify_rootless_docker_staged_preinstall()
        if type(staged) is not RootlessDockerStagedPreinstallEvidence:
            raise OSError
        static_host = (
            staged.host.expected_workflow_sha,
            staged.host.host_dependencies,
            staged.host.cgroup_controllers,
        )
        workflow = static_host[0]
        bundle = staged.bundle
    else:
        static_host = _qualify_static_host()
        workflow = static_host[0]
        bundle = qualify_rootless_docker_package_bundle()

    owned: list[int] = []
    failure = False
    control = None
    result = None
    try:
        directory, descriptors = _open_bundle(bundle, owned)

        if phase == "complete":
            _require_masks_effective()
            _require_no_runtime()
            if _qualify_static_host() != static_host:
                raise OSError
            _rehash_bundle(directory, descriptors, bundle)
            verified = qualify_rootless_docker_package_bundle()
            if verified != bundle or _root_identity() != identity:
                raise OSError
            final_states = _package_states()
            result = RootlessDockerPackageInstallationEvidence(
                "already-installed",
                workflow,
                _installed_evidence(final_states),
                INSTALLATION_AUTHORITY.rootful_units,
                bundle.staging_directory,
                tuple(item.sha256 for item in bundle.files),
            )
        else:
            _create_policy()
            masks = _mask_prefix()
            states = _package_states()
            if masks < len(INSTALLATION_AUTHORITY.rootful_units):
                if not _all_absent(states):
                    raise OSError
                _create_masks(masks)

            daemon_reload = _run((_SYSTEMCTL, "daemon-reload"))
            if daemon_reload.returncode != 0:
                raise OSError
            _require_masks_effective()
            _require_no_runtime()
            _verify_start_blockers()

            states = _package_states()
            if not _all_installed(states):
                _rehash_bundle(directory, descriptors, bundle)
                _run_dpkg(descriptors)
                _rehash_bundle(directory, descriptors, bundle)
                states = _package_states()
                if not _all_installed(states):
                    raise OSError

            if _qualify_static_host() != static_host:
                raise OSError
            _require_masks_effective()
            _require_no_runtime()
            verified = qualify_rootless_docker_package_bundle()
            if verified != bundle or _root_identity() != identity:
                raise OSError

            _remove_policy()

            if _policy_fingerprint() is not None:
                raise OSError
            _require_masks_effective()
            _require_no_runtime()
            if _qualify_static_host() != static_host:
                raise OSError
            final_states = _package_states()
            if not _all_installed(final_states):
                raise OSError
            final_bundle = qualify_rootless_docker_package_bundle()
            if final_bundle != bundle or _root_identity() != identity:
                raise OSError

            result = RootlessDockerPackageInstallationEvidence(
                "installed" if phase == "initial" else "resumed",
                workflow,
                _installed_evidence(final_states),
                INSTALLATION_AUTHORITY.rootful_units,
                final_bundle.staging_directory,
                tuple(item.sha256 for item in final_bundle.files),
            )
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        for descriptor in reversed(owned):
            try:
                os.close(descriptor)
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise OSError
    return result


def install_rootless_docker_packages() -> RootlessDockerPackageInstallationEvidence:
    """Install the exact C32ZR bundle offline under the shared mutation lock."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        result = _install_under_lock()
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
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
        raise RootlessDockerPackageInstallationError(_ERROR) from None
    return result
