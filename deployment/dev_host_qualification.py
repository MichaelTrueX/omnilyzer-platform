"""Closed, read-only C29 qualification of the future DEV host.

Qualification revalidates C17/C24/C26/C27/C28 evidence, observes the fixed C23
principals and paths, and compares installed CPython payload files with the
manifest derived from the exact C27 Debian artifacts.  It never provisions,
repairs, installs, activates, or treats package-manager metadata as file
integrity evidence.  Import and evidence construction are inert.
"""

from dataclasses import dataclass as _dataclass
import grp as _grp
import hashlib as _hashlib
import json as _json
import os as _os
import platform as _platform
import pwd as _pwd
import stat as _stat
import subprocess as _subprocess

from . import application_manifest as _c26
from . import executor_service_config as _c17
from . import host_provisioning_contract as _c23
from . import installation_integrity_contract as _c24
from . import python_interpreter_provenance as _c27
from . import wheelhouse_qualification as _c28

__all__ = (
    "HostQualificationError",
    "HostPlatformObservation",
    "HostGroupObservation",
    "HostUserObservation",
    "HostManagedPathObservation",
    "HostPackageObservation",
    "HostPayloadFileObservation",
    "HostApplicationObservation",
    "DevHostQualificationEvidence",
    "qualify_dev_host",
)

_ERROR = "DEV host qualification is unavailable"
_MODEL_ERROR = "DEV host qualification evidence is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_PAYLOAD_PATH = "provenance/python3.12-3.12.3-1ubuntu0.17-amd64-payload.json"
_PAYLOAD_SIZE = 127763
_PAYLOAD_SHA256 = "8e1b6d6a96105e0d8d38a6749768101b0d4603f9568dffbf2a247bea0ee16319"
_CHUNK = 64 * 1024
_MAX_MANAGED_FILE_BYTES = 64 * 1024


class HostQualificationError(Exception):
    """Actual host state did not satisfy the closed reviewed requirements."""


def _exact_text(value: object) -> str:
    if type(value) is not str or not value:
        raise ValueError(_MODEL_ERROR)
    return value


def _exact_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(_MODEL_ERROR)
    return value


def _digest(value: object) -> str:
    text = _exact_text(value)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(_MODEL_ERROR)
    return text


@_dataclass(frozen=True, slots=True)
class HostPlatformObservation:
    system: str
    distribution: str
    version: str
    machine: str
    archive_architecture: str
    libc: str

    def __post_init__(self) -> None:
        for value in (self.system, self.distribution, self.version, self.machine,
                      self.archive_architecture, self.libc):
            _exact_text(value)


@_dataclass(frozen=True, slots=True)
class HostGroupObservation:
    name: str
    gid: int
    state: str

    def __post_init__(self) -> None:
        _exact_text(self.name); _exact_int(self.gid)
        if self.state not in ("absent", "exact") or type(self.state) is not str:
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class HostUserObservation:
    name: str
    uid: int
    primary_gid: int
    supplementary_gids: tuple[int, ...]
    state: str

    def __post_init__(self) -> None:
        _exact_text(self.name); _exact_int(self.uid); _exact_int(self.primary_gid)
        if (type(self.supplementary_gids) is not tuple
                or any(type(value) is not int or value < 0 for value in self.supplementary_gids)
                or self.state not in ("absent", "exact") or type(self.state) is not str):
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class HostManagedPathObservation:
    path: str
    kind: str
    state: str
    mode: int
    owner_uid: int
    group_gid: int

    def __post_init__(self) -> None:
        _exact_text(self.path); _exact_text(self.kind)
        for value in (self.mode, self.owner_uid, self.group_gid): _exact_int(value)
        if self.state not in ("absent", "exact") or type(self.state) is not str:
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class HostPackageObservation:
    package: str
    version: str
    architecture: str
    status: str

    def __post_init__(self) -> None:
        for value in (self.package, self.version, self.architecture, self.status):
            _exact_text(value)
        if self.status != "installed":
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class HostPayloadFileObservation:
    package: str
    path: str
    kind: str
    mode: int
    owner_uid: int
    group_gid: int
    size: int | None
    sha256: str | None
    target: str | None

    def __post_init__(self) -> None:
        _exact_text(self.package); _exact_text(self.path); _exact_text(self.kind)
        for value in (self.mode, self.owner_uid, self.group_gid): _exact_int(value)
        if self.kind == "regular_file":
            if type(self.size) is not int or self.size < 0 or self.target is not None:
                raise ValueError(_MODEL_ERROR)
            _digest(self.sha256)
        elif self.kind == "symbolic_link":
            if self.size is not None or self.sha256 is not None or type(self.target) is not str:
                raise ValueError(_MODEL_ERROR)
        else:
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class HostApplicationObservation:
    root: str
    state: str
    reviewed_commit: str
    manifest_sha256: str

    def __post_init__(self) -> None:
        for value in (self.root, self.state, self.reviewed_commit): _exact_text(value)
        _digest(self.manifest_sha256)
        if self.state not in ("absent", "exact"):
            raise ValueError(_MODEL_ERROR)


@_dataclass(frozen=True, slots=True)
class DevHostQualificationEvidence:
    platform: HostPlatformObservation
    groups: tuple[HostGroupObservation, ...]
    users: tuple[HostUserObservation, ...]
    managed_paths: tuple[HostManagedPathObservation, ...]
    packages: tuple[HostPackageObservation, ...]
    payload_files: tuple[HostPayloadFileObservation, ...]
    application: HostApplicationObservation
    wheelhouse_path: str
    wheel_files: tuple[_c28.WheelhouseFileEvidence, ...]
    payload_manifest_sha256: str

    def __post_init__(self) -> None:
        expected = (
            (self.platform, HostPlatformObservation),
            (self.application, HostApplicationObservation),
        )
        if any(type(value) is not kind for value, kind in expected):
            raise ValueError(_MODEL_ERROR)
        collections = (
            (self.groups, HostGroupObservation), (self.users, HostUserObservation),
            (self.managed_paths, HostManagedPathObservation),
            (self.packages, HostPackageObservation),
            (self.payload_files, HostPayloadFileObservation),
            (self.wheel_files, _c28.WheelhouseFileEvidence),
        )
        if any(type(items) is not tuple or any(type(item) is not kind for item in items)
               for items, kind in collections):
            raise ValueError(_MODEL_ERROR)
        HostPlatformObservation.__post_init__(self.platform)
        HostApplicationObservation.__post_init__(self.application)
        for items, kind in collections:
            for item in items:
                kind.__post_init__(item)
        _exact_text(self.wheelhouse_path); _digest(self.payload_manifest_sha256)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _load_payload(provenance: _c27.DevPythonInterpreterProvenance) -> tuple[dict, ...]:
    path = _os.path.join(_os.path.dirname(__file__), _PAYLOAD_PATH)
    descriptor = _os.open(path, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC)
    try:
        status = _os.fstat(descriptor)
        if not _stat.S_ISREG(status.st_mode) or status.st_size != _PAYLOAD_SIZE:
            raise OSError
        raw = bytearray()
        while len(raw) <= _PAYLOAD_SIZE:
            chunk = _os.read(descriptor, min(_CHUNK, _PAYLOAD_SIZE + 1 - len(raw)))
            if type(chunk) is not bytes or len(chunk) > _CHUNK:
                raise OSError
            if not chunk: break
            raw.extend(chunk)
        if len(raw) != _PAYLOAD_SIZE or _hashlib.sha256(raw).hexdigest() != _PAYLOAD_SHA256:
            raise OSError
    finally:
        _os.close(descriptor)
    value = _json.loads(raw, object_pairs_hook=_pairs)
    if type(value) is not dict or set(value) != {"schema_version", "kind", "packages"}:
        raise ValueError
    if value["schema_version"] != 1 or value["kind"] != "debian-installed-payload-v1":
        raise ValueError
    packages = value["packages"]
    if type(packages) is not list or len(packages) != len(provenance.packages):
        raise ValueError
    entries = []
    seen = set()
    for source, reviewed in zip(packages, provenance.packages, strict=True):
        if type(source) is not dict or set(source) != {
            "package", "version", "architecture", "artifact_sha256", "entries"
        }:
            raise ValueError
        if (source["package"], source["version"], source["architecture"],
                source["artifact_sha256"]) != (
                reviewed.package, reviewed.version, reviewed.architecture, reviewed.sha256):
            raise ValueError
        records = source["entries"]
        if type(records) is not list or not records:
            raise ValueError
        previous = ""
        for record in records:
            if type(record) is not dict:
                raise ValueError
            path_value = record.get("path")
            if (type(path_value) is not str or not path_value.startswith("/")
                    or path_value <= previous or path_value in seen):
                raise ValueError
            previous = path_value; seen.add(path_value)
            kind = record.get("kind")
            required = {"path", "kind", "mode", "uid", "gid"}
            if kind == "regular_file": required |= {"size", "sha256"}
            elif kind == "symbolic_link": required |= {"target"}
            else: raise ValueError
            if set(record) != required:
                raise ValueError
            mode = int(record["mode"], 8)
            observation = HostPayloadFileObservation(
                source["package"], path_value, kind, mode, record["uid"], record["gid"],
                record.get("size"), record.get("sha256"), record.get("target"),
            )
            entries.append({"observation": observation})
    if len(entries) != 658:
        raise ValueError
    return tuple(entries)


def _platform_observation() -> HostPlatformObservation:
    uname = _os.uname()
    if type(uname) is not _os.uname_result or uname.sysname != "Linux" or uname.machine != "x86_64":
        raise OSError
    raw = _read_small_regular("/usr/lib/os-release", 16384)
    values = {}
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"): continue
        if "=" not in line: raise OSError
        key, value = line.split("=", 1)
        if key in values: raise OSError
        if len(value) >= 2 and value[0] == value[-1] == '"': value = value[1:-1]
        values[key] = value
    libc = _os.confstr("CS_GNU_LIBC_VERSION")
    if values.get("ID") != "ubuntu" or values.get("VERSION_ID") != "24.04": raise OSError
    if type(libc) is not str or not libc.startswith("glibc "): raise OSError
    return HostPlatformObservation("Linux", "Ubuntu", "24.04", "x86_64", "amd64", libc)


def _open_parent(path: str, owned: list[int]) -> tuple[int | None, str]:
    parts = path[1:].split("/")
    descriptor = _os.open("/", _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC)
    owned.append(descriptor)
    for component in parts[:-1]:
        try:
            status = _os.stat(component, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None, parts[-1]
        if not _stat.S_ISDIR(status.st_mode) or _stat.S_ISLNK(status.st_mode): raise OSError
        child = _os.open(component, _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                         dir_fd=descriptor)
        owned.append(child)
        opened = _os.fstat(child)
        if (status.st_dev, status.st_ino) != (opened.st_dev, opened.st_ino): raise OSError
        descriptor = child
    return descriptor, parts[-1]


def _fingerprint(status) -> tuple[int, ...]:
    return (status.st_mode, status.st_ino, status.st_dev, status.st_nlink,
            status.st_uid, status.st_gid, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns)


def _named_status(path: str):
    owned = []
    try:
        parent, name = _open_parent(path, owned)
        if parent is None: raise OSError
        return _os.stat(name, dir_fd=parent, follow_symlinks=False)
    finally:
        for descriptor in reversed(owned): _os.close(descriptor)


def _read_small_regular(path: str, maximum: int) -> bytes:
    owned = []
    try:
        parent, name = _open_parent(path, owned)
        if parent is None: raise OSError
        named = _os.stat(name, dir_fd=parent, follow_symlinks=False)
        fd = _os.open(name, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC, dir_fd=parent)
        owned.append(fd); opened = _os.fstat(fd)
        if (not _stat.S_ISREG(opened.st_mode) or opened.st_size < 0 or opened.st_size > maximum
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)):
            raise OSError
        data = bytearray()
        while len(data) <= maximum:
            chunk = _os.read(fd, min(_CHUNK, maximum + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
        if len(data) != opened.st_size: raise OSError
        return bytes(data)
    finally:
        for descriptor in reversed(owned): _os.close(descriptor)


def _query_packages(provenance: _c27.DevPythonInterpreterProvenance) -> tuple[HostPackageObservation, ...]:
    names = tuple(item.package for item in provenance.packages)
    process = _subprocess.run(
        ("/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\\n", *names),
        stdin=_subprocess.DEVNULL, stdout=_subprocess.PIPE, stderr=_subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        shell=False, timeout=5, check=False,
    )
    if type(process.returncode) is not int or process.returncode != 0 or type(process.stdout) is not bytes:
        raise OSError
    records = {}
    for line in process.stdout.decode("utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] in records: raise OSError
        records[fields[0]] = fields[1:]
    observations = []
    for expected in provenance.packages:
        if records.get(expected.package) != [expected.version, expected.architecture, "ii "]:
            raise OSError
        observations.append(HostPackageObservation(expected.package, expected.version,
                                                   expected.architecture, "installed"))
    if set(records) != set(names): raise OSError
    return tuple(observations)


def _observe_principals(contract: _c23.DevHostProvisioningContract):
    groups = []
    for expected in contract.group_requirements():
        try: by_name = _grp.getgrnam(expected.name)
        except KeyError: by_name = None
        try: by_id = _grp.getgrgid(expected.gid)
        except KeyError: by_id = None
        if by_name is None and by_id is None:
            groups.append(HostGroupObservation(expected.name, expected.gid, "absent")); continue
        if by_name is None or by_id is None or by_name.gr_gid != expected.gid or by_id.gr_name != expected.name:
            raise OSError
        groups.append(HostGroupObservation(expected.name, expected.gid, "exact"))
    users = []
    for expected in contract.user_requirements():
        try: by_name = _pwd.getpwnam(expected.name)
        except KeyError: by_name = None
        try: by_id = _pwd.getpwuid(expected.uid)
        except KeyError: by_id = None
        if by_name is None and by_id is None:
            users.append(HostUserObservation(expected.name, expected.uid, expected.primary_gid,
                                             expected.supplementary_gids, "absent")); continue
        if (by_name is None or by_id is None or by_name.pw_uid != expected.uid
                or by_id.pw_name != expected.name or by_name.pw_gid != expected.primary_gid):
            raise OSError
        actual = tuple(sorted(set(_os.getgrouplist(expected.name, expected.primary_gid))
                              - {expected.primary_gid}))
        if actual != tuple(sorted(expected.supplementary_gids)): raise OSError
        users.append(HostUserObservation(expected.name, expected.uid, expected.primary_gid,
                                         actual, "exact"))
    return tuple(groups), tuple(users)


def _kind_matches(mode: int, kind: str) -> bool:
    return ((kind == "directory" and _stat.S_ISDIR(mode))
            or (kind in ("regular_file", "sqlite_database") and _stat.S_ISREG(mode))
            or (kind == "unix_socket" and _stat.S_ISSOCK(mode)))


def _observe_managed_path(path: str, kind: str, mode: int, uid: int, gid: int,
                          expected_bytes: bytes | None = None,
                          expected_sha256: str | None = None) -> HostManagedPathObservation:
    owned = []
    try:
        if expected_sha256 is not None:
            if expected_bytes is not None or kind != "regular_file": raise OSError
            try: _digest(expected_sha256)
            except Exception: raise OSError from None
        parent, name = _open_parent(path, owned)
        if parent is None:
            return HostManagedPathObservation(path, kind, "absent", mode, uid, gid)
        try: named = _os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return HostManagedPathObservation(path, kind, "absent", mode, uid, gid)
        if (_stat.S_ISLNK(named.st_mode) or not _kind_matches(named.st_mode, kind)
                or _stat.S_IMODE(named.st_mode) != mode or named.st_uid != uid or named.st_gid != gid):
            raise OSError
        if kind != "unix_socket":
            flags = _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC
            if kind == "directory": flags |= _os.O_DIRECTORY
            descriptor = _os.open(name, flags, dir_fd=parent); owned.append(descriptor)
            opened = _os.fstat(descriptor)
            if _fingerprint(named) != _fingerprint(opened): raise OSError
            if expected_bytes is not None:
                data = bytearray()
                while len(data) <= len(expected_bytes):
                    chunk = _os.read(descriptor, min(_CHUNK, len(expected_bytes) + 1 - len(data)))
                    if not chunk: break
                    data.extend(chunk)
                if bytes(data) != expected_bytes: raise OSError
            elif expected_sha256 is not None:
                if opened.st_size < 0 or opened.st_size > _MAX_MANAGED_FILE_BYTES: raise OSError
                digest = _hashlib.sha256(); remaining = opened.st_size
                while remaining:
                    chunk = _os.read(descriptor, min(_CHUNK, remaining))
                    if not chunk: raise OSError
                    digest.update(chunk); remaining -= len(chunk)
                if _os.read(descriptor, 1) != b"" or digest.hexdigest() != expected_sha256:
                    raise OSError
            if _fingerprint(_os.fstat(descriptor)) != _fingerprint(opened): raise OSError
        if _fingerprint(_named_status(path)) != _fingerprint(named): raise OSError
        return HostManagedPathObservation(path, kind, "exact", mode, uid, gid)
    finally:
        for descriptor in reversed(owned): _os.close(descriptor)


def _observe_paths(contract: _c23.DevHostProvisioningContract, configuration):
    if type(contract) is not _c23.DevHostProvisioningContract: raise OSError
    _c23.DevHostProvisioningContract.__post_init__(contract)
    observations = []
    config_path = "/etc/omnilyzer/deployment/dev/executor.json"
    for item in (*contract.path_requirements(), *contract.runtime_resource_requirements()):
        expected = configuration.canonical_bytes() if item.path == config_path else None
        observation = _observe_managed_path(item.path, item.kind, item.mode,
                                            item.owner_uid, item.group_gid, expected)
        observations.append(observation)
        if (item.path == contract.service_layout().virtualenv_root
                and observation.state == "exact"):
            owned = []
            try:
                parent, name = _open_parent(item.path, owned)
                descriptor = _os.open(name, _os.O_RDONLY | _os.O_DIRECTORY
                                      | _os.O_NOFOLLOW | _os.O_CLOEXEC, dir_fd=parent)
                owned.append(descriptor)
                with _os.scandir(descriptor) as iterator:
                    if any(True for _entry in iterator): raise OSError
            finally:
                for descriptor in reversed(owned): _os.close(descriptor)
    for asset in contract.installed_asset_requirements():
        observations.append(_observe_managed_path(asset.destination_path, "regular_file", asset.mode,
                                                  asset.owner_uid, asset.group_gid,
                                                  expected_sha256=asset.sha256))
    return tuple(observations)


def _observe_payload(entries: tuple[dict, ...]) -> tuple[HostPayloadFileObservation, ...]:
    result = []
    for wrapped in entries:
        expected = wrapped["observation"]; owned = []
        try:
            parent, name = _open_parent(expected.path, owned)
            if parent is None: raise OSError
            named = _os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (_stat.S_IMODE(named.st_mode) != expected.mode or named.st_uid != expected.owner_uid
                    or named.st_gid != expected.group_gid): raise OSError
            if expected.kind == "symbolic_link":
                if not _stat.S_ISLNK(named.st_mode): raise OSError
                if _os.readlink(name, dir_fd=parent) != expected.target: raise OSError
            else:
                if not _stat.S_ISREG(named.st_mode) or _stat.S_ISLNK(named.st_mode): raise OSError
                descriptor = _os.open(name, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                                      dir_fd=parent); owned.append(descriptor)
                opened = _os.fstat(descriptor)
                if ((named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                        or opened.st_size != expected.size): raise OSError
                digest = _hashlib.sha256(); remaining = expected.size
                while remaining:
                    chunk = _os.read(descriptor, min(_CHUNK, remaining))
                    if not chunk: raise OSError
                    digest.update(chunk); remaining -= len(chunk)
                if _os.read(descriptor, 1) != b"" or digest.hexdigest() != expected.sha256:
                    raise OSError
                current = _os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _fingerprint(current) != _fingerprint(opened):
                    raise OSError
            if _fingerprint(_named_status(expected.path)) != _fingerprint(named): raise OSError
            result.append(expected)
        finally:
            for descriptor in reversed(owned): _os.close(descriptor)
    return tuple(result)


def _observe_application(manifest: _c26.DevApplicationManifest,
                         requirement: _c24.ApplicationIntegrityRequirement,
                         root_requirement: _c23.HostPathRequirement) -> HostApplicationObservation:
    digest = _hashlib.sha256(manifest.canonical_bytes()).hexdigest()
    if (root_requirement.path != requirement.root or root_requirement.kind != "directory"
            or root_requirement.lifecycle != "must-contain-reviewed-application-before-activation"):
        raise OSError
    owned = []
    try:
        parent, name = _open_parent(requirement.root, owned)
        if parent is None:
            return HostApplicationObservation(requirement.root, "absent", manifest.reviewed_commit, digest)
        try: status = _os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return HostApplicationObservation(requirement.root, "absent", manifest.reviewed_commit, digest)
        if (not _stat.S_ISDIR(status.st_mode) or _stat.S_ISLNK(status.st_mode)
                or _stat.S_IMODE(status.st_mode) != root_requirement.mode
                or status.st_uid != root_requirement.owner_uid
                or status.st_gid != root_requirement.group_gid):
            raise OSError
        root_fd = _os.open(name, _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                           dir_fd=parent)
        owned.append(root_fd)
        if _fingerprint(_os.fstat(root_fd)) != _fingerprint(status): raise OSError
        expected = {entry.path: entry for entry in manifest.entries}
        prefixes = {part for path in expected for part in
                    ("/".join(path.split("/")[:index]) for index in range(1, len(path.split("/"))))}
        found = set()

        def scan(directory_fd: int, prefix: str) -> bool:
            with _os.scandir(directory_fd) as iterator:
                names = tuple(sorted(entry.name for entry in iterator))
            for child_name in names:
                if type(child_name) is not str or child_name in ("", ".", ".."): raise OSError
                relative = child_name if not prefix else prefix + "/" + child_name
                child_status = _os.stat(child_name, dir_fd=directory_fd, follow_symlinks=False)
                if _stat.S_ISDIR(child_status.st_mode) and not _stat.S_ISLNK(child_status.st_mode):
                    if (relative not in prefixes
                            or _stat.S_IMODE(child_status.st_mode) != root_requirement.mode
                            or child_status.st_uid != root_requirement.owner_uid
                            or child_status.st_gid != root_requirement.group_gid):
                        raise OSError
                    child_fd = _os.open(child_name, _os.O_RDONLY | _os.O_DIRECTORY
                                        | _os.O_NOFOLLOW | _os.O_CLOEXEC, dir_fd=directory_fd)
                    owned.append(child_fd)
                    if _fingerprint(_os.fstat(child_fd)) != _fingerprint(child_status): raise OSError
                    scan(child_fd, relative)
                    current = _os.stat(child_name, dir_fd=directory_fd, follow_symlinks=False)
                    if _fingerprint(current) != _fingerprint(child_status): raise OSError
                else:
                    entry = expected.get(relative)
                    if entry is None or not _stat.S_ISREG(child_status.st_mode) or _stat.S_ISLNK(child_status.st_mode):
                        raise OSError
                    if (_stat.S_IMODE(child_status.st_mode) != int(entry.mode, 8)
                            or child_status.st_uid != root_requirement.owner_uid
                            or child_status.st_gid != root_requirement.group_gid):
                        raise OSError
                    child_fd = _os.open(child_name, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                                        dir_fd=directory_fd)
                    owned.append(child_fd)
                    opened = _os.fstat(child_fd)
                    if _fingerprint(opened) != _fingerprint(child_status) or opened.st_size > 1024 * 1024:
                        raise OSError
                    file_digest = _hashlib.sha256(); remaining = opened.st_size
                    while remaining:
                        chunk = _os.read(child_fd, min(_CHUNK, remaining))
                        if not chunk: raise OSError
                        file_digest.update(chunk); remaining -= len(chunk)
                    if _os.read(child_fd, 1) != b"" or file_digest.hexdigest() != entry.sha256:
                        raise OSError
                    current = _os.stat(child_name, dir_fd=directory_fd, follow_symlinks=False)
                    if _fingerprint(current) != _fingerprint(opened): raise OSError
                    found.add(relative)
            return bool(names)

        root_nonempty = scan(root_fd, "")
        if _fingerprint(_named_status(requirement.root)) != _fingerprint(status):
            raise OSError
        if not root_nonempty:
            return HostApplicationObservation(requirement.root, "absent", manifest.reviewed_commit, digest)
        if found != set(expected): raise OSError
        return HostApplicationObservation(requirement.root, "exact", manifest.reviewed_commit, digest)
    finally:
        for descriptor in reversed(owned): _os.close(descriptor)


def qualify_dev_host(*, configuration: _c17.DevExecutorServiceConfiguration,
                     application_manifest: _c26.DevApplicationManifest,
                     wheelhouse_evidence: _c28.DevWheelhouseEvidence) -> DevHostQualificationEvidence:
    """Return immutable observations or one fixed error; never mutate the host."""
    try:
        if type(configuration) is not _c17.DevExecutorServiceConfiguration: raise ValueError
        integrity = _c24.DevInstallationIntegrityContract(configuration=configuration)
        application_requirement = integrity.application_requirement()
        environment = integrity.python_environment_requirement()
        if type(application_manifest) is not _c26.DevApplicationManifest: raise ValueError
        _c26.DevApplicationManifest.__post_init__(application_manifest)
        if application_manifest.reviewed_commit != configuration.reviewed_commit: raise ValueError
        if type(wheelhouse_evidence) is not _c28.DevWheelhouseEvidence: raise ValueError
        _c28.DevWheelhouseEvidence.__post_init__(wheelhouse_evidence, environment)
        provenance = _c27.DevPythonInterpreterProvenance()
        _c27.DevPythonInterpreterProvenance.__post_init__(provenance)
        if (provenance.implementation, provenance.python_series, provenance.operating_system,
                provenance.distribution, provenance.architecture, provenance.libc) != (
                environment.implementation, environment.python_series, environment.operating_system,
                environment.distribution, environment.architecture, environment.libc): raise ValueError
        provisioning = _c23.DevHostProvisioningContract(installation=configuration.installation_contract())
        application_paths = tuple(item for item in provisioning.path_requirements()
                                  if item.path == application_requirement.root)
        if len(application_paths) != 1: raise ValueError
        application_path = application_paths[0]
        payload = _load_payload(provenance)
        platform = _platform_observation()
        packages = _query_packages(provenance)
        payload_files = _observe_payload(payload)
        groups, users = _observe_principals(provisioning)
        paths = _observe_paths(provisioning, configuration)
        application = _observe_application(application_manifest, application_requirement,
                                            application_path)
        return DevHostQualificationEvidence(
            platform, groups, users, paths, packages, payload_files, application,
            wheelhouse_evidence.wheelhouse_path, wheelhouse_evidence.files, _PAYLOAD_SHA256,
        )
    except _CONTROL:
        raise
    except Exception:
        raise HostQualificationError(_ERROR) from None
