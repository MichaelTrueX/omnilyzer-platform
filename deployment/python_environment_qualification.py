"""Closed read-only C31A qualification of the populated DEV Python venv.

The retained manifest was derived from the exact C24 wheels installed by the
exact C31P pip wheel with the reviewed command contract.  This boundary is
separate from C29's pre-provision qualification and never installs, repairs or
removes anything.
"""

from dataclasses import dataclass as _dataclass, field as _field
import hashlib as _hashlib
import json as _json
import os as _os
import stat as _stat

from . import executor_service_config as _c17
from . import host_provisioning_contract as _c23
from . import installation_integrity_contract as _c24
from . import pip_installer_provenance as _c31p
from . import python_interpreter_provenance as _c27

__all__ = (
    "PythonEnvironmentQualificationError",
    "PythonDistributionEvidence",
    "DevPythonEnvironmentEvidence",
    "qualify_dev_python_environment",
)

_ERROR = "DEV Python environment qualification is unavailable"
_MODEL_ERROR = "DEV Python environment qualification evidence is invalid"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_CHUNK = 64 * 1024
_MANIFEST_PATH = "provenance/python-runtime-py312-linux-x86_64-installed.json"
_MANIFEST_SIZE = 57824
_MANIFEST_SHA256 = "3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b"
_ENTRY_COUNT = 237
_FILE_COUNT = 197
_DIRECTORY_COUNT = 36
_SYMLINK_COUNT = 4
_ROOT = "/opt/omnilyzer/deployment/venv"
_PYTHON = _ROOT + "/bin/python"
_SYSTEM_PYTHON = "/usr/bin/python3.12"
_SITE_PACKAGES = "lib/python3.12/site-packages"
_DISTRIBUTIONS = (
    ("cffi", "2.1.1", "cffi-2.1.1.dist-info"),
    ("cryptography", "50.0.1", "cryptography-50.0.1.dist-info"),
    ("pycparser", "3.0", "pycparser-3.0.dist-info"),
    ("PyJWT", "2.13.0", "pyjwt-2.13.0.dist-info"),
)
_SOURCES = {
    "venv", "wheel-layout", "pip-generated-metadata", "pip-generated-script",
}
_SOURCE_COUNTS = {
    "venv": 15,
    "wheel-layout": 30,
    "pip-generated-metadata": 12,
    "pip-generated-script": 1,
    "pyjwt-2.13.0-py3-none-any.whl": 18,
    "cryptography-50.0.1-cp311-abi3-manylinux_2_34_x86_64.whl": 119,
    "cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl": 30,
    "pycparser-3.0-py3-none-any.whl": 12,
}


class PythonEnvironmentQualificationError(Exception):
    """The fixed populated venv did not match the reviewed C31A model."""


def _text(value: object) -> str:
    if type(value) is not str or not value:
        raise ValueError(_MODEL_ERROR)
    return value


def _digest(value: object) -> str:
    text = _text(value)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(_MODEL_ERROR)
    return text


def _close(owned: list[int]) -> tuple[bool, BaseException | None]:
    """Close every descriptor once and retain cleanup/control failure state."""
    failed = False
    control: BaseException | None = None
    for descriptor in reversed(owned):
        try:
            if _os.close(descriptor) is not None:
                failed = True
        except _CONTROL as exc:
            if control is None:
                control = exc
        except Exception:
            failed = True
    owned.clear()
    return failed, control


@_dataclass(frozen=True, slots=True)
class PythonDistributionEvidence:
    """One exact installed runtime distribution identity."""

    name: str
    version: str
    dist_info: str

    def __post_init__(self) -> None:
        if (
            any(type(value) is not str for value in (self.name, self.version, self.dist_info))
            or (self.name, self.version, self.dist_info) not in _DISTRIBUTIONS
        ):
            raise ValueError(_MODEL_ERROR)


_DISTRIBUTION_EVIDENCE = tuple(PythonDistributionEvidence(*item) for item in _DISTRIBUTIONS)


@_dataclass(frozen=True, slots=True)
class DevPythonEnvironmentEvidence:
    """Immutable aggregate observation of the exact reviewed populated tree."""

    root: str = _field(init=False, default=_ROOT)
    python_executable: str = _field(init=False, default=_PYTHON)
    system_python_target: str = _field(init=False, default=_SYSTEM_PYTHON)
    implementation: str = _field(init=False, default="CPython")
    python_series: str = _field(init=False, default="3.12")
    site_packages: str = _field(init=False, default=_SITE_PACKAGES)
    distributions: tuple[PythonDistributionEvidence, ...] = _field(
        init=False, default=_DISTRIBUTION_EVIDENCE,
    )
    regular_file_count: int = _field(init=False, default=_FILE_COUNT)
    directory_count: int = _field(init=False, default=_DIRECTORY_COUNT)
    symbolic_link_count: int = _field(init=False, default=_SYMLINK_COUNT)
    payload_manifest_sha256: str = _field(init=False, default=_MANIFEST_SHA256)

    def __post_init__(self) -> None:
        expected = (
            (self.root, _ROOT),
            (self.python_executable, _PYTHON),
            (self.system_python_target, _SYSTEM_PYTHON),
            (self.implementation, "CPython"),
            (self.python_series, "3.12"),
            (self.site_packages, _SITE_PACKAGES),
            (self.distributions, _DISTRIBUTION_EVIDENCE),
            (self.regular_file_count, _FILE_COUNT),
            (self.directory_count, _DIRECTORY_COUNT),
            (self.symbolic_link_count, _SYMLINK_COUNT),
            (self.payload_manifest_sha256, _MANIFEST_SHA256),
        )
        for actual, required in expected:
            if type(actual) is not type(required) or actual != required:
                raise ValueError(_MODEL_ERROR)
        for value in self.distributions:
            if type(value) is not PythonDistributionEvidence:
                raise ValueError(_MODEL_ERROR)
            PythonDistributionEvidence.__post_init__(value)


def _pairs(pairs: list[tuple[object, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _repository_manifest() -> bytes:
    path = _os.path.dirname(__file__) + "/" + _MANIFEST_PATH
    descriptor = _os.open(
        path,
        _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC | _os.O_NONBLOCK,
    )
    owned = [descriptor]
    try:
        named = _os.stat(path, follow_symlinks=False)
        opened = _os.fstat(descriptor)
        if (
            not _stat.S_ISREG(named.st_mode)
            or _stat.S_ISLNK(named.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size != _MANIFEST_SIZE
        ):
            raise OSError
        raw = bytearray()
        remaining = _MANIFEST_SIZE
        while remaining:
            chunk = _os.read(descriptor, min(_CHUNK, remaining))
            if type(chunk) is not bytes or not chunk:
                raise OSError
            raw.extend(chunk)
            remaining -= len(chunk)
        if _os.read(descriptor, 1) != b"":
            raise OSError
        current = _os.fstat(descriptor)
        rebound = _os.stat(path, follow_symlinks=False)
        fingerprint = lambda value: (
            value.st_mode, value.st_ino, value.st_dev, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if fingerprint(current) != fingerprint(opened) or fingerprint(rebound) != fingerprint(opened):
            raise OSError
        result = bytes(raw)
        if _hashlib.sha256(result).hexdigest() != _MANIFEST_SHA256:
            raise OSError
    except _CONTROL:
        _close(owned)
        raise
    except Exception:
        _failed, cleanup_control = _close(owned)
        if cleanup_control is not None:
            raise cleanup_control
        raise
    cleanup_failed, cleanup_control = _close(owned)
    if cleanup_control is not None:
        raise cleanup_control
    if cleanup_failed:
        raise OSError
    return result


def _relative_path(value: object) -> str:
    path = _text(value)
    if (
        path.startswith("/")
        or "\\" in path
        or "\0" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise ValueError
    return path


def _load_manifest(
    environment: _c24.PythonEnvironmentIntegrityRequirement,
    installer: _c31p.DevPipInstallerProvenance,
) -> tuple[dict, ...]:
    value = _json.loads(_repository_manifest(), object_pairs_hook=_pairs)
    if type(value) is not dict or set(value) != {
        "schema_version", "root", "system_python", "python_executable",
        "site_packages", "venv_command", "pyvenv", "installer", "wheels",
        "distributions", "entries",
    }:
        raise ValueError
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["root"] != environment.root
        or value["root"] != _ROOT
        or value["system_python"] != _SYSTEM_PYTHON
        or value["python_executable"] != environment.python_executable
        or value["python_executable"] != _PYTHON
        or value["site_packages"] != _SITE_PACKAGES
        or value["venv_command"] != [
            _SYSTEM_PYTHON, "-m", "venv", "--without-pip", _ROOT,
        ]
    ):
        raise ValueError
    if value["pyvenv"] != {
        "home": "/usr/bin",
        "include-system-site-packages": "false",
        "version": "3.12.3",
        "executable": _SYSTEM_PYTHON,
        "command": _SYSTEM_PYTHON + " -m venv --without-pip " + _ROOT,
    }:
        raise ValueError
    if value["installer"] != {
        "filename": installer.artifact.filename,
        "sha256": installer.artifact.sha256,
        "version": installer.artifact.version,
    }:
        raise ValueError
    if value["wheels"] != [
        {"filename": wheel.filename, "sha256": wheel.sha256}
        for wheel in environment.wheels
    ]:
        raise ValueError
    if value["distributions"] != [
        {"name": name, "version": version, "dist_info": dist_info}
        for name, version, dist_info in _DISTRIBUTIONS
    ]:
        raise ValueError
    records = value["entries"]
    if type(records) is not list or len(records) != _ENTRY_COUNT:
        raise ValueError
    allowed_sources = _SOURCES | {wheel.filename for wheel in environment.wheels}
    entries = []
    previous = ""
    sources: dict[str, int] = {}
    kinds = {"regular_file": 0, "directory": 0, "symbolic_link": 0}
    for record in records:
        if type(record) is not dict:
            raise ValueError
        path = _relative_path(record.get("path"))
        if path <= previous or path.endswith(".pyc") or "__pycache__" in path.split("/"):
            raise ValueError
        previous = path
        kind = record.get("kind")
        source = record.get("source")
        mode = record.get("mode")
        if kind not in kinds or type(source) is not str or source not in allowed_sources:
            raise ValueError
        if type(mode) is not str or mode not in ("0644", "0755", "0777"):
            raise ValueError
        required = {"path", "kind", "mode", "source"}
        if kind == "regular_file":
            required |= {"size", "sha256"}
            if (
                type(record.get("size")) is not int
                or record["size"] < 0
                or record["size"] > 32 * 1024 * 1024
                or mode not in ("0644", "0755")
            ):
                raise ValueError
            _digest(record.get("sha256"))
        elif kind == "directory":
            if mode != "0755":
                raise ValueError
        else:
            required |= {"target"}
            if type(record.get("target")) is not str or not record["target"] or mode != "0777":
                raise ValueError
        if set(record) != required:
            raise ValueError
        kinds[kind] += 1
        sources[source] = sources.get(source, 0) + 1
        entries.append(record)
    if kinds != {
        "regular_file": _FILE_COUNT,
        "directory": _DIRECTORY_COUNT,
        "symbolic_link": _SYMLINK_COUNT,
    } or sources != _SOURCE_COUNTS:
        raise ValueError
    by_path = {entry["path"]: entry for entry in entries}
    if len(by_path) != len(entries):
        raise ValueError
    required_links = {
        "bin/python": "python3.12",
        "bin/python3": "python3.12",
        "bin/python3.12": _SYSTEM_PYTHON,
        "lib64": "lib",
    }
    if {
        path: by_path[path].get("target") for path in required_links
    } != required_links:
        raise ValueError
    generated = [entry for entry in entries if entry["source"] == "pip-generated-metadata"]
    for suffix, count in (("/INSTALLER", 4), ("/REQUESTED", 4), ("/RECORD", 4)):
        if sum(entry["path"].endswith(suffix) for entry in generated) != count:
            raise ValueError
    for entry in generated:
        if entry["path"].endswith("/INSTALLER") and (
            entry["size"] != 4
            or entry["sha256"] != "ceebae7b8927a3227e5303cf5e0f1f7b34bb542ad7250ac03fbcde36ec2f1508"
        ):
            raise ValueError
        if entry["path"].endswith("/REQUESTED") and (
            entry["size"] != 0
            or entry["sha256"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ):
            raise ValueError
    script = by_path.get("bin/cffi-gen-src")
    if script is None or script.get("source") != "pip-generated-script" or script.get("mode") != "0755":
        raise ValueError
    for _name, _version, dist_info in _DISTRIBUTIONS:
        prefix = _SITE_PACKAGES + "/" + dist_info + "/"
        if not all(prefix + leaf in by_path for leaf in ("METADATA", "RECORD", "INSTALLER", "REQUESTED")):
            raise ValueError
    if any("pip-" in path.lower() and ".dist-info" in path.lower() for path in by_path):
        raise ValueError
    return tuple(entries)


def _metadata(value: _os.stat_result) -> tuple[int, ...]:
    if type(value) is not _os.stat_result:
        raise OSError
    return (
        value.st_mode, value.st_ino, value.st_dev, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _hash_file(descriptor: int, size: int) -> str:
    digest = _hashlib.sha256()
    remaining = size
    while remaining:
        maximum = min(_CHUNK, remaining)
        chunk = _os.read(descriptor, maximum)
        if type(chunk) is not bytes or not chunk or len(chunk) > maximum:
            raise OSError
        digest.update(chunk)
        remaining -= len(chunk)
    if _os.read(descriptor, 1) != b"":
        raise OSError
    return digest.hexdigest()


def _open_root(
    path: str, owner_uid: int, group_gid: int, owned: list[int],
) -> tuple[int, list[tuple[int | None, str, int, tuple[int, ...]]]]:
    flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC
    if (
        type(path) is not str
        or not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or "\0" in path
        or any(part in ("", ".", "..") for part in path[1:].split("/"))
    ):
        raise OSError
    root_named = _os.stat("/", follow_symlinks=False)
    parent = _os.open("/", flags)
    owned.append(parent)
    root_opened = _os.fstat(parent)
    if _metadata(root_opened) != _metadata(root_named):
        raise OSError
    chain: list[tuple[int | None, str, int, tuple[int, ...]]] = [
        (None, "/", parent, _metadata(root_opened)),
    ]
    components = path[1:].split("/")
    for index, component in enumerate(components):
        named = _os.stat(component, dir_fd=parent, follow_symlinks=False)
        child = _os.open(component, flags, dir_fd=parent)
        owned.append(child)
        opened = _os.fstat(child)
        if (
            not _stat.S_ISDIR(opened.st_mode)
            or _stat.S_ISLNK(opened.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise OSError
        mode = _stat.S_IMODE(opened.st_mode)
        if index == len(components) - 1:
            if mode != 0o755 or opened.st_uid != owner_uid or opened.st_gid != group_gid:
                raise OSError
        elif mode & 0o022 and not (opened.st_uid == 0 and mode & _stat.S_ISVTX):
            raise OSError
        chain.append((parent, component, child, _metadata(opened)))
        parent = child
    return parent, chain


def _revalidate_chain(
    chain: list[tuple[int | None, str, int, tuple[int, ...]]],
) -> None:
    for parent, name, descriptor, expected in chain:
        if _metadata(_os.fstat(descriptor)) != expected:
            raise OSError
        named = (
            _os.stat("/", follow_symlinks=False)
            if parent is None
            else _os.stat(name, dir_fd=parent, follow_symlinks=False)
        )
        if _metadata(named) != expected:
            raise OSError


def _observe_tree(path: str, entries: tuple[dict, ...], owner_uid: int, group_gid: int) -> None:
    expected = {entry["path"]: entry for entry in entries}
    if len(expected) != len(entries):
        raise OSError
    owned: list[int] = []
    found = set()
    try:
        root, chain = _open_root(path, owner_uid, group_gid, owned)

        def scan(directory: int, prefix: str) -> None:
            with _os.scandir(directory) as iterator:
                names = tuple(sorted(entry.name for entry in iterator))
            for name in names:
                if type(name) is not str or not name or "/" in name or "\0" in name:
                    raise OSError
                relative = name if not prefix else prefix + "/" + name
                requirement = expected.get(relative)
                if requirement is None or relative in found:
                    raise OSError
                named = _os.stat(name, dir_fd=directory, follow_symlinks=False)
                if named.st_uid != owner_uid or named.st_gid != group_gid:
                    raise OSError
                mode = _stat.S_IMODE(named.st_mode)
                if mode != int(requirement["mode"], 8):
                    raise OSError
                kind = requirement["kind"]
                if kind == "directory":
                    if not _stat.S_ISDIR(named.st_mode) or _stat.S_ISLNK(named.st_mode):
                        raise OSError
                    child = _os.open(
                        name,
                        _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                    owned.append(child)
                    opened = _os.fstat(child)
                    if _metadata(opened) != _metadata(named):
                        raise OSError
                    found.add(relative)
                    scan(child, relative)
                    if _metadata(_os.fstat(child)) != _metadata(opened):
                        raise OSError
                    if _metadata(_os.stat(name, dir_fd=directory, follow_symlinks=False)) != _metadata(opened):
                        raise OSError
                elif kind == "regular_file":
                    if (
                        not _stat.S_ISREG(named.st_mode)
                        or _stat.S_ISLNK(named.st_mode)
                        or named.st_nlink != 1
                        or named.st_size != requirement["size"]
                    ):
                        raise OSError
                    descriptor = _os.open(
                        name,
                        _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC
                        | _os.O_NONBLOCK,
                        dir_fd=directory,
                    )
                    owned.append(descriptor)
                    opened = _os.fstat(descriptor)
                    if _metadata(opened) != _metadata(named):
                        raise OSError
                    if _hash_file(descriptor, opened.st_size) != requirement["sha256"]:
                        raise OSError
                    if _metadata(_os.fstat(descriptor)) != _metadata(opened):
                        raise OSError
                    if _metadata(_os.stat(name, dir_fd=directory, follow_symlinks=False)) != _metadata(opened):
                        raise OSError
                    found.add(relative)
                elif kind == "symbolic_link":
                    if not _stat.S_ISLNK(named.st_mode):
                        raise OSError
                    target = _os.readlink(name, dir_fd=directory)
                    rebound = _os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if target != requirement["target"] or _metadata(rebound) != _metadata(named):
                        raise OSError
                    found.add(relative)
                else:
                    raise OSError

        scan(root, "")
        if found != set(expected):
            raise OSError
        _revalidate_chain(chain)
    except _CONTROL:
        _close(owned)
        raise
    except Exception:
        _failed, cleanup_control = _close(owned)
        if cleanup_control is not None:
            raise cleanup_control
        raise
    cleanup_failed, cleanup_control = _close(owned)
    if cleanup_control is not None:
        raise cleanup_control
    if cleanup_failed:
        raise OSError


def qualify_dev_python_environment(
    *, configuration: _c17.DevExecutorServiceConfiguration,
) -> DevPythonEnvironmentEvidence:
    """Read and compare the fixed populated venv with retained reviewed evidence."""
    try:
        if type(configuration) is not _c17.DevExecutorServiceConfiguration:
            raise ValueError
        integrity = _c24.DevInstallationIntegrityContract(configuration=configuration)
        environment = integrity.python_environment_requirement()
        provisioning = _c23.DevHostProvisioningContract(
            installation=configuration.installation_contract(),
        )
        roots = tuple(
            requirement for requirement in provisioning.path_requirements()
            if requirement.path == environment.root
        )
        interpreter = _c27.DevPythonInterpreterProvenance()
        _c27.DevPythonInterpreterProvenance.__post_init__(interpreter)
        installer = _c31p.DevPipInstallerProvenance()
        _c31p.DevPipInstallerProvenance.__post_init__(installer)
        if (
            environment.root != _ROOT
            or environment.python_executable != _PYTHON
            or len(roots) != 1
            or roots[0].kind != "directory"
            or roots[0].mode != 0o755
            or interpreter.implementation != environment.implementation
            or interpreter.python_series != environment.python_series
        ):
            raise ValueError
        entries = _load_manifest(environment, installer)
        _observe_tree(_ROOT, entries, roots[0].owner_uid, roots[0].group_gid)
        return DevPythonEnvironmentEvidence()
    except _CONTROL:
        raise
    except Exception:
        raise PythonEnvironmentQualificationError(_ERROR) from None
