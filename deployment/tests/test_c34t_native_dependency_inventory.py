"""File: deployment/tests/test_c34t_native_dependency_inventory.py

Purpose: Read-only transitive ELF DT_NEEDED inventory of existing C27 Python
and C31A native wheels, without loading inspected binaries or granting root.
Related: deployment/dev_host_qualification.py,
deployment/python_environment_qualification.py,
deployment/c34r_installed_python_observation.py,
docs/operations/task014-c34t-native-dependency-inventory.md.

Normal CI tests are offline. Set OMNILYZER_C34T_HOST_READONLY=1 to
explicitly run the nonprivileged host audit. This is observation only, not
signed external-package qualification or privileged execution.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deployment import dev_host_qualification as c29
from deployment import python_environment_qualification as c31
from deployment import python_interpreter_provenance as c27
from deployment import c34r_installed_python_observation as c34r
from deployment.tests.test_executor_service_config import make_configuration

# Section 1: Fixed observation envelope, not a new authority source.
_ERROR = "C34T native dependency inventory unavailable"
_NAMES = tuple(sorted((
    "ld-linux-x86-64.so.2", "libbz2.so.1.0", "libc.so.6",
    "libcrypt.so.1", "libcrypto.so.3", "libdb-5.3.so",
    "libexpat.so.1", "libffi.so.8", "libgcc_s.so.1",
    "liblzma.so.5", "libm.so.6", "libncursesw.so.6",
    "libpanelw.so.6", "libpthread.so.0", "libreadline.so.8",
    "libsqlite3.so.0", "libssl.so.3", "libtinfo.so.6", "libz.so.1",
)))
_WHEEL_EXTENSIONS = (
    "lib/python3.12/site-packages/_cffi_backend.cpython-312-x86_64-linux-gnu.so",
    "lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so",
)
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class NativeAuditHold(Exception):
    """Expose only a fixed nonsecret failure response."""


@dataclass(frozen=True, slots=True)
class StaticNativeReceipt:
    """Immutable observation, with hardcoded FALSE privilege/authority flags."""
    roots: int
    objects: int
    needed: tuple[str, ...]
    packages: tuple[str, ...]
    installed_bytes_observed: bool
    signed_external_packages: bool = False
    sealed_root_imports: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Reject forged authorization or incomplete expected static inventory."""
        if (
            type(self.roots) is not int or self.roots != 49
            or type(self.objects) is not int or self.objects != 68
            or self.needed != _NAMES or type(self.needed) is not tuple
            or type(self.packages) is not tuple
            or len(self.packages) != 14
            or self.packages != tuple(sorted(set(self.packages)))
            or self.installed_bytes_observed is not True
            or self.signed_external_packages is not False
            or self.sealed_root_imports is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


# Section 2: Strict static ELF and ldconfig parsing.
def _needed(text: str) -> tuple[str, ...]:
    """Parse DT_NEEDED, rejecting altered search paths and malformed names."""
    if type(text) is not str or "Dynamic section" not in text:
        raise ValueError(_ERROR)
    if re.search(r"\((?:RUNPATH|RPATH|AUDIT|DEPAUDIT|FILTER|AUXILIARY)\)", text):
        raise ValueError(_ERROR)
    found = tuple(re.findall(
        r"\(NEEDED\)\s+Shared library: \[([A-Za-z0-9+._-]+)\]", text,
    ))
    if len(found) != text.count("(NEEDED)") or len(set(found)) != len(found):
        raise ValueError(_ERROR)
    return found


def _cache(text: str) -> dict[str, Path]:
    """Observe standard x86-64 loader-cache resolutions, not authenticate them."""
    result: dict[str, Path] = {}
    for line in text.splitlines():
        match = re.fullmatch(
            r"\s*([A-Za-z0-9+._-]+) \(libc6,x86-64\) => "
            r"(/(?:usr/)?lib/x86_64-linux-gnu/[A-Za-z0-9+._/-]+)", line,
        )
        if match is None:
            continue
        name, path = match.groups()
        if name in result and str(result[name]) != path:
            raise ValueError(_ERROR)
        result[name] = Path(path)
    if set(_NAMES) - set(result):
        raise ValueError(_ERROR)
    return result


def _run(argv: tuple[str, ...]) -> str:
    """Run only installed metadata readers, never the inspected ELF objects."""
    p = subprocess.run(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=_ENV, shell=False,
        timeout=15, check=True, text=True,
    )
    if type(p.stdout) is not str or len(p.stdout) > 2_000_000:
        raise ValueError(_ERROR)
    return p.stdout


# Section 3: Descriptor-based native library byte witness and dpkg observation.
def _hash_root_library(path: Path) -> str:
    """Hash a root-owned regular file without following symlinks or tolerating races."""
    fd = os.open(path, _FLAGS)
    try:
        before = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        def signature(s: os.stat_result) -> tuple[int, ...]:
            """Include both inode identity and mutation-sensitive metadata."""
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (
            signature(before) != signature(named)
            or not stat.S_ISREG(before.st_mode)
            or (before.st_uid, before.st_gid) != (0, 0)
            or stat.S_IMODE(before.st_mode) not in (0o644, 0o755)
            or not 0 < before.st_size <= 128 * 1024 * 1024
        ):
            raise ValueError(_ERROR)
        left = before.st_size
        h = hashlib.sha256()
        while left:
            part = os.read(fd, min(left, 65536))
            if not part:
                raise ValueError(_ERROR)
            h.update(part)
            left -= len(part)
        if (os.read(fd, 1) or signature(os.fstat(fd)) != signature(before)
                or signature(os.stat(path, follow_symlinks=False)) != signature(before)):
            raise ValueError(_ERROR)
        return h.hexdigest()
    finally:
        os.close(fd)


def _owner(path: Path) -> tuple[str, str]:
    """Identify installed package owner and version only as untrusted observations."""
    records = _run(("/usr/bin/dpkg-query", "-S", str(path))).strip().splitlines()
    if len(records) != 1 or not records[0].endswith(": " + str(path)):
        raise ValueError(_ERROR)
    owner = records[0].split(": ", 1)[0]
    if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*:amd64", owner) is None:
        raise ValueError(_ERROR)
    version = _run(("/usr/bin/dpkg-query", "-W",
                    "-f=$" + "{Version}", owner)).strip()
    if re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", version) is None:
        raise ValueError(_ERROR)
    return owner.removesuffix(":amd64"), version


# Section 4: Optional actual host inventory, deliberately non-authorizing.
def observe_native_closure() -> StaticNativeReceipt:
    """Inventory actual C27/C31A roots and transitive DT_NEEDED linkages read-only."""
    try:
        provenance = c27.DevPythonInterpreterProvenance()
        installed = c29._observe_payload(c29._load_payload(provenance))
        if len(installed) != 658:
            raise ValueError
        witness = c34r._read_system_interpreter_witness()
        binary = next(x for x in installed if x.path == witness.path)
        if (binary.sha256, binary.size) != (witness.sha256, witness.size_bytes):
            raise ValueError
        qualified_venv = c31.qualify_dev_python_environment(
            configuration=make_configuration(),
        )
        if type(qualified_venv) is not c31.DevPythonEnvironmentEvidence:
            raise ValueError
        c31.DevPythonEnvironmentEvidence.__post_init__(qualified_venv)
        roots = [
            Path(e.path) for e in installed
            if e.path.endswith(".so") or e.path == witness.path
        ]
        manifest = json.loads(c31._repository_manifest())["entries"]
        pinned = {e["path"]: e for e in manifest if e["path"] in _WHEEL_EXTENSIONS}
        if len(roots) != 47 or set(pinned) != set(_WHEEL_EXTENSIONS):
            raise ValueError
        for name in _WHEEL_EXTENSIONS:
            path = Path(c31._ROOT, name)
            row = pinned[name]
            if (path.stat().st_size != row["size"]
                    or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]):
                raise ValueError
            roots.append(path)
        resolved = _cache(_run(("/usr/sbin/ldconfig", "-p")))
        pending = deque(roots)
        seen: set[str] = set()
        needed: set[str] = set()
        versions: dict[str, str] = {}
        while pending:
            path = pending.popleft()
            if str(path) in seen:
                continue
            seen.add(str(path))
            for name in _needed(_run(("/usr/bin/readelf", "-d", str(path)))):
                needed.add(name)
                alias = resolved.get(name)
                if alias is None:
                    raise ValueError
                target = alias.resolve(strict=True)
                if (not str(target).startswith("/usr/lib/x86_64-linux-gnu/")
                        or not target.is_file() or target.is_symlink()):
                    raise ValueError
                _hash_root_library(target)
                package, version = _owner(target)
                if package in versions and versions[package] != version:
                    raise ValueError
                versions[package] = version
                if str(alias) not in seen:
                    pending.append(alias)
        result = StaticNativeReceipt(
            len(roots), len(seen), tuple(sorted(needed)),
            tuple(sorted(versions)), True,
        )
        StaticNativeReceipt.__post_init__(result)
        return result
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise NativeAuditHold(_ERROR) from None


# Section 5: CI-safe negative cases, no installed-host reads.
class NativeInventoryContracts(unittest.TestCase):
    """Confirm static source/loader evidence never becomes authorization."""

    def test_a_readelf_needed_strict_grammar(self) -> None:
        """Accept one well-formed dependency without implying it is trusted."""
        self.assertEqual(
            _needed("Dynamic section:\n 1 (NEEDED) Shared library: [libssl.so.3]"),
            ("libssl.so.3",),
        )

    def test_b_runpath_missing_and_duplicate_rejected(self) -> None:
        """Unsafe loader paths and altered or repeated ELF names fail closed."""
        basic = "Dynamic section:\n 1 (NEEDED) Shared library: [libc.so.6]"
        for bad in (
            basic + "\n 2 (RPATH) Library rpath: [/tmp]",
            basic + "\n 2 (RUNPATH) Library runpath: [/tmp]",
            basic + "\n 1 (NEEDED) Shared library: [libc.so.6]",
            "Dynamic section:\n 1 (NEEDED) Shared library: [/tmp/evil.so]",
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _needed(bad)

    def test_c_missing_cache_name_rejected(self) -> None:
        """A partial or forged resolver snapshot cannot qualify the closure."""
        with self.assertRaises(ValueError):
            _cache("libc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6")

    def test_d_no_forged_root_approval(self) -> None:
        """All privileged result flags must remain FALSE, even if counts match."""
        base = StaticNativeReceipt(
            49, 68, _NAMES,
            tuple(f"package{i:02d}" for i in range(14)), True,
        )
        for name in ("signed_external_packages", "sealed_root_imports",
                     "root_execution_approved"):
            with self.subTest(flag=name), self.assertRaises(ValueError):
                replace(base, **{name: True})

    def test_e_wrong_packages_and_closure_rejected(self) -> None:
        """Changed native dependency set or incomplete ownership cannot pass."""
        base = StaticNativeReceipt(
            49, 68, _NAMES,
            tuple(f"package{i:02d}" for i in range(14)), True,
        )
        for name, value in (
            ("roots", 48), ("objects", 67), ("needed", _NAMES[:-1]),
            ("packages", ("libc6",)),
        ):
            with self.subTest(field=name), self.assertRaises(ValueError):
                replace(base, **{name: value})

    def test_f_symlink_substitution_rejected(self) -> None:
        """A user-supplied symlink cannot satisfy a root library witness."""
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory, "libfake.so")
            candidate.write_bytes(b"fake ELF bytes")
            alias = Path(directory, "libalias.so")
            alias.symlink_to(candidate.name)
            with self.assertRaises(OSError):
                _hash_root_library(alias)

    def test_g_spoofed_dpkg_owner_and_version_rejected(self) -> None:
        """Malformed package-owner and newline-injected metadata are denied."""
        library = Path("/usr/lib/x86_64-linux-gnu/libssl.so.3")
        with patch(
            __name__ + "._run", return_value="not-a-package: " + str(library),
        ):
            with self.assertRaises(ValueError):
                _owner(library)
        def metadata(argv: tuple[str, ...]) -> str:
            """Simulate a matching owner but injected version newline."""
            return ("libssl3t64:amd64: " + str(library)) if "-S" in argv else "3.0\nspoofed"
        with patch(__name__ + "._run", side_effect=metadata):
            with self.assertRaises(ValueError):
                _owner(library)


# Section 6: Run only under an explicit nonprivileged host-audit opt-in.
@unittest.skipUnless(
    os.environ.get("OMNILYZER_C34T_HOST_READONLY") == "1",
    "no read-only installed host audit requested",
)
class C34TInstalledHostEvidence(unittest.TestCase):
    """Observe installed linkage without approving signed external packages."""

    def test_observed_native_runtime_closure(self) -> None:
        """Ensure all static dependencies resolve, with hardcoded HOLD flags."""
        evidence = observe_native_closure()
        self.assertFalse(evidence.root_execution_approved)
        print("C34T_STATIC_PASS roots=49 linked_elf=68 sonames=19 "
              "package_groups=14 signed_external=false root_approved=false")


if __name__ == "__main__":
    unittest.main()
