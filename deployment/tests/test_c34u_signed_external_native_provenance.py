"""File: deployment/tests/test_c34u_signed_external_native_provenance.py

Purpose: Independently verify Ubuntu-signed external Debian archives and the
installed 19 static native ELF dependency aliases/regular-file bytes identified
by C34T, while explicitly forbidding root authorization or deployment.
Related: deployment/tests/test_c34t_native_dependency_inventory.py,
deployment/tests/test_c34s_signed_python_provenance.py,
deployment/python_interpreter_provenance.py,
deployment/provenance/c34u-external-native-package-set.json,
deployment/provenance/c34u-noble.InRelease,
deployment/provenance/c34u-noble-security.InRelease,
docs/operations/task014-c34u-signed-external-native-provenance.md.

Default tests are local/offline and do not touch installed host binaries.
The explicitly opt-in full audit requires Packages indexes plus fourteen exact
.deb files in a nonprivileged 0700 directory. No package installs, extraction
to the host, dynamic library imports, privileged execution or host changes.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deployment import python_interpreter_provenance as c27
from deployment.tests import test_c34s_signed_python_provenance as c34s
from deployment.tests import test_c34t_native_dependency_inventory as c34t


# Section 1: Closed source contract and non-authorizing result.
_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "deployment/provenance/c34u-external-native-package-set.json"
_MANIFEST_SHA256 = "c59040077ca8829aaf2758d47c9dea4bc9d25a771ab3c27d75a59c853de57b0c"
_NAMES = (
    "libbz2-1.0", "libc6", "libcrypt1", "libdb5.3t64", "libexpat1",
    "libffi8", "libgcc-s1", "liblzma5", "libncursesw6", "libreadline8t64",
    "libsqlite3-0", "libssl3t64", "libtinfo6", "zlib1g",
)
_SUITES = ("noble", "noble-security")
_ERROR = "C34U signed native provenance is unavailable"
_SIGNER = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_ARCHIVE_ENV = "OMNILYZER_C34U_ARCHIVE_DIR"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class SignedNativeProvenanceHold(Exception):
    """One fail-closed response, without exposing package or host internals."""


@dataclass(frozen=True, slots=True)
class C34USignedNativeScopeReceipt:
    """Authenticated scope-specific installed bytes, never privileged authority."""

    signed_release_count: int
    signed_package_count: int
    verified_native_sonames: int
    previous_static_scope_verified: bool
    signed_external_scope_verified: bool
    complete_dynamic_loading_verified: bool = False
    immutable_root_import_package_approved: bool = False
    canonical_root_config_approved: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Forbid forging runtime authority from scoped package verification."""
        if (
            type(self.signed_release_count) is not int
            or self.signed_release_count != 2
            or type(self.signed_package_count) is not int
            or self.signed_package_count != 14
            or type(self.verified_native_sonames) is not int
            or self.verified_native_sonames != 19
            or self.previous_static_scope_verified is not True
            or self.signed_external_scope_verified is not True
            or self.complete_dynamic_loading_verified is not False
            or self.immutable_root_import_package_approved is not False
            or self.canonical_root_config_approved is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


# Section 2: Exact immutable manifest and signed InRelease evidence.
def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous duplicate JSON keys instead of silently using the last."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError(_ERROR)
        result[key] = value
    return result


def _load_manifest() -> dict:
    """Require the exact retained C34U artifact-selection model, not host hashes."""
    raw = _MANIFEST.read_bytes()
    if not c34s._digest_match(raw, _MANIFEST_SHA256, 4405):
        raise ValueError(_ERROR)
    model = json.loads(raw, object_pairs_hook=_pairs)
    if (
        type(model) is not dict
        or set(model) != {"schema_version", "kind", "signer_fingerprint",
                          "suites", "packages"}
        or model["schema_version"] != 1
        or model["kind"] != "signed-ubuntu-native-package-selection-v1"
        or model["signer_fingerprint"] != _SIGNER
        or set(model["suites"]) != set(_SUITES)
        or type(model["packages"]) is not list
        or tuple(x["name"] for x in model["packages"]) != _NAMES
    ):
        raise ValueError(_ERROR)
    for name, entry in model["suites"].items():
        if (
            type(entry) is not dict
            or set(entry) != {"inrelease_path", "inrelease_sha256",
                              "inrelease_size", "packages_sha256",
                              "packages_size"}
            or entry["inrelease_path"]
            != "deployment/provenance/c34u-" + name + ".InRelease"
            or _DIGEST.fullmatch(entry["inrelease_sha256"]) is None
            or _DIGEST.fullmatch(entry["packages_sha256"]) is None
            or type(entry["inrelease_size"]) is not int
            or type(entry["packages_size"]) is not int
            or not 0 < entry["inrelease_size"] < 400_000
            or not 0 < entry["packages_size"] < 10_000_000
        ):
            raise ValueError(_ERROR)
    for record in model["packages"]:
        if (
            type(record) is not dict
            or set(record) != {"name", "version", "architecture", "suite",
                               "filename", "size", "sha256"}
            or record["suite"] not in _SUITES
            or record["architecture"] != "amd64"
            or re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", record["name"]) is None
            or re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", record["version"]) is None
            or re.fullmatch(
                r"pool/main/[a-z0-9+.-]+/[a-z0-9+.-]+/"
                r"[A-Za-z0-9+._~-]+_amd64\.deb", record["filename"],
            ) is None
            or _DIGEST.fullmatch(record["sha256"]) is None
            or type(record["size"]) is not int
            or not 0 < record["size"] <= 8_000_000
        ):
            raise ValueError(_ERROR)
    return model


def _release_bytes(model: dict, suite: str) -> bytes:
    """Bind retained InRelease bytes to the pinned manifest, without signing."""
    entry = model["suites"][suite]
    raw = (_ROOT / entry["inrelease_path"]).read_bytes()
    if not c34s._digest_match(raw, entry["inrelease_sha256"],
                             entry["inrelease_size"]):
        raise ValueError(_ERROR)
    return raw


def _check_signature(model: dict, suite: str, keyring: Path) -> None:
    """Verify Ubuntu OpenPGP signature and exact signer using gpgv, no network."""
    release = _ROOT / model["suites"][suite]["inrelease_path"]
    result = subprocess.run(
        ("/usr/bin/gpgv", "--status-fd", "1", "--keyring", str(keyring),
         str(release)),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, check=True, timeout=10,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
    )
    if (b"[GNUPG:] VALIDSIG " + _SIGNER.encode() + b" ") not in result.stdout:
        raise ValueError(_ERROR)


# Section 3: Index and signed artifact record verification.
def _index(model: dict, suite: str, directory: Path) -> bytes:
    """Validate exact Packages bytes against the signed InRelease checksum."""
    entry = model["suites"][suite]
    data = (directory / (suite + ".Packages")).read_bytes()
    if not c34s._digest_match(data, entry["packages_sha256"],
                             entry["packages_size"]):
        raise ValueError(_ERROR)
    reference = c34s._signed_index_record(
        _release_bytes(model, suite), "main/binary-amd64/Packages",
    )
    if reference != (entry["packages_sha256"], entry["packages_size"]):
        raise ValueError(_ERROR)
    return data


def _records(index: bytes, expected: tuple[dict, ...]) -> None:
    """Match exact name/version/arch/path/length/hash for all selected packages."""
    needed = {x["name"]: x for x in expected}
    found: set[str] = set()
    for paragraph in index.decode("utf-8").split("\n\n"):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if line.startswith(" ") or ": " not in line:
                continue
            key, value = line.split(": ", 1)
            if key in fields:
                raise ValueError(_ERROR)
            fields[key] = value
        name = fields.get("Package")
        if name not in needed:
            continue
        requirement = needed[name]
        if (fields.get("Version"), fields.get("Architecture")) != (
            requirement["version"], "amd64",
        ):
            continue
        if name in found or (
            fields.get("Filename"), fields.get("Size"), fields.get("SHA256")
        ) != (
            requirement["filename"], str(requirement["size"]),
            requirement["sha256"],
        ):
            raise ValueError(_ERROR)
        found.add(name)
    if found != set(needed):
        raise ValueError(_ERROR)


# Section 4: Match signed Debian payloads to installed native library files.
def _archive_members(archive: Path, paths: set[str]) -> dict[str, tuple]:
    """Inspect exact native tar members in a signed .deb without extracting."""
    completed = subprocess.run(
        ("/usr/bin/dpkg-deb", "--fsys-tarfile", str(archive)),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=25, check=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
    )
    if not 0 < len(completed.stdout) < 110_000_000:
        raise ValueError(_ERROR)
    found: dict[str, tuple] = {}
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:*") as tar:
        for member in tar:
            path = "/" + member.name.removeprefix("./").lstrip("/")
            if path.startswith(("/lib/", "/lib64/", "/bin/", "/sbin/")):
                path = "/usr" + path
            if path not in paths:
                continue
            if path in found:
                raise ValueError(_ERROR)
            if member.isfile():
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError(_ERROR)
                with stream:
                    body = stream.read()
                found[path] = ("regular", len(body), hashlib.sha256(body).hexdigest())
            elif member.issym():
                if (
                    not member.linkname
                    or "/" in member.linkname
                    or member.linkname in (".", "..")
                ):
                    raise ValueError(_ERROR)
                found[path] = ("symlink", member.linkname)
            else:
                raise ValueError(_ERROR)
    if set(found) != paths:
        raise ValueError(_ERROR)
    return found


def _canonical(path: Path) -> str:
    """Normalize Ubuntu merged-/usr aliases only for signed archive member names."""
    raw = str(path)
    if raw.startswith(("/lib/", "/lib64/", "/bin/", "/sbin/")):
        raw = "/usr" + raw
    if not raw.startswith("/usr/lib/") or "/.." in raw:
        raise ValueError(_ERROR)
    return raw


def _matched_external_bytes(
    model: dict, directory: Path, paths: dict[str, tuple[str, Path, Path]],
) -> int:
    """Verify each native SONAME alias and target against its signed .deb."""
    verified: set[str] = set()
    for package in model["packages"]:
        name = package["name"]
        subset = {
            soname: (alias, real)
            for soname, (owner, alias, real) in paths.items() if owner == name
        }
        if not subset:
            raise ValueError(_ERROR)
        archive = directory / (name + ".deb")
        if archive.is_symlink() or not archive.is_file():
            raise ValueError(_ERROR)
        if not c34s._digest_match(archive.read_bytes(), package["sha256"],
                                  package["size"]):
            raise ValueError(_ERROR)
        requested: set[str] = set()
        for alias, real in subset.values():
            requested.add(_canonical(alias))
            requested.add(_canonical(real))
        members = _archive_members(archive, requested)
        for soname, (alias, real) in subset.items():
            target = members[_canonical(real)]
            if target[0] != "regular":
                raise ValueError(_ERROR)
            current = c34t._hash_root_library(real)
            if target[2] != current or real.stat().st_size != target[1]:
                raise ValueError(_ERROR)
            alias_member = members[_canonical(alias)]
            if _canonical(alias) == _canonical(real):
                if alias_member != target:
                    raise ValueError(_ERROR)
            else:
                if (alias_member[0] != "symlink"
                        or os.readlink(alias) != alias_member[1]
                        or str((PurePosixPath(_canonical(alias)).parent /
                                alias_member[1])) != _canonical(real)):
                    raise ValueError(_ERROR)
            verified.add(soname)
    if verified != set(c34t._NAMES):
        raise ValueError(_ERROR)
    return len(verified)


# Section 5: Opt-in complete source-to-host audit. Root authority NEVER follows.
def audit_external_native_provenance(directory: Path) -> C34USignedNativeScopeReceipt:
    """Authenticate Ubuntu signatures, .deb members and current installed bytes."""
    try:
        if (
            directory.is_symlink() or not directory.is_dir()
            or stat.S_IMODE(directory.stat().st_mode) != 0o700
            or directory.stat().st_uid != os.getuid()
        ):
            raise ValueError
        if os.environ.get("LD_PRELOAD") or os.environ.get("LD_LIBRARY_PATH"):
            raise ValueError
        model = _load_manifest()
        key = c27.DevPythonInterpreterProvenance().archive_key
        keyfile = _ROOT / key.repository_path
        if not c34s._digest_match(keyfile.read_bytes(), key.sha256, key.size):
            raise ValueError
        with tempfile.TemporaryDirectory() as scratch:
            ring = Path(scratch) / "ubuntu.gpg"
            subprocess.run(
                ("/usr/bin/gpg", "--batch", "--dearmor", "--output",
                 str(ring), str(keyfile)),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=True, timeout=10,
            )
            for suite in _SUITES:
                _check_signature(model, suite, ring)
                _records(
                    _index(model, suite, directory),
                    tuple(p for p in model["packages"] if p["suite"] == suite),
                )
        previous = c34t.observe_native_closure()
        c34t.StaticNativeReceipt.__post_init__(previous)
        cache = c34t._cache(c34t._run(("/usr/sbin/ldconfig", "-p")))
        targets: dict[str, tuple[str, Path, Path]] = {}
        for soname in c34t._NAMES:
            alias = cache[soname]
            real = alias.resolve(strict=True)
            if not str(real).startswith("/usr/lib/x86_64-linux-gnu/"):
                raise ValueError
            owner, version = c34t._owner(real)
            expectation = next(
                (p for p in model["packages"] if p["name"] == owner), None,
            )
            if expectation is None or expectation["version"] != version:
                raise ValueError
            targets[soname] = (owner, alias, real)
        count = _matched_external_bytes(model, directory, targets)
        return C34USignedNativeScopeReceipt(2, 14, count, True, True)
    except _CONTROL:
        raise
    except Exception:
        raise SignedNativeProvenanceHold(_ERROR) from None


# Section 6: CI-safe positive and negative boundary tests.
class SignedExternalNativeContracts(unittest.TestCase):
    """Regression checks run without staged downloads or installed-host reads."""

    def test_a_manifest_retained_signatures_and_source_pins(self) -> None:
        """Require exact committed evidence and independently pinned C27 signer."""
        model = _load_manifest()
        self.assertEqual(len(model["packages"]), 14)
        self.assertEqual(model["signer_fingerprint"], _SIGNER)
        for suite in _SUITES:
            release = _release_bytes(model, suite)
            pin = model["suites"][suite]
            self.assertEqual(
                c34s._signed_index_record(release, "main/binary-amd64/Packages"),
                (pin["packages_sha256"], pin["packages_size"]),
            )

    def test_b_changed_manifest_rejected(self) -> None:
        """Never silently rederive an authority pin from mutable host metadata."""
        with patch(__name__ + "._MANIFEST_SHA256", "0" * 64):
            with self.assertRaises(ValueError):
                _load_manifest()

    def test_c_modified_signed_index_rejected(self) -> None:
        """Same-sized fake index cannot replace the signed Packages bytes."""
        model = _load_manifest()
        with tempfile.TemporaryDirectory() as directory:
            for suite in _SUITES:
                (Path(directory) / (suite + ".Packages")).write_bytes(
                    b"x" * model["suites"][suite]["packages_size"],
                )
                with self.assertRaises(ValueError):
                    _index(model, suite, Path(directory))

    def test_d_wrong_package_version_and_hash_rejected(self) -> None:
        """A wrong/missing package stanza cannot satisfy a reviewed selection."""
        record = _load_manifest()["packages"][0]
        data = (
            "Package: " + record["name"] + "\nVersion: wrong\n"
            "Architecture: amd64\nFilename: " + record["filename"] +
            "\nSize: " + str(record["size"]) + "\nSHA256: " +
            record["sha256"] + "\n"
        ).encode()
        with self.assertRaises(ValueError):
            _records(data, (record,))

    def test_e_symlink_and_file_substitution_rejected(self) -> None:
        """Real comparison rejects altered installed bytes or symlink targets."""
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            file = folder / "liboriginal.so.1"
            file.write_bytes(b"signed native payload")
            alias = folder / "liboriginal.so"
            alias.symlink_to(file.name)
            artifact = folder / "reviewed.deb"
            artifact.write_bytes(b"signed deb")
            signed_hash = hashlib.sha256(file.read_bytes()).hexdigest()
            model = {"packages": [{
                "name": "reviewed",
                "size": artifact.stat().st_size,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }]}
            members = {
                str(file): ("regular", file.stat().st_size, signed_hash),
                str(alias): ("symlink", file.name),
            }
            targets = {
                name: ("reviewed", alias, file) for name in c34t._NAMES
            }
            with (
                patch(__name__ + "._canonical", side_effect=lambda p: str(p)),
                patch(__name__ + "._archive_members", return_value=members),
                patch.object(
                    c34t, "_hash_root_library",
                    side_effect=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(),
                ),
            ):
                self.assertEqual(
                    _matched_external_bytes(model, folder, targets), 19,
                )
                alias.unlink()
                alias.symlink_to("substituted.so")
                with self.assertRaises(ValueError):
                    _matched_external_bytes(model, folder, targets)
                alias.unlink()
                alias.symlink_to(file.name)
                file.write_bytes(b"tampered native payload")
                with self.assertRaises(ValueError):
                    _matched_external_bytes(model, folder, targets)

    def test_f_forged_root_authority_rejected(self) -> None:
        """A signed native scope still does not certify root or dynamic loading."""
        receipt = C34USignedNativeScopeReceipt(2, 14, 19, True, True)
        for flag in (
            "complete_dynamic_loading_verified",
            "immutable_root_import_package_approved",
            "canonical_root_config_approved", "root_execution_approved",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                replace(receipt, **{flag: True})


# Section 7: Explicit real-host audit, never part of default CI.
@unittest.skipUnless(os.environ.get(_ARCHIVE_ENV), "no staged signed external archives")
class ActualSignedExternalNativeAudit(unittest.TestCase):
    """Run staged package->native file verification as nonprivileged user only."""

    def test_signed_ubuntu_packages_match_installed_native_libraries(self) -> None:
        """Audit all 19 native names against 14 authenticated signed .deb files."""
        directory = Path(os.environ[_ARCHIVE_ENV])
        result = audit_external_native_provenance(directory)
        self.assertIs(result.root_execution_approved, False)
        self.assertIs(result.complete_dynamic_loading_verified, False)
        print("C34U_SIGNED_NATIVE_PASS releases=2 debs=14 "
              "sonames=19 root_approved=false dynamic_loading_verified=false")


if __name__ == "__main__":
    unittest.main()
