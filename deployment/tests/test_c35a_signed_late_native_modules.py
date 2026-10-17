"""File: deployment/tests/test_c35a_signed_late_native_modules.py

Purpose: Authenticate five observed NSS/OpenSSL late-loadable module bytes
against the exact four Ubuntu .deb payloads selected by signed Package indexes.
Reuse C27's pinned Ubuntu signing key and C34U's retained signed InRelease
records; do not invent a new signing source or installation layout.
Related: deployment/provenance/c35a-signed-late-native-modules-review.json,
deployment/tests/test_c34u_signed_external_native_provenance.py,
deployment/tests/test_c34z_main_loader_release_gap.py,
deployment/python_interpreter_provenance.py,
docs/operations/task014-c35a-signed-late-native-provenance.md,
.github/workflows/task014-c34d-review.yml.

Normal CI tests operate without installed-host access or network. An explicit
OMNILYZER_C35A_ARCHIVE_DIR directory enables a nonprivileged replay of signed
archive payloads against root-owned installed bytes. Host configuration
observations are pinned but NOT independently signed/approved for root loading.
No modules are imported, dlopened, installed, extracted onto the host or run.
"""

from __future__ import annotations

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

from deployment import python_interpreter_provenance as c27
from deployment.tests import test_c34u_signed_external_native_provenance as c34u
from deployment.tests import test_c34s_signed_python_provenance as c34s
from deployment.tests import test_c34t_native_dependency_inventory as c34t
from deployment.tests import test_c34z_main_loader_release_gap as c34z


# Section 1: Closed candidate and trust boundary.
_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "deployment/provenance/c35a-signed-late-native-modules-review.json"
_MANIFEST_SHA = "b78cf375285ea4aa086e79ff96f2658540e185dd7ab050bb45cb40ec70547244"
_MANIFEST_SIZE = 2856
_SIGNED_SOURCE_SHA = "c59040077ca8829aaf2758d47c9dea4bc9d25a771ab3c27d75a59c853de57b0c"
_NAMES = ("libc6", "libnss-mdns", "libnss-systemd", "libssl3t64")
_MODULE_PATHS = tuple(sorted(c34z._LOADER_MODULES))
_CONFIG_PATHS = ("/etc/ld.so.conf", "/etc/nsswitch.conf", "/etc/ssl/openssl.cnf")
_ENV = "OMNILYZER_C35A_ARCHIVE_DIR"
_ERROR = "C35A independently signed late native scope unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_UNSAFE_ENV = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
               "OPENSSL_CONF", "OPENSSL_MODULES", "PYTHONPATH", "PYTHONHOME")


class C35ANativeScopeHold(Exception):
    """Fail-closed scoped provenance failure; does not reveal host internals."""


@dataclass(frozen=True, slots=True)
class C35ANativeScopeReceipt:
    """Signed scope verification never becomes dynamic-loading or root authority."""

    signed_release_sources: int
    authenticated_package_archives: int
    verified_installed_late_modules: int
    config_files_observed: int
    all_five_signed_native_bytes_verified: bool
    signed_native_package_reuse_verified: bool
    observed_config_bytes_are_signed: bool = False
    native_runtime_loader_closed: bool = False
    protected_main_approved: bool = False
    privileged_import_package_approved: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Reject invented installed verification, complete loader or root claims."""
        if (
            type(self.signed_release_sources) is not int
            or self.signed_release_sources != 2
            or type(self.authenticated_package_archives) is not int
            or self.authenticated_package_archives != 4
            or type(self.verified_installed_late_modules) is not int
            or self.verified_installed_late_modules != 5
            or type(self.config_files_observed) is not int
            or self.config_files_observed != 3
            or self.all_five_signed_native_bytes_verified is not True
            or self.signed_native_package_reuse_verified is not True
            or self.observed_config_bytes_are_signed is not False
            or self.native_runtime_loader_closed is not False
            or self.protected_main_approved is not False
            or self.privileged_import_package_approved is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


# Section 2: Exact pinned manifest parsing and C34U signing source reuse.
def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    """Never resolve untrusted duplicate JSON fields using last-key-wins."""
    out: dict = {}
    for k, v in pairs:
        if type(k) is not str or k in out:
            raise ValueError(_ERROR)
        out[k] = v
    return out


def _load_closed_selection() -> dict:
    """Accept one reviewed snapshot and four exact existing package versions."""
    raw = _MANIFEST.read_bytes()
    if (len(raw) != _MANIFEST_SIZE
            or hashlib.sha256(raw).hexdigest() != _MANIFEST_SHA):
        raise ValueError(_ERROR)
    model = json.loads(raw, object_pairs_hook=_unique_pairs)
    if (
        type(model) is not dict
        or set(model) != {
            "schema_version", "kind", "ubuntu_signer",
            "inrelease_reference_manifest_sha256", "signed_package_records",
            "modules", "observed_host_config_not_signed",
            "openssl_config_alias", "openssl_config_alias_target",
            "root_execution_approved", "dynamic_loading_closed",
            "provider_configuration_signed_verified",
        }
        or type(model["schema_version"]) is not int
        or model["schema_version"] != 1
        or model["kind"] != "task014-c35a-signed-five-late-modules-review-only"
        or model["ubuntu_signer"] != c34u._SIGNER
        or model["inrelease_reference_manifest_sha256"] != _SIGNED_SOURCE_SHA
        or model["openssl_config_alias"] != "/usr/lib/ssl/openssl.cnf"
        or model["openssl_config_alias_target"] != "/etc/ssl/openssl.cnf"
        or model["root_execution_approved"] is not False
        or model["dynamic_loading_closed"] is not False
        or model["provider_configuration_signed_verified"] is not False
        or type(model["signed_package_records"]) is not list
        or type(model["modules"]) is not list
        or type(model["observed_host_config_not_signed"]) is not list
        or tuple(p["name"] for p in model["signed_package_records"]) != _NAMES
        or tuple(p["path"] for p in model["modules"]) != _MODULE_PATHS
        or tuple(p["path"] for p in model["observed_host_config_not_signed"])
        != _CONFIG_PATHS
    ):
        raise ValueError(_ERROR)
    for p in model["signed_package_records"]:
        if (
            type(p) is not dict
            or set(p) != {"name", "version", "architecture", "suite",
                          "filename", "size", "sha256"}
            or p["suite"] not in ("noble", "noble-security")
            or p["architecture"] != "amd64"
            or type(p["size"]) is not int or not 0 < p["size"] <= 8_000_000
            or type(p["sha256"]) is not str
            or _DIGEST.fullmatch(p["sha256"]) is None
            or type(p["filename"]) is not str
            or re.fullmatch(
                r"pool/main/[a-z0-9+.-]+/[a-z0-9+.-]+/"
                r"[A-Za-z0-9+._~-]+_amd64\.deb", p["filename"],
            ) is None
            or type(p["version"]) is not str
            or re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", p["version"]) is None
        ):
            raise ValueError(_ERROR)
    for m in model["modules"]:
        if (
            type(m) is not dict
            or set(m) != {"path", "package", "bytes", "sha256"}
            or c34z._LOADER_MODULES[m["path"]] != m["package"]
            or type(m["bytes"]) is not int or not 0 < m["bytes"] <= 10_000_000
            or type(m["sha256"]) is not str
            or _DIGEST.fullmatch(m["sha256"]) is None
        ):
            raise ValueError(_ERROR)
    for config in model["observed_host_config_not_signed"]:
        if (
            type(config) is not dict
            or set(config) != {"path", "sha256", "bytes", "uid", "gid", "mode"}
            or type(config["bytes"]) is not int or not 0 < config["bytes"] <= 100_000
            or type(config["sha256"]) is not str
            or _DIGEST.fullmatch(config["sha256"]) is None
            or config["uid"] != 0 or config["gid"] != 0
            or type(config["uid"]) is not int or type(config["gid"]) is not int
            or config["mode"] != "0644"
        ):
            raise ValueError(_ERROR)
    source = c34u._load_manifest()
    if hashlib.sha256(c34u._MANIFEST.read_bytes()).hexdigest() != _SIGNED_SOURCE_SHA:
        raise ValueError(_ERROR)
    originals = {p["name"]: p for p in source["packages"]}
    for p in model["signed_package_records"]:
        if p["name"] in originals and p != originals[p["name"]]:
            raise ValueError(_ERROR)
    if set(_NAMES) - set(p["name"] for p in model["signed_package_records"]):
        raise ValueError(_ERROR)
    return model


# Section 3: Package-to-installed-module hash comparison; no ELF execution.
def _verify_archive_members(model: dict, directory: Path) -> int:
    """Join fully authenticated .deb member bytes to five installed file hashes."""
    verified: set[str] = set()
    for package in model["signed_package_records"]:
        name = package["name"]
        archive = directory / (name + ".deb")
        if archive.is_symlink() or not archive.is_file():
            raise ValueError(_ERROR)
        with archive.open("rb") as stream:
            archive_digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if (archive.stat().st_size != package["size"]
                or archive_digest != package["sha256"]):
            raise ValueError(_ERROR)
        subset = [x for x in model["modules"] if x["package"] == name]
        if not subset:
            raise ValueError(_ERROR)
        expected_paths = {item["path"] for item in subset}
        members = c34u._archive_members(archive, expected_paths)
        for item in subset:
            path = Path(item["path"])
            actual = c34t._hash_root_library(path)
            owner, version = c34t._owner(path)
            if (
                owner != name or version != package["version"]
                or actual != item["sha256"]
                or path.lstat().st_size != item["bytes"]
                or members[item["path"]] != (
                    "regular", item["bytes"], item["sha256"],
                )
            ):
                raise ValueError(_ERROR)
            verified.add(item["path"])
    if verified != set(_MODULE_PATHS):
        raise ValueError(_ERROR)
    return len(verified)


# Section 4: Observe config hashes only; do not label them signed.
def _observe_untrusted_config(model: dict) -> int:
    """Require reviewed host config snapshot without implying loader authority."""
    alias = Path(model["openssl_config_alias"])
    l = alias.lstat()
    if (
        not stat.S_ISLNK(l.st_mode) or l.st_uid != 0 or l.st_gid != 0
        or os.readlink(alias) != model["openssl_config_alias_target"]
    ):
        raise ValueError(_ERROR)
    for record in model["observed_host_config_not_signed"]:
        path = Path(record["path"])
        st = path.lstat()
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != 0 or st.st_gid != 0
            or stat.S_IMODE(st.st_mode) != 0o644
            or st.st_size != record["bytes"]
            or c34t._hash_root_library(path) != record["sha256"]
        ):
            raise ValueError(_ERROR)
    return 3


# Section 5: Explicit full signed archival audit with retained signer and index.
def audit_signed_late_modules(directory: Path) -> C35ANativeScopeReceipt:
    """Authenticate signatures/indexes/archives/module bytes; root always HOLD."""
    try:
        if (
            directory.is_symlink() or not directory.is_dir()
            or directory.stat().st_uid != os.getuid()
            or stat.S_IMODE(directory.stat().st_mode) != 0o700
            or any(os.environ.get(name) for name in _UNSAFE_ENV)
        ):
            raise ValueError(_ERROR)
        model = _load_closed_selection()
        source = c34u._load_manifest()
        key = c27.DevPythonInterpreterProvenance().archive_key
        keyfile = _ROOT / key.repository_path
        if not c34s._digest_match(keyfile.read_bytes(), key.sha256, key.size):
            raise ValueError(_ERROR)
        with tempfile.TemporaryDirectory() as scratch:
            ring = Path(scratch) / "ubuntu.gpg"
            subprocess.run(
                ("/usr/bin/gpg", "--batch", "--dearmor", "--output",
                 str(ring), str(keyfile)),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=True, timeout=10,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
            )
            for suite in ("noble", "noble-security"):
                c34u._check_signature(source, suite, ring)
                index = c34u._index(source, suite, directory)
                c34u._records(
                    index, tuple(p for p in model["signed_package_records"]
                                 if p["suite"] == suite),
                )
        count = _verify_archive_members(model, directory)
        configs = _observe_untrusted_config(model)
        receipt = C35ANativeScopeReceipt(2, 4, count, configs, True, True)
        C35ANativeScopeReceipt.__post_init__(receipt)
        return receipt
    except _CONTROL:
        raise
    except Exception:
        raise C35ANativeScopeHold(_ERROR) from None


# Section 6: CI-safe boundary regressions, using exact committed snapshots.
class C35AReviewOnlyTests(unittest.TestCase):
    """Detect forged module provenance, bad pins or privilege escalation claims."""

    def test_a_exact_selection_and_prior_signed_package_reuse(self) -> None:
        """Ensure the same pinned Ubuntu InRelease and C27 archive signer."""
        m = _load_closed_selection()
        self.assertEqual(len(m["signed_package_records"]), 4)
        self.assertEqual(len(m["modules"]), 5)
        original = c34u._load_manifest()
        self.assertEqual(original["signer_fingerprint"], m["ubuntu_signer"])
        for suite in ("noble", "noble-security"):
            source = c34u._release_bytes(original, suite)
            self.assertIn(b"SHA256:", source)

    def test_b_changed_source_pin_and_duplicate_json_rejected(self) -> None:
        """Cannot substitute host metadata as upstream signing authority."""
        with patch(__name__ + "._MANIFEST_SHA", "f" * 64):
            with self.assertRaises(ValueError):
                _load_closed_selection()
        with self.assertRaises(ValueError):
            _unique_pairs([("signed", True), ("signed", False)])

    def test_c_module_and_signed_package_scope_is_exact(self) -> None:
        """Neither module paths nor package versions are automatically extensible."""
        m = _load_closed_selection()
        self.assertEqual(set(x["path"] for x in m["modules"]), set(_MODULE_PATHS))
        self.assertEqual(set(x["name"] for x in m["signed_package_records"]), set(_NAMES))

    def test_d_bad_archive_never_enters_installed_comparison(self) -> None:
        """Reject a substitute .deb before unpacking or comparing host files."""
        model = _load_closed_selection()
        with tempfile.TemporaryDirectory() as scratch:
            with self.assertRaises(ValueError):
                _verify_archive_members(model, Path(scratch))

    def test_e_altered_module_bytes_or_config_cannot_mean_root_approval(self) -> None:
        """A correct signed scope cannot validate configuration or live process."""
        result = C35ANativeScopeReceipt(2, 4, 5, 3, True, True)
        for key in (
            "observed_config_bytes_are_signed",
            "native_runtime_loader_closed",
            "protected_main_approved",
            "privileged_import_package_approved",
            "root_execution_approved",
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                replace(result, **{key: True})
        with self.assertRaises(ValueError):
            replace(result, verified_installed_late_modules=4)

    def test_f_untrusted_loader_environment_fail_closed(self) -> None:
        """Reject ELF/provider/Python path overrides before any archive reads."""
        with tempfile.TemporaryDirectory() as scratch:
            for key in _UNSAFE_ENV:
                with self.subTest(key=key), patch.dict(
                    os.environ, {key: "/tmp/untrusted-path"},
                ):
                    with self.assertRaises(C35ANativeScopeHold):
                        audit_signed_late_modules(Path(scratch))

    def test_g_rootless_manifest_review_is_not_installed_acceptance(self) -> None:
        """Offline source validation intentionally cannot approve signed bytes."""
        m = _load_closed_selection()
        self.assertIs(m["dynamic_loading_closed"], False)
        self.assertIs(m["root_execution_approved"], False)


# Section 7: Explicit host opt-in, skipped by GitHub CI.
@unittest.skipUnless(os.environ.get(_ENV), "no C35A staged signed packages")
class C35AActualHostSignedReplay(unittest.TestCase):
    """Verify staged source packages and five installed native files as nonroot."""

    def test_signed_ubuntu_archives_match_all_five_modules(self) -> None:
        """The result proves exactly five module bytes, not dynamic loader safety."""
        receipt = audit_signed_late_modules(Path(os.environ[_ENV]))
        self.assertTrue(receipt.all_five_signed_native_bytes_verified)
        self.assertFalse(receipt.native_runtime_loader_closed)
        self.assertFalse(receipt.observed_config_bytes_are_signed)
        self.assertFalse(receipt.root_execution_approved)
        print("C35A_SIGNED_LATE_NATIVE_PASS signed_releases=2 "
              "authenticated_debs=4 native_files=5 configs_observed=3 "
              "configs_signed=false dynamic_loader_closed=false "
              "root_approved=false")


if __name__ == "__main__":
    unittest.main()
