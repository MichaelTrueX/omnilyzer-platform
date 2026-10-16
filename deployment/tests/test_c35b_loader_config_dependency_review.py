"""File: deployment/tests/test_c35b_loader_config_dependency_review.py

Purpose: Audit existing OpenSSL/NSS and ld.so configuration plus six native
ELF dependency sets, and independently authenticate the newly identified
libcap.so.2.66 against Ubuntu signed package metadata and archive payload.
Related: deployment/provenance/c35b-loader-config-dependency-review.json,
deployment/tests/test_c35a_signed_late_native_modules.py,
deployment/tests/test_c34u_signed_external_native_provenance.py,
deployment/tests/test_c34t_native_dependency_inventory.py,
docs/operations/task014-c35b-loader-config-dependency-review.md,
.github/workflows/task014-c34d-review.yml.

This is nonprivileged review-only evidence: not a root-owned configuration
seal, exhaustive dlopen trace, launcher, service modification or deployment.
Normal CI uses pinned source data; actual host audit needs explicit opt-in.
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
from deployment.tests import test_c34t_native_dependency_inventory as c34t
from deployment.tests import test_c34u_signed_external_native_provenance as c34u
from deployment.tests import test_c34s_signed_python_provenance as c34s
from deployment.tests import test_c35a_signed_late_native_modules as c35a
from deployment.tests import test_c34z_main_loader_release_gap as c34z


# Section 1: Scoped immutable evidence and fail-closed root permissions.
_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "deployment/provenance/c35b-loader-config-dependency-review.json"
_MANIFEST_SHA = "66ecbf08296607a9cb7e07f492f49bd5544164dd383025de3653f72fadebc085"
_MANIFEST_LEN = 2884
_ERROR = "C35B loader configuration and native dependency review unavailable"
_SOURCE = "a13e64bdcc721cd416c9004fe0683729ade1209a"
_HOST_ENV = "OMNILYZER_C35B_SIGNED_DIR"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_CONFIG_PATHS = (
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf",
    "/etc/ld.so.conf.d/libc.conf",
    "/etc/ld.so.conf.d/x86_64-linux-gnu.conf",
    "/etc/nsswitch.conf",
    "/etc/ssl/openssl.cnf",
)
_EXPECTED_NSS = {
    "passwd": "files systemd",
    "group": "files systemd",
    "shadow": "files",
    "hosts": "files mdns4_minimal [NOTFOUND=return] dns",
    "networks": "files",
    "services": "db files",
}
_EXPECTED_LD = {
    _CONFIG_PATHS[0]: ["include /etc/ld.so.conf.d/*.conf"],
    _CONFIG_PATHS[1]: ["/usr/lib/x86_64-linux-gnu/libfakeroot"],
    _CONFIG_PATHS[2]: ["/usr/local/lib"],
    _CONFIG_PATHS[3]: [
        "/usr/local/lib/x86_64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
    ],
}
_EXTRA_CAP = "/usr/lib/x86_64-linux-gnu/libcap.so.2.66"
_CAP_ALIAS = Path("/usr/lib/x86_64-linux-gnu/libcap.so.2")
_SEARCH = (
    "/usr/lib/x86_64-linux-gnu/libfakeroot",
    "/usr/local/lib",
    "/usr/local/lib/x86_64-linux-gnu",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
)
_UNSAFE = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
           "OPENSSL_CONF", "OPENSSL_MODULES", "PYTHONHOME", "PYTHONPATH")


class C35BLoaderHold(Exception):
    """Single fail-closed audit failure, without leaking host configuration."""


@dataclass(frozen=True, slots=True)
class C35BReviewReceipt:
    """Scoped observations never authorize privileged loading or promotion."""

    retained_source_commit: str
    verified_config_metadata_paths: int
    native_elf_metadata_paths: int
    additional_signed_package_artifacts: int
    observed_external_search_entries: int
    signed_additional_libcap_verified: bool
    host_configuration_rechecked: bool
    privileged_loader_config_signed: bool = False
    complete_dynamic_library_closure: bool = False
    protected_main_approved: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Explicitly reject fabricated complete native/privileged evidence."""
        if (
            self.retained_source_commit != _SOURCE
            or type(self.verified_config_metadata_paths) is not int
            or self.verified_config_metadata_paths != 6
            or type(self.native_elf_metadata_paths) is not int
            or self.native_elf_metadata_paths != 6
            or type(self.additional_signed_package_artifacts) is not int
            or self.additional_signed_package_artifacts != 1
            or type(self.observed_external_search_entries) is not int
            or self.observed_external_search_entries != 2
            or self.signed_additional_libcap_verified is not True
            or self.host_configuration_rechecked is not True
            or self.privileged_loader_config_signed is not False
            or self.complete_dynamic_library_closure is not False
            or self.protected_main_approved is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


# Section 2: Strict JSON pinned review and inherited signed-file facts.
def _distinct_pairs(items: list[tuple[str, object]]) -> dict:
    """Reject duplicate keys in all JSON objects, including nested objects."""
    result = {}
    for key, value in items:
        if type(key) is not str or key in result:
            raise ValueError(_ERROR)
        result[key] = value
    return result


def _load_review() -> dict:
    """Validate complete exact retained historical configuration observation."""
    raw = _MANIFEST.read_bytes()
    if len(raw) != _MANIFEST_LEN or hashlib.sha256(raw).hexdigest() != _MANIFEST_SHA:
        raise ValueError(_ERROR)
    model = json.loads(raw, object_pairs_hook=_distinct_pairs)
    if (
        type(model) is not dict
        or set(model) != {
            "kind", "version", "source_commit", "configs", "modules",
            "signed_additional_libcap2", "nss_required",
            "ld_config_include", "loader_search_paths",
            "openssl_provider_default_declared",
            "openssl_legacy_explicitly_activated",
            "openssl_fips_explicitly_activated",
            "config_signed", "effective_loader_approved",
            "root_execution_approved",
        }
        or model["kind"] != "task014-c35b-closed-review-only"
        or type(model["version"]) is not int or model["version"] != 1
        or model["source_commit"] != _SOURCE
        or model["nss_required"] != _EXPECTED_NSS
        or model["ld_config_include"] != _EXPECTED_LD[_CONFIG_PATHS[0]][0]
        or tuple(model["loader_search_paths"]) != _SEARCH
        or model["openssl_provider_default_declared"] is not True
        or model["openssl_legacy_explicitly_activated"] is not False
        or model["openssl_fips_explicitly_activated"] is not False
        or model["config_signed"] is not False
        or model["effective_loader_approved"] is not False
        or model["root_execution_approved"] is not False
        or type(model["configs"]) is not list or len(model["configs"]) != 6
        or type(model["modules"]) is not list or len(model["modules"]) != 6
        or tuple(x["path"] for x in model["configs"]) != _CONFIG_PATHS
        or tuple(x["path"] for x in model["modules"]) != tuple(sorted((
            *c34z._LOADER_MODULES, _EXTRA_CAP,
        )))
    ):
        raise ValueError(_ERROR)
    for item in model["configs"]:
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "size", "signed"}
            or type(item["sha256"]) is not str or not _SHA.fullmatch(item["sha256"])
            or type(item["size"]) is not int or not 0 < item["size"] <= 100_000
            or item["signed"] is not False
        ):
            raise ValueError(_ERROR)
    original = {x["path"]: x for x in c35a._load_closed_selection()["modules"]}
    for item in model["modules"]:
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "needed"}
            or type(item["sha256"]) is not str or not _SHA.fullmatch(item["sha256"])
            or type(item["needed"]) is not list
            or any(type(n) is not str or
                   re.fullmatch(r"[a-zA-Z0-9_.+-]{1,100}", n) is None
                   for n in item["needed"])
        ):
            raise ValueError(_ERROR)
        if item["path"] != _EXTRA_CAP and (
            item["sha256"] != original[item["path"]]["sha256"]
        ):
            raise ValueError(_ERROR)
        if item["path"] == _EXTRA_CAP and item["needed"] != ["libc.so.6"]:
            raise ValueError(_ERROR)
        if not set(item["needed"]) <= set(c34t._NAMES) | {"libcap.so.2"}:
            raise ValueError(_ERROR)
    cap = model["signed_additional_libcap2"]
    if (
        type(cap) is not dict or
        set(cap) != {"name", "version", "architecture", "suite",
                     "filename", "size", "sha256"}
        or cap != {
            "name": "libcap2", "version": "1:2.66-5ubuntu2.4",
            "architecture": "amd64", "suite": "noble-security",
            "filename": "pool/main/libc/libcap2/libcap2_2.66-5ubuntu2.4_amd64.deb",
            "size": 30500,
            "sha256": "23c627c77c66552a658e62852f244f4946dc543898e0ec5428d5dc6bffde2d6a",
        }
    ):
        raise ValueError(_ERROR)
    return model


# Section 3: Pure textual configuration policy (not a trusted root seal).
def _active_lines(raw: bytes) -> list[str]:
    """Strip comments for observed plain loader configurations only."""
    return [
        line.strip() for line in raw.decode("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]


def _inspect_nss(raw: bytes) -> None:
    """Verify existing six NSS service choices and important NOTFOUND ordering."""
    observed = {}
    for line in _active_lines(raw):
        if ":" not in line:
            raise ValueError(_ERROR)
        name, rest = line.split(":", 1)
        if name.strip() in _EXPECTED_NSS:
            if name.strip() in observed:
                raise ValueError(_ERROR)
            observed[name.strip()] = " ".join(rest.split())
    if observed != _EXPECTED_NSS:
        raise ValueError(_ERROR)


def _inspect_openssl(raw: bytes) -> None:
    """Require no active provider includes, legacy/FIPS or unsafe substitutions.

    Only an observed subset is checked. This does NOT parse all OpenSSL syntax,
    application-specific configs or inherited environment overrides.
    """
    lines = _active_lines(raw)
    if (
        "openssl_conf = openssl_init" not in lines
        or "providers = provider_sect" not in lines
        or "[provider_sect]" not in lines
        or "default = default_sect" not in lines
        or any(
            line.startswith((".include", "legacy =", "fips ="))
            for line in lines
        )
    ):
        raise ValueError(_ERROR)


# Section 4: Read-only installed config and six ELF DT_NEEDED witnesses.
def _inspect_host(model: dict) -> None:
    """Check exact existing files and bounded metadata, never execute them."""
    for entry in model["configs"]:
        p = Path(entry["path"])
        if c34t._hash_root_library(p) != entry["sha256"] or p.stat().st_size != entry["size"]:
            raise ValueError(_ERROR)
        if entry["path"] in _EXPECTED_LD and _active_lines(p.read_bytes()) != _EXPECTED_LD[entry["path"]]:
            raise ValueError(_ERROR)
        if p.name == "nsswitch.conf":
            _inspect_nss(p.read_bytes())
        if p.name == "openssl.cnf":
            _inspect_openssl(p.read_bytes())
    # Require no unreviewed config fragments that could add a loader directory.
    confdir = Path("/etc/ld.so.conf.d")
    if sorted(x.name for x in confdir.iterdir()) != sorted(
        Path(x).name for x in _CONFIG_PATHS if x.startswith("/etc/ld.so.conf.d/")
    ):
        raise ValueError(_ERROR)
    for p in _SEARCH:
        target = Path(p)
        if target.exists():
            s = target.lstat()
            if (not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_gid != 0
                    or stat.S_IMODE(s.st_mode) != 0o755):
                raise ValueError(_ERROR)
        elif p != "/usr/local/lib/x86_64-linux-gnu":
            raise ValueError(_ERROR)
    alias = Path("/usr/lib/ssl/openssl.cnf")
    if not alias.is_symlink() or os.readlink(alias) != "/etc/ssl/openssl.cnf":
        raise ValueError(_ERROR)
    for module in model["modules"]:
        p = Path(module["path"])
        if c34t._hash_root_library(p) != module["sha256"]:
            raise ValueError(_ERROR)
        needed = c34t._needed(c34t._run(("/usr/bin/readelf", "-d", str(p))))
        if tuple(module["needed"]) != needed:
            raise ValueError(_ERROR)
    # Explicitly observe only the one previously unauthenticated module SONAME.
    resolved = c34t._cache(c34t._run(("/usr/sbin/ldconfig", "-p")))
    p = resolved.get("libcap.so.2")
    if p is None or p.resolve(strict=True) != Path(_EXTRA_CAP):
        raise ValueError(_ERROR)


# Section 5: Independent signed Ubuntu libcap2 payload evidence.
def _check_libcap_archive(model: dict, directory: Path) -> None:
    """Reuse C34U's verified signer/indices, then archive member+symlink bytes."""
    if (
        directory.is_symlink() or not directory.is_dir()
        or directory.stat().st_uid != os.getuid()
        or stat.S_IMODE(directory.stat().st_mode) != 0o700
        or any(os.environ.get(k) for k in _UNSAFE)
    ):
        raise ValueError(_ERROR)
    signed = c34u._load_manifest()
    key = c27.DevPythonInterpreterProvenance().archive_key
    key_path = _ROOT / key.repository_path
    if not c34s._digest_match(key_path.read_bytes(), key.sha256, key.size):
        raise ValueError(_ERROR)
    with tempfile.TemporaryDirectory() as scratch:
        ring = Path(scratch) / "ubuntu.gpg"
        subprocess.run(
            ("/usr/bin/gpg", "--batch", "--dearmor", "--output", str(ring), str(key_path)),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=True, timeout=10,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
        c34u._check_signature(signed, "noble-security", ring)
        index = c34u._index(signed, "noble-security", directory)
        c34u._records(index, (model["signed_additional_libcap2"],))
    archive = directory / "libcap2.deb"
    cap = model["signed_additional_libcap2"]
    if (archive.is_symlink() or not archive.is_file()
            or archive.stat().st_size != cap["size"]):
        raise ValueError(_ERROR)
    with archive.open("rb") as fd:
        if hashlib.file_digest(fd, "sha256").hexdigest() != cap["sha256"]:
            raise ValueError(_ERROR)
    members = c34u._archive_members(archive, {_EXTRA_CAP, str(_CAP_ALIAS)})
    target_hash = c34t._hash_root_library(Path(_EXTRA_CAP))
    size = Path(_EXTRA_CAP).stat().st_size
    if (members[_EXTRA_CAP] != ("regular", size, target_hash)
            or members[str(_CAP_ALIAS)] != ("symlink", "libcap.so.2.66")
            or os.readlink(_CAP_ALIAS) != "libcap.so.2.66"
            or c34t._owner(Path(_EXTRA_CAP)) != (cap["name"], cap["version"])):
        raise ValueError(_ERROR)


def review_c35b_host(directory: Path) -> C35BReviewReceipt:
    """Observe config+native dependencies and signed libcap; root stays HOLD."""
    try:
        model = _load_review()
        _inspect_host(model)
        _check_libcap_archive(model, directory)
        result = C35BReviewReceipt(_SOURCE, 6, 6, 1, 2, True, True)
        C35BReviewReceipt.__post_init__(result)
        return result
    except _CONTROL:
        raise
    except Exception:
        raise C35BLoaderHold(_ERROR) from None


# Section 6: Nonprivileged offline security tests for intentional HOLD.
class C35BReviewCases(unittest.TestCase):
    """Reject changed config, substituted archives and forged privileged trust."""

    def test_a_pinned_manifest_and_c35a_module_hashes(self) -> None:
        """Require the exact six native inputs and C35A inherited signed bytes."""
        m = _load_review()
        self.assertEqual(len(m["configs"]), 6)
        self.assertEqual(len(m["modules"]), 6)
        self.assertFalse(m["config_signed"])

    def test_b_manifest_hash_tamper_and_duplicate_keys(self) -> None:
        """No ambiguous or rewritten config snapshot can authorize a root path."""
        with patch(__name__ + "._MANIFEST_SHA", "0" * 64):
            with self.assertRaises(ValueError):
                _load_review()
        with self.assertRaises(ValueError):
            _distinct_pairs([("loader", "safe"), ("loader", "unsafe")])

    def test_c_nss_modified_resolution_and_missing_notfound_denied(self) -> None:
        """DNS/mDNS order and NOTFOUND=return must not silently drift."""
        data = b"hosts: files mdns4_minimal [NOTFOUND=return] dns\npasswd: files systemd\ngroup: files systemd\nshadow: files\nnetworks: files\nservices: db files\n"
        _inspect_nss(data)
        with self.assertRaises(ValueError):
            _inspect_nss(data.replace(b"[NOTFOUND=return]", b""))
        with self.assertRaises(ValueError):
            _inspect_nss(data.replace(b"files mdns4_minimal", b"dns mdns4_minimal"))

    def test_d_openssl_legacy_and_fips_activation_denied(self) -> None:
        """A new provider or config include requires separate root review."""
        base = b"openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\ndefault = default_sect\n"
        _inspect_openssl(base)
        for add in (b"legacy = legacy_sect\n", b"fips = fips_sect\n",
                    b".include /tmp/evil.cnf\n"):
            with self.subTest(add=add), self.assertRaises(ValueError):
                _inspect_openssl(base + add)

    def test_e_existing_root_owned_plugin_scope_not_complete(self) -> None:
        """The six ELF modules are metadata, not a complete runtime load trace."""
        data = _load_review()
        modules = {Path(x["path"]).name: x["needed"] for x in data["modules"]}
        self.assertIn("libcap.so.2", modules["libnss_systemd.so.2"])
        self.assertEqual(modules["libcap.so.2.66"], ["libc.so.6"])

    def test_f_no_forged_root_or_config_signature(self) -> None:
        """Even an independently signed libcap member cannot approve root."""
        receipt = C35BReviewReceipt(_SOURCE, 6, 6, 1, 2, True, True)
        for k in ("privileged_loader_config_signed",
                  "complete_dynamic_library_closure",
                  "protected_main_approved", "root_execution_approved"):
            with self.subTest(k=k), self.assertRaises(ValueError):
                replace(receipt, **{k: True})

    def test_g_archive_missing_does_not_reuse_prior_metadata(self) -> None:
        """Never turn C35A selected module hashes into a libcap acceptance."""
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises((ValueError, OSError)):
                _check_libcap_archive(_load_review(), Path(temp))


# Section 7: Explicit actual host audit; CI skips without signed artifacts.
@unittest.skipUnless(os.environ.get(_HOST_ENV), "no C35B signed archive staging requested")
class C35BActualSignedHostReview(unittest.TestCase):
    """Run read-only host config/ELF scan plus one signed libcap archive check."""

    def test_config_loader_closure_remains_hold(self) -> None:
        """A bounded native closure is verified, root authority remains denied."""
        result = review_c35b_host(Path(os.environ[_HOST_ENV]))
        self.assertTrue(result.signed_additional_libcap_verified)
        self.assertFalse(result.complete_dynamic_library_closure)
        self.assertFalse(result.privileged_loader_config_signed)
        print("C35B_LOADER_HOLD configs=6 modules=6 signed_extra_libcap=1 "
              "uncontrolled_search_dirs=2 config_signed=false "
              "complete_dynamic_loading=false root_approved=false")


if __name__ == "__main__":
    unittest.main()
