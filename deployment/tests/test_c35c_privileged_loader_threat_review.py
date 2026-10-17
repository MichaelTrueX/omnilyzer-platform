"""File: deployment/tests/test_c35c_privileged_loader_threat_review.py

Purpose: Model privilege isolation, native-library search path substitution,
environment injection and systemd-unit drift before any hypothetical C34O root
recovery execution. Bind a nonprivileged snapshot to existing C35B evidence.
Related: deployment/provenance/c35c-privileged-loader-threat-review.json,
deployment/tests/test_c35b_loader_config_dependency_review.py,
deployment/tests/test_c35a_signed_late_native_modules.py,
deployment/tests/test_c34w_installed_source_feasibility.py,
docs/operations/task014-c35c-privileged-loader-threat-review.md,
.github/workflows/task014-c34d-review.yml.

Offline CI checks JSON and synthetic attacks only. Host observation requires
OMNILYZER_C35C_HOST_READONLY=1 and reads files/metadata without executing any
inspected service, reading secrets or running as root. Results never authorize
a privileged launch, merge, deployment, promotion or systemd modifications.
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
import unittest
from unittest.mock import patch

from deployment.tests import test_c35b_loader_config_dependency_review as c35b
from deployment.tests import test_c34t_native_dependency_inventory as c34t


# Section 1: Historical snapshot and narrowly scoped non-authority.
_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "deployment/provenance/c35c-privileged-loader-threat-review.json"
_MANIFEST_DIGEST = "318d4911219e75875454a9661fe18f214b93e8e2f2fa27d8d2b3a238db50bff7"
_MANIFEST_SIZE = 4329
_PARENT_SHA = "66ecbf08296607a9cb7e07f492f49bd5544164dd383025de3653f72fadebc085"
_CANDIDATE = "300282c3a783b8acfbb1a76f2971d4354a3c5f69"
_GATE_ERROR = "C35C privileged loader threat-model review unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_OPT_IN = "OMNILYZER_C35C_HOST_READONLY"
_ALLOWED_ENV = {
    "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC",
}
_DANGEROUS_PREFIXES = ("LD_", "PYTHON", "OPENSSL_", "NSS_")
_DANGEROUS_EXACT = ("BASH_ENV", "ENV", "GCONV_PATH", "IFS", "LOCPATH")
_UNITS = (
    "/etc/systemd/system/omnilyzer-deployment-broker.service",
    "/etc/systemd/system/omnilyzer-deployment-executor.service",
    "/etc/systemd/system/omnilyzer-deployment-executor.service.d/rootless-docker-socket.conf",
    "/etc/systemd/system/omnilyzer-deployment-executor.socket",
)
_CONFIGS = (
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf",
    "/etc/ld.so.conf.d/libc.conf",
    "/etc/ld.so.conf.d/x86_64-linux-gnu.conf",
    "/etc/nsswitch.conf",
    "/etc/ssl/openssl.cnf",
)
_ROOT_LINKS = {"/lib": "usr/lib"}
_ABSENT_DIR = "/usr/local/lib/x86_64-linux-gnu"


class C35CPrivilegedHold(Exception):
    """One fail-closed review outcome without secret-bearing error messages."""


@dataclass(frozen=True, slots=True)
class C35CReviewReceipt:
    """Evidence for threat review only, never self-approving root launch."""

    candidate_commit: str
    service_file_snapshots: int
    native_config_snapshots: int
    observed_root_ancestor_entries: int
    observed_services_inactive: bool
    proposed_environment_model_verified: bool
    observed_directory_metadata_verified: bool
    actual_systemd_service_protections_transfer_to_root: bool = False
    privileged_environment_enforced: bool = False
    effective_loader_search_sealed: bool = False
    independently_signed_config_verified: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Make host-observed privilege and root authority unforgeably distinct."""
        if (
            self.candidate_commit != _CANDIDATE
            or type(self.service_file_snapshots) is not int
            or self.service_file_snapshots != 4
            or type(self.native_config_snapshots) is not int
            or self.native_config_snapshots != 7
            or type(self.observed_root_ancestor_entries) is not int
            or self.observed_root_ancestor_entries != 20
            or self.observed_services_inactive is not True
            or self.proposed_environment_model_verified is not True
            or self.observed_directory_metadata_verified is not True
            or self.actual_systemd_service_protections_transfer_to_root is not False
            or self.privileged_environment_enforced is not False
            or self.effective_loader_search_sealed is not False
            or self.independently_signed_config_verified is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_GATE_ERROR)


# Section 2: Stable historical JSON model, not a privileged trust anchor.
def _strict_pairs(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate JSON keys in every nested structure."""
    data = {}
    for key, value in pairs:
        if type(key) is not str or key in data:
            raise ValueError(_GATE_ERROR)
        data[key] = value
    return data


def _validate_snapshot(model: object) -> dict:
    """Reject changed source, unknown source paths or raised approval gates."""
    if type(model) is not dict or set(model) != {
        "kind", "schema_version", "candidate_commit", "parent_c35b_sha256",
        "systemd_unit_files", "root_directory_observations",
        "host_loader_config", "service_baseline",
        "dangerous_environment_name_prefixes", "dangerous_environment_exact",
        "proposed_privileged_env_allowlist", "root_launcher_installed",
        "unit_protections_transfer_to_root", "runtime_library_search_frozen",
        "protected_main_approved", "root_execution_approved",
    }:
        raise ValueError(_GATE_ERROR)
    if (
        model["kind"] != "task014-c35c-privileged-loader-threat-review-only"
        or type(model["schema_version"]) is not int
        or model["schema_version"] != 1
        or model["candidate_commit"] != _CANDIDATE
        or model["parent_c35b_sha256"] != _PARENT_SHA
        or model["root_launcher_installed"] is not False
        or model["unit_protections_transfer_to_root"] is not False
        or model["runtime_library_search_frozen"] is not False
        or model["protected_main_approved"] is not False
        or model["root_execution_approved"] is not False
        or model["dangerous_environment_name_prefixes"] != list(_DANGEROUS_PREFIXES)
        or model["dangerous_environment_exact"] != list(_DANGEROUS_EXACT)
        or model["proposed_privileged_env_allowlist"] != list(_ALLOWED_ENV)
        or type(model["systemd_unit_files"]) is not list
        or type(model["host_loader_config"]) is not list
        or type(model["root_directory_observations"]) is not list
        or tuple(item["path"] for item in model["systemd_unit_files"]) != _UNITS
        or tuple(item["path"] for item in model["host_loader_config"]) != _CONFIGS
        or len(model["root_directory_observations"]) != 20
        or model["service_baseline"] != {
            "broker_account": "omnilyzer-broker",
            "executor_account": "omnilyzer-executor",
            "systemd_unit_hardening_only": True,
            "both_services_observed_inactive": True,
        }
    ):
        raise ValueError(_GATE_ERROR)
    paths: set[str] = set()
    for item in model["systemd_unit_files"]:
        if type(item) is not dict or set(item) != {
            "path", "sha256", "size", "uid", "gid", "mode",
        }:
            raise ValueError(_GATE_ERROR)
        if (item["uid"] != 0 or item["gid"] != 0
                or item["mode"] != "0644"):
            raise ValueError(_GATE_ERROR)
        _check_hash_record(item)
    for item in model["host_loader_config"]:
        if type(item) is not dict or set(item) != {"path", "sha256", "size"}:
            raise ValueError(_GATE_ERROR)
        _check_hash_record(item)
    for item in model["root_directory_observations"]:
        if (type(item) is not dict or
                set(item) not in ({"path", "kind", "target"}, {
                    "path", "kind", "uid", "gid", "mode", "target",
                }) or item["path"] in paths):
            raise ValueError(_GATE_ERROR)
        paths.add(item["path"])
        kind = item["kind"]
        if kind == "absent":
            if item["path"] != _ABSENT_DIR or item["target"] is not None:
                raise ValueError(_GATE_ERROR)
        elif kind == "symlink":
            if set(item) != {"path", "kind", "uid", "gid", "mode", "target"}:
                raise ValueError(_GATE_ERROR)
            if (item["path"] not in _ROOT_LINKS
                    or item["target"] != _ROOT_LINKS[item["path"]]
                    or item["uid"] != 0 or item["gid"] != 0
                    or item["mode"] != "0o777"):
                raise ValueError(_GATE_ERROR)
        elif kind == "directory":
            if set(item) != {"path", "kind", "uid", "gid", "mode", "target"}:
                raise ValueError(_GATE_ERROR)
            if (item["target"] is not None
                    or item["uid"] != 0 or item["gid"] != 0
                    or item["mode"] != "0o755"):
                raise ValueError(_GATE_ERROR)
        else:
            raise ValueError(_GATE_ERROR)
    if {x["path"] for x in model["root_directory_observations"]} != {
        "/", "/etc", "/etc/systemd", "/etc/systemd/system",
        "/etc/ld.so.conf.d", "/etc/ssl", "/usr", "/usr/local",
        "/usr/local/lib", "/usr/local/lib/x86_64-linux-gnu",
        "/usr/lib", "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu/ossl-modules",
        "/opt", "/opt/omnilyzer", "/opt/omnilyzer/deployment",
        "/opt/omnilyzer/deployment/app",
        "/opt/omnilyzer/deployment/venv", "/lib",
        "/lib/x86_64-linux-gnu",
    }:
        raise ValueError(_GATE_ERROR)
    return model


def _check_hash_record(item: dict) -> None:
    """Require bounded independent data file hashes and nonzero byte lengths."""
    if (
        type(item["size"]) is not int or not 0 < item["size"] <= 200000
        or type(item["sha256"]) is not str
        or _SHA.fullmatch(item["sha256"]) is None
    ):
        raise ValueError(_GATE_ERROR)


def _load_snapshot() -> dict:
    """Pin exact immutable review bytes without inventing a release signature."""
    blob = _MANIFEST.read_bytes()
    if (len(blob) != _MANIFEST_SIZE
            or hashlib.sha256(blob).hexdigest() != _MANIFEST_DIGEST):
        raise ValueError(_GATE_ERROR)
    model = json.loads(blob, object_pairs_hook=_strict_pairs)
    _validate_snapshot(model)
    if hashlib.sha256(c35b._MANIFEST.read_bytes()).hexdigest() != _PARENT_SHA:
        raise ValueError(_GATE_ERROR)
    c35b._load_review()
    return model


# Section 3: Future environment contract is only a pure proposed model.
def proposed_minimal_root_environment(values: dict[str, str]) -> bool:
    """Reject unapproved inherited variables and modified trusted values."""
    if type(values) is not dict or set(values) != set(_ALLOWED_ENV):
        return False
    return all(
        type(key) is str and type(value) is str
        and not key.startswith(_DANGEROUS_PREFIXES)
        and key not in _DANGEROUS_EXACT
        and value == _ALLOWED_ENV[key]
        for key, value in values.items()
    )


# Section 4: Explicit root-parent and systemd-unit observations.
def _compare_root_path_state(snapshot: dict) -> None:
    """Validate observed parent ownership/symlinks, not future atomicity."""
    for item in snapshot["root_directory_observations"]:
        path = Path(item["path"])
        try:
            info = path.lstat()
        except FileNotFoundError:
            if item["kind"] == "absent":
                continue
            raise
        if item["kind"] == "absent":
            raise ValueError(_GATE_ERROR)
        if info.st_uid != 0 or info.st_gid != 0:
            raise ValueError(_GATE_ERROR)
        if item["kind"] == "symlink":
            if (not stat.S_ISLNK(info.st_mode)
                    or os.readlink(path) != item["target"]):
                raise ValueError(_GATE_ERROR)
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError(_GATE_ERROR)
        if oct(stat.S_IMODE(info.st_mode)) != item["mode"]:
            raise ValueError(_GATE_ERROR)


def _unit_properties(raw: bytes) -> dict[str, str]:
    """Collect limited service security directives, ignoring argument values."""
    lines = raw.decode("utf-8").splitlines()
    result: dict[str, str] = {}
    for line in lines:
        text = line.strip()
        if text.startswith(("#", "[")) or not text or "=" not in text:
            continue
        k, v = text.split("=", 1)
        if k in result:
            if k not in {"After", "Before", "Requires", "Wants",
                         "PartOf", "ReadWritePaths", "ReadOnlyPaths"}:
                raise ValueError(_GATE_ERROR)
            continue
        result[k] = v
    return result


def _compare_unit_hardening(model: dict) -> None:
    """Verify existing service safeguards WITHOUT transferring them to root."""
    for record in model["systemd_unit_files"]:
        path = Path(record["path"])
        if (c34t._hash_root_library(path) != record["sha256"]
                or path.stat().st_size != record["size"]):
            raise ValueError(_GATE_ERROR)
    for name, expected_user in (
        ("omnilyzer-deployment-broker.service", "omnilyzer-broker"),
        ("omnilyzer-deployment-executor.service", "omnilyzer-executor"),
    ):
        props = _unit_properties(Path("/etc/systemd/system", name).read_bytes())
        if (
            props.get("User") != expected_user
            or props.get("Group") != expected_user
            or props.get("UMask") != "0077"
            or props.get("NoNewPrivileges") != "yes"
            or props.get("ProtectSystem") != "strict"
            or props.get("ProtectHome") != "yes"
            or props.get("PrivateTmp") != "yes"
            or props.get("CapabilityBoundingSet") != ""
            or props.get("AmbientCapabilities") != ""
            or not props.get("ExecStart", "").startswith(
                "/opt/omnilyzer/deployment/venv/bin/python "
            )
        ):
            raise ValueError(_GATE_ERROR)
    for name in (
        "omnilyzer-deployment-broker.service",
        "omnilyzer-deployment-executor.service",
    ):
        drop = Path("/etc/systemd/system", name + ".d")
        if drop.exists():
            info = drop.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755):
                raise ValueError(_GATE_ERROR)
        actual = sorted(p.name for p in drop.iterdir()) if drop.is_dir() else []
        expected = [] if "broker" in name else ["rootless-docker-socket.conf"]
        if actual != expected:
            raise ValueError(_GATE_ERROR)


def _read_host_state(model: dict) -> None:
    """Read original metadata and status; never start/restart/stop any service."""
    _compare_root_path_state(model)
    _compare_unit_hardening(model)
    for item in model["host_loader_config"]:
        p = Path(item["path"])
        if (c34t._hash_root_library(p) != item["sha256"]
                or p.stat().st_size != item["size"]):
            raise ValueError(_GATE_ERROR)
    for unit in ("omnilyzer-deployment-broker.service",
                 "omnilyzer-deployment-executor.service"):
        result = subprocess.run(
            ("/usr/bin/systemctl", "is-active", unit),
            capture_output=True, timeout=8,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        if result.stdout.strip() != b"inactive" or result.returncode != 3:
            raise ValueError(_GATE_ERROR)


# Section 5: Always-HOLD result regardless of observational success.
def review_c35c_host() -> C35CReviewReceipt:
    """Establish bounded observations only, with false privileged authority."""
    try:
        model = _load_snapshot()
        if not proposed_minimal_root_environment(dict(_ALLOWED_ENV)):
            raise ValueError(_GATE_ERROR)
        _read_host_state(model)
        receipt = C35CReviewReceipt(
            _CANDIDATE, 4, 7, 20, True, True, True,
        )
        C35CReviewReceipt.__post_init__(receipt)
        return receipt
    except _CONTROL:
        raise
    except Exception:
        raise C35CPrivilegedHold(_GATE_ERROR) from None


# Section 6: CI-safe synthetic negative regression tests.
class C35CReviewContractTests(unittest.TestCase):
    """Protect review-only metadata, stop-state and environment boundaries."""

    def test_a_pinned_review_and_systemd_scope(self) -> None:
        """The exact six config observations and four units remain recorded."""
        model = _load_snapshot()
        self.assertEqual(len(model["systemd_unit_files"]), 4)
        self.assertEqual(len(model["host_loader_config"]), 7)
        self.assertFalse(model["root_execution_approved"])

    def test_b_snapshot_modification_and_duplicate_fields_fail(self) -> None:
        """Never accept a changed file or ambiguous nested JSON key."""
        with patch(__name__ + "._MANIFEST_DIGEST", "0" * 64):
            with self.assertRaises(ValueError):
                _load_snapshot()
        with self.assertRaises(ValueError):
            _strict_pairs([("root_execution_approved", False),
                           ("root_execution_approved", True)])

    def test_c_environment_poisoning_denied(self) -> None:
        """Model exact minimal env; reject each dangerous class and altered PATH."""
        self.assertTrue(proposed_minimal_root_environment(dict(_ALLOWED_ENV)))
        for key in (
            "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "PYTHONPATH",
            "PYTHONHOME", "OPENSSL_CONF", "OPENSSL_MODULES", "NSS_MODULES",
            "BASH_ENV", "ENV", "GCONV_PATH", "LOCPATH", "IFS",
        ):
            with self.subTest(key=key):
                self.assertFalse(proposed_minimal_root_environment(
                    dict(_ALLOWED_ENV, **{key: "/tmp/attacker"}),
                ))
        self.assertFalse(proposed_minimal_root_environment(
            dict(_ALLOWED_ENV, PATH="/tmp:/usr/bin"),
        ))

    def test_d_symlink_parent_and_extra_loader_dir_fail_closed(self) -> None:
        """Alternate root ancestors and unexpected absent-path creation deny GO."""
        model = _load_snapshot()
        forged = json.loads(json.dumps(model))
        ancestor = next(x for x in forged["root_directory_observations"]
                        if x["path"] == "/lib")
        ancestor["target"] = "/tmp/not-approved"
        with self.assertRaises(ValueError):
            _validate_snapshot(forged)
        forged = json.loads(json.dumps(model))
        absent = next(x for x in forged["root_directory_observations"]
                      if x["path"] == _ABSENT_DIR)
        absent["kind"] = "directory"
        with self.assertRaises(ValueError):
            _validate_snapshot(forged)

    def test_e_existing_service_protection_not_root_authority(self) -> None:
        """A hardened nonroot unit is not permission to launch root code."""
        receipt = C35CReviewReceipt(_CANDIDATE, 4, 7, 20, True, True, True)
        for flag in (
            "actual_systemd_service_protections_transfer_to_root",
            "privileged_environment_enforced", "effective_loader_search_sealed",
            "independently_signed_config_verified", "root_execution_approved",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                replace(receipt, **{flag: True})

    def test_f_stripped_unit_hardening_rejected(self) -> None:
        """Reject missing nonroot/sandbox directives in proposed fixtures."""
        minimal = b"User=omnilyzer-executor\nProtectSystem=strict\n"
        self.assertNotIn("NoNewPrivileges", _unit_properties(minimal))
        self.assertNotIn("CapabilityBoundingSet", _unit_properties(minimal))

    def test_g_manifest_does_not_declare_installed_launcher(self) -> None:
        """Remain explicit that no root launcher has been approved or installed."""
        model = _load_snapshot()
        self.assertFalse(model["root_launcher_installed"])
        self.assertFalse(model["runtime_library_search_frozen"])
        self.assertFalse(model["protected_main_approved"])


# Section 7: Nonprivileged host review, disabled by default in GitHub CI.
@unittest.skipUnless(os.environ.get(_OPT_IN) == "1",
                     "no C35C installed host read-only audit requested")
class C35CRealHostReview(unittest.TestCase):
    """Observe host snapshot against exact pins, with root permanently HOLD."""

    def test_nonroot_service_observation_keeps_root_hold(self) -> None:
        """Do not start stopped services or infer privileged execution rights."""
        receipt = review_c35c_host()
        self.assertIs(receipt.root_execution_approved, False)
        self.assertIs(receipt.effective_loader_search_sealed, False)
        print("C35C_PRIVILEGE_HOLD units=4 config_files=7 path_entries=20 "
              "services_inactive=true env_model_only=true "
              "root_launcher_installed=false loader_sealed=false "
              "root_approved=false")


if __name__ == "__main__":
    unittest.main()
