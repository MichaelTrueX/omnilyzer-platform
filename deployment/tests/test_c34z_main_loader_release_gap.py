"""File: deployment/tests/test_c34z_main_loader_release_gap.py

Purpose: Verify C34Z's exact protected-main-vs-95-file-candidate gap evidence,
reassess ALL 92 Python sources for direct dynamic loader/import patterns,
identify specifically observed NSS/OpenSSL late-loaded module gaps, and preserve
the separate broker diagnostic approval requirement.
Related: deployment/provenance/c34z-protected-main-gap-review.json,
deployment/provenance/c34y-service-recovery-source-review.json,
deployment/tests/test_c34y_service_recovery_manifest_review.py,
deployment/tests/test_c34x_service_recovery_source_reconciliation.py,
deployment/tests/test_c34v_privileged_import_seal.py,
deployment/tests/test_c34u_signed_external_native_provenance.py,
deployment/tests/test_c34e_diagnostic_events.py,
docs/operations/task014-c34z-protected-main-loader-gap.md,
.github/workflows/task014-c34d-review.yml.

CI tests are offline and review-only, reading immutable local HEAD Git blobs.
Only explicit C34Z_MAIN_GIT_READONLY=1 verifies retained local main Git blobs;
only C34Z_DYNAMIC_HOST_READONLY=1 inspects installed native plugin metadata.
No external fetch, application import, native plugin load, root, installation,
service action, OIDC change, promotion, merge or deployment.
"""

from __future__ import annotations

from collections import Counter
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

from deployment.tests import test_c34y_service_recovery_manifest_review as c34y
from deployment.tests import test_c34x_service_recovery_source_reconciliation as c34x
from deployment.tests import test_c34v_privileged_import_seal as c34v
from deployment.tests import test_c34t_native_dependency_inventory as c34t


# Section 1: Exact pinned historical evidence; no authority inferred.
_ROOT = Path(__file__).resolve().parents[2]
_SNAPSHOT = _ROOT / "deployment/provenance/c34z-protected-main-gap-review.json"
_SNAPSHOT_SHA = "b82fe038205c8e949135f54490d84688c20255ac9f83d14d263732bc7de3972f"
_SNAPSHOT_LENGTH = 15204
_CANDIDATE = "72c75914e307fa03105600874a10d69b0caae204"
_MAIN = "57919c3b9aca0cb98e85bbb26460f6267d093fa9"
_MAIN_TREE = "4a8d30bdb5827664ca650a19cd324377445f6eb4"
_C34Y_SHA = "d817404801ca9d7364a2aaadf0f120a19c49cb806f60692e3d8dae90de59e4a5"
_STATE_COUNTS = {"matching": 81, "different": 3, "missing": 11}
_MISSING = (
    "deployment/c34f_application_generation_evidence.py",
    "deployment/c34g_installed_predecessor_preflight.py",
    "deployment/c34g_migration_authority.py",
    "deployment/c34i_final_main_seal.py",
    "deployment/c34i_merged_migration_authority.py",
    "deployment/c34j_atomic_file_mechanics.py",
    "deployment/c34k_five_file_backup_barrier.py",
    "deployment/c34l_one_prefix_coordinator.py",
    "deployment/c34m_descriptor_source_observation.py",
    "deployment/c34n_root_predecessor_adapter.py",
    "deployment/c34o_six_prefix_recovery_inspection.py",
)
_LOADER_MODULES = {
    "/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so": "libssl3t64",
    "/usr/lib/x86_64-linux-gnu/libnss_dns.so.2": "libc6",
    "/usr/lib/x86_64-linux-gnu/libnss_files.so.2": "libc6",
    "/usr/lib/x86_64-linux-gnu/libnss_mdns_minimal.so.2": "libnss-mdns",
    "/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2": "libnss-systemd",
}
_FIXED_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
              "GIT_NO_LAZY_FETCH": "1"}
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_ERROR = "C34Z protected-main and late-loader review unavailable"


class C34ZReleaseHold(Exception):
    """Fail closed with one nonsecret message and no release-side effects."""


@dataclass(frozen=True, slots=True)
class C34ZReviewReceipt:
    """Strictly historical gap facts; never root or dynamic-loader authority."""

    candidate_source_commit: str
    observed_protected_main: str
    reviewed_source_and_resource_files: int
    matched_main: int
    missing_main: int
    differing_main: int
    full_candidate_python_source_files_reviewed: int
    explicit_python_loader_patterns: int
    sqlite_extension_disables: int
    known_late_native_module_candidates: int
    main_git_replay_observed: bool
    native_module_metadata_observed: bool
    protected_main_source_complete: bool = False
    late_native_modules_signed_verified: bool = False
    diagnostics_behavior_approved: bool = False
    root_owned_source_and_loader_sealed: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Keep the 11 missing modules and all authorization flags blocked."""
        if (
            self.candidate_source_commit != _CANDIDATE
            or self.observed_protected_main != _MAIN
            or type(self.reviewed_source_and_resource_files) is not int
            or self.reviewed_source_and_resource_files != 95
            or type(self.matched_main) is not int or self.matched_main != 81
            or type(self.missing_main) is not int or self.missing_main != 11
            or type(self.differing_main) is not int or self.differing_main != 3
            or type(self.full_candidate_python_source_files_reviewed) is not int
            or self.full_candidate_python_source_files_reviewed != 92
            or type(self.explicit_python_loader_patterns) is not int
            or self.explicit_python_loader_patterns != 0
            or type(self.sqlite_extension_disables) is not int
            or self.sqlite_extension_disables != 3
            or type(self.known_late_native_module_candidates) is not int
            or self.known_late_native_module_candidates != 5
            or type(self.main_git_replay_observed) is not bool
            or type(self.native_module_metadata_observed) is not bool
            or self.protected_main_source_complete is not False
            or self.late_native_modules_signed_verified is not False
            or self.diagnostics_behavior_approved is not False
            or self.root_owned_source_and_loader_sealed is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


# Section 2: The immutable main snapshot is a REVIEW, not signing evidence.
def _distinct_json_keys(items: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous duplicate JSON keys, including nested entry objects."""
    result: dict[str, object] = {}
    for key, value in items:
        if key in result or type(key) is not str:
            raise ValueError(_ERROR)
        result[key] = value
    return result


def _validate_snapshot(model: object) -> tuple[dict, ...]:
    """Check main status for every C34Y source/resource path and exact gap sets."""
    if type(model) is not dict or set(model) != {
        "schema_version", "kind", "candidate_review_commit",
        "protected_main_observed_commit", "protected_main_tree",
        "c34y_manifest_sha256", "main_attested_as_release",
        "root_execution_approved", "entries",
    }:
        raise ValueError(_ERROR)
    if (
        type(model["schema_version"]) is not int or model["schema_version"] != 1
        or model["kind"] != "task014-c34z-protected-main-gap-review-only"
        or model["candidate_review_commit"] != _CANDIDATE
        or model["protected_main_observed_commit"] != _MAIN
        or model["protected_main_tree"] != _MAIN_TREE
        or model["c34y_manifest_sha256"] != _C34Y_SHA
        or model["main_attested_as_release"] is not False
        or model["root_execution_approved"] is not False
        or type(model["entries"]) is not list or len(model["entries"]) != 95
    ):
        raise ValueError(_ERROR)
    expected = {item["path"]: item for item in c34y._load_manifest()}
    entries = tuple(model["entries"])
    if tuple(item.get("path") for item in entries) != tuple(sorted(expected)):
        raise ValueError(_ERROR)
    for item in entries:
        if type(item) is not dict or set(item) != {
            "path", "protected_main_sha256", "status",
        }:
            raise ValueError(_ERROR)
        status = item["status"]
        sha = item["protected_main_sha256"]
        if (
            status not in _STATE_COUNTS
            or (status == "missing") != (sha is None)
            or (sha is not None and (
                type(sha) is not str or re.fullmatch(r"[a-f0-9]{64}", sha) is None
            ))
            or (status == "matching"
                and sha != expected[item["path"]]["sha256"])
            or (status == "different"
                and sha == expected[item["path"]]["sha256"])
        ):
            raise ValueError(_ERROR)
    if Counter(x["status"] for x in entries) != _STATE_COUNTS:
        raise ValueError(_ERROR)
    if tuple(x["path"] for x in entries if x["status"] == "missing") != _MISSING:
        raise ValueError(_ERROR)
    if tuple(x["path"] for x in entries if x["status"] == "different") != tuple(
        sorted(c34x._PREVIOUS)
    ):
        raise ValueError(_ERROR)
    return entries


def _load_snapshot() -> tuple[dict, ...]:
    """Accept only the exact retained C34Z review, never an inferred main SHA."""
    data = _SNAPSHOT.read_bytes()
    if (
        len(data) != _SNAPSHOT_LENGTH
        or hashlib.sha256(data).hexdigest() != _SNAPSHOT_SHA
    ):
        raise ValueError(_ERROR)
    return _validate_snapshot(json.loads(
        data, object_pairs_hook=_distinct_json_keys,
    ))


# Section 3: Optional exact Git protected-main object replay, no fetch/network.
def _git_blob(revision: str, name: str) -> bytes | None:
    """Return immutable Git bytes or missing; no lazy fetch or checkout."""
    if (
        revision not in (_MAIN, _CANDIDATE)
        or type(name) is not str
        or not (
            c34y.c34w._LOCAL_PY.fullmatch(name) is not None
            or name in c34x._RESOURCE
        )
    ):
        raise ValueError(_ERROR)
    listing = subprocess.run(
        ("git", "ls-tree", "-r", "--name-only", revision, "--", name),
        cwd=_ROOT, capture_output=True, check=True, timeout=10,
        env=_FIXED_ENV,
    ).stdout
    if listing == b"":
        return None
    if listing != (name + "\n").encode():
        raise ValueError(_ERROR)
    return subprocess.run(
        ("git", "cat-file", "blob", revision + ":" + name),
        cwd=_ROOT, capture_output=True, check=True, timeout=10,
        env=_FIXED_ENV,
    ).stdout


def _replay_protected_main(entries: tuple[dict, ...]) -> None:
    """Compare every reviewed main object against its pinned historical snapshot."""
    tree = subprocess.run(
        ("git", "rev-parse", _MAIN + "^{tree}"),
        cwd=_ROOT, check=True, capture_output=True, text=True,
        timeout=10, env=_FIXED_ENV,
    ).stdout.strip()
    if tree != _MAIN_TREE:
        raise ValueError(_ERROR)
    wanted = {x["path"]: x for x in c34y._load_manifest()}
    for entry in entries:
        actual_main = _git_blob(_MAIN, entry["path"])
        main_digest = (
            hashlib.sha256(actual_main).hexdigest()
            if actual_main is not None else None
        )
        if main_digest != entry["protected_main_sha256"]:
            raise ValueError(_ERROR)
        candidate = _git_blob(_CANDIDATE, entry["path"])
        if (
            candidate is None
            or hashlib.sha256(candidate).hexdigest()
            != wanted[entry["path"]]["sha256"]
        ):
            raise ValueError(_ERROR)


# Section 4: Explicit complete candidate Python static loader-pattern coverage.
def _candidate_source_loader_scan() -> tuple[int, int, int]:
    """Inspect exact current HEAD 92-source manifest bytes as AST, not imports."""
    entries = c34y._load_manifest()
    issues = 0
    sqlite_disables = 0
    source_count = 0
    for entry in entries:
        if entry["scope"] == "runtime_resource":
            continue
        raw = c34y._candidate_blob_at_head(entry["path"])
        if (
            len(raw) != entry["size"]
            or hashlib.sha256(raw).hexdigest() != entry["sha256"]
        ):
            raise ValueError(_ERROR)
        findings, disabled = c34v._static_dynamic_loader_findings(
            raw, entry["path"],
        )
        if findings:
            issues += len(findings)
        sqlite_disables += disabled
        source_count += 1
    if source_count != 92 or issues != 0 or sqlite_disables != 3:
        raise ValueError(_ERROR)
    return source_count, issues, sqlite_disables


# Section 5: Opt-in native plugin metadata inventory; NOT package signatures.
def _native_plugin_metadata_observed() -> None:
    """Read five known late-load candidates without loading or hashing them."""
    for raw, expected_package in sorted(_LOADER_MODULES.items()):
        path = Path(raw)
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o644
            or not 0 < info.st_size <= 10_000_000
        ):
            raise ValueError(_ERROR)
        if path.name in c34t._NAMES:
            raise ValueError(_ERROR)
        result = subprocess.run(
            ("/usr/bin/dpkg-query", "-S", raw),
            env=_FIXED_ENV, capture_output=True, timeout=10,
            check=True,
        )
        if not result.stdout.startswith(
            (expected_package + ":").encode()
        ):
            raise ValueError(_ERROR)


# Section 6: Non-authorizing audit orchestration with explicit optional checks.
def review_release_gaps(
    *, replay_main: bool = False, inspect_native: bool = False,
) -> C34ZReviewReceipt:
    """Return reviewed missing-gate evidence, never protected-main approval."""
    try:
        if type(replay_main) is not bool or type(inspect_native) is not bool:
            raise ValueError
        entries = _load_snapshot()
        c34y._verify_related_manifests()
        c34y._verify_candidate_sources(c34y._load_manifest())
        source_count, issues, sqlite = _candidate_source_loader_scan()
        if replay_main:
            _replay_protected_main(entries)
        if inspect_native:
            _native_plugin_metadata_observed()
        return C34ZReviewReceipt(
            candidate_source_commit=_CANDIDATE,
            observed_protected_main=_MAIN,
            reviewed_source_and_resource_files=95,
            matched_main=81, missing_main=11, differing_main=3,
            full_candidate_python_source_files_reviewed=source_count,
            explicit_python_loader_patterns=issues,
            sqlite_extension_disables=sqlite,
            known_late_native_module_candidates=5,
            main_git_replay_observed=replay_main,
            native_module_metadata_observed=inspect_native,
        )
    except _CONTROL:
        raise
    except Exception:
        raise C34ZReleaseHold(_ERROR) from None


# Section 7: CI-safe negatives and exact candidate review.
class C34ZGapContracts(unittest.TestCase):
    """Missing root approval, native proof and diagnostics cannot be fabricated."""

    def test_a_review_snapshot_is_pinned_and_complete(self) -> None:
        """Validate 95 historical protected-main statuses and three divergence IDs."""
        entries = _load_snapshot()
        self.assertEqual(Counter(x["status"] for x in entries), _STATE_COUNTS)

    def test_b_manifest_tampering_and_ambiguous_json_rejected(self) -> None:
        """Reject altered pins, duplicate keys and unauthorized status upgrades."""
        with patch(__name__ + "._SNAPSHOT_SHA", "0" * 64):
            with self.assertRaises(ValueError):
                _load_snapshot()
        with self.assertRaises(ValueError):
            _distinct_json_keys([("status", "missing"), ("status", "matching")])
        model = json.loads(_SNAPSHOT.read_bytes())
        item = next(x for x in model["entries"] if x["status"] == "missing")
        item["status"] = "matching"
        with self.assertRaises(ValueError):
            _validate_snapshot(model)

    def test_c_no_missing_module_may_be_claimed_as_in_main(self) -> None:
        """Fail closed on reclassifying any C34O missing protected-main file."""
        model = json.loads(_SNAPSHOT.read_bytes())
        item = next(x for x in model["entries"] if x["status"] == "missing")
        item["protected_main_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            _validate_snapshot(model)

    def test_d_all_92_sources_undergo_loader_syntax_review(self) -> None:
        """Recovery-only C34V scan was not enough; include service-only modules."""
        self.assertEqual(_candidate_source_loader_scan(), (92, 0, 3))
        with patch.object(
            c34v, "_static_dynamic_loader_findings",
            return_value=(("unsafe-native-import",), 0),
        ):
            with self.assertRaises(ValueError):
                _candidate_source_loader_scan()

    def test_e_all_five_late_native_modules_outside_static_scope(self) -> None:
        """Installed native provider presence never implies signed provenance."""
        self.assertEqual(len(_LOADER_MODULES), 5)
        self.assertTrue(all(
            Path(path).name not in c34t._NAMES
            for path in _LOADER_MODULES
        ))

    def test_f_diagnostic_source_changes_unapproved(self) -> None:
        """Six pinned historical/draft source pairs still require approval."""
        self.assertEqual(
            tuple(sorted(c34x._PREVIOUS)),
            ("deployment/broker.py", "deployment/broker_https_ingress.py",
             "deployment/broker_integration.py"),
        )
        self.assertEqual(len(c34x._PREVIOUS), 3)

    def test_g_authority_flags_unforgeable(self) -> None:
        """No review completeness or plugin observation can authorize root."""
        result = C34ZReviewReceipt(
            _CANDIDATE, _MAIN, 95, 81, 11, 3, 92, 0, 3, 5, False, False,
        )
        for flag in (
            "protected_main_source_complete",
            "late_native_modules_signed_verified",
            "diagnostics_behavior_approved",
            "root_owned_source_and_loader_sealed",
            "root_execution_approved",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                replace(result, **{flag: True})

    def test_h_candidate_git_head_is_exactly_scanned(self) -> None:
        """Verify all 95 current candidate Git blobs and emit one scoped receipt."""
        receipt = review_release_gaps()
        self.assertEqual(receipt.missing_main, 11)
        self.assertEqual(receipt.differing_main, 3)
        self.assertFalse(receipt.root_execution_approved)
        print("C34Z_REVIEW_HOLD candidate=95 main_matching=81 "
              "main_missing=11 main_differing=3 python_sources=92 "
              "explicit_loader_findings=0 late_modules=5 root_approved=false")


# Section 8: Real nonprivileged main replay, disabled by default.
@unittest.skipUnless(
    os.environ.get("C34Z_MAIN_GIT_READONLY") == "1",
    "no historical protected-main Git-object replay requested",
)
class C34ZMainObjectReplay(unittest.TestCase):
    """Audit locally retained main commit and candidate blobs, no Git fetch."""

    def test_main_snapshot_exact_object_replay(self) -> None:
        """Confirms historical source gap but does NOT approve protected main."""
        receipt = review_release_gaps(replay_main=True)
        self.assertTrue(receipt.main_git_replay_observed)
        self.assertFalse(receipt.protected_main_source_complete)
        print("C34Z_MAIN_HOLD matched=81 missing=11 differing=3 "
              "release_attested=false")


@unittest.skipUnless(
    os.environ.get("C34Z_DYNAMIC_HOST_READONLY") == "1",
    "no host native-module metadata inspection requested",
)
class C34ZNativeMetadataReplay(unittest.TestCase):
    """Inspect only known native provider metadata; no binary execution."""

    def test_observed_native_modules_outside_c34u_static_set(self) -> None:
        """Plugin owner labels are NOT independently signed archive content."""
        receipt = review_release_gaps(inspect_native=True)
        self.assertTrue(receipt.native_module_metadata_observed)
        self.assertFalse(receipt.late_native_modules_signed_verified)
        print("C34Z_NATIVE_HOLD late_module_candidates=5 "
              "signed_plugin_provenance=false")


if __name__ == "__main__":
    unittest.main()
