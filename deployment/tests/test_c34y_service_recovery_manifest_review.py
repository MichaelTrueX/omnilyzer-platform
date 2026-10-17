"""File: deployment/tests/test_c34y_service_recovery_manifest_review.py

Purpose: Review an exact, non-destructive 92-Python-source and three-resource
candidate package inventory; bind all intended files to Git source bytes and
existing installed-service observations without building a privileged package.
Linked files: deployment/provenance/c34y-service-recovery-source-review.json,
deployment/tests/test_c34x_service_recovery_source_reconciliation.py,
deployment/tests/test_c34w_installed_source_feasibility.py,
deployment/c34p_dependency_source_closure.py,
deployment/provenance/python-runtime-py312-linux-x86_64-installed.json,
deployment/provenance/c34u-external-native-package-set.json,
docs/operations/task014-c34y-source-resource-manifest-review.md,
.github/workflows/task014-c34d-review.yml.

Tests are read-only and nonprivileged. Inspected source modules are never
imported. Actual installed-source replay requires the explicit environment
flag OMNILYZER_C34Y_HOST_READONLY=1. No installer, root, deployment, service,
config, OIDC, token, wheel, native loader or migration operation is performed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch

from deployment.tests import test_c34w_installed_source_feasibility as c34w
from deployment.tests import test_c34x_service_recovery_source_reconciliation as c34x


# Section 1: Fixed manifest review constraints, not installer authority.
_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "deployment/provenance/c34y-service-recovery-source-review.json"
_MANIFEST_SHA256 = "d817404801ca9d7364a2aaadf0f120a19c49cb806f60692e3d8dae90de59e4a5"
_MANIFEST_SIZE = 26640
_SOURCE_COMMIT = "482ab09ca3350c37a025720a4d28e796507819b0"
_VENV_MANIFEST = _ROOT / "deployment/provenance/python-runtime-py312-linux-x86_64-installed.json"
_VENV_SHA256 = "3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b"
_NATIVE_MANIFEST = _ROOT / "deployment/provenance/c34u-external-native-package-set.json"
_NATIVE_SHA256 = "c59040077ca8829aaf2758d47c9dea4bc9d25a771ab3c27d75a59c853de57b0c"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ERR = "C34Y reviewed source and resource manifest is unavailable"
_RESOURCE = frozenset(c34x._RESOURCE)
_EXPLICIT_HOST = "OMNILYZER_C34Y_HOST_READONLY"
_COUNT_SCOPE = {
    "service_and_recovery": 19,
    "service_only": 19,
    "recovery_only": 54,
    "runtime_resource": 3,
}
_COUNT_STATE = {"matching": 38, "absent": 54, "divergent": 3}
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class C34YManifestHold(Exception):
    """Use one nonsecret fail-closed response for manifest or host drift."""


@dataclass(frozen=True, slots=True)
class C34YReviewReceipt:
    """Scoped review result. Never become a root/production installation seal."""

    reviewed_source_commit: str
    source_paths: int
    runtime_resources: int
    installed_service_sources: int
    absent_recovery_sources: int
    installed_divergent_sources: int
    candidate_git_objects_match: bool
    dependency_manifests_pinned: bool
    installed_snapshot_reconciled: bool
    root_owned_package_created: bool = False
    conflicting_service_modules_approved: bool = False
    complete_dynamic_loading_verified: bool = False
    protected_main_attested: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Make incorrect counts, inferred approvals and self-sealing impossible."""
        if (
            self.reviewed_source_commit != _SOURCE_COMMIT
            or type(self.source_paths) is not int or self.source_paths != 92
            or type(self.runtime_resources) is not int or self.runtime_resources != 3
            or type(self.installed_service_sources) is not int
            or self.installed_service_sources != 38
            or type(self.absent_recovery_sources) is not int
            or self.absent_recovery_sources != 54
            or type(self.installed_divergent_sources) is not int
            or self.installed_divergent_sources != 3
            or self.candidate_git_objects_match is not True
            or self.dependency_manifests_pinned is not True
            or type(self.installed_snapshot_reconciled) is not bool
            or self.root_owned_package_created is not False
            or self.conflicting_service_modules_approved is not False
            or self.complete_dynamic_loading_verified is not False
            or self.protected_main_attested is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERR)


# Section 2: Strict deterministic manifest parsing and source-set accounting.
def _unique_keys(items: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON fields rather than last-field-wins parsing."""
    result: dict[str, object] = {}
    for key, value in items:
        if type(key) is not str or key in result:
            raise ValueError(_ERR)
        result[key] = value
    return result


def _validate_entry(entry: object) -> None:
    """Enforce exact path/mode/ownership/state/hash for a proposed review item."""
    if type(entry) is not dict or set(entry) != {
        "path", "scope", "size", "sha256", "mode", "uid", "gid",
        "installed_state", "installed_sha256",
    }:
        raise ValueError(_ERR)
    path = entry["path"]
    if (
        type(path) is not str
        or not (
            c34w._LOCAL_PY.fullmatch(path) is not None
            or path in _RESOURCE
        )
        or type(entry["scope"]) is not str
        or entry["scope"] not in _COUNT_SCOPE
        or (entry["scope"] == "runtime_resource") != (path in _RESOURCE)
        or type(entry["size"]) is not int or not 0 < entry["size"] <= 1024 * 1024
        or type(entry["sha256"]) is not str
        or _SHA.fullmatch(entry["sha256"]) is None
        or entry["mode"] != "0644"
        or type(entry["uid"]) is not int or entry["uid"] != 0
        or type(entry["gid"]) is not int or entry["gid"] != 0
        or entry["installed_state"] not in _COUNT_STATE
    ):
        raise ValueError(_ERR)
    observed = entry["installed_sha256"]
    if (
        (entry["installed_state"] == "absent") != (observed is None)
        or (observed is not None and (
            type(observed) is not str or _SHA.fullmatch(observed) is None
        ))
        or (entry["installed_state"] == "matching"
            and observed != entry["sha256"])
        or (entry["installed_state"] == "divergent"
            and observed == entry["sha256"])
        or (entry["scope"] in ("runtime_resource", "service_and_recovery",
                              "service_only")
            and entry["installed_state"] == "absent")
        or (entry["scope"] == "recovery_only"
            and entry["installed_state"] != "absent")
    ):
        raise ValueError(_ERR)


def _validate_manifest(model: object) -> tuple[dict, ...]:
    """Check exact structural and aggregate facts, with no host-derived defaults."""
    if type(model) is not dict or set(model) != {
        "schema_version", "kind", "candidate_git_sha", "application_root",
        "virtualenv_root", "expected_installation_sources",
        "expected_recovery_sources", "expected_source_union",
        "expected_runtime_resources", "dependency_manifest_sha256",
        "signed_native_manifest_sha256", "root_execution_approved", "entries",
    }:
        raise ValueError(_ERR)
    if (
        type(model["schema_version"]) is not int or model["schema_version"] != 1
        or model["kind"] != "task014-c34y-unapproved-source-resource-review"
        or model["candidate_git_sha"] != _SOURCE_COMMIT
        or model["application_root"] != str(c34w._SOURCE_ROOT)
        or model["virtualenv_root"] != str(c34w._VENV)
        or model["dependency_manifest_sha256"] != _VENV_SHA256
        or model["signed_native_manifest_sha256"] != _NATIVE_SHA256
        or model["root_execution_approved"] is not False
        or type(model["expected_installation_sources"]) is not int
        or model["expected_installation_sources"] != 38
        or type(model["expected_recovery_sources"]) is not int
        or model["expected_recovery_sources"] != 73
        or type(model["expected_source_union"]) is not int
        or model["expected_source_union"] != 92
        or type(model["expected_runtime_resources"]) is not int
        or model["expected_runtime_resources"] != 3
        or type(model["entries"]) is not list
        or len(model["entries"]) != 95
    ):
        raise ValueError(_ERR)
    entries = tuple(model["entries"])
    for entry in entries:
        _validate_entry(entry)
    paths = tuple(x["path"] for x in entries)
    if paths != tuple(sorted(set(paths))):
        raise ValueError(_ERR)
    if Counter(x["scope"] for x in entries) != _COUNT_SCOPE:
        raise ValueError(_ERR)
    if Counter(x["installed_state"] for x in entries) != _COUNT_STATE:
        raise ValueError(_ERR)
    divergent = {
        x["path"]: (x["installed_sha256"], x["sha256"])
        for x in entries if x["installed_state"] == "divergent"
    }
    if divergent != c34x._PREVIOUS:
        raise ValueError(_ERR)
    if {x["path"] for x in entries
        if x["scope"] == "runtime_resource"} != _RESOURCE:
        raise ValueError(_ERR)
    return entries


def _load_manifest() -> tuple[dict, ...]:
    """Bind this exact reviewed manifest to independently pinned file bytes."""
    raw = _MANIFEST.read_bytes()
    if (
        len(raw) != _MANIFEST_SIZE
        or hashlib.sha256(raw).hexdigest() != _MANIFEST_SHA256
    ):
        raise ValueError(_ERR)
    model = json.loads(raw, object_pairs_hook=_unique_keys)
    return _validate_manifest(model)


# Section 3: Immutable Git object verification, but NOT GitHub main attestation.
def _candidate_blob_at_head(name: str) -> bytes:
    """Read HEAD Git blob, disallow network object fetch and path substitution."""
    if not (
        type(name) is str
        and (c34w._LOCAL_PY.fullmatch(name) is not None or name in _RESOURCE)
    ):
        raise ValueError(_ERR)
    return subprocess.run(
        ("git", "cat-file", "blob", "HEAD:" + name),
        cwd=_ROOT, capture_output=True, check=True, timeout=10,
        env=dict(os.environ, GIT_NO_LAZY_FETCH="1"),
    ).stdout


def _verify_candidate_sources(entries: tuple[dict, ...]) -> None:
    """Verify all 95 Git blobs and independent C34P recovery-source membership."""
    expected_names = {x["path"] for x in entries}
    source_entries = {
        x["path"]: x for x in entries if x["scope"] != "runtime_resource"
    }
    sha, recovered = c34w._git_candidate_review()
    if sha != subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=_ROOT, text=True,
    ).strip():
        raise ValueError(_ERR)
    if len(recovered) != 73 or len(source_entries) != 92:
        raise ValueError(_ERR)
    for record in entries:
        raw = _candidate_blob_at_head(record["path"])
        if (
            len(raw) != record["size"]
            or hashlib.sha256(raw).hexdigest() != record["sha256"]
        ):
            raise ValueError(_ERR)
        should_recover = record["scope"] in (
            "recovery_only", "service_and_recovery",
        )
        if should_recover != (record["path"] in recovered):
            raise ValueError(_ERR)
        if should_recover and recovered[record["path"]] != record["sha256"]:
            raise ValueError(_ERR)
    service = {
        x["path"] for x in entries if x["scope"] in (
            "service_only", "service_and_recovery",
        )
    }
    if len(service) != 38 or not set(c34x._SERVICE_ENTRIES) <= service:
        raise ValueError(_ERR)
    if len(expected_names) != 95 or not set(c34x._RESOURCE) <= expected_names:
        raise ValueError(_ERR)


def _verify_related_manifests() -> None:
    """Pin existing C31A virtualenv and C34U signed native provenance inputs."""
    for path, pin in (
        (_VENV_MANIFEST, _VENV_SHA256),
        (_NATIVE_MANIFEST, _NATIVE_SHA256),
    ):
        if hashlib.sha256(path.read_bytes()).hexdigest() != pin:
            raise ValueError(_ERR)


# Section 4: Opt-in installed-source replay; absent C34O files stay absent.
def _verify_installed_snapshot(entries: tuple[dict, ...]) -> None:
    """Fail closed on source/resource drift; do not accept any installation."""
    installed = c34w._installed_python_sources()
    resources = c34x._installed_resource_hashes()
    observed = installed | resources
    expected_installed = {
        x["path"] for x in entries if x["installed_state"] != "absent"
    }
    if (
        set(observed) != expected_installed
        or len(installed) != 38
        or len(resources) != 3
    ):
        raise ValueError(_ERR)
    for record in entries:
        actual = observed.get(record["path"])
        if actual != record["installed_sha256"]:
            raise ValueError(_ERR)
    audit = c34x.observe_readonly_c34x_service_recovery_reconciliation()
    if (
        audit.proposed_union_count != 92
        or audit.candidate_installed_conflicts != tuple(sorted(c34x._PREVIOUS))
        or audit.root_execution_approved is not False
    ):
        raise ValueError(_ERR)


def review_candidate_manifest(*, audit_installed: bool = False) -> C34YReviewReceipt:
    """Return only a review receipt, never an installation or root approval."""
    try:
        if type(audit_installed) is not bool:
            raise ValueError
        entries = _load_manifest()
        _verify_related_manifests()
        _verify_candidate_sources(entries)
        if audit_installed:
            _verify_installed_snapshot(entries)
        result = C34YReviewReceipt(
            reviewed_source_commit=_SOURCE_COMMIT,
            source_paths=92, runtime_resources=3,
            installed_service_sources=38,
            absent_recovery_sources=54, installed_divergent_sources=3,
            candidate_git_objects_match=True,
            dependency_manifests_pinned=True,
            installed_snapshot_reconciled=audit_installed,
        )
        C34YReviewReceipt.__post_init__(result)
        return result
    except _CONTROL:
        raise
    except Exception:
        raise C34YManifestHold(_ERR) from None


# Section 5: Offline/pure negative tests and exact candidate Git source audit.
class C34YManifestSafetyTests(unittest.TestCase):
    """Ensure a review manifest cannot be silently mutated or promoted to root."""

    def test_a_manifest_exactly_pinned_and_reconciled(self) -> None:
        """Check exact 95 records, membership and pinned review-only status."""
        entries = _load_manifest()
        self.assertEqual(len(entries), 95)
        self.assertEqual(
            Counter(x["scope"] for x in entries), _COUNT_SCOPE,
        )

    def test_b_changed_manifest_bytes_and_duplicate_keys_fail(self) -> None:
        """Reject changed authority pin and duplicate-key JSON ambiguity."""
        with patch(__name__ + "._MANIFEST_SHA256", "0" * 64):
            with self.assertRaises(ValueError):
                _load_manifest()
        with self.assertRaises(ValueError):
            json.loads('{"path":"a","path":"b"}',
                       object_pairs_hook=_unique_keys)

    def test_c_extra_missing_path_and_symlink_ownership_rejected(self) -> None:
        """Path substitution, incorrect owner or symlink mode cannot be accepted."""
        entry = dict(_load_manifest()[0])
        for name, value in (
            ("path", "deployment/../malicious.py"),
            ("size", 0),
            ("mode", "0777"),
            ("uid", 1005),
            ("gid", 1005),
            ("sha256", "0" * 63),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                _validate_entry(dict(entry, **{name: value}))

    def test_d_status_forgery_does_not_approve_missing_files(self) -> None:
        """Installed-state/sha mismatch or scope substitution must fail."""
        records = _load_manifest()
        absent = next(x for x in records
                      if x["installed_state"] == "absent")
        with self.assertRaises(ValueError):
            _validate_entry(dict(absent, installed_state="matching"))
        divergent = next(x for x in records
                         if x["installed_state"] == "divergent")
        with self.assertRaises(ValueError):
            _validate_entry(dict(divergent, installed_sha256=divergent["sha256"]))
        with self.assertRaises(ValueError):
            _validate_entry(dict(divergent, scope="recovery_only"))

    def test_e_bad_counts_or_missing_live_service_fail_closed(self) -> None:
        """Never drop a service module or accept a 73-file recovery-only output."""
        original = json.loads(_MANIFEST.read_bytes())
        original["entries"] = [
            x for x in original["entries"]
            if x["path"] != "deployment/executor_service_entrypoint.py"
        ]
        with self.assertRaises(ValueError):
            _validate_manifest(original)

    def test_f_dependencies_and_root_authorization_are_independent(self) -> None:
        """Review cannot infer approval from pinned C31A/C34U evidence."""
        receipt = C34YReviewReceipt(
            reviewed_source_commit=_SOURCE_COMMIT,
            source_paths=92, runtime_resources=3,
            installed_service_sources=38,
            absent_recovery_sources=54,
            installed_divergent_sources=3,
            candidate_git_objects_match=True,
            dependency_manifests_pinned=True,
            installed_snapshot_reconciled=False,
        )
        for key in (
            "root_owned_package_created",
            "conflicting_service_modules_approved",
            "complete_dynamic_loading_verified",
            "protected_main_attested",
            "root_execution_approved",
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                replace(receipt, **{key: True})

    def test_g_source_blob_substitution_fails_closed(self) -> None:
        """Even valid-size stale Git object substitutions require re-review."""
        original = _candidate_blob_at_head
        def substituted(name: str) -> bytes:
            """Change one reviewed blob without editing Git or the filesystem."""
            raw = original(name)
            if name == "deployment/broker.py":
                return b"x" + raw[1:]
            return raw
        with patch(__name__ + "._candidate_blob_at_head", substituted):
            with self.assertRaises(C34YManifestHold):
                review_candidate_manifest()

    def test_h_exact_git_candidate_and_dependencies_revalidated(self) -> None:
        """Verify all 95 current Git objects against pinned review manifest."""
        receipt = review_candidate_manifest()
        self.assertFalse(receipt.installed_snapshot_reconciled)
        self.assertFalse(receipt.root_execution_approved)
        print("C34Y_MANIFEST_REVIEW_PASS sources=92 resources=3 "
              "candidate_objects=95 installed_verified=false root_approved=false")


# Section 6: Explicit nonprivileged real-host audit, skipped in normal CI.
@unittest.skipUnless(
    os.environ.get(_EXPLICIT_HOST) == "1",
    "no C34Y installed-host read-only replay requested",
)
class C34YRealHostReplay(unittest.TestCase):
    """Compare pinned manifest with existing root-owned installed bytes."""

    def test_installed_snapshot_remains_hold(self) -> None:
        """Observed matching review inputs are not installation authority."""
        receipt = review_candidate_manifest(audit_installed=True)
        self.assertTrue(receipt.installed_snapshot_reconciled)
        self.assertFalse(receipt.root_execution_approved)
        print("C34Y_HOST_HOLD installed=38 absent=54 divergent=3 "
              "resources=3 source_union=92 root_approved=false")


if __name__ == "__main__":
    unittest.main()
