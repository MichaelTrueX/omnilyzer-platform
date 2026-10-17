"""File: deployment/tests/test_c35d_release_gate_consolidation.py

Purpose: Consolidate accepted Task 014 read-only evidence into a fail-closed
release-gate decision and a prioritized nonprivileged incident-triage handover.
The original DEV promotion 403 is not fixed; no rerun or auto-approval occurs.

Linked files:
- deployment/tests/test_c34z_main_loader_release_gap.py (historical main 81/11/3)
- deployment/tests/test_c34y_service_recovery_manifest_review.py (95 files)
- deployment/tests/test_c34x_service_recovery_source_reconciliation.py (three diffs)
- deployment/tests/test_c35c_privileged_loader_threat_review.py (root HOLD)
- docs/operations/task014-c35d-release-gate-consolidation.md
- .github/workflows/task014-c34d-review.yml
- https://github.com/MichaelTrueX/omnilyzer-platform/issues/182 (403 incident)

No root, network, GitHub workflow dispatch, live HTTP, token capture, service
start/stop, secrets inspection, app import, deployment or migration activity.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import unittest

from deployment.tests import test_c34x_service_recovery_source_reconciliation as c34x
from deployment.tests import test_c34y_service_recovery_manifest_review as c34y
from deployment.tests import test_c34z_main_loader_release_gap as c34z
from deployment.tests import test_c35a_signed_late_native_modules as c35a
from deployment.tests import test_c35b_loader_config_dependency_review as c35b
from deployment.tests import test_c35c_privileged_loader_threat_review as c35c


# Section 1. Fixed incident facts, scope and immutable authorization boundary.
_REPOSITORY = "MichaelTrueX/omnilyzer-platform"
_ISSUE = 182
_FAILED_RUN = 38382512194
_FAILED_STEP = "Submit DEV promotion once"
_FAILED_STATUS = 403
_CANDIDATE_HEAD_BEFORE_C35D = "5f1adce3d880ae1aba009643bcefeade5297fb99"
_PROTECTED_MAIN = "57919c3b9aca0cb98e85bbb26460f6267d093fa9"
_OPEN_GATES = (
    "403_original_rejection_boundary",
    "protected_main_source_set",
    "broker_diagnostics_change_approval",
    "privileged_loader_and_config_seal",
    "stopped_host_backup_rollback_and_reauthorization",
)
_DOCUMENT = Path(__file__).resolve().parents[2] / (
    "docs/operations/task014-c35d-release-gate-consolidation.md"
)
_ERR = "C35D Task 014 release remains on hold"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class C35DReleaseHold(Exception):
    """Single nonsecret HOLD result for incomplete release evidence."""


@dataclass(frozen=True, slots=True)
class C35DGateReceipt:
    """Bounded read-only review result; no field grants deployment authority."""

    incident_issue: int
    failed_run: int
    http_status: int
    historical_candidate_source_files_and_resources: int
    protected_main_matching: int
    protected_main_missing: int
    protected_main_different: int
    unapproved_service_diagnostic_files: int
    verified_prior_native_file_provenance_scopes: int
    tracked_open_gates: tuple[str, ...]
    historical_incident_root_cause_proven: bool = False
    protected_main_source_ready: bool = False
    diagnostic_changes_approved: bool = False
    privileged_loader_approved: bool = False
    recovery_acceptance_approved: bool = False
    broker_promotion_reauthorized: bool = False
    root_execution_approved: bool = False
    deployment_released: bool = False

    def __post_init__(self) -> None:
        """Prevent closed-by-count/CI/metadata and forged GO classifications."""
        if (
            type(self.incident_issue) is not int or self.incident_issue != _ISSUE
            or type(self.failed_run) is not int or self.failed_run != _FAILED_RUN
            or type(self.http_status) is not int or self.http_status != _FAILED_STATUS
            or type(self.historical_candidate_source_files_and_resources) is not int
            or self.historical_candidate_source_files_and_resources != 95
            or type(self.protected_main_matching) is not int
            or self.protected_main_matching != 81
            or type(self.protected_main_missing) is not int
            or self.protected_main_missing != 11
            or type(self.protected_main_different) is not int
            or self.protected_main_different != 3
            or type(self.unapproved_service_diagnostic_files) is not int
            or self.unapproved_service_diagnostic_files != 3
            or type(self.verified_prior_native_file_provenance_scopes) is not int
            or self.verified_prior_native_file_provenance_scopes != 3
            or self.tracked_open_gates != _OPEN_GATES
            or any(
                getattr(self, key) is not False for key in (
                    "historical_incident_root_cause_proven",
                    "protected_main_source_ready",
                    "diagnostic_changes_approved",
                    "privileged_loader_approved",
                    "recovery_acceptance_approved",
                    "broker_promotion_reauthorized",
                    "root_execution_approved",
                    "deployment_released",
                )
            )
        ):
            raise ValueError(_ERR)


# Section 2. Historical evidence is source-bound, not an incident diagnosis.
def consolidate_prior_reviews() -> C35DGateReceipt:
    """Recheck prior immutable scope observations without touching the host.

    Scope: 95 C34Y candidate entries; historical C34Z 81 matching, 11 absent,
    3 different in main; C34X three disputed installed diagnostic source
    files; C35A/C35B native provenance and C35C loader/root status remain
    distinct. Never infer live incident cause from source code or CI tests.
    """
    try:
        c34y_records = c34y._load_manifest()
        main_records = c34z._load_snapshot()
        c35a_record = c35a._load_closed_selection()
        c35b_record = c35b._load_review()
        c35c_record = c35c._load_snapshot()

        if (
            len(c34y_records) != 95
            or len(main_records) != 95
            or sum(i["status"] == "matching" for i in main_records) != 81
            or sum(i["status"] == "missing" for i in main_records) != 11
            or sum(i["status"] == "different" for i in main_records) != 3
            or tuple(
                x["path"] for x in main_records if x["status"] == "different"
            ) != tuple(sorted(c34x._PREVIOUS))
            or len(c34x._PREVIOUS) != 3
            or len(c35a_record["modules"]) != 5
            or len(c35b_record["modules"]) != 6
            or c35b_record["config_signed"] is not False
            or c35b_record["effective_loader_approved"] is not False
            or c35c_record["root_launcher_installed"] is not False
            or c35c_record["root_execution_approved"] is not False
            or c35c_record["protected_main_approved"] is not False
            or c35c_record["runtime_library_search_frozen"] is not False
        ):
            raise ValueError(_ERR)

        result = C35DGateReceipt(
            incident_issue=_ISSUE,
            failed_run=_FAILED_RUN,
            http_status=_FAILED_STATUS,
            historical_candidate_source_files_and_resources=95,
            protected_main_matching=81,
            protected_main_missing=11,
            protected_main_different=3,
            unapproved_service_diagnostic_files=3,
            verified_prior_native_file_provenance_scopes=3,
            tracked_open_gates=_OPEN_GATES,
        )
        C35DGateReceipt.__post_init__(result)
        return result
    except _CONTROL:
        raise
    except Exception:
        raise C35DReleaseHold(_ERR) from None


# Section 3. CI-safe approval and evidence-contract regressions.
class C35DReleaseGateTests(unittest.TestCase):
    """Preserve 403-first triage priority and reject premature deployment GO."""

    def test_a_historical_release_gaps_reconcile(self) -> None:
        """Verify the 95-entry source gap from authoritative retained reviews."""
        evidence = consolidate_prior_reviews()
        self.assertEqual(
            (evidence.protected_main_matching, evidence.protected_main_missing,
             evidence.protected_main_different),
            (81, 11, 3),
        )
        self.assertFalse(evidence.protected_main_source_ready)

    def test_b_native_provenance_does_not_authorize_loader(self) -> None:
        """Signed module byte scopes do not establish dynamic loader authority."""
        evidence = consolidate_prior_reviews()
        self.assertEqual(evidence.verified_prior_native_file_provenance_scopes, 3)
        self.assertFalse(evidence.privileged_loader_approved)

    def test_c_historical_403_is_not_diagnosed_by_synthetic_tests(self) -> None:
        """Known failed workflow identity/status is not a proved rejection stage."""
        evidence = consolidate_prior_reviews()
        self.assertEqual((_FAILED_RUN, _FAILED_STATUS), (38382512194, 403))
        self.assertEqual(_FAILED_STEP, "Submit DEV promotion once")
        self.assertFalse(evidence.historical_incident_root_cause_proven)
        self.assertFalse(evidence.broker_promotion_reauthorized)

    def test_d_all_unresolved_gates_remain_false(self) -> None:
        """Refuse promotion if any proposed authority flag is forged as true."""
        record = consolidate_prior_reviews()
        for flag in (
            "historical_incident_root_cause_proven",
            "protected_main_source_ready",
            "diagnostic_changes_approved",
            "privileged_loader_approved",
            "recovery_acceptance_approved",
            "broker_promotion_reauthorized",
            "root_execution_approved",
            "deployment_released",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                replace(record, **{flag: True})

    def test_e_closed_gates_do_not_change_with_ci_volume(self) -> None:
        """More test passes cannot resolve an absent live incident observation."""
        record = consolidate_prior_reviews()
        with self.assertRaises(ValueError):
            replace(record, protected_main_missing=0)
        with self.assertRaises(ValueError):
            replace(record, protected_main_different=0)
        self.assertFalse(record.deployment_released)

    def test_f_incident_handover_is_linked_and_separately_gated(self) -> None:
        """Require a complete review document; no script or workflow dispatch."""
        text = _DOCUMENT.read_text()
        for marker in (
            "38382512194", "Issue #182", "11 missing", "three",
            "Do not retry", "proposed", "approved", "implemented",
            "verified", "released",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)
        self.assertEqual(len(_OPEN_GATES), 5)

    def test_g_stable_hold_receipt(self) -> None:
        """Emit one safe bounded CI result without exposing tokens or journal."""
        record = consolidate_prior_reviews()
        self.assertFalse(record.root_execution_approved)
        print(
            "C35D_RELEASE_HOLD 403_cause_proven=false main_missing=11 "
            "main_different=3 diagnostic_approved=false "
            "privileged_loader_approved=false recovery_approved=false "
            "root_approved=false released=false"
        )


if __name__ == "__main__":
    unittest.main()
