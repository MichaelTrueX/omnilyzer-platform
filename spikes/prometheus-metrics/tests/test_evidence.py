"""Assertions over captured Task 010 live and multiprocess evidence."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


RESULTS = Path(__file__).resolve().parents[1] / "results"
SPIKE = RESULTS.parent


class CapturedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.live = json.loads((RESULTS / "live-validation.json").read_text(encoding="utf-8"))
        cls.multi = json.loads((RESULTS / "multiprocess-validation.json").read_text(encoding="utf-8"))

    def test_live_decision_passes(self) -> None:
        self.assertEqual(self.live["decision"], "PASS")

    def test_real_prometheus_scraped_three_targets(self) -> None:
        self.assertEqual(self.live["prometheus"]["version"], "3.14.0")
        self.assertEqual(self.live["queries"]["targets_up"], 3)

    def test_runtime_network_boundary_was_private_and_loopback_only(self) -> None:
        boundary = self.live["network_boundary"]
        self.assertEqual(boundary["runtime_target_host_port_bindings"], 0)
        self.assertEqual(boundary["runtime_prometheus_port_binding"], "127.0.0.1:19090")
        for networks in boundary["runtime_target_networks"].values():
            self.assertEqual(networks, ["task010-prometheus-metrics_metrics-internal"])

    def test_cardinality_matches_histogram_mechanics_exactly(self) -> None:
        cardinality = self.live["cardinality"]
        self.assertEqual(cardinality["actual_request_metric_series_including_histogram_mechanics"], cardinality["expected_from_actual_base_and_mechanics"])
        self.assertLessEqual(cardinality["actual_base_request_label_sets"], cardinality["configured_theoretical_base_bound"])

    def test_per_label_set_series_arithmetic_accounts_for_created_configuration(self) -> None:
        cardinality = self.live["cardinality"]
        base = cardinality["actual_base_request_label_sets"]
        per_base = {
            name: count // base for name, count in cardinality["mechanics"].items()
        }
        self.assertEqual(per_base, {
            "counter_total": 1,
            "counter_created": 1,
            "histogram_bucket": 11,
            "histogram_count": 1,
            "histogram_sum": 1,
            "histogram_created": 1,
        })
        self.assertEqual(sum(per_base.values()), 16)
        self.assertEqual(
            sum(value for name, value in per_base.items() if not name.endswith("_created")),
            14,
        )

    def test_hostile_ids_do_not_expand_routes(self) -> None:
        self.assertGreaterEqual(self.live["distinct_raw_ids"], 10_000)
        self.assertNotIn("/api/users/1", self.live["cardinality"]["actual_route_label_values"])
        self.assertIn("unmatched", self.live["cardinality"]["actual_route_label_values"])

    def test_sensitive_data_absent(self) -> None:
        self.assertEqual(self.live["sensitive_data"]["found"], [])
        self.assertEqual(self.live["cardinality"]["prohibited_request_labels_found"], [])

    def test_prometheus_outage_did_not_affect_application(self) -> None:
        outage = self.live["prometheus_outage"]
        self.assertEqual(outage["outage_request_failures"], 0)
        self.assertFalse(outage["application_container_restarted"])
        self.assertTrue(outage["livez_passed"] and outage["readyz_passed"])

    def test_failed_targets_are_isolated_and_recover(self) -> None:
        failure = self.live["failed_target_isolation"]
        self.assertEqual(failure["stopped_target_up"], 0)
        self.assertEqual(failure["healthy_target_up"], 1)
        self.assertEqual(failure["slow_target_up"], 0)
        self.assertEqual(failure["malformed_target_up"], 0)
        self.assertLessEqual(
            failure["slow_target_pids_after_repeated_timeouts"],
            failure["slow_target_pid_acceptance_bound"],
        )

    def test_multiprocess_semantics_are_explicit(self) -> None:
        self.assertEqual(self.multi["decision"], "PASS_WITH_LIFECYCLE_REQUIREMENTS")
        self.assertEqual(self.multi["initial_aggregate"]["counter"], 12)
        self.assertEqual(self.multi["clean_new_deployment_after_directory_wipe"]["counter"], 2)
        self.assertGreater(self.multi["cross_deployment_contamination_without_directory_wipe"]["counter"], 2)

    def test_default_gauge_mode_is_unsafe_for_bounded_build_info(self) -> None:
        default = self.multi["unsafe_default_all_mode"]
        self.assertEqual(default["per_process_series"], 2)
        self.assertTrue(default["pid_label_present"])
        self.assertFalse(default["mark_process_dead_removed_default_series"])
        for stage in (
            "two_live_workers", "after_mark_process_dead_one_worker",
            "after_mark_process_dead_both_workers",
        ):
            builds = default[stage]["builds"]
            self.assertEqual(len(builds), 2)
            self.assertEqual({item["value"] for item in builds}, {1.0})
            self.assertEqual(
                {item["labels"]["pid"] for item in builds},
                {"<worker-pid-1>", "<worker-pid-2>"},
            )

    def test_livemax_candidate_is_one_logical_build_info_series(self) -> None:
        self.assertEqual(self.multi["safe_candidate_gauge_mode"], "livemax")
        for stage in ("initial_aggregate", "after_clean_worker_exit", "after_worker_restart"):
            builds = self.multi[stage]["builds"]
            self.assertEqual(len(builds), 1)
            self.assertEqual(builds[0]["value"], 1.0)
            self.assertNotIn("pid", builds[0]["labels"])

    def test_worker_exit_and_deployment_cleanup_have_distinct_semantics(self) -> None:
        self.assertEqual(self.multi["after_clean_worker_exit"]["counter"], 12)
        self.assertEqual(self.multi["after_clean_worker_exit"]["histogram_count"], 12)
        self.assertEqual(self.multi["after_mark_process_dead"]["builds"][0]["labels"]["app_version"], "2.0.0")
        self.assertEqual(self.multi["cross_deployment_contamination_without_directory_wipe"]["counter"], 19)
        self.assertEqual(self.multi["clean_new_deployment_after_directory_wipe"]["counter"], 2)

    def test_focused_probe_reproduces_captured_multiprocess_evidence(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SPIKE / "multiprocess_probe.py")],
            text=True, capture_output=True, check=True,
        )
        self.assertEqual(json.loads(result.stdout), self.multi)


if __name__ == "__main__":
    unittest.main()
