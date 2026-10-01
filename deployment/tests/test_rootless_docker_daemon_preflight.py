"""Tests for non-fail-fast rootless Docker daemon preflight."""

from dataclasses import FrozenInstanceError
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment import rootless_docker_daemon_preflight as module


ROOT = Path(__file__).resolve().parents[2]


class RootlessDockerDaemonPreflightTests(unittest.TestCase):
    def test_check_and_evidence_are_exact_and_immutable(self):
        passed = module.RootlessDockerDaemonPreflightCheck("one", True, None)
        failed = module.RootlessDockerDaemonPreflightCheck("two", False, "OSError")
        evidence = module.RootlessDockerDaemonPreflightEvidence((passed, failed))

        self.assertFalse(evidence.passed)
        self.assertEqual(evidence.failures, (failed,))
        with self.assertRaises(FrozenInstanceError):
            passed.passed = False

        for args in (
            ("", True, None),
            ("one", True, "OSError"),
            ("one", False, None),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                module.RootlessDockerDaemonPreflightCheck(*args)

        with self.assertRaises(ValueError):
            module.RootlessDockerDaemonPreflightEvidence((passed, passed))

    def test_evaluate_records_failure_without_private_message(self):
        self.assertEqual(
            module._evaluate("ok", lambda: 1),
            module.RootlessDockerDaemonPreflightCheck("ok", True, None),
        )

        def fail():
            raise OSError("private detail")

        self.assertEqual(
            module._evaluate("bad", fail),
            module.RootlessDockerDaemonPreflightCheck("bad", False, "OSError"),
        )

    def test_preflight_runs_all_checks_after_failure(self):
        events = []

        def ok_one():
            events.append("one")

        def fail_two():
            events.append("two")
            raise OSError("private")

        def ok_three():
            events.append("three")

        checks = (
            ("one", ok_one),
            ("two", fail_two),
            ("three", ok_three),
        )
        with patch.object(module, "_component_checks", return_value=checks):
            evidence = module.preflight_rootless_docker_daemon()

        self.assertEqual(events, ["one", "two", "three"])
        self.assertFalse(evidence.passed)
        self.assertEqual(
            tuple((item.name, item.passed, item.error_type) for item in evidence.checks),
            (
                ("one", True, None),
                ("two", False, "OSError"),
                ("three", True, None),
            ),
        )

    def test_real_matrix_contains_component_and_composite_process_gates(self):
        names = tuple(name for name, _function in module._component_checks())
        self.assertEqual(len(names), len(set(names)))
        for required in (
            "successor_migration",
            "executor_identity",
            "package_host_composite",
            "post_daemon_data_root",
            "post_daemon_static_assets",
            "executor_dropins",
            "user_dropins",
            "deployment_units",
            "user_unit",
            "process_evidence",
            "daemon_socket",
            "rootlesskit_state",
            "runtime_artifacts",
            "docker_info",
            "user_manager",
            "qualify_once_first",
            "qualify_once_second",
            "qualify_observations_equal",
        ):
            with self.subTest(required=required):
                self.assertIn(required, names)

        self.assertTrue(any(name.startswith("host_dependency:") for name in names))
        self.assertTrue(any(name.startswith("package:") for name in names))
        self.assertTrue(any(name.startswith("directory:") for name in names))
        self.assertTrue(any(name.startswith("asset:") for name in names))
        self.assertNotIn("public_c33f", names)

    def test_observation_equality_is_checked_without_public_qualifier(self):
        first = object()
        with patch.object(module.daemonq, "_qualify_once", side_effect=(first, first)) as once, \
             patch.object(module.daemonq, "qualify_rootless_docker_daemon") as public:
            module._qualify_observations_equal()
        self.assertEqual(once.call_count, 2)
        public.assert_not_called()

        with patch.object(module.daemonq, "_qualify_once", side_effect=(object(), object())), \
             self.assertRaises(OSError):
            module._qualify_observations_equal()

    def test_preflight_source_is_read_only_and_independent_of_c33e(self):
        source = (
            ROOT / "deployment/rootless_docker_daemon_preflight.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("rootless_docker_daemon_start", source)
        for forbidden in (
            '"start"',
            '"stop"',
            '"restart"',
            '"enable"',
            '"enable-now"',
            "os.mkdir",
            "os.chown",
            "os.chmod",
            "os.unlink",
            "os.rename",
            "shell=True",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
