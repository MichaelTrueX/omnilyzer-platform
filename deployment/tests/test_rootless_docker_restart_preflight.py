"""Tests for the read-only rootless Docker restart preflight."""

from dataclasses import FrozenInstanceError
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from deployment import rootless_docker_restart_preflight as module
from deployment.rootless_docker_authority import AUTHORITY


ROOT = Path(__file__).resolve().parents[2]


class RootlessDockerRestartPreflightTests(unittest.TestCase):
    def test_check_and_evidence_are_exact_and_immutable(self):
        passed = module.RootlessDockerRestartPreflightCheck("one", True, None)
        failed = module.RootlessDockerRestartPreflightCheck("two", False, "OSError")
        evidence = module.RootlessDockerRestartPreflightEvidence((passed, failed))
        self.assertFalse(evidence.passed)
        self.assertEqual(evidence.failures, (failed,))
        with self.assertRaises(FrozenInstanceError):
            passed.passed = False
        with self.assertRaises(ValueError):
            module.RootlessDockerRestartPreflightCheck("", True, None)
        with self.assertRaises(ValueError):
            module.RootlessDockerRestartPreflightEvidence((passed, passed))

    def test_non_fail_fast_matrix_runs_every_check(self):
        events = []

        def first():
            events.append("first")

        def second():
            events.append("second")
            raise OSError("private")

        def third():
            events.append("third")

        with patch.object(
            module,
            "_component_checks",
            return_value=(("first", first), ("second", second), ("third", third)),
        ):
            evidence = module.preflight_rootless_docker_restart()

        self.assertEqual(events, ["first", "second", "third"])
        self.assertFalse(evidence.passed)
        self.assertEqual(
            tuple((x.name, x.passed, x.error_type) for x in evidence.checks),
            (
                ("first", True, None),
                ("second", False, "OSError"),
                ("third", True, None),
            ),
        )

    def test_matrix_contains_all_restart_specific_boundaries(self):
        names = tuple(name for name, _ in module._component_checks())
        self.assertEqual(
            names,
            (
                "daemon_preflight_all_pass",
                "installed_launcher_exact",
                "launcher_source_digest",
                "launcher_static_live",
                "runtime_principal_and_environment",
                "restart_unit_policy",
            ),
        )
        self.assertEqual(
            tuple(name for name, _ in module._candidate_checks()),
            (
                "launcher_source_digest",
                "launcher_static_live",
                "runtime_principal_and_environment",
                "restart_unit_policy",
            ),
        )

    def test_candidate_preflight_excludes_installed_target_and_daemon_matrix(self):
        events = []
        checks = (
            ("one", lambda: events.append("one")),
            ("two", lambda: events.append("two")),
        )
        with patch.object(module, "_candidate_checks", return_value=checks):
            evidence = module.preflight_rootless_docker_restart_candidate()
        self.assertTrue(evidence.passed)
        self.assertEqual(events, ["one", "two"])
        self.assertNotIn("installed_launcher_exact", tuple(x.name for x in evidence.checks))
        self.assertNotIn("daemon_preflight_all_pass", tuple(x.name for x in evidence.checks))

    def test_restart_unit_policy_is_exact_and_disabled(self):
        expected = {
            "Restart": "always",
            "Type": "notify",
            "NotifyAccess": "all",
            "UnitFileState": "disabled",
        }
        with patch.object(
            module,
            "_user_systemctl_value",
            side_effect=lambda prop: expected[prop],
        ):
            module._restart_unit_policy()

        for property_name, value in (
            ("Restart", "on-failure"),
            ("Type", "simple"),
            ("NotifyAccess", "main"),
            ("UnitFileState", "enabled"),
        ):
            altered = expected | {property_name: value}
            with self.subTest(property_name=property_name), patch.object(
                module,
                "_user_systemctl_value",
                side_effect=lambda prop, altered=altered: altered[prop],
            ), self.assertRaises(OSError):
                module._restart_unit_policy()

    def test_runtime_principal_requires_exact_groups_and_launcher_environment(self):
        status = (
            b"Name:\trootlesskit\n"
            b"Uid:\t991\t991\t991\t991\n"
            b"Gid:\t991\t991\t991\t991\n"
            b"Groups:\t992 \n"
        )
        with patch.object(
            module.daemonq,
            "_user_unit_evidence",
            return_value=(("loaded", "active", "running", "disabled"), AUTHORITY.user_unit, 4000),
        ), patch.object(
            module.daemonq,
            "_process_evidence",
            return_value=(4000, ("rootlesskit",), 4001, ("/usr/bin/dockerd",)),
        ), patch.object(
            module.daemonq,
            "_read_proc_file",
            return_value=status,
        ), patch.object(
            module,
            "_read_proc_environment",
            return_value=dict(module._EXPECTED_ENVIRONMENT),
        ):
            module._runtime_principal_and_environment()

        hostile = dict(module._EXPECTED_ENVIRONMENT)
        hostile["DOCKER_HOST"] = "tcp://127.0.0.1:2375"
        with patch.object(
            module.daemonq,
            "_user_unit_evidence",
            return_value=(("loaded", "active", "running", "disabled"), AUTHORITY.user_unit, 4000),
        ), patch.object(
            module.daemonq,
            "_process_evidence",
            return_value=(4000, ("rootlesskit",), 4001, ("/usr/bin/dockerd",)),
        ), patch.object(
            module.daemonq,
            "_read_proc_file",
            return_value=status,
        ), patch.object(
            module,
            "_read_proc_environment",
            return_value=hostile,
        ), self.assertRaises(OSError):
            module._runtime_principal_and_environment()

    def test_launcher_digest_matches_authority(self):
        expected = next(
            item[2] for item in AUTHORITY.installed_assets
            if item[1] == AUTHORITY.launcher
        )
        self.assertEqual(module._launcher_digest(), expected)

    def test_user_systemctl_reader_is_closed(self):
        completed = subprocess.CompletedProcess((), 0, b"always\n", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            self.assertEqual(module._user_systemctl_value("Restart"), "always")
        argv = run.call_args.args[0]
        self.assertEqual(
            argv,
            (
                "/usr/bin/systemctl",
                "--user",
                "--machine=omnilyzer-executor@.host",
                "show",
                "--property=Restart",
                "--value",
                "omnilyzer-task014-rootless-docker.service",
            ),
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        with self.assertRaises(OSError):
            module._user_systemctl_value("ExecStart")

    def test_source_is_read_only_and_has_no_restart_mutator(self):
        source = (
            ROOT / "deployment/rootless_docker_restart_preflight.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("rootless_docker_daemon_start", source)
        for forbidden in (
            '"start"',
            '"stop"',
            '"restart"',
            '"enable"',
            '"enable-now"',
            "loginctl",
            "os.unlink",
            "os.rename",
            "os.chmod",
            "os.chown",
            "os.mkdir",
            "shell=True",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
