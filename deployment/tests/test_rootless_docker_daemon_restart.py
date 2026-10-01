"""Tests for the C33M one-shot rootless Docker daemon restart."""

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch, call

from deployment import rootless_docker_daemon_restart as module
from deployment.tests.test_rootless_docker_daemon_qualification import (
    evidence as daemon_evidence,
)


ROOT = Path(__file__).resolve().parents[2]


def green_preflight():
    check = module.restart_preflight.RootlessDockerRestartPreflightCheck(
        "all", True, None
    )
    return module.restart_preflight.RootlessDockerRestartPreflightEvidence(
        (check,)
    )


def runtime_pids(base: int):
    return (
        ("rootlesskit", base),
        ("dockerd", base + 1),
        ("containerd", base + 2),
        ("slirp4netns", base + 3),
    )


def after_daemon():
    return replace(
        daemon_evidence(),
        user_unit_main_pid=5000,
        rootlesskit_pid=5000,
        dockerd_pid=5001,
    )


class RootlessDockerDaemonRestartTests(unittest.TestCase):
    def test_evidence_is_exact_and_immutable(self):
        value = module.RootlessDockerDaemonRestartEvidence(
            operation="restarted",
            before_pids=runtime_pids(4000),
            after_pids=runtime_pids(5000),
            preflight_checks=("one",),
            postflight_checks=("one",),
            daemon_signature_equal=True,
            user_unit_state=("loaded", "active", "running", "disabled"),
            containers=(0, 0, 0, 0),
            images=0,
        )
        with self.assertRaises(FrozenInstanceError):
            value.operation = "changed"

        bad_values = (
            {"operation": "wrong"},
            {"after_pids": runtime_pids(4000)},
            {"postflight_checks": ("two",)},
            {"daemon_signature_equal": False},
            {"user_unit_state": ("loaded", "active", "running", "enabled")},
            {"containers": (1, 1, 0, 0)},
            {"images": 1},
        )
        base = {
            name: getattr(value, name)
            for name in value.__dataclass_fields__
        }
        for change in bad_values:
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.RootlessDockerDaemonRestartEvidence(**(base | change))

    def test_restart_command_is_exact_and_closed(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            module._run_restart()

        self.assertEqual(
            run.call_args.args[0],
            (
                "/usr/bin/systemctl",
                "--user",
                "--machine=omnilyzer-executor@.host",
                "restart",
                "omnilyzer-task014-rootless-docker.service",
            ),
        )
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.PIPE)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 120.0)
        self.assertEqual(
            run.call_args.kwargs["env"],
            {
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "HOME": "/root",
            },
        )

        for completed in (
            subprocess.CompletedProcess((), 1, b"", b"failed"),
            subprocess.CompletedProcess((), 0, b"x" * (module._OUTPUT_LIMIT + 1), b""),
            subprocess.CompletedProcess((), 0, b"", b"x" * (module._OUTPUT_LIMIT + 1)),
        ):
            with self.subTest(completed=completed), patch.object(
                module.subprocess, "run", return_value=completed
            ), self.assertRaises(OSError):
                module._run_restart()

    def test_runtime_pids_are_exact_unique_and_bind_mainpid(self):
        with patch.object(
            module.c33f,
            "_user_unit_evidence",
            return_value=(("loaded", "active", "running", "disabled"), "/unit", 4000),
        ), patch.object(
            module.c33f,
            "_process_evidence",
            return_value=(4000, ("rootlesskit",), 4001, ("/usr/bin/dockerd",)),
        ) as process, patch.object(
            module.c33f,
            "_pids",
            side_effect=lambda name: {
                "containerd": (4002,),
                "slirp4netns": (4003,),
            }[name],
        ):
            self.assertEqual(module._runtime_pids(), runtime_pids(4000))
        process.assert_called_once_with(4000)

        with patch.object(
            module.c33f,
            "_user_unit_evidence",
            return_value=(("loaded", "active", "running", "enabled"), "/unit", 4000),
        ), self.assertRaises(OSError):
            module._runtime_pids()

    def test_stable_signature_excludes_only_runtime_process_ids(self):
        before = daemon_evidence()
        after = after_daemon()
        self.assertEqual(
            module._stable_daemon_signature(before),
            module._stable_daemon_signature(after),
        )

        changed = replace(after, expected_workflow_sha="b" * 40)
        self.assertNotEqual(
            module._stable_daemon_signature(before),
            module._stable_daemon_signature(changed),
        )
        self.assertEqual(
            module._VOLATILE_DAEMON_FIELDS,
            frozenset({"user_unit_main_pid", "rootlesskit_pid", "dockerd_pid"}),
        )

    def test_restart_under_lock_requires_preflight_then_restart_then_stable_postflight(self):
        green = green_preflight()
        before = daemon_evidence()
        after = after_daemon()
        events = []

        with patch.object(
            module,
            "_require_green_preflight",
            side_effect=lambda: events.append("preflight") or green,
        ), patch.object(
            module.c33f,
            "qualify_rootless_docker_daemon",
            side_effect=lambda: events.append("c33f") or (
                before if events.count("c33f") == 1 else after
            ),
        ), patch.object(
            module,
            "_runtime_pids",
            side_effect=lambda: events.append("pids") or (
                runtime_pids(4000) if events.count("pids") == 1 else runtime_pids(5000)
            ),
        ), patch.object(
            module,
            "_run_restart",
            side_effect=lambda: events.append("restart"),
        ):
            result = module._restart_under_lock()

        self.assertEqual(result.operation, "restarted")
        self.assertEqual(result.before_pids, runtime_pids(4000))
        self.assertEqual(result.after_pids, runtime_pids(5000))
        self.assertTrue(result.daemon_signature_equal)
        self.assertEqual(
            events,
            [
                "preflight",
                "c33f",
                "pids",
                "restart",
                "pids",
                "preflight",
                "preflight",
                "c33f",
            ],
        )

    def test_preflight_failure_prevents_restart(self):
        red_check = module.restart_preflight.RootlessDockerRestartPreflightCheck(
            "blocked", False, "OSError"
        )
        red = module.restart_preflight.RootlessDockerRestartPreflightEvidence(
            (red_check,)
        )
        with patch.object(
            module.restart_preflight,
            "preflight_rootless_docker_restart",
            return_value=red,
        ), patch.object(module, "_run_restart") as restart, self.assertRaises(OSError):
            module._restart_under_lock()
        restart.assert_not_called()

    def test_reused_runtime_pid_or_postflight_drift_fails_without_second_restart(self):
        green = green_preflight()
        before = daemon_evidence()
        after = after_daemon()

        with patch.object(module, "_require_green_preflight", return_value=green),              patch.object(
                 module.c33f,
                 "qualify_rootless_docker_daemon",
                 side_effect=(before, after),
             ),              patch.object(
                 module,
                 "_runtime_pids",
                 side_effect=(runtime_pids(4000), runtime_pids(4000)),
             ),              patch.object(module, "_run_restart") as restart,              self.assertRaises(OSError):
            module._restart_under_lock()
        restart.assert_called_once_with()

        post_other = module.restart_preflight.RootlessDockerRestartPreflightEvidence(
            (
                module.restart_preflight.RootlessDockerRestartPreflightCheck(
                    "different", True, None
                ),
            )
        )
        with patch.object(
            module,
            "_require_green_preflight",
            side_effect=(green, green, post_other),
        ), patch.object(
            module.c33f,
            "qualify_rootless_docker_daemon",
            side_effect=(before, after),
        ), patch.object(
            module,
            "_runtime_pids",
            side_effect=(runtime_pids(4000), runtime_pids(5000)),
        ), patch.object(module, "_run_restart") as restart, self.assertRaises(OSError):
            module._restart_under_lock()
        restart.assert_called_once_with()

    def test_public_transition_is_root_locked_and_generic_on_failure(self):
        expected = module.RootlessDockerDaemonRestartEvidence(
            operation="restarted",
            before_pids=runtime_pids(4000),
            after_pids=runtime_pids(5000),
            preflight_checks=("one",),
            postflight_checks=("one",),
            daemon_signature_equal=True,
            user_unit_state=("loaded", "active", "running", "disabled"),
            containers=(0, 0, 0, 0),
            images=0,
        )
        with patch.object(module, "_root_identity", return_value=(0, 0)),              patch.object(module.orchestration, "_acquire_process_lock", return_value=70) as acquire,              patch.object(module, "_restart_under_lock", return_value=expected),              patch.object(module.orchestration, "_release_process_lock") as release:
            self.assertEqual(module.restart_rootless_docker_daemon(), expected)
        acquire.assert_called_once_with()
        release.assert_called_once_with(70)

        with patch.object(module, "_root_identity", side_effect=OSError("private")):
            with self.assertRaises(module.RootlessDockerDaemonRestartError) as caught:
                module.restart_rootless_docker_daemon()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_source_has_one_exact_restart_mutation_and_no_other_service_surface(self):
        source = (
            ROOT / "deployment/rootless_docker_daemon_restart.py"
        ).read_text(encoding="utf-8")
        self.assertEqual(source.count('"restart"'), 1)
        for forbidden in (
            '"start"',
            '"stop"',
            '"enable"',
            '"enable-now"',
            "loginctl",
            "docker run",
            "docker pull",
            "docker build",
            "docker compose",
            "os.unlink",
            "os.replace",
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
