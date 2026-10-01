"""Tests for C33Q fresh user-manager recovery preflight."""

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import subprocess
import unittest
from unittest.mock import call, patch

from deployment import rootless_docker_fresh_manager_preflight as module
from deployment.tests.test_rootless_docker_daemon_qualification import (
    evidence as daemon_evidence,
)


ROOT = Path(__file__).resolve().parents[2]


def persistence_state(daemon=None):
    daemon = daemon or daemon_evidence()
    return module.persistence.RootlessDockerPersistenceStateEvidence(
        persistent_state="enabled",
        enable_link=(
            module.persistence._ENABLE_LINK,
            module.AUTHORITY.user_unit,
            0,
            0,
            0o777,
        ),
        daemon=daemon,
    )


def snapshot():
    daemon = daemon_evidence()
    return module.RootlessDockerFreshManagerSnapshot(
        persistent_state="enabled",
        live_user_unit_state=daemon.user_unit_state,
        user_manager_state=("loaded", "active", "running", "static"),
        user_manager_pid=3000,
        user_runtime_state=("loaded", "active", "exited"),
        linger_state=(
            "yes",
            module.AUTHORITY.runtime_directory,
            str(module.AUTHORITY.executor_uid),
            module.AUTHORITY.executor_user,
            "lingering",
            "",
            "",
        ),
        rootlesskit_pid=daemon.rootlesskit_pid,
        dockerd_pid=daemon.dockerd_pid,
        containerd_pid=4002,
        slirp4netns_pid=4003,
        containers=daemon.containers,
        images=daemon.images,
    )


class RootlessDockerFreshManagerPreflightTests(unittest.TestCase):
    def test_snapshot_is_exact_and_immutable(self):
        value = snapshot()
        with self.assertRaises(FrozenInstanceError):
            value.user_manager_pid = 1

        values = {
            name: getattr(value, name)
            for name in value.__dataclass_fields__
        }
        for change in (
            {"persistent_state": "disabled"},
            {"live_user_unit_state": ("loaded", "active", "running", "enabled")},
            {"user_manager_state": ("loaded", "inactive", "dead", "static")},
            {"user_manager_pid": 1},
            {"user_runtime_state": ("loaded", "inactive", "dead")},
            {"linger_state": ("yes", "/wrong", "991", "omnilyzer-executor", "lingering", "", "")},
            {"dockerd_pid": value.rootlesskit_pid},
            {"containers": (1, 1, 0, 0)},
            {"images": 1},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.RootlessDockerFreshManagerSnapshot(
                    **(values | change)
                )

    def test_check_and_matrix_are_exact_and_immutable(self):
        good = module.RootlessDockerFreshManagerPreflightCheck(
            "one", True, None
        )
        bad = module.RootlessDockerFreshManagerPreflightCheck(
            "two", False, "OSError"
        )
        matrix = module.RootlessDockerFreshManagerPreflightEvidence(
            (good, bad)
        )
        self.assertFalse(matrix.passed)
        self.assertEqual(matrix.failures, (bad,))
        with self.assertRaises(FrozenInstanceError):
            good.passed = False
        with self.assertRaises(ValueError):
            module.RootlessDockerFreshManagerPreflightEvidence((good, good))

    def test_read_helpers_pin_read_only_command_shapes(self):
        completed = subprocess.CompletedProcess((), 0, b"active\n", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            self.assertEqual(
                module._system_value("user@991.service", "ActiveState"),
                "active",
            )
        self.assertEqual(
            run.call_args.args[0],
            (
                "/usr/bin/systemctl",
                "show",
                "--property=ActiveState",
                "--value",
                "user@991.service",
            ),
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(run.call_args.kwargs["check"])

        completed = subprocess.CompletedProcess((), 0, b"yes\n", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            self.assertEqual(module._login_value("Linger"), "yes")
        self.assertEqual(
            run.call_args.args[0],
            (
                "/usr/bin/loginctl",
                "show-user",
                module.AUTHORITY.executor_user,
                "--property=Linger",
                "--value",
            ),
        )

        with self.assertRaises(OSError):
            module._system_value("wrong.service", "ActiveState")
        with self.assertRaises(OSError):
            module._login_value("Wrong")

    def test_user_manager_and_linger_state_are_exact(self):
        system_values = {
            ("user@991.service", "LoadState"): "loaded",
            ("user@991.service", "ActiveState"): "active",
            ("user@991.service", "SubState"): "running",
            ("user@991.service", "UnitFileState"): "static",
            ("user@991.service", "MainPID"): "3000",
            ("user@991.service", "ControlGroup"): module._CGROUP_ROOT,
            ("user@991.service", "Delegate"): "yes",
            ("user@991.service", "DelegateControllers"): "pids cpu memory",
            ("user-runtime-dir@991.service", "LoadState"): "loaded",
            ("user-runtime-dir@991.service", "ActiveState"): "active",
            ("user-runtime-dir@991.service", "SubState"): "exited",
        }
        with patch.object(
            module,
            "_system_value",
            side_effect=lambda unit, prop: system_values[(unit, prop)],
        ):
            self.assertEqual(
                module._user_manager_state(),
                (
                    ("loaded", "active", "running", "static"),
                    3000,
                    ("loaded", "active", "exited"),
                ),
            )

        login_values = dict(
            zip(
                ("Linger", "RuntimePath", "UID", "Name", "State", "Sessions", "Display"),
                snapshot().linger_state,
                strict=True,
            )
        )
        with patch.object(
            module,
            "_login_value",
            side_effect=lambda prop: login_values[prop],
        ):
            self.assertEqual(module._linger_state(), snapshot().linger_state)

        login_values["Sessions"] = "7"
        with patch.object(
            module,
            "_login_value",
            side_effect=lambda prop: login_values[prop],
        ), self.assertRaises(OSError):
            module._linger_state()

    def test_snapshot_consumes_c33o_and_all_four_rootless_pids(self):
        state = persistence_state()
        with patch.object(
            module.persistence,
            "qualify_rootless_docker_persistence",
            return_value=state,
        ), patch.object(
            module,
            "_user_manager_state",
            return_value=(
                ("loaded", "active", "running", "static"),
                3000,
                ("loaded", "active", "exited"),
            ),
        ), patch.object(
            module,
            "_linger_state",
            return_value=snapshot().linger_state,
        ), patch.object(
            module,
            "_single_pid",
            side_effect=lambda name: {"containerd": 4002, "slirp4netns": 4003}[name],
        ):
            value = module._snapshot()

        self.assertEqual(value.user_manager_pid, 3000)
        self.assertEqual(value.rootlesskit_pid, state.daemon.rootlesskit_pid)
        self.assertEqual(value.dockerd_pid, state.daemon.dockerd_pid)
        self.assertEqual(value.containerd_pid, 4002)
        self.assertEqual(value.slirp4netns_pid, 4003)

    def test_candidate_snapshot_requires_two_identical_observations(self):
        value = snapshot()
        with patch.object(module, "_snapshot", side_effect=(value, value)) as observed:
            self.assertEqual(
                module.snapshot_rootless_docker_fresh_manager_candidate(),
                value,
            )
        self.assertEqual(observed.call_count, 2)

        changed = replace(value, user_manager_pid=3001)
        with patch.object(
            module,
            "_snapshot",
            side_effect=(value, changed),
        ), self.assertRaises(OSError):
            module.snapshot_rootless_docker_fresh_manager_candidate()

    def test_uid_process_boundary_prefilters_other_users_and_rejects_escape(self):
        entries = tuple(
            type("E", (), {"name": str(pid)})()
            for pid in (3000, 4000, 4001, 4002, 4003, 5000)
        )
        value = snapshot()
        cgroups = {
            3000: module._CGROUP_ROOT + "/init.scope",
            4000: module._CGROUP_ROOT + "/app.slice/rootless.service",
            4001: module._CGROUP_ROOT + "/app.slice/rootless.service",
            4002: module._CGROUP_ROOT + "/app.slice/rootless.service",
            4003: module._CGROUP_ROOT + "/app.slice/rootless.service",
        }
        with patch.object(
            module,
            "snapshot_rootless_docker_fresh_manager_candidate",
            return_value=value,
        ), patch.object(module.os, "scandir", return_value=entries), patch.object(
            module.c33f,
            "_proc_dir_uid",
            side_effect=lambda pid: 0 if pid == 5000 else module.AUTHORITY.executor_uid,
        ), patch.object(
            module,
            "_read_cgroup",
            side_effect=lambda pid: cgroups[pid],
        ) as cgroup:
            observed = module._uid_process_cgroup_boundary()

        self.assertEqual({pid for pid, _path in observed}, {3000, 4000, 4001, 4002, 4003})
        self.assertNotIn(call(5000), cgroup.call_args_list)

        cgroups[4002] = "/system.slice/unrelated.service"
        with patch.object(
            module,
            "snapshot_rootless_docker_fresh_manager_candidate",
            return_value=value,
        ), patch.object(module.os, "scandir", return_value=entries[:-1]), patch.object(
            module.c33f,
            "_proc_dir_uid",
            return_value=module.AUTHORITY.executor_uid,
        ), patch.object(
            module,
            "_read_cgroup",
            side_effect=lambda pid: cgroups[pid],
        ), self.assertRaises(OSError):
            module._uid_process_cgroup_boundary()

    def test_boot_contract_requires_condition_user_and_default_target(self):
        unit = """[Unit]
ConditionUser=omnilyzer-executor
[Service]
ExecStart=/usr/bin/python3 -I -B /opt/omnilyzer/deployment/rootless-docker/launch.py
Restart=always
[Install]
WantedBy=default.target
"""
        with patch.object(module.Path, "read_text", return_value=unit), patch.object(
            module.persistence, "_enable_link_evidence"
        ), patch.object(
            module.persistence,
            "_global_enable_evidence",
            return_value="enabled",
        ):
            self.assertEqual(
                module._boot_activation_contract(),
                (
                    "ConditionUser=omnilyzer-executor",
                    "ExecStart=/usr/bin/python3 -I -B /opt/omnilyzer/deployment/rootless-docker/launch.py",
                    "Restart=always",
                    "WantedBy=default.target",
                ),
            )

        bad = unit + "WantedBy=graphical-session.target\n"
        with patch.object(module.Path, "read_text", return_value=bad), self.assertRaises(OSError):
            module._boot_activation_contract()

    def test_preflight_is_non_fail_fast_and_never_runs_restart(self):
        events = []

        def good(name):
            def fn():
                events.append(name)
                return name
            return fn

        def bad():
            events.append("bad")
            raise OSError

        checks = (
            ("one", good("one")),
            ("bad", bad),
            ("three", good("three")),
        )
        with patch.object(module, "_component_checks", return_value=checks), patch.object(
            module.subprocess, "run"
        ) as run:
            result = module.preflight_rootless_docker_fresh_manager()

        self.assertEqual(events, ["one", "bad", "three"])
        self.assertFalse(result.passed)
        self.assertEqual(tuple(item.name for item in result.failures), ("bad",))
        run.assert_not_called()

        self.assertEqual(
            module._restart_command_contract(),
            ("/usr/bin/systemctl", "restart", "user@991.service"),
        )
        source = (
            ROOT / "deployment/rootless_docker_fresh_manager_preflight.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("subprocess.run(\n        _RESTART_COMMAND", source)
        self.assertNotIn("subprocess.run(_RESTART_COMMAND", source)


if __name__ == "__main__":
    unittest.main()
