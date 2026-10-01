"""Tests for the C33N rootless Docker persistence enablement."""

from dataclasses import FrozenInstanceError
import os
import stat
import subprocess
import unittest
from unittest.mock import patch

from deployment import rootless_docker_persistence_enablement as module
from deployment.tests.test_rootless_docker_daemon_qualification import (
    evidence as daemon_evidence,
)


def link_stat():
    return type(
        "S",
        (),
        {
            "st_mode": stat.S_IFLNK | 0o777,
            "st_uid": 0,
            "st_gid": 0,
            "st_nlink": 1,
        },
    )()


class RootlessDockerPersistenceEnablementTests(unittest.TestCase):
    def test_evidence_is_exact_and_immutable(self):
        value = module.RootlessDockerPersistenceEnablementEvidence(
            operation="enabled",
            enable_link=(
                module._ENABLE_LINK,
                module.AUTHORITY.user_unit,
                0,
                0,
                0o777,
            ),
            before_unit_state=("loaded", "active", "running", "disabled"),
            after_unit_state=("loaded", "active", "running", "enabled"),
            before_pids=(4000, 4001),
            after_pids=(4000, 4001),
            daemon_signature_equal=True,
            containers=(0, 0, 0, 0),
            images=0,
        )
        with self.assertRaises(FrozenInstanceError):
            value.images = 1

        values = {
            name: getattr(value, name)
            for name in value.__dataclass_fields__
        }
        for change in (
            {"operation": "wrong"},
            {"enable_link": (module._ENABLE_LINK, "wrong", 0, 0, 0o777)},
            {"after_unit_state": ("loaded", "active", "running", "disabled")},
            {"after_pids": (5000, 5001)},
            {"daemon_signature_equal": False},
            {"containers": (1, 1, 0, 0)},
            {"images": 1},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.RootlessDockerPersistenceEnablementEvidence(
                    **(values | change)
                )

    def test_enable_command_is_global_exact_and_never_now(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            module._run_enable()

        self.assertEqual(
            run.call_args.args[0],
            (
                "/usr/bin/systemctl",
                "--global",
                "enable",
                "omnilyzer-task014-rootless-docker.service",
            ),
        )
        self.assertNotIn("--now", run.call_args.args[0])
        self.assertNotIn("start", run.call_args.args[0])
        self.assertNotIn("restart", run.call_args.args[0])
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.PIPE)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(run.call_args.kwargs["check"])

        with patch.object(
            module.subprocess,
            "run",
            return_value=subprocess.CompletedProcess((), 1, b"", b"failed"),
        ), self.assertRaises(OSError):
            module._run_enable()

    def test_enable_link_requires_exact_global_symlink(self):
        with patch.object(module.os, "lstat", return_value=link_stat()),              patch.object(
                 module.os,
                 "readlink",
                 return_value=module.AUTHORITY.user_unit,
             ):
            self.assertEqual(
                module._enable_link_evidence(),
                (
                    module._ENABLE_LINK,
                    module.AUTHORITY.user_unit,
                    0,
                    0,
                    0o777,
                ),
            )

        bad = link_stat()
        bad.st_uid = 991
        with patch.object(module.os, "lstat", return_value=bad),              patch.object(
                 module.os,
                 "readlink",
                 return_value=module.AUTHORITY.user_unit,
             ), self.assertRaises(OSError):
            module._enable_link_evidence()

    def test_enabled_user_unit_requires_enabled_running_same_fragment(self):
        values = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "UnitFileState": "enabled",
            "FragmentPath": module.AUTHORITY.user_unit,
            "MainPID": "4000",
        }
        with patch.object(
            module.c33f,
            "_read_user_systemctl",
            side_effect=lambda name: values[name],
        ), patch.object(
            module.c33f,
            "_canonical_user_unit_fragment",
            side_effect=lambda value: value,
        ), patch.object(module, "_enable_link_evidence"):
            self.assertEqual(
                module._enabled_user_unit_evidence(),
                (
                    ("loaded", "active", "running", "enabled"),
                    module.AUTHORITY.user_unit,
                    4000,
                ),
            )

        values["UnitFileState"] = "disabled"
        with patch.object(
            module.c33f,
            "_read_user_systemctl",
            side_effect=lambda name: values[name],
        ), patch.object(
            module.c33f,
            "_canonical_user_unit_fragment",
            side_effect=lambda value: value,
        ), self.assertRaises(OSError):
            module._enabled_user_unit_evidence()

    def test_post_enable_requires_full_c33f_equivalence_and_same_pids(self):
        before = daemon_evidence()
        package_host = (
            before.expected_workflow_sha,
            ("ignored",),
            before.host_dependencies,
            before.packages,
            before.cgroup_controllers,
            before.critical_executables,
            before.bundle,
        )
        info = (
            before.server_version,
            before.storage_driver,
            before.docker_root_dir,
            before.cgroup_driver,
            before.cgroup_version,
            before.security_options,
            before.containers,
            before.images,
        )
        user_manager = (
            before.linger_mode,
            before.runtime_directory,
            before.user_manager_control_group,
            before.delegate_controllers,
        )
        enabled_state = ("loaded", "active", "running", "enabled")
        link = (
            module._ENABLE_LINK,
            module.AUTHORITY.user_unit,
            0,
            0,
            0o777,
        )

        def static_systemctl(unit, prop):
            self.assertEqual(prop, "DropInPaths")
            return (
                " ".join(before.executor_dropins)
                if unit == "omnilyzer-deployment-executor.service"
                else " ".join(before.user_manager_dropins)
            )

        with patch.object(module, "_root_identity", return_value=(0, 0)),              patch.object(module.c33f, "_package_host", return_value=package_host),              patch.object(
                 module.c33f.userq.staticq,
                 "_require_subids",
                 return_value=(before.subuid_records, before.subgid_records),
             ), patch.object(
                 module.c33f,
                 "_require_post_daemon_static_assets",
                 return_value=(before.directories, before.assets),
             ), patch.object(
                 module.c33f.userq.staticq,
                 "_require_user_manager_template_dropins",
             ), patch.object(
                 module.c33f.userq.staticq,
                 "_read_systemctl",
                 side_effect=static_systemctl,
             ), patch.object(
                 module.c33f.userq,
                 "_read_systemctl",
                 return_value="inactive",
             ), patch.object(
                 module,
                 "_enabled_user_unit_evidence",
                 return_value=(
                     enabled_state,
                     before.user_unit_fragment,
                     before.user_unit_main_pid,
                 ),
             ), patch.object(
                 module.c33f,
                 "_process_evidence",
                 return_value=(
                     before.rootlesskit_pid,
                     before.rootlesskit_argv,
                     before.dockerd_pid,
                     before.dockerd_argv,
                 ),
             ), patch.object(
                 module.c33f,
                 "_socket_evidence",
                 return_value=(
                     before.daemon_socket,
                     before.socket_uid,
                     before.socket_gid,
                     before.socket_mode,
                 ),
             ), patch.object(
                 module.c33f,
                 "_rootlesskit_state_evidence",
                 return_value=before.rootlesskit_state,
             ), patch.object(
                 module.c33f,
                 "_runtime_artifacts_exact",
             ), patch.object(
                 module.c33f,
                 "_docker_info_evidence",
                 return_value=info,
             ), patch.object(
                 module.c33f,
                 "_user_manager_evidence",
                 return_value=user_manager,
             ), patch.object(
                 module,
                 "_enable_link_evidence",
                 return_value=link,
             ):
            self.assertEqual(
                module._post_enable_matches(before),
                (
                    enabled_state,
                    (before.rootlesskit_pid, before.dockerd_pid),
                    link,
                ),
            )

        drift_info = (*info[:-1], 1)
        with patch.object(module, "_root_identity", return_value=(0, 0)),              patch.object(module.c33f, "_package_host", return_value=package_host),              patch.object(
                 module.c33f.userq.staticq,
                 "_require_subids",
                 return_value=(before.subuid_records, before.subgid_records),
             ), patch.object(
                 module.c33f,
                 "_require_post_daemon_static_assets",
                 return_value=(before.directories, before.assets),
             ), patch.object(
                 module.c33f.userq.staticq,
                 "_require_user_manager_template_dropins",
             ), patch.object(
                 module.c33f.userq.staticq,
                 "_read_systemctl",
                 side_effect=static_systemctl,
             ), patch.object(
                 module.c33f.userq,
                 "_read_systemctl",
                 return_value="inactive",
             ), patch.object(
                 module,
                 "_enabled_user_unit_evidence",
                 return_value=(
                     enabled_state,
                     before.user_unit_fragment,
                     before.user_unit_main_pid,
                 ),
             ), patch.object(
                 module.c33f,
                 "_process_evidence",
                 return_value=(
                     before.rootlesskit_pid,
                     before.rootlesskit_argv,
                     before.dockerd_pid,
                     before.dockerd_argv,
                 ),
             ), patch.object(
                 module.c33f,
                 "_socket_evidence",
                 return_value=(
                     before.daemon_socket,
                     before.socket_uid,
                     before.socket_gid,
                     before.socket_mode,
                 ),
             ), patch.object(
                 module.c33f,
                 "_rootlesskit_state_evidence",
                 return_value=before.rootlesskit_state,
             ), patch.object(module.c33f, "_runtime_artifacts_exact"),              patch.object(
                 module.c33f,
                 "_docker_info_evidence",
                 return_value=drift_info,
             ), patch.object(
                 module.c33f,
                 "_user_manager_evidence",
                 return_value=user_manager,
             ), self.assertRaises(OSError):
            module._post_enable_matches(before)

    def test_enable_under_lock_runs_c33f_then_one_enable_then_postcheck(self):
        before = daemon_evidence()
        state = ("loaded", "active", "running", "enabled")
        link = (
            module._ENABLE_LINK,
            module.AUTHORITY.user_unit,
            0,
            0,
            0o777,
        )
        events = []
        with patch.object(
            module.c33f,
            "qualify_rootless_docker_daemon",
            side_effect=lambda: events.append("c33f") or before,
        ), patch.object(
            module,
            "_run_enable",
            side_effect=lambda: events.append("enable"),
        ), patch.object(
            module,
            "_post_enable_matches",
            side_effect=lambda _before: events.append("post") or (
                state,
                (before.rootlesskit_pid, before.dockerd_pid),
                link,
            ),
        ):
            result = module._enable_under_lock()

        self.assertEqual(events, ["c33f", "enable", "post"])
        self.assertEqual(result.operation, "enabled")
        self.assertEqual(result.before_pids, result.after_pids)

    def test_public_transition_is_root_locked_and_generic_on_failure(self):
        expected = module.RootlessDockerPersistenceEnablementEvidence(
            operation="enabled",
            enable_link=(
                module._ENABLE_LINK,
                module.AUTHORITY.user_unit,
                0,
                0,
                0o777,
            ),
            before_unit_state=("loaded", "active", "running", "disabled"),
            after_unit_state=("loaded", "active", "running", "enabled"),
            before_pids=(4000, 4001),
            after_pids=(4000, 4001),
            daemon_signature_equal=True,
            containers=(0, 0, 0, 0),
            images=0,
        )
        with patch.object(module, "_root_identity", return_value=(0, 0)),              patch.object(
                 module.orchestration,
                 "_acquire_process_lock",
                 return_value=70,
             ) as acquire, patch.object(
                 module,
                 "_enable_under_lock",
                 return_value=expected,
             ), patch.object(
                 module.orchestration,
                 "_release_process_lock",
             ) as release:
            self.assertEqual(
                module.enable_rootless_docker_persistence(),
                expected,
            )
        acquire.assert_called_once_with()
        release.assert_called_once_with(70)

        with patch.object(module, "_root_identity", side_effect=OSError("private")):
            with self.assertRaises(
                module.RootlessDockerPersistenceEnablementError
            ) as caught:
                module.enable_rootless_docker_persistence()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
