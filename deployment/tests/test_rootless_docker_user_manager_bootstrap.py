"""Tests for C33C rootless Docker user-manager bootstrap."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import patch

from deployment import rootless_docker_user_manager_bootstrap as module
from deployment.rootless_docker_authority import AUTHORITY


WORKFLOW = "a" * 40


def package_host():
    return (
        WORKFLOW,
        (992,),
        (("libc6", "2.39-test", "amd64"),),
        (("docker-ce", "5:29.8.1-test", "amd64"),),
        ("cpu", "io", "memory", "pids"),
        (("docker-ce", "/usr/bin/dockerd", 0o755, "b" * 64),),
        ("bundle",),
    )


def static_state():
    return (
        package_host(),
        (
            ("omnigpt", 427680, 65536),
            (AUTHORITY.executor_user, AUTHORITY.subuid_start, AUTHORITY.subordinate_count),
        ),
        (
            ("omnigpt", 427680, 65536),
            (AUTHORITY.executor_user, AUTHORITY.subgid_start, AUTHORITY.subordinate_count),
        ),
        AUTHORITY.provisioned_directories,
        tuple(
            (destination, digest, uid, gid, mode)
            for _source, destination, digest, uid, gid, mode
            in AUTHORITY.installed_assets
        ),
    )


def static_evidence():
    state = static_state()
    return SimpleNamespace(
        expected_workflow_sha=WORKFLOW,
        subuid_records=state[1],
        subgid_records=state[2],
        directories=state[3],
        assets=state[4],
        packages=state[0][3],
        host_dependencies=state[0][2],
        critical_executables=state[0][5],
        cgroup_controllers=state[0][4],
        executor_dropins=(AUTHORITY.executor_socket_dropin,),
        user_manager_dropins=module.staticq._expected_user_manager_dropins(),
        bundle=state[0][6],
    )


def evidence(operation="bootstrapped"):
    expected_subid = (
        AUTHORITY.executor_user,
        AUTHORITY.subuid_start,
        AUTHORITY.subordinate_count,
    )
    return module.RootlessDockerUserManagerBootstrapEvidence(
        operation=operation,
        expected_workflow_sha=WORKFLOW,
        linger_path=module._LINGER_PATH,
        runtime_directory=AUTHORITY.runtime_directory,
        runtime_uid=AUTHORITY.executor_uid,
        runtime_gid=AUTHORITY.executor_gid,
        runtime_mode=0o700,
        user_manager=module._USER_MANAGER,
        user_manager_control_group="/user.slice/user-991.slice/user@991.service",
        delegate_controllers=("cpu", "memory", "pids"),
        static_subuid=expected_subid,
        static_subgid=expected_subid,
    )


class RootlessDockerUserManagerBootstrapTests(unittest.TestCase):
    def test_evidence_is_exact_and_immutable(self):
        value = evidence()
        with self.assertRaises(FrozenInstanceError):
            value.operation = "resumed"
        values = {
            name: getattr(value, name)
            for name in value.__dataclass_fields__
        }
        for field, bad in (
            ("operation", "other"),
            ("expected_workflow_sha", "0" * 40),
            ("runtime_mode", 0o755),
            ("delegate_controllers", ("cpu", "memory")),
            ("static_subuid", ("wrong", 1, 2)),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.RootlessDockerUserManagerBootstrapEvidence(
                    **(values | {field: bad})
                )

    def test_phase_accepts_only_initial_resume_or_complete(self):
        with patch.object(module, "_linger_state", return_value="absent"),              patch.object(module, "_runtime_state", return_value="absent"),              patch.object(module, "_read_systemctl", return_value="inactive"):
            self.assertEqual(module._phase()[0], "initial")

        with patch.object(module, "_linger_state", return_value="exact"),              patch.object(module, "_runtime_state", return_value="absent"),              patch.object(module, "_read_systemctl", return_value="inactive"):
            self.assertEqual(module._phase()[0], "resume")

        with patch.object(module, "_linger_state", return_value="exact"),              patch.object(module, "_runtime_state", return_value="exact"),              patch.object(module, "_read_systemctl", return_value="active"):
            self.assertEqual(module._phase()[0], "complete")

        for linger, runtime, manager in (
            ("absent", "exact", "active"),
            ("absent", "absent", "active"),
            ("exact", "exact", "inactive"),
            ("absent", "exact", "inactive"),
        ):
            with self.subTest(
                linger=linger, runtime=runtime, manager=manager
            ), patch.object(module, "_linger_state", return_value=linger),                  patch.object(module, "_runtime_state", return_value=runtime),                  patch.object(module, "_read_systemctl", return_value=manager),                  self.assertRaises(OSError):
                module._phase()

    def test_mutation_runner_allows_only_linger_and_user_manager_start(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        for argv in (
            (module._LOGINCTL, "enable-linger", AUTHORITY.executor_user),
            (module._SYSTEMCTL, "start", module._USER_MANAGER),
        ):
            with self.subTest(argv=argv), patch.object(
                module.subprocess, "run", return_value=completed
            ) as run:
                self.assertIs(module._run(argv), completed)
                self.assertFalse(run.call_args.kwargs["shell"])
                self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

        for argv in (
            (module._LOGINCTL, "enable-linger", "trust"),
            (module._LOGINCTL, "disable-linger", AUTHORITY.executor_user),
            (module._SYSTEMCTL, "start", "docker.service"),
            (module._SYSTEMCTL, "start", "omnilyzer-task014-rootless-docker.service"),
            (module._SYSTEMCTL, "enable", module._USER_MANAGER),
        ):
            with self.subTest(argv=argv), patch.object(
                module.subprocess, "run"
            ) as run, self.assertRaises(OSError):
                module._run(argv)
            run.assert_not_called()

    def test_initial_transition_requires_c33a_before_linger_then_manager(self):
        events = []
        completed = subprocess.CompletedProcess((), 0, b"", b"")

        def run(argv):
            events.append(argv)
            return completed

        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(module, "_phase", return_value=("initial", "absent", "absent")),              patch.object(
                 module.staticq,
                 "qualify_rootless_docker_static_bootstrap",
                 side_effect=lambda: events.append("c33a") or static_evidence(),
             ),              patch.object(module, "_run", side_effect=run),              patch.object(module, "_linger_state", return_value="exact"),              patch.object(module, "_require_rootless_inactive"),              patch.object(
                 module,
                 "_require_complete_user_manager",
                 return_value=(
                     "/user.slice/user-991.slice/user@991.service",
                     ("cpu", "memory", "pids"),
                 ),
             ),              patch.object(module, "_static_state", return_value=static_state()):
            value = module._bootstrap_under_lock()

        self.assertEqual(value.operation, "bootstrapped")
        self.assertEqual(events[0], "c33a")
        self.assertEqual(
            events[1],
            (module._LOGINCTL, "enable-linger", AUTHORITY.executor_user),
        )
        self.assertEqual(events[2], (module._SYSTEMCTL, "start", module._USER_MANAGER))

    def test_resume_does_not_reenable_linger_or_reuse_c33a(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(module, "_phase", return_value=("resume", "exact", "absent")),              patch.object(module, "_static_state", return_value=static_state()),              patch.object(
                 module.staticq, "qualify_rootless_docker_static_bootstrap"
             ) as c33a,              patch.object(module, "_require_rootless_inactive"),              patch.object(module, "_run", return_value=completed) as run,              patch.object(
                 module,
                 "_require_complete_user_manager",
                 return_value=(
                     "/user.slice/user-991.slice/user@991.service",
                     ("cpu", "memory", "pids"),
                 ),
             ):
            value = module._bootstrap_under_lock()

        self.assertEqual(value.operation, "resumed")
        c33a.assert_not_called()
        run.assert_called_once_with((module._SYSTEMCTL, "start", module._USER_MANAGER))

    def test_complete_state_is_idempotent_without_mutation(self):
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(module, "_phase", return_value=("complete", "exact", "exact")),              patch.object(module, "_static_state", return_value=static_state()),              patch.object(module, "_run") as run,              patch.object(
                 module,
                 "_require_complete_user_manager",
                 return_value=(
                     "/user.slice/user-991.slice/user@991.service",
                     ("cpu", "memory", "pids"),
                 ),
             ):
            value = module._bootstrap_under_lock()

        self.assertEqual(value.operation, "already-bootstrapped")
        run.assert_not_called()

    def test_public_boundary_holds_shared_lock_and_collapses_failure(self):
        expected = evidence()
        lock = object()
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(
                 module.orchestration, "_acquire_process_lock", return_value=lock
             ) as acquire,              patch.object(module, "_bootstrap_under_lock", return_value=expected),              patch.object(
                 module.orchestration, "_release_process_lock"
             ) as release:
            self.assertEqual(module.bootstrap_rootless_docker_user_manager(), expected)
        acquire.assert_called_once_with()
        release.assert_called_once_with(lock)

        with patch.object(module, "_root_identity", side_effect=OSError("private")),              self.assertRaises(module.RootlessDockerUserManagerBootstrapError) as caught:
            module.bootstrap_rootless_docker_user_manager()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_source_has_no_docker_activation_or_deployment_surface(self):
        source = Path(
            "deployment/rootless_docker_user_manager_bootstrap.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "disable-linger",
            "/usr/bin/docker",
            "docker run",
            "systemctl --user start",
            "enable-now",
            '("/usr/bin/systemctl", "start", "omnilyzer-deployment-broker.service")',
            '("/usr/bin/systemctl", "start", "omnilyzer-deployment-executor.service")',
            "shell=True",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
