"""Tests for C33E rootless Docker daemon start."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import json
import stat
import subprocess
import unittest
from unittest.mock import patch

from deployment import rootless_docker_daemon_start as module
from deployment.rootless_docker_authority import AUTHORITY


WORKFLOW = "a" * 40


def info_payload():
    return {
        "ServerVersion": AUTHORITY.engine_version,
        "Driver": "overlay2",
        "DockerRootDir": AUTHORITY.data_root,
        "CgroupDriver": "systemd",
        "CgroupVersion": "2",
        "SecurityOptions": [
            "name=seccomp,profile=builtin",
            "name=cgroupns",
            "name=rootless",
        ],
        "Containers": 0,
        "ContainersRunning": 0,
        "ContainersPaused": 0,
        "ContainersStopped": 0,
        "Images": 0,
        "LiveRestoreEnabled": False,
        "Swarm": {"LocalNodeState": "inactive"},
    }


def evidence(operation="started"):
    return module.RootlessDockerDaemonStartEvidence(
        operation=operation,
        expected_workflow_sha=WORKFLOW,
        user_unit_state=("loaded", "active", "running", "disabled"),
        daemon_socket=AUTHORITY.daemon_socket,
        socket_uid=AUTHORITY.executor_uid,
        socket_gid=AUTHORITY.executor_gid,
        socket_mode=AUTHORITY.daemon_socket_mode,
        dockerd_pid=4242,
        dockerd_argv=module._EXPECTED_DOCKERD_ARGV,
        server_version=AUTHORITY.engine_version,
        storage_driver="overlay2",
        docker_root_dir=AUTHORITY.data_root,
        cgroup_driver="systemd",
        cgroup_version="2",
        security_options=(
            "name=cgroupns",
            "name=rootless",
            "name=seccomp,profile=builtin",
        ),
        containers=(0, 0, 0, 0),
        images=0,
    )


class RootlessDockerDaemonStartTests(unittest.TestCase):
    def test_evidence_is_exact_and_immutable(self):
        value = evidence()
        with self.assertRaises(FrozenInstanceError):
            value.operation = "other"
        values = {name: getattr(value, name) for name in value.__dataclass_fields__}
        for field, bad in (
            ("operation", "other"),
            ("user_unit_state", ("loaded", "active", "running", "enabled")),
            ("socket_mode", 0o666),
            ("dockerd_argv", module._EXPECTED_DOCKERD_ARGV[:-1]),
            ("server_version", "0"),
            ("storage_driver", "vfs"),
            ("cgroup_driver", "cgroupfs"),
            ("security_options", ("name=cgroupns",)),
            ("containers", (1, 1, 0, 0)),
            ("images", 1),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.RootlessDockerDaemonStartEvidence(**(values | {field: bad}))

    def test_mutation_runner_allows_only_exact_user_unit_start(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        expected = (
            module._SYSTEMCTL,
            "--user",
            "--machine=omnilyzer-executor@.host",
            "start",
            module._USER_UNIT,
        )
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            self.assertIs(module._run(expected), completed)
        self.assertFalse(run.call_args.kwargs["shell"])

        for argv in (
            (
                module._SYSTEMCTL,
                "--user",
                "--machine=omnilyzer-executor@.host",
                "enable",
                module._USER_UNIT,
            ),
            (
                module._SYSTEMCTL,
                "--user",
                "--machine=omnilyzer-executor@.host",
                "start",
                "default.target",
            ),
            (module._SYSTEMCTL, "start", "docker.service"),
        ):
            with self.subTest(argv=argv), patch.object(
                module.subprocess, "run"
            ) as run, self.assertRaises(OSError):
                module._run(argv)
            run.assert_not_called()

    def test_post_daemon_static_assets_use_transitioned_data_root_only(self):
        expected_data = next(
            item for item in AUTHORITY.post_daemon_provisioned_directories
            if item[0] == AUTHORITY.data_root
        )
        with patch.object(
            module, "_require_post_daemon_data_root", return_value=expected_data
        ) as data_root, patch.object(
            module.userq.staticq,
            "_require_directory",
            side_effect=lambda path, uid, gid, mode, _children: (path, uid, gid, mode),
        ) as require_directory, patch.object(
            module.userq.staticq,
            "_require_file",
            side_effect=lambda path, digest, uid, gid, mode: (path, digest, uid, gid, mode),
        ):
            directories, assets = module._require_post_daemon_static_assets()

        self.assertEqual(directories, AUTHORITY.post_daemon_provisioned_directories)
        self.assertEqual(
            assets,
            tuple(
                (destination, digest, uid, gid, mode)
                for _source, destination, digest, uid, gid, mode
                in AUTHORITY.installed_assets
            ),
        )
        data_root.assert_called_once_with()
        self.assertEqual(
            require_directory.call_count,
            len(AUTHORITY.post_daemon_provisioned_directories) - 1,
        )

    def test_runtime_artifact_modes_are_exact_rootless_host_view(self):
        pid = type("S", (), {
            "st_mode": stat.S_IFREG | AUTHORITY.pid_file_mode,
            "st_uid": 991, "st_gid": 991,
        })()
        root = type("S", (), {
            "st_mode": stat.S_IFDIR | AUTHORITY.exec_root_mode,
            "st_uid": 991, "st_gid": 991,
        })()
        with patch.object(
            module.os, "lstat",
            side_effect=lambda path: pid if path == AUTHORITY.pid_file else root,
        ):
            module._runtime_artifacts_exact()

        bad = type("S", (), {
            "st_mode": stat.S_IFREG | 0o644,
            "st_uid": 991, "st_gid": 991,
        })()
        with patch.object(module.os, "lstat", return_value=bad), self.assertRaises(OSError):
            module._runtime_artifacts_exact()

    def test_docker_info_uses_exact_private_endpoint_and_closed_config(self):
        payload = json.dumps(info_payload()).encode("utf-8") + b"\n"
        completed = subprocess.CompletedProcess((), 0, payload, b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            value = module._docker_info_evidence()
        argv = run.call_args.args[0]
        self.assertEqual(
            argv,
            (
                AUTHORITY.docker_cli,
                "--config",
                "/etc/omnilyzer/deployment/docker-client",
                "--host",
                "unix://" + AUTHORITY.daemon_socket,
                "info",
                "--format",
                "json",
            ),
        )
        self.assertEqual(value[0], AUTHORITY.engine_version)
        self.assertEqual(value[1], "overlay2")
        self.assertEqual(value[2], AUTHORITY.data_root)
        self.assertEqual(value[3:5], ("systemd", "2"))
        self.assertIn("name=rootless", value[5])
        self.assertEqual(value[6:], ((0, 0, 0, 0), 0))

    def test_docker_info_rejects_nonrootless_or_nonempty_inventory(self):
        for mutate in (
            lambda x: x.update(SecurityOptions=["name=cgroupns"]),
            lambda x: x.update(Driver="vfs"),
            lambda x: x.update(DockerRootDir="/var/lib/docker"),
            lambda x: x.update(Containers=1, ContainersRunning=1),
            lambda x: x.update(Images=1),
            lambda x: x.update(LiveRestoreEnabled=True),
            lambda x: x.update(Swarm={"LocalNodeState": "active"}),
        ):
            payload = info_payload()
            mutate(payload)
            completed = subprocess.CompletedProcess(
                (), 0, json.dumps(payload).encode() + b"\n", b""
            )
            with self.subTest(payload=payload), patch.object(
                module.subprocess, "run", return_value=completed
            ), self.assertRaises(OSError):
                module._docker_info_evidence()

    def test_initial_start_consumes_c33d_before_exact_start(self):
        before = SimpleNamespace(
            expected_workflow_sha=WORKFLOW,
            subuid_records=(("omnigpt", 427680, 65536),),
            subgid_records=(("omnigpt", 427680, 65536),),
            directories=AUTHORITY.provisioned_directories,
            assets=("assets",),
            linger_mode=0o644,
            runtime_directory=AUTHORITY.runtime_directory,
            runtime_uid=991,
            runtime_gid=991,
            runtime_mode=0o700,
            packages=("packages",),
            host_dependencies=("deps",),
            critical_executables=("execs",),
            cgroup_controllers=("cpu", "memory", "pids"),
            bundle="bundle",
            executor_dropins=(AUTHORITY.executor_socket_dropin,),
            user_manager_dropins=module.userq.staticq._expected_user_manager_dropins(),
            user_manager_control_group="/user.slice/user-991.slice/user@991.service",
            delegate_controllers=("cpu", "memory", "pids"),
        )
        after = (
            (
                WORKFLOW,
                (992,),
                before.host_dependencies,
                before.packages,
                before.cgroup_controllers,
                before.critical_executables,
                before.bundle,
            ),
            before.subuid_records,
            before.subgid_records,
            AUTHORITY.post_daemon_provisioned_directories,
            before.assets,
            before.linger_mode,
            (
                before.runtime_directory,
                before.runtime_uid,
                before.runtime_gid,
                before.runtime_mode,
            ),
            before.executor_dropins,
            before.user_manager_dropins,
            before.user_manager_control_group,
            before.delegate_controllers,
        )
        events = []
        completed = subprocess.CompletedProcess((), 0, b"", b"")

        def start(argv):
            events.append(("start", argv))
            return completed

        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(
                 module,
                 "_user_unit_state",
                 return_value=("loaded", "inactive", "dead", "disabled"),
             ),              patch.object(
                 module.userq,
                 "qualify_rootless_docker_user_manager",
                 side_effect=lambda: events.append(("c33d", None)) or before,
             ),              patch.object(module, "_run", side_effect=start),              patch.object(module, "_static_evidence_after_start", return_value=after),              patch.object(
                 module, "_ready_evidence", return_value=evidence("started")
             ):
            value = module._start_under_lock()

        self.assertEqual(value.operation, "started")
        self.assertEqual(events[0][0], "c33d")
        self.assertEqual(events[1][0], "start")

    def test_already_started_is_idempotent(self):
        after = (
            (WORKFLOW, (992,), (), (), ("cpu", "memory", "pids"), (), "bundle"),
            (),
            (),
            (),
            (),
            0o644,
            (AUTHORITY.runtime_directory, 991, 991, 0o700),
            (AUTHORITY.executor_socket_dropin,),
            module.userq.staticq._expected_user_manager_dropins(),
            "/user.slice/user-991.slice/user@991.service",
            ("cpu", "memory", "pids"),
        )
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(
                 module,
                 "_user_unit_state",
                 return_value=("loaded", "active", "running", "disabled"),
             ),              patch.object(module.userq, "qualify_rootless_docker_user_manager") as c33d,              patch.object(module, "_run") as run,              patch.object(module, "_static_evidence_after_start", return_value=after),              patch.object(
                 module,
                 "_ready_evidence",
                 return_value=evidence("already-started"),
             ):
            value = module._start_under_lock()
        self.assertEqual(value.operation, "already-started")
        c33d.assert_not_called()
        run.assert_not_called()

    def test_ambiguous_user_unit_state_fails_without_mutation(self):
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(
                 module,
                 "_user_unit_state",
                 return_value=("loaded", "failed", "failed", "disabled"),
             ),              patch.object(module, "_run") as run,              self.assertRaises(OSError):
            module._start_under_lock()
        run.assert_not_called()

    def test_public_boundary_holds_lock_and_collapses_failure(self):
        expected = evidence()
        lock = object()
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(
                 module.orchestration, "_acquire_process_lock", return_value=lock
             ) as acquire,              patch.object(module, "_start_under_lock", return_value=expected),              patch.object(
                 module.orchestration, "_release_process_lock"
             ) as release:
            self.assertEqual(module.start_rootless_docker_daemon(), expected)
        acquire.assert_called_once_with()
        release.assert_called_once_with(lock)

        with patch.object(module, "_root_identity", side_effect=OSError("private")),              self.assertRaises(module.RootlessDockerDaemonStartError) as caught:
            module.start_rootless_docker_daemon()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_source_has_no_enable_deployment_or_tcp_surface(self):
        source = Path(
            "deployment/rootless_docker_daemon_start.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            '("enable", _USER_UNIT)',
            '"enable-now"',
            '"tcp://"',
            '("/usr/bin/systemctl", "start", "docker.service")',
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
