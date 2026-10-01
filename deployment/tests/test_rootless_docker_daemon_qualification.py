"""Tests for C33F running rootless Docker daemon qualification."""

from dataclasses import FrozenInstanceError
from pathlib import Path
import json
import stat
import subprocess
import unittest
from unittest.mock import call, patch

from deployment import rootless_docker_daemon_qualification as module
from deployment.rootless_docker_authority import AUTHORITY
from deployment.rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from deployment.rootless_docker_package_bundle_qualification import (
    PackageBundleFileEvidence,
    RootlessDockerPackageBundleEvidence,
)


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40


def bundle_evidence():
    files = tuple(
        PackageBundleFileEvidence(
            item.package,
            item.filename,
            item.size,
            item.sha256,
            (
                stat.S_IFREG | 0o600,
                index + 100,
                10,
                1,
                0,
                0,
                item.size,
                1000 + index,
                2000 + index,
            ),
        )
        for index, item in enumerate(INSTALLATION_AUTHORITY.payloads)
    )
    return RootlessDockerPackageBundleEvidence(
        INSTALLATION_AUTHORITY.staging_directory,
        "sha256",
        INSTALLATION_AUTHORITY.bundle_size(),
        (stat.S_IFDIR | 0o700, 99, 10, 2, 0, 0, 4096, 3000, 4000),
        files,
    )


def package_rows():
    versions = {
        item.name: item.apt_version
        for item in (
            *INSTALLATION_AUTHORITY.packages,
            *INSTALLATION_AUTHORITY.supplemental_packages,
        )
    }
    return tuple(
        (payload.package, versions[payload.package], "amd64")
        for payload in INSTALLATION_AUTHORITY.payloads
    )


def dependency_rows():
    return tuple(
        (item.package, "9.9-test", item.architecture)
        for item in INSTALLATION_AUTHORITY.host_dependencies
    )


def executable_rows():
    values = []
    for index, (package, path) in enumerate(
        module.userq.staticq.postinstall._REQUIRED_EXECUTABLES
    ):
        sha256 = (
            AUTHORITY.vendor_rootless_script_sha256
            if path == AUTHORITY.vendor_rootless_script
            else format(index + 1, "064x")
        )
        values.append(
            (
                package,
                path,
                module.userq.staticq.postinstall._EXECUTABLE_MODES[path],
                sha256,
            )
        )
    return tuple(values)


def subids():
    return (
        ("ysabel", 100000, 65536),
        ("trust", 165536, 65536),
        ("ayeshia", 231072, 65536),
        ("jane", 296608, 65536),
        ("omnidev", 362144, 65536),
        ("omnigpt", 427680, 65536),
        (AUTHORITY.executor_user, AUTHORITY.subuid_start, AUTHORITY.subordinate_count),
    )


def rootlesskit_argv():
    return (
        AUTHORITY.rootlesskit,
        "--state-dir=" + AUTHORITY.rootlesskit_state,
        "--net=slirp4netns",
        "--mtu=65520",
        "--slirp4netns-sandbox=auto",
        "--slirp4netns-seccomp=auto",
        "--disable-host-loopback",
        "--port-driver=builtin",
        "--copy-up=/etc",
        "--copy-up=/run",
        "--propagation=rslave",
        "--detach-netns",
        "--subid-source=static",
        "--slirp4netns-binary=/usr/bin/slirp4netns",
        AUTHORITY.vendor_rootless_script,
        *module._EXPECTED_DOCKERD_ARGV[1:],
    )


def evidence(workflow=WORKFLOW):
    return module.RootlessDockerDaemonEvidence(
        application_reviewed_commit=module.userq.staticq.TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=workflow,
        user_unit_state=("loaded", "active", "running", "disabled"),
        user_unit_fragment=AUTHORITY.user_unit,
        user_unit_main_pid=4000,
        rootlesskit_pid=4000,
        rootlesskit_argv=rootlesskit_argv(),
        dockerd_pid=4001,
        dockerd_argv=module._EXPECTED_DOCKERD_ARGV,
        daemon_socket=AUTHORITY.daemon_socket,
        socket_uid=991,
        socket_gid=991,
        socket_mode=AUTHORITY.daemon_socket_mode,
        rootlesskit_state=(AUTHORITY.rootlesskit_state, 991, 991, AUTHORITY.rootlesskit_state_mode),
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
        linger_mode=0o644,
        runtime_directory=(AUTHORITY.runtime_directory, 991, 991, 0o700),
        user_manager_control_group="/user.slice/user-991.slice/user@991.service",
        delegate_controllers=("cpu", "memory", "pids"),
        subuid_records=subids(),
        subgid_records=subids(),
        directories=AUTHORITY.post_daemon_provisioned_directories,
        assets=tuple(
            (destination, digest, uid, gid, mode)
            for _source, destination, digest, uid, gid, mode
            in AUTHORITY.installed_assets
        ),
        packages=package_rows(),
        host_dependencies=dependency_rows(),
        masked_units=INSTALLATION_AUTHORITY.rootful_units,
        critical_executables=executable_rows(),
        cgroup_controllers=("cpu", "io", "memory", "pids"),
        executor_dropins=(AUTHORITY.executor_socket_dropin,),
        user_manager_dropins=module.userq.staticq._expected_user_manager_dropins(),
        bundle=bundle_evidence(),
    )


def docker_info_payload():
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


class RootlessDockerDaemonQualificationTests(unittest.TestCase):
    def test_evidence_is_exact_and_immutable(self):
        value = evidence()
        with self.assertRaises(FrozenInstanceError):
            value.images = 1
        values = {name: getattr(value, name) for name in value.__dataclass_fields__}
        for field, bad in (
            ("expected_workflow_sha", "0" * 40),
            ("user_unit_state", ("loaded", "active", "running", "enabled")),
            ("user_unit_main_pid", 0),
            ("rootlesskit_pid", 9999),
            ("rootlesskit_argv", (AUTHORITY.rootlesskit,)),
            ("dockerd_argv", module._EXPECTED_DOCKERD_ARGV[:-1]),
            ("socket_mode", 0o666),
            ("server_version", "0"),
            ("storage_driver", "vfs"),
            ("cgroup_driver", "cgroupfs"),
            ("security_options", ("name=cgroupns",)),
            ("containers", (1, 1, 0, 0)),
            ("images", 1),
            ("delegate_controllers", ("cpu", "memory")),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.RootlessDockerDaemonEvidence(**(values | {field: bad}))

    def test_post_daemon_data_root_accepts_exact_empty_engine_and_rejects_drift(self):
        root_mode = next(
            mode for path, _uid, _gid, mode
            in AUTHORITY.post_daemon_provisioned_directories
            if path == AUTHORITY.data_root
        )
        root = type("S", (), {
            "st_mode": stat.S_IFDIR | root_mode,
            "st_uid": 991, "st_gid": 991,
            "st_dev": 17, "st_ino": 41,
        })()
        entries = {
            name: (kind, mode)
            for name, kind, mode in AUTHORITY.post_daemon_data_root_entries
        }

        def child_stat(name, *, dir_fd, follow_symlinks):
            self.assertEqual(dir_fd, 50)
            self.assertFalse(follow_symlinks)
            kind, mode = entries[name]
            return type("S", (), {
                "st_mode": (stat.S_IFDIR if kind == "directory" else stat.S_IFREG) | mode,
                "st_uid": 991, "st_gid": 991,
                "st_nlink": 2 if kind == "directory" else 1,
                "st_size": AUTHORITY.post_daemon_engine_id_size if name == "engine-id" else 4096,
            })()

        def open_path(path, flags, *, dir_fd=None):
            if path == AUTHORITY.data_root and dir_fd is None:
                return 50
            if path == "engine-id" and dir_fd == 50:
                return 51
            raise AssertionError((path, flags, dir_fd))

        exact_names = list(entries)
        with patch.object(module.os, "lstat", return_value=root), \
             patch.object(module.os, "open", side_effect=open_path), \
             patch.object(module.os, "fstat", return_value=root), \
             patch.object(module.os, "listdir", return_value=exact_names), \
             patch.object(module.os, "stat", side_effect=child_stat), \
             patch.object(module.os, "read", return_value=b"c03e22b6-225e-4318-8d26-bd7e6eaa104d"), \
             patch.object(module.os, "close"):
            self.assertEqual(
                module._require_post_daemon_data_root(),
                (AUTHORITY.data_root, 991, 991, root_mode),
            )

        with patch.object(module.os, "lstat", return_value=root), \
             patch.object(module.os, "open", return_value=50), \
             patch.object(module.os, "fstat", return_value=root), \
             patch.object(module.os, "listdir", return_value=exact_names + ["unexpected"]), \
             patch.object(module.os, "close"), self.assertRaises(OSError):
            module._require_post_daemon_data_root()

        wrong_mode = type("S", (), {
            "st_mode": stat.S_IFDIR | 0o700,
            "st_uid": 991, "st_gid": 991,
            "st_dev": 17, "st_ino": 41,
        })()
        with patch.object(module.os, "lstat", return_value=wrong_mode), self.assertRaises(OSError):
            module._require_post_daemon_data_root()

    def test_user_unit_gate_requires_active_running_disabled_exact_fragment(self):
        values = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "UnitFileState": "disabled",
            "FragmentPath": AUTHORITY.user_unit_fragment_alias,
            "MainPID": "4000",
        }
        link = type("S", (), {
            "st_mode": stat.S_IFLNK | 0o777, "st_uid": 0, "st_gid": 0,
        })()
        reviewed = type("S", (), {
            "st_mode": stat.S_IFREG | 0o644, "st_uid": 0, "st_gid": 0,
            "st_dev": 17, "st_ino": 41,
        })()
        with patch.object(
            module, "_read_user_systemctl", side_effect=lambda name: values[name]
        ), patch.object(module.os.path, "lexists", return_value=False), \
             patch.object(module.os, "lstat", return_value=link), \
             patch.object(module.os, "readlink", return_value=AUTHORITY.user_unit_fragment_alias_target), \
             patch.object(module.os, "stat", return_value=reviewed):
            self.assertEqual(
                module._user_unit_evidence(),
                (("loaded", "active", "running", "disabled"), AUTHORITY.user_unit, 4000),
            )

        values["UnitFileState"] = "enabled"
        with patch.object(
            module, "_read_user_systemctl", side_effect=lambda name: values[name]
        ), patch.object(module.os.path, "lexists", return_value=False), \
             patch.object(module.os, "lstat", return_value=link), \
             patch.object(module.os, "readlink", return_value=AUTHORITY.user_unit_fragment_alias_target), \
             patch.object(module.os, "stat", return_value=reviewed), self.assertRaises(OSError):
            module._user_unit_evidence()

    def test_fragment_alias_must_be_exact_symlink_to_reviewed_unit(self):
        link = type("S", (), {
            "st_mode": stat.S_IFLNK | 0o777, "st_uid": 0, "st_gid": 0,
        })()
        reviewed = type("S", (), {
            "st_mode": stat.S_IFREG | 0o644, "st_uid": 0, "st_gid": 0,
            "st_dev": 17, "st_ino": 41,
        })()
        with patch.object(module.os, "lstat", return_value=link), \
             patch.object(module.os, "readlink", return_value=AUTHORITY.user_unit_fragment_alias_target), \
             patch.object(module.os, "stat", return_value=reviewed):
            self.assertEqual(
                module._canonical_user_unit_fragment(AUTHORITY.user_unit_fragment_alias),
                AUTHORITY.user_unit,
            )
        with patch.object(module.os, "lstat", return_value=link), \
             patch.object(module.os, "readlink", return_value="../../other"), \
             self.assertRaises(OSError):
            module._canonical_user_unit_fragment(AUTHORITY.user_unit_fragment_alias)
        with self.assertRaises(OSError):
            module._canonical_user_unit_fragment(AUTHORITY.user_unit)

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

    def test_runtime_process_discovery_is_procfs_only_and_uid_bound(self):
        entries = tuple(
            type("E", (), {"name": str(pid)})()
            for pid in (4000, 4001, 4002, 4003, 5000)
        )
        names = {
            4000: "rootlesskit",
            4001: "dockerd",
            4002: "containerd",
            4003: "slirp4netns",
            5000: "unrelated",
        }
        with patch.object(module.os, "scandir", return_value=entries), \
             patch.object(
                 module,
                 "_proc_dir_uid",
                 side_effect=lambda pid: (
                     AUTHORITY.executor_uid if pid != 5000 else 0
                 ),
             ), \
             patch.object(module, "_proc_comm", side_effect=lambda pid: names[pid]) as comm, \
             patch.object(module, "_proc_uid", return_value=AUTHORITY.executor_uid), \
             patch.object(module.userq.staticq.preinstall, "_run") as old_runner:
            self.assertEqual(module._pids("rootlesskit"), (4000,))
            self.assertEqual(module._pids("dockerd"), (4001,))
            self.assertEqual(module._pids("containerd"), (4002,))
            self.assertEqual(module._pids("slirp4netns"), (4003,))
        old_runner.assert_not_called()
        self.assertNotIn(call(5000), comm.call_args_list)

        with patch.object(module.os, "scandir", return_value=entries), \
             patch.object(module, "_proc_dir_uid", return_value=0), \
             patch.object(module, "_proc_comm") as comm, \
             self.assertRaises(OSError):
            module._pids("dockerd")
        comm.assert_not_called()

        with self.assertRaises(OSError):
            module._pids("not-reviewed")

    def test_proc_dir_uid_requires_real_proc_directory(self):
        directory = type(
            "S",
            (),
            {"st_mode": stat.S_IFDIR | 0o555, "st_uid": AUTHORITY.executor_uid},
        )()
        with patch.object(module.os, "stat", return_value=directory) as observed:
            self.assertEqual(module._proc_dir_uid(4000), AUTHORITY.executor_uid)
        observed.assert_called_once_with("/proc/4000", follow_symlinks=False)

        regular = type(
            "S",
            (),
            {"st_mode": stat.S_IFREG | 0o444, "st_uid": AUTHORITY.executor_uid},
        )()
        with patch.object(module.os, "stat", return_value=regular), self.assertRaises(OSError):
            module._proc_dir_uid(4000)

    def test_pid_discovery_filters_unrelated_process_before_comm_read(self):
        entries = (
            type("E", (), {"name": "4001"})(),
            type("E", (), {"name": "5000"})(),
        )
        with patch.object(module.os, "scandir", return_value=entries), \
             patch.object(
                 module,
                 "_proc_dir_uid",
                 side_effect=lambda pid: AUTHORITY.executor_uid if pid == 4001 else 0,
             ), \
             patch.object(
                 module,
                 "_proc_comm",
                 side_effect=lambda pid: "dockerd" if pid == 4001 else (_ for _ in ()).throw(OSError()),
             ) as comm, \
             patch.object(module, "_proc_uid", return_value=AUTHORITY.executor_uid):
            self.assertEqual(module._pids("dockerd"), (4001,))
        self.assertNotIn(call(5000), comm.call_args_list)

    def test_proc_comm_requires_one_bounded_ascii_line(self):
        with patch.object(module, "_read_proc_file", return_value=b"dockerd\n"):
            self.assertEqual(module._proc_comm(4001), "dockerd")
        for bad in (b"", b"dockerd", b"dockerd\nextra\n", b"\xff\n"):
            with self.subTest(bad=bad), patch.object(
                module, "_read_proc_file", return_value=bad
            ), self.assertRaises(OSError):
                module._proc_comm(4001)

    def test_process_gate_binds_mainpid_to_rootlesskit_and_exact_dockerd_argv(self):
        with patch.object(
            module, "_pids", side_effect=lambda name: {
                "rootlesskit": (4000,),
                "dockerd": (4001,),
                "containerd": (4002,),
                "slirp4netns": (4003,),
            }[name]
        ), patch.object(
            module, "_proc_cmdline", side_effect=lambda pid: {
                4000: rootlesskit_argv(),
                4001: module._EXPECTED_DOCKERD_ARGV,
            }[pid]
        ):
            self.assertEqual(
                module._process_evidence(4000),
                (
                    4000,
                    rootlesskit_argv(),
                    4001,
                    module._EXPECTED_DOCKERD_ARGV,
                ),
            )

        with patch.object(
            module, "_pids", return_value=(4000,)
        ), patch.object(
            module, "_proc_cmdline", return_value=(AUTHORITY.rootlesskit,)
        ), self.assertRaises(OSError):
            module._process_evidence(4000)

    def test_docker_info_uses_exact_private_endpoint_and_requires_empty_rootless_engine(self):
        completed = subprocess.CompletedProcess(
            (), 0, json.dumps(docker_info_payload()).encode() + b"\n", b""
        )
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            value = module._docker_info_evidence()
        self.assertEqual(
            run.call_args.args[0],
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
        self.assertIn("name=rootless", value[5])
        self.assertEqual(value[6:], ((0, 0, 0, 0), 0))

    def test_rootlesskit_state_requires_exact_dir_and_no_containerd_rootless_conflict(self):
        fake = type(
            "S",
            (),
            {
                "st_mode": stat.S_IFDIR | 0o700,
                "st_uid": 991,
                "st_gid": 991,
            },
        )()
        with patch.object(module.os, "lstat", return_value=fake), patch.object(
            module.os.path, "lexists", return_value=False
        ):
            self.assertEqual(
                module._rootlesskit_state_evidence(),
                (AUTHORITY.rootlesskit_state, 991, 991, AUTHORITY.rootlesskit_state_mode),
            )
        with patch.object(module.os, "lstat", return_value=fake), patch.object(
            module.os.path, "lexists", return_value=True
        ), self.assertRaises(OSError):
            module._rootlesskit_state_evidence()

    def test_public_qualification_requires_two_identical_observations(self):
        first = evidence()
        with patch.object(module, "_qualify_once", side_effect=(first, first)) as once:
            self.assertEqual(module.qualify_rootless_docker_daemon(), first)
        self.assertEqual(once.call_count, 2)

        changed = evidence("b" * 40)
        with patch.object(module, "_qualify_once", side_effect=(first, changed)), self.assertRaises(
            module.RootlessDockerDaemonQualificationError
        ):
            module.qualify_rootless_docker_daemon()

    def test_public_qualification_collapses_private_failure(self):
        with patch.object(module, "_qualify_once", side_effect=OSError("private")), self.assertRaises(
            module.RootlessDockerDaemonQualificationError
        ) as caught:
            module.qualify_rootless_docker_daemon()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_source_is_read_only_independent_and_has_no_activation_surface(self):
        source = (
            ROOT / "deployment/rootless_docker_daemon_qualification.py"
        ).read_text()
        self.assertNotIn("rootless_docker_daemon_start import", source)
        self.assertNotIn("preinstall._run", source)
        self.assertNotIn("_PGREP", source)
        for forbidden in (
            '"start"',
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
