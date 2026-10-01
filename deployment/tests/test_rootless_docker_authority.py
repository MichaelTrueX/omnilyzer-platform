"""Repository-only adversarial checks for the inert C32ZF host boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import errno
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

from deployment import final_application_generation as frozen
from deployment.application_source_set import DevApplicationSourceSet
import deployment.docker_runtime as docker_runtime
from deployment.rootless_docker_authority import AUTHORITY


ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "deployment/systemd/rootless"
BASE = "5c94cb99a21b7bbbfdc977bdccad0d75946d8d3b"


class RootlessDockerAuthorityTests(unittest.TestCase):
    @staticmethod
    def _launcher():
        spec = importlib.util.spec_from_file_location(
            "_task014_rootless_launcher", ASSETS / "rootless-docker-launcher.py")
        assert spec is not None and spec.loader is not None
        launcher = importlib.util.module_from_spec(spec)
        with patch.object(sys, "dont_write_bytecode", True):
            spec.loader.exec_module(launcher)
        return launcher

    @staticmethod
    def _stat(kind: int, *, inode: int = 41, uid: int = 991,
              gid: int = 991, mode: int = 0o660, links: int = 1, size: int = 0):
        return os.stat_result((kind | mode, inode, 17, links, uid, gid, size, 0, 0, 0))

    def test_complete_c32w_application_and_freeze_tests_remain_historical(self) -> None:
        selected = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(selected), 41)
        self.assertIn("deployment/docker_runtime.py", selected)
        self.assertEqual(frozen.TARGET_REVIEWED_COMMIT,
                         "e4f0030c7a028beb834618254781c2fbff5d6b0d")
        self.assertEqual(subprocess.run(
            ("git", "diff", "--quiet", BASE, frozen.TARGET_REVIEWED_COMMIT, "--", *selected),
            cwd=ROOT, check=False,
        ).returncode, 0)
        historical_freeze = (
            "deployment/final_application_generation.py",
            "deployment/final_configuration_authority.py",
            "deployment/dev_final_application_update.py",
            "deployment/broker_edge_contract.py",
        )
        self.assertEqual(subprocess.run(
            ("git", "diff", "--quiet", BASE, "--", *historical_freeze),
            cwd=ROOT, check=False,
        ).returncode, 0)
        self.assertIn("frozen-c32w-application-authority-unchanged",
                      (ROOT / "deployment/broker_edge_contract.py").read_text())
        for source, *_ in AUTHORITY.installed_assets:
            self.assertNotIn(source, selected)
        self.assertNotIn("deployment/rootless_docker_authority.py", selected)

    def test_successor_repository_adapter_matches_rootless_host_authority(self) -> None:
        self.assertEqual(docker_runtime.DOCKER_CLI, AUTHORITY.docker_cli)
        self.assertEqual(docker_runtime.DOCKER_SOCKET, Path(AUTHORITY.socket))
        self.assertEqual(docker_runtime.DOCKER_HOST, AUTHORITY.socket_host)
        self.assertEqual(
            docker_runtime.DOCKER_CLIENT_CONFIG, str(Path(AUTHORITY.client_config).parent),
        )
        self.assertEqual(
            docker_runtime.DOCKER_PREFIX,
            (
                AUTHORITY.docker_cli, "--config", str(Path(AUTHORITY.client_config).parent),
                "--host", AUTHORITY.socket_host,
            ),
        )
        self.assertEqual(
            (docker_runtime.DOCKER_SOCKET_UID, docker_runtime.DOCKER_SOCKET_GID,
             docker_runtime.DOCKER_SOCKET_MODE),
            (AUTHORITY.executor_uid, AUTHORITY.executor_gid, 0o660),
        )

    def test_exact_seven_package_authorities_and_provenance(self) -> None:
        expected = {
            "docker-ce": ("5:29.8.1-1~ubuntu.24.04~noble", "607bcf63bf85c5a245b73229c2797fda5c5a430343c02ebf80f32f6db7513eb9", ("/usr/bin/dockerd",)),
            "docker-ce-cli": ("5:29.8.1-1~ubuntu.24.04~noble", "e26e6770fab41256cf16c09c24a0b75e70bf72465ef2688f85d1f7d3fdb9b99c", ("/usr/bin/docker",)),
            "docker-ce-rootless-extras": ("5:29.8.1-1~ubuntu.24.04~noble", "02897501837b7ff4fec8248decdd5828b7d40d7f591021a91f29673e02d0f982", ("/usr/bin/dockerd-rootless.sh", "/usr/bin/rootlesskit")),
            "docker-compose-plugin": ("5.5.1-1~ubuntu.24.04~noble", "82ff966149ca2c62e1a4e1fdebdf65fda8c3a8bea80b32deda6903b40afc2347", ("/usr/libexec/docker/cli-plugins/docker-compose",)),
            "containerd.io": ("2.3.6-1~ubuntu.24.04~noble", "2eb8c6e244fe6886f2fa2eee9ec418c4b9bb44eb44fca748504f57c23341aed2", ("/usr/bin/containerd",)),
            "uidmap": ("1:4.13+dfsg1-4ubuntu3.2", "a80cb7f72dd18c73cbb0b07b7fbe855504f26bfafae072a9b3d125c89d499b9e", ("/usr/bin/newuidmap", "/usr/bin/newgidmap")),
            "slirp4netns": ("1.2.1-1build2", "3fc72a72a376a3ad3b439434bc87d89d245f9d54a1d540e8a06b74d4e2385e0a", ("/usr/bin/slirp4netns",)),
        }
        self.assertEqual({item.name for item in AUTHORITY.packages}, set(expected))
        for item in AUTHORITY.packages:
            with self.subTest(package=item.name):
                self.assertEqual((item.apt_version, item.deb_sha256, item.required_executables),
                                 expected[item.name])
                self.assertEqual(len(item.deb_sha256), 64)
                if item.name in ("uidmap", "slirp4netns"):
                    self.assertTrue(item.origin.startswith("Ubuntu signed noble"))
                else:
                    self.assertIn("download.docker.com", item.origin)
        self.assertNotIn("docker-buildx-plugin", expected)
        self.assertEqual(AUTHORITY.vendor_rootless_script,
                         "/usr/bin/dockerd-rootless.sh")
        self.assertEqual(AUTHORITY.vendor_rootless_script_sha256,
                         "200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488")

    def test_identity_paths_and_mapping_are_exact(self) -> None:
        self.assertEqual((AUTHORITY.executor_uid, AUTHORITY.executor_gid), (991, 991))
        self.assertEqual((AUTHORITY.subuid_start, AUTHORITY.subgid_start,
                          AUTHORITY.subordinate_count), (493216, 493216, 65536))
        self.assertEqual(AUTHORITY.executor_uid, 991)  # Container ID zero.
        self.assertEqual((AUTHORITY.canary_host_uid, AUTHORITY.canary_host_gid),
                         (493216 + 10001 - 1, 493216 + 10001 - 1))
        self.assertEqual((AUTHORITY.nginx_host_uid, AUTHORITY.nginx_host_gid),
                         (493216 + 65532 - 1, 493216 + 65532 - 1))
        self.assertEqual(AUTHORITY.daemon_socket, "/run/user/991/docker.sock")
        self.assertEqual(AUTHORITY.daemon_socket_mode, 0o1660)
        self.assertEqual(AUTHORITY.pid_file_mode, 0o1644)
        self.assertEqual(AUTHORITY.exec_root_mode, 0o1700)
        self.assertEqual(AUTHORITY.rootlesskit_state_mode, 0o700)
        self.assertEqual(
            AUTHORITY.user_unit_fragment_alias,
            "/etc/xdg/systemd/user/omnilyzer-task014-rootless-docker.service",
        )
        self.assertEqual(
            AUTHORITY.user_unit_fragment_alias_parent, "/etc/xdg/systemd/user"
        )
        self.assertEqual(
            AUTHORITY.user_unit_fragment_alias_target, "../../systemd/user"
        )
        self.assertEqual(AUTHORITY.socket,
                         "/run/omnilyzer/deployment/rootless-docker/docker.sock")
        self.assertEqual(AUTHORITY.data_root,
                         "/var/lib/omnilyzer/deployment/rootless-docker-data")
        self.assertEqual(AUTHORITY.exec_root, "/run/user/991/docker-exec")
        self.assertEqual(AUTHORITY.home,
                         "/var/lib/omnilyzer/deployment/rootless-home")
        self.assertEqual(AUTHORITY.cgroup_dropin,
                         "/etc/systemd/system/user@991.service.d/omnilyzer-task014-cgroup-delegation.conf")
        self.assertTrue(AUTHORITY.detach_netns)
        provisioned = {path: (uid, gid, mode) for path, uid, gid, mode
                       in AUTHORITY.provisioned_directories}
        external = {path: (uid, gid, mode) for path, uid, gid, mode
                    in AUTHORITY.external_runtime_prerequisites}
        self.assertNotIn("/run/user/991", provisioned)
        self.assertEqual(external["/run/user/991"], (991, 991, 0o700))
        self.assertNotIn(AUTHORITY.socket_directory, provisioned)
        post_daemon = {
            path: (uid, gid, mode)
            for path, uid, gid, mode in AUTHORITY.post_daemon_provisioned_directories
        }
        self.assertEqual(
            post_daemon[AUTHORITY.data_root],
            (AUTHORITY.executor_uid, AUTHORITY.executor_gid, 0o710),
        )
        self.assertEqual(
            tuple(path for path, _uid, _gid, _mode in AUTHORITY.provisioned_directories),
            tuple(path for path, _uid, _gid, _mode in AUTHORITY.post_daemon_provisioned_directories),
        )
        self.assertEqual(
            tuple(name for name, _kind, _mode in AUTHORITY.post_daemon_data_root_entries),
            (
                "buildkit", "containerd", "containers", "engine-id",
                "image", "network", "overlay2", "plugins", "runtimes",
                "swarm", "tmp", "volumes",
            ),
        )
        self.assertEqual(AUTHORITY.post_daemon_engine_id_size, 36)
        self.assertEqual(provisioned[AUTHORITY.canary_runtime], (991, 503216, 0o770))
        self.assertEqual(provisioned[AUTHORITY.nginx_runtime], (991, 991, 0o755))

    def test_inert_assets_are_byte_pinned_and_keep_executor_hardening(self) -> None:
        self.assertEqual(len(AUTHORITY.installed_assets), 6)
        for source, destination, digest, uid, gid, mode in AUTHORITY.installed_assets:
            with self.subTest(source=source):
                path = ROOT / source
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                self.assertTrue(destination.startswith(("/etc/", "/opt/")))
                self.assertEqual((uid, gid, mode), (0, 0, 0o644))
        user_unit = (ASSETS / "omnilyzer-task014-rootless-docker.service").read_text()
        self.assertIn("ConditionUser=omnilyzer-executor", user_unit)
        self.assertIn("Restart=always", user_unit)
        self.assertIn("Environment=PATH=/usr/bin:/usr/sbin:/bin", user_unit)
        self.assertIn("Delegate=yes", user_unit)
        self.assertNotIn("User=root", user_unit)
        self.assertNotIn("SupplementaryGroups=docker", user_unit)
        self.assertNotIn("sudo", user_unit)
        self.assertIn("Delegate=cpu memory pids",
                      (ASSETS / "omnilyzer-task014-cgroup-delegation.conf").read_text())
        socket_dropin = (ASSETS / "rootless-docker-executor-socket.conf").read_text()
        self.assertIn("RuntimeDirectory=omnilyzer/deployment/rootless-docker",
                      socket_dropin)
        self.assertIn("RuntimeDirectoryMode=0700", socket_dropin)
        self.assertIn("BindReadOnlyPaths=" + AUTHORITY.daemon_socket + ":" + AUTHORITY.socket,
                      socket_dropin)
        executor = (ROOT / "deployment/systemd/dev/omnilyzer-deployment-executor.service").read_text()
        self.assertIn("User=omnilyzer-executor", executor)
        self.assertIn("SupplementaryGroups=omnilyzer-replay", executor)
        self.assertIn("ProtectHome=yes", executor)
        self.assertIn("NoNewPrivileges=yes", executor)
        self.assertNotIn("SupplementaryGroups=docker", executor)
        broker = (ROOT / "deployment/systemd/dev/omnilyzer-deployment-broker.service").read_text()
        self.assertNotIn("docker", broker.lower())

    def test_user_manager_template_dropins_are_exact_package_pinned_baseline(self) -> None:
        expected = (
            (
                "/usr/lib/systemd/system/user@.service.d/10-login-barrier.conf",
                "systemd", "255.4-1ubuntu8.17", "amd64",
                "1c1452839b609b0609cccaba3c648d780372df6f244deb487da6da5ee002a993",
            ),
            (
                "/usr/lib/systemd/system/user@.service.d/10-oomd-user-service-defaults.conf",
                "systemd-oomd", "255.4-1ubuntu8.17", "amd64",
                "ddf0f174373b79ea32997999cf2139e595c3fe9ccaf6ff66b2230d493fc664ef",
            ),
            (
                "/usr/lib/systemd/system/user@.service.d/timeout.conf",
                "systemd", "255.4-1ubuntu8.17", "amd64",
                "597eac16d8d7a289bb16aeeb01be0191d0c90beca4c6e0dba0f0c2d7c4e0ea81",
            ),
        )
        self.assertEqual(
            tuple(
                (x.path, x.package, x.apt_version, x.architecture, x.sha256)
                for x in AUTHORITY.user_manager_template_dropins
            ),
            expected,
        )
        self.assertTrue(
            all((x.uid, x.gid, x.mode) == (0, 0, 0o644)
                for x in AUTHORITY.user_manager_template_dropins)
        )

    def test_vendor_bootstrap_environment_is_explicit_and_closed(self) -> None:
        expected = {
            "DOCKERD": "/usr/bin/dockerd",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": "/run/user/991/dockerd-rootless",
            "CONTAINERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": "/run/user/991/containerd-rootless",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_NET": "slirp4netns",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_MTU": "65520",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER": "builtin",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX": "auto",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SECCOMP": "auto",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK": "true",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS": "true",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS": "--subid-source=static --slirp4netns-binary=/usr/bin/slirp4netns",
        }
        self.assertEqual(dict(AUTHORITY.rootless_environment), expected)
        self.assertEqual(len(AUTHORITY.rootless_environment), len(expected))
        self.assertNotIn("DOCKER_HOST", expected)
        self.assertNotIn("DOCKER_CONTEXT", expected)
        self.assertNotIn("DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false", repr(expected))
        self.assertEqual(AUTHORITY.subid_source, "static")
        self.assertEqual(AUTHORITY.slirp4netns_binary, "/usr/bin/slirp4netns")
        self.assertEqual(AUTHORITY.rootlesskit_flags,
                         "--subid-source=static --slirp4netns-binary=/usr/bin/slirp4netns")
        self.assertNotIn("--subid-source=auto", repr(expected))
        self.assertNotIn("--subid-source=dynamic", repr(expected))
        self.assertNotIn("getsubids", repr(expected))

    def test_launcher_has_no_generic_shell_or_partial_rootless_bootstrap(self) -> None:
        launcher = (ASSETS / "rootless-docker-launcher.py").read_text()
        for forbidden in ("subprocess", "shell=True", "sh -c", "/bin/sh",
                          "rootlesskit --", "nsenter", "sysctl", "rm -rf", "tcp://"):
            self.assertNotIn(forbidden, launcher)
        self.assertIn('VENDOR_SCRIPT = "/usr/bin/dockerd-rootless.sh"', launcher)
        self.assertIn("os.execve(VENDOR_SCRIPT", launcher)
        self.assertIn("if len(sys.argv) != 1", launcher)
        self.assertIn('ROOTLESSKIT_FLAGS = "--subid-source=static --slirp4netns-binary=/usr/bin/slirp4netns"', launcher)
        self.assertIn('"DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS": ROOTLESSKIT_FLAGS', launcher)
        self.assertNotIn("os.unlink", launcher)
        self.assertIn('_directory(RUNTIME, UID, GID, 0o700)', launcher)
        self.assertIn('_data_root()', launcher)
        self.assertIn('SOCKET_MODE = 0o1660', launcher)
        self.assertIn('DATA_INITIAL_MODE = 0o700', launcher)
        self.assertIn('DATA_MANAGED_MODE = 0o710', launcher)
        self.assertNotIn("os.mkdir", launcher)
        self.assertNotIn("os.chown", launcher)
        self.assertNotIn("os.chmod", launcher)

    def test_launcher_adversarial_environment_and_argv(self) -> None:
        launcher = self._launcher()

        class CapturedExec(Exception):
            pass

        def opened(path, mode):
            self.assertEqual(mode, "rb")
            if path == launcher.CONFIG:
                return io.BytesIO(launcher.DAEMON_CONFIG_BYTES)
            if path == launcher.VENDOR_SCRIPT:
                return io.BytesIO(b"verified vendor script fixture")
            raise AssertionError(path)

        digest = hashlib.sha256(b"verified vendor script fixture").hexdigest()
        with patch.dict(os.environ, {
            "NOTIFY_SOCKET": "/run/user/991/systemd/notify",
            "DOCKERD": "/tmp/hostile", "DOCKER_HOST": "tcp://127.0.0.1:2375",
            "DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS": "-p 0.0.0.0:2375:2375/tcp",
            "HOME": "/tmp/hostile", "PATH": "/tmp/hostile", "HTTP_PROXY": "http://x",
        }, clear=True), patch.object(launcher.os, "geteuid", return_value=991), \
                patch.object(launcher.os, "getegid", return_value=991), \
                patch.object(launcher.os, "getgroups", return_value=[992]), \
                patch.object(launcher, "_directory"), patch.object(launcher, "_file"), \
                patch.object(launcher, "_data_root"), \
                patch("builtins.open", side_effect=opened), \
                patch.object(launcher, "VENDOR_SCRIPT_SHA256", digest), \
                patch.object(launcher.os.path, "lexists", return_value=False), \
                patch.object(launcher, "_rootlesskit_state"), \
                patch.object(launcher, "_check_daemon_socket"), \
                patch.object(launcher.os, "execve", side_effect=CapturedExec) as execute, \
                patch.object(launcher.sys, "argv", ["launch.py"]), \
                self.assertRaises(CapturedExec):
            launcher.main()
        program, argv, environment = execute.call_args.args
        self.assertEqual(program, "/usr/bin/dockerd-rootless.sh")
        self.assertEqual(argv, (
            program, "--host=unix:///run/user/991/docker.sock",
            "--data-root=" + AUTHORITY.data_root,
            "--exec-root=" + AUTHORITY.exec_root,
            "--pidfile=" + AUTHORITY.pid_file,
            "--config-file=" + AUTHORITY.daemon_config,
            "--exec-opt=native.cgroupdriver=systemd",
            "--storage-driver=overlay2", "--group=0",
        ))
        self.assertEqual(set(environment), {
            "HOME", "XDG_RUNTIME_DIR", "PATH", "LANG", "DBUS_SESSION_BUS_ADDRESS",
            "NOTIFY_SOCKET", *dict(AUTHORITY.rootless_environment),
        })
        for name, value in AUTHORITY.rootless_environment:
            self.assertEqual(environment[name], value)
        self.assertEqual(environment["PATH"], "/usr/bin:/usr/sbin:/bin")
        self.assertLess(environment["PATH"].split(":").index("/usr/bin"),
                        environment["PATH"].split(":").index("/usr/sbin"))
        self.assertNotIn("/usr/local", environment["PATH"])
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("DOCKER_CONTEXT", environment)
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertNotIn("/tmp/hostile", repr(environment))
        self.assertNotIn("tcp://", repr(environment))

        with patch.dict(os.environ, {"NOTIFY_SOCKET": "/run/user/991/systemd/notify"}, clear=True), \
                patch.object(launcher.os, "geteuid", return_value=991), \
                patch.object(launcher.os, "getegid", return_value=991), \
                patch.object(launcher.os, "getgroups", return_value=[27, 992]), \
                patch.object(launcher.os, "execve", side_effect=AssertionError("executed")), \
                patch.object(launcher.sys, "argv", ["launch.py"]), \
                self.assertRaises(RuntimeError):
            launcher.main()
        with patch.object(launcher.sys, "argv", ["launch.py", "--host=tcp://x"]), \
                patch.object(launcher.os, "execve", side_effect=AssertionError("executed")), \
                self.assertRaises(RuntimeError):
            launcher.main()

    def test_launcher_data_root_accepts_only_clean_initial_or_exact_managed_state(self) -> None:
        launcher = self._launcher()
        initial = self._stat(stat.S_IFDIR, mode=0o700)
        with patch.object(launcher.os, "lstat", return_value=initial), \
                patch.object(launcher.os, "open", return_value=50), \
                patch.object(launcher.os, "fstat", return_value=initial), \
                patch.object(launcher.os, "listdir", return_value=[]), \
                patch.object(launcher.os, "close") as close:
            launcher._data_root()
        close.assert_called_once_with(50)

        with patch.object(launcher.os, "lstat", return_value=initial), \
                patch.object(launcher.os, "open", return_value=50), \
                patch.object(launcher.os, "fstat", return_value=initial), \
                patch.object(launcher.os, "listdir", return_value=["unexpected"]), \
                patch.object(launcher.os, "close"), self.assertRaises(RuntimeError):
            launcher._data_root()

        managed = self._stat(stat.S_IFDIR, mode=0o710)
        expected = {name: (kind, mode) for name, kind, mode in launcher.DATA_MANAGED_ENTRIES}

        def child_stat(name, *, dir_fd, follow_symlinks):
            self.assertEqual(dir_fd, 50)
            self.assertFalse(follow_symlinks)
            kind, mode = expected[name]
            return self._stat(
                stat.S_IFDIR if kind == "directory" else stat.S_IFREG,
                mode=mode, links=2 if kind == "directory" else 1,
                size=launcher.ENGINE_ID_SIZE if name == "engine-id" else 4096,
            )

        def opened(path, flags, *, dir_fd=None):
            if path == launcher.DATA and dir_fd is None:
                return 50
            if path == "engine-id" and dir_fd == 50:
                return 51
            raise AssertionError((path, flags, dir_fd))

        names = list(expected)
        with patch.object(launcher.os, "lstat", return_value=managed), \
                patch.object(launcher.os, "open", side_effect=opened), \
                patch.object(launcher.os, "fstat", return_value=managed), \
                patch.object(launcher.os, "listdir", return_value=names), \
                patch.object(launcher.os, "stat", side_effect=child_stat), \
                patch.object(launcher.os, "read", return_value=b"c03e22b6-225e-4318-8d26-bd7e6eaa104d"), \
                patch.object(launcher.os, "close"):
            launcher._data_root()

        with patch.object(launcher.os, "lstat", return_value=managed), \
                patch.object(launcher.os, "open", return_value=50), \
                patch.object(launcher.os, "fstat", return_value=managed), \
                patch.object(launcher.os, "listdir", return_value=names + ["unexpected"]), \
                patch.object(launcher.os, "close"), self.assertRaises(RuntimeError):
            launcher._data_root()

        wrong_mode = self._stat(stat.S_IFDIR, mode=0o711)
        with patch.object(launcher.os, "lstat", return_value=wrong_mode), \
                self.assertRaises(RuntimeError):
            launcher._data_root()

    def test_launcher_runtime_modes_match_live_authority(self) -> None:
        launcher = self._launcher()
        self.assertEqual(launcher.SOCKET_MODE, AUTHORITY.daemon_socket_mode)
        self.assertEqual(launcher.DATA_INITIAL_MODE, dict(
            (path, mode) for path, _uid, _gid, mode in AUTHORITY.provisioned_directories
        )[AUTHORITY.data_root])
        self.assertEqual(launcher.DATA_MANAGED_MODE, dict(
            (path, mode) for path, _uid, _gid, mode in AUTHORITY.post_daemon_provisioned_directories
        )[AUTHORITY.data_root])
        self.assertEqual(launcher.DATA_MANAGED_ENTRIES, AUTHORITY.post_daemon_data_root_entries)
        self.assertEqual(launcher.ENGINE_ID_SIZE, AUTHORITY.post_daemon_engine_id_size)

    def test_rootlesskit_state_absent_or_safe_stale_is_vendor_managed(self) -> None:
        launcher = self._launcher()
        with patch.object(launcher.os, "lstat", side_effect=FileNotFoundError):
            launcher._rootlesskit_state()
        safe = self._stat(stat.S_IFDIR, mode=0o700)
        with patch.object(launcher.os, "lstat", return_value=safe) as lstat, \
                patch.object(launcher.os, "unlink", side_effect=AssertionError("removed")):
            launcher._rootlesskit_state()
        lstat.assert_called_once_with("/run/user/991/dockerd-rootless")
        self.assertIn("Restart=always", (ASSETS / "omnilyzer-task014-rootless-docker.service").read_text())
        self.assertNotIn("rmtree", (ASSETS / "rootless-docker-launcher.py").read_text())
        for unsafe in (
            self._stat(stat.S_IFLNK, mode=0o700),
            self._stat(stat.S_IFREG, mode=0o700),
            self._stat(stat.S_IFDIR, uid=0, mode=0o700),
            self._stat(stat.S_IFDIR, gid=0, mode=0o700),
            self._stat(stat.S_IFDIR, mode=0o755),
        ):
            with self.subTest(unsafe=unsafe), patch.object(launcher.os, "lstat", return_value=unsafe), \
                    self.assertRaises(RuntimeError):
                launcher._rootlesskit_state()

    def test_existing_socket_probe_never_unlinks_before_vendor_lock(self) -> None:
        launcher = self._launcher()
        path = "/run/user/991/docker.sock"
        safe = self._stat(stat.S_IFSOCK, mode=0o1660)
        with patch.object(launcher.os, "lstat", side_effect=FileNotFoundError), \
                patch.object(launcher.socket, "socket") as socket_factory, \
                patch.object(launcher.os, "unlink") as unlink:
            launcher._check_daemon_socket()
            socket_factory.assert_not_called()
            unlink.assert_not_called()

        probe = MagicMock()
        with patch.object(launcher.os, "lstat", return_value=safe), \
                patch.object(launcher.socket, "socket", return_value=probe), \
                patch.object(launcher.os, "unlink") as unlink, \
                self.assertRaisesRegex(RuntimeError, "live owner"):
            launcher._check_daemon_socket()
        probe.__enter__.return_value.connect.assert_called_with(path)
        unlink.assert_not_called()

        probe = MagicMock()
        probe.__enter__.return_value.connect.side_effect = OSError(errno.ECONNREFUSED, "refused")
        with patch.object(launcher.os, "lstat", return_value=safe) as lstat, \
                patch.object(launcher.socket, "socket", return_value=probe) as socket_factory, \
                patch.object(launcher.os, "unlink") as unlink:
            launcher._check_daemon_socket()
        lstat.assert_called_once_with(path)
        socket_factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        unlink.assert_not_called()

        for unsafe in (
            self._stat(stat.S_IFLNK), self._stat(stat.S_IFREG),
            self._stat(stat.S_IFSOCK, uid=0), self._stat(stat.S_IFSOCK, gid=0),
            self._stat(stat.S_IFSOCK, mode=0o600),
            self._stat(stat.S_IFSOCK, mode=0o660),
        ):
            with self.subTest(unsafe=unsafe), patch.object(launcher.os, "lstat", return_value=unsafe), \
                    patch.object(launcher.socket, "socket") as socket_factory, \
                    patch.object(launcher.os, "unlink") as unlink, \
                    self.assertRaises(RuntimeError):
                launcher._check_daemon_socket()
            socket_factory.assert_not_called()
            unlink.assert_not_called()

        probe = MagicMock()
        probe.__enter__.return_value.connect.side_effect = OSError(errno.EACCES, "denied")
        with patch.object(launcher.os, "lstat", return_value=safe), \
                patch.object(launcher.socket, "socket", return_value=probe), \
                patch.object(launcher.os, "unlink") as unlink, \
                self.assertRaisesRegex(RuntimeError, "ambiguous"):
            launcher._check_daemon_socket()
        unlink.assert_not_called()
        source = (ASSETS / "rootless-docker-launcher.py").read_text()
        self.assertNotIn("os.unlink", source)
        self.assertIn("_rootlesskit_state()", source)
        self.assertIn("_check_daemon_socket()", source)

    def test_basename_lookups_resolve_to_reviewed_usr_bin_authority(self) -> None:
        packages = {package.name: package.required_executables for package in AUTHORITY.packages}
        self.assertIn("/usr/bin/newuidmap", packages["uidmap"])
        self.assertIn("/usr/bin/newgidmap", packages["uidmap"])
        self.assertIn("/usr/bin/containerd", packages["containerd.io"])
        self.assertIn("/usr/bin/rootlesskit", packages["docker-ce-rootless-extras"])
        self.assertIn("/usr/bin/dockerd", packages["docker-ce"])
        fixed_path = "/usr/bin:/usr/sbin:/bin".split(":")
        for name in ("newuidmap", "newgidmap", "containerd", "rootlesskit", "dockerd"):
            with self.subTest(name=name):
                # Even if a similarly named /usr/sbin binary exists, PATH
                # selects the reviewed package-owned /usr/bin binary first.
                candidates = {"/usr/bin/" + name, "/usr/sbin/" + name}
                resolved = next(path + "/" + name for path in fixed_path
                                if path + "/" + name in candidates)
                self.assertEqual(resolved, "/usr/bin/" + name)

    def test_preinstall_mask_and_live_gates_are_explicit(self) -> None:
        checks = AUTHORITY.qualification
        self.assertEqual(len(checks), len(set(checks)))
        for required in (
            "preinstall-rootful-docker-containerd-units-masked-and-start-blocked-before-apt-maintainer-scripts",
            "postinstall-rootful-docker-and-containerd-units-masked-inactive-no-rootful-process-or-socket",
            "all-seven-packages-exact-version-signed-origin-deb-digest-and-critical-binary-owner",
            "vendor-containerd-conflict-copyup-cleanup-and-ipv4-ipv6-forwarding-behavior",
            "logind-linger-user-manager-and-ephemeral-XDG-runtime-exact-for-uid-991",
            "successor-rootless-application-generation-reviewed-installed-before-activation",
            "exact-zot-image-pull-and-digest-without-persistent-docker-credentials",
            "static-subid-source-exact-etc-subuid-and-subgid-entry-no-extra-or-overlap",
            "slirp4netns-exact-absolute-package-owned-binary-no-path-shadow",
            "safe-rootlesskit-state-owned-0700-vendor-lock-and-crash-recovery",
            "launcher-first-start-empty-0700-or-managed-restart-0710-and-socket-01660",
            "existing-docker-socket-exact-identity-live-probe-refused-defers-to-vendor-lock-no-launcher-unlink",
        ):
            self.assertIn(required, checks)
        readme = (ROOT / "deployment/README.md").read_text()
        self.assertIn("`omnilyzer-executor:493216:65536`", readme)
        self.assertIn("earlier `427680:65536` range is already", readme)
        self.assertNotEqual(AUTHORITY.subuid_start, 427680)
        self.assertNotEqual(AUTHORITY.subgid_start, 427680)
        self.assertIn("no extra\nexecutor range or overlap", readme)
        self.assertIn("already-qualified private tailnet-only Tailscale Serve ingress", readme)
        self.assertIn("Funnel remains off and prohibited", readme)
        self.assertNotIn("Broker/executor/Serve activation remains prohibited", readme)
        compose = (ROOT / "deployment/runtime/dev/compose.yaml").read_text()
        self.assertEqual(compose.count("127.0.0.1:3020:8080"), 1)
        self.assertIn("internal: true", compose)
        self.assertEqual(compose.count('user: "10001:10001"'), 1)
        self.assertEqual(compose.count('user: "65532:65532"'), 1)


if __name__ == "__main__":
    unittest.main()
