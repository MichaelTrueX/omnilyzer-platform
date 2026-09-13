"""Tests for the read-only hardened DEV executor configuration loader."""

from __future__ import annotations

import ast
from contextlib import ExitStack
import importlib
import inspect
import os
from pathlib import Path
import socket
import stat
import subprocess
import unittest
from unittest.mock import patch

from deployment.executor_service_config import (
    DevExecutorServiceConfiguration,
    EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE,
    EXECUTOR_SERVICE_CONFIG_FILE_MODE,
    MAX_EXECUTOR_SERVICE_CONFIG_BYTES,
    PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH,
)
import deployment.executor_service_config_loader as loader
from deployment.replay_sqlite import MAX_UID_GID


CANARY_IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:"
    "628af866084f08763b31a44c8a484c5ae4c64db6697f4c4ceaad91bbf54ba72a"
)
HASHES = (
    "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
)


def configuration() -> DevExecutorServiceConfiguration:
    return DevExecutorServiceConfiguration(
        schema_version=1,
        stage="dev",
        broker_uid=1001,
        broker_gid=1002,
        executor_uid=2001,
        executor_gid=2002,
        replay_group_gid=2003,
        socket_group_gid=2004,
        canary_image=CANARY_IMAGE,
        reviewed_commit="a" * 40,
        runtime_configuration_sha256=(
            "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f"
        ),
        ingress_file_sha256=HASHES,
    )


def status_result(
    mode: int, inode: int, *, uid: int = 0, gid: int = 0,
    links: int = 2, size: int = 0, device: int = 50,
) -> os.stat_result:
    return os.stat_result((mode, inode, device, links, uid, gid, size, 0, 0, 0))


class FakeHost:
    """A deterministic descriptor-relative syscall model with no host I/O."""

    def __init__(self) -> None:
        self.config = configuration()
        self.raw = self.config.canonical_bytes()
        self.open_map = {
            ("/", None): 10,
            ("etc", 10): 11,
            ("omnilyzer", 11): 12,
            ("deployment", 12): 13,
            ("dev", 13): 14,
            ("executor.json", 14): 15,
        }
        self.fd_status = {
            10: status_result(stat.S_IFDIR | 0o755, 100),
            11: status_result(stat.S_IFDIR | 0o755, 101),
            12: status_result(stat.S_IFDIR | 0o755, 102),
            13: status_result(stat.S_IFDIR | 0o755, 103),
            14: status_result(stat.S_IFDIR | 0o750, 104, gid=2002),
            15: status_result(
                stat.S_IFREG | 0o640, 105, gid=2002, links=1,
                size=len(self.raw),
            ),
        }
        self.named_status = {
            key: self.fd_status[descriptor]
            for key, descriptor in self.open_map.items()
        }
        self.open_calls: list[tuple[str, int, int | None]] = []
        self.stat_calls: list[tuple[str, int | None, bool]] = []
        self.fstat_calls: list[int] = []
        self.inheritable_calls: list[int] = []
        self.read_calls: list[tuple[int, int]] = []
        self.close_calls: list[int] = []
        self.offset = 0
        self.identity = (2001, 2001, 2002, 2002, [2003])

    def open(self, path: str, flags: int, *, dir_fd: int | None = None) -> int:
        self.open_calls.append((path, flags, dir_fd))
        return self.open_map[(path, dir_fd)]

    def stat(
        self, path: str, *, dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        self.stat_calls.append((path, dir_fd, follow_symlinks))
        return self.named_status[(path, dir_fd)]

    def fstat(self, descriptor: int) -> os.stat_result:
        self.fstat_calls.append(descriptor)
        return self.fd_status[descriptor]

    def get_inheritable(self, descriptor: int) -> bool:
        self.inheritable_calls.append(descriptor)
        return False

    def read(self, descriptor: int, maximum: int) -> bytes:
        self.read_calls.append((descriptor, maximum))
        if self.offset == len(self.raw):
            return b""
        value = self.raw[self.offset:self.offset + maximum]
        self.offset += len(value)
        return value

    def close(self, descriptor: int) -> None:
        self.close_calls.append(descriptor)
        return None

    def patches(self) -> ExitStack:
        stack = ExitStack()
        for name in ("open", "stat", "fstat", "get_inheritable", "read", "close"):
            stack.enter_context(patch.object(loader._os, name, side_effect=getattr(self, name)))
        uid, euid, gid, egid, groups = self.identity
        stack.enter_context(patch.object(loader._os, "getuid", return_value=uid))
        stack.enter_context(patch.object(loader._os, "geteuid", return_value=euid))
        stack.enter_context(patch.object(loader._os, "getgid", return_value=gid))
        stack.enter_context(patch.object(loader._os, "getegid", return_value=egid))
        stack.enter_context(patch.object(loader._os, "getgroups", return_value=groups))
        return stack


class LoaderTestCase(unittest.TestCase):
    def assert_unavailable(self, action) -> None:
        with self.assertRaises(loader.ExecutorServiceConfigurationUnavailableError) as caught:
            action()
        self.assertEqual(str(caught.exception), "DEV executor service configuration is unavailable")


class ImportAndSurfaceTests(LoaderTestCase):
    def test_import_is_inert(self) -> None:
        targets = (
            "open", "close", "read", "stat", "fstat", "getuid", "geteuid",
            "getgid", "getegid", "getgroups",
        )
        with ExitStack() as stack:
            for name in targets:
                stack.enter_context(patch.object(os, name, side_effect=AssertionError(name)))
            stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError("socket")))
            stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("process")))
            importlib.reload(loader)

    def test_exact_public_surface_and_zero_argument_function(self) -> None:
        self.assertEqual(loader.__all__, (
            "ExecutorServiceConfigurationUnavailableError",
            "load_dev_executor_service_configuration",
        ))
        self.assertEqual(
            tuple(inspect.signature(loader.load_dev_executor_service_configuration).parameters),
            (),
        )
        forbidden = {"load_path", "from_path", "open_config", "install", "provision",
                     "write", "save", "bootstrap", "serve", "run", "activate",
                     "deploy", "reset", "retry"}
        self.assertTrue(forbidden.isdisjoint(loader.__all__))

    def test_reuses_exact_c17_resource_contract(self) -> None:
        self.assertEqual(PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH,
                         "/etc/omnilyzer/deployment/dev/executor.json")
        self.assertEqual(EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE, 0o750)
        self.assertEqual(EXECUTOR_SERVICE_CONFIG_FILE_MODE, 0o640)
        self.assertEqual(MAX_EXECUTOR_SERVICE_CONFIG_BYTES, 4096)


class SuccessfulLoadTests(LoaderTestCase):
    def test_successful_hardened_load_and_cleanup(self) -> None:
        host = FakeHost()
        with host.patches():
            result = loader.load_dev_executor_service_configuration()
        self.assertEqual(result.to_dict(), host.config.to_dict())
        self.assertIs(type(result), loader._DevExecutorServiceConfiguration)
        self.assertEqual(host.close_calls, [15, 14, 13, 12, 11, 10])
        self.assertEqual(host.inheritable_calls, [10, 11, 12, 13, 14, 15])

    def test_traversal_is_descriptor_relative_and_named_stats_do_not_follow(self) -> None:
        host = FakeHost()
        with host.patches():
            loader.load_dev_executor_service_configuration()
        self.assertEqual([call[0] for call in host.open_calls],
                         ["/", "etc", "omnilyzer", "deployment", "dev", "executor.json"])
        self.assertEqual([call[2] for call in host.open_calls],
                         [None, 10, 11, 12, 13, 14])
        self.assertTrue(all(call[2] is False for call in host.stat_calls))
        self.assertEqual({call[0] for call in host.stat_calls},
                         {"/", "etc", "omnilyzer", "deployment", "dev", "executor.json"})

    def test_exact_read_only_open_flags(self) -> None:
        host = FakeHost()
        with host.patches():
            loader.load_dev_executor_service_configuration()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        self.assertTrue(all(flags == directory_flags for _, flags, _ in host.open_calls[:-1]))
        self.assertEqual(host.open_calls[-1][1], file_flags)
        forbidden = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        self.assertEqual(file_flags & forbidden, 0)

    def test_parser_receives_exact_bytes_once(self) -> None:
        host = FakeHost()
        with host.patches(), patch.object(
            loader, "_parse_configuration", wraps=loader._parse_configuration,
        ) as parser:
            loader.load_dev_executor_service_configuration()
        parser.assert_called_once_with(host.raw)


class FilesystemPolicyTests(LoaderTestCase):
    def test_standard_ancestor_policy_failures(self) -> None:
        cases = {
            "non_directory": stat.S_IFREG | 0o644,
            "symlink": stat.S_IFLNK | 0o777,
            "group_writable": stat.S_IFDIR | 0o775,
            "other_writable": stat.S_IFDIR | 0o757,
        }
        for label, mode in cases.items():
            with self.subTest(label=label):
                host = FakeHost()
                host.named_status[("omnilyzer", 11)] = status_result(mode, 102)
                with host.patches():
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)
                self.assertEqual(len(host.close_calls), len(set(host.close_calls)))
        host = FakeHost()
        host.named_status[("etc", 10)] = status_result(stat.S_IFDIR | 0o755, 101, uid=1)
        with host.patches():
            self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_named_opened_directory_identity_mismatch_rejected(self) -> None:
        host = FakeHost()
        host.named_status[("deployment", 12)] = status_result(stat.S_IFDIR | 0o755, 999)
        with host.patches():
            self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_final_directory_requires_root_exact_mode_and_configured_group(self) -> None:
        variants = (
            status_result(stat.S_IFDIR | 0o700, 104, gid=2002),
            status_result(stat.S_IFDIR | 0o750, 104, uid=2001, gid=2002),
            status_result(stat.S_IFDIR | 0o750, 104, gid=2999),
        )
        for value in variants:
            with self.subTest(value=value):
                host = FakeHost()
                host.fd_status[14] = value
                host.named_status[("dev", 13)] = value
                with host.patches():
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_file_requires_regular_root_0640_single_link_and_configured_group(self) -> None:
        host0 = FakeHost()
        size = len(host0.raw)
        variants = (
            status_result(stat.S_IFIFO | 0o640, 105, gid=2002, links=1, size=size),
            status_result(stat.S_IFREG | 0o600, 105, gid=2002, links=1, size=size),
            status_result(stat.S_IFREG | 0o640, 105, uid=2001, gid=2002, links=1, size=size),
            status_result(stat.S_IFREG | 0o640, 105, gid=2002, links=2, size=size),
            status_result(stat.S_IFREG | 0o640, 105, gid=2999, links=1, size=size),
        )
        for value in variants:
            with self.subTest(value=value):
                host = FakeHost()
                host.fd_status[15] = value
                host.named_status[("executor.json", 14)] = value
                with host.patches():
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_empty_and_oversized_reported_file_rejected_before_read(self) -> None:
        for size in (0, 4097):
            with self.subTest(size=size):
                host = FakeHost()
                value = status_result(stat.S_IFREG | 0o640, 105, gid=2002,
                                      links=1, size=size)
                host.fd_status[15] = value
                host.named_status[("executor.json", 14)] = value
                with host.patches():
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)
                self.assertEqual(host.read_calls, [])

    def test_fifo_swap_between_named_stat_and_opened_fstat_is_rejected(self) -> None:
        host = FakeHost()
        host.fd_status[15] = status_result(stat.S_IFIFO | 0o640, 105, gid=2002,
                                           links=1, size=len(host.raw))
        with host.patches(), patch.object(
            loader, "_parse_configuration", side_effect=AssertionError("parser"),
        ):
            self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_inheritable_and_duplicate_descriptors_rejected_without_double_close(self) -> None:
        host = FakeHost()
        with host.patches(), patch.object(
            loader._os, "get_inheritable",
            side_effect=lambda fd: True if fd == 12 else False,
        ):
            self.assert_unavailable(loader.load_dev_executor_service_configuration)
        self.assertEqual(len(host.close_calls), len(set(host.close_calls)))

        host = FakeHost()
        host.open_map[("omnilyzer", 11)] = 11
        with host.patches():
            self.assert_unavailable(loader.load_dev_executor_service_configuration)
        self.assertEqual(host.close_calls.count(11), 1)

    def test_post_read_file_metadata_change_rejected(self) -> None:
        for index, replacement in enumerate((
            status_result(stat.S_IFREG | 0o640, 999, gid=2002, links=1),
            status_result(stat.S_IFREG | 0o640, 105, gid=2002, links=1, device=99),
            status_result(stat.S_IFREG | 0o600, 105, gid=2002, links=1),
            status_result(stat.S_IFREG | 0o640, 105, uid=1, gid=2002, links=1),
            status_result(stat.S_IFREG | 0o640, 105, gid=2001, links=1),
            status_result(stat.S_IFREG | 0o640, 105, gid=2002, links=2),
            status_result(stat.S_IFREG | 0o640, 105, gid=2002, links=1, size=1),
        )):
            with self.subTest(index=index):
                host = FakeHost()
                original = host.fd_status[15]
                replacement = status_result(
                    replacement.st_mode, replacement.st_ino,
                    uid=replacement.st_uid, gid=replacement.st_gid,
                    links=replacement.st_nlink,
                    size=replacement.st_size or len(host.raw),
                    device=replacement.st_dev,
                )
                calls = 0
                def changing_fstat(fd: int):
                    nonlocal calls
                    calls += fd == 15
                    return replacement if fd == 15 and calls > 1 else host.fd_status[fd]
                with host.patches(), patch.object(loader._os, "fstat", side_effect=changing_fstat):
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)
                self.assertEqual(original.st_size, len(host.raw))

    def test_directory_chain_change_after_read_rejected(self) -> None:
        for changed_fd in range(10, 15):
            with self.subTest(changed_fd=changed_fd):
                host = FakeHost()
                counts: dict[int, int] = {}
                def changing_fstat(fd: int):
                    counts[fd] = counts.get(fd, 0) + 1
                    if fd == changed_fd and counts[fd] > 1:
                        mode = 0o750 if fd == 14 else 0o755
                        gid = 2002 if fd == 14 else 0
                        return status_result(stat.S_IFDIR | mode, 900, gid=gid)
                    return host.fd_status[fd]
                with host.patches(), patch.object(
                    loader._os, "fstat", side_effect=changing_fstat,
                ):
                    self.assert_unavailable(
                        loader.load_dev_executor_service_configuration,
                    )


class ReadAndParserTests(LoaderTestCase):
    def test_multiple_short_reads_are_bounded(self) -> None:
        host = FakeHost()
        chunks = [host.raw[:20], host.raw[20:100], host.raw[100:], b""]
        with host.patches(), patch.object(loader._os, "read", side_effect=chunks):
            self.assertEqual(
                loader.load_dev_executor_service_configuration().to_dict(),
                host.config.to_dict(),
            )

    def test_invalid_read_behaviors_fail_closed(self) -> None:
        behaviors = (
            ["not bytes"],
            [b""],
            [b"x" * 4097],
        )
        for behavior in behaviors:
            with self.subTest(behavior=type(behavior[0]).__name__):
                host = FakeHost()
                with host.patches(), patch.object(loader._os, "read", side_effect=behavior):
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_reported_size_must_equal_actual_bytes(self) -> None:
        host = FakeHost()
        bad_size = len(host.raw) - 1
        value = status_result(stat.S_IFREG | 0o640, 105, gid=2002,
                              links=1, size=bad_size)
        host.fd_status[15] = value
        host.named_status[("executor.json", 14)] = value
        with host.patches():
            self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_excessive_short_reads_fail_after_finite_limit(self) -> None:
        host = FakeHost()
        with host.patches(), patch.object(loader._os, "read", return_value=b"x") as read:
            self.assert_unavailable(loader.load_dev_executor_service_configuration)
        self.assertEqual(read.call_count, 64)

    def test_parser_failure_is_generic_and_not_retried(self) -> None:
        host = FakeHost()
        with host.patches(), patch.object(
            loader, "_parse_configuration", side_effect=ValueError("raw JSON marker"),
        ) as parser:
            self.assert_unavailable(loader.load_dev_executor_service_configuration)
        self.assertEqual(parser.call_count, 1)


class ProcessIdentityTests(LoaderTestCase):
    def test_real_effective_identity_and_groups_are_bound(self) -> None:
        bad_identities = (
            (2000, 2001, 2002, 2002, [2003]),
            (2001, 2000, 2002, 2002, [2003]),
            (2001, 2001, 2000, 2002, [2003]),
            (2001, 2001, 2002, 2000, [2003]),
            (2001, 2001, 2002, 2002, []),
            (2001, 2001, 2002, 2002, [2003, 2999]),
            (2001, 2001, 2002, 2002, [2003, 2003]),
        )
        for identity in bad_identities:
            with self.subTest(identity=identity):
                host = FakeHost()
                host.identity = identity
                with host.patches():
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_primary_group_may_also_be_reported(self) -> None:
        host = FakeHost()
        host.identity = (2001, 2001, 2002, 2002, [2002, 2003])
        with host.patches():
            self.assertEqual(
                loader.load_dev_executor_service_configuration().to_dict(),
                host.config.to_dict(),
            )

    def test_process_values_are_strict_and_bounded(self) -> None:
        for value in (True, -1, 1.0, "2001", MAX_UID_GID + 1):
            with self.subTest(value=value):
                host = FakeHost()
                with host.patches(), patch.object(loader._os, "getuid", return_value=value):
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)
                    self.assertEqual(host.open_calls, [])
        for groups in ((2003,), [True], [1.0], ["2003"], [-1], [MAX_UID_GID + 1]):
            with self.subTest(groups=groups):
                host = FakeHost()
                with host.patches(), patch.object(loader._os, "getgroups", return_value=groups):
                    self.assert_unavailable(loader.load_dev_executor_service_configuration)

    def test_process_identity_must_remain_stable(self) -> None:
        host = FakeHost()
        with host.patches(), patch.object(
            loader._os, "getuid", side_effect=[2001, 2000],
        ):
            self.assert_unavailable(loader.load_dev_executor_service_configuration)


class CleanupAndErrorTests(LoaderTestCase):
    def test_socket_or_open_failure_is_generic_and_closes_owned_fds_once(self) -> None:
        host = FakeHost()
        def failing_open(path, flags, *, dir_fd=None):
            if path == "executor.json":
                raise OSError("sensitive marker")
            return host.open(path, flags, dir_fd=dir_fd)
        with host.patches(), patch.object(loader._os, "open", side_effect=failing_open):
            self.assert_unavailable(loader.load_dev_executor_service_configuration)
        self.assertEqual(host.close_calls, [14, 13, 12, 11, 10])

    def test_close_failure_on_success_and_failure_is_generic(self) -> None:
        host = FakeHost()
        def bad_close(fd: int):
            host.close_calls.append(fd)
            if fd == 13:
                raise OSError("close marker")
        with host.patches(), patch.object(loader._os, "close", side_effect=bad_close):
            self.assert_unavailable(loader.load_dev_executor_service_configuration)
        self.assertEqual(len(host.close_calls), 6)

        host = FakeHost()
        with host.patches(), patch.object(loader._os, "read", side_effect=OSError("read")), \
                patch.object(loader._os, "close", side_effect=OSError("close")) as close:
            self.assert_unavailable(loader.load_dev_executor_service_configuration)
        self.assertEqual(close.call_count, 6)

    def test_control_flow_exceptions_are_preserved_and_cleanup_runs(self) -> None:
        for exception in (KeyboardInterrupt(), SystemExit(), GeneratorExit()):
            with self.subTest(exception=type(exception).__name__):
                host = FakeHost()
                with host.patches(), patch.object(loader._os, "read", side_effect=exception):
                    with self.assertRaises(type(exception)):
                        loader.load_dev_executor_service_configuration()
                self.assertEqual(host.close_calls, [15, 14, 13, 12, 11, 10])

    def test_cleanup_failure_does_not_replace_active_control_flow(self) -> None:
        host = FakeHost()
        with host.patches(), patch.object(
            loader._os, "read", side_effect=KeyboardInterrupt("control marker"),
        ), patch.object(
            loader._os, "close", side_effect=OSError("cleanup marker"),
        ) as close:
            with self.assertRaisesRegex(KeyboardInterrupt, "control marker"):
                loader.load_dev_executor_service_configuration()
        self.assertEqual(close.call_count, 6)

    def test_generic_message_does_not_reflect_lower_level_data(self) -> None:
        host = FakeHost()
        with host.patches(), patch.object(
            loader._os, "stat", side_effect=OSError("uid=999 inode=secret JSON"),
        ):
            with self.assertRaises(loader.ExecutorServiceConfigurationUnavailableError) as caught:
                loader.load_dev_executor_service_configuration()
        self.assertEqual(str(caught.exception), "DEV executor service configuration is unavailable")


class StructuralSeparationTests(LoaderTestCase):
    def test_no_write_provision_or_operational_coupling(self) -> None:
        source_path = Path(loader.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = {
            alias.name for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        forbidden_imports = {
            "DevExecutorComposition", "acquire_systemd_executor_listener",
            "UnixExecutorListener", "SubprocessCommandRunner", "DockerRuntimeAdapter",
            "DockerComposeCandidateHttpClient", "SQLiteReplayGuard",
            "FilesystemDeploymentStateStore", "FilesystemAuditSink", "tempfile", "shutil",
        }
        self.assertTrue(imported.isdisjoint(forbidden_imports))

        forbidden_calls = {
            "mkdir", "makedirs", "write", "pwrite", "chmod", "chown", "fchmod",
            "fchown", "rename", "replace", "unlink", "remove", "link", "symlink",
            "mknod", "mkfifo", "fsync", "getenv",
        }
        calls = {
            node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(tree) if isinstance(node, ast.Call)
            if isinstance(node.func, (ast.Attribute, ast.Name))
        }
        self.assertTrue(calls.isdisjoint(forbidden_calls))
        self.assertNotIn("DevExecutorComposition", source_path.read_text(encoding="utf-8"))
        self.assertNotIn("acquire_systemd_executor_listener", source_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
