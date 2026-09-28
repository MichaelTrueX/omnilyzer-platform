"""C32Y privileged read adapter reuses the frozen C17 loader mechanics."""

import importlib
import inspect
import stat
import unittest
from unittest.mock import patch

from deployment import executor_service_config_loader as live
from deployment import root_executor_configuration_reader as root
from deployment.application_source_set import DevApplicationSourceSet
from deployment.tests.test_executor_service_config_loader import FakeHost, status_result


class RootReaderTests(unittest.TestCase):
    def host(self):
        fake = FakeHost()
        fake.identity = (0, 0, 0, 0, [])
        return fake

    def test_fixed_read_reuses_loader_and_never_calls_live_identity_binding(self):
        fake = self.host()
        with fake.patches(), patch.object(live, "_load", side_effect=AssertionError), \
                patch.object(live, "_bind_configuration", side_effect=AssertionError), \
                patch.object(live, "load_dev_executor_service_configuration",
                             side_effect=AssertionError):
            result = root.read_root_dev_executor_configuration()
        self.assertEqual(result.to_dict(), fake.config.to_dict())
        self.assertEqual(tuple(inspect.signature(root.read_root_dev_executor_configuration).parameters), ())
        self.assertEqual(fake.close_calls, [15, 14, 13, 12, 11, 10])
        self.assertEqual([x[0] for x in fake.open_calls],
                         ["/", "etc", "omnilyzer", "deployment", "dev", "executor.json"])
        self.assertNotIn("deployment/root_executor_configuration_reader.py",
                         tuple(item.repository_path for item in DevApplicationSourceSet().files))

    def test_import_is_inert(self):
        with patch.object(root.os, "open", side_effect=AssertionError("host read")):
            importlib.reload(root)

    def test_root_identity_and_group_binding(self):
        for changed in ("getuid", "geteuid", "getgid", "getegid"):
            fake = self.host()
            with fake.patches(), patch.object(root.os, changed, return_value=1), \
                    self.assertRaises(root.RootExecutorConfigurationUnavailableError):
                root.read_root_dev_executor_configuration()
        for descriptor in (14, 15):
            fake = self.host()
            current = fake.fd_status[descriptor]
            fake.fd_status[descriptor] = status_result(current.st_mode, current.st_ino,
                gid=0, links=current.st_nlink, size=current.st_size)
            fake.named_status[next(key for key, value in fake.open_map.items()
                                   if value == descriptor)] = fake.fd_status[descriptor]
            with fake.patches(), self.assertRaises(root.RootExecutorConfigurationUnavailableError):
                root.read_root_dev_executor_configuration()

    def test_symlink_link_mode_replacement_and_noncanonical_rejected(self):
        for change in ("symlink", "link", "mode", "owner", "replace", "directory-replace",
                       "oversize", "json"):
            fake = self.host()
            if change == "symlink":
                fake.fd_status[15] = status_result(stat.S_IFLNK | 0o640, 105,
                    gid=2002, links=1, size=len(fake.raw))
                fake.named_status[("executor.json", 14)] = fake.fd_status[15]
            elif change == "link":
                fake.fd_status[15] = status_result(stat.S_IFREG | 0o640, 105,
                    gid=2002, links=2, size=len(fake.raw))
                fake.named_status[("executor.json", 14)] = fake.fd_status[15]
            elif change == "mode":
                fake.fd_status[14] = status_result(stat.S_IFDIR | 0o755, 104, gid=2002)
                fake.named_status[("dev", 13)] = fake.fd_status[14]
            elif change == "owner":
                fake.fd_status[15] = status_result(stat.S_IFREG | 0o640, 105,
                    uid=1, gid=2002, links=1, size=len(fake.raw))
                fake.named_status[("executor.json", 14)] = fake.fd_status[15]
            elif change == "replace":
                fake.named_status[("executor.json", 14)] = status_result(
                    stat.S_IFREG | 0o640, 106, gid=2002, links=1, size=len(fake.raw))
            elif change == "directory-replace":
                fake.named_status[("dev", 13)] = status_result(
                    stat.S_IFDIR | 0o750, 106, gid=2002)
            elif change == "oversize":
                fake.fd_status[15] = status_result(stat.S_IFREG | 0o640, 105,
                    gid=2002, links=1, size=live._MAX_BYTES + 1)
                fake.named_status[("executor.json", 14)] = fake.fd_status[15]
            elif change == "json":
                fake.raw = b'{"schema_version":1,"schema_version":1}\n'
                fake.fd_status[15] = status_result(stat.S_IFREG | 0o640, 105,
                    gid=2002, links=1, size=len(fake.raw))
                fake.named_status[("executor.json", 14)] = fake.fd_status[15]
            with self.subTest(change=change), fake.patches(), \
                    self.assertRaises(root.RootExecutorConfigurationUnavailableError):
                root.read_root_dev_executor_configuration()

    def test_identity_change_and_cleanup_failure_fail_closed(self):
        fake = self.host()
        with fake.patches(), patch.object(root.os, "getuid", side_effect=[0, 1]), \
                self.assertRaises(root.RootExecutorConfigurationUnavailableError):
            root.read_root_dev_executor_configuration()
        fake = self.host()
        with fake.patches(), patch.object(live, "_close_owned", return_value=(True, None)), \
                self.assertRaises(root.RootExecutorConfigurationUnavailableError):
            root.read_root_dev_executor_configuration()

    def test_named_file_and_directory_replacement_after_read_fail(self):
        for target in ("file", "directory"):
            fake = self.host()
            original_read = fake.read
            def replacing_read(descriptor, maximum):
                value = original_read(descriptor, maximum)
                if value:
                    if target == "file":
                        fake.named_status[("executor.json", 14)] = status_result(
                            stat.S_IFREG | 0o640, 106, gid=2002, links=1,
                            size=len(fake.raw))
                    else:
                        fake.named_status[("dev", 13)] = status_result(
                            stat.S_IFDIR | 0o750, 106, gid=2002)
                return value
            fake.read = replacing_read
            with self.subTest(target=target), fake.patches(), \
                    self.assertRaises(root.RootExecutorConfigurationUnavailableError):
                root.read_root_dev_executor_configuration()

    def test_no_mutation_surface_or_secret_diagnostic(self):
        source = inspect.getsource(root)
        for forbidden in ("os.mkdir", "os.chown", "os.chmod", "os.unlink", "os.replace",
                          "subprocess", "socket.socket"):
            self.assertNotIn(forbidden, source)
        fake = self.host()
        fake.raw = b'{"secret":"DO-NOT-REPORT"}\n'
        fake.fd_status[15] = status_result(stat.S_IFREG | 0o640, 105,
            gid=2002, links=1, size=len(fake.raw))
        fake.named_status[("executor.json", 14)] = fake.fd_status[15]
        with fake.patches(), self.assertRaises(root.RootExecutorConfigurationUnavailableError) as caught:
            root.read_root_dev_executor_configuration()
        self.assertNotIn("DO-NOT-REPORT", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
