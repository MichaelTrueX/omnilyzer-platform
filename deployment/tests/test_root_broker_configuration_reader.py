"""C32ZK privileged broker read adapter reuses hardened loader mechanics."""

import importlib
import inspect
import stat
import unittest
from unittest.mock import patch

from deployment import broker_service_config_loader as live
from deployment import root_broker_configuration_reader as root
from deployment.application_source_set import DevApplicationSourceSet
from deployment.tests.test_broker_service_config_loader import (
    FakeHost,
    status_result,
)


class RootBrokerReaderTests(unittest.TestCase):
    def host(self):
        """Return the broker loader fake with a root process identity."""

        fake = FakeHost()
        fake.identity = (0, 0, 0, 0, [])
        return fake

    def test_fixed_read_reuses_loader_without_live_identity_binding(self) -> None:
        fake = self.host()
        with fake.patches(), patch.object(
            live, "_load", side_effect=AssertionError,
        ), patch.object(
            live, "_bind_configuration", side_effect=AssertionError,
        ), patch.object(
            live, "load_dev_broker_service_configuration",
            side_effect=AssertionError,
        ):
            result = root.read_root_dev_broker_configuration()
        self.assertEqual(result.to_dict(), fake.config.to_dict())
        self.assertEqual(
            tuple(
                inspect.signature(
                    root.read_root_dev_broker_configuration,
                ).parameters
            ),
            (),
        )
        self.assertEqual(fake.close_calls, [15, 14, 13, 12, 11, 10])
        self.assertEqual(
            [item[0] for item in fake.open_calls],
            ["/", "etc", "omnilyzer", "deployment", "broker", "dev.json"],
        )
        self.assertNotIn(
            "deployment/root_broker_configuration_reader.py",
            tuple(
                item.repository_path for item in DevApplicationSourceSet().files
            ),
        )

    def test_import_is_inert(self) -> None:
        with patch.object(root.os, "open", side_effect=AssertionError("host")):
            importlib.reload(root)

    def test_root_identity_and_broker_group_binding(self) -> None:
        for changed in ("getuid", "geteuid", "getgid", "getegid"):
            fake = self.host()
            with fake.patches(), patch.object(
                root.os, changed, return_value=1,
            ), self.assertRaises(root.RootBrokerConfigurationUnavailableError):
                root.read_root_dev_broker_configuration()
        for descriptor in (14, 15):
            fake = self.host()
            current = fake.fd_status[descriptor]
            fake.fd_status[descriptor] = status_result(
                current.st_mode,
                current.st_ino,
                gid=0,
                links=current.st_nlink,
                size=current.st_size,
            )
            fake.named_status[
                next(
                    key
                    for key, value in fake.open_map.items()
                    if value == descriptor
                )
            ] = fake.fd_status[descriptor]
            with fake.patches(), self.assertRaises(
                root.RootBrokerConfigurationUnavailableError,
            ):
                root.read_root_dev_broker_configuration()

    def test_symlink_link_mode_owner_and_replacement_rejected(self) -> None:
        for change in (
            "symlink", "link", "mode", "owner", "replace", "directory-replace",
            "oversize", "json",
        ):
            fake = self.host()
            if change == "symlink":
                fake.fd_status[15] = status_result(
                    stat.S_IFLNK | 0o640, 105, gid=1002,
                    links=1, size=len(fake.raw),
                )
                fake.named_status[("dev.json", 14)] = fake.fd_status[15]
            elif change == "link":
                fake.fd_status[15] = status_result(
                    stat.S_IFREG | 0o640, 105, gid=1002,
                    links=2, size=len(fake.raw),
                )
                fake.named_status[("dev.json", 14)] = fake.fd_status[15]
            elif change == "mode":
                fake.fd_status[14] = status_result(
                    stat.S_IFDIR | 0o755, 104, gid=1002,
                )
                fake.named_status[("broker", 13)] = fake.fd_status[14]
            elif change == "owner":
                fake.fd_status[15] = status_result(
                    stat.S_IFREG | 0o640, 105, uid=1, gid=1002,
                    links=1, size=len(fake.raw),
                )
                fake.named_status[("dev.json", 14)] = fake.fd_status[15]
            elif change == "replace":
                fake.named_status[("dev.json", 14)] = status_result(
                    stat.S_IFREG | 0o640, 106, gid=1002,
                    links=1, size=len(fake.raw),
                )
            elif change == "directory-replace":
                fake.named_status[("broker", 13)] = status_result(
                    stat.S_IFDIR | 0o750, 106, gid=1002,
                )
            elif change == "oversize":
                fake.fd_status[15] = status_result(
                    stat.S_IFREG | 0o640, 105, gid=1002, links=1,
                    size=live._MAX_BYTES + 1,
                )
                fake.named_status[("dev.json", 14)] = fake.fd_status[15]
            elif change == "json":
                fake.raw = b'{"schema_version":2,"schema_version":2}\n'
                fake.fd_status[15] = status_result(
                    stat.S_IFREG | 0o640, 105, gid=1002,
                    links=1, size=len(fake.raw),
                )
                fake.named_status[("dev.json", 14)] = fake.fd_status[15]
            with self.subTest(change=change), fake.patches(), self.assertRaises(
                root.RootBrokerConfigurationUnavailableError,
            ):
                root.read_root_dev_broker_configuration()

    def test_identity_change_cleanup_failure_and_secret_diagnostic_fail_closed(self):
        fake = self.host()
        with fake.patches(), patch.object(
            root.os, "getuid", side_effect=[0, 1],
        ), self.assertRaises(root.RootBrokerConfigurationUnavailableError):
            root.read_root_dev_broker_configuration()

        fake = self.host()
        with fake.patches(), patch.object(
            live, "_close_owned", return_value=(True, None),
        ), self.assertRaises(root.RootBrokerConfigurationUnavailableError):
            root.read_root_dev_broker_configuration()

        fake = self.host()
        fake.raw = b'{"secret":"DO-NOT-REPORT"}\n'
        fake.fd_status[15] = status_result(
            stat.S_IFREG | 0o640, 105, gid=1002,
            links=1, size=len(fake.raw),
        )
        fake.named_status[("dev.json", 14)] = fake.fd_status[15]
        with fake.patches(), self.assertRaises(
            root.RootBrokerConfigurationUnavailableError,
        ) as caught:
            root.read_root_dev_broker_configuration()
        self.assertNotIn("DO-NOT-REPORT", str(caught.exception))

    def test_no_mutation_surface(self) -> None:
        source = inspect.getsource(root)
        for forbidden in (
            "os.mkdir", "os.chown", "os.chmod", "os.unlink", "os.replace",
            "subprocess", "socket.socket",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
