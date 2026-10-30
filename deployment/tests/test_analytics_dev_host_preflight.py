"""File: deployment/tests/test_analytics_dev_host_preflight.py

Purpose: Verify read-only Analytics DEV prerequisite classification and
         exhaustive tri-state reporting without opening secrets or changing
         running services, source directories, Docker or databases.
Related: deployment/analytics_dev_host_preflight.py and original Task014 C17
         host source/socket contracts.

Sections: root metadata/owner tests, permissions vs missing distinction,
          source and service matrix, no accidental installation grant.
"""
from __future__ import annotations

import errno
import io
import json
import os
import stat
import unittest
from unittest.mock import patch

from deployment import analytics_dev_host_preflight as probe


class AnalyticsHostReadOnlyPreflightTests(unittest.TestCase):
    """Mock only stat and service observations; no host-side mutations."""

    def test_permission_denial_never_masquerades_as_missing(self):
        """Protected C17 config may exist but be invisible to omnigpt."""
        with patch.object(
            probe.os, "stat", side_effect=PermissionError(errno.EACCES, "denied"),
        ):
            self.assertEqual(probe._file_probe("/private", "file", 0o640),
                             "inaccessible")
        with patch.object(
            probe.os, "stat", side_effect=FileNotFoundError(errno.ENOENT, "absent"),
        ):
            self.assertEqual(probe._file_probe("/missing", "file", 0o640),
                             "missing")
        with patch.object(
            probe.os, "stat", side_effect=OSError(errno.EIO, "io"),
        ):
            self.assertEqual(probe._file_probe("/fault", "file", 0o640),
                             "unknown")

    def test_symlink_wrong_owner_and_wrong_mode_are_invalid(self):
        """Never follow an attacker-selected source symlink."""
        def fake(mode, uid=0, links=1):
            return os.stat_result((mode, 1, 1, links, uid, 0, 0, 0, 0, 0))
        for kind, mode, uid, links, expected in (
            ("file", stat.S_IFREG | 0o640, 0, 1, "present"),
            ("file", stat.S_IFREG | 0o600, 0, 1, "invalid"),
            ("file", stat.S_IFREG | 0o640, 55, 1, "invalid"),
            ("file", stat.S_IFREG | 0o640, 0, 2, "invalid"),
            ("file", stat.S_IFLNK | 0o640, 0, 1, "invalid"),
            ("directory", stat.S_IFDIR | 0o755, 0, 2, "present"),
            ("socket", stat.S_IFSOCK | 0o660, 991, 1, "present"),
        ):
            with self.subTest(kind=kind, mode=mode, uid=uid, links=links), \
                 patch.object(probe.os, "stat", return_value=fake(
                     mode, uid, links,
                 )):
                self.assertEqual(probe._file_probe("/fixed", kind, (
                    0o640 if kind == "file" else 0o755
                    if kind == "directory" else None
                )), expected)
        with patch.object(probe.os, "stat", return_value=fake(
            stat.S_IFREG | 0o640,
        )) as stat_mock:
            probe._file_probe("/fixed", "file", 0o640)
            stat_mock.assert_called_once_with("/fixed", follow_symlinks=False)

    def test_all_independent_errors_and_services_collected(self):
        """No first failure masks later missing/permission/invalid statuses."""
        responses = {
            "original_canary_app": "present",
            "analytics_app": "missing",
            "source_approval": "inaccessible",
            "source_archive": "missing",
            "analytics_broker_config": "inaccessible",
            "analytics_executor_config": "inaccessible",
            "four_secret_directory": "missing",
            "rootless_bind_socket": "missing",
            "rootless_daemon_socket": "inaccessible",
        }
        unit_values = {
            "original_broker": "active",
            "original_executor_socket": "active",
            "analytics_executor_socket": "inactive",
        }
        labels = [name for name, *_ in probe._FILES]
        services = [name for name, *_ in probe._SERVICES]
        def file_effect(_path, _kind, _mode):
            return responses[labels[file_counter.__next__()]]
        def unit_effect(_name):
            return unit_values[services[unit_counter.__next__()]]
        file_counter = iter(range(len(labels)))
        unit_counter = iter(range(len(services)))
        with patch.object(probe, "_file_probe", side_effect=file_effect) as file_call, \
             patch.object(probe, "_unit_probe", side_effect=unit_effect) as unit_call:
            review = probe.collect_analytics_dev_preflight()
        self.assertEqual(file_call.call_count, len(responses))
        self.assertEqual(unit_call.call_count, len(services))
        self.assertTrue(review["original_canary_healthy"])
        self.assertFalse(review["installed_source_preflight_complete"])
        self.assertEqual(review["missing"], sorted([
            "analytics_app", "source_archive", "four_secret_directory",
            "rootless_bind_socket",
        ]))
        self.assertEqual(review["inaccessible"], sorted([
            "source_approval", "analytics_broker_config",
            "analytics_executor_config", "rootless_daemon_socket",
        ]))
        self.assertFalse(review["deployment_authorized"])
        self.assertFalse(review["release_signatures_verified"])
        self.assertFalse(review["real_runtime_accepted"])

    def test_active_canary_does_not_prove_analytics_ready(self):
        """Source and service status is NOT a signed-release qualification."""
        with patch.object(probe, "_file_probe", return_value="present"), \
             patch.object(probe, "_unit_probe", side_effect=(
                "active", "active", "inactive",
             )):
            value = probe.collect_analytics_dev_preflight()
        self.assertTrue(value["original_canary_healthy"])
        self.assertFalse(value["deployment_authorized"])
        self.assertFalse(value["real_runtime_accepted"])
        self.assertFalse(value["release_signatures_verified"])
        self.assertEqual(value["services"]["analytics_executor_socket"], "inactive")

    def test_cli_is_fixed_and_never_discloses_any_secret_values(self):
        """Only fixed status labels and public canonical resource identities."""
        with patch.object(probe, "_file_probe", return_value="missing"), \
             patch.object(probe, "_unit_probe", return_value="inactive"), \
             patch("sys.argv", ["analytics_dev_host_preflight", "--read-only"]), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(probe.main(), 0)
            result = json.loads(output.getvalue())
        self.assertEqual(result["product_id"], "analytics")
        self.assertFalse(result["deployment_authorized"])
        self.assertNotIn("JWT_SECRET", output.getvalue())
        self.assertNotIn("DATABASE_URL", output.getvalue())
        with patch("sys.argv", ["analytics_dev_host_preflight", "--install"]):
            self.assertEqual(probe.main(), 2)


if __name__ == "__main__":
    unittest.main()
