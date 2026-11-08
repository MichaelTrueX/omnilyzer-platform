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
        ]))
        self.assertEqual(review["inaccessible"], sorted([
            "source_approval", "analytics_broker_config",
            "analytics_executor_config", "rootless_daemon_socket",
        ]))
        self.assertEqual(
            review["executor_private_mount"],
            {
                "name": "rootless_bind_socket",
                "host_observation": "missing",
                "required_as_host_path": False,
                "actual_executor_mount_verified": False,
            },
        )
        self.assertFalse(review["deployment_authorized"])
        self.assertFalse(review["release_signatures_verified"])
        self.assertFalse(review["real_runtime_accepted"])

    def test_rootless_runtime_bind_is_not_a_host_install_prerequisite(self):
        """Systemd creates the bind inside executor mount namespace only.

        A running rootless daemon socket is required on the host; even when
        all other prerequisites are visible, no signed release or real
        executor mount is automatically proved by this read-only preflight.
        """
        with patch.object(probe, "_file_probe", side_effect=(
            "present", "present", "present", "present",
            "present", "present", "present", "missing", "present",
        )), patch.object(probe, "_unit_probe", return_value="active"):
            report = probe.collect_analytics_dev_preflight()
        self.assertEqual(report["files"]["rootless_bind_socket"], "missing")
        self.assertNotIn("rootless_bind_socket", report["missing"])
        self.assertTrue(report["installed_source_preflight_complete"])
        self.assertFalse(
            report["executor_private_mount"]["actual_executor_mount_verified"],
        )
        self.assertFalse(report["release_signatures_verified"])
        self.assertFalse(report["real_runtime_accepted"])
        self.assertFalse(report["deployment_authorized"])

    def test_missing_daemon_socket_is_a_hard_host_prerequisite(self):
        """Never infer a working daemon merely from the bind-mount design."""
        with patch.object(probe, "_file_probe", side_effect=(
            "present", "present", "present", "present",
            "present", "present", "present", "missing", "missing",
        )), patch.object(probe, "_unit_probe", return_value="active"):
            report = probe.collect_analytics_dev_preflight()
        self.assertFalse(report["installed_source_preflight_complete"])
        self.assertEqual(report["missing"], ["rootless_daemon_socket"])
        self.assertFalse(report["executor_private_mount"]["actual_executor_mount_verified"])

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

    def test_successor_preflight_is_aggregated_and_never_authorizes(self):
        """Even perfect metadata and HTTP health cannot grant a release."""
        with patch.object(probe, "collect_analytics_dev_preflight", return_value={
            "read_only": True, "files": {}, "services": {}, "missing": [],
            "inaccessible": [], "invalid": [], "deployment_authorized": False,
        }), patch.object(probe, "_owner_trust_metadata_probe", return_value="present"), \
             patch.object(probe, "_unit_probe", return_value="active"), \
             patch.object(probe, "_private_http_status", return_value="200"):
            result = probe.collect_analytics_successor_preflight()
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["owner_source_approval_key"], "present")
        self.assertTrue(result["successor_runtime_observed"])
        self.assertTrue(result["preflight_observations_complete"])
        for key in (
            "deployment_authorized", "task14b_supported_release_verified",
            "task14b_owner_signature_verified", "task14b_m04_qa_accepted",
            "task14b_rollback_verified",
        ):
            self.assertIs(result[key], False)

    def test_successor_unknown_original_host_state_is_not_complete(self):
        """An original socket stat error must not be hidden by new health GETs."""
        with patch.object(probe, "collect_analytics_dev_preflight", return_value={
            "read_only": True, "files": {"rootless_daemon_socket": "unknown"},
            "services": {"original_executor_socket": "active"},
            "missing": [], "inaccessible": [], "invalid": [],
            "deployment_authorized": False,
        }), patch.object(probe, "_owner_trust_metadata_probe", return_value="present"), \
             patch.object(probe, "_unit_probe", return_value="active"), \
             patch.object(probe, "_private_http_status", return_value="200"):
            report = probe.collect_analytics_successor_preflight()
        self.assertFalse(report["preflight_observations_complete"])
        self.assertTrue(report["successor_runtime_observed"])
        self.assertEqual(report["release_decision"], "HOLD")

    def test_successor_collects_all_statuses_after_inaccessible_key(self):
        """Unprivileged stat EACCES stays UNKNOWN, never a missing key claim."""
        with patch.object(probe, "collect_analytics_dev_preflight", return_value={
            "read_only": True, "files": {}, "services": {},
            "missing": ["existing_missing"], "inaccessible": ["existing_unknown"],
            "invalid": ["existing_invalid"], "deployment_authorized": False,
        }), patch.object(probe, "_owner_trust_metadata_probe", return_value="inaccessible"), \
             patch.object(probe, "_unit_probe", return_value="active") as units, \
             patch.object(probe, "_private_http_status", side_effect=[
                 "200", "503", "503",
             ]) as probes:
            result = probe.collect_analytics_successor_preflight()
        self.assertEqual(units.call_count, len(probe._SUCCESSOR_SERVICES))
        self.assertEqual(probes.call_count, len(probe._PRIVATE_HTTP))
        self.assertEqual(result["missing"], ["existing_missing"])
        self.assertEqual(result["inaccessible"], [
            "existing_unknown", "owner_source_approval_key",
        ])
        self.assertFalse(result["successor_runtime_observed"])
        self.assertFalse(result["preflight_observations_complete"])
        self.assertEqual(result["release_decision"], "HOLD")
        self.assertFalse(result["task14b_owner_signature_verified"])

    def test_owner_key_metadata_denies_world_writable_or_wrong_owner(self):
        """No read, content, key, secret or privileged operation is performed."""
        def metadata(mode, owner=0, size=128):
            return os.stat_result((mode, 3, 4, 1, owner, 0, size, 0, 0, 0))
        valid_dirs = [
            metadata(stat.S_IFDIR | 0o755),
            metadata(stat.S_IFDIR | 0o755),
            metadata(stat.S_IFDIR | 0o755),
            metadata(stat.S_IFDIR | 0o750),
        ]
        with patch.object(probe.os, "stat", side_effect=[
            *valid_dirs, metadata(stat.S_IFREG | 0o640),
        ]) as inspected:
            self.assertEqual(probe._owner_trust_metadata_probe(), "present")
        self.assertEqual(inspected.call_count, 5)
        with patch.object(probe.os, "stat", side_effect=[
            *valid_dirs, metadata(stat.S_IFREG | 0o666),
        ]):
            self.assertEqual(probe._owner_trust_metadata_probe(), "invalid")
        with patch.object(probe.os, "stat", side_effect=[
            *valid_dirs, metadata(stat.S_IFREG | 0o640, owner=1005),
        ]):
            self.assertEqual(probe._owner_trust_metadata_probe(), "invalid")
        with patch.object(probe.os, "stat", side_effect=PermissionError(
            errno.EACCES, "protected",
        )):
            self.assertEqual(probe._owner_trust_metadata_probe(), "inaccessible")
        with patch.object(probe.os, "stat", side_effect=FileNotFoundError(
            errno.ENOENT, "absent",
        )):
            self.assertEqual(probe._owner_trust_metadata_probe(), "missing")

    def test_fixed_local_http_refuses_arbitrary_destinations(self):
        """Host/port/path are closed and redirects are not followed."""
        with patch.object(probe.http.client, "HTTPConnection") as make:
            self.assertEqual(probe._private_http_status(8080, "/readyz"), "not-allowed")
            self.assertEqual(probe._private_http_status(3141, "/admin"), "not-allowed")
            make.assert_not_called()
            client = make.return_value
            client.getresponse.return_value.status = 302
            self.assertEqual(probe._private_http_status(3141, "/livez"), "302")
            make.assert_called_once_with("127.0.0.1", 3141, timeout=3)
            client.request.assert_called_once_with(
                "GET", "/livez", headers={"Connection": "close"},
            )
            client.close.assert_called_once()

    def test_successor_cli_only_emits_readonly_status_matrix(self):
        with patch.object(probe, "_file_probe", return_value="inaccessible"), \
             patch.object(probe, "_unit_probe", return_value="inactive"), \
             patch.object(probe, "_owner_trust_metadata_probe", return_value="inaccessible"), \
             patch.object(probe, "_private_http_status", return_value="unavailable"), \
             patch("sys.argv", ["analytics_dev_host_preflight", "--successor-read-only"]), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(probe.main(), 0)
            report = json.loads(output.getvalue())
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["owner_source_approval_key"], "inaccessible")
        self.assertEqual(report["private_http_status"]["analytics_ready"], "unavailable")
        self.assertFalse(report["task14b_supported_release_verified"])
        self.assertFalse(report["deployment_authorized"])
        self.assertNotIn("JWT_SECRET", output.getvalue())
        self.assertNotIn("DATABASE_URL", output.getvalue())

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
