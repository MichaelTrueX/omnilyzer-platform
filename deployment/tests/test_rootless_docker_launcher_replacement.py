"""Tests for the C33K launcher-only replacement transition."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import os
import stat
import unittest
from unittest.mock import patch, call

from deployment import rootless_docker_launcher_replacement as module
from deployment.rootless_docker_authority import AUTHORITY


ROOT = Path(__file__).resolve().parents[2]


class RootlessDockerLauncherReplacementTests(unittest.TestCase):
    @staticmethod
    def _stat(mode: int, *, size: int = 3, inode: int = 41):
        return os.stat_result(
            (
                mode,
                inode,
                17,
                1,
                0,
                0,
                size,
                0,
                0,
                0,
            )
        )

    def test_evidence_is_exact_and_immutable(self):
        value = module.RootlessDockerLauncherReplacementEvidence(
            "replaced",
            module._PREDECESSOR_SHA256,
            module._TARGET_SHA256,
            module._TARGET_SHA256,
        )
        with self.assertRaises(FrozenInstanceError):
            value.operation = "already-replaced"
        for bad in (
            ("wrong", module._PREDECESSOR_SHA256, module._TARGET_SHA256, module._TARGET_SHA256),
            ("replaced", "0" * 64, module._TARGET_SHA256, module._TARGET_SHA256),
            ("replaced", module._PREDECESSOR_SHA256, "0" * 64, module._TARGET_SHA256),
            ("replaced", module._PREDECESSOR_SHA256, module._TARGET_SHA256, "0" * 64),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                module.RootlessDockerLauncherReplacementEvidence(*bad)

    def test_transition_pins_exact_predecessor_and_authority_target(self):
        self.assertEqual(
            module._PREDECESSOR_SHA256,
            "34d5557a068e030c75e063cf6b6106ef118ec7ff87de1d953d900dfbd1eaefff",
        )
        expected = next(
            item[2]
            for item in AUTHORITY.installed_assets
            if item[1] == AUTHORITY.launcher
        )
        self.assertEqual(module._TARGET_SHA256, expected)
        self.assertNotEqual(module._PREDECESSOR_SHA256, module._TARGET_SHA256)
        self.assertEqual(module._PARENT, "/opt/omnilyzer/deployment/rootless-docker")
        self.assertEqual(module._NAME, "launch.py")

    def test_replacement_is_same_directory_atomic_and_fsyncs_parent(self):
        payload = b"new"
        old = ((0o100644, 17, 41, 1, 0, 0), b"old", module._PREDECESSOR_SHA256)
        new = ((0o100644, 17, 42, 1, 0, 0), payload, module._TARGET_SHA256)
        created = self._stat(stat.S_IFREG | 0o600)
        exact = self._stat(stat.S_IFREG | 0o644)

        with patch.object(module, "_source_bytes", return_value=payload),              patch.object(module, "_parent", return_value=50),              patch.object(module, "_installed", side_effect=(old, old, new)),              patch.object(module, "_temporary_state", side_effect=(("absent", 0), ("exact", len(payload)))),              patch.object(module.os, "open", return_value=60) as opened,              patch.object(module.os, "fstat", side_effect=(created, exact)),              patch.object(module, "_write_all") as write_all,              patch.object(module.os, "fsync") as fsync,              patch.object(module.os, "fchmod") as fchmod,              patch.object(module.os, "replace") as replace,              patch.object(module.os, "close") as close:
            evidence = module._replace_under_lock()

        self.assertEqual(evidence.operation, "replaced")
        opened.assert_called_once()
        write_all.assert_called_once_with(60, payload)
        fchmod.assert_called_once_with(60, 0o644)
        replace.assert_called_once_with(
            module._TEMPORARY,
            module._NAME,
            src_dir_fd=50,
            dst_dir_fd=50,
        )
        self.assertIn(call(50), fsync.call_args_list)
        self.assertIn(call(60), close.call_args_list)
        self.assertEqual(close.call_args_list[-1], call(50))

    def test_exact_prefix_stage_resumes_without_rewriting_prefix(self):
        payload = b"abcdef"
        old = ((0o100644, 17, 41, 1, 0, 0), b"old", module._PREDECESSOR_SHA256)
        new = ((0o100644, 17, 42, 1, 0, 0), payload, module._TARGET_SHA256)
        resumed = self._stat(stat.S_IFREG | 0o600, size=3)
        exact = self._stat(stat.S_IFREG | 0o644, size=6)

        with patch.object(module, "_source_bytes", return_value=payload), \
             patch.object(module, "_parent", return_value=50), \
             patch.object(module, "_installed", side_effect=(old, old, new)), \
             patch.object(module, "_temporary_state", side_effect=(("prefix", 3), ("exact", 6))), \
             patch.object(module.os, "open", return_value=60), \
             patch.object(module.os, "fstat", side_effect=(resumed, exact)), \
             patch.object(module.os, "lseek") as lseek, \
             patch.object(module, "_write_all") as write_all, \
             patch.object(module.os, "fsync"), \
             patch.object(module.os, "fchmod"), \
             patch.object(module.os, "replace"), \
             patch.object(module.os, "close"):
            evidence = module._replace_under_lock()

        self.assertEqual(evidence.operation, "replaced")
        lseek.assert_called_once_with(60, 3, os.SEEK_SET)
        write_all.assert_called_once_with(60, b"def")

    def test_already_replaced_is_idempotent_and_cleans_only_exact_stage(self):
        payload = b"new"
        current = ((0o100644, 17, 42, 1, 0, 0), payload, module._TARGET_SHA256)
        with patch.object(module, "_source_bytes", return_value=payload),              patch.object(module, "_parent", return_value=50),              patch.object(module, "_installed", return_value=current),              patch.object(module, "_temporary_state", return_value=("exact", len(payload))),              patch.object(module.os, "unlink") as unlink,              patch.object(module.os, "fsync") as fsync,              patch.object(module.os, "replace") as replace,              patch.object(module.os, "close"):
            evidence = module._replace_under_lock()

        self.assertEqual(evidence.operation, "already-replaced")
        unlink.assert_called_once_with(module._TEMPORARY, dir_fd=50)
        fsync.assert_called_once_with(50)
        replace.assert_not_called()

    def test_target_with_partial_stage_fails_closed(self):
        payload = b"new"
        current = ((0o100644, 17, 42, 1, 0, 0), payload, module._TARGET_SHA256)
        with patch.object(module, "_source_bytes", return_value=payload), \
             patch.object(module, "_parent", return_value=50), \
             patch.object(module, "_installed", return_value=current), \
             patch.object(module, "_temporary_state", return_value=("prefix", 1)), \
             patch.object(module.os, "replace") as replace, \
             patch.object(module.os, "unlink") as unlink, \
             patch.object(module.os, "close"), self.assertRaises(OSError):
            module._replace_under_lock()
        replace.assert_not_called()
        unlink.assert_not_called()

    def test_public_transition_requires_candidate_then_replacement_then_full_preflight(self):
        expected = module.RootlessDockerLauncherReplacementEvidence(
            "already-replaced",
            module._PREDECESSOR_SHA256,
            module._TARGET_SHA256,
            module._TARGET_SHA256,
        )
        green = SimpleNamespace(passed=True)
        events = []

        def candidate():
            events.append("candidate")
            return green

        def replace():
            events.append("replace")
            return expected

        def full():
            events.append("full")
            return green

        with patch.object(module, "_root_identity", return_value=(0, 0)), \
             patch.object(module.orchestration, "_acquire_process_lock", return_value=70) as acquire, \
             patch.object(
                 module.restart_preflight,
                 "preflight_rootless_docker_restart_candidate",
                 side_effect=candidate,
             ), \
             patch.object(module, "_replace_under_lock", side_effect=replace), \
             patch.object(
                 module.restart_preflight,
                 "preflight_rootless_docker_restart",
                 side_effect=full,
             ), \
             patch.object(module.orchestration, "_release_process_lock") as release:
            self.assertEqual(module.replace_rootless_docker_launcher(), expected)
        self.assertEqual(events, ["candidate", "replace", "full"])
        acquire.assert_called_once_with()
        release.assert_called_once_with(70)

    def test_candidate_failure_prevents_mutation_and_post_failure_prevents_success(self):
        red = SimpleNamespace(passed=False)
        green = SimpleNamespace(passed=True)
        expected = module.RootlessDockerLauncherReplacementEvidence(
            "replaced",
            module._PREDECESSOR_SHA256,
            module._TARGET_SHA256,
            module._TARGET_SHA256,
        )

        with patch.object(module, "_root_identity", return_value=(0, 0)), \
             patch.object(module.orchestration, "_acquire_process_lock", return_value=70), \
             patch.object(
                 module.restart_preflight,
                 "preflight_rootless_docker_restart_candidate",
                 return_value=red,
             ), \
             patch.object(module, "_replace_under_lock") as replace, \
             patch.object(module.orchestration, "_release_process_lock"), \
             self.assertRaises(module.RootlessDockerLauncherReplacementError):
            module.replace_rootless_docker_launcher()
        replace.assert_not_called()

        with patch.object(module, "_root_identity", return_value=(0, 0)), \
             patch.object(module.orchestration, "_acquire_process_lock", return_value=70), \
             patch.object(
                 module.restart_preflight,
                 "preflight_rootless_docker_restart_candidate",
                 return_value=green,
             ), \
             patch.object(module, "_replace_under_lock", return_value=expected) as replace, \
             patch.object(
                 module.restart_preflight,
                 "preflight_rootless_docker_restart",
                 return_value=red,
             ), \
             patch.object(module.orchestration, "_release_process_lock"), \
             self.assertRaises(module.RootlessDockerLauncherReplacementError):
            module.replace_rootless_docker_launcher()
        replace.assert_called_once_with()

        with patch.object(module, "_root_identity", side_effect=OSError("private")):
            with self.assertRaises(module.RootlessDockerLauncherReplacementError) as caught:
                module.replace_rootless_docker_launcher()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_source_has_no_service_docker_network_or_general_path_surface(self):
        source = (
            ROOT / "deployment/rootless_docker_launcher_replacement.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "systemctl",
            "loginctl",
            "subprocess",
            "socket.",
            "urllib",
            "requests",
            "http.client",
            "docker ",
            "dockerd",
            "execve",
            "shell=True",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertEqual(module._PARENT, "/opt/omnilyzer/deployment/rootless-docker")
        self.assertIn('".launch.py.c33k.tmp"', source)


if __name__ == "__main__":
    unittest.main()
