"""Tests for C33N/C33O rootless Docker persistence lifecycle authority."""

from dataclasses import FrozenInstanceError, replace
import stat
import subprocess
import unittest
from unittest.mock import patch

from deployment import rootless_docker_persistence_enablement as module
from deployment.tests.test_rootless_docker_daemon_qualification import (
    evidence as daemon_evidence,
)


def link_stat():
    return type(
        "S",
        (),
        {
            "st_mode": stat.S_IFLNK | 0o777,
            "st_uid": 0,
            "st_gid": 0,
            "st_nlink": 1,
        },
    )()


def persistence_state(daemon=None):
    return module.RootlessDockerPersistenceStateEvidence(
        persistent_state="enabled",
        enable_link=(
            module._ENABLE_LINK,
            module.AUTHORITY.user_unit,
            0,
            0,
            0o777,
        ),
        daemon=daemon or daemon_evidence(),
    )


def transition_evidence():
    before = daemon_evidence()
    return module.RootlessDockerPersistenceEnablementEvidence(
        operation="enabled",
        persistent_state="enabled",
        enable_link=(
            module._ENABLE_LINK,
            module.AUTHORITY.user_unit,
            0,
            0,
            0o777,
        ),
        before_unit_state=before.user_unit_state,
        after_unit_state=before.user_unit_state,
        before_pids=(before.rootlesskit_pid, before.dockerd_pid),
        after_pids=(before.rootlesskit_pid, before.dockerd_pid),
        daemon_signature_equal=True,
        containers=before.containers,
        images=before.images,
    )


class RootlessDockerPersistenceEnablementTests(unittest.TestCase):
    def test_state_evidence_models_enabled_disk_and_unchanged_live_manager(self):
        value = persistence_state()
        self.assertEqual(value.persistent_state, "enabled")
        self.assertEqual(
            value.daemon.user_unit_state,
            ("loaded", "active", "running", "disabled"),
        )
        with self.assertRaises(FrozenInstanceError):
            value.persistent_state = "disabled"

        with self.assertRaises(ValueError):
            persistence_state(
                replace(
                    daemon_evidence(),
                    user_unit_state=("loaded", "active", "running", "enabled"),
                )
            )

    def test_transition_evidence_requires_same_live_state_and_pids(self):
        value = transition_evidence()
        self.assertEqual(value.before_unit_state, value.after_unit_state)
        self.assertEqual(value.before_pids, value.after_pids)

        values = {
            name: getattr(value, name)
            for name in value.__dataclass_fields__
        }
        for change in (
            {"persistent_state": "disabled"},
            {"after_unit_state": ("loaded", "active", "running", "enabled")},
            {"after_pids": (5000, 5001)},
            {"daemon_signature_equal": False},
            {"containers": (1, 1, 0, 0)},
            {"images": 1},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.RootlessDockerPersistenceEnablementEvidence(
                    **(values | change)
                )

    def test_enable_command_is_global_exact_and_never_now(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            module._run_enable()

        self.assertEqual(
            run.call_args.args[0],
            (
                "/usr/bin/systemctl",
                "--global",
                "enable",
                "omnilyzer-task014-rootless-docker.service",
            ),
        )
        self.assertNotIn("--now", run.call_args.args[0])
        self.assertNotIn("start", run.call_args.args[0])
        self.assertNotIn("restart", run.call_args.args[0])

    def test_global_enable_evidence_is_exact_and_read_only(self):
        completed = subprocess.CompletedProcess((), 0, b"enabled\n", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            self.assertEqual(module._global_enable_evidence(), "enabled")
        self.assertEqual(
            run.call_args.args[0],
            (
                "/usr/bin/systemctl",
                "--global",
                "is-enabled",
                "omnilyzer-task014-rootless-docker.service",
            ),
        )

        for bad in (
            subprocess.CompletedProcess((), 1, b"disabled\n", b""),
            subprocess.CompletedProcess((), 0, b"enabled-runtime\n", b""),
        ):
            with self.subTest(bad=bad), patch.object(
                module.subprocess, "run", return_value=bad
            ), self.assertRaises(OSError):
                module._global_enable_evidence()

    def test_enable_link_requires_exact_global_symlink(self):
        with patch.object(module.os, "lstat", return_value=link_stat()), patch.object(
            module.os,
            "readlink",
            return_value=module.AUTHORITY.user_unit,
        ):
            self.assertEqual(
                module._enable_link_evidence(),
                (
                    module._ENABLE_LINK,
                    module.AUTHORITY.user_unit,
                    0,
                    0,
                    0o777,
                ),
            )

        bad = link_stat()
        bad.st_uid = 991
        with patch.object(module.os, "lstat", return_value=bad), patch.object(
            module.os,
            "readlink",
            return_value=module.AUTHORITY.user_unit,
        ), self.assertRaises(OSError):
            module._enable_link_evidence()

    def test_post_enable_user_unit_requires_live_manager_unchanged(self):
        values = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "UnitFileState": "disabled",
            "FragmentPath": module.AUTHORITY.user_unit,
            "MainPID": "4000",
        }
        with patch.object(
            module.c33f,
            "_read_user_systemctl",
            side_effect=lambda name: values[name],
        ), patch.object(
            module.c33f,
            "_canonical_user_unit_fragment",
            side_effect=lambda value: value,
        ), patch.object(module, "_enable_link_evidence"), patch.object(
            module, "_global_enable_evidence", return_value="enabled"
        ):
            self.assertEqual(
                module._post_enable_user_unit_evidence(),
                (
                    ("loaded", "active", "running", "disabled"),
                    module.AUTHORITY.user_unit,
                    4000,
                ),
            )

        values["UnitFileState"] = "enabled"
        with patch.object(
            module.c33f,
            "_read_user_systemctl",
            side_effect=lambda name: values[name],
        ), patch.object(
            module.c33f,
            "_canonical_user_unit_fragment",
            side_effect=lambda value: value,
        ), patch.object(module, "_enable_link_evidence"), patch.object(
            module, "_global_enable_evidence", return_value="enabled"
        ), self.assertRaises(OSError):
            module._post_enable_user_unit_evidence()

    def test_persistence_qualification_reuses_full_c33f_with_lifecycle_unit_evidence(self):
        daemon = daemon_evidence()
        link = (
            module._ENABLE_LINK,
            module.AUTHORITY.user_unit,
            0,
            0,
            0o777,
        )
        with patch.object(
            module, "_global_enable_evidence", return_value="enabled"
        ), patch.object(
            module, "_enable_link_evidence", return_value=link
        ), patch.object(
            module.c33f,
            "_qualify_once_with_user_unit",
            return_value=daemon,
        ) as qualify:
            result = module._qualify_persistence_once()

        self.assertEqual(result, persistence_state(daemon))
        qualify.assert_called_once_with(module._post_enable_user_unit_evidence)

    def test_public_persistence_qualification_requires_two_identical_observations(self):
        first = persistence_state()
        with patch.object(
            module, "_qualify_persistence_once", side_effect=(first, first)
        ) as once:
            self.assertEqual(
                module.qualify_rootless_docker_persistence(),
                first,
            )
        self.assertEqual(once.call_count, 2)

        changed = persistence_state(
            replace(daemon_evidence(), expected_workflow_sha="b" * 40)
        )
        with patch.object(
            module,
            "_qualify_persistence_once",
            side_effect=(first, changed),
        ), self.assertRaises(module.RootlessDockerPersistenceQualificationError):
            module.qualify_rootless_docker_persistence()

    def test_post_enable_matches_requires_full_daemon_equality(self):
        before = daemon_evidence()
        state = persistence_state(before)
        with patch.object(
            module,
            "qualify_rootless_docker_persistence",
            return_value=state,
        ):
            self.assertEqual(
                module._post_enable_matches(before),
                (
                    before.user_unit_state,
                    (before.rootlesskit_pid, before.dockerd_pid),
                    state.enable_link,
                    "enabled",
                ),
            )

        drift = persistence_state(
            replace(before, expected_workflow_sha="b" * 40)
        )
        with patch.object(
            module,
            "qualify_rootless_docker_persistence",
            return_value=drift,
        ), self.assertRaises(OSError):
            module._post_enable_matches(before)

    def test_enable_under_lock_runs_c33f_then_one_enable_then_postcheck(self):
        before = daemon_evidence()
        state = persistence_state(before)
        events = []

        with patch.object(
            module.c33f,
            "qualify_rootless_docker_daemon",
            side_effect=lambda: events.append("c33f") or before,
        ), patch.object(
            module,
            "_run_enable",
            side_effect=lambda: events.append("enable"),
        ), patch.object(
            module,
            "_post_enable_matches",
            side_effect=lambda _before: events.append("post") or (
                before.user_unit_state,
                (before.rootlesskit_pid, before.dockerd_pid),
                state.enable_link,
                "enabled",
            ),
        ):
            result = module._enable_under_lock()

        self.assertEqual(events, ["c33f", "enable", "post"])
        self.assertEqual(result, transition_evidence())

    def test_public_transition_is_root_locked_and_generic_on_failure(self):
        expected = transition_evidence()
        with patch.object(module, "_root_identity", return_value=(0, 0)), patch.object(
            module.orchestration,
            "_acquire_process_lock",
            return_value=70,
        ) as acquire, patch.object(
            module,
            "_enable_under_lock",
            return_value=expected,
        ), patch.object(
            module.orchestration,
            "_release_process_lock",
        ) as release:
            self.assertEqual(
                module.enable_rootless_docker_persistence(),
                expected,
            )
        acquire.assert_called_once_with()
        release.assert_called_once_with(70)

        with patch.object(module, "_root_identity", side_effect=OSError("private")):
            with self.assertRaises(
                module.RootlessDockerPersistenceEnablementError
            ) as caught:
                module.enable_rootless_docker_persistence()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
