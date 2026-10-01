"""deployment/tests/test_rootless_docker_fresh_manager_transition.py - C33S tests.

Purpose:
- prove the fresh-manager transition is fail-closed and single-mutation;
- preserve C33R preflight authority and separate post-manager enabled semantics;
- prove PID turnover, stable Docker authority, and no automatic retry.

Links:
- deployment/rootless_docker_fresh_manager_transition.py is the C33S implementation.
- deployment/rootless_docker_fresh_manager_preflight.py supplies C33R preflight
  evidence used by the transition.
"""

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from deployment import rootless_docker_fresh_manager_transition as module
from deployment import rootless_docker_fresh_manager_preflight as c33q
from deployment.rootless_docker_authority import AUTHORITY
from deployment.rootless_docker_installation_authority import INSTALLATION_AUTHORITY


ROOT = Path(__file__).resolve().parents[2]


def green_preflight():
    """Build minimal green C33R evidence for transition-unit tests."""

    check = c33q.RootlessDockerFreshManagerPreflightCheck("all", True, None)
    return c33q.RootlessDockerFreshManagerPreflightEvidence((check,))


def candidate_snapshot():
    """Build the exact pre-recycle snapshot shape expected by C33S."""

    return c33q.RootlessDockerFreshManagerSnapshot(
        persistent_state="enabled",
        live_user_unit_state=module._BEFORE_UNIT_STATE,
        user_manager_state=module._USER_MANAGER_STATE,
        user_manager_pid=3000,
        user_runtime_state=module._USER_RUNTIME_STATE,
        linger_state=(
            "yes",
            AUTHORITY.runtime_directory,
            str(AUTHORITY.executor_uid),
            AUTHORITY.executor_user,
            "lingering",
            "",
            "",
        ),
        rootlesskit_pid=4000,
        dockerd_pid=4001,
        containerd_pid=4002,
        slirp4netns_pid=4003,
        containers=(0, 0, 0, 0),
        images=0,
    )


def lifecycle(
    *,
    unit_state=module._BEFORE_UNIT_STATE,
    manager_pid=3000,
    runtime_base=4000,
):
    """Build valid C33S lifecycle evidence with controllable volatile values."""

    runtime_pids = (
        ("rootlesskit", runtime_base),
        ("dockerd", runtime_base + 1),
        ("containerd", runtime_base + 2),
        ("slirp4netns", runtime_base + 3),
    )
    cgroup = module._CGROUP_ROOT
    cgroup_processes = (
        (manager_pid, cgroup + "/init.scope"),
        (runtime_base, cgroup + "/app.slice/omnilyzer-task014-rootless-docker.service"),
        (
            runtime_base + 1,
            cgroup + "/app.slice/omnilyzer-task014-rootless-docker.service",
        ),
        (
            runtime_base + 2,
            cgroup + "/app.slice/omnilyzer-task014-rootless-docker.service",
        ),
        (
            runtime_base + 3,
            cgroup + "/app.slice/omnilyzer-task014-rootless-docker.service",
        ),
    )
    return module.RootlessDockerFreshManagerLifecycleEvidence(
        persistent_state="enabled",
        enable_link=(module._ENABLE_LINK, AUTHORITY.user_unit, 0, 0, 0o777),
        user_manager_state=module._USER_MANAGER_STATE,
        user_manager_pid=manager_pid,
        user_runtime_state=module._USER_RUNTIME_STATE,
        linger_state=(
            "yes",
            AUTHORITY.runtime_directory,
            str(AUTHORITY.executor_uid),
            AUTHORITY.executor_user,
            "lingering",
            "",
            "",
        ),
        user_unit_state=unit_state,
        user_unit_fragment=AUTHORITY.user_unit,
        runtime_pids=runtime_pids,
        daemon_socket=(
            AUTHORITY.daemon_socket,
            AUTHORITY.executor_uid,
            AUTHORITY.executor_gid,
            AUTHORITY.daemon_socket_mode,
        ),
        rootlesskit_state=(
            AUTHORITY.rootlesskit_state,
            AUTHORITY.executor_uid,
            AUTHORITY.executor_gid,
            AUTHORITY.rootlesskit_state_mode,
        ),
        docker_info=(
            AUTHORITY.engine_version,
            "overlay2",
            AUTHORITY.data_root,
            "systemd",
            "2",
            ("name=cgroupns", "name=rootless"),
            (0, 0, 0, 0),
            0,
        ),
        masked_units=INSTALLATION_AUTHORITY.rootful_units,
        inactive_deployment_units=module.c33f._DEPLOYMENT_UNITS,
        cgroup_processes=cgroup_processes,
    )


class RootlessDockerFreshManagerTransitionTests(unittest.TestCase):
    """Exercise all C33S security and lifecycle invariants without live mutation."""

    def test_lifecycle_evidence_is_exact_and_immutable(self):
        """Reject malformed lifecycle evidence and preserve frozen evidence."""

        value = lifecycle()
        with self.assertRaises(FrozenInstanceError):
            value.user_manager_pid = 1

        for change in (
            {"persistent_state": "disabled"},
            {"user_manager_pid": 1},
            {"user_unit_state": ("loaded", "active", "running", "static")},
            {"runtime_pids": value.runtime_pids[:-1]},
            {"docker_info": value.docker_info[:-2] + ((1, 1, 0, 0), 0)},
            {"masked_units": ()},
            {"inactive_deployment_units": ()},
            {"cgroup_processes": ((3000, "/system.slice/escape.service"),)},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.RootlessDockerFreshManagerLifecycleEvidence(
                    **{
                        name: change.get(name, getattr(value, name))
                        for name in value.__dataclass_fields__
                    }
                )

    def test_transition_evidence_requires_exact_turnover(self):
        """Require enabled post-state, new manager PID, four new Docker PIDs, and stable authority."""

        before = lifecycle()
        after = lifecycle(
            unit_state=module._AFTER_UNIT_STATE,
            manager_pid=5000,
            runtime_base=6000,
        )
        value = module.RootlessDockerFreshManagerTransitionEvidence(
            operation="recycled",
            restart_command=module._RESTART_COMMAND,
            preflight_checks=("all",),
            before=before,
            after=after,
            daemon_signature_equal=True,
        )
        self.assertEqual(value.before.user_unit_state, module._BEFORE_UNIT_STATE)
        self.assertEqual(value.after.user_unit_state, module._AFTER_UNIT_STATE)

        with self.assertRaises(ValueError):
            replace(value, after=replace(after, user_manager_pid=before.user_manager_pid))
        with self.assertRaises(ValueError):
            replace(value, after=lifecycle(
                unit_state=module._AFTER_UNIT_STATE,
                manager_pid=5000,
                runtime_base=4000,
            ))
        with self.assertRaises(ValueError):
            replace(value, daemon_signature_equal=False)

    def test_user_unit_evidence_separates_before_and_after_semantics(self):
        """Accept disabled only before recycle and enabled only after recycle."""

        def reader_factory(state):
            values = {
                "LoadState": state[0],
                "ActiveState": state[1],
                "SubState": state[2],
                "UnitFileState": state[3],
                "FragmentPath": AUTHORITY.user_unit_fragment_alias,
                "MainPID": "4000",
            }
            return lambda prop: values[prop]

        for state in (module._BEFORE_UNIT_STATE, module._AFTER_UNIT_STATE):
            with self.subTest(state=state), patch.object(
                module.c33f,
                "_read_user_systemctl",
                side_effect=reader_factory(state),
            ), patch.object(
                module.c33f,
                "_canonical_user_unit_fragment",
                return_value=AUTHORITY.user_unit,
            ), patch.object(
                module.persistence,
                "_global_enable_evidence",
                return_value="enabled",
            ), patch.object(
                module.persistence,
                "_enable_link_evidence",
                return_value=(module._ENABLE_LINK, AUTHORITY.user_unit, 0, 0, 0o777),
            ):
                observed = module._user_unit_evidence(state)
            self.assertEqual(observed, (state, AUTHORITY.user_unit, 4000))

        with self.assertRaises(OSError):
            module._user_unit_evidence(("loaded", "inactive", "dead", "enabled"))

    def test_runtime_pids_are_exact_unique_and_bound_to_rootlesskit(self):
        """Collect one exact four-process runtime and reject multiplicity."""

        with patch.object(
            module.c33f,
            "_process_evidence",
            return_value=(4000, ("rootlesskit",), 4001, ("dockerd",)),
        ), patch.object(
            module.c33f,
            "_pids",
            side_effect=lambda name: {
                "containerd": (4002,),
                "slirp4netns": (4003,),
            }[name],
        ):
            self.assertEqual(
                module._runtime_pids(4000),
                (
                    ("rootlesskit", 4000),
                    ("dockerd", 4001),
                    ("containerd", 4002),
                    ("slirp4netns", 4003),
                ),
            )

        with patch.object(
            module.c33f,
            "_process_evidence",
            return_value=(4000, ("rootlesskit",), 4001, ("dockerd",)),
        ), patch.object(
            module.c33f,
            "_pids",
            side_effect=lambda name: {
                "containerd": (4002, 4999),
                "slirp4netns": (4003,),
            }[name],
        ), self.assertRaises(OSError):
            module._runtime_pids(4000)

    def test_stable_lifecycle_requires_two_identical_observations(self):
        """Reject any read-only lifecycle drift between consecutive observations."""

        before = lifecycle()
        with patch.object(
            module,
            "_lifecycle_once",
            side_effect=(before, before),
        ) as observe:
            self.assertEqual(
                module._stable_lifecycle(module._BEFORE_UNIT_STATE),
                before,
            )
        self.assertEqual(observe.call_count, 2)

        changed = lifecycle(manager_pid=3001, runtime_base=4000)
        with patch.object(
            module,
            "_lifecycle_once",
            side_effect=(before, changed),
        ), self.assertRaises(OSError):
            module._stable_lifecycle(module._BEFORE_UNIT_STATE)

        contained_churn = replace(
            before,
            cgroup_processes=before.cgroup_processes
            + ((7999, module._CGROUP_ROOT + "/session.slice/transient.service"),),
        )
        with patch.object(
            module,
            "_lifecycle_once",
            side_effect=(before, contained_churn),
        ):
            self.assertEqual(
                module._stable_lifecycle(module._BEFORE_UNIT_STATE),
                contained_churn,
            )

    def test_post_qualification_uses_enabled_semantics_and_generic_failure(self):
        """Expose enabled fresh-manager state and hide internal qualification errors."""

        after = lifecycle(
            unit_state=module._AFTER_UNIT_STATE,
            manager_pid=5000,
            runtime_base=6000,
        )
        with patch.object(
            module,
            "_stable_lifecycle",
            return_value=after,
        ) as stable:
            self.assertEqual(
                module.qualify_rootless_docker_fresh_manager_post(),
                after,
            )
        stable.assert_called_once_with(module._AFTER_UNIT_STATE)

        with patch.object(
            module,
            "_stable_lifecycle",
            side_effect=OSError("private"),
        ):
            with self.assertRaises(
                module.RootlessDockerFreshManagerPostQualificationError
            ) as caught:
                module.qualify_rootless_docker_fresh_manager_post()
        self.assertEqual(str(caught.exception), module._POST_ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_restart_command_is_exact_and_closed(self):
        """Pin the only mutation to one system-manager restart command."""

        completed = subprocess.CompletedProcess((), 0, b"", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            module._run_user_manager_restart()

        self.assertEqual(
            run.call_args.args[0],
            ("/usr/bin/systemctl", "restart", "user@991.service"),
        )
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.PIPE)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 120.0)
        self.assertEqual(
            run.call_args.kwargs["env"],
            {
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "HOME": "/root",
            },
        )

        for completed in (
            subprocess.CompletedProcess((), 1, b"", b"failed"),
            subprocess.CompletedProcess(
                (), 0, b"x" * (module._OUTPUT_LIMIT + 1), b""
            ),
            subprocess.CompletedProcess(
                (), 0, b"", b"x" * (module._OUTPUT_LIMIT + 1)
            ),
        ):
            with self.subTest(completed=completed), patch.object(
                module.subprocess,
                "run",
                return_value=completed,
            ), self.assertRaises(OSError):
                module._run_user_manager_restart()

    def test_transition_rechecks_preflight_then_mutates_once_then_qualifies(self):
        """Require exhaustive pre-state immediately before the single mutation."""

        before = lifecycle()
        after = lifecycle(
            unit_state=module._AFTER_UNIT_STATE,
            manager_pid=5000,
            runtime_base=6000,
        )
        snapshot = candidate_snapshot()
        events = []

        with patch.object(
            module,
            "_require_green_preflight",
            side_effect=lambda: events.append("preflight") or green_preflight(),
        ), patch.object(
            module.c33q,
            "snapshot_rootless_docker_fresh_manager_candidate",
            side_effect=lambda: events.append("snapshot") or snapshot,
        ), patch.object(
            module,
            "_stable_lifecycle",
            side_effect=lambda state: events.append(("lifecycle", state)) or before,
        ), patch.object(
            module,
            "_require_preflight_snapshot_match",
            side_effect=lambda *_args: events.append("bind"),
        ), patch.object(
            module,
            "_run_user_manager_restart",
            side_effect=lambda: events.append("restart"),
        ) as restart, patch.object(
            module,
            "qualify_rootless_docker_fresh_manager_post",
            side_effect=lambda: events.append("post") or after,
        ):
            result = module._transition_under_lock()

        self.assertEqual(
            events,
            [
                "preflight",
                "snapshot",
                ("lifecycle", module._BEFORE_UNIT_STATE),
                "bind",
                "restart",
                "post",
            ],
        )
        restart.assert_called_once_with()
        self.assertEqual(result.operation, "recycled")
        self.assertEqual(result.before, before)
        self.assertEqual(result.after, after)
        self.assertTrue(result.daemon_signature_equal)

    def test_preflight_or_postflight_failure_never_retries_mutation(self):
        """Prevent mutation on red preflight and prevent second restart after post failure."""

        red = c33q.RootlessDockerFreshManagerPreflightEvidence(
            (c33q.RootlessDockerFreshManagerPreflightCheck("blocked", False, "OSError"),)
        )
        with patch.object(
            module.c33q,
            "preflight_rootless_docker_fresh_manager",
            return_value=red,
        ), patch.object(
            module,
            "_run_user_manager_restart",
        ) as restart, self.assertRaises(OSError):
            module._transition_under_lock()
        restart.assert_not_called()

        before = lifecycle()
        snapshot = candidate_snapshot()
        with patch.object(
            module,
            "_require_green_preflight",
            return_value=green_preflight(),
        ), patch.object(
            module.c33q,
            "snapshot_rootless_docker_fresh_manager_candidate",
            return_value=snapshot,
        ), patch.object(
            module,
            "_stable_lifecycle",
            return_value=before,
        ), patch.object(
            module,
            "_require_preflight_snapshot_match",
        ), patch.object(
            module,
            "_run_user_manager_restart",
        ) as restart, patch.object(
            module,
            "qualify_rootless_docker_fresh_manager_post",
            side_effect=module.RootlessDockerFreshManagerPostQualificationError(
                module._POST_ERROR
            ),
        ), self.assertRaises(
            module.RootlessDockerFreshManagerPostQualificationError
        ):
            module._transition_under_lock()
        restart.assert_called_once_with()

    def test_pid_reuse_or_signature_drift_fails_without_second_restart(self):
        """Reject incomplete turnover or stable-authority drift after exactly one mutation."""

        before = lifecycle()
        snapshot = candidate_snapshot()
        reused = lifecycle(
            unit_state=module._AFTER_UNIT_STATE,
            manager_pid=5000,
            runtime_base=4000,
        )
        with patch.object(
            module,
            "_require_green_preflight",
            return_value=green_preflight(),
        ), patch.object(
            module.c33q,
            "snapshot_rootless_docker_fresh_manager_candidate",
            return_value=snapshot,
        ), patch.object(
            module,
            "_stable_lifecycle",
            return_value=before,
        ), patch.object(
            module,
            "_require_preflight_snapshot_match",
        ), patch.object(
            module,
            "_run_user_manager_restart",
        ) as restart, patch.object(
            module,
            "qualify_rootless_docker_fresh_manager_post",
            return_value=reused,
        ), self.assertRaises(OSError):
            module._transition_under_lock()
        restart.assert_called_once_with()

        after = lifecycle(
            unit_state=module._AFTER_UNIT_STATE,
            manager_pid=5000,
            runtime_base=6000,
        )
        drifted_info = list(after.docker_info)
        drifted_info[5] = tuple(sorted((*drifted_info[5], "name=extra")))
        drifted = replace(after, docker_info=tuple(drifted_info))
        with patch.object(
            module,
            "_require_green_preflight",
            return_value=green_preflight(),
        ), patch.object(
            module.c33q,
            "snapshot_rootless_docker_fresh_manager_candidate",
            return_value=snapshot,
        ), patch.object(
            module,
            "_stable_lifecycle",
            return_value=before,
        ), patch.object(
            module,
            "_require_preflight_snapshot_match",
        ), patch.object(
            module,
            "_run_user_manager_restart",
        ) as restart, patch.object(
            module,
            "qualify_rootless_docker_fresh_manager_post",
            return_value=drifted,
        ), self.assertRaises(OSError):
            module._transition_under_lock()
        restart.assert_called_once_with()

    def test_public_transition_is_root_locked_and_generic_on_failure(self):
        """Serialize C33S under the root lock and expose no private error detail."""

        before = lifecycle()
        after = lifecycle(
            unit_state=module._AFTER_UNIT_STATE,
            manager_pid=5000,
            runtime_base=6000,
        )
        expected = module.RootlessDockerFreshManagerTransitionEvidence(
            operation="recycled",
            restart_command=module._RESTART_COMMAND,
            preflight_checks=("all",),
            before=before,
            after=after,
            daemon_signature_equal=True,
        )
        with patch.object(
            module,
            "_root_identity",
            return_value=(0, 0),
        ), patch.object(
            module.orchestration,
            "_acquire_process_lock",
            return_value=70,
        ) as acquire, patch.object(
            module,
            "_transition_under_lock",
            return_value=expected,
        ), patch.object(
            module.orchestration,
            "_release_process_lock",
        ) as release:
            self.assertEqual(module.recycle_rootless_docker_user_manager(), expected)
        acquire.assert_called_once_with()
        release.assert_called_once_with(70)

        with patch.object(module, "_root_identity", side_effect=OSError("private")):
            with self.assertRaises(
                module.RootlessDockerFreshManagerTransitionError
            ) as caught:
                module.recycle_rootless_docker_user_manager()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))


    def test_uid_process_boundary_prefilters_other_users_and_rejects_escape(self):
        """Ignore other UIDs but fail closed if any UID-991 process escapes its cgroup."""

        entries = tuple(
            type("E", (), {"name": str(pid)})()
            for pid in (3000, 4000, 4001, 4002, 4003, 9000)
        )
        paths = {
            3000: module._CGROUP_ROOT + "/init.scope",
            4000: module._CGROUP_ROOT + "/app.slice/rootless.service",
            4001: module._CGROUP_ROOT + "/app.slice/rootless.service",
            4002: module._CGROUP_ROOT + "/app.slice/rootless.service",
            4003: module._CGROUP_ROOT + "/app.slice/rootless.service",
        }
        runtime = lifecycle().runtime_pids
        with patch.object(module.os, "scandir", return_value=entries), patch.object(
            module.c33f,
            "_proc_dir_uid",
            side_effect=lambda pid: 0 if pid == 9000 else AUTHORITY.executor_uid,
        ), patch.object(
            module.c33q,
            "_read_cgroup",
            side_effect=lambda pid: paths[pid],
        ) as cgroup:
            observed = module._uid_process_cgroup_boundary(3000, runtime)

        self.assertEqual(
            {pid for pid, _path in observed},
            {3000, 4000, 4001, 4002, 4003},
        )
        self.assertNotIn(unittest.mock.call(9000), cgroup.call_args_list)

        paths[4002] = "/system.slice/escape.service"
        with patch.object(
            module.os,
            "scandir",
            return_value=entries[:-1],
        ), patch.object(
            module.c33f,
            "_proc_dir_uid",
            return_value=AUTHORITY.executor_uid,
        ), patch.object(
            module.c33q,
            "_read_cgroup",
            side_effect=lambda pid: paths[pid],
        ), self.assertRaises(OSError):
            module._uid_process_cgroup_boundary(3000, runtime)

    def test_preflight_snapshot_binding_rejects_any_immediate_drift(self):
        """Prevent state changes between the exhaustive C33R gate and mutation."""

        snapshot = candidate_snapshot()
        before = lifecycle()
        module._require_preflight_snapshot_match(snapshot, before)

        with self.assertRaises(OSError):
            module._require_preflight_snapshot_match(
                replace(snapshot, dockerd_pid=4999),
                before,
            )

    def test_deployment_units_must_remain_inactive(self):
        """Reject any broker/executor surface that becomes active."""

        with patch.object(
            module.c33f.userq,
            "_read_systemctl",
            return_value="inactive",
        ):
            self.assertEqual(
                module._deployment_inactive_evidence(),
                module.c33f._DEPLOYMENT_UNITS,
            )

        with patch.object(
            module.c33f.userq,
            "_read_systemctl",
            side_effect=lambda unit, _prop: (
                "active"
                if unit == module.c33f._DEPLOYMENT_UNITS[0]
                else "inactive"
            ),
        ), self.assertRaises(OSError):
            module._deployment_inactive_evidence()

    def test_source_contains_only_the_pinned_manager_restart_surface(self):
        """Keep C33S free of alternative service/deployment mutation commands."""

        source = (
            ROOT / "deployment/rootless_docker_fresh_manager_transition.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '_RESTART_COMMAND = (_SYSTEMCTL, "restart", _USER_MANAGER)',
            source,
        )
        self.assertEqual(source.count("subprocess.run("), 1)
        for forbidden in (
            '"daemon-reload"',
            '"enable-now"',
            '"terminate-user"',
            "docker run",
            "docker pull",
            "docker build",
            "docker compose",
            "os.unlink",
            "os.replace",
            "os.chmod",
            "os.chown",
            "os.mkdir",
            "shell=True",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
