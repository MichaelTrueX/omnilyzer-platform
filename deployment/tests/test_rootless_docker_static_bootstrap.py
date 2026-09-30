"""Tests for C32ZZ static rootless Docker host bootstrap."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import call, patch

from deployment import rootless_docker_static_bootstrap as module
from deployment.rootless_docker_authority import AUTHORITY
from deployment.rootless_docker_installation_authority import INSTALLATION_AUTHORITY


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40


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


def bundle():
    return SimpleNamespace(
        files=tuple(
            SimpleNamespace(sha256=item.sha256)
            for item in INSTALLATION_AUTHORITY.payloads
        )
    )


def static_host():
    return (
        WORKFLOW,
        (992,),
        tuple(
            (item.package, "9.9-test", item.architecture)
            for item in INSTALLATION_AUTHORITY.host_dependencies
        ),
        package_rows(),
        ("cpu", "memory", "pids"),
        (("docker-ce", "/usr/bin/dockerd", 0o755, "b" * 64),),
        bundle(),
    )


def final_evidence(operation="bootstrapped"):
    return module.RootlessDockerStaticBootstrapEvidence(
        operation,
        WORKFLOW,
        (AUTHORITY.executor_user, AUTHORITY.subuid_start, AUTHORITY.subordinate_count),
        (AUTHORITY.executor_user, AUTHORITY.subgid_start, AUTHORITY.subordinate_count),
        AUTHORITY.provisioned_directories,
        tuple(
            (destination, digest, uid, gid, mode)
            for _source, destination, digest, uid, gid, mode
            in AUTHORITY.installed_assets
        ),
        INSTALLATION_AUTHORITY.rootful_units,
        package_rows(),
        tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads),
    )


class RootlessDockerStaticBootstrapTests(unittest.TestCase):
    def test_evidence_is_exact_and_immutable(self):
        value = final_evidence()
        with self.assertRaises(FrozenInstanceError):
            value.operation = "resumed"
        with self.assertRaises(ValueError):
            module.RootlessDockerStaticBootstrapEvidence(
                "other",
                value.expected_workflow_sha,
                value.subuid,
                value.subgid,
                value.directories,
                value.assets,
                value.masked_units,
                value.packages,
                value.bundle_sha256s,
            )
        with self.assertRaises(ValueError):
            module.RootlessDockerStaticBootstrapEvidence(
                value.operation,
                value.expected_workflow_sha,
                ("wrong", AUTHORITY.subuid_start, AUTHORITY.subordinate_count),
                value.subgid,
                value.directories,
                value.assets,
                value.masked_units,
                value.packages,
                value.bundle_sha256s,
            )

    def test_phase_accepts_only_absent_exact_and_supports_resume(self):
        absent_dirs = ("absent",) * len(AUTHORITY.provisioned_directories)
        absent_assets = ("absent",) * len(AUTHORITY.installed_assets)
        exact_dirs = ("exact",) * len(AUTHORITY.provisioned_directories)
        exact_assets = ("exact",) * len(AUTHORITY.installed_assets)
        self.assertEqual(
            module._phase(("absent", "absent", absent_dirs, absent_assets)),
            "initial",
        )
        self.assertEqual(
            module._phase(("exact", "exact", exact_dirs, exact_assets)),
            "complete",
        )
        self.assertEqual(
            module._phase(("exact", "absent", absent_dirs, absent_assets)),
            "resume",
        )
        with self.assertRaises(OSError):
            module._phase(("wrong", "absent", absent_dirs, absent_assets))

    def test_subid_state_accepts_only_absent_or_exact_target(self):
        base = (
            ("omnigpt", 427680, 65536),
            ("trust", 165536, 65536),
        )
        with patch.object(module.preinstall, "_subid_records", return_value=base):
            self.assertEqual(module._subid_state(module._SUBUID), "absent")
            self.assertEqual(module._subid_state(module._SUBGID), "absent")

        exact = base + (
            (AUTHORITY.executor_user, AUTHORITY.subuid_start, AUTHORITY.subordinate_count),
        )
        with patch.object(module.preinstall, "_subid_records", return_value=exact):
            self.assertEqual(module._subid_state(module._SUBUID), "exact")

        wrong = base + ((AUTHORITY.executor_user, 600000, 65536),)
        with patch.object(module.preinstall, "_subid_records", return_value=wrong), self.assertRaises(OSError):
            module._subid_state(module._SUBUID)

        overlap = base + (("other", AUTHORITY.subuid_start + 100, 100),)
        with patch.object(module.preinstall, "_subid_records", return_value=overlap), self.assertRaises(OSError):
            module._subid_state(module._SUBUID)

    def test_ensure_subids_mutates_only_missing_exact_ranges(self):
        states = {
            module._SUBUID: ["absent", "exact"],
            module._SUBGID: ["exact"],
        }

        def state(path):
            return states[path].pop(0)

        completed = subprocess.CompletedProcess((), 0, b"", b"")
        with patch.object(module, "_subid_state", side_effect=state), \
             patch.object(module, "_run", return_value=completed) as run, \
             patch.object(module.preinstall, "_require_executor_identity", return_value=(992,)):
            self.assertEqual(module._ensure_subids(), ("exact", "exact"))

        run.assert_called_once_with(
            (
                module._USERMOD,
                "--add-subuids",
                module._SUBID_RANGE,
                AUTHORITY.executor_user,
            )
        )

    def test_mutation_runner_allows_only_usermod_ranges_and_daemon_reload(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        allowed = (
            (module._SYSTEMCTL, "daemon-reload"),
            (
                module._USERMOD,
                "--add-subuids",
                module._SUBID_RANGE,
                AUTHORITY.executor_user,
            ),
            (
                module._USERMOD,
                "--add-subgids",
                module._SUBID_RANGE,
                AUTHORITY.executor_user,
            ),
        )
        for argv in allowed:
            with self.subTest(argv=argv), patch.object(
                module.subprocess, "run", return_value=completed
            ) as run:
                self.assertIs(module._run(argv), completed)
                self.assertFalse(run.call_args.kwargs["shell"])
                self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

        for argv in (
            (module._SYSTEMCTL, "start", "user@991.service"),
            (module._SYSTEMCTL, "enable", "anything"),
            (module._USERMOD, "--add-subuids", "1-2", AUTHORITY.executor_user),
            ("/usr/bin/loginctl", "enable-linger", AUTHORITY.executor_user),
            ("/usr/bin/docker", "info"),
        ):
            with self.subTest(argv=argv), patch.object(module.subprocess, "run") as run, self.assertRaises(OSError):
                module._run(argv)
            run.assert_not_called()

    def test_initial_bootstrap_consumes_c32zx_before_any_mutation(self):
        absent_dirs = ("absent",) * len(AUTHORITY.provisioned_directories)
        absent_assets = ("absent",) * len(AUTHORITY.installed_assets)
        exact_dirs = ("exact",) * len(AUTHORITY.provisioned_directories)
        exact_assets = ("exact",) * len(AUTHORITY.installed_assets)
        before = SimpleNamespace(
            expected_workflow_sha=WORKFLOW,
            supplementary_gids=(992,),
            host_dependencies=static_host()[2],
            packages=static_host()[3],
            cgroup_controllers=static_host()[4],
            critical_executables=static_host()[5],
            bundle=static_host()[6],
        )
        events = []

        def mark(name, result=None):
            def inner(*args, **kwargs):
                events.append(name)
                return result
            return inner

        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(
                 module,
                 "_bootstrap_state",
                 side_effect=(
                     ("absent", "absent", absent_dirs, absent_assets),
                     ("exact", "exact", exact_dirs, exact_assets),
                 ),
             ), \
             patch.object(
                 module.postinstall,
                 "qualify_rootless_docker_postinstall",
                 side_effect=mark("c32zx", before),
             ), \
             patch.object(module, "_ensure_subids", side_effect=mark("subids", ("exact", "exact"))), \
             patch.object(module, "_install_static_assets", side_effect=mark("assets")), \
             patch.object(
                 module,
                 "_run",
                 side_effect=mark(
                     "daemon-reload",
                     subprocess.CompletedProcess((), 0, b"", b""),
                 ),
             ), \
             patch.object(module, "_require_directory_contents"), \
             patch.object(module, "_require_systemd_assets_visible"), \
             patch.object(module, "_static_package_host", return_value=static_host()):
            value = module._bootstrap_under_lock()

        self.assertEqual(value.operation, "bootstrapped")
        self.assertLess(events.index("c32zx"), events.index("subids"))
        self.assertLess(events.index("subids"), events.index("assets"))
        self.assertLess(events.index("assets"), events.index("daemon-reload"))

    def test_resume_does_not_reuse_c32zx(self):
        absent_dirs = ("absent",) * len(AUTHORITY.provisioned_directories)
        absent_assets = ("absent",) * len(AUTHORITY.installed_assets)
        exact_dirs = ("exact",) * len(AUTHORITY.provisioned_directories)
        exact_assets = ("exact",) * len(AUTHORITY.installed_assets)

        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(
                 module,
                 "_bootstrap_state",
                 side_effect=(
                     ("exact", "absent", absent_dirs, absent_assets),
                     ("exact", "exact", exact_dirs, exact_assets),
                 ),
             ), \
             patch.object(module, "_static_package_host", return_value=static_host()), \
             patch.object(
                 module.postinstall, "qualify_rootless_docker_postinstall"
             ) as c32zx, \
             patch.object(module, "_ensure_subids", return_value=("exact", "exact")), \
             patch.object(module, "_install_static_assets"), \
             patch.object(
                 module,
                 "_run",
                 return_value=subprocess.CompletedProcess((), 0, b"", b""),
             ), \
             patch.object(module, "_require_directory_contents"), \
             patch.object(module, "_require_systemd_assets_visible"):
            value = module._bootstrap_under_lock()

        self.assertEqual(value.operation, "resumed")
        c32zx.assert_not_called()

    def test_complete_state_is_idempotent_without_mutation(self):
        exact_dirs = ("exact",) * len(AUTHORITY.provisioned_directories)
        exact_assets = ("exact",) * len(AUTHORITY.installed_assets)

        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(
                 module,
                 "_bootstrap_state",
                 side_effect=(
                     ("exact", "exact", exact_dirs, exact_assets),
                     ("exact", "exact", exact_dirs, exact_assets),
                 ),
             ), \
             patch.object(module, "_static_package_host", return_value=static_host()), \
             patch.object(module, "_ensure_subids") as subids, \
             patch.object(module, "_install_static_assets") as assets, \
             patch.object(module, "_run") as run, \
             patch.object(module, "_require_directory_contents"), \
             patch.object(module, "_require_systemd_assets_visible"):
            value = module._bootstrap_under_lock()

        self.assertEqual(value.operation, "already-bootstrapped")
        subids.assert_not_called()
        assets.assert_not_called()
        run.assert_not_called()

    def test_directory_content_gate_rejects_unknown_children_and_requires_final_assets(self):
        path, expected = next(
            (item for item in module._EXPECTED_DIRECTORY_CHILDREN.items() if item[1])
        )
        fake_fd = 77
        with patch.object(module, "_EXPECTED_DIRECTORY_CHILDREN", {path: expected}), \
             patch.object(module.os, "open", return_value=fake_fd), \
             patch.object(module.os, "close"), \
             patch.object(module.os, "listdir", return_value=["unexpected"]), \
             self.assertRaises(OSError):
            module._require_directory_contents(allow_temporary=True)

        observed = sorted(expected)
        with patch.object(module, "_EXPECTED_DIRECTORY_CHILDREN", {path: expected}), \
             patch.object(module.os, "open", return_value=fake_fd), \
             patch.object(module.os, "close"), \
             patch.object(module.os, "listdir", return_value=observed):
            module._require_directory_contents(allow_temporary=False)

        missing = observed[:-1]
        with patch.object(module, "_EXPECTED_DIRECTORY_CHILDREN", {path: expected}), \
             patch.object(module.os, "open", return_value=fake_fd), \
             patch.object(module.os, "close"), \
             patch.object(module.os, "listdir", return_value=missing), \
             self.assertRaises(OSError):
            module._require_directory_contents(allow_temporary=False)

    def test_public_boundary_holds_shared_lock_and_collapses_failure(self):
        expected = final_evidence()
        lock = object()
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(
                 module.orchestration, "_acquire_process_lock", return_value=lock
             ) as acquire, \
             patch.object(module, "_bootstrap_under_lock", return_value=expected), \
             patch.object(
                 module.orchestration, "_release_process_lock"
             ) as release:
            self.assertEqual(module.bootstrap_rootless_docker_static_host(), expected)
        acquire.assert_called_once_with()
        release.assert_called_once_with(lock)

        with patch.object(module, "_root_identity", side_effect=OSError("private")), \
             self.assertRaises(module.RootlessDockerStaticBootstrapError) as caught:
            module.bootstrap_rootless_docker_static_host()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_static_bootstrap_source_has_no_activation_network_or_docker_surface(self):
        source = (ROOT / "deployment/rootless_docker_static_bootstrap.py").read_text()
        for forbidden in (
            "enable-linger",
            "disable-linger",
            '"start"',
            '"enable"',
            "/usr/bin/docker",
            "dockerd",
            "urllib",
            "requests",
            "http.client",
            "socket.",
            "shell=True",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
