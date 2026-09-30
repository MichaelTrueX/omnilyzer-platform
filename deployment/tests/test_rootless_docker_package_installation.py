"""Tests for C32ZW exact offline rootless Docker package installation."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import Mock, call, patch

from deployment import rootless_docker_package_installation as module
from deployment.rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from deployment.rootless_docker_package_bundle_qualification import (
    PackageBundleFileEvidence,
    RootlessDockerPackageBundleEvidence,
)
from deployment.rootless_docker_preinstall_qualification import (
    RootlessDockerPreinstallEvidence,
)
from deployment.rootless_docker_staged_preinstall_qualification import (
    RootlessDockerStagedPreinstallEvidence,
)
from deployment.successor_application_generation import TARGET_REVIEWED_COMMIT


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40


def host_evidence() -> RootlessDockerPreinstallEvidence:
    return RootlessDockerPreinstallEvidence(
        application_reviewed_commit=TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=WORKFLOW,
        executor_uid=991,
        executor_gid=991,
        supplementary_gids=(992,),
        subuid_start=493216,
        subgid_start=493216,
        subordinate_count=65536,
        direct_packages=tuple(item.name for item in INSTALLATION_AUTHORITY.packages),
        supplemental_packages=tuple(
            item.name for item in INSTALLATION_AUTHORITY.supplemental_packages
        ),
        host_dependencies=tuple(
            (item.package, "9.9-test", item.architecture)
            for item in INSTALLATION_AUTHORITY.host_dependencies
        ),
        cgroup_controllers=("cpu", "io", "memory", "pids"),
    )



def static_host_observation():
    host = host_evidence()
    return (
        host.expected_workflow_sha,
        host.host_dependencies,
        host.cgroup_controllers,
    )


def bundle_evidence() -> RootlessDockerPackageBundleEvidence:
    files = tuple(
        PackageBundleFileEvidence(
            item.package,
            item.filename,
            item.size,
            item.sha256,
            (
                0o100600,
                index + 100,
                10,
                1,
                0,
                0,
                item.size,
                1000 + index,
                2000 + index,
            ),
        )
        for index, item in enumerate(INSTALLATION_AUTHORITY.payloads)
    )
    return RootlessDockerPackageBundleEvidence(
        INSTALLATION_AUTHORITY.staging_directory,
        "sha256",
        INSTALLATION_AUTHORITY.bundle_size(),
        (0o40700, 99, 10, 2, 0, 0, 4096, 3000, 4000),
        files,
    )


def absent_states():
    return tuple((item.package, None) for item in INSTALLATION_AUTHORITY.payloads)


def installed_states():
    versions = {
        item.name: item.apt_version
        for item in (
            *INSTALLATION_AUTHORITY.packages,
            *INSTALLATION_AUTHORITY.supplemental_packages,
        )
    }
    return tuple(
        (item.package, ("ii ", versions[item.package], "amd64"))
        for item in INSTALLATION_AUTHORITY.payloads
    )


def partial_states():
    values = list(absent_states())
    first = INSTALLATION_AUTHORITY.payloads[0]
    versions = {
        item.name: item.apt_version
        for item in (
            *INSTALLATION_AUTHORITY.packages,
            *INSTALLATION_AUTHORITY.supplemental_packages,
        )
    }
    values[0] = (first.package, ("iU ", versions[first.package], "amd64"))
    return tuple(values)


def final_evidence(operation="installed"):
    versions = {
        item.name: item.apt_version
        for item in (
            *INSTALLATION_AUTHORITY.packages,
            *INSTALLATION_AUTHORITY.supplemental_packages,
        )
    }
    return module.RootlessDockerPackageInstallationEvidence(
        operation,
        WORKFLOW,
        tuple(
            (item.package, versions[item.package], "amd64")
            for item in INSTALLATION_AUTHORITY.payloads
        ),
        INSTALLATION_AUTHORITY.rootful_units,
        INSTALLATION_AUTHORITY.staging_directory,
        tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads),
    )


class RootlessDockerPackageInstallationTests(unittest.TestCase):
    def test_evidence_is_immutable_and_exact_authority_bound(self):
        value = final_evidence()
        with self.assertRaises(FrozenInstanceError):
            value.operation = "resumed"
        with self.assertRaises(ValueError):
            module.RootlessDockerPackageInstallationEvidence(
                "installed",
                WORKFLOW,
                value.packages[:-1],
                value.masked_units,
                value.staging_directory,
                value.staged_sha256s,
            )
        with self.assertRaises(ValueError):
            module.RootlessDockerPackageInstallationEvidence(
                "other",
                WORKFLOW,
                value.packages,
                value.masked_units,
                value.staging_directory,
                value.staged_sha256s,
            )

    def test_package_state_accepts_absent_exact_partial_and_installed_only(self):
        payload = INSTALLATION_AUTHORITY.payloads[0]
        version = module._TARGET_VERSIONS[payload.package]

        with patch.object(
            module.preinstall,
            "_run",
            return_value=subprocess.CompletedProcess((), 1, b"", b""),
        ):
            self.assertIsNone(module._package_state(payload.package))

        for status in ("iU ", "iF ", "ii ", "iiR"):
            with self.subTest(status=status), patch.object(
                module.preinstall,
                "_run",
                return_value=subprocess.CompletedProcess(
                    (),
                    0,
                    f"{status}\t{version}\tamd64\n".encode(),
                    b"",
                ),
            ):
                self.assertEqual(
                    module._package_state(payload.package),
                    (status, version, "amd64"),
                )

        for row in (
            f"ri \t{version}\tamd64\n",
            f"ii \t0:{version}\tamd64\n",
            f"ii \t{version}\tarm64\n",
        ):
            with self.subTest(row=row), patch.object(
                module.preinstall,
                "_run",
                return_value=subprocess.CompletedProcess((), 0, row.encode(), b""),
            ), self.assertRaises(OSError):
                module._package_state(payload.package)

    def test_phase_accepts_only_clean_initial_owned_resume_or_exact_complete(self):
        self.assertEqual(module._phase(None, 0, absent_states()), "initial")
        self.assertEqual(
            module._phase((1,) * 9, 0, absent_states()),
            "resume",
        )
        self.assertEqual(
            module._phase(
                (1,) * 9,
                len(INSTALLATION_AUTHORITY.rootful_units),
                partial_states(),
            ),
            "resume",
        )
        self.assertEqual(
            module._phase(
                None,
                len(INSTALLATION_AUTHORITY.rootful_units),
                installed_states(),
            ),
            "complete",
        )
        with self.assertRaises(OSError):
            module._phase(None, 1, absent_states())
        with self.assertRaises(OSError):
            module._phase((1,) * 9, 1, partial_states())
        with self.assertRaises(OSError):
            module._phase(
                None,
                len(INSTALLATION_AUTHORITY.rootful_units),
                partial_states(),
            )

    def test_run_allows_only_fixed_mutation_shapes_and_closed_environment(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            self.assertIs(module._run((module._SYSTEMCTL, "daemon-reload")), completed)
        kwargs = run.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(
            kwargs["env"],
            {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "HOME": "/root",
                "DEBIAN_FRONTEND": "noninteractive",
            },
        )

        fds = tuple(range(20, 20 + len(INSTALLATION_AUTHORITY.payloads)))
        argv = (
            module._DPKG,
            "--install",
            *(f"/proc/self/fd/{item}" for item in fds),
        )
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            module._run(argv, pass_fds=fds)
        self.assertEqual(run.call_args.kwargs["pass_fds"], fds)
        self.assertEqual(run.call_args.kwargs["timeout"], module._DPKG_TIMEOUT)

        for argv in (
            ("/usr/bin/apt-get", "install", "docker-ce"),
            (module._DPKG, "--configure", "-a"),
            (module._SYSTEMCTL, "enable", "docker.service"),
            (module._SYSTEMCTL, "start", "ssh.service"),
        ):
            with self.subTest(argv=argv), patch.object(
                module.subprocess, "run"
            ) as run, self.assertRaises(OSError):
                module._run(argv)
            run.assert_not_called()

    def test_initial_install_consumes_c32zv_before_mutation_and_removes_policy_last(self):
        bundle = bundle_evidence()
        staged = RootlessDockerStagedPreinstallEvidence(host_evidence(), bundle)
        events = []

        def event(name, result=None):
            def inner(*args, **kwargs):
                events.append(name)
                return result
            return inner

        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(module, "_policy_fingerprint", side_effect=(None, None)), \
             patch.object(module, "_mask_prefix", side_effect=(0, 0)), \
             patch.object(
                 module,
                 "_package_states",
                 side_effect=(
                     absent_states(),
                     absent_states(),
                     absent_states(),
                     installed_states(),
                     installed_states(),
                 ),
             ), \
             patch.object(
                 module,
                 "qualify_rootless_docker_staged_preinstall",
                 side_effect=event("c32zv", staged),
             ), \
             patch.object(
                 module,
                 "_open_bundle",
                 side_effect=event(
                     "open-bundle",
                     (10, tuple(range(20, 20 + len(INSTALLATION_AUTHORITY.payloads)))),
                 ),
             ), \
             patch.object(module.os, "close"), \
             patch.object(module, "_create_policy", side_effect=event("policy")), \
             patch.object(module, "_create_masks", side_effect=event("masks")), \
             patch.object(
                 module,
                 "_run",
                 return_value=subprocess.CompletedProcess((), 0, b"", b""),
             ), \
             patch.object(module, "_require_masks_effective"), \
             patch.object(module, "_require_no_runtime"), \
             patch.object(module, "_verify_start_blockers"), \
             patch.object(module, "_rehash_bundle"), \
             patch.object(module, "_run_dpkg", side_effect=event("dpkg")), \
             patch.object(
                 module,
                 "_qualify_static_host",
                 return_value=static_host_observation(),
             ), \
             patch.object(
                 module,
                 "qualify_rootless_docker_package_bundle",
                 return_value=bundle,
             ), \
             patch.object(
                 module, "_remove_policy", side_effect=event("remove-policy")
             ):
            value = module._install_under_lock()

        self.assertEqual(value.operation, "installed")
        self.assertLess(events.index("c32zv"), events.index("policy"))
        self.assertLess(events.index("policy"), events.index("masks"))
        self.assertLess(events.index("masks"), events.index("dpkg"))
        self.assertLess(events.index("dpkg"), events.index("remove-policy"))

    def test_resume_never_reuses_c32zv_and_reinstalls_exact_partial_prefix(self):
        bundle = bundle_evidence()
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(
                 module, "_policy_fingerprint", side_effect=((1,) * 9, None)
             ), \
             patch.object(
                 module,
                 "_mask_prefix",
                 side_effect=(
                     len(INSTALLATION_AUTHORITY.rootful_units),
                     len(INSTALLATION_AUTHORITY.rootful_units),
                 ),
             ), \
             patch.object(
                 module,
                 "_package_states",
                 side_effect=(
                     partial_states(),
                     partial_states(),
                     partial_states(),
                     installed_states(),
                     installed_states(),
                 ),
             ), \
             patch.object(
                 module,
                 "_qualify_static_host",
                 return_value=static_host_observation(),
             ), \
             patch.object(
                 module,
                 "qualify_rootless_docker_package_bundle",
                 return_value=bundle,
             ), \
             patch.object(
                 module, "qualify_rootless_docker_staged_preinstall"
             ) as c32zv, \
             patch.object(
                 module,
                 "_open_bundle",
                 return_value=(
                     10,
                     tuple(range(20, 20 + len(INSTALLATION_AUTHORITY.payloads))),
                 ),
             ), \
             patch.object(module.os, "close"), \
             patch.object(module, "_create_policy"), \
             patch.object(module, "_create_masks") as create_masks, \
             patch.object(
                 module,
                 "_run",
                 return_value=subprocess.CompletedProcess((), 0, b"", b""),
             ), \
             patch.object(module, "_require_masks_effective"), \
             patch.object(module, "_require_no_runtime"), \
             patch.object(module, "_verify_start_blockers"), \
             patch.object(module, "_rehash_bundle"), \
             patch.object(module, "_run_dpkg") as dpkg, \
             patch.object(module, "_remove_policy"):
            value = module._install_under_lock()

        self.assertEqual(value.operation, "resumed")
        c32zv.assert_not_called()
        create_masks.assert_not_called()
        dpkg.assert_called_once()

    def test_complete_state_is_idempotent_and_never_mutates(self):
        bundle = bundle_evidence()
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(module, "_policy_fingerprint", return_value=None), \
             patch.object(
                 module,
                 "_mask_prefix",
                 return_value=len(INSTALLATION_AUTHORITY.rootful_units),
             ), \
             patch.object(
                 module,
                 "_package_states",
                 side_effect=(installed_states(), installed_states()),
             ), \
             patch.object(
                 module,
                 "_qualify_static_host",
                 return_value=static_host_observation(),
             ), \
             patch.object(
                 module,
                 "qualify_rootless_docker_package_bundle",
                 return_value=bundle,
             ), \
             patch.object(
                 module,
                 "_open_bundle",
                 return_value=(
                     10,
                     tuple(range(20, 20 + len(INSTALLATION_AUTHORITY.payloads))),
                 ),
             ), \
             patch.object(module.os, "close"), \
             patch.object(module, "_require_masks_effective"), \
             patch.object(module, "_require_no_runtime"), \
             patch.object(module, "_rehash_bundle"), \
             patch.object(module, "_create_policy") as policy, \
             patch.object(module, "_create_masks") as masks, \
             patch.object(module, "_run_dpkg") as dpkg, \
             patch.object(module, "_remove_policy") as remove:
            value = module._install_under_lock()

        self.assertEqual(value.operation, "already-installed")
        policy.assert_not_called()
        masks.assert_not_called()
        dpkg.assert_not_called()
        remove.assert_not_called()

    def test_descriptor_close_failure_cancels_otherwise_complete_success(self):
        bundle = bundle_evidence()
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(module, "_policy_fingerprint", return_value=None), \
             patch.object(
                 module,
                 "_mask_prefix",
                 return_value=len(INSTALLATION_AUTHORITY.rootful_units),
             ), \
             patch.object(
                 module,
                 "_package_states",
                 side_effect=(installed_states(), installed_states()),
             ), \
             patch.object(
                 module,
                 "_qualify_static_host",
                 return_value=static_host_observation(),
             ), \
             patch.object(
                 module,
                 "qualify_rootless_docker_package_bundle",
                 return_value=bundle,
             ), \
             patch.object(
                 module,
                 "_open_bundle",
                 side_effect=lambda _bundle, owned: (
                     owned.extend((10, 20)) or 10,
                     (20,),
                 ),
             ), \
             patch.object(module, "_require_masks_effective"), \
             patch.object(module, "_require_no_runtime"), \
             patch.object(module, "_rehash_bundle"), \
             patch.object(module.os, "close", side_effect=OSError("close")), \
             self.assertRaises(OSError):
            module._install_under_lock()

    def test_public_boundary_holds_shared_lock_and_collapses_failure(self):
        expected = final_evidence()
        lock = object()
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
             patch.object(
                 module.orchestration, "_acquire_process_lock", return_value=lock
             ) as acquire, \
             patch.object(
                 module, "_install_under_lock", return_value=expected
             ) as install, \
             patch.object(
                 module.orchestration, "_release_process_lock"
             ) as release:
            self.assertEqual(module.install_rootless_docker_packages(), expected)
        acquire.assert_called_once_with()
        install.assert_called_once_with()
        release.assert_called_once_with(lock)

        with patch.object(module, "_root_identity", side_effect=OSError("private")), \
             self.assertRaises(
                 module.RootlessDockerPackageInstallationError
             ) as caught:
            module.install_rootless_docker_packages()
        self.assertEqual(
            str(caught.exception),
            "rootless Docker package installation is unavailable",
        )
        self.assertNotIn("private", str(caught.exception))

    def test_source_has_no_network_apt_activation_or_caller_cli_surface(self):
        source = (
            ROOT / "deployment/rootless_docker_package_installation.py"
        ).read_text()
        for forbidden in (
            "/usr/bin/apt",
            "apt-get",
            "http.client",
            "urllib",
            "requests",
            "socket.",
            "Popen",
            "shell=True",
            "systemctl\", \"enable",
            "systemctl\", \"restart",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
