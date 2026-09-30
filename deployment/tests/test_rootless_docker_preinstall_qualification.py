"""deployment/tests/test_rootless_docker_preinstall_qualification.py.

Purpose:
- exercise the C32ZQ privileged read-only qualification boundary without host
  mutation;
- prove package absence, rootful-runtime absence, subordinate-ID isolation,
  executor identity, exact preinstalled dependency closure, kernel prerequisites,
  and repeated stable observation.

Linked file:
- deployment/rootless_docker_preinstall_qualification.py
"""

from dataclasses import FrozenInstanceError, fields
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

from deployment import rootless_docker_preinstall_qualification as module
from deployment.rootless_docker_authority import AUTHORITY
from deployment.rootless_docker_installation_authority import (
    INSTALLATION_AUTHORITY,
)
from deployment.successor_application_generation import TARGET_REVIEWED_COMMIT


WORKFLOW = "a" * 40


def completed(returncode: int, stdout: bytes = b""):
    """Return one deterministic subprocess result for command-boundary tests."""

    return subprocess.CompletedProcess(
        args=(), returncode=returncode, stdout=stdout, stderr=b"",
    )


def evidence(**changes):
    """Return canonical C32ZQ evidence with selected field overrides."""

    values = {
        "application_reviewed_commit": TARGET_REVIEWED_COMMIT,
        "expected_workflow_sha": WORKFLOW,
        "executor_uid": 991,
        "executor_gid": 991,
        "supplementary_gids": (992,),
        "subuid_start": 493216,
        "subgid_start": 493216,
        "subordinate_count": 65536,
        "direct_packages": tuple(
            item.name for item in INSTALLATION_AUTHORITY.packages
        ),
        "supplemental_packages": tuple(
            item.name for item in INSTALLATION_AUTHORITY.supplemental_packages
        ),
        "host_dependencies": tuple(
            (item.package, "9.9-test", item.architecture)
            for item in INSTALLATION_AUTHORITY.host_dependencies
        ),
        "cgroup_controllers": ("cpu", "io", "memory", "pids"),
    }
    values.update(changes)
    return module.RootlessDockerPreinstallEvidence(**values)


class RootlessDockerPreinstallQualificationTests(unittest.TestCase):
    """Adversarial tests for the clean pre-install host boundary."""

    def test_evidence_is_closed_and_immutable(self) -> None:
        value = evidence()
        with self.assertRaises(FrozenInstanceError):
            value.subuid_start = 1
        values = {item.name: getattr(value, item.name) for item in fields(value)}
        for field, bad in (
            ("application_reviewed_commit", "b" * 40),
            ("expected_workflow_sha", "0" * 40),
            ("executor_uid", 0),
            ("supplementary_gids", (992, 999)),
            ("subuid_start", 427680),
            ("direct_packages", ()),
            ("host_dependencies", ()),
            (
                "host_dependencies",
                value.host_dependencies[:1]
                + (("wrong", "1.0", "amd64"),)
                + value.host_dependencies[2:],
            ),
            ("cgroup_controllers", ("cpu", "memory")),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.RootlessDockerPreinstallEvidence(
                    **(values | {field: bad})
                )

    def test_package_absence_query_is_exact(self) -> None:
        with patch.object(module, "_run", return_value=completed(1)) as run:
            module._require_package_absent("docker-ce")
        run.assert_called_once_with(
            (
                "/usr/bin/dpkg-query",
                "-W",
                module._DPKG_FORMAT,
                "docker-ce",
            )
        )
        for result in (
            completed(0, b"ii \t29.8.1\tamd64\n"),
            completed(1, b"unexpected"),
            completed(2),
        ):
            with self.subTest(result=result), patch.object(
                module, "_run", return_value=result,
            ), self.assertRaises(OSError):
                module._require_package_absent("docker-ce")
        for name in ("", "../docker", "DOCKER", "docker_ce", "curl"):
            with self.subTest(name=name), self.assertRaises(OSError):
                module._require_package_absent(name)

    def test_host_dependency_query_and_version_floor_are_closed(self) -> None:
        requirement = INSTALLATION_AUTHORITY.host_dependencies[0]
        self.assertEqual(requirement.package, "libc6")
        self.assertEqual(requirement.minimum_version, "2.38")
        with patch.object(
            module,
            "_run",
            side_effect=(
                completed(0, b"ii \t2.39-0ubuntu8.9\tamd64\n"),
                completed(0),
            ),
        ) as run:
            self.assertEqual(
                module._require_host_dependency(requirement),
                ("libc6", "2.39-0ubuntu8.9", "amd64"),
            )
        self.assertEqual(
            run.call_args_list,
            [
                call(("/usr/bin/dpkg-query", "-W", module._DPKG_FORMAT, "libc6")),
                call(("/usr/bin/dpkg", "--compare-versions", "2.39-0ubuntu8.9", "ge", "2.38")),
            ],
        )

        unversioned = next(
            item
            for item in INSTALLATION_AUTHORITY.host_dependencies
            if item.minimum_version is None
        )
        with patch.object(
            module,
            "_run",
            return_value=completed(
                0,
                f"ii \t1.0\t{unversioned.architecture}\n".encode("ascii"),
            ),
        ) as run:
            self.assertEqual(
                module._require_host_dependency(unversioned),
                (unversioned.package, "1.0", unversioned.architecture),
            )
        self.assertEqual(run.call_count, 1)

    def test_host_dependency_rejects_forged_requirement_type(self) -> None:
        requirement = INSTALLATION_AUTHORITY.host_dependencies[0]
        forged = SimpleNamespace(
            package=requirement.package,
            minimum_version=requirement.minimum_version,
            architecture=requirement.architecture,
        )
        with self.assertRaises(OSError):
            module._require_host_dependency(forged)

    def test_host_dependency_rejects_bad_status_architecture_and_floor(self) -> None:
        requirement = INSTALLATION_AUTHORITY.host_dependencies[0]
        for result in (
            completed(1),
            completed(0, b"rc \t2.39\tamd64\n"),
            completed(0, b"ii \t2.39\tall\n"),
            completed(0, b"ii \tbad version\tamd64\n"),
        ):
            with self.subTest(result=result), patch.object(
                module, "_run", return_value=result,
            ), self.assertRaises(OSError):
                module._require_host_dependency(requirement)
        with patch.object(
            module,
            "_run",
            side_effect=(
                completed(0, b"ii \t2.39\tamd64\n"),
                completed(1),
            ),
        ), self.assertRaises(OSError):
            module._require_host_dependency(requirement)

    def test_command_runner_rejects_unreviewed_shapes(self) -> None:
        for argv in (
            ("/usr/bin/dpkg-query", "--help"),
            ("/usr/bin/dpkg", "--configure", "-a"),
            ("/usr/bin/dpkg", "--compare-versions", "2.39", "lt", "2.38"),
            ("/usr/bin/systemctl", "start", "docker.service"),
            ("/usr/bin/pgrep", "-f", "dockerd"),
            ("/bin/sh", "-c", "true"),
        ):
            with self.subTest(argv=argv), self.assertRaises(OSError):
                module._run(argv)

    def test_rootful_runtime_absence_is_exact(self) -> None:
        def systemctl(unit, property_name):
            return {
                "LoadState": "not-found",
                "ActiveState": "inactive",
                "UnitFileState": "",
            }[property_name]

        with patch.object(module, "_systemctl_value", side_effect=systemctl), \
                patch.object(module, "_run", return_value=completed(1)) as run, \
                patch.object(module.os, "lstat", side_effect=FileNotFoundError):
            module._require_rootful_runtime_absent()
        self.assertEqual(
            run.call_args_list,
            [call(("/usr/bin/pgrep", "-x", "dockerd")),
             call(("/usr/bin/pgrep", "-x", "containerd"))],
        )

        with patch.object(
            module, "_systemctl_value",
            side_effect=lambda _unit, prop: {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "UnitFileState": "disabled",
            }[prop],
        ), self.assertRaises(OSError):
            module._require_rootful_runtime_absent()

        with patch.object(module, "_systemctl_value", side_effect=systemctl), \
                patch.object(module, "_run", return_value=completed(0, b"42\n")), \
                self.assertRaises(OSError):
            module._require_rootful_runtime_absent()

    def test_subid_parser_rejects_overlap_and_target_collision(self) -> None:
        clean = (
            b"ysabel:100000:65536\n"
            b"trust:165536:65536\n"
            b"omnidev:362144:65536\n"
            b"omnigpt:427680:65536\n"
        )
        with patch.object(module, "_read_root_regular", return_value=clean):
            records = module._subid_records("/etc/subuid")
        self.assertEqual(records[-1], ("omnigpt", 427680, 65536))

        overlap = b"alpha:100000:65536\nbeta:120000:65536\n"
        with patch.object(module, "_read_root_regular", return_value=overlap), \
                self.assertRaises(OSError):
            module._subid_records("/etc/subuid")

        exact_records = (
            ("ysabel", 100000, 65536),
            ("trust", 165536, 65536),
            ("ayeshia", 231072, 65536),
            ("jane", 296608, 65536),
            ("omnidev", 362144, 65536),
            ("omnigpt", 427680, 65536),
        )
        with patch.object(module, "_subid_records", return_value=exact_records):
            module._require_subid_authority()

        collided = exact_records + (("other", 493216, 1),)
        with patch.object(module, "_subid_records", return_value=collided), \
                self.assertRaises(OSError):
            module._require_subid_authority()

        executor_present = exact_records + (
            ("omnilyzer-executor", 558752, 65536),
        )
        with patch.object(
            module, "_subid_records", return_value=executor_present,
        ), self.assertRaises(OSError):
            module._require_subid_authority()

    def test_executor_identity_requires_only_replay_supplementary_group(self) -> None:
        account = SimpleNamespace(
            pw_uid=991,
            pw_gid=991,
            pw_dir="/nonexistent",
            pw_shell="/usr/sbin/nologin",
            pw_name="omnilyzer-executor",
        )
        primary = SimpleNamespace(gr_gid=991)
        replay = SimpleNamespace(gr_gid=992)
        with patch.object(module.pwd, "getpwnam", return_value=account), \
                patch.object(
                    module.grp, "getgrnam",
                    side_effect=lambda name: (
                        primary if name == "omnilyzer-executor" else replay
                    ),
                ), patch.object(
                    module.os, "getgrouplist", return_value=[991, 992],
                ):
            self.assertEqual(module._require_executor_identity(), (992,))
        with patch.object(module.pwd, "getpwnam", return_value=account), \
                patch.object(
                    module.grp, "getgrnam",
                    side_effect=lambda name: (
                        primary if name == "omnilyzer-executor" else replay
                    ),
                ), patch.object(
                    module.os, "getgrouplist", return_value=[991, 992, 999],
                ), self.assertRaises(OSError):
            module._require_executor_identity()

    def test_kernel_prerequisites_require_userns_profile_and_controllers(self) -> None:
        values = {
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1",
            "/proc/sys/kernel/unprivileged_userns_clone": "1",
            "/sys/fs/cgroup/cgroup.controllers": "cpu io memory pids",
        }
        profile = (
            b"profile rootlesskit /usr/bin/rootlesskit flags=(unconfined) {\n"
            b"  userns,\n}\n"
        )
        with patch.object(
            module, "_read_virtual_scalar",
            side_effect=lambda path: values[path],
        ), patch.object(module, "_read_root_regular", return_value=profile):
            self.assertEqual(
                module._require_kernel_prerequisites(),
                ("cpu", "io", "memory", "pids"),
            )

        bad_values = values | {
            "/sys/fs/cgroup/cgroup.controllers": "cpu io memory"
        }
        with patch.object(
            module, "_read_virtual_scalar",
            side_effect=lambda path: bad_values[path],
        ), patch.object(module, "_read_root_regular", return_value=profile), \
                self.assertRaises(OSError):
            module._require_kernel_prerequisites()

        with patch.object(
            module, "_read_virtual_scalar",
            side_effect=lambda path: values[path],
        ), patch.object(module, "_read_root_regular", return_value=b"userns,\n"), \
                self.assertRaises(OSError):
            module._require_kernel_prerequisites()

    def test_qualify_once_composes_only_reviewed_absence_checks(self) -> None:
        migrated = SimpleNamespace(
            phase="complete",
            next_operation="complete",
            application_sha256=(
                "9bb162e1712a8ec76874c229ce1af1c8a88f527686d4a43376ca93a8b0d00b88"
            ),
            executor_reviewed_commit=TARGET_REVIEWED_COMMIT,
            broker_reviewed_commit=TARGET_REVIEWED_COMMIT,
            expected_workflow_sha=WORKFLOW,
        )
        checked = []
        checked_dependencies = []
        dependency_evidence = tuple(
            (item.package, "9.9-test", item.architecture)
            for item in INSTALLATION_AUTHORITY.host_dependencies
        )
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(
                    module, "qualify_successor_host_migration",
                    return_value=migrated,
                ), patch.object(
                    module, "_require_executor_identity", return_value=(992,),
                ), patch.object(
                    module, "_require_host_dependency",
                    side_effect=lambda item: (
                        checked_dependencies.append(item.package)
                        or (item.package, "9.9-test", item.architecture)
                    ),
                ), patch.object(
                    module, "_require_package_absent",
                    side_effect=lambda name: checked.append(name),
                ), patch.object(
                    module, "_require_rootful_runtime_absent",
                ) as rootful, patch.object(
                    module, "_require_subid_authority",
                ) as subids, patch.object(
                    module, "_require_kernel_prerequisites",
                    return_value=("cpu", "io", "memory", "pids"),
                ):
            result = module._qualify_once()
        self.assertEqual(result, evidence(host_dependencies=dependency_evidence))
        self.assertEqual(
            checked_dependencies,
            [item.package for item in INSTALLATION_AUTHORITY.host_dependencies],
        )
        self.assertEqual(len(checked), len(set(checked)))
        self.assertTrue(
            {item.name for item in INSTALLATION_AUTHORITY.packages}
            .issubset(set(checked))
        )
        self.assertTrue(
            {item.name for item in INSTALLATION_AUTHORITY.supplemental_packages}
            .issubset(set(checked))
        )
        self.assertTrue(
            set(INSTALLATION_AUTHORITY.conflicting_packages).issubset(set(checked))
        )
        rootful.assert_called_once_with()
        subids.assert_called_once_with()

    def test_top_level_requires_two_identical_observations(self) -> None:
        first = evidence()
        with patch.object(module, "_qualify_once", return_value=first) as qualify:
            self.assertEqual(module.qualify_rootless_docker_preinstall(), first)
        self.assertEqual(qualify.call_count, 2)

        with patch.object(
            module,
            "_qualify_once",
            side_effect=(first, evidence(expected_workflow_sha="b" * 40)),
        ), self.assertRaises(module.RootlessDockerPreinstallQualificationError):
            module.qualify_rootless_docker_preinstall()

    def test_public_boundary_collapses_operational_failures(self) -> None:
        with patch.object(module, "_qualify_once", side_effect=OSError("secret")), \
                self.assertRaises(
                    module.RootlessDockerPreinstallQualificationError,
                ) as caught:
            module.qualify_rootless_docker_preinstall()
        self.assertEqual(
            str(caught.exception),
            "rootless Docker preinstall qualification is unavailable",
        )
        self.assertNotIn("secret", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
