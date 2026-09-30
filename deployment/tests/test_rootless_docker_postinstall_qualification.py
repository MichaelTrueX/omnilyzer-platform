"""Tests for C32ZX rootless Docker post-install qualification."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import patch

from deployment import rootless_docker_postinstall_qualification as module
from deployment.rootless_docker_authority import AUTHORITY
from deployment.rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from deployment.rootless_docker_package_bundle_qualification import (
    PackageBundleFileEvidence,
    RootlessDockerPackageBundleEvidence,
)
from deployment.successor_application_generation import TARGET_REVIEWED_COMMIT


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40


def bundle_evidence(*, inode: int = 99) -> RootlessDockerPackageBundleEvidence:
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
        (0o40700, inode, 10, 2, 0, 0, 4096, 3000, 4000),
        files,
    )


def packages_evidence():
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


def dependencies_evidence():
    return tuple(
        (item.package, "9.9-test", item.architecture)
        for item in INSTALLATION_AUTHORITY.host_dependencies
    )


def executables_evidence():
    values = []
    for index, (package, path) in enumerate(module._REQUIRED_EXECUTABLES):
        sha256 = (
            AUTHORITY.vendor_rootless_script_sha256
            if path == AUTHORITY.vendor_rootless_script
            else format(index + 1, "064x")
        )
        values.append((package, path, module._EXECUTABLE_MODES[path], sha256))
    return tuple(values)


def evidence(*, bundle=None):
    return module.RootlessDockerPostinstallEvidence(
        application_reviewed_commit=TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=WORKFLOW,
        executor_uid=AUTHORITY.executor_uid,
        executor_gid=AUTHORITY.executor_gid,
        supplementary_gids=(992,),
        packages=packages_evidence(),
        host_dependencies=dependencies_evidence(),
        masked_units=INSTALLATION_AUTHORITY.rootful_units,
        critical_executables=executables_evidence(),
        vendor_rootless_script_sha256=AUTHORITY.vendor_rootless_script_sha256,
        subuid_start=AUTHORITY.subuid_start,
        subgid_start=AUTHORITY.subgid_start,
        subordinate_count=AUTHORITY.subordinate_count,
        cgroup_controllers=("cpu", "io", "memory", "pids"),
        bundle=bundle or bundle_evidence(),
    )


class RootlessDockerPostinstallQualificationTests(unittest.TestCase):
    def test_evidence_is_immutable_and_exact_authority_bound(self):
        value = evidence()
        with self.assertRaises(FrozenInstanceError):
            value.executor_uid = 1
        with self.assertRaises(ValueError):
            module.RootlessDockerPostinstallEvidence(
                value.application_reviewed_commit,
                value.expected_workflow_sha,
                value.executor_uid,
                value.executor_gid,
                value.supplementary_gids,
                value.packages[:-1],
                value.host_dependencies,
                value.masked_units,
                value.critical_executables,
                value.vendor_rootless_script_sha256,
                value.subuid_start,
                value.subgid_start,
                value.subordinate_count,
                value.cgroup_controllers,
                value.bundle,
            )
        with self.assertRaises(ValueError):
            module.RootlessDockerPostinstallEvidence(
                value.application_reviewed_commit,
                value.expected_workflow_sha,
                value.executor_uid,
                value.executor_gid,
                value.supplementary_gids,
                value.packages,
                value.host_dependencies,
                value.masked_units,
                value.critical_executables,
                "0" * 64,
                value.subuid_start,
                value.subgid_start,
                value.subordinate_count,
                value.cgroup_controllers,
                value.bundle,
            )

    def test_require_package_accepts_only_exact_ii_version_architecture(self):
        payload = INSTALLATION_AUTHORITY.payloads[0]
        version = module._TARGET_VERSIONS[payload.package]
        good = subprocess.CompletedProcess(
            (),
            0,
            f"ii \t{version}\tamd64\n".encode(),
            b"",
        )
        with patch.object(module.preinstall, "_run", return_value=good):
            self.assertEqual(
                module._require_package(payload),
                (payload.package, version, "amd64"),
            )

        bad_rows = (
            f"iU \t{version}\tamd64\n",
            f"ii \t{version}x\tamd64\n",
            f"ii \t{version}\tarm64\n",
        )
        for row in bad_rows:
            with self.subTest(row=row), patch.object(
                module.preinstall,
                "_run",
                return_value=subprocess.CompletedProcess(
                    (), 0, row.encode(), b""
                ),
            ), self.assertRaises(OSError):
                module._require_package(payload)

    def test_owner_query_is_closed_and_exact(self):
        for package, path in module._REQUIRED_EXECUTABLES:
            with self.subTest(path=path):
                good = subprocess.CompletedProcess(
                    (),
                    0,
                    f"{package}: {path}\n".encode(),
                    b"",
                )
                with patch.object(module.subprocess, "run", return_value=good) as run:
                    self.assertEqual(module._run_owner(path), package)
                self.assertEqual(
                    run.call_args.args[0],
                    (module._DPKG_QUERY, "-S", path),
                )
                self.assertFalse(run.call_args.kwargs["shell"])
                self.assertEqual(
                    run.call_args.kwargs["env"],
                    {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )

        with self.assertRaises(OSError):
            module._run_owner("/tmp/not-reviewed")

        package, path = module._REQUIRED_EXECUTABLES[0]
        bad = subprocess.CompletedProcess(
            (),
            0,
            f"other-package: {path}\n".encode(),
            b"",
        )
        with patch.object(module.subprocess, "run", return_value=bad), self.assertRaises(OSError):
            module._run_owner(path)

    def test_conflict_gate_uses_postinstall_not_installed_semantics(self):
        seen = []
        with patch.object(
            module.preinstall,
            "_require_package_not_installed",
            side_effect=lambda name: seen.append(name),
        ):
            module._require_conflicts_absent()
        targets = set(module._TARGET_VERSIONS)
        self.assertEqual(
            seen,
            [
                name
                for name in INSTALLATION_AUTHORITY.conflicting_packages
                if name not in targets
            ],
        )

    def test_rootful_mask_gate_requires_exact_links_masked_inactive_and_no_runtime(self):
        link = SimpleNamespace(st_mode=0o120777, st_uid=0, st_gid=0)
        properties = {
            (unit, "LoadState"): "masked"
            for unit in INSTALLATION_AUTHORITY.rootful_units
        }
        properties.update({
            (unit, "UnitFileState"): "masked"
            for unit in INSTALLATION_AUTHORITY.rootful_units
        })
        properties.update({
            (unit, "ActiveState"): "inactive"
            for unit in INSTALLATION_AUTHORITY.rootful_units
        })

        def systemctl(unit, prop):
            return properties[(unit, prop)]

        with patch.object(module.os, "lstat", side_effect=[
            link, link, link,
            *[FileNotFoundError() for _ in module._RUNTIME_FORBIDDEN],
        ]), patch.object(
            module.os, "readlink", return_value="/dev/null"
        ), patch.object(
            module.preinstall, "_systemctl_value", side_effect=systemctl
        ), patch.object(
            module.preinstall,
            "_run",
            side_effect=(
                subprocess.CompletedProcess((), 1, b"", b""),
                subprocess.CompletedProcess((), 1, b"", b""),
            ),
        ):
            module._require_rootful_masked()

        properties[(INSTALLATION_AUTHORITY.rootful_units[0], "LoadState")] = "loaded"
        with patch.object(module.os, "lstat", return_value=link), patch.object(
            module.os, "readlink", return_value="/dev/null"
        ), patch.object(
            module.preinstall, "_systemctl_value", side_effect=systemctl
        ), self.assertRaises(OSError):
            module._require_rootful_masked()

    def test_shadow_gate_rejects_rootlesskit_buildx_and_distinct_compose(self):
        with patch.object(module.os.path, "lexists", return_value=False):
            module._require_no_shadowing()

        first = module._ROOTLESSKIT_SHADOWS[0]
        with patch.object(
            module.os.path,
            "lexists",
            side_effect=lambda path: path == first,
        ), self.assertRaises(OSError):
            module._require_no_shadowing()

        buildx = module._BUILDX_SHADOWS[0]
        with patch.object(
            module.os.path,
            "lexists",
            side_effect=lambda path: path == buildx,
        ), patch.object(module.os.path, "samefile", return_value=True), self.assertRaises(OSError):
            module._require_no_shadowing()

        compose = module._COMPOSE_SHADOWS[0]
        with patch.object(
            module.os.path,
            "lexists",
            side_effect=lambda path: path == compose,
        ), patch.object(module.os.path, "samefile", return_value=True):
            module._require_no_shadowing()

        with patch.object(
            module.os.path,
            "lexists",
            side_effect=lambda path: path == compose,
        ), patch.object(module.os.path, "samefile", return_value=False), self.assertRaises(OSError):
            module._require_no_shadowing()

    def test_critical_executables_bind_owner_mode_and_vendor_hash(self):
        calls = []

        def owner(path):
            package = next(
                package
                for package, candidate in module._REQUIRED_EXECUTABLES
                if candidate == path
            )
            calls.append(("owner", path, package))
            return package

        digest_map = {
            path: sha256
            for _package, path, _mode, sha256 in executables_evidence()
        }

        def hashed(path, *, mode, expected_sha256=None):
            calls.append(("hash", path, mode, expected_sha256))
            return (0,) * 9, digest_map[path]

        with patch.object(module, "_run_owner", side_effect=owner), patch.object(
            module, "_hash_exact_file", side_effect=hashed
        ):
            self.assertEqual(
                module._require_critical_executables(),
                executables_evidence(),
            )

        vendor = [
            item for item in calls
            if item[0] == "hash" and item[1] == AUTHORITY.vendor_rootless_script
        ]
        self.assertEqual(len(vendor), 1)
        self.assertEqual(vendor[0][3], AUTHORITY.vendor_rootless_script_sha256)

    def test_one_observation_binds_all_package_only_postinstall_authority(self):
        bundle = bundle_evidence()
        migrated = SimpleNamespace(
            phase="complete",
            next_operation="complete",
            application_sha256=module._EXPECTED_APPLICATION_SHA256,
            executor_reviewed_commit=TARGET_REVIEWED_COMMIT,
            broker_reviewed_commit=TARGET_REVIEWED_COMMIT,
            expected_workflow_sha=WORKFLOW,
        )

        with patch.object(
            module, "_root_identity", return_value=(0, 0, 0, 0)
        ), patch.object(
            module, "qualify_successor_host_migration", return_value=migrated
        ), patch.object(
            module.preinstall, "_require_executor_identity", return_value=(992,)
        ), patch.object(
            module.preinstall,
            "_require_host_dependency",
            side_effect=[
                value for value in dependencies_evidence()
            ],
        ), patch.object(
            module,
            "_require_package",
            side_effect=[value for value in packages_evidence()],
        ), patch.object(
            module, "_require_conflicts_absent"
        ) as conflicts, patch.object(
            module, "_require_rootful_masked"
        ) as masks, patch.object(
            module.preinstall, "_require_subid_authority"
        ) as subids, patch.object(
            module.preinstall,
            "_require_kernel_prerequisites",
            return_value=("cpu", "io", "memory", "pids"),
        ), patch.object(
            module, "_require_no_shadowing"
        ) as shadows, patch.object(
            module,
            "_require_critical_executables",
            return_value=executables_evidence(),
        ), patch.object(
            module,
            "qualify_rootless_docker_package_bundle",
            return_value=bundle,
        ):
            value = module._qualify_once()

        self.assertEqual(value, evidence(bundle=bundle))
        conflicts.assert_called_once_with()
        masks.assert_called_once_with()
        subids.assert_called_once_with()
        shadows.assert_called_once_with()

    def test_public_gate_requires_two_identical_observations(self):
        first = evidence()
        with patch.object(module, "_qualify_once", return_value=first) as qualify:
            self.assertEqual(module.qualify_rootless_docker_postinstall(), first)
        self.assertEqual(qualify.call_count, 2)

        changed = evidence(bundle=bundle_evidence(inode=100))
        with patch.object(
            module, "_qualify_once", side_effect=(first, changed)
        ), self.assertRaises(
            module.RootlessDockerPostinstallQualificationError
        ):
            module.qualify_rootless_docker_postinstall()

    def test_public_gate_collapses_operational_failure(self):
        with patch.object(
            module, "_qualify_once", side_effect=OSError("private")
        ), self.assertRaises(
            module.RootlessDockerPostinstallQualificationError
        ) as caught:
            module.qualify_rootless_docker_postinstall()
        self.assertEqual(
            str(caught.exception),
            "rootless Docker postinstall qualification is unavailable",
        )
        self.assertNotIn("private", str(caught.exception))

    def test_module_has_no_mutation_network_or_activation_surface(self):
        source = (
            ROOT / "deployment/rootless_docker_postinstall_qualification.py"
        ).read_text()
        for forbidden in (
            "apt-get",
            "/usr/bin/apt",
            "http.client",
            "urllib",
            "requests",
            "socket.",
            "os.write",
            "os.unlink",
            "os.remove",
            "os.rename",
            "os.mkdir",
            "os.makedirs",
            "os.chmod",
            "os.chown",
            "O_WRONLY",
            "O_CREAT",
            "systemctl\", \"start",
            "systemctl\", \"enable",
            "systemctl\", \"restart",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
