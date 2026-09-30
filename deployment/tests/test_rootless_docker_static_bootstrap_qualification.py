"""Tests for C33A static rootless Docker bootstrap qualification."""

from dataclasses import FrozenInstanceError
from pathlib import Path
import stat
import subprocess
import unittest
from unittest.mock import patch

from deployment import rootless_docker_static_bootstrap_qualification as module
from deployment.rootless_docker_authority import AUTHORITY
from deployment.rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from deployment.rootless_docker_package_bundle_qualification import (
    PackageBundleFileEvidence,
    RootlessDockerPackageBundleEvidence,
)


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40


def bundle_evidence():
    files = tuple(
        PackageBundleFileEvidence(
            item.package,
            item.filename,
            item.size,
            item.sha256,
            (
                stat.S_IFREG | 0o600,
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
        (stat.S_IFDIR | 0o700, 99, 10, 2, 0, 0, 4096, 3000, 4000),
        files,
    )


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


def dependency_rows():
    return tuple(
        (item.package, "9.9-test", item.architecture)
        for item in INSTALLATION_AUTHORITY.host_dependencies
    )


def executable_rows():
    values = []
    for index, (package, path) in enumerate(module.postinstall._REQUIRED_EXECUTABLES):
        sha256 = (
            AUTHORITY.vendor_rootless_script_sha256
            if path == AUTHORITY.vendor_rootless_script
            else format(index + 1, "064x")
        )
        values.append(
            (package, path, module.postinstall._EXECUTABLE_MODES[path], sha256)
        )
    return tuple(values)


def subid_rows():
    return (
        ("ysabel", 100000, 65536),
        ("trust", 165536, 65536),
        ("ayeshia", 231072, 65536),
        ("jane", 296608, 65536),
        ("omnidev", 362144, 65536),
        ("omnigpt", 427680, 65536),
        (AUTHORITY.executor_user, AUTHORITY.subuid_start, AUTHORITY.subordinate_count),
    )


def evidence(workflow=WORKFLOW):
    return module.RootlessDockerStaticBootstrapEvidence(
        application_reviewed_commit=module.TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=workflow,
        executor_uid=AUTHORITY.executor_uid,
        executor_gid=AUTHORITY.executor_gid,
        supplementary_gids=(992,),
        subuid_records=subid_rows(),
        subgid_records=subid_rows(),
        directories=AUTHORITY.provisioned_directories,
        assets=tuple(
            (destination, digest, uid, gid, mode)
            for _source, destination, digest, uid, gid, mode
            in AUTHORITY.installed_assets
        ),
        packages=package_rows(),
        host_dependencies=dependency_rows(),
        masked_units=INSTALLATION_AUTHORITY.rootful_units,
        critical_executables=executable_rows(),
        cgroup_controllers=("cpu", "io", "memory", "pids"),
        executor_dropins=(AUTHORITY.executor_socket_dropin,),
        user_manager_dropins=(AUTHORITY.cgroup_dropin,),
        bundle=bundle_evidence(),
    )


class RootlessDockerStaticBootstrapQualificationTests(unittest.TestCase):
    def test_evidence_is_exact_and_immutable(self):
        value = evidence()
        with self.assertRaises(FrozenInstanceError):
            value.executor_uid = 0
        values = {
            name: getattr(value, name)
            for name in value.__dataclass_fields__
        }
        for field, bad in (
            ("expected_workflow_sha", "0" * 40),
            ("subuid_records", value.subuid_records[:-1]),
            ("directories", ()),
            ("assets", ()),
            ("packages", ()),
            ("critical_executables", value.critical_executables[:-1]),
            ("cgroup_controllers", ("cpu", "memory")),
            ("executor_dropins", ()),
            ("user_manager_dropins", ()),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.RootlessDockerStaticBootstrapEvidence(
                    **(values | {field: bad})
                )

    def test_subid_gate_requires_identical_files_and_exact_executor_range(self):
        good = subid_rows()
        with patch.object(module.preinstall, "_subid_records", side_effect=(good, good)):
            self.assertEqual(module._require_subids(), (good, good))

        wrong = good[:-1] + ((AUTHORITY.executor_user, 600000, 65536),)
        with patch.object(module.preinstall, "_subid_records", side_effect=(wrong, wrong)), self.assertRaises(OSError):
            module._require_subids()

        with patch.object(module.preinstall, "_subid_records", side_effect=(good, good[:-1])), self.assertRaises(OSError):
            module._require_subids()

    def test_systemctl_reader_is_read_only_closed_environment(self):
        completed = subprocess.CompletedProcess((), 0, b"inactive\n", b"")
        with patch.object(module.subprocess, "run", return_value=completed) as run:
            self.assertEqual(
                module._read_systemctl(
                    "omnilyzer-deployment-executor.service", "ActiveState"
                ),
                "inactive",
            )
        self.assertEqual(
            run.call_args.args[0][:2],
            (module._SYSTEMCTL, "show"),
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

        for unit, prop in (
            ("ssh.service", "ActiveState"),
            ("omnilyzer-deployment-executor.service", "Environment"),
        ):
            with self.subTest(unit=unit, prop=prop), patch.object(
                module.subprocess, "run"
            ) as run, self.assertRaises(OSError):
                module._read_systemctl(unit, prop)
            run.assert_not_called()

    def test_directory_gate_requires_exact_metadata_contents_and_stability(self):
        path, uid, gid, mode = AUTHORITY.provisioned_directories[0]
        fake = type(
            "S",
            (),
            {
                "st_mode": stat.S_IFDIR | mode,
                "st_ino": 1,
                "st_dev": 2,
                "st_nlink": 2,
                "st_uid": uid,
                "st_gid": gid,
                "st_size": 4096,
                "st_mtime_ns": 3,
                "st_ctime_ns": 4,
            },
        )()
        expected = module._EXPECTED_DIRECTORY_CHILDREN[path]
        with patch.object(module.os, "lstat", return_value=fake),              patch.object(module.os, "open", return_value=77),              patch.object(module.os, "fstat", return_value=fake),              patch.object(module.os, "listdir", return_value=sorted(expected)),              patch.object(module.os, "close"):
            self.assertEqual(
                module._require_directory(path, uid, gid, mode, expected),
                (path, uid, gid, mode),
            )

        with patch.object(module.os, "lstat", return_value=fake),              patch.object(module.os, "open", return_value=77),              patch.object(module.os, "fstat", return_value=fake),              patch.object(module.os, "listdir", return_value=["unexpected"]),              patch.object(module.os, "close"),              self.assertRaises(OSError):
            module._require_directory(path, uid, gid, mode, expected)

    def test_inert_systemd_requires_exact_dropins_no_linger_and_no_runtime(self):
        values = {
            ("omnilyzer-deployment-broker.service", "ActiveState"): "inactive",
            ("omnilyzer-deployment-executor.service", "ActiveState"): "inactive",
            ("omnilyzer-deployment-executor.socket", "ActiveState"): "inactive",
            (module._USER_MANAGER, "LoadState"): "loaded",
            (module._USER_MANAGER, "ActiveState"): "inactive",
            (
                "omnilyzer-deployment-executor.service",
                "DropInPaths",
            ): AUTHORITY.executor_socket_dropin,
            (module._USER_MANAGER, "DropInPaths"): AUTHORITY.cgroup_dropin,
        }

        def read(unit, prop):
            return values[(unit, prop)]

        with patch.object(module, "_read_systemctl", side_effect=read),              patch.object(module.os.path, "lexists", return_value=False),              patch.object(module.os, "lstat", side_effect=FileNotFoundError):
            self.assertEqual(
                module._require_inert_systemd(),
                ((AUTHORITY.executor_socket_dropin,), (AUTHORITY.cgroup_dropin,)),
            )

        with patch.object(module, "_read_systemctl", side_effect=read),              patch.object(
                 module.os.path,
                 "lexists",
                 side_effect=lambda p: p == module._LINGER_PATH,
             ),              self.assertRaises(OSError):
            module._require_inert_systemd()

    def test_one_observation_combines_independent_proofs(self):
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(
                 module,
                 "_require_package_host",
                 return_value=(
                     WORKFLOW,
                     (992,),
                     dependency_rows(),
                     package_rows(),
                     ("cpu", "io", "memory", "pids"),
                     executable_rows(),
                     bundle_evidence(),
                 ),
             ),              patch.object(module, "_require_subids", return_value=(subid_rows(), subid_rows())),              patch.object(
                 module,
                 "_require_static_assets",
                 return_value=(
                     AUTHORITY.provisioned_directories,
                     tuple(
                         (destination, digest, uid, gid, mode)
                         for _source, destination, digest, uid, gid, mode
                         in AUTHORITY.installed_assets
                     ),
                 ),
             ),              patch.object(
                 module,
                 "_require_inert_systemd",
                 return_value=(
                     (AUTHORITY.executor_socket_dropin,),
                     (AUTHORITY.cgroup_dropin,),
                 ),
             ):
            self.assertEqual(module._qualify_once(), evidence())

    def test_public_qualification_requires_two_identical_observations(self):
        first = evidence()
        with patch.object(module, "_qualify_once", side_effect=(first, first)) as once:
            self.assertEqual(module.qualify_rootless_docker_static_bootstrap(), first)
        self.assertEqual(once.call_count, 2)

        changed = evidence("b" * 40)
        with patch.object(module, "_qualify_once", side_effect=(first, changed)), self.assertRaises(
            module.RootlessDockerStaticBootstrapQualificationError
        ):
            module.qualify_rootless_docker_static_bootstrap()

    def test_public_qualification_collapses_private_failure(self):
        with patch.object(module, "_qualify_once", side_effect=OSError("private")), self.assertRaises(
            module.RootlessDockerStaticBootstrapQualificationError
        ) as caught:
            module.qualify_rootless_docker_static_bootstrap()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_source_is_strictly_read_only_and_independent_from_c32zz(self):
        source = (
            ROOT / "deployment/rootless_docker_static_bootstrap_qualification.py"
        ).read_text()
        self.assertNotIn("rootless_docker_static_bootstrap import", source)
        for forbidden in (
            "/usr/sbin/usermod",
            "enable-linger",
            "disable-linger",
            "daemon-reload",
            "os.mkdir",
            "os.chown",
            "os.chmod",
            "os.unlink",
            "os.rmdir",
            "renameat2",
            "/usr/bin/docker",
            "shell=True",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
