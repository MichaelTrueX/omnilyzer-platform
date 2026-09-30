"""Tests for C33D rootless Docker user-manager qualification."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import stat
import unittest
from unittest.mock import patch

from deployment import rootless_docker_user_manager_qualification as module
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
    for index, (package, path) in enumerate(module.staticq.postinstall._REQUIRED_EXECUTABLES):
        sha256 = (
            AUTHORITY.vendor_rootless_script_sha256
            if path == AUTHORITY.vendor_rootless_script
            else format(index + 1, "064x")
        )
        values.append(
            (
                package,
                path,
                module.staticq.postinstall._EXECUTABLE_MODES[path],
                sha256,
            )
        )
    return tuple(values)


def subids():
    return (
        ("ysabel", 100000, 65536),
        ("trust", 165536, 65536),
        ("ayeshia", 231072, 65536),
        ("jane", 296608, 65536),
        ("omnidev", 362144, 65536),
        ("omnigpt", 427680, 65536),
        (AUTHORITY.executor_user, AUTHORITY.subuid_start, AUTHORITY.subordinate_count),
    )


def package_host():
    return (
        WORKFLOW,
        (992,),
        dependency_rows(),
        package_rows(),
        ("cpu", "io", "memory", "pids"),
        executable_rows(),
        bundle_evidence(),
    )


def evidence(workflow=WORKFLOW):
    return module.RootlessDockerUserManagerEvidence(
        application_reviewed_commit=module.staticq.TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=workflow,
        linger_path=module._LINGER_PATH,
        linger_mode=0o644,
        runtime_directory=AUTHORITY.runtime_directory,
        runtime_uid=AUTHORITY.executor_uid,
        runtime_gid=AUTHORITY.executor_gid,
        runtime_mode=0o700,
        user_manager=module._USER_MANAGER,
        user_manager_control_group="/user.slice/user-991.slice/user@991.service",
        delegate_controllers=("cpu", "memory", "pids"),
        rootless_user_unit=module._USER_UNIT,
        rootless_user_unit_state=("loaded", "inactive", "disabled"),
        subuid_records=subids(),
        subgid_records=subids(),
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
        user_manager_dropins=module.staticq._expected_user_manager_dropins(),
        bundle=bundle_evidence(),
    )


class RootlessDockerUserManagerQualificationTests(unittest.TestCase):
    def test_evidence_is_exact_and_immutable(self):
        value = evidence()
        with self.assertRaises(FrozenInstanceError):
            value.runtime_mode = 0o755
        values = {name: getattr(value, name) for name in value.__dataclass_fields__}
        for field, bad in (
            ("expected_workflow_sha", "0" * 40),
            ("linger_mode", 0o777),
            ("rootless_user_unit_state", ("loaded", "active", "enabled")),
            ("subuid_records", value.subuid_records[:-1]),
            ("critical_executables", value.critical_executables[:-1]),
            ("delegate_controllers", ("cpu", "memory")),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.RootlessDockerUserManagerEvidence(
                    **(values | {field: bad})
                )

    def test_linger_gate_requires_exact_marker_and_logind_identity(self):
        value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644,
            st_nlink=1,
            st_uid=0,
            st_gid=0,
            st_size=0,
        )
        reads = {"Linger": "yes", "UID": "991", "Name": AUTHORITY.executor_user}
        with patch.object(module.os, "lstat", return_value=value),              patch.object(
                 module, "_read_loginctl", side_effect=lambda name: reads[name]
             ):
            self.assertEqual(module._linger_evidence(), 0o644)

        reads["Linger"] = "no"
        with patch.object(module.os, "lstat", return_value=value),              patch.object(
                 module, "_read_loginctl", side_effect=lambda name: reads[name]
             ), self.assertRaises(OSError):
            module._linger_evidence()

    def test_runtime_gate_requires_exact_uid_gid_mode(self):
        value = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_ino=10,
            st_dev=20,
            st_uid=991,
            st_gid=991,
        )
        with patch.object(module.os, "lstat", return_value=value),              patch.object(module.os, "open", return_value=77),              patch.object(module.os, "fstat", return_value=value),              patch.object(module.os, "close"):
            self.assertEqual(
                module._runtime_evidence(),
                (AUTHORITY.runtime_directory, 991, 991, 0o700),
            )

        wrong = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755,
            st_ino=10,
            st_dev=20,
            st_uid=991,
            st_gid=991,
        )
        with patch.object(module.os, "lstat", return_value=wrong), self.assertRaises(OSError):
            module._runtime_evidence()

    def test_user_manager_gate_requires_delegation_and_rootless_unit_inactive(self):
        values = {
            (module._USER_MANAGER, "LoadState"): "loaded",
            (module._USER_MANAGER, "ActiveState"): "active",
            (module._USER_RUNTIME, "LoadState"): "loaded",
            (module._USER_RUNTIME, "ActiveState"): "active",
            (module._USER_MANAGER, "ControlGroup"):
                "/user.slice/user-991.slice/user@991.service",
            (module._USER_MANAGER, "Delegate"): "yes",
            (module._USER_MANAGER, "DelegateControllers"): "cpu memory pids",
        }
        user = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "UnitFileState": "disabled",
        }
        cgroup_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)
        with patch.object(
            module, "_read_systemctl", side_effect=lambda u, p: values[(u, p)]
        ), patch.object(
            module, "_read_loginctl", return_value=AUTHORITY.runtime_directory
        ), patch.object(
            module, "_read_user_systemctl", side_effect=lambda p: user[p]
        ), patch.object(
            module.os, "lstat", return_value=cgroup_dir
        ), patch.object(
            module,
            "_read_cgroup_tokens",
            return_value=frozenset({"cpu", "memory", "pids"}),
        ):
            self.assertEqual(
                module._require_user_manager(),
                (
                    "/user.slice/user-991.slice/user@991.service",
                    ("cpu", "memory", "pids"),
                ),
            )

        user["ActiveState"] = "active"
        with patch.object(
            module, "_read_systemctl", side_effect=lambda u, p: values[(u, p)]
        ), patch.object(
            module, "_read_loginctl", return_value=AUTHORITY.runtime_directory
        ), patch.object(
            module, "_read_user_systemctl", side_effect=lambda p: user[p]
        ), patch.object(
            module.os, "lstat", return_value=cgroup_dir
        ), patch.object(
            module,
            "_read_cgroup_tokens",
            return_value=frozenset({"cpu", "memory", "pids"}),
        ), self.assertRaises(OSError):
            module._require_user_manager()

    def test_one_observation_combines_static_and_user_manager_proofs(self):
        runtime = (AUTHORITY.runtime_directory, 991, 991, 0o700)
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)),              patch.object(module, "_package_host", return_value=package_host()),              patch.object(module.staticq, "_require_subids", return_value=(subids(), subids())),              patch.object(
                 module.staticq,
                 "_require_static_assets",
                 return_value=(
                     AUTHORITY.provisioned_directories,
                     tuple(
                         (destination, digest, uid, gid, mode)
                         for _source, destination, digest, uid, gid, mode
                         in AUTHORITY.installed_assets
                     ),
                 ),
             ),              patch.object(module.staticq, "_require_user_manager_template_dropins"),              patch.object(
                 module.staticq,
                 "_read_systemctl",
                 side_effect=lambda u, p: (
                     AUTHORITY.executor_socket_dropin
                     if u == "omnilyzer-deployment-executor.service"
                     else " ".join(module.staticq._expected_user_manager_dropins())
                 ),
             ),              patch.object(module, "_read_systemctl", return_value="inactive"),              patch.object(module, "_linger_evidence", return_value=0o644),              patch.object(module, "_runtime_evidence", return_value=runtime),              patch.object(
                 module,
                 "_require_user_manager",
                 return_value=(
                     "/user.slice/user-991.slice/user@991.service",
                     ("cpu", "memory", "pids"),
                 ),
             ),              patch.object(module, "_require_rootless_inactive"),              patch.object(
                 module,
                 "_read_user_systemctl",
                 side_effect=lambda p: {
                     "LoadState": "loaded",
                     "ActiveState": "inactive",
                     "UnitFileState": "disabled",
                 }[p],
             ):
            self.assertEqual(module._qualify_once(), evidence())

    def test_public_boundary_requires_two_identical_observations(self):
        first = evidence()
        with patch.object(module, "_qualify_once", side_effect=(first, first)) as once:
            self.assertEqual(module.qualify_rootless_docker_user_manager(), first)
        self.assertEqual(once.call_count, 2)

        changed = evidence("b" * 40)
        with patch.object(module, "_qualify_once", side_effect=(first, changed)),              self.assertRaises(module.RootlessDockerUserManagerQualificationError):
            module.qualify_rootless_docker_user_manager()

    def test_public_boundary_collapses_private_failure(self):
        with patch.object(module, "_qualify_once", side_effect=OSError("private")),              self.assertRaises(module.RootlessDockerUserManagerQualificationError) as caught:
            module.qualify_rootless_docker_user_manager()
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_source_is_read_only_and_independent_from_c33c(self):
        source = (
            ROOT / "deployment/rootless_docker_user_manager_qualification.py"
        ).read_text()
        self.assertNotIn("rootless_docker_user_manager_bootstrap import", source)
        for forbidden in (
            "enable-linger",
            "disable-linger",
            '"start"',
            '"enable"',
            "os.mkdir",
            "os.chown",
            "os.chmod",
            "os.unlink",
            "os.rename",
            "/usr/bin/docker",
            "shell=True",
            "__main__",
            "argparse",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
