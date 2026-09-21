"""C31D read-only post-provision convergence qualification tests."""

import ast
from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

import deployment.application_manifest as c26
from deployment.application_source_set import DevApplicationSourceSet
import deployment.dev_host_qualification as c29
import deployment.dev_persistent_state_prerequisites as c31c
import deployment.dev_post_provision_qualification as module
import deployment.executor_service_config as c17
import deployment.host_provisioning_contract as c23
import deployment.python_environment_qualification as python_environment
import deployment.python_interpreter_provenance as c27
from deployment.tests.test_executor_service_config import configuration_values


ERROR = "DEV post-provision qualification is unavailable"


def fixtures():
    configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
    manifest = c26.DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", configuration.reviewed_commit,
        tuple(
            c26.ApplicationManifestEntry(item.repository_path, "a" * 64, "0644")
            for item in DevApplicationSourceSet().files
        ),
    )
    provisioning = c23.DevHostProvisioningContract(
        installation=configuration.installation_contract(),
    )
    return configuration, manifest, provisioning


def observations(configuration, manifest, provisioning):
    platform = c29.HostPlatformObservation(
        "Linux", "Ubuntu", "24.04", "x86_64", "amd64", "glibc 2.39",
    )
    groups = tuple(
        c29.HostGroupObservation(item.name, item.gid, "exact")
        for item in provisioning.group_requirements()
    )
    users = tuple(
        c29.HostUserObservation(
            item.name, item.uid, item.primary_gid,
            item.supplementary_gids, "exact",
        )
        for item in provisioning.user_requirements()
    )
    provenance = c27.DevPythonInterpreterProvenance()
    packages = tuple(
        c29.HostPackageObservation(
            item.package, item.version, item.architecture, "installed",
        )
        for item in provenance.packages
    )
    payload = tuple(
        item["observation"] for item in c29._load_payload(provenance)
    )
    application = c29.HostApplicationObservation(
        "/opt/omnilyzer/deployment/app", "exact",
        configuration.reviewed_commit,
        hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
    )
    persistent = (
        c31c.PersistentPrerequisiteEvidence(
            "/var/lib/omnilyzer/deployment/dev/state.json",
            "deployment_state", "verified-initial", 1,
        ),
        c31c.PersistentPrerequisiteEvidence(
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
            "replay_database", "verified", 1,
        ),
        c31c.PersistentPrerequisiteEvidence(
            "/var/log/omnilyzer/deployment/dev/events.jsonl",
            "audit_history", "pristine", 0,
        ),
    )
    return platform, groups, users, packages, payload, application, persistent


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.configuration, self.manifest, self.provisioning = fixtures()
        self.values = observations(
            self.configuration, self.manifest, self.provisioning,
        )

    def qualify(self, *, groups=None, users=None, managed=None,
                application=None, python=None, persistent=None):
        (
            platform, exact_groups, exact_users, packages, payload,
            exact_app, exact_persistent,
        ) = self.values
        managed_calls = []

        def observe_path(path, kind, mode, uid, gid, expected_bytes=None,
                         expected_sha256=None):
            managed_calls.append((path, expected_bytes, expected_sha256))
            if managed is not None:
                override = managed(path, kind, mode, uid, gid)
                if override is not None:
                    return override
            state = "absent" if path == module._SNAPSHOT_PATH else "exact"
            return c29.HostManagedPathObservation(
                path, kind, state, mode, uid, gid,
            )

        application_patch = (
            patch.object(module._c29, "_observe_application", side_effect=application)
            if isinstance(application, BaseException)
            else patch.object(module._c29, "_observe_application",
                              return_value=exact_app if application is None else application)
        )
        python_patch = (
            patch.object(module._python_environment,
                         "qualify_dev_python_environment", side_effect=python)
            if isinstance(python, BaseException)
            else patch.object(module._python_environment,
                              "qualify_dev_python_environment",
                              return_value=(python_environment.DevPythonEnvironmentEvidence()
                                            if python is None else python))
        )
        persistent_patch = (
            patch.object(module._c31c.DevPersistentStatePrerequisites,
                         "verify_persistent_prerequisites", side_effect=persistent)
            if isinstance(persistent, BaseException)
            else patch.object(module._c31c.DevPersistentStatePrerequisites,
                              "verify_persistent_prerequisites",
                              return_value=(exact_persistent if persistent is None
                                            else persistent))
        )
        with patch.object(module._c29, "_platform_observation", return_value=platform), \
             patch.object(module._c29, "_query_packages", return_value=packages), \
             patch.object(module._c29, "_observe_payload", return_value=payload), \
             patch.object(module._c29, "_observe_principals", return_value=(
                 exact_groups if groups is None else groups,
                 exact_users if users is None else users,
             )), \
             patch.object(module._c29, "_observe_managed_path", side_effect=observe_path), \
             application_patch, python_patch, persistent_patch:
            result = module.qualify_dev_provisioned_host(
                configuration=self.configuration,
                application_manifest=self.manifest,
            )
        return result, managed_calls

    def test_a_exact_post_provision_state_qualifies_read_only(self):
        result, calls = self.qualify()
        self.assertIs(type(result), module.DevPostProvisionEvidence)
        self.assertEqual(len(result.groups), 4)
        self.assertEqual(len(result.users), 2)
        self.assertEqual(len(result.payload_files), 658)
        self.assertEqual({item.state for item in result.managed_paths}, {"exact"})
        self.assertEqual(result.provisioning_snapshot.state, "absent")
        self.assertNotIn(
            "/run/omnilyzer/deployment/executor.sock",
            {item.path for item in result.managed_paths},
        )
        self.assertEqual(
            next(value for path, value, _digest in calls
                 if path == module._CONFIG_PATH),
            self.configuration.canonical_bytes(),
        )
        asset_digests = {
            path: digest for path, _value, digest in calls if digest is not None
        }
        self.assertEqual(asset_digests, {
            item.destination_path: item.sha256
            for item in self.provisioning.installed_asset_requirements()
        })

    def test_b_missing_group_and_wrong_user_memberships_fail_closed(self):
        groups = self.values[1]
        users = self.values[2]
        missing = dataclasses.replace(groups[0], state="absent")
        wrong_user = dataclasses.replace(users[0], supplementary_gids=())
        for changes in (
            {"groups": (missing, *groups[1:])},
            {"users": (dataclasses.replace(users[0], state="absent"), *users[1:])},
            {"users": (wrong_user, *users[1:])},
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                module.PostProvisionQualificationError, ERROR,
            ):
                self.qualify(**changes)

    def test_c_missing_or_wrong_managed_metadata_fails(self):
        targets = (
            "/opt/omnilyzer",
            module._CONFIG_PATH,
            self.provisioning.installed_asset_requirements()[0].destination_path,
        )
        for target in targets:
            def override(path, kind, mode, uid, gid, target=target):
                if path == target:
                    return c29.HostManagedPathObservation(
                        path, kind, "absent", mode, uid, gid,
                    )
                return None
            with self.subTest(target=target), self.assertRaisesRegex(
                module.PostProvisionQualificationError, ERROR,
            ):
                self.qualify(managed=override)
            def mismatch(path, kind, mode, uid, gid, target=target):
                if path == target:
                    raise OSError("content or metadata mismatch")
                return None
            with self.subTest(target=target, mismatch=True), self.assertRaisesRegex(
                module.PostProvisionQualificationError, ERROR,
            ):
                self.qualify(managed=mismatch)

    def test_d_application_mismatch_and_known_temporary_entry_fail(self):
        absent = dataclasses.replace(self.values[5], state="absent")
        with self.assertRaisesRegex(module.PostProvisionQualificationError, ERROR):
            self.qualify(application=absent)
        with self.assertRaisesRegex(module.PostProvisionQualificationError, ERROR):
            self.qualify(application=OSError("extra temp"))

    def test_e_python_persistent_and_snapshot_failures_reject_convergence(self):
        for target, values in (
            ("python", {"python": ValueError("python")}),
            ("persistent", {"persistent": ValueError("persistent")}),
        ):
            with self.subTest(target=target), self.assertRaisesRegex(
                module.PostProvisionQualificationError, ERROR,
            ):
                self.qualify(**values)

        def present(path, kind, mode, uid, gid):
            if path == module._SNAPSHOT_PATH:
                return c29.HostManagedPathObservation(
                    path, kind, "exact", mode, uid, gid,
                )
            return None
        with self.assertRaisesRegex(module.PostProvisionQualificationError, ERROR):
            self.qualify(managed=present)

    def test_f_fixed_error_control_flow_and_forged_evidence(self):
        with self.assertRaisesRegex(module.PostProvisionQualificationError, ERROR):
            module.qualify_dev_provisioned_host(
                configuration=object(), application_manifest=self.manifest,
            )
        for exception in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with patch.object(module._c29, "_platform_observation",
                              side_effect=exception), self.assertRaises(exception):
                module.qualify_dev_provisioned_host(
                    configuration=self.configuration,
                    application_manifest=self.manifest,
                )
        result, _calls = self.qualify()
        forged = object.__new__(module.DevPostProvisionEvidence)
        for field in dataclasses.fields(result):
            object.__setattr__(forged, field.name, getattr(result, field.name))
        object.__setattr__(forged, "groups", result.groups[1:])
        with self.assertRaisesRegex(ValueError, "evidence is invalid"):
            module.DevPostProvisionEvidence.__post_init__(
                forged, self.configuration, self.manifest,
            )
        forged_payload = object.__new__(module.DevPostProvisionEvidence)
        for field in dataclasses.fields(result):
            object.__setattr__(forged_payload, field.name, getattr(result, field.name))
        object.__setattr__(
            forged_payload, "payload_files",
            (result.payload_files[1], result.payload_files[0], *result.payload_files[2:]),
        )
        with self.assertRaisesRegex(ValueError, "evidence is invalid"):
            module.DevPostProvisionEvidence.__post_init__(
                forged_payload, self.configuration, self.manifest,
            )


class BoundaryTests(unittest.TestCase):
    def test_g_public_api_import_construction_and_nonactivation_boundary(self):
        self.assertEqual(module.__all__, (
            "PostProvisionQualificationError", "DevPostProvisionEvidence",
            "qualify_dev_provisioned_host",
        ))
        self.assertEqual(
            {name for name in vars(module) if not name.startswith("_")},
            set(module.__all__),
        )
        parameters = inspect.signature(module.qualify_dev_provisioned_host).parameters
        self.assertEqual(tuple(parameters), ("configuration", "application_manifest"))
        self.assertTrue(all(
            value.kind is inspect.Parameter.KEYWORD_ONLY
            for value in parameters.values()
        ))
        source = Path(module.__file__).read_text()
        imports = {
            (node.module or "").split(".")[0]
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom)
        }
        self.assertFalse(imports & {"socket", "subprocess"})
        for marker in ("systemctl", "docker", "daemon-reload", "requests"):
            self.assertNotIn(marker, source.lower())
        configuration, manifest, _provisioning = fixtures()
        with ExitStack() as stack:
            blocked = stack.enter_context(
                patch.object(socket, "socket", side_effect=AssertionError),
            )
            importlib.reload(module)
            module.DevPostProvisionEvidence
            blocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
