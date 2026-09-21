"""C31D closed 22-step provisioning orchestration tests."""

from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
import multiprocessing
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import deployment.application_manifest as c26
from deployment.application_source_set import DevApplicationSourceSet
import deployment.dev_host_provisioning_mechanics as c31b
import deployment.dev_host_provisioning_orchestration as module
import deployment.dev_host_qualification as c29
import deployment.dev_persistent_state_prerequisites as c31c
import deployment.dev_post_provision_qualification as post
import deployment.executor_service_config as c17
import deployment.host_provisioning_contract as c23
import deployment.installation_integrity_contract as c24
import deployment.pip_installer_provenance as c31p
import deployment.pip_installer_qualification as pip_qualification
import deployment.privileged_host_runtime as c30
import deployment.python_environment_qualification as python_environment
import deployment.python_interpreter_provenance as c27
import deployment.wheelhouse_qualification as c28
from deployment.tests.test_executor_service_config import configuration_values


ERROR = "DEV host provisioning orchestration is unavailable"


def fixtures():
    configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
    manifest = c26.DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", configuration.reviewed_commit,
        tuple(
            c26.ApplicationManifestEntry(item.repository_path, "a" * 64, "0644")
            for item in DevApplicationSourceSet().files
        ),
    )
    integrity = c24.DevInstallationIntegrityContract(configuration=configuration)
    provisioning = c23.DevHostProvisioningContract(
        installation=configuration.installation_contract(),
    )
    environment = integrity.python_environment_requirement()
    wheel_files = tuple(
        c28.WheelhouseFileEvidence(item.filename, item.sha256)
        for item in environment.wheels
    )
    wheels = c28.DevWheelhouseEvidence(
        "/staging/runtime-wheels", "sha256", wheel_files, environment,
    )
    installer = pip_qualification.DevPipInstallerEvidence(
        "/staging/pip-installer", "sha256",
        c31p.DevPipInstallerProvenance().artifact,
    )
    return configuration, manifest, integrity, provisioning, wheels, installer


def host_evidence(configuration, manifest, wheels, provisioning):
    platform = c29.HostPlatformObservation(
        "Linux", "Ubuntu", "24.04", "x86_64", "amd64", "glibc 2.39",
    )
    groups = tuple(
        c29.HostGroupObservation(item.name, item.gid, "absent")
        for item in provisioning.group_requirements()
    )
    users = tuple(
        c29.HostUserObservation(
            item.name, item.uid, item.primary_gid,
            item.supplementary_gids, "absent",
        )
        for item in provisioning.user_requirements()
    )
    paths = tuple(
        c29.HostManagedPathObservation(
            item.path, item.kind, "absent", item.mode,
            item.owner_uid, item.group_gid,
        )
        for item in (
            *provisioning.path_requirements(),
            *provisioning.runtime_resource_requirements(),
        )
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
        "/opt/omnilyzer/deployment/app", "absent",
        configuration.reviewed_commit,
        hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
    )
    return c29.DevHostQualificationEvidence(
        platform, groups, users, paths, packages, payload, application,
        wheels.wheelhouse_path, wheels.files, c29._PAYLOAD_SHA256,
    )


def post_evidence(configuration, manifest, provisioning):
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
    paths, directories, assets = post._managed_requirements(provisioning)
    managed = tuple(
        c29.HostManagedPathObservation(
            item.path, item.kind, "exact", item.mode,
            item.owner_uid, item.group_gid,
        )
        for item in (*paths, *directories)
    ) + tuple(
        c29.HostManagedPathObservation(
            item.destination_path, "regular_file", "exact", item.mode,
            item.owner_uid, item.group_gid,
        )
        for item in assets
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
    digest = hashlib.sha256(manifest.canonical_bytes()).hexdigest()
    application = c29.HostApplicationObservation(
        "/opt/omnilyzer/deployment/app", "exact",
        configuration.reviewed_commit, digest,
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
    snapshot = c29.HostManagedPathObservation(
        post._SNAPSHOT_PATH, "directory", "absent", 0o700, 0, 0,
    )
    return post.DevPostProvisionEvidence(
        configuration.reviewed_commit, digest, platform, groups, users,
        managed, packages, payload, application,
        python_environment.DevPythonEnvironmentEvidence(), persistent,
        snapshot, c29._PAYLOAD_SHA256, configuration, manifest,
    )


class FakeRuntime:
    def __init__(self, events):
        self.events = events

    def create_required_group(self, name):
        self.events.append(("group", name))
        return c30.HostMutationEvidence("group", name, "created")

    def create_required_user(self, name):
        self.events.append(("user", name))
        return c30.HostMutationEvidence("user", name, "created")

    def create_required_directory(self, path):
        self.events.append(("directory", path))
        return c30.HostMutationEvidence("directory", path, "created")

    def install_executor_configuration(self):
        self.events.append(("configuration", module._CONFIG_PATH))
        return c30.HostMutationEvidence(
            "regular_file", module._CONFIG_PATH, "created",
        )

    def install_required_asset(self, destination):
        self.events.append(("asset", destination))
        return c30.HostMutationEvidence("regular_file", destination, "created")


class FakeMechanics:
    def __init__(self, events, configuration, manifest, fail_python=False):
        self.events = events
        self.configuration = configuration
        self.manifest = manifest
        self.fail_python = fail_python

    def materialize_application_tree(self, **values):
        self.events.append(("application", values))
        return c31b.ApplicationMaterializationEvidence(
            "/opt/omnilyzer/deployment/app",
            self.configuration.reviewed_commit,
            hashlib.sha256(self.manifest.canonical_bytes()).hexdigest(),
            28, "materialized",
        )

    def construct_python_environment(self, **values):
        self.events.append(("python", values))
        if self.fail_python:
            raise c31b.ProvisioningMechanicsError(
                "DEV host provisioning mechanics are unavailable",
            )
        return python_environment.DevPythonEnvironmentEvidence()


class FakePersistent:
    def __init__(self, events):
        self.events = events

    def initialize_deployment_state(self):
        self.events.append(("state",))
        return c31c.PersistentPrerequisiteEvidence(
            "/var/lib/omnilyzer/deployment/dev/state.json",
            "deployment_state", "initialized", 1,
        )

    def initialize_replay(self):
        self.events.append(("replay",))
        return c31c.PersistentPrerequisiteEvidence(
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
            "replay_database", "initialized", 1,
        )

    def prepare_audit(self):
        self.events.append(("audit",))
        return c31c.PersistentPrerequisiteEvidence(
            "/var/log/omnilyzer/deployment/dev/events.jsonl",
            "audit_history", "pristine", 0,
        )


def process_lock_contender(path, result):
    try:
        value = module._acquire_process_lock(path)
    except OSError:
        result.put("blocked")
    else:
        module._release_process_lock(value)
        result.put("acquired")


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        values = fixtures()
        (self.configuration, self.manifest, self.integrity,
         self.provisioning, self.wheels, self.installer) = values
        self.host = host_evidence(
            self.configuration, self.manifest, self.wheels, self.provisioning,
        )
        self.post = post_evidence(
            self.configuration, self.manifest, self.provisioning,
        )
        self.events = []
        self.value = module.DevHostProvisioningOrchestrator(
            configuration=self.configuration,
        )
        authority = object.__getattribute__(self.value, "_authority")
        object.__setattr__(self.value, "_authority", dataclasses.replace(
            authority,
            runtime=FakeRuntime(self.events),
            mechanics=FakeMechanics(
                self.events, self.configuration, self.manifest,
            ),
            persistent=FakePersistent(self.events),
        ))

    def invoke(self, post_values=None, c29_value=None, snapshot_state="absent"):
        if post_values is None:
            post_values = (
                post.PostProvisionQualificationError(
                    "DEV post-provision qualification is unavailable",
                ),
                self.post,
            )
        post_iterator = iter(post_values)

        def post_call(**_values):
            self.events.append(("post",))
            value = next(post_iterator)
            if isinstance(value, BaseException):
                raise value
            return value

        def generated(**values):
            self.events.append(("manifest", values))
            return self.manifest

        def wheels(**values):
            self.events.append(("wheels", values))
            return self.wheels

        def installer(**values):
            self.events.append(("installer", values))
            return self.installer

        def host(**values):
            self.events.append(("c29", values))
            if isinstance(c29_value, BaseException):
                raise c29_value
            return self.host if c29_value is None else c29_value

        def observe_snapshot(path, kind, mode, owner_uid, group_gid):
            self.events.append(("snapshot", path))
            return c29.HostManagedPathObservation(
                path, kind, snapshot_state, mode, owner_uid, group_gid,
            )

        with patch.object(module, "_acquire_process_lock", return_value=object()), \
             patch.object(module, "_release_process_lock"), \
             patch.object(module._c26, "generate_dev_application_manifest",
                          side_effect=generated), \
             patch.object(module._c28, "qualify_dev_wheelhouse", side_effect=wheels), \
             patch.object(module._pip_qualification,
                          "qualify_dev_pip_installer", side_effect=installer), \
             patch.object(module._c29, "qualify_dev_host", side_effect=host), \
             patch.object(module._c29, "_observe_managed_path",
                          side_effect=observe_snapshot), \
             patch.object(module._post, "qualify_dev_provisioned_host",
                          side_effect=post_call):
            return self.value.provision(
                repository_root="/reviewed/repository",
                wheelhouse_path=self.wheels.wheelhouse_path,
                pip_installer_staging=self.installer.staging_directory,
            )

    def test_a_exact_initial_twenty_two_step_composition(self):
        result = self.invoke()
        self.assertEqual(result.operation, "initial-provisioning")
        self.assertEqual(
            tuple(item.sequence for item in result.completed_steps),
            tuple(range(1, 23)),
        )
        self.assertEqual(result.plan_steps[-1].boundary, "C31D")
        names = [item[0] for item in self.events]
        self.assertLess(names.index("wheels"), names.index("c29"))
        self.assertLess(names.index("installer"), names.index("c29"))
        self.assertLess(names.index("c29"), names.index("group"))
        self.assertEqual(names.count("python"), 1)
        self.assertEqual(names[-4:], ["state", "replay", "audit", "post"])
        self.assertEqual(
            [item[1] for item in self.events if item[0] == "group"],
            [item.name for item in self.provisioning.group_requirements()],
        )
        self.assertEqual(
            [item[1] for item in self.events if item[0] == "user"],
            [item.name for item in self.provisioning.user_requirements()],
        )
        self.assertEqual(
            [item[1] for item in self.events if item[0] == "directory"],
            [item.path for item in module._directory_requirements(self.provisioning)],
        )
        self.assertEqual(
            [item[1] for item in self.events if item[0] == "asset"],
            [item.destination_path
             for item in self.provisioning.installed_asset_requirements()],
        )
        python_call = next(item[1] for item in self.events if item[0] == "python")
        self.assertIs(python_call["host_qualification"], self.host)
        self.assertEqual(python_call["repository_root"], "/reviewed/repository")

    def test_b_already_converged_precheck_returns_without_mutation(self):
        result = self.invoke(post_values=(self.post,))
        self.assertEqual(result.operation, "already-converged")
        self.assertEqual(
            tuple(item.sequence for item in result.completed_steps),
            (1, 2, 3, 22),
        )
        self.assertEqual([item[0] for item in self.events], ["manifest", "post"])

    def test_c_partial_state_c29_failure_permits_no_mutation(self):
        with self.assertRaisesRegex(module.ProvisioningOrchestrationError, ERROR):
            self.invoke(c29_value=c29.HostQualificationError(
                "DEV host qualification is unavailable",
            ))
        names = [item[0] for item in self.events]
        self.assertEqual(names, ["manifest", "post", "wheels", "installer", "c29"])

    def test_c_leftover_snapshot_fails_before_mutation(self):
        with self.assertRaisesRegex(module.ProvisioningOrchestrationError, ERROR):
            self.invoke(snapshot_state="exact")
        mutation = {
            "group", "user", "directory", "application", "configuration",
            "asset", "python", "state", "replay", "audit",
        }
        self.assertFalse(any(item[0] in mutation for item in self.events))

    def test_d_c31b_failure_records_no_grouped_or_later_steps(self):
        authority = object.__getattribute__(self.value, "_authority")
        object.__setattr__(self.value, "_authority", dataclasses.replace(
            authority,
            mechanics=FakeMechanics(
                self.events, self.configuration, self.manifest,
                fail_python=True,
            ),
        ))
        recorded = []
        real_step = module._step

        def step(sequence, outcome):
            recorded.append(sequence)
            return real_step(sequence, outcome)

        with patch.object(module, "_step", side_effect=step):
            with self.assertRaisesRegex(module.ProvisioningOrchestrationError, ERROR):
                self.invoke()
        self.assertNotIn(14, recorded)
        self.assertFalse({14, 15, 16, 17, 18, 19, 20, 21, 22} & set(recorded))
        self.assertNotIn("state", [item[0] for item in self.events])

    def test_e_fixed_inputs_errors_and_control_exceptions(self):
        with self.assertRaisesRegex(module.ProvisioningOrchestrationError, ERROR):
            self.value.provision(
                repository_root="relative", wheelhouse_path="/wheels",
                pip_installer_staging="/installer",
            )
        with patch.object(module, "_acquire_process_lock", return_value=object()), \
             patch.object(module, "_release_process_lock"), \
             patch.object(module._c26, "generate_dev_application_manifest",
                          side_effect=KeyboardInterrupt), \
             self.assertRaises(KeyboardInterrupt):
            self.value.provision(
                repository_root="/repository", wheelhouse_path="/wheels",
                pip_installer_staging="/installer",
            )

    def test_f_same_instance_and_cross_process_invocations_are_nonblocking(self):
        local = object.__getattribute__(self.value, "_lock")
        local.acquire()
        try:
            with self.assertRaisesRegex(module.ProvisioningOrchestrationError, ERROR):
                self.value.provision(
                    repository_root="/repository", wheelhouse_path="/wheels",
                    pip_installer_staging="/installer",
                )
        finally:
            local.release()

        with tempfile.TemporaryDirectory(prefix="task014-c31d-lock-") as temporary:
            path = Path(temporary) / "python3.12"
            path.write_bytes(b"lock anchor")
            held = module._acquire_process_lock(str(path))
            context = multiprocessing.get_context("fork")
            results = context.Queue()
            process = context.Process(
                target=process_lock_contender, args=(str(path), results),
            )
            process.start(); process.join(timeout=5)
            self.assertFalse(process.is_alive())
            self.assertEqual(results.get(timeout=1), "blocked")
            module._release_process_lock(held)
            process = context.Process(
                target=process_lock_contender, args=(str(path), results),
            )
            process.start(); process.join(timeout=5)
            self.assertFalse(process.is_alive())
            self.assertEqual(results.get(timeout=1), "acquired")

    def test_g_failure_at_every_sequence_position_stops_later_steps(self):
        real_step = module._step
        for target in range(1, 23):
            with self.subTest(sequence=target):
                self.setUp()
                recorded = []

                def fail_at(sequence, outcome):
                    recorded.append(sequence)
                    if sequence == target:
                        raise OSError("step failure")
                    return real_step(sequence, outcome)

                with patch.object(module, "_step", side_effect=fail_at):
                    with self.assertRaisesRegex(
                        module.ProvisioningOrchestrationError, ERROR,
                    ):
                        self.invoke()
                self.assertIn(target, recorded)
                self.assertFalse(any(sequence > target for sequence in recorded))
                self.assertFalse(any(
                    item[0] in ("remove", "reset", "rollback")
                    for item in self.events
                ))


class BoundaryTests(unittest.TestCase):
    def test_h_public_api_construction_inert_and_no_activation_authority(self):
        self.assertEqual(module.__all__, (
            "ProvisioningOrchestrationError", "ProvisioningStepEvidence",
            "DevHostProvisioningEvidence", "DevHostProvisioningOrchestrator",
        ))
        self.assertEqual(
            {name for name in vars(module) if not name.startswith("_")},
            set(module.__all__),
        )
        self.assertEqual(
            tuple(inspect.signature(
                module.DevHostProvisioningOrchestrator.provision,
            ).parameters),
            ("self", "repository_root", "wheelhouse_path",
             "pip_installer_staging"),
        )
        configuration, _manifest, *_rest = fixtures()
        with ExitStack() as stack:
            blocked = [
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                for owner, name in (
                    (os, "open"), (subprocess, "Popen"),
                    (subprocess, "run"), (socket, "socket"),
                )
            ]
            importlib.reload(module)
            module.DevHostProvisioningOrchestrator(configuration=configuration)
            for value in blocked:
                value.assert_not_called()
        source = Path(module.__file__).read_text().lower()
        for marker in ("systemctl", "daemon-reload", "docker", "registry"):
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
