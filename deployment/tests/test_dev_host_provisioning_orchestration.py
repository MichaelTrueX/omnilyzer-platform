"""C31D closed 22-step provisioning orchestration tests."""

from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
import os
from pathlib import Path
import socket
import subprocess
import sys
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
from deployment.tests.test_dev_host_provisioning_mechanics import repository_fixture, git


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
            "/var/lib/omnilyzer/deployment/audit/events.jsonl",
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
                "snapshot-preparation",
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
            "/var/lib/omnilyzer/deployment/audit/events.jsonl",
            "audit_history", "pristine", 0,
        )


def independent_lock_attempt(path):
    repository = str(Path(module.__file__).resolve().parents[1])
    source = """
import sys
sys.path.insert(0, sys.argv[1])
from deployment.dev_host_provisioning_orchestration import (
    _acquire_process_lock, _release_process_lock,
)
try:
    held = _acquire_process_lock(sys.argv[2])
except OSError:
    raise SystemExit(23)
_release_process_lock(held)
"""
    return subprocess.run(
        (sys.executable, "-I", "-c", source, repository, str(path)),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False, close_fds=True, timeout=5, check=False,
    )


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

    def invoke(self, post_values=None, c29_value=None, snapshot_state="absent",
               release_error=None):
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
             patch.object(module, "_release_process_lock",
                          side_effect=release_error), \
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

    def assert_failure(self, expected_last, expected_failed, mutation_started,
                       invoke=None):
        with self.assertRaises(module.ProvisioningOrchestrationError) as caught:
            (invoke or self.invoke)()
        error = caught.exception
        self.assertEqual(str(error), ERROR)
        evidence = error.evidence
        self.assertIs(type(evidence), module.ProvisioningFailureEvidence)
        self.assertEqual(evidence.last_completed_sequence, expected_last)
        self.assertIs(evidence.failed_step, module._c31a._STEPS[expected_failed - 1])
        self.assertEqual(evidence.mutation_started, mutation_started)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            evidence.mutation_started = False
        self.assertNotIn("secret", repr(evidence))

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

    def test_converged_lock_release_failure_reports_no_mutation(self):
        self.assert_failure(22, 22, False, lambda: self.invoke(
            post_values=(self.post,),
            release_error=OSError("secret lock detail"),
        ))
        self.assertEqual([item[0] for item in self.events], ["manifest", "post"])

    def test_c_partial_state_c29_failure_permits_no_mutation(self):
        self.assert_failure(6, 7, False, lambda: self.invoke(
            c29_value=c29.HostQualificationError("secret preflight detail"),
        ))
        names = [item[0] for item in self.events]
        self.assertEqual(names, ["manifest", "post", "wheels", "installer", "c29"])

    def test_c_retained_exact_previous_config_blocks_current_c29(self):
        previous = c17.DevExecutorServiceConfiguration(**configuration_values(
            reviewed_commit="c8646e1ef72f0cbab4878d383f7765f07aef8417",
        ))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "executor.json"
            path.write_bytes(previous.canonical_bytes())
            path.chmod(0o640)
            with self.assertRaises(OSError):
                c29._observe_managed_path(
                    str(path), "regular_file", 0o640, os.getuid(), os.getgid(),
                    self.configuration.canonical_bytes(),
                )
            self.assertEqual(c29._observe_managed_path(
                str(path), "regular_file", 0o640, os.getuid(), os.getgid(),
                previous.canonical_bytes(),
            ).state, "exact")
            path.chmod(0o600)
            with self.assertRaises(OSError):
                c29._observe_managed_path(
                    str(path), "regular_file", 0o640, os.getuid(), os.getgid(),
                    previous.canonical_bytes(),
                )
            path.chmod(0o640)
            with self.assertRaises(OSError):
                c29._observe_managed_path(
                    str(path), "regular_file", 0o640, os.getuid() + 1,
                    os.getgid(), previous.canonical_bytes(),
                )
            path.unlink()
            target = Path(directory) / "target"
            target.write_bytes(previous.canonical_bytes())
            path.symlink_to(target)
            with self.assertRaises(OSError):
                c29._observe_managed_path(
                    str(path), "regular_file", 0o640, os.getuid(), os.getgid(),
                    previous.canonical_bytes(),
                )
            path.unlink()
            self.assertEqual(c29._observe_managed_path(
                str(path), "regular_file", 0o640, os.getuid(), os.getgid(),
                self.configuration.canonical_bytes(),
            ).state, "absent")
            path.write_bytes(self.configuration.canonical_bytes())
            path.chmod(0o640)
            self.assertEqual(c29._observe_managed_path(
                str(path), "regular_file", 0o640, os.getuid(), os.getgid(),
                self.configuration.canonical_bytes(),
            ).state, "exact")

    def test_c_pinned_recovery_qualifies_previous_config_and_identical_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, previous, previous_manifest = repository_fixture(directory)
            prior_commit = previous.reviewed_commit
            (repository / "recovery-note.txt").write_text("reviewed change\n")
            git(repository, "add", "recovery-note.txt")
            git(repository, "commit", "--quiet", "-m", "recovery")
            current_commit = git(repository, "rev-parse", "HEAD").decode().strip()
            current = c17.DevExecutorServiceConfiguration(**configuration_values(
                reviewed_commit=current_commit,
            ))
            manifest = c26.generate_dev_application_manifest(
                repository_root=str(repository), reviewed_commit=current_commit,
            )
            config_path = Path(directory) / "executor.json"
            config_path.write_bytes(previous.canonical_bytes())
            config_path.chmod(0o640)
            qualified = object()
            original_output = c26._output
            def output_without_predecessor(root, arguments, maximum):
                if prior_commit in arguments:
                    raise AssertionError("predecessor Git object was requested")
                return original_output(root, arguments, maximum)
            def qualify_previous(**values):
                observed = c29._observe_managed_path(
                    str(config_path), "regular_file", 0o640,
                    os.getuid(), os.getgid(),
                    values["configuration"].canonical_bytes(),
                )
                self.assertEqual(observed.state, "exact")
                return qualified
            with patch.object(module, "_CONFIG_PATH", str(config_path)), \
                 patch.object(module, "_RECOVERY_COMMIT", prior_commit), \
                 patch.object(module, "_RECOVERY_BASE_COMMIT", prior_commit), \
                 patch.object(module, "_RECOVERY_CONFIG_SHA256",
                              hashlib.sha256(previous.canonical_bytes()).hexdigest()), \
                 patch.object(module, "_RECOVERY_MANIFEST_SHA256",
                              hashlib.sha256(previous_manifest.canonical_bytes()).hexdigest()), \
                 patch.object(c26, "_output", side_effect=output_without_predecessor), \
                 patch.object(c29, "qualify_dev_host", side_effect=qualify_previous) as qualify:
                self.assertIs(module._qualify_reviewed_recovery(
                    current, manifest, self.wheels, str(repository),
                ), qualified)
                args = qualify.call_args.kwargs
                self.assertEqual(args["configuration"].canonical_bytes(),
                                 previous.canonical_bytes())
                self.assertEqual(args["application_manifest"].reviewed_commit,
                                 prior_commit)
                self.assertEqual(args["application_manifest"].entries,
                                 manifest.entries)

                shallow = Path(directory) / "shallow"
                git(repository, "clone", "--quiet", "--depth=1",
                    "file://" + str(repository), str(shallow))
                with self.assertRaises(subprocess.CalledProcessError):
                    git(shallow, "cat-file", "-e", prior_commit)
                shallow_manifest = c26.generate_dev_application_manifest(
                    repository_root=str(shallow), reviewed_commit=current_commit,
                )
                self.assertEqual(shallow_manifest.entries, manifest.entries)
                self.assertIs(module._qualify_reviewed_recovery(
                    current, shallow_manifest, self.wheels, str(shallow),
                ), qualified)

                tree = git(repository, "rev-parse", current_commit + "^{tree}").decode().strip()
                merge_commit = git(
                    repository, "commit-tree", tree, "-p", current_commit,
                    "-p", prior_commit, "-m", "recovery merge",
                ).decode().strip()
                git(repository, "reset", "--hard", merge_commit)
                merge_current = c17.DevExecutorServiceConfiguration(**configuration_values(
                    reviewed_commit=merge_commit,
                ))
                merge_manifest = c26.generate_dev_application_manifest(
                    repository_root=str(repository), reviewed_commit=merge_commit,
                )
                self.assertIs(module._qualify_reviewed_recovery(
                    merge_current, merge_manifest, self.wheels, str(repository),
                ), qualified)
                git(repository, "reset", "--hard", current_commit)
                qualify.reset_mock()

                with patch.object(module, "_RECOVERY_MANIFEST_SHA256", "0" * 64):
                    with self.assertRaises(OSError):
                        module._qualify_reviewed_recovery(
                            current, manifest, self.wheels, str(repository),
                        )
                qualify.assert_not_called()

                with patch.object(module, "_RECOVERY_BASE_COMMIT", "0" * 40):
                    with self.assertRaises(OSError):
                        module._qualify_reviewed_recovery(
                            current, manifest, self.wheels, str(repository),
                        )
                qualify.assert_not_called()

                (repository / "unrelated-note.txt").write_text("unrelated change\n")
                git(repository, "add", "unrelated-note.txt")
                git(repository, "commit", "--quiet", "-m", "unrelated")
                unrelated_commit = git(repository, "rev-parse", "HEAD").decode().strip()
                unrelated_current = c17.DevExecutorServiceConfiguration(**configuration_values(
                    reviewed_commit=unrelated_commit,
                ))
                unrelated_manifest = c26.generate_dev_application_manifest(
                    repository_root=str(repository), reviewed_commit=unrelated_commit,
                )
                with self.assertRaises(OSError):
                    module._qualify_reviewed_recovery(
                        unrelated_current, unrelated_manifest, self.wheels, str(repository),
                    )
                qualify.assert_not_called()

                config_path.write_bytes(previous.canonical_bytes() + b" ")
                with self.assertRaises(OSError):
                    module._qualify_reviewed_recovery(
                        current, manifest, self.wheels, str(repository),
                    )
                config_path.write_bytes(previous.canonical_bytes())
                config_path.chmod(0o600)
                with self.assertRaises(OSError):
                    module._qualify_reviewed_recovery(
                        current, manifest, self.wheels, str(repository),
                    )
                config_path.chmod(0o640)
                unrelated = c17.DevExecutorServiceConfiguration(**configuration_values(
                    reviewed_commit="b" * 40,
                ))
                config_path.write_bytes(unrelated.canonical_bytes())
                with self.assertRaises(OSError):
                    module._qualify_reviewed_recovery(
                        current, manifest, self.wheels, str(repository),
                    )
                config_path.write_bytes(previous.canonical_bytes())
                config_path.unlink()
                config_path.symlink_to(Path(directory) / "other")
                with self.assertRaises(OSError):
                    module._qualify_reviewed_recovery(
                        current, manifest, self.wheels, str(repository),
                    )
                config_path.unlink()
                config_path.write_bytes(previous.canonical_bytes())
                git(repository, "reset", "--hard", prior_commit)
                selected = repository / DevApplicationSourceSet().files[0].repository_path
                selected.write_bytes(b"changed selected bytes\n")
                git(repository, "add", ".")
                git(repository, "commit", "--quiet", "-m", "changed application")
                changed_commit = git(repository, "rev-parse", "HEAD").decode().strip()
                changed = c17.DevExecutorServiceConfiguration(**configuration_values(
                    reviewed_commit=changed_commit,
                ))
                changed_manifest = c26.generate_dev_application_manifest(
                    repository_root=str(repository), reviewed_commit=changed_commit,
                )
                self.assertEqual(
                    git(repository, "rev-list", "--parents", "-n", "1", changed_commit)
                    .decode().split(), [changed_commit, prior_commit],
                )
                self.assertNotEqual(changed_manifest.entries, manifest.entries)
                qualify.reset_mock()
                with self.assertRaises(OSError):
                    module._qualify_reviewed_recovery(
                        changed, changed_manifest, self.wheels, str(repository),
                    )
                qualify.assert_not_called()

    def test_c_recovery_evidence_is_code_pinned_not_caller_selected(self):
        self.assertEqual(tuple(inspect.signature(module.DevHostProvisioningOrchestrator.provision)
                               .parameters),
                         ("self", "repository_root", "wheelhouse_path",
                          "pip_installer_staging"))
        self.assertEqual(module._RECOVERY_COMMIT,
                         "c8646e1ef72f0cbab4878d383f7765f07aef8417")
        self.assertEqual(module._RECOVERY_BASE_COMMIT,
                         "fdae74dd656f421211b0c2463c6eecb217edccde")
        self.assertEqual(module._RECOVERY_CONFIG_SHA256,
                         "0d464f4c0792ddfc184b2fc65b4a46d7e233abf6471167e80ed2e728d9f6837c")
        self.assertEqual(module._RECOVERY_MANIFEST_SHA256,
                         "2743932cfb2e8d431f56de25aaab6c77177c52165ea3f35ca80281602909e69a")

    def test_c_proven_recovery_reaches_atomic_configuration_step(self):
        with patch.object(module, "_qualify_reviewed_recovery",
                          return_value=self.host) as recovery:
            result = self.invoke(c29_value=c29.HostQualificationError("prior config"))
        self.assertEqual(result.operation, "initial-provisioning")
        self.assertEqual(recovery.call_count, 1)
        names = [item[0] for item in self.events]
        self.assertLess(names.index("application"), names.index("configuration"))
        self.assertLess(names.index("configuration"), names.index("python"))

    def test_c_leftover_snapshot_fails_before_mutation(self):
        self.assert_failure(6, 7, False,
                            lambda: self.invoke(snapshot_state="exact"))
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
            with self.assertRaises(module.ProvisioningOrchestrationError) as caught:
                self.invoke()
        self.assertEqual(caught.exception.evidence.last_completed_sequence, 13)
        self.assertIs(caught.exception.evidence.failed_step, module._c31a._STEPS[13])
        self.assertTrue(caught.exception.evidence.mutation_started)
        self.assertEqual(caught.exception.evidence.internal_phase, "snapshot-preparation")
        self.assertEqual(str(caught.exception), ERROR)
        self.assertNotIn(14, recorded)
        self.assertFalse({14, 15, 16, 17, 18, 19, 20, 21, 22} & set(recorded))
        self.assertNotIn("state", [item[0] for item in self.events])

    def test_failure_at_first_mutation_reports_attempt_without_completion(self):
        authority = object.__getattribute__(self.value, "_authority")
        with patch.object(authority.runtime, "create_required_group",
                          side_effect=OSError("secret group detail")):
            self.assert_failure(7, 8, True)
        self.assertNotIn("user", [item[0] for item in self.events])

    def test_persistent_state_and_replay_failures_identify_boundary(self):
        authority = object.__getattribute__(self.value, "_authority")
        for method, last, failed in (
            ("initialize_deployment_state", 18, 19),
            ("initialize_replay", 19, 20),
        ):
            with self.subTest(method=method):
                self.events.clear()
                with patch.object(authority.persistent, method,
                                  side_effect=OSError("secret state detail")):
                    self.assert_failure(last, failed, True)

    def test_final_qualification_failure_reports_completed_prerequisites(self):
        self.assert_failure(21, 22, True, lambda: self.invoke(post_values=(
            post.PostProvisionQualificationError("precheck unavailable"),
            post.PostProvisionQualificationError("secret final detail"),
        )))

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

    def test_f_same_instance_invocations_are_nonblocking(self):
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

    def test_g_independent_process_directory_lock_and_cloexec(self):
        with tempfile.TemporaryDirectory(prefix="task014-c31d-lock-") as temporary:
            anchor = Path(temporary) / "usr" / "bin"
            anchor.mkdir(parents=True)
            held = module._acquire_process_lock(str(anchor))
            blocked = independent_lock_attempt(anchor)
            self.assertEqual(blocked.returncode, 23)
            self.assertTrue(
                module._fcntl.fcntl(held.descriptor, module._fcntl.F_GETFD)
                & module._fcntl.FD_CLOEXEC,
            )
            probe = subprocess.run(
                (sys.executable, "-I", "-c",
                 "import os,sys\ntry: os.fstat(int(sys.argv[1]))\n"
                 "except OSError: raise SystemExit(0)\nraise SystemExit(1)",
                 str(held.descriptor)),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, cwd="/", env={"LC_ALL": "C"},
                shell=False, close_fds=False, timeout=5, check=False,
            )
            self.assertEqual(probe.returncode, 0)
            module._release_process_lock(held)
            acquired = independent_lock_attempt(anchor)
            self.assertEqual(acquired.returncode, 0)

    def test_h_child_python_replacement_does_not_split_directory_lock(self):
        with tempfile.TemporaryDirectory(prefix="task014-c31d-replace-") as temporary:
            anchor = Path(temporary) / "usr" / "bin"
            anchor.mkdir(parents=True)
            interpreter = anchor / "python3.12"
            interpreter.write_bytes(b"first inode")
            held = module._acquire_process_lock(str(anchor))
            replacement = anchor / "replacement"
            replacement.write_bytes(b"second inode")
            os.replace(replacement, interpreter)
            self.assertEqual(independent_lock_attempt(anchor).returncode, 23)
            module._release_process_lock(held)
            self.assertEqual(independent_lock_attempt(anchor).returncode, 0)

    def test_i_anchor_symlink_and_replacement_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="task014-c31d-anchor-") as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError):
                module._acquire_process_lock(str(link))

            parent = root / "usr"
            anchor = parent / "bin"
            anchor.mkdir(parents=True)
            held = module._acquire_process_lock(str(anchor))
            anchor.rename(parent / "old-bin")
            anchor.mkdir()
            with self.assertRaises(OSError):
                module._release_process_lock(held)

    def test_j_failure_at_every_sequence_position_stops_later_steps(self):
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
    def test_failure_phase_accepts_only_fixed_c31b_labels_at_step_14(self):
        step_14 = module._c31a._STEPS[13]
        for phase in ("secret path", "venv-command /tmp/secret", 1, True):
            with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, module._MODEL_ERROR):
                module.ProvisioningFailureEvidence(13, step_14, True, phase)
        with self.assertRaisesRegex(ValueError, module._MODEL_ERROR):
            module.ProvisioningFailureEvidence(12, module._c31a._STEPS[12], True,
                                              "venv-command")

    def test_failure_error_rejects_unrelated_evidence(self):
        with self.assertRaisesRegex(ValueError, module._MODEL_ERROR):
            module.ProvisioningOrchestrationError(object())

    def test_failure_error_rejects_evidence_subclass(self):
        class AlternateEvidence(module.ProvisioningFailureEvidence):
            pass

        evidence = AlternateEvidence(0, module._c31a._STEPS[0], False)
        with self.assertRaisesRegex(ValueError, module._MODEL_ERROR):
            module.ProvisioningOrchestrationError(evidence)

    def test_h_public_api_construction_inert_and_no_activation_authority(self):
        self.assertEqual(module._PROCESS_LOCK_ANCHOR, "/usr/bin")
        self.assertEqual(
            inspect.signature(module._acquire_process_lock)
            .parameters["path"].default,
            "/usr/bin",
        )
        self.assertEqual(module.__all__, (
            "ProvisioningOrchestrationError", "ProvisioningFailureEvidence",
            "ProvisioningStepEvidence",
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
