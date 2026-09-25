"""C31A closed plan and post-install Python environment tests."""

import ast
import base64
import builtins
import csv
from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deployment.application_manifest as c26
from deployment.application_source_set import DevApplicationSourceSet
import deployment.dev_host_provisioning_plan as plan_module
import deployment.executor_service_config as c17
import deployment.installation_integrity_contract as c24
import deployment.pip_installer_provenance as c31p
import deployment.pip_installer_qualification as pip_qualification
import deployment.python_environment_qualification as environment_module
import deployment.wheelhouse_qualification as c28
from deployment.tests.test_executor_service_config import configuration_values


PLAN_ERROR = "DEV host provisioning plan is invalid"
ENVIRONMENT_ERROR = "DEV Python environment qualification is unavailable"


def fixture_root_only(path, owner_uid, group_gid, owned):
    """Test descendant integrity when sandbox /tmp has a non-root owner."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    owned.append(descriptor)
    status = os.fstat(descriptor)
    if (status.st_mode & 0o777, status.st_uid, status.st_gid) != (
        0o755, owner_uid, group_gid,
    ):
        raise OSError
    return descriptor, []


def fixtures():
    configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
    integrity = c24.DevInstallationIntegrityContract(configuration=configuration)
    paths = c26._predecessor_paths()
    manifest = c26.DevApplicationManifest(
        "canonical-relative-file-set-v1",
        "sha256",
        configuration.reviewed_commit,
        tuple(c26.ApplicationManifestEntry(path, "a" * 64, "0644") for path in paths),
    )
    requirement = integrity.python_environment_requirement()
    wheel_files = tuple(
        c28.WheelhouseFileEvidence(item.filename, item.sha256)
        for item in requirement.wheels
    )
    wheels = c28.DevWheelhouseEvidence(
        "/staging/runtime-wheels", "sha256", wheel_files, requirement,
    )
    installer_artifact = c31p.DevPipInstallerProvenance().artifact
    installer = pip_qualification.DevPipInstallerEvidence(
        "/staging/pip-installer", "sha256", installer_artifact,
    )
    return configuration, integrity, manifest, wheels, installer


def build_plan():
    configuration, _integrity, manifest, wheels, installer = fixtures()
    plan = plan_module.build_dev_host_provisioning_plan(
        configuration=configuration,
        application_manifest=manifest,
        wheelhouse_evidence=wheels,
        pip_installer_evidence=installer,
    )
    return configuration, manifest, wheels, installer, plan


class ProvisioningPlanTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(plan_module)
        self.configuration, self.manifest, self.wheels, self.installer, self.plan = build_plan()

    def test_a_public_api_shapes_and_immutability(self):
        self.assertEqual(plan_module.__all__, (
            "ProvisioningPlanError", "ProvisioningStep", "DevHostProvisioningPlan",
            "build_dev_host_provisioning_plan",
        ))
        self.assertEqual({name for name in vars(plan_module) if not name.startswith("_")},
                         set(plan_module.__all__))
        parameters = inspect.signature(
            plan_module.build_dev_host_provisioning_plan,
        ).parameters
        self.assertEqual(tuple(parameters), (
            "configuration", "application_manifest", "wheelhouse_evidence",
            "pip_installer_evidence",
        ))
        self.assertTrue(all(value.kind is inspect.Parameter.KEYWORD_ONLY
                            for value in parameters.values()))
        for kind in (plan_module.ProvisioningStep, plan_module.DevHostProvisioningPlan):
            self.assertTrue(dataclasses.is_dataclass(kind))
            self.assertTrue(kind.__dataclass_params__.frozen)
            self.assertIn("__slots__", vars(kind))
        for value, field in ((self.plan, "steps"), (self.plan.steps[0], "identifier")):
            self.assertFalse(hasattr(value, "__dict__"))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(value, field, "changed")
        self.assertFalse({"trusted", "approved", "ready", "safe"} & {
            field.name for field in dataclasses.fields(self.plan)
        })

    def test_b_exact_ordered_twenty_two_step_plan(self):
        expected = (
            "revalidate-c17-configuration",
            "reconstruct-c23-c24-authority",
            "revalidate-c26-application-manifest",
            "construct-c27-interpreter-provenance",
            "freshly-qualify-c28-runtime-wheelhouse",
            "freshly-qualify-c31p-installer-staging",
            "run-c29-pre-provision-host-qualification",
            "create-exact-c23-groups",
            "create-exact-c23-users",
            "create-exact-required-directories",
            "install-exact-c26-application-tree",
            "install-exact-c17-configuration",
            "install-exact-c22-c23-systemd-assets",
            "create-exact-no-pip-venv",
            "bind-fresh-c31p-qualification-to-consumption",
            "bind-fresh-c28-qualification-to-consumption",
            "install-exact-c24-runtime-wheels",
            "qualify-post-install-python-environment",
            "establish-initial-deployment-state-prerequisites",
            "initialize-replay-under-existing-lifecycle",
            "establish-audit-prerequisites-preserving-history",
            "verify-post-provision-convergence-and-integrity",
        )
        self.assertEqual(tuple(step.sequence for step in self.plan.steps),
                         tuple(range(1, 23)))
        self.assertEqual(tuple(step.identifier for step in self.plan.steps), expected)
        self.assertEqual(len(set(expected)), 22)
        self.assertEqual(self.plan.steps[-1].boundary, "C31D")

    def test_c_exact_application_and_no_pip_venv_contracts(self):
        self.assertEqual(self.plan.reviewed_commit, self.configuration.reviewed_commit)
        self.assertEqual(self.plan.application_file_count, 28)
        self.assertEqual(
            self.plan.application_manifest_sha256,
            hashlib.sha256(self.manifest.canonical_bytes()).hexdigest(),
        )
        self.assertIn("exact-reviewed-git-blob-bytes", self.plan.application_source_model)
        self.assertIn("C26 path+sha256+0644", self.plan.application_source_model)
        self.assertEqual(self.plan.venv_argv, (
            "/usr/bin/python3.12", "-m", "venv", "--without-pip",
            "/opt/omnilyzer/deployment/venv",
        ))
        self.assertEqual(self.plan.venv_umask, 0o022)
        self.assertIn("absent or exact empty C23 venv root", self.plan.venv_precondition)
        self.assertIn("shell=False", self.plan.process_execution_model)
        self.assertIn("bounded output and timeout", self.plan.process_execution_model)
        self.assertNotIn("ensurepip", self.plan.venv_argv)
        self.assertEqual(dict(self.plan.venv_environment), {
            "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        })

    def test_d_exact_c31p_direct_wheel_installation_contract(self):
        provenance = c31p.DevPipInstallerProvenance()
        self.assertEqual(self.plan.pip_python_executable,
                         "/opt/omnilyzer/deployment/venv/bin/python")
        self.assertEqual(self.plan.pip_isolation_argument, "-I")
        self.assertEqual(self.plan.pip_bootstrap_source,
                         provenance.invocation.bootstrap_source)
        arguments = self.plan.pip_arguments
        self.assertEqual(arguments[1], "install")
        for required in (
            "--no-input", "--disable-pip-version-check", "--no-cache-dir",
            "--no-index", "--only-binary=:all:", "--no-deps",
            "--require-hashes", "--no-compile", "--find-links", "--requirement",
        ):
            self.assertEqual(arguments.count(required), 1)
        self.assertEqual(arguments[0], "<identity-bound-pip-installer-wheel>")
        self.assertIn("<identity-bound-runtime-wheel-snapshot>", arguments)
        self.assertIn("<identity-bound-requirements-lock>", arguments)
        self.assertEqual(dict(self.plan.pip_environment)["PIP_CONFIG_FILE"], "/dev/null")
        self.assertEqual(dict(self.plan.pip_environment)["PIP_NO_INDEX"], "1")
        self.assertEqual(self.plan.pip_umask, 0o022)
        self.assertNotIn("-m", arguments)
        self.assertNotIn("pip", arguments)

    def test_e_qualification_is_identity_bound_to_private_snapshot(self):
        self.assertEqual(
            self.plan.input_snapshot_root,
            "/opt/omnilyzer/deployment/.provisioning-inputs",
        )
        model = self.plan.qualification_consumption_model
        for marker in (
            "still-open descriptors", "root-owned 0700 private snapshot",
            "re-hashes and fsyncs", "retains snapshot identity",
            "directory ownership alone never confers byte trust",
        ):
            self.assertIn(marker, model)
        self.assertIn("materialize-identity-bound-python-input-snapshot",
                      self.plan.c30_extensions)
        self.assertIn("remove-own-identity-bound-input-snapshot",
                      self.plan.c30_extensions)

    def test_f_runtime_manifest_and_four_wheel_separation(self):
        requirement = c24.DevInstallationIntegrityContract(
            configuration=self.configuration,
        ).python_environment_requirement()
        self.assertEqual(len(requirement.wheels), 4)
        self.assertFalse(any(item.filename.startswith("pip-") for item in requirement.wheels))
        self.assertEqual(self.plan.runtime_entry_count, 237)
        self.assertEqual(self.plan.runtime_manifest_size, 57824)
        self.assertEqual(
            self.plan.runtime_manifest_sha256,
            "3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b",
        )
        self.assertEqual(self.installer.artifact.filename,
                         "pip-26.2.1-py3-none-any.whl")
        self.assertNotIn(self.installer.artifact.filename,
                         {item.filename for item in requirement.wheels})

    def test_g_forged_inputs_commit_mismatch_and_overrides_rejected(self):
        wrong_manifest = c26.DevApplicationManifest(
            self.manifest.manifest_kind, self.manifest.digest_algorithm, "b" * 40,
            self.manifest.entries,
        )
        forged_installer = object.__new__(pip_qualification.DevPipInstallerEvidence)
        for field in dataclasses.fields(self.installer):
            object.__setattr__(forged_installer, field.name,
                               getattr(self.installer, field.name))
        forged_artifact = object.__new__(c31p.PipInstallerArtifactEvidence)
        for field in dataclasses.fields(self.installer.artifact):
            object.__setattr__(forged_artifact, field.name,
                               getattr(self.installer.artifact, field.name))
        object.__setattr__(forged_artifact, "sha256", "0" * 64)
        object.__setattr__(forged_installer, "artifact", forged_artifact)
        attacks = (
            (object(), self.manifest, self.wheels, self.installer),
            (self.configuration, wrong_manifest, self.wheels, self.installer),
            (self.configuration, self.manifest, object(), self.installer),
            (self.configuration, self.manifest, self.wheels, forged_installer),
        )
        for configuration, manifest, wheels, installer in attacks:
            with self.subTest(attack=attacks.index((configuration, manifest, wheels, installer))):
                with self.assertRaises(plan_module.ProvisioningPlanError) as caught:
                    plan_module.build_dev_host_provisioning_plan(
                        configuration=configuration,
                        application_manifest=manifest,
                        wheelhouse_evidence=wheels,
                        pip_installer_evidence=installer,
                    )
                self.assertEqual(str(caught.exception), PLAN_ERROR)
        with self.assertRaises(TypeError):
            plan_module.build_dev_host_provisioning_plan(
                configuration=self.configuration,
                application_manifest=self.manifest,
                wheelhouse_evidence=self.wheels,
                pip_installer_evidence=self.installer,
                command=("/bin/sh",),
            )

    def test_h_forged_plan_and_step_values_rejected(self):
        with self.assertRaisesRegex(ValueError, PLAN_ERROR):
            plan_module.ProvisioningStep(1, "run-arbitrary-command", "root")
        values = {
            field.name: getattr(self.plan, field.name)
            for field in dataclasses.fields(self.plan)
        }
        init_values = (
            self.configuration, self.manifest, self.wheels, self.installer,
        )
        for field, value in (
            ("venv_argv", self.plan.venv_argv + ("--upgrade",)),
            ("pip_arguments", self.plan.pip_arguments + ("--index-url",)),
            ("input_snapshot_root", "/tmp/caller-selected"),
            ("c30_extensions", self.plan.c30_extensions + ("run-command",)),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, PLAN_ERROR):
                plan_module.DevHostProvisioningPlan(
                    *(values | {field: value}).values(), *init_values,
                )

    def test_i_state_replay_audit_are_non_destructive_plan_requirements(self):
        text = " ".join(self.plan.lifecycle_requirements)
        self.assertIn("fixed canonical no-active bootstrap bytes", text)
        self.assertIn("never reset existing state", text)
        self.assertIn("never replace a database", text)
        self.assertIn("preserve every existing history entry", text)
        self.assertNotIn("establish-deployment-state-initialization-boundary",
                         self.plan.c30_extensions)
        self.assertNotIn("reset", self.plan.c30_extensions)
        self.assertNotIn("delete", self.plan.c30_extensions)

    def test_j_import_construction_and_build_are_inert(self):
        with ExitStack() as stack:
            mocks = [
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                for owner, name in (
                    (builtins, "open"), (os, "open"), (os, "stat"),
                    (subprocess, "Popen"), (subprocess, "run"), (socket, "socket"),
                )
            ]
            importlib.reload(plan_module)
            configuration, _integrity, manifest, wheels, installer = fixtures()
            plan_module.build_dev_host_provisioning_plan(
                configuration=configuration, application_manifest=manifest,
                wheelhouse_evidence=wheels, pip_installer_evidence=installer,
            )
            for mocked in mocks:
                mocked.assert_not_called()


class PythonEnvironmentQualificationTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(environment_module)
        self.configuration = fixtures()[0]
        integrity = c24.DevInstallationIntegrityContract(configuration=self.configuration)
        self.environment = integrity.python_environment_requirement()
        self.installer = c31p.DevPipInstallerProvenance()
        self.entries = environment_module._load_manifest(self.environment, self.installer)

    def materialize(self, root: Path, entries):
        root.mkdir()
        root.chmod(0o755)
        for entry in entries:
            path = root / entry["path"]
            if entry["kind"] == "directory":
                path.mkdir()
                path.chmod(int(entry["mode"], 8))
        for entry in entries:
            path = root / entry["path"]
            if entry["kind"] == "regular_file":
                with path.open("wb") as stream:
                    stream.truncate(entry["size"])
                path.chmod(int(entry["mode"], 8))
            elif entry["kind"] == "symbolic_link":
                path.symlink_to(entry["target"])

    def mini_tree(self, parent: str):
        root = Path(parent) / "venv"
        root.mkdir(); root.chmod(0o755)
        payload = b"reviewed-runtime"
        file = root / "runtime.py"
        file.write_bytes(payload); file.chmod(0o644)
        entry = {
            "path": "runtime.py", "kind": "regular_file", "mode": "0644",
            "source": "fixture", "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        return root, file, (entry,)

    def test_k_public_api_and_closed_immutable_evidence(self):
        self.assertEqual(environment_module.__all__, (
            "PythonEnvironmentQualificationError", "PythonDistributionEvidence",
            "DevPythonEnvironmentEvidence", "qualify_dev_python_environment",
        ))
        self.assertEqual({name for name in vars(environment_module)
                          if not name.startswith("_")}, set(environment_module.__all__))
        parameters = inspect.signature(
            environment_module.qualify_dev_python_environment,
        ).parameters
        self.assertEqual(tuple(parameters), ("configuration",))
        self.assertIs(parameters["configuration"].kind, inspect.Parameter.KEYWORD_ONLY)
        evidence = environment_module.DevPythonEnvironmentEvidence()
        self.assertEqual(evidence.root, "/opt/omnilyzer/deployment/venv")
        self.assertEqual(evidence.python_series, "3.12")
        self.assertEqual(evidence.regular_file_count, 197)
        self.assertEqual(evidence.directory_count, 36)
        self.assertEqual(evidence.symbolic_link_count, 4)
        self.assertEqual(tuple((item.name, item.version) for item in evidence.distributions), (
            ("cffi", "2.1.1"), ("cryptography", "50.0.1"),
            ("pycparser", "3.0"), ("PyJWT", "2.13.0"),
        ))
        for value, field in ((evidence, "root"), (evidence.distributions[0], "version")):
            self.assertFalse(hasattr(value, "__dict__"))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(value, field, "changed")
        for override in ("root", "distributions", "payload_manifest_sha256"):
            with self.assertRaises(TypeError):
                environment_module.DevPythonEnvironmentEvidence(
                    **{override: "caller-selected"},
                )

    def test_cffi_record_uses_pip_csv_crlf_serialization(self):
        """Rebuild pip 26.2.1's sorted, site-relative installed RECORD rows."""
        site = "lib/python3.12/site-packages/"
        record = site + "cffi-2.1.1.dist-info/RECORD"
        wheel = c24.DevInstallationIntegrityContract(
            configuration=self.configuration,
        ).python_environment_requirement().wheels[2].filename
        selected = [
            entry for entry in self.entries
            if entry["kind"] == "regular_file" and (
                entry["source"] == wheel
                or entry["path"] == "bin/cffi-gen-src"
                or (entry["source"] == "pip-generated-metadata"
                    and entry["path"].startswith(site + "cffi-2.1.1.dist-info/"))
            )
        ]
        self.assertEqual(len(selected), 34)
        rows = []
        for entry in selected:
            path = entry["path"]
            relative = (
                "../../../" + path if path.startswith("bin/")
                else path.removeprefix(site)
            )
            digest = (
                "sha256=" + base64.urlsafe_b64encode(
                    bytes.fromhex(entry["sha256"])
                ).rstrip(b"=").decode("ascii")
                if path != record else ""
            )
            rows.append((relative, digest, str(entry["size"]) if digest else ""))
        rows.sort(key=lambda row: row[0])
        self.assertEqual(len(rows), 34)

        def serialize(newline=None):
            output = io.StringIO(newline="")
            writer = csv.writer(output) if newline is None else csv.writer(
                output, lineterminator=newline,
            )
            writer.writerows(rows)
            return output.getvalue().encode("utf-8")

        crlf, lf = serialize(), serialize("\n")
        self.assertEqual((len(crlf), hashlib.sha256(crlf).hexdigest()), (
            2665, "e17a08d7a6b2a942aca45d2e533ca3c805d02d069a6674fdda39ba5e90193200",
        ))
        self.assertEqual((len(lf), hashlib.sha256(lf).hexdigest()), (
            2631, "7f43cc4e11358f6468993deccf1bcd24bc451b7464deb7ea7b14e4fba361abdb",
        ))
        bound = next(entry for entry in self.entries if entry["path"] == record)
        self.assertEqual((bound["size"], bound["sha256"]),
                         (len(crlf), hashlib.sha256(crlf).hexdigest()))
        self.assertNotEqual((len(crlf), hashlib.sha256(crlf).hexdigest()),
                            (len(lf), hashlib.sha256(lf).hexdigest()))
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "venv"
            root.mkdir()
            root.chmod(0o755)
            (root / "RECORD").write_bytes(crlf)
            (root / "RECORD").chmod(0o644)
            old = ({"path": "RECORD", "kind": "regular_file", "mode": "0644",
                    "source": "fixture", "size": len(lf),
                    "sha256": hashlib.sha256(lf).hexdigest()},)
            corrected = ({**old[0], "size": bound["size"],
                          "sha256": bound["sha256"]},)
            with patch.object(environment_module, "_open_root", fixture_root_only):
                with self.assertRaises(OSError):
                    environment_module._observe_tree(
                        str(root), old, os.getuid(), os.getgid(),
                    )
                environment_module._observe_tree(
                    str(root), corrected, os.getuid(), os.getgid(),
                )

    def test_l_retained_manifest_exact_wheel_and_generated_file_model(self):
        path = Path(environment_module.__file__).parent / environment_module._MANIFEST_PATH
        raw = path.read_bytes()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (
            57824, "3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b",
        ))
        self.assertEqual(len(self.entries), 237)
        self.assertEqual(sum(item["kind"] == "regular_file" for item in self.entries), 197)
        self.assertEqual(sum(item["kind"] == "directory" for item in self.entries), 36)
        self.assertEqual(sum(item["kind"] == "symbolic_link" for item in self.entries), 4)
        files = {item["path"]: item for item in self.entries}
        self.assertEqual(files["bin/python3.12"]["target"], "/usr/bin/python3.12")
        self.assertEqual(files["bin/cffi-gen-src"]["source"], "pip-generated-script")
        self.assertEqual(files["bin/cffi-gen-src"]["mode"], "0755")
        self.assertEqual(files["bin/cffi-gen-src"]["sha256"],
                         "7830ab39bc7f17dc93e19dda03cd45a3b6540e2c6370fb2a97e8c11094493532")
        self.assertEqual(files["pyvenv.cfg"]["source"], "venv")
        self.assertEqual(files["pyvenv.cfg"]["sha256"],
                         "d9d534e019c68dd6a8a8e08ee9fd64db84b81c54e71c4591204fa42fbb940fe4")
        self.assertEqual(
            tuple((files[name]["size"], files[name]["sha256"]) for name in (
                "bin/activate", "bin/activate.csh", "bin/activate.fish",
            )),
            (
                (2048, "7555ce6ac2867169ec71db3894941242974ecdd80c8951e48b31cda958cc68ac"),
                (926, "2de860874b9c32547eba340ea89ce7328da0b8fd0878a96967605bf18150bb9e"),
                (2201, "9ac4f169ab38f0c52f34879c47549f7e7cdb04a07d4a5fb5207989c45904c5d7"),
            ),
        )
        self.assertFalse(any(path.endswith(".pyc") or "__pycache__" in path.split("/")
                             for path in files))
        self.assertFalse(any("pip-" in path.lower() and ".dist-info" in path.lower()
                             for path in files))
        generated = [item for item in self.entries
                     if item["source"] == "pip-generated-metadata"]
        self.assertEqual(len(generated), 12)
        self.assertEqual(sum(item["path"].endswith("/RECORD") for item in generated), 4)
        self.assertEqual(sum(item["path"].endswith("/INSTALLER") for item in generated), 4)
        self.assertEqual(sum(item["path"].endswith("/REQUESTED") for item in generated), 4)

    @patch.object(environment_module, "_open_root", fixture_root_only)
    def test_m_complete_exact_tree_passes_read_only_observation(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "venv"
            self.materialize(root, self.entries)
            before = tuple((path.relative_to(root).as_posix(), path.lstat().st_mode)
                           for path in sorted(root.rglob("*")))
            hashes = {entry["path"]: entry["sha256"] for entry in self.entries
                      if entry["kind"] == "regular_file"}

            def reviewed_hash(descriptor, size):
                path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                return hashes[path.relative_to(root).as_posix()]

            with patch.object(environment_module, "_hash_file",
                              side_effect=reviewed_hash):
                environment_module._observe_tree(
                    str(root), self.entries, os.getuid(), os.getgid(),
                )
            after = tuple((path.relative_to(root).as_posix(), path.lstat().st_mode)
                          for path in sorted(root.rglob("*")))
        self.assertEqual(before, after)

    @patch.object(environment_module, "_open_root", fixture_root_only)
    def test_n_modified_file_symlink_extra_pyc_and_pip_package_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root, file, entries = self.mini_tree(parent)
            environment_module._observe_tree(str(root), entries, os.getuid(), os.getgid())
            file.write_bytes(b"modified-runtime")
            with self.assertRaises(OSError):
                environment_module._observe_tree(
                    str(root), entries, os.getuid(), os.getgid(),
                )
        with tempfile.TemporaryDirectory() as parent:
            root, file, entries = self.mini_tree(parent)
            file.unlink(); file.symlink_to("other")
            with self.assertRaises(OSError):
                environment_module._observe_tree(
                    str(root), entries, os.getuid(), os.getgid(),
                )
        for relative in ("extra.py", "__pycache__/attack.pyc", "pip-26.2.1.dist-info/METADATA"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as parent:
                root, _file, entries = self.mini_tree(parent)
                extra = root / relative
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_bytes(b"extra")
                with self.assertRaises(OSError):
                    environment_module._observe_tree(
                        str(root), entries, os.getuid(), os.getgid(),
                    )

    @patch.object(environment_module, "_open_root", fixture_root_only)
    def test_o_wrong_ownership_mode_and_path_substitution_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root, file, entries = self.mini_tree(parent)
            file.chmod(0o666)
            with self.assertRaises(OSError):
                environment_module._observe_tree(
                    str(root), entries, os.getuid(), os.getgid(),
                )
        with tempfile.TemporaryDirectory() as parent:
            root, _file, entries = self.mini_tree(parent)
            with self.assertRaises(OSError):
                environment_module._observe_tree(
                    str(root), entries, os.getuid() + 1, os.getgid(),
                )
        with tempfile.TemporaryDirectory() as parent:
            real = Path(parent) / "real"; real.mkdir()
            root, _file, entries = self.mini_tree(str(real))
            alias = Path(parent) / "alias"; alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                environment_module._observe_tree(
                    str(alias), entries, os.getuid(), os.getgid(),
                )

    def test_p_malformed_generated_metadata_manifest_rejected(self):
        path = Path(environment_module.__file__).parent / environment_module._MANIFEST_PATH
        value = json.loads(path.read_bytes())
        installer = next(item for item in value["entries"]
                         if item["path"].endswith("/INSTALLER"))
        installer["sha256"] = "0" * 64
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with patch.object(environment_module, "_repository_manifest", return_value=raw):
            with self.assertRaises(ValueError):
                environment_module._load_manifest(self.environment, self.installer)
        value = json.loads(path.read_bytes())
        record = next(item for item in value["entries"]
                      if item["path"].endswith("/RECORD"))
        record["sha256"] = "malformed"
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with patch.object(environment_module, "_repository_manifest", return_value=raw):
            with self.assertRaises(ValueError):
                environment_module._load_manifest(self.environment, self.installer)

    def test_q_public_qualifier_fixed_root_error_and_no_c29_weakening(self):
        expected = environment_module.DevPythonEnvironmentEvidence()
        with patch.object(environment_module, "_load_manifest", return_value=self.entries), \
             patch.object(environment_module, "_observe_tree") as observe:
            actual = environment_module.qualify_dev_python_environment(
                configuration=self.configuration,
            )
        self.assertEqual(actual, expected)
        observe.assert_called_once_with(
            "/opt/omnilyzer/deployment/venv", self.entries, 0, 0,
        )
        with patch.object(environment_module, "_observe_tree", side_effect=OSError):
            with self.assertRaises(environment_module.PythonEnvironmentQualificationError) as caught:
                environment_module.qualify_dev_python_environment(
                    configuration=self.configuration,
                )
        self.assertEqual(str(caught.exception), ENVIRONMENT_ERROR)
        c29_source = (Path(environment_module.__file__).with_name(
            "dev_host_qualification.py")).read_text()
        self.assertNotIn("python_environment_qualification", c29_source)
        self.assertIn("and observation.state == \"exact\"", c29_source)
        self.assertIn("if any(True for _entry in iterator): raise OSError", c29_source)

    def test_r_plan_and_qualifier_have_no_mutation_network_or_activation_authority(self):
        for path in (Path(plan_module.__file__), Path(environment_module.__file__)):
            source = path.read_text()
            tree = ast.parse(source)
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.add((node.module or "").split(".")[0])
            self.assertFalse(imports & {
                "socket", "subprocess", "urllib", "http", "venv", "shutil",
            })
            operations = {node.attr for node in ast.walk(tree)
                          if isinstance(node, ast.Attribute)}
            self.assertFalse(operations & {
                "write", "write_bytes", "write_text", "mkdir", "makedirs",
                "unlink", "remove", "rename", "replace", "chmod", "chown",
                "truncate", "system", "Popen", "run",
            })
            self.assertNotIn("O_CREAT", source)
        self.assertFalse(any(
            marker in Path(plan_module.__file__).read_text()
            for marker in ("systemctl", "docker", "shell=True", "/bin/sh")
        ))

    def test_s_hashing_is_bounded_and_fifo_substitution_cannot_block(self):
        payload = b"x" * (environment_module._CHUNK * 2 + 1)
        with tempfile.TemporaryFile() as stream:
            stream.write(payload)
            stream.seek(0)
            requests = []
            read = os.read

            def bounded_read(descriptor, maximum):
                requests.append(maximum)
                return read(descriptor, maximum)

            with patch.object(environment_module._os, "read", side_effect=bounded_read):
                digest = environment_module._hash_file(stream.fileno(), len(payload))
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertTrue(requests)
        self.assertLessEqual(max(requests), environment_module._CHUNK)

        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation unavailable")
        with tempfile.TemporaryDirectory() as parent:
            root, file, entries = self.mini_tree(parent)
            file.unlink()
            os.mkfifo(file, 0o644)
            with self.assertRaises(OSError):
                environment_module._observe_tree(
                    str(root), entries, os.getuid(), os.getgid(),
                )


if __name__ == "__main__":
    unittest.main()
