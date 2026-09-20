"""C29 read-only host qualification, payload, collision and evidence tests."""

import ast
import builtins
from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import deployment.application_manifest as c26
import deployment.dev_host_qualification as module
import deployment.executor_service_config as c17
import deployment.host_provisioning_contract as c23
import deployment.installation_integrity_contract as c24
import deployment.python_interpreter_provenance as c27
import deployment.wheelhouse_qualification as c28
from deployment.application_source_set import DevApplicationSourceSet
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]
ERROR = "DEV host qualification is unavailable"


def fixtures():
    configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
    integrity = c24.DevInstallationIntegrityContract(configuration=configuration)
    paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
    manifest = c26.DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", configuration.reviewed_commit,
        tuple(c26.ApplicationManifestEntry(path, "a" * 64, "0644") for path in paths),
    )
    requirement = integrity.python_environment_requirement()
    files = tuple(c28.WheelhouseFileEvidence(item.filename, item.sha256)
                  for item in requirement.wheels)
    wheels = c28.DevWheelhouseEvidence("/staging/wheelhouse", "sha256", files, requirement)
    provisioning = c23.DevHostProvisioningContract(
        installation=configuration.installation_contract())
    return configuration, integrity, manifest, wheels, provisioning


def fake_observations(provisioning, manifest, wheels):
    platform = module.HostPlatformObservation(
        "Linux", "Ubuntu", "24.04", "x86_64", "amd64", "glibc 2.39")
    groups = tuple(module.HostGroupObservation(item.name, item.gid, "absent")
                   for item in provisioning.group_requirements())
    users = tuple(module.HostUserObservation(
        item.name, item.uid, item.primary_gid, item.supplementary_gids, "absent")
        for item in provisioning.user_requirements())
    paths = tuple(module.HostManagedPathObservation(
        item.path, item.kind, "absent", item.mode, item.owner_uid, item.group_gid)
        for item in (*provisioning.path_requirements(),
                     *provisioning.runtime_resource_requirements()))
    provenance = c27.DevPythonInterpreterProvenance()
    packages = tuple(module.HostPackageObservation(
        item.package, item.version, item.architecture, "installed")
        for item in provenance.packages)
    payload = (module.HostPayloadFileObservation(
        "python3.12-minimal", "/usr/bin/python3.12", "regular_file",
        0o755, 0, 0, 1, "a" * 64, None),)
    application = module.HostApplicationObservation(
        integrity_root(), "absent", manifest.reviewed_commit,
        hashlib.sha256(manifest.canonical_bytes()).hexdigest())
    return platform, groups, users, paths, packages, payload, application


def integrity_root():
    return "/opt/omnilyzer/deployment/app"


def application_fixture(temporary):
    root = Path(temporary) / "app"
    source = root / "deployment/example.py"
    source.parent.mkdir(parents=True)
    root.chmod(0o755); source.parent.chmod(0o755)
    source.write_bytes(b"app"); source.chmod(0o644)
    entry = SimpleNamespace(path="deployment/example.py",
                            sha256=hashlib.sha256(b"app").hexdigest(), mode="0644")
    manifest = SimpleNamespace(entries=(entry,), reviewed_commit="a" * 40,
                               canonical_bytes=lambda: b"manifest\n")
    requirement = SimpleNamespace(root=str(root))
    root_requirement = c23.HostPathRequirement(
        str(root), "directory", 0o755, os.getuid(), os.getgid(),
        "must-contain-reviewed-application-before-activation")
    return root, source, manifest, requirement, root_requirement


def changed_status(status, **changes):
    names = ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size",
             "st_mtime_ns", "st_ctime_ns")
    values = {name: getattr(status, name) for name in names}
    values.update(changes)
    return SimpleNamespace(**values)


class ModelAndCompositionTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(module)
        self.configuration, self.integrity, self.manifest, self.wheels, self.provisioning = fixtures()

    def test_a_public_api_and_evidence_shapes(self):
        self.assertEqual(module.__all__, (
            "HostQualificationError", "HostPlatformObservation", "HostGroupObservation",
            "HostUserObservation", "HostManagedPathObservation", "HostPackageObservation",
            "HostPayloadFileObservation", "HostApplicationObservation",
            "DevHostQualificationEvidence", "qualify_dev_host",
        ))
        self.assertEqual({name for name in vars(module) if not name.startswith("_")},
                         set(module.__all__))
        parameters = inspect.signature(module.qualify_dev_host).parameters
        self.assertEqual(tuple(parameters),
                         ("configuration", "application_manifest", "wheelhouse_evidence"))
        self.assertTrue(all(item.kind is inspect.Parameter.KEYWORD_ONLY
                            for item in parameters.values()))
        for name in module.__all__[1:-1]:
            cls = getattr(module, name)
            self.assertTrue(dataclasses.is_dataclass(cls))
            self.assertTrue(cls.__dataclass_params__.frozen)
            self.assertIn("__slots__", vars(cls))
            self.assertFalse({"trusted", "approved", "ready", "safe"}
                             & {field.name for field in dataclasses.fields(cls)})

    def test_b_import_and_construction_inert(self):
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                     for owner, name in (
                         (builtins, "open"), (os, "open"), (os, "stat"), (os, "walk"),
                         (subprocess, "Popen"), (subprocess, "run"), (socket, "socket"))]
            importlib.reload(module)
            module.HostPlatformObservation("Linux", "Ubuntu", "24.04", "x86_64",
                                           "amd64", "glibc 2.39")
            for mocked in mocks: mocked.assert_not_called()

    def test_c_valid_composition_and_acceptable_absence(self):
        values = fake_observations(self.provisioning, self.manifest, self.wheels)
        with patch.object(module, "_platform_observation", return_value=values[0]), \
             patch.object(module, "_query_packages", return_value=values[4]), \
             patch.object(module, "_observe_payload", return_value=values[5]), \
             patch.object(module, "_observe_principals", return_value=(values[1], values[2])), \
             patch.object(module, "_observe_paths", return_value=values[3]), \
             patch.object(module, "_observe_application", return_value=values[6]):
            result = module.qualify_dev_host(
                configuration=self.configuration, application_manifest=self.manifest,
                wheelhouse_evidence=self.wheels)
        self.assertIs(type(result), module.DevHostQualificationEvidence)
        self.assertEqual({item.state for item in result.groups}, {"absent"})
        self.assertEqual({item.state for item in result.users}, {"absent"})
        self.assertEqual({item.state for item in result.managed_paths}, {"absent"})
        self.assertEqual(result.application.state, "absent")
        self.assertEqual(result.wheel_files, self.wheels.files)
        self.assertEqual(result.payload_manifest_sha256, module._PAYLOAD_SHA256)

    def test_d_forged_c26_c27_c28_and_commit_mismatch_rejected(self):
        forged_manifest = object.__new__(c26.DevApplicationManifest)
        for field in dataclasses.fields(self.manifest):
            object.__setattr__(forged_manifest, field.name, getattr(self.manifest, field.name))
        object.__setattr__(forged_manifest, "reviewed_commit", "b" * 40)
        forged_wheels = object.__new__(c28.DevWheelhouseEvidence)
        for field in dataclasses.fields(self.wheels):
            object.__setattr__(forged_wheels, field.name, getattr(self.wheels, field.name))
        bad_file = object.__new__(c28.WheelhouseFileEvidence)
        object.__setattr__(bad_file, "filename", self.wheels.files[0].filename)
        object.__setattr__(bad_file, "sha256", "0" * 64)
        object.__setattr__(forged_wheels, "files", (bad_file, *self.wheels.files[1:]))
        forged_provenance = object.__new__(c27.DevPythonInterpreterProvenance)
        valid_provenance = c27.DevPythonInterpreterProvenance()
        for field in dataclasses.fields(valid_provenance):
            object.__setattr__(forged_provenance, field.name, getattr(valid_provenance, field.name))
        object.__setattr__(forged_provenance, "architecture", "arm64")
        for manifest, wheels, provenance in (
            (forged_manifest, self.wheels, valid_provenance),
            (self.manifest, forged_wheels, valid_provenance),
            (self.manifest, self.wheels, forged_provenance),
        ):
            with self.subTest(manifest=manifest, wheels=wheels, provenance=provenance), \
                 patch.object(module._c27, "DevPythonInterpreterProvenance",
                              return_value=provenance):
                with self.assertRaises(module.HostQualificationError) as caught:
                    module.qualify_dev_host(configuration=self.configuration,
                                            application_manifest=manifest,
                                            wheelhouse_evidence=wheels)
                self.assertEqual(str(caught.exception), ERROR)

    def test_e_fixed_error_and_control_flow(self):
        for value in (None, object(), {}):
            with self.assertRaises(module.HostQualificationError) as caught:
                module.qualify_dev_host(configuration=value,
                                        application_manifest=self.manifest,
                                        wheelhouse_evidence=self.wheels)
            self.assertEqual(str(caught.exception), ERROR)
            self.assertIsNone(caught.exception.__cause__)
        for exception in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with patch.object(module, "_platform_observation", side_effect=exception):
                with self.assertRaises(exception):
                    module.qualify_dev_host(configuration=self.configuration,
                                            application_manifest=self.manifest,
                                            wheelhouse_evidence=self.wheels)
        values = fake_observations(self.provisioning, self.manifest, self.wheels)
        with patch.object(module, "_platform_observation", return_value=values[0]), \
             patch.object(module, "_query_packages", return_value=values[4]), \
             patch.object(module, "_observe_payload", return_value=values[5]), \
             patch.object(module, "_observe_principals", return_value=(values[1], values[2])), \
             patch.object(module, "_observe_paths", return_value=values[3]), \
             patch.object(module, "_observe_application", side_effect=OSError):
            with self.assertRaises(module.HostQualificationError) as caught:
                module.qualify_dev_host(configuration=self.configuration,
                                        application_manifest=self.manifest,
                                        wheelhouse_evidence=self.wheels)
            self.assertEqual(str(caught.exception), ERROR)
            self.assertIsNone(caught.exception.__cause__)

    def test_f_forged_nested_result_observation_rejected(self):
        values = list(fake_observations(self.provisioning, self.manifest, self.wheels))
        forged = object.__new__(module.HostPackageObservation)
        object.__setattr__(forged, "package", values[4][0].package)
        object.__setattr__(forged, "version", values[4][0].version)
        object.__setattr__(forged, "architecture", values[4][0].architecture)
        object.__setattr__(forged, "status", "unknown")
        values[4] = (forged, *values[4][1:])
        with self.assertRaisesRegex(ValueError, "DEV host qualification evidence is invalid"):
            module.DevHostQualificationEvidence(
                *values, self.wheels.wheelhouse_path, self.wheels.files,
                module._PAYLOAD_SHA256)


class PayloadEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.provenance = c27.DevPythonInterpreterProvenance()

    def test_g_retained_payload_manifest_closed_and_c27_bound(self):
        path = ROOT / "deployment/provenance/python3.12-3.12.3-1ubuntu0.17-amd64-payload.json"
        raw = path.read_bytes()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()),
                         (module._PAYLOAD_SIZE, module._PAYLOAD_SHA256))
        parsed = json.loads(raw)
        self.assertEqual((parsed["schema_version"], parsed["kind"]),
                         (1, "debian-installed-payload-v1"))
        actual = tuple((item["package"], item["version"], item["architecture"],
                        item["artifact_sha256"]) for item in parsed["packages"])
        expected = tuple((item.package, item.version, item.architecture, item.sha256)
                         for item in self.provenance.packages)
        self.assertEqual(actual, expected)
        entries = [entry for package in parsed["packages"] for entry in package["entries"]]
        self.assertEqual(len(entries), 658)
        self.assertEqual(sum(item["kind"] == "regular_file" for item in entries), 651)
        self.assertEqual(sum(item["kind"] == "symbolic_link" for item in entries), 7)
        self.assertEqual(len({item["path"] for item in entries}), 658)
        interpreter = next(item for item in entries if item["path"] == "/usr/bin/python3.12")
        self.assertEqual(interpreter["kind"], "regular_file")
        self.assertRegex(interpreter["sha256"], r"^[0-9a-f]{64}$")

    def test_h_payload_regular_bytes_and_substitutions(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "python3.12"
            target.write_bytes(b"reviewed interpreter")
            target.chmod(0o755)
            status = target.stat()
            expected = module.HostPayloadFileObservation(
                "python3.12-minimal", str(target), "regular_file", 0o755,
                status.st_uid, status.st_gid, status.st_size,
                hashlib.sha256(target.read_bytes()).hexdigest(), None)
            self.assertEqual(module._observe_payload(({"observation": expected},)), (expected,))
            target.write_bytes(b"modified interpreter")
            with self.assertRaises(OSError): module._observe_payload(({"observation": expected},))
            target.unlink(); target.symlink_to("elsewhere")
            with self.assertRaises(OSError): module._observe_payload(({"observation": expected},))

    def test_i_payload_symlink_target_and_regular_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "pdb3.12"
            target.symlink_to("../lib/python3.12/pdb.py")
            status = target.lstat()
            expected = module.HostPayloadFileObservation(
                "python3.12", str(target), "symbolic_link", stat.S_IMODE(status.st_mode),
                status.st_uid, status.st_gid, None, None, "../lib/python3.12/pdb.py")
            self.assertEqual(module._observe_payload(({"observation": expected},)), (expected,))
            target.unlink(); target.symlink_to("wrong")
            with self.assertRaises(OSError): module._observe_payload(({"observation": expected},))
            target.unlink(); target.write_bytes(b"not a symlink")
            with self.assertRaises(OSError): module._observe_payload(({"observation": expected},))

    def test_j_symlinked_parent_component_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); real = root / "real"; real.mkdir()
            item = real / "python"; item.write_bytes(b"x")
            alias = root / "alias"; alias.symlink_to(real, target_is_directory=True)
            status = item.stat()
            expected = module.HostPayloadFileObservation(
                "python3.12", str(alias / "python"), "regular_file", stat.S_IMODE(status.st_mode),
                status.st_uid, status.st_gid, 1, hashlib.sha256(b"x").hexdigest(), None)
            with self.assertRaises(OSError): module._observe_payload(({"observation": expected},))


class HostObservationTests(unittest.TestCase):
    def setUp(self):
        self.configuration, _, self.manifest, self.wheels, self.provisioning = fixtures()

    def test_k_platform_mismatch(self):
        fake = os.uname_result(("Darwin", "host", "release", "version", "x86_64"))
        with patch.object(module._os, "uname", return_value=fake):
            with self.assertRaises(OSError): module._platform_observation()
        fake = os.uname_result(("Linux", "host", "release", "version", "aarch64"))
        with patch.object(module._os, "uname", return_value=fake):
            with self.assertRaises(OSError): module._platform_observation()

    def test_l_package_missing_wrong_version_and_architecture(self):
        provenance = c27.DevPythonInterpreterProvenance()
        valid = b"".join(
            f"{item.package}\t{item.version}\t{item.architecture}\tii \n".encode()
            for item in provenance.packages)
        for output in (
            valid.splitlines(keepends=True)[1:] and b"".join(valid.splitlines(keepends=True)[1:]),
            valid.replace(b"3.12.3-1ubuntu0.17", b"3.12.3-wrong", 1),
            valid.replace(b"amd64", b"arm64", 1),
        ):
            completed = subprocess.CompletedProcess((), 0, stdout=output, stderr=b"")
            with patch.object(module._subprocess, "run", return_value=completed):
                with self.assertRaises(OSError): module._query_packages(provenance)

    def test_m_managed_path_absent_exact_conflict_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "managed")
            uid, gid = os.getuid(), os.getgid()
            absent = module._observe_managed_path(path, "directory", 0o750, uid, gid)
            self.assertEqual(absent.state, "absent")
            os.mkdir(path, 0o750)
            exact = module._observe_managed_path(path, "directory", 0o750, uid, gid)
            self.assertEqual(exact.state, "exact")
            os.chmod(path, 0o755)
            with self.assertRaises(OSError):
                module._observe_managed_path(path, "directory", 0o750, uid, gid)
            os.rmdir(path); Path(path).symlink_to(temporary, target_is_directory=True)
            with self.assertRaises(OSError):
                module._observe_managed_path(path, "directory", 0o750, uid, gid)

    def test_n_conflicting_user_and_group_identities(self):
        group = self.provisioning.group_requirements()[0]
        with patch.object(module._grp, "getgrnam", return_value=SimpleNamespace(gr_gid=group.gid)), \
             patch.object(module._grp, "getgrgid", return_value=SimpleNamespace(gr_name="unrelated")):
            with self.assertRaises(OSError): module._observe_principals(self.provisioning)
        user = self.provisioning.user_requirements()[0]
        with patch.object(module._grp, "getgrnam", side_effect=KeyError), \
             patch.object(module._grp, "getgrgid", side_effect=KeyError), \
             patch.object(module._pwd, "getpwnam", return_value=SimpleNamespace(
                 pw_uid=user.uid, pw_gid=user.primary_gid)), \
             patch.object(module._pwd, "getpwuid", return_value=SimpleNamespace(pw_name="unrelated")):
            with self.assertRaises(OSError): module._observe_principals(self.provisioning)

    def test_o_application_absence_is_acceptable(self):
        manifest = SimpleNamespace(entries=(), reviewed_commit="a" * 40,
                                   canonical_bytes=lambda: b"manifest\n")
        requirement = SimpleNamespace(root="/path/that/c29-test-does-not-create")
        root_requirement = c23.HostPathRequirement(
            requirement.root, "directory", 0o755, 0, 0,
            "must-contain-reviewed-application-before-activation")
        self.assertEqual(module._observe_application(
            manifest, requirement, root_requirement).state, "absent")

    def test_p_exact_application_tree_qualifies(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, manifest, requirement, root_requirement = application_fixture(temporary)
            self.assertEqual(module._observe_application(
                manifest, requirement, root_requirement).state, "exact")

    def test_q_application_file_content_and_mode_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, source, manifest, requirement, root_requirement = application_fixture(temporary)
            source.write_bytes(b"changed")
            with self.assertRaises(OSError):
                module._observe_application(manifest, requirement, root_requirement)
        with tempfile.TemporaryDirectory() as temporary:
            _, source, manifest, requirement, root_requirement = application_fixture(temporary)
            source.chmod(0o664)
            with self.assertRaises(OSError):
                module._observe_application(manifest, requirement, root_requirement)

    def test_r_application_file_wrong_uid_and_gid_rejected(self):
        for field in ("st_uid", "st_gid"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                _, _, manifest, requirement, root_requirement = application_fixture(temporary)
                real_stat = os.stat

                def altered(path, *args, **kwargs):
                    status = real_stat(path, *args, **kwargs)
                    if path == "example.py":
                        return changed_status(status, **{field: getattr(status, field) + 1})
                    return status

                with patch.object(module._os, "stat", side_effect=altered), self.assertRaises(OSError):
                    module._observe_application(manifest, requirement, root_requirement)

    def test_s_application_directory_wrong_owner_or_writable_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, manifest, requirement, root_requirement = application_fixture(temporary)
            real_stat = os.stat

            def wrong_owner(path, *args, **kwargs):
                status = real_stat(path, *args, **kwargs)
                if path == "deployment":
                    return changed_status(status, st_uid=status.st_uid + 1)
                return status

            with patch.object(module._os, "stat", side_effect=wrong_owner), self.assertRaises(OSError):
                module._observe_application(manifest, requirement, root_requirement)
        with tempfile.TemporaryDirectory() as temporary:
            _, source, manifest, requirement, root_requirement = application_fixture(temporary)
            source.parent.chmod(0o775)
            with self.assertRaises(OSError):
                module._observe_application(manifest, requirement, root_requirement)

    def test_t_application_symlink_and_extra_entry_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, source, manifest, requirement, root_requirement = application_fixture(temporary)
            source.unlink(); source.symlink_to("elsewhere")
            with self.assertRaises(OSError):
                module._observe_application(manifest, requirement, root_requirement)
        with tempfile.TemporaryDirectory() as temporary:
            root, _, manifest, requirement, root_requirement = application_fixture(temporary)
            (root / "extra").write_bytes(b"unlisted")
            with self.assertRaises(OSError):
                module._observe_application(manifest, requirement, root_requirement)

    def test_w_reviewed_systemd_digests_qualify_exact_bytes_only(self):
        assets = self.provisioning.installed_asset_requirements()
        self.assertEqual(tuple(item.sha256 for item in assets), (
            "4211b0a4498548a54c4aedeaeb419aef84fb76d16f9da5f60a40b20be1daf95f",
            "00b4d6bef37a1582092ec927cd8501ff922c209f7b10542d264a9c48b74088fa",
        ))
        for asset in assets:
            with self.subTest(asset=asset.source_path), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / Path(asset.destination_path).name
                reviewed = (ROOT / asset.source_path).read_bytes()
                target.write_bytes(reviewed); target.chmod(asset.mode)
                status = target.stat()
                exact = module._observe_managed_path(
                    str(target), "regular_file", asset.mode, status.st_uid, status.st_gid,
                    expected_sha256=asset.sha256)
                self.assertEqual(exact.state, "exact")

                changed = bytes((reviewed[0] ^ 1,)) + reviewed[1:]
                self.assertEqual(len(changed), len(reviewed))
                target.write_bytes(changed); target.chmod(asset.mode)
                with self.assertRaises(OSError):
                    module._observe_managed_path(
                        str(target), "regular_file", asset.mode,
                        status.st_uid, status.st_gid, expected_sha256=asset.sha256)

                target.unlink(); target.symlink_to("elsewhere")
                with self.assertRaises(OSError):
                    module._observe_managed_path(
                        str(target), "regular_file", asset.mode,
                        status.st_uid, status.st_gid, expected_sha256=asset.sha256)

    def test_x_systemd_digest_observation_retains_metadata_checks(self):
        asset = self.provisioning.installed_asset_requirements()[0]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "unit.socket"
            target.write_bytes((ROOT / asset.source_path).read_bytes()); target.chmod(asset.mode)
            status = target.stat()
            for mode, uid, gid in (
                    (0o600, status.st_uid, status.st_gid),
                    (asset.mode, status.st_uid + 1, status.st_gid),
                    (asset.mode, status.st_uid, status.st_gid + 1)):
                target.chmod(mode)
                with self.subTest(mode=mode, uid=uid, gid=gid), self.assertRaises(OSError):
                    module._observe_managed_path(
                        str(target), "regular_file", asset.mode, uid, gid,
                        expected_sha256=asset.sha256)

    def test_y_c29_uses_c23_digests_without_reading_checkout_sources(self):
        calls = []

        def observe(path, kind, mode, uid, gid, expected_bytes=None, expected_sha256=None):
            calls.append((path, kind, mode, uid, gid, expected_bytes, expected_sha256))
            return module.HostManagedPathObservation(path, kind, "absent", mode, uid, gid)

        with patch.object(module, "_read_small_regular", side_effect=AssertionError), \
             patch.object(module, "_observe_managed_path", side_effect=observe):
            module._observe_paths(self.provisioning, self.configuration)
        assets = self.provisioning.installed_asset_requirements()
        asset_calls = calls[-len(assets):]
        self.assertEqual(tuple(item[0] for item in asset_calls),
                         tuple(item.destination_path for item in assets))
        self.assertEqual(tuple(item[1] for item in asset_calls),
                         ("regular_file", "regular_file"))
        self.assertEqual(tuple(item[6] for item in asset_calls),
                         tuple(item.sha256 for item in assets))
        self.assertTrue(all(item[5] is None for item in asset_calls))
        config_call = next(item for item in calls
                           if item[0] == "/etc/omnilyzer/deployment/dev/executor.json")
        self.assertEqual(config_call[5], self.configuration.canonical_bytes())
        self.assertIsNone(config_call[6])

    def test_z_forged_c23_asset_cache_cannot_redefine_digest(self):
        contract = self.provisioning
        original = contract.installed_asset_requirements()[0]
        for digest in ("malformed", "0" * 64):
            forged_asset = object.__new__(c23.HostInstalledAssetRequirement)
            for field in dataclasses.fields(original):
                object.__setattr__(forged_asset, field.name, getattr(original, field.name))
            object.__setattr__(forged_asset, "sha256", digest)
            forged_contract = object.__new__(c23.DevHostProvisioningContract)
            for field in dataclasses.fields(contract):
                object.__setattr__(forged_contract, field.name, getattr(contract, field.name))
            object.__setattr__(forged_contract, "_assets", (
                forged_asset, *contract.installed_asset_requirements()[1:]))
            calls = []

            def observe(path, kind, mode, uid, gid, expected_bytes=None, expected_sha256=None):
                calls.append((path, expected_sha256))
                return module.HostManagedPathObservation(path, kind, "absent", mode, uid, gid)

            with self.subTest(digest=digest), \
                 patch.object(module, "_observe_managed_path", side_effect=observe):
                module._observe_paths(forged_contract, self.configuration)
            asset_calls = calls[-2:]
            self.assertEqual(asset_calls[0], (original.destination_path, original.sha256))

    def test_u_no_network_mutation_installation_or_activation_authority(self):
        source = Path(module.__file__).read_text(); tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom): imports.add((node.module or "").split(".")[0])
        self.assertFalse(imports & {"socket", "urllib", "http", "requests", "venv", "shutil"})
        operations = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(operations & {"write", "write_bytes", "mkdir", "makedirs", "unlink",
                                       "remove", "rename", "replace", "chmod", "chown", "truncate"})
        lowered = source.lower()
        for forbidden in ("apt install", "apt update", "pip install", "systemctl", "docker"):
            self.assertNotIn(forbidden, lowered)

    def test_v_documented_c29_boundaries(self):
        documentation = (ROOT / "deployment/README.md").read_text()
        section = documentation.split("## C29 read-only DEV host qualification", 1)[1]
        for required in (
            "C27 proves", "installed-file hashes",
            "fresh C28 qualification", "absence is recorded explicitly",
            "Conflicting pre-existing", "C30 remains", "C31 remains",
            "Live activation remains", "every C26 file must have",
            "neither broker nor executor may own or write",
        ):
            self.assertIn(required, section)


if __name__ == "__main__":
    unittest.main()
