"""C31P immutable installer provenance and staged-byte qualification tests."""

import ast
import builtins
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
import unittest
from unittest.mock import patch
import zipfile

import deployment.executor_service_config as c17
import deployment.installation_integrity_contract as c24
import deployment.pip_installer_provenance as provenance
import deployment.pip_installer_qualification as qualification
import deployment.wheelhouse_qualification as c28
from deployment.tests.test_executor_service_config import configuration_values


PROVENANCE_ERROR = "DEV pip installer provenance evidence is invalid"
QUALIFICATION_ERROR = "DEV pip installer qualification is unavailable"
MODEL_ERROR = "DEV pip installer qualification evidence is invalid"
FILENAME = "pip-26.2.1-py3-none-any.whl"
SIZE = 1816632
SHA256 = "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"


class Text(str):
    """Non-exact text attack."""


class Integer(int):
    """Non-exact integer attack."""


class PipInstallerProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.provenance = provenance.DevPipInstallerProvenance()

    def assert_provenance_invalid(self, callback):
        with self.assertRaises((TypeError, ValueError)) as caught:
            callback()
        self.assertEqual(str(caught.exception), PROVENANCE_ERROR)

    def test_a_exact_zero_input_provenance_and_public_api(self):
        self.assertEqual(provenance.__all__, (
            "PipInstallerArtifactEvidence", "PipInstallerPublicationEvidence",
            "PipInstallerInvocationRequirement", "DevPipInstallerProvenance",
        ))
        self.assertEqual({name for name in vars(provenance) if not name.startswith("_")},
                         set(provenance.__all__))
        self.assertEqual(
            tuple(inspect.signature(provenance.DevPipInstallerProvenance).parameters), (),
        )
        for kind in (
            provenance.PipInstallerArtifactEvidence,
            provenance.PipInstallerPublicationEvidence,
            provenance.PipInstallerInvocationRequirement,
            provenance.DevPipInstallerProvenance,
        ):
            self.assertTrue(dataclasses.is_dataclass(kind))
            self.assertTrue(kind.__dataclass_params__.frozen)
            self.assertEqual(kind.__slots__, tuple(
                field.name for field in dataclasses.fields(kind)
            ))
        for override in ("artifact", "publication", "invocation", "version", "sha256"):
            with self.assertRaises(TypeError):
                provenance.DevPipInstallerProvenance(**{override: "caller-selected"})
        for value, field in (
            (self.provenance, "artifact"),
            (self.provenance.artifact, "sha256"),
            (self.provenance.publication, "source_commit"),
            (self.provenance.invocation, "bootstrap_source"),
        ):
            self.assertFalse(hasattr(value, "__dict__"))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(value, field, "changed")
        self.assertFalse({"trusted", "approved", "safe", "ready"} & {
            field.name for field in dataclasses.fields(self.provenance)
        })

    def test_b_exact_artifact_and_publication_identity(self):
        artifact = self.provenance.artifact
        self.assertEqual((artifact.package, artifact.version, artifact.filename),
                         ("pip", "26.2.1", FILENAME))
        self.assertEqual((artifact.size, artifact.sha256), (SIZE, SHA256))
        self.assertEqual(artifact.wheel_tags, ("py3-none-any",))
        self.assertEqual(artifact.requires_python, ">=3.10")
        self.assertEqual(artifact.release_date, "2026-08-04")
        self.assertEqual(artifact.uploaded_at, "2026-08-04T22:51:12.472093Z")
        self.assertEqual(
            artifact.file_url,
            "https://files.pythonhosted.org/packages/f3/6e/"
            "1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/"
            "pip-26.2.1-py3-none-any.whl",
        )
        publication = self.provenance.publication
        self.assertEqual(publication.publication_method, "PyPI Trusted Publishing")
        self.assertEqual(publication.provenance_service, "PyPI Integrity API v1")
        self.assertEqual((publication.publisher_environment, publication.publisher_kind),
                         ("pypi", "GitHub"))
        self.assertEqual(publication.repository, "pypa/pip")
        self.assertEqual(publication.source_commit,
                         "634a6ec1a5d9dcc2433571cdb2f4c58a4bb29caf")
        self.assertEqual(publication.release_tag, "refs/tags/26.2.1")
        self.assertEqual(publication.workflow_path, ".github/workflows/release.yml")
        self.assertEqual(publication.sigstore_log_index, 2341605236)
        self.assertIn("@refs/tags/26.2.1", publication.certificate_identity)

    def test_c_nested_malformed_and_forged_provenance_rejected(self):
        artifact = self.provenance.artifact
        values = {field.name: getattr(artifact, field.name)
                  for field in dataclasses.fields(artifact)}
        attacks = {
            "package": (None, Text("pip"), ""),
            "filename": ("other.whl", "../" + FILENAME, Text(FILENAME)),
            "size": (None, True, Integer(SIZE), 0),
            "sha256": (None, "A" * 64, "0" * 63),
            "wheel_tags": (["py3-none-any"], (), (Text("py3-none-any"),)),
            "release_date": ("2026/08/04", None),
            "uploaded_at": ("2026-08-04", None),
            "release_url": ("http://pypi.org/project/pip/26.2.1/", None),
        }
        for field, candidates in attacks.items():
            for candidate in candidates:
                with self.subTest(model="artifact", field=field, value=candidate):
                    self.assert_provenance_invalid(lambda field=field, candidate=candidate:
                        provenance.PipInstallerArtifactEvidence(
                            **(values | {field: candidate})))

        publication = self.provenance.publication
        values = {field.name: getattr(publication, field.name)
                  for field in dataclasses.fields(publication)}
        attacks = {
            "source_commit": (None, "A" * 40, "0" * 39),
            "sigstore_log_index": (None, True, Integer(2341605236), -1),
            "authoritative_references": ([], (), ("http://pypi.org",)),
            "release_tag": (None, Text("refs/tags/26.2.1"), ""),
        }
        for field, candidates in attacks.items():
            for candidate in candidates:
                with self.subTest(model="publication", field=field, value=candidate):
                    self.assert_provenance_invalid(lambda field=field, candidate=candidate:
                        provenance.PipInstallerPublicationEvidence(
                            **(values | {field: candidate})))

        invocation = self.provenance.invocation
        self.assertEqual((invocation.implementation, invocation.python_series),
                         ("CPython", "3.12"))
        values = {field.name: getattr(invocation, field.name)
                  for field in dataclasses.fields(invocation)}
        for field, candidate in (
            ("python_executable", "venv/bin/python"),
            ("python_executable", "/opt/../bin/python"),
            ("isolation_argument", None),
            ("bootstrap_source", Text(invocation.bootstrap_source)),
            ("expected_version", ""),
        ):
            with self.subTest(model="invocation", field=field, value=candidate):
                self.assert_provenance_invalid(lambda field=field, candidate=candidate:
                    provenance.PipInstallerInvocationRequirement(
                        **(values | {field: candidate})))

        forged = object.__new__(provenance.PipInstallerArtifactEvidence)
        for field in dataclasses.fields(artifact):
            object.__setattr__(forged, field.name, getattr(artifact, field.name))
        object.__setattr__(forged, "sha256", "0" * 64)
        aggregate = object.__new__(provenance.DevPipInstallerProvenance)
        object.__setattr__(aggregate, "artifact", forged)
        object.__setattr__(aggregate, "publication", publication)
        object.__setattr__(aggregate, "invocation", self.provenance.invocation)
        self.assert_provenance_invalid(aggregate.__post_init__)
        for field, nested in (
            ("publication", dataclasses.replace(publication, source_commit="0" * 40)),
            ("invocation", dataclasses.replace(
                self.provenance.invocation, expected_version="26.2.2",
            )),
        ):
            with self.subTest(forged_nested=field):
                aggregate = object.__new__(provenance.DevPipInstallerProvenance)
                object.__setattr__(aggregate, "artifact", artifact)
                object.__setattr__(aggregate, "publication", publication)
                object.__setattr__(aggregate, "invocation", self.provenance.invocation)
                object.__setattr__(aggregate, field, nested)
                self.assert_provenance_invalid(aggregate.__post_init__)

    def test_d_import_and_construction_are_inert(self):
        with ExitStack() as stack:
            mocks = [
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                for owner, name in (
                    (builtins, "open"), (os, "open"), (os, "stat"),
                    (subprocess, "Popen"), (socket, "socket"), (hashlib, "sha256"),
                )
            ]
            importlib.reload(provenance)
            provenance.DevPipInstallerProvenance()
            for mocked in mocks:
                mocked.assert_not_called()

    def test_e_direct_wheel_zip_import_execution_model(self):
        self.assertEqual(sys.version_info[:2], (3, 12))
        invocation = self.provenance.invocation
        self.assertEqual(invocation.python_executable,
                         "/opt/omnilyzer/deployment/venv/bin/python")
        self.assertEqual(invocation.isolation_argument, "-I")
        with tempfile.TemporaryDirectory() as parent:
            wheel = Path(parent) / FILENAME
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pip/__init__.py", '__version__ = "26.2.1"\n')
                archive.writestr(
                    "pip/__main__.py",
                    "import pip, sys\nprint(f'pip {pip.__version__} from {pip.__file__}')\n",
                )
            environment = {"PATH": "/definitely/untrusted", "PYTHONPATH": "/untrusted"}
            completed = subprocess.run(
                (sys.executable, invocation.isolation_argument, "-c",
                 invocation.bootstrap_source, str(wheel), "--version"),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False,
                timeout=10, env=environment,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("pip 26.2.1", completed.stdout)
        self.assertIn(FILENAME + "/pip/__init__.py", completed.stdout)
        self.assertNotIn("site-packages", completed.stdout)

    def test_f_direct_wheel_origin_and_version_assertion_blocks_fallback(self):
        invocation = self.provenance.invocation
        with tempfile.TemporaryDirectory() as parent:
            wheel = Path(parent) / "fake.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pip/__init__.py", '__version__ = "0.0"\n')
                archive.writestr("pip/__main__.py", "raise AssertionError('executed')\n")
            completed = subprocess.run(
                (sys.executable, "-I", "-c", invocation.bootstrap_source,
                 str(wheel), "--version"),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=10,
                env={"PATH": "/definitely/untrusted", "PYTHONPATH": "/untrusted"},
            )
        self.assertEqual(completed.returncode, 86)


class PipInstallerQualificationTests(unittest.TestCase):
    def setUp(self):
        self.reviewed = provenance.DevPipInstallerProvenance()
        self.artifact = self.reviewed.artifact

    def make_staging(self, parent: str, size: int = SIZE) -> Path:
        root = Path(parent) / "pip-installer"
        root.mkdir()
        with (root / FILENAME).open("wb") as stream:
            stream.truncate(size)
        return root

    def qualify_with_reviewed_hash(self, root: Path):
        with patch.object(qualification, "_hash_file", return_value=SHA256):
            return qualification.qualify_dev_pip_installer(
                staging_directory=str(root),
            )

    def assert_unavailable(self, root: object):
        with self.assertRaises(qualification.PipInstallerQualificationError) as caught:
            qualification.qualify_dev_pip_installer(staging_directory=root)
        self.assertEqual(str(caught.exception), QUALIFICATION_ERROR)

    def test_g_public_api_and_exact_valid_staging_directory(self):
        self.assertEqual(qualification.__all__, (
            "PipInstallerQualificationError", "DevPipInstallerEvidence",
            "qualify_dev_pip_installer",
        ))
        self.assertEqual({name for name in vars(qualification) if not name.startswith("_")},
                         set(qualification.__all__))
        parameters = tuple(inspect.signature(
            qualification.qualify_dev_pip_installer
        ).parameters.values())
        self.assertEqual(tuple(value.name for value in parameters), ("staging_directory",))
        self.assertTrue(all(value.kind is inspect.Parameter.KEYWORD_ONLY
                            for value in parameters))
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_staging(parent)
            before = (root.stat(), (root / FILENAME).stat())
            evidence = self.qualify_with_reviewed_hash(root)
            after = (root.stat(), (root / FILENAME).stat())
        self.assertEqual(evidence.staging_directory, str(root))
        self.assertEqual(evidence.digest_algorithm, "sha256")
        self.assertEqual(evidence.artifact, self.artifact)
        self.assertEqual(before, after)
        self.assertTrue(dataclasses.is_dataclass(type(evidence)))
        self.assertTrue(type(evidence).__dataclass_params__.frozen)
        self.assertFalse(hasattr(evidence, "__dict__"))

    def test_h_wrong_filename_size_digest_and_extra_entry_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_staging(parent)
            (root / FILENAME).rename(root / "pip-renamed.whl")
            self.assert_unavailable(root)
        for size in (0, SIZE - 1, SIZE + 1):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as parent:
                self.assert_unavailable(self.make_staging(parent, size))
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_staging(parent)
            self.assert_unavailable(root)
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_staging(parent)
            (root / "metadata.json").write_text("{}")
            self.assert_unavailable(root)

    def test_i_symlink_wheel_and_symlink_path_component_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_staging(parent)
            wheel = root / FILENAME
            wheel.unlink()
            target = root / "target"
            with target.open("wb") as stream:
                stream.truncate(SIZE)
            wheel.symlink_to(target)
            self.assert_unavailable(root)
        with tempfile.TemporaryDirectory() as parent:
            real = Path(parent) / "real"
            real.mkdir()
            root = self.make_staging(str(real))
            alias = Path(parent) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            self.assert_unavailable(alias / root.name)
        for kind in ("directory", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as parent:
                root = self.make_staging(parent)
                wheel = root / FILENAME
                wheel.unlink()
                if kind == "directory":
                    wheel.mkdir()
                else:
                    os.mkfifo(wheel)
                self.assert_unavailable(root)

    def test_j_source_replacement_during_hash_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_staging(parent)

            def replace(descriptor, expected_size):
                replacement = root / "replacement"
                with replacement.open("wb") as stream:
                    stream.truncate(expected_size)
                os.replace(replacement, root / FILENAME)
                return SHA256

            with patch.object(qualification, "_hash_file", side_effect=replace):
                self.assert_unavailable(root)

    def test_k_hashing_is_bounded_and_requires_exact_eof(self):
        payload = b"x" * (qualification._HASH_CHUNK_BYTES * 2 + 11)
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(payload)
            stream.flush()
            stream.seek(0)
            calls = []
            real_read = os.read

            def checked_read(descriptor, maximum):
                calls.append(maximum)
                return real_read(descriptor, maximum)

            with patch.object(qualification._os, "read", side_effect=checked_read):
                digest = qualification._hash_file(stream.fileno(), len(payload))
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertTrue(all(0 < maximum <= qualification._HASH_CHUNK_BYTES
                            for maximum in calls))
        self.assertEqual(calls[-1], 1)

    def test_l_forged_evidence_and_caller_identity_overrides_rejected(self):
        valid = qualification.DevPipInstallerEvidence(
            "/staging/pip-installer", "sha256", self.artifact,
        )
        attacks = (
            ("relative", "sha256", self.artifact),
            (Text("/staging/pip-installer"), "sha256", self.artifact),
            (valid.staging_directory, "sha512", self.artifact),
            (valid.staging_directory, Text("sha256"), self.artifact),
            (valid.staging_directory, "sha256", object()),
        )
        for values in attacks:
            with self.assertRaises(ValueError) as caught:
                qualification.DevPipInstallerEvidence(*values)
            self.assertEqual(str(caught.exception), MODEL_ERROR)
        forged = object.__new__(provenance.PipInstallerArtifactEvidence)
        for field in dataclasses.fields(self.artifact):
            object.__setattr__(forged, field.name, getattr(self.artifact, field.name))
        object.__setattr__(forged, "sha256", "0" * 64)
        with self.assertRaisesRegex(ValueError, MODEL_ERROR):
            qualification.DevPipInstallerEvidence(
                valid.staging_directory, "sha256", forged,
            )
        with self.assertRaises(TypeError):
            qualification.qualify_dev_pip_installer(
                staging_directory="/staging/pip", sha256="0" * 64,
            )

    def test_m_invalid_paths_and_fixed_generic_errors(self):
        for path in (None, "relative", "/", "//tmp/pip", "/tmp/../pip",
                     "/tmp//pip", "/tmp\\pip", "/tmp/pip\0bad"):
            with self.subTest(path=path):
                self.assert_unavailable(path)

    def test_n_qualification_import_and_construction_are_inert(self):
        with ExitStack() as stack:
            mocks = [
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                for owner, name in (
                    (builtins, "open"), (os, "open"), (os, "stat"),
                    (os, "fstat"), (os, "scandir"), (os, "read"),
                    (subprocess, "Popen"), (socket, "socket"), (hashlib, "sha256"),
                )
            ]
            importlib.reload(qualification)
            artifact = provenance.DevPipInstallerProvenance().artifact
            qualification.DevPipInstallerEvidence(
                "/staging/pip-installer", "sha256", artifact,
            )
            for mocked in mocks:
                mocked.assert_not_called()

    def test_o_no_network_mutation_or_installation_authority(self):
        for target in (Path(provenance.__file__), Path(qualification.__file__)):
            source = target.read_text()
            tree = ast.parse(source)
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.add((node.module or "").split(".")[0])
            self.assertFalse(imports & {
                "socket", "subprocess", "urllib", "http", "venv", "ensurepip",
            })
            operations = {node.attr for node in ast.walk(tree)
                          if isinstance(node, ast.Attribute)}
            self.assertFalse(operations & {
                "write", "write_bytes", "write_text", "mkdir", "makedirs",
                "unlink", "remove", "rename", "replace", "chmod", "chown",
                "truncate", "install",
            })
            self.assertNotIn("O_CREAT", source)

    def test_p_c24_and_c28_runtime_closure_remains_exactly_four(self):
        configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        contract = c24.DevInstallationIntegrityContract(configuration=configuration)
        wheels = contract.python_environment_requirement().wheels
        self.assertEqual(len(wheels), 4)
        self.assertFalse(any(wheel.filename.startswith("pip-") for wheel in wheels))
        source = Path(c28.__file__).read_text().lower()
        self.assertNotIn(FILENAME.lower(), source)
        self.assertNotIn(SHA256, source)

    def test_q_documented_separation_and_attestation_boundary(self):
        readme = Path(provenance.__file__).with_name("README.md").read_text()
        section = readme.split(
            "## C31P reviewed pip installer provenance and qualification", 1,
        )[1]
        self.assertIn(
            "does not claim to reverify the\nattestation cryptographically offline",
            section,
        )
        self.assertIn("not one of C24/C28's four runtime wheels", section)
        self.assertIn("system pip", section)
        self.assertIn("ensurepip", section)
        self.assertIn("directly from its ZIP bytes", section)
        self.assertIn("C31P performs no host provisioning", section)


if __name__ == "__main__":
    unittest.main()
