"""C27 closed CPython archive-provenance model and retained-evidence tests."""

import ast
import builtins
from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deployment.executor_service_config as c17
import deployment.installation_integrity_contract as c24
import deployment.python_interpreter_provenance as module
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]
ERROR = "DEV Python interpreter provenance evidence is invalid"
FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
PACKAGES = (
    (
        "libpython3.12-minimal", "3.12.3-1ubuntu0.17", "amd64",
        "pool/main/p/python3.12/libpython3.12-minimal_3.12.3-1ubuntu0.17_amd64.deb",
        838536, "d646ad7112b5adec21ba0e1af015f04ae8ca7f5efdc619622547dd6673c4c14b",
    ),
    (
        "libpython3.12-stdlib", "3.12.3-1ubuntu0.17", "amd64",
        "pool/main/p/python3.12/libpython3.12-stdlib_3.12.3-1ubuntu0.17_amd64.deb",
        2070530, "45d3f530ba1f9d6e879ad46b92046fabab13fe50a82450e4f65557a3bbad1489",
    ),
    (
        "python3.12", "3.12.3-1ubuntu0.17", "amd64",
        "pool/main/p/python3.12/python3.12_3.12.3-1ubuntu0.17_amd64.deb",
        650732, "6745c9463432e619d7402b117ad4ac86c31dcd3999ba20daa9e395f6f9909d86",
    ),
    (
        "python3.12-minimal", "3.12.3-1ubuntu0.17", "amd64",
        "pool/main/p/python3.12/python3.12-minimal_3.12.3-1ubuntu0.17_amd64.deb",
        2334634, "d452689b9660845345a4c3e05e4ad82c082d5474e04031b7aa47f1a6d5610a6e",
    ),
)


class Text(str):
    """Non-exact text attack."""


class Integer(int):
    """Non-exact integer attack."""


class ProvenanceModelTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(module)
        self.evidence = module.DevPythonInterpreterProvenance()

    def assert_invalid(self, callback):
        with self.assertRaises((TypeError, ValueError)) as caught:
            callback()
        self.assertEqual(str(caught.exception), ERROR)

    def test_a_exact_api_shapes_and_zero_input_boundary(self):
        self.assertEqual(module.__all__, (
            "ArchiveSigningKeyEvidence", "SignedPackagesIndexEvidence",
            "PythonPackageArtifactEvidence", "DevPythonInterpreterProvenance",
        ))
        self.assertEqual({name for name in vars(module) if not name.startswith("_")},
                         set(module.__all__))
        self.assertEqual(tuple(inspect.signature(module.DevPythonInterpreterProvenance).parameters), ())
        for cls in (
            module.ArchiveSigningKeyEvidence, module.SignedPackagesIndexEvidence,
            module.PythonPackageArtifactEvidence, module.DevPythonInterpreterProvenance,
        ):
            self.assertTrue(dataclasses.is_dataclass(cls))
            self.assertTrue(cls.__dataclass_params__.frozen)
            self.assertEqual(cls.__slots__, tuple(field.name for field in dataclasses.fields(cls)))
        for value, field in (
            (self.evidence, "implementation"),
            (self.evidence.archive_key, "fingerprint"),
            (self.evidence.packages_index, "suite"),
            (self.evidence.packages[0], "sha256"),
        ):
            self.assertFalse(hasattr(value, "__dict__"))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(value, field, "changed")
        for name in ("trusted", "approved", "ready", "qualified", "installed"):
            self.assertFalse(any(field.name == name for field in dataclasses.fields(self.evidence)))
        for override in ("packages", "archive_key", "fingerprint", "version", "suite"):
            with self.assertRaises(TypeError):
                module.DevPythonInterpreterProvenance(**{override: "caller-selected"})

    def test_b_import_and_construction_are_inert(self):
        with ExitStack() as stack:
            mocks = [
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                for owner, name in (
                    (builtins, "open"), (os, "open"), (os, "stat"),
                    (subprocess, "Popen"), (socket, "socket"), (hashlib, "sha256"),
                )
            ]
            importlib.reload(module)
            module.DevPythonInterpreterProvenance()
            for mocked in mocks:
                mocked.assert_not_called()

    def test_c_exact_key_index_and_package_evidence(self):
        key = self.evidence.archive_key
        self.assertEqual(key.fingerprint, FINGERPRINT)
        self.assertEqual(key.repository_path,
                         "deployment/provenance/ubuntu-archive-key-2018.asc")
        self.assertEqual(key.sha256,
                         "2a3cc57ab6b47626b496a101c29af6dfe54d54d03d613f2326b9f2a30a15c39b")
        self.assertEqual(key.size, 1660)
        self.assertEqual(self.evidence.packages_index, module._INDEX)
        index = self.evidence.packages_index
        self.assertEqual((index.archive, index.release, index.suite, index.component,
                          index.architecture),
                         ("Ubuntu", "24.04", "noble-security", "main", "amd64"))
        self.assertEqual((index.packages_path, index.packages_sha256, index.packages_size), (
            "main/binary-amd64/Packages",
            "f8fca2bdd59ee4de64a30fc88df870356c6f43e19372b0dbc7caf8b1f2bb2536",
            5476895,
        ))
        actual = tuple((item.package, item.version, item.architecture, item.filename,
                        item.size, item.sha256) for item in self.evidence.packages)
        self.assertEqual(actual, PACKAGES)
        self.assertEqual(tuple(item.package for item in self.evidence.packages),
                         tuple(sorted(item.package for item in self.evidence.packages)))
        self.assertNotIn("python3.12-venv", {item.package for item in self.evidence.packages})

    def test_d_exact_c24_platform_compatibility(self):
        configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
        requirement = c24.DevInstallationIntegrityContract(
            configuration=configuration,
        ).python_environment_requirement()
        self.assertEqual(
            (
                self.evidence.implementation, self.evidence.python_series,
                self.evidence.operating_system, self.evidence.distribution,
                self.evidence.architecture, self.evidence.libc,
            ),
            (
                requirement.implementation, requirement.python_series,
                requirement.operating_system, requirement.distribution,
                requirement.architecture, requirement.libc,
            ),
        )
        self.assertIs(requirement.interpreter_integrity_required, True)
        self.assertEqual(self.evidence.archive_architecture, "amd64")

    def test_e_runtime_package_dependency_boundary(self):
        records = {item.package: item for item in self.evidence.packages}
        self.assertIn("python3.12-minimal (= 3.12.3-1ubuntu0.17)",
                      records["python3.12"].depends)
        self.assertIn("libpython3.12-stdlib (= 3.12.3-1ubuntu0.17)",
                      records["python3.12"].depends)
        self.assertIn("libpython3.12-minimal (= 3.12.3-1ubuntu0.17)",
                      records["python3.12-minimal"].depends)
        self.assertIn("libpython3.12-minimal (= 3.12.3-1ubuntu0.17)",
                      records["libpython3.12-stdlib"].depends)
        self.assertFalse(any("python3.12-venv" in item.depends for item in records.values()))

    def test_f_malformed_value_objects_rejected(self):
        key = self.evidence.archive_key
        key_values = {field.name: getattr(key, field.name) for field in dataclasses.fields(key)}
        key_attacks = {
            "repository_path": (None, Text(key.repository_path), "/absolute.asc", "../key.asc"),
            "sha256": (None, "A" * 64, "0" * 63),
            "size": (None, True, Integer(key.size), 0, -1),
            "fingerprint": (None, FINGERPRINT.lower(), FINGERPRINT[:-1]),
            "canonical_references": (list(key.canonical_references), (), ("http://ubuntu.com",)),
        }
        for field, values in key_attacks.items():
            for value in values:
                with self.subTest(model="key", field=field, value=value):
                    self.assert_invalid(lambda field=field, value=value:
                        module.ArchiveSigningKeyEvidence(**(key_values | {field: value})))

        index = self.evidence.packages_index
        index_values = {field.name: getattr(index, field.name)
                        for field in dataclasses.fields(index)}
        index_attacks = {
            "suite": (None, Text(index.suite), ""),
            "snapshot_timestamp": (None, "2026-09-19", "2026-09-19T00:46:15+00:00"),
            "snapshot_base_url": (None, "http://snapshot.ubuntu.com/ubuntu"),
            "repository_inrelease_path": ("/absolute.InRelease", "../bad.InRelease"),
            "inrelease_sha256": ("A" * 64, "0" * 63),
            "packages_size": (True, Integer(index.packages_size), 0),
            "signing_key_fingerprint": (FINGERPRINT.lower(), FINGERPRINT[:-1]),
        }
        for field, values in index_attacks.items():
            for value in values:
                with self.subTest(model="index", field=field, value=value):
                    self.assert_invalid(lambda field=field, value=value:
                        module.SignedPackagesIndexEvidence(**(index_values | {field: value})))

        package = self.evidence.packages[0]
        package_values = {field.name: getattr(package, field.name)
                          for field in dataclasses.fields(package)}
        package_attacks = {
            "package": (None, Text(package.package), "Bad_Name", ""),
            "version": (None, Text(package.version), ""),
            "filename": (None, "/absolute.deb", "../bad.deb", "pool/source.tar.gz"),
            "size": (None, True, Integer(package.size), 0),
            "sha256": (None, "A" * 64, "0" * 63),
            "depends": (None, Text(package.depends), ""),
        }
        for field, values in package_attacks.items():
            for value in values:
                with self.subTest(model="package", field=field, value=value):
                    self.assert_invalid(lambda field=field, value=value:
                        module.PythonPackageArtifactEvidence(
                            **(package_values | {field: value})))

    def test_g_forged_or_widened_aggregate_rejected(self):
        attacks = []
        widened = object.__new__(module.DevPythonInterpreterProvenance)
        for field in dataclasses.fields(self.evidence):
            object.__setattr__(widened, field.name, getattr(self.evidence, field.name))
        object.__setattr__(widened, "packages", self.evidence.packages + (self.evidence.packages[0],))
        attacks.append(widened)
        forged_key = object.__new__(module.ArchiveSigningKeyEvidence)
        for field in dataclasses.fields(self.evidence.archive_key):
            object.__setattr__(forged_key, field.name,
                               getattr(self.evidence.archive_key, field.name))
        object.__setattr__(forged_key, "fingerprint", "0" * 40)
        changed_key = object.__new__(module.DevPythonInterpreterProvenance)
        for field in dataclasses.fields(self.evidence):
            object.__setattr__(changed_key, field.name, getattr(self.evidence, field.name))
        object.__setattr__(changed_key, "archive_key", forged_key)
        attacks.append(changed_key)
        changed_target = object.__new__(module.DevPythonInterpreterProvenance)
        for field in dataclasses.fields(self.evidence):
            object.__setattr__(changed_target, field.name, getattr(self.evidence, field.name))
        object.__setattr__(changed_target, "distribution", "Ubuntu 26.04")
        attacks.append(changed_target)
        for value in attacks:
            with self.subTest(value=value):
                self.assert_invalid(value.__post_init__)

    def test_h_no_operational_or_installation_authority(self):
        source = Path(module.__file__).read_text()
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        self.assertFalse(imports & {
            "socket", "subprocess", "urllib", "http", "pathlib", "os", "shutil", "venv",
        })
        operations = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(operations & {
            "open", "read_bytes", "write", "write_bytes", "mkdir", "unlink", "replace",
            "chmod", "chown", "system", "run", "Popen",
        })
        lowered = source.lower()
        for forbidden in ("trusted=true", "approved=true", "ready=true", "apt install",
                          "apt update", "pip install", "/opt/"):
            self.assertNotIn(forbidden, lowered)


class RetainedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.evidence = module.DevPythonInterpreterProvenance()
        self.key_path = ROOT / self.evidence.archive_key.repository_path
        self.inrelease_path = ROOT / self.evidence.packages_index.repository_inrelease_path

    def test_i_retained_file_hashes_sizes_and_bounds(self):
        key = self.key_path.read_bytes()
        signed = self.inrelease_path.read_bytes()
        self.assertEqual((len(key), hashlib.sha256(key).hexdigest()),
                         (self.evidence.archive_key.size, self.evidence.archive_key.sha256))
        self.assertEqual((len(signed), hashlib.sha256(signed).hexdigest()),
                         (self.evidence.packages_index.inrelease_size,
                          self.evidence.packages_index.inrelease_sha256))
        self.assertLess(len(key), 4096)
        self.assertLess(len(signed), 256 * 1024)
        self.assertTrue(signed.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\n"))
        self.assertTrue(signed.endswith(b"-----END PGP SIGNATURE-----\n"))

    def test_j_key_fingerprint_and_inrelease_signature_offline(self):
        with tempfile.TemporaryDirectory(prefix="task014-c27-gpg-") as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            show = subprocess.run(
                ("/usr/bin/gpg", "--batch", "--no-options", "--homedir", str(home),
                 "--show-keys", "--with-colons", str(self.key_path)),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, timeout=5, check=True,
            )
            fingerprints = [line.split(b":")[9].decode("ascii")
                            for line in show.stdout.splitlines() if line.startswith(b"fpr:")]
            self.assertEqual(fingerprints, [FINGERPRINT])
            keyring = Path(temporary) / "key.gpg"
            subprocess.run(
                ("/usr/bin/gpg", "--batch", "--yes", "--no-options", "--homedir", str(home),
                 "--dearmor", "--output", str(keyring), str(self.key_path)),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, timeout=5, check=True,
            )
            verified = subprocess.run(
                ("/usr/bin/gpgv", "--status-fd", "1", "--keyring", str(keyring),
                 str(self.inrelease_path)),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, timeout=5, check=True,
            )
        status = verified.stdout.decode("ascii")
        self.assertIn("[GNUPG:] GOODSIG 871920D1991BC93C ", status)
        valid = [line for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0].split()[2], FINGERPRINT)
        self.assertIn(" 1789778829 ", valid[0])

    def test_k_signed_inrelease_identifies_exact_packages_indexes(self):
        text = self.inrelease_path.read_text(encoding="utf-8")
        self.assertIn("Origin: Ubuntu\n", text)
        self.assertIn("Suite: noble-security\n", text)
        self.assertIn("Codename: noble\n", text)
        self.assertIn("Architectures: amd64 ", text)
        self.assertIn("Components: main ", text)
        lines = text.splitlines()
        start = lines.index("SHA256:") + 1
        records = {}
        for line in lines[start:]:
            if not line.startswith(" "):
                break
            match = re.fullmatch(r" ([0-9a-f]{64}) +([0-9]+) (.+)", line)
            self.assertIsNotNone(match)
            records[match.group(3)] = (match.group(1), int(match.group(2)))
        index = self.evidence.packages_index
        self.assertEqual(records[index.packages_path],
                         (index.packages_sha256, index.packages_size))
        self.assertEqual(records[index.compressed_packages_path],
                         (index.compressed_packages_sha256,
                          index.compressed_packages_size))

    def test_l_documented_chain_and_boundaries(self):
        documentation = (ROOT / "deployment/README.md").read_text()
        section = documentation.split("## C27 reviewed CPython interpreter provenance", 1)[1]
        section = section.split("## C28 closed staged wheelhouse qualification", 1)[0]
        for expected in (
            FINGERPRINT, "noble-security", "main/binary-amd64/Packages",
            "3.12.3-1ubuntu0.17", "python3.12-venv", "installed-file hash",
            "Ubuntu base/system-library", "C29", "does not install",
        ):
            self.assertIn(expected, section)


if __name__ == "__main__":
    unittest.main()
