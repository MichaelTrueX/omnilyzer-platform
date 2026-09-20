"""C28 closed staged-wheel byte qualification and attack tests."""

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
import tempfile
import unittest
from unittest.mock import patch

import deployment.executor_service_config as c17
import deployment.installation_integrity_contract as c24
import deployment.wheelhouse_qualification as module
from deployment.tests.test_executor_service_config import configuration_values


UNAVAILABLE = "DEV staged wheelhouse evidence is unavailable"
MODEL_ERROR = "DEV staged wheelhouse evidence is invalid"


class Text(str):
    """Non-exact text attack."""


def contract():
    """Derive all wheel test values from C24, never from a duplicate allowlist."""
    configuration = c17.DevExecutorServiceConfiguration(**configuration_values())
    return c24.DevInstallationIntegrityContract(configuration=configuration)


class WheelhouseQualificationTests(unittest.TestCase):
    """Exercise the value boundary and descriptor-relative qualifier."""

    def setUp(self):
        self.contract = contract()
        self.requirement = self.contract.python_environment_requirement()
        self.wheels = self.requirement.wheels

    def make_wheelhouse(self, parent: str) -> Path:
        root = Path(parent) / "wheelhouse"
        root.mkdir()
        for index, wheel in enumerate(self.wheels):
            (root / wheel.filename).write_bytes((b"staged-test-wheel-" + bytes([index])) * 8192)
        return root

    def expected_hashes(self):
        return [wheel.sha256 for wheel in self.wheels]

    def qualify_with_reviewed_hashes(self, root: Path):
        with patch.object(module, "_hash_file", side_effect=self.expected_hashes()):
            return module.qualify_dev_wheelhouse(
                wheelhouse_path=str(root), integrity_contract=self.contract,
            )

    def assert_unavailable(self, root: Path, hashes=None):
        context = (
            patch.object(module, "_hash_file", side_effect=hashes)
            if hashes is not None else ExitStack()
        )
        with context:
            with self.assertRaises(module.WheelhouseQualificationError) as caught:
                module.qualify_dev_wheelhouse(
                    wheelhouse_path=str(root), integrity_contract=self.contract,
                )
        self.assertEqual(str(caught.exception), UNAVAILABLE)

    def evidence(self):
        files = tuple(module.WheelhouseFileEvidence(w.filename, w.sha256) for w in self.wheels)
        return module.DevWheelhouseEvidence("/staging/wheelhouse", "sha256", files,
                                            self.requirement)

    def test_a_public_api_and_shapes(self):
        self.assertEqual(module.__all__, (
            "WheelhouseQualificationError", "WheelhouseFileEvidence",
            "DevWheelhouseEvidence", "qualify_dev_wheelhouse",
        ))
        self.assertEqual({name for name in vars(module) if not name.startswith("_")},
                         set(module.__all__))
        self.assertTrue(issubclass(module.WheelhouseQualificationError, Exception))
        for cls, names in (
            (module.WheelhouseFileEvidence, ("filename", "sha256")),
            (module.DevWheelhouseEvidence,
             ("wheelhouse_path", "digest_algorithm", "files")),
        ):
            self.assertTrue(dataclasses.is_dataclass(cls))
            self.assertTrue(cls.__dataclass_params__.frozen)
            self.assertTrue(hasattr(cls, "__slots__"))
            self.assertEqual(tuple(field.name for field in dataclasses.fields(cls)), names)
        parameters = tuple(inspect.signature(module.qualify_dev_wheelhouse).parameters.values())
        self.assertEqual(tuple(item.name for item in parameters),
                         ("wheelhouse_path", "integrity_contract"))
        self.assertTrue(all(item.kind is inspect.Parameter.KEYWORD_ONLY for item in parameters))
        evidence = self.evidence()
        self.assertFalse(any(name in {"qualified", "approved", "trusted", "ready"}
                             for name in vars(type(evidence))))
        for value, field in ((evidence, "wheelhouse_path"), (evidence.files[0], "sha256")):
            self.assertFalse(hasattr(value, "__dict__"))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(value, field, "changed")

    def test_b_import_and_construction_are_inert(self):
        with ExitStack() as stack:
            mocks = [
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                for owner, name in (
                    (builtins, "open"), (os, "open"), (os, "stat"), (os, "fstat"),
                    (os, "scandir"), (os, "read"), (subprocess, "Popen"),
                    (socket, "socket"), (hashlib, "sha256"),
                )
            ]
            importlib.reload(module)
            requirement = contract().python_environment_requirement()
            files = tuple(module.WheelhouseFileEvidence(w.filename, w.sha256)
                          for w in requirement.wheels)
            module.DevWheelhouseEvidence("/staging/wheelhouse", "sha256", files, requirement)
            for mocked in mocks:
                mocked.assert_not_called()

    def test_c_exact_valid_four_wheel_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_wheelhouse(parent)
            before = {path.name: (path.read_bytes(), path.stat().st_mode)
                      for path in root.iterdir()}
            evidence = self.qualify_with_reviewed_hashes(root)
            after = {path.name: (path.read_bytes(), path.stat().st_mode)
                     for path in root.iterdir()}
        self.assertEqual(evidence.wheelhouse_path, str(root))
        self.assertEqual(evidence.digest_algorithm, "sha256")
        self.assertEqual(tuple((item.filename, item.sha256) for item in evidence.files),
                         tuple((wheel.filename, wheel.sha256) for wheel in self.wheels))
        self.assertEqual(before, after)

    def test_d_missing_extra_renamed_sdist_and_metadata_rejected(self):
        mutations = (
            lambda root: (root / self.wheels[0].filename).unlink(),
            lambda root: (root / "extra.whl").write_bytes(b"extra"),
            lambda root: (root / self.wheels[0].filename).rename(root / "renamed.whl"),
            lambda root: (root / "source.tar.gz").write_bytes(b"sdist"),
            lambda root: (root / "requirements.txt").write_bytes(b"metadata"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as parent:
                root = self.make_wheelhouse(parent)
                mutate(root)
                self.assert_unavailable(root)

    def test_e_wrong_hash_zero_length_and_truncated_replacement_rejected(self):
        bad_hashes = list(self.expected_hashes())
        bad_hashes[0] = "0" * 64
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_wheelhouse(parent)
            self.assert_unavailable(root, bad_hashes)
        for replacement in (b"", b"truncated"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as parent:
                root = self.make_wheelhouse(parent)
                (root / self.wheels[0].filename).write_bytes(replacement)
                self.assert_unavailable(root)

    def test_f_symlink_directory_and_fifo_wheel_rejected(self):
        for kind in ("symlink", "directory", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as parent:
                root = self.make_wheelhouse(parent)
                target = root / self.wheels[0].filename
                target.unlink()
                if kind == "symlink":
                    target.symlink_to(root / self.wheels[1].filename)
                elif kind == "directory":
                    target.mkdir()
                else:
                    os.mkfifo(target)
                self.assert_unavailable(root)

    def test_g_symlinked_wheelhouse_and_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_wheelhouse(parent)
            alias = Path(parent) / "alias"
            alias.symlink_to(root, target_is_directory=True)
            self.assert_unavailable(alias)
        with tempfile.TemporaryDirectory() as parent:
            real = Path(parent) / "real"
            real.mkdir()
            root = self.make_wheelhouse(str(real))
            alias = Path(parent) / "ancestor"
            alias.symlink_to(real, target_is_directory=True)
            self.assert_unavailable(alias / root.name)

    def test_h_filesystem_replacement_and_directory_races_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_wheelhouse(parent)
            original = module._hash_file
            calls = 0

            def replace_after_hash(descriptor, expected_size):
                nonlocal calls
                self.assertGreater(expected_size, 0)
                result = self.wheels[calls].sha256
                if calls == 0:
                    target = root / self.wheels[0].filename
                    replacement = root / "replacement"
                    replacement.write_bytes(b"replacement")
                    os.replace(replacement, target)
                calls += 1
                return result

            with patch.object(module, "_hash_file", side_effect=replace_after_hash):
                self.assert_unavailable(root)
            self.assertIsNotNone(original)
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_wheelhouse(parent)
            calls = 0

            def replace_first_after_last_hash(descriptor, expected_size):
                nonlocal calls
                result = self.wheels[calls].sha256
                calls += 1
                if calls == len(self.wheels):
                    target = root / self.wheels[0].filename
                    replacement = root / "replacement"
                    replacement.write_bytes(b"late replacement")
                    os.replace(replacement, target)
                return result

            with patch.object(module, "_hash_file", side_effect=replace_first_after_last_hash):
                self.assert_unavailable(root)
        with tempfile.TemporaryDirectory() as parent:
            root = self.make_wheelhouse(parent)
            original_names = module._entry_names
            calls = 0

            def changed_scan(descriptor):
                nonlocal calls
                calls += 1
                names = original_names(descriptor)
                return names if calls == 1 else names + ("late-metadata.json",)

            with patch.object(module, "_hash_file", side_effect=self.expected_hashes()), \
                    patch.object(module, "_entry_names", side_effect=changed_scan):
                self.assert_unavailable(root)

    def test_i_hashing_uses_bounded_chunks(self):
        payload = b"x" * (module._HASH_CHUNK_BYTES * 3 + 17)
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(payload)
            stream.flush()
            stream.seek(0)
            calls = []
            real_read = os.read

            def checked_read(descriptor, maximum):
                calls.append(maximum)
                return real_read(descriptor, maximum)

            with patch.object(module._os, "read", side_effect=checked_read):
                actual = module._hash_file(stream.fileno(), len(payload))
        self.assertEqual(actual, hashlib.sha256(payload).hexdigest())
        self.assertGreaterEqual(len(calls), 5)
        self.assertTrue(all(0 < maximum <= module._HASH_CHUNK_BYTES for maximum in calls))
        self.assertEqual(calls[-1], 1)

    def test_j_malformed_and_forged_evidence_rejected(self):
        wheel = self.wheels[0]
        for filename, digest in (
            (None, wheel.sha256), (Text(wheel.filename), wheel.sha256),
            ("../attack.whl", wheel.sha256), (wheel.filename, None),
            (wheel.filename, "A" * 64), (wheel.filename, "0" * 63),
        ):
            with self.assertRaises(ValueError) as caught:
                module.WheelhouseFileEvidence(filename, digest)
            self.assertEqual(str(caught.exception), MODEL_ERROR)
        valid = self.evidence()
        files = valid.files
        attacks = (
            ("relative", "sha256", files, self.requirement),
            (Text("/staging/wheelhouse"), "sha256", files, self.requirement),
            ("/staging/wheelhouse", Text("sha256"), files, self.requirement),
            ("/staging/wheelhouse", "sha512", files, self.requirement),
            ("/staging/wheelhouse", "sha256", list(files), self.requirement),
            ("/staging/wheelhouse", "sha256", files[:-1], self.requirement),
            ("/staging/wheelhouse", "sha256", tuple(reversed(files)), self.requirement),
            ("/staging/wheelhouse", "sha256", files, object()),
        )
        for values in attacks:
            with self.assertRaises(ValueError) as caught:
                module.DevWheelhouseEvidence(*values)
            self.assertEqual(str(caught.exception), MODEL_ERROR)
        forged = object.__new__(module.WheelhouseFileEvidence)
        object.__setattr__(forged, "filename", wheel.filename)
        object.__setattr__(forged, "sha256", "0" * 64)
        with self.assertRaises(ValueError):
            module.DevWheelhouseEvidence("/staging/wheelhouse", "sha256",
                                         (forged, *files[1:]), self.requirement)

    def test_k_invalid_callers_paths_and_fixed_errors(self):
        for path in (None, "relative", "/", "//tmp/wheels", "/tmp/../wheels",
                     "/tmp//wheels", "/tmp\\wheels", "/tmp/wheels\0bad"):
            with self.assertRaises(module.WheelhouseQualificationError) as caught:
                module.qualify_dev_wheelhouse(
                    wheelhouse_path=path, integrity_contract=self.contract,
                )
            self.assertEqual(str(caught.exception), UNAVAILABLE)
        with self.assertRaises(module.WheelhouseQualificationError):
            module.qualify_dev_wheelhouse(
                wheelhouse_path="/tmp/wheelhouse", integrity_contract=object(),
            )

    def test_l_c24_is_the_only_wheel_closure_source(self):
        source = Path(module.__file__).read_text()
        tree = ast.parse(source)
        constants = {node.value for node in ast.walk(tree)
                     if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        self.assertFalse(any(value.endswith(".whl") for value in constants))
        self.assertFalse(any(len(value) == 64 and set(value) <= set("0123456789abcdef")
                             for value in constants))
        self.assertIn(".python_environment_requirement()", source)
        self.assertNotIn("pip", source.lower())
        self.assertNotIn("urllib", source.lower())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        self.assertFalse(imports & {"socket", "subprocess", "urllib", "http", "venv"})
        operations = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(operations & {
            "write", "write_bytes", "write_text", "mkdir", "makedirs", "unlink",
            "remove", "rename", "replace", "chmod", "chown", "truncate",
        })
        self.assertNotIn("O_CREAT", source)

    def test_m_documented_scope_and_future_boundaries(self):
        documentation = (Path(module.__file__).with_name("README.md")).read_text()
        section = documentation.split("## C28 closed staged wheelhouse qualification", 1)[1]
        self.assertIn("qualifies staged wheel bytes only", section)
        self.assertIn("C27 CPython interpreter provenance remains unresolved", section)
        self.assertIn("A later C29 must compare", section)
        self.assertIn("C28 itself does not install anything", section)
        self.assertIn("contains no\nindependent production filename or digest allowlist", section)


if __name__ == "__main__":
    unittest.main()
