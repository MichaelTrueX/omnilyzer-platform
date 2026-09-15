"""deployment/tests/test_installation_integrity_contract.py — inert C24 tests.

Repository lock reads occur only in tests; no installation or host activation.
"""

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
import unittest
from unittest.mock import patch

import deployment.installation_integrity_contract as module
import deployment.executor_service_config as c17
import deployment.host_service_layout as c21
from deployment.tests.test_executor_service_config import configuration_values

_API = (
    "RepositoryFileIntegrityRequirement", "WheelIntegrityRequirement",
    "ApplicationIntegrityRequirement", "PythonEnvironmentIntegrityRequirement",
    "DevInstallationIntegrityContract",
)
_ERROR = "DEV installation integrity contract is invalid"
_LOCK_PATH = "deployment/requirements-linux-x86_64-py312.lock"
_LOCK_HASH = "13c7b3f0050f9aff0a94ab324a66276638f8b1b9dd0c62232ec205b24d874d0d"
_WHEELS = (
    ("pyjwt-2.13.0-py3-none-any.whl", "66adcc2aff09b3f1bbd95fc1e1577df8ac8723c978552fd43304c8a290ac5728"),
    ("cryptography-50.0.1-cp311-abi3-manylinux_2_34_x86_64.whl", "51afcfceb15597cf2635068e4ac9a56b2abde622edde17f37d85fd7b5306497a"),
    ("cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl", "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf"),
    ("pycparser-3.0-py3-none-any.whl", "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992"),
)


def make_configuration(**changes):
    """Use the current C17 class after lower-contract import/reload tests."""
    return c17.DevExecutorServiceConfiguration(**configuration_values(**changes))


class Text(str):
    """Non-exact string attack."""


class Integer(int):
    """Non-exact integer attack."""


class Collection(tuple):
    """Non-exact tuple attack."""


class InstallationIntegrityTests(unittest.TestCase):
    """Exercise closed inputs, authority projection and inertness."""

    def setUp(self):
        """Build pure fixtures without host discovery."""
        importlib.reload(module)
        self.configuration = make_configuration(reviewed_commit="7" * 40)
        self.contract = module.DevInstallationIntegrityContract(configuration=self.configuration)
        self.application = self.contract.application_requirement()
        self.environment = self.contract.python_environment_requirement()
        self.layout = self.contract.service_layout()

    def assert_invalid(self, cls, **values):
        """Require the fixed error for a public value-class attack."""
        with self.assertRaises((TypeError, ValueError)) as caught:
            cls(**values)
        self.assertEqual(str(caught.exception), _ERROR)

    def test_a_import_construction_inert(self):
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
                     for owner, name in ((builtins, "open"), (os, "open"), (os, "stat"),
                                         (os, "getenv"), (subprocess, "Popen"), (socket, "socket"))]
            importlib.reload(module)
            configuration = make_configuration()
            module.DevInstallationIntegrityContract(configuration=configuration)
            for mock in mocks:
                mock.assert_not_called()

    def test_b_public_api(self):
        self.assertEqual(module.__all__, _API)
        self.assertEqual(tuple(name for name in vars(module) if not name.startswith("_")), _API)
        for name in _API:
            cls = getattr(module, name)
            self.assertTrue(dataclasses.is_dataclass(cls))
            self.assertTrue(cls.__dataclass_params__.frozen)
            self.assertTrue(hasattr(cls, "__slots__"))
        self.assertEqual(tuple(name for name, value in vars(module.DevInstallationIntegrityContract).items()
                               if not name.startswith("_") and callable(value)),
                         ("service_layout", "application_requirement", "python_environment_requirement"))

    def test_c_constructor_boundary(self):
        cls = module.DevInstallationIntegrityContract
        parameters = tuple(inspect.signature(cls).parameters.values())
        self.assertEqual(tuple(p.name for p in parameters), ("configuration",))
        self.assertIs(parameters[0].kind, inspect.Parameter.KEYWORD_ONLY)
        class Subclass(c17.DevExecutorServiceConfiguration):
            """Exact C17 type is required."""
        class Duck:
            """Canonical-like methods do not grant authority."""
            canonical_bytes = self.configuration.canonical_bytes
        for value in (None, {}, object(), Duck(), object.__new__(Subclass)):
            with self.assertRaises(TypeError) as caught:
                cls(configuration=value)
            self.assertEqual(str(caught.exception), _ERROR)
        with self.assertRaises(TypeError):
            cls(self.configuration)
        for name in ("reviewed_commit", "application_sha256", "application_manifest_sha256",
                     "python_sha256", "interpreter_sha256", "venv_sha256", "wheelhouse_sha256",
                     "wheelhouse_manifest_sha256", "layout", "wheels", "dependency_lock"):
            with self.assertRaises(TypeError):
                cls(configuration=self.configuration, **{name: "sensitive"})

    def test_d_forged_c17_fixed_error(self):
        forged = object.__new__(c17.DevExecutorServiceConfiguration)
        objects = [forged]
        partial = object.__new__(c17.DevExecutorServiceConfiguration)
        object.__setattr__(partial, "reviewed_commit", "sensitive")
        objects.append(partial)
        for name, value in (("reviewed_commit", "sensitive"), ("reviewed_commit", Text("7" * 40)),
                            ("schema_version", True), ("broker_uid", Integer(1001)),
                            ("ingress_file_sha256", list(self.configuration.ingress_file_sha256)),
                            ("ingress_file_sha256", tuple(Text(v) for v in self.configuration.ingress_file_sha256)),
                            ("_installation", None)):
            item = make_configuration(reviewed_commit="7" * 40)
            object.__setattr__(item, name, value)
            objects.append(item)
        no_cache = object.__new__(c17.DevExecutorServiceConfiguration)
        for field in dataclasses.fields(self.configuration):
            if field.init:
                object.__setattr__(no_cache, field.name, getattr(self.configuration, field.name))
        objects.append(no_cache)
        bad_cache = make_configuration(reviewed_commit="7" * 40)
        cache = bad_cache.installation_contract()
        object.__setattr__(cache, "broker_required_group_gids",
                           tuple(Integer(v) for v in cache.broker_required_group_gids))
        objects.append(bad_cache)
        bad_resource = make_configuration(reviewed_commit="7" * 40)
        object.__setattr__(bad_resource.installation_contract().resource_requirements()[0],
                           "owner_uid", Integer(1003))
        objects.append(bad_resource)
        for item in objects:
            with self.assertRaises(TypeError) as caught:
                module.DevInstallationIntegrityContract(configuration=item)
            self.assertEqual(str(caught.exception), _ERROR)
        for raw in (None, bytearray(self.configuration.canonical_bytes()), b"sensitive"):
            with patch.object(c17.DevExecutorServiceConfiguration, "canonical_bytes", return_value=raw):
                with self.assertRaises(TypeError) as caught:
                    module.DevInstallationIntegrityContract(configuration=self.configuration)
                self.assertEqual(str(caught.exception), _ERROR)
        for exception in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with patch.object(c17.DevExecutorServiceConfiguration, "canonical_bytes", side_effect=exception):
                with self.assertRaises(exception):
                    module.DevInstallationIntegrityContract(configuration=self.configuration)

    def test_e_commit_binding(self):
        self.assertEqual(self.application.reviewed_commit, self.configuration.reviewed_commit)
        other = make_configuration(reviewed_commit="8" * 40)
        self.assertEqual(module.DevInstallationIntegrityContract(configuration=other)
                         .application_requirement().reviewed_commit, "8" * 40)
        with patch.object(module, "_parse_configuration", return_value=other):
            with self.assertRaises(TypeError) as caught:
                module.DevInstallationIntegrityContract(configuration=self.configuration)
            self.assertEqual(str(caught.exception), _ERROR)

    def test_f_c21_paths_cached_once(self):
        self.assertEqual((self.application.root, self.environment.root, self.environment.python_executable),
                         (self.layout.application_root, self.layout.virtualenv_root, self.layout.python_executable))
        self.assertEqual((self.application.root, self.environment.root, self.environment.python_executable),
                         ("/opt/omnilyzer/deployment/app", "/opt/omnilyzer/deployment/venv",
                          "/opt/omnilyzer/deployment/venv/bin/python"))
        with patch.object(module, "_DevHostServiceLayout", wraps=c21.DevHostServiceLayout) as constructor:
            # Validation reads C21 dataclass defaults, so retain the class metadata on the spy.
            constructor.__dataclass_fields__ = c21.DevHostServiceLayout.__dataclass_fields__
            contract = module.DevInstallationIntegrityContract(configuration=self.configuration)
            constructor.assert_called_once_with()
            self.assertIs(contract.service_layout(), contract.service_layout())
        self.assertIs(self.application, self.contract.application_requirement())
        self.assertIs(self.environment, self.contract.python_environment_requirement())

    def test_g_manifest_semantics(self):
        self.assertEqual(dataclasses.astuple(self.application), (
            self.layout.application_root, self.configuration.reviewed_commit,
            "canonical-relative-file-set-v1", "sha256", True,
            ("path", "sha256", "mode"), True, True, False, False,
        ))
        self.assertEqual(tuple(f.name for f in dataclasses.fields(self.application)), (
            "root", "reviewed_commit", "manifest_kind", "digest_algorithm", "manifest_required",
            "manifest_entry_fields", "regular_files_only", "sorted_unique_paths",
            "symlinks_allowed", "unlisted_paths_allowed",
        ))

    def test_h_lock_independent_hash(self):
        lock = Path(__file__).absolute().parents[2] / _LOCK_PATH
        self.assertEqual(hashlib.sha256(lock.read_bytes()).hexdigest(), _LOCK_HASH)
        self.assertIs(type(self.environment.dependency_lock), module.RepositoryFileIntegrityRequirement)
        self.assertEqual(dataclasses.astuple(self.environment.dependency_lock), (_LOCK_PATH, _LOCK_HASH))

    def test_i_exact_wheel_closure(self):
        wheels = self.environment.wheels
        self.assertIs(type(wheels), tuple)
        self.assertEqual(len(wheels), 4)
        self.assertTrue(all(type(w) is module.WheelIntegrityRequirement for w in wheels))
        self.assertEqual(tuple(dataclasses.astuple(w) for w in wheels), _WHEELS)
        self.assertEqual(len({w.filename for w in wheels}), 4)
        self.assertEqual(len({w.sha256 for w in wheels}), 4)
        self.assertTrue(all(w.filename.endswith(".whl") for w in wheels))

    def test_j_lock_records_cross_check(self):
        text = (Path(__file__).absolute().parents[2] / _LOCK_PATH).read_text()
        names = re.findall(r"^# wheel: (.+)$", text, re.MULTILINE)
        hashes = re.findall(r"^    --hash=sha256:([0-9a-f]{64})$", text, re.MULTILINE)
        self.assertEqual(len(names), 4)
        self.assertEqual(len(hashes), 4)
        self.assertEqual(tuple(zip(names, hashes)), _WHEELS)
        blocks = text.split("# wheel: ")[1:]
        for block, (filename, digest) in zip(blocks, _WHEELS, strict=True):
            self.assertEqual(block.splitlines()[0], filename)
            self.assertIn("--hash=sha256:" + digest, block)

    def test_k_python_target(self):
        env = self.environment
        self.assertEqual((env.implementation, env.python_series, env.operating_system,
                          env.distribution, env.architecture, env.libc),
                         ("CPython", "3.12", "Linux", "Ubuntu 24.04", "x86_64", "glibc"))
        self.assertIs(env.interpreter_integrity_required, True)
        for value in (env.source_builds_allowed, env.network_install_allowed, env.extra_wheels_allowed):
            self.assertIs(value, False)

    def test_l_no_fake_digests_or_trust(self):
        source = inspect.getsource(module)
        for name in ("application_sha256", "application_manifest_sha256", "python_sha256",
                     "interpreter_sha256", "venv_sha256", "wheelhouse_sha256", "wheelhouse_manifest_sha256"):
            self.assertNotIn(name, source)
        for name in _API:
            self.assertFalse({f.name for f in dataclasses.fields(getattr(module, name))}
                             & {"qualified", "is_qualified", "approved", "trusted", "ready"})

    def test_m_no_production_wheelhouse_path(self):
        literals = [n.value for n in ast.walk(ast.parse(inspect.getsource(module)))
                    if isinstance(n, ast.Constant) and type(n.value) is str]
        for value in literals:
            self.assertIsNone(re.search(r"/[^\s]*wheelhouse", value))
        for value in (self.application, self.environment):
            self.assertFalse(any("wheelhouse" in f.name for f in dataclasses.fields(value)))

    def test_n_no_task013_authority(self):
        source = inspect.getsource(module)
        imports = [n for n in ast.walk(ast.parse(source)) if isinstance(n, (ast.Import, ast.ImportFrom))]
        for node in imports:
            self.assertIsInstance(node, ast.ImportFrom)
            self.assertFalse(node.module.startswith("release"))
        for value in ("omnilyzer-release-canary", "@omnilyzer/release-canary",
                      "omnilyzer/task013-release-canary", "release-manifest.json", "release-provenance.json"):
            self.assertNotIn(value, source)

    def test_o_value_attacks(self):
        for requirement in (self.application, self.environment, self.environment.dependency_lock,
                            self.environment.wheels[0]):
            values = {f.name: getattr(requirement, f.name) for f in dataclasses.fields(requirement)}
            for name, original in values.items():
                attacks = [None, 1, Integer(1)]
                if type(original) is str:
                    attacks.extend((Text(original), "", "../", "./", "a\\b", "a\0b"))
                    if name != "path":
                        attacks.append("sensitive")
                elif type(original) is bool:
                    attacks.append(not original)
                elif type(original) is tuple:
                    attacks.extend((list(original), Collection(original)))
                for attack in attacks:
                    self.assert_invalid(type(requirement), **(values | {name: attack}))
        for path in ("/absolute", "a/", "a//b", "a/../b", "a/./b", ".", ".."):
            self.assert_invalid(module.RepositoryFileIntegrityRequirement, path=path, sha256=_LOCK_HASH)
        for digest in (_LOCK_HASH.upper(), "a" * 63, "g" * 64):
            self.assert_invalid(module.RepositoryFileIntegrityRequirement, path=_LOCK_PATH, sha256=digest)
            self.assert_invalid(module.WheelIntegrityRequirement, filename=_WHEELS[0][0], sha256=digest)
        for filename in ("../a.whl", "/a.whl", "a\\b.whl", "a b.whl", "é.whl", "a\0.whl",
                         "a.tar.gz", "a.zip", "a.WHL", ".", "..", "a" * 256 + ".whl"):
            self.assert_invalid(module.WheelIntegrityRequirement, filename=filename, sha256=_LOCK_HASH)
        env = {f.name: getattr(self.environment, f.name) for f in dataclasses.fields(self.environment)}
        for wheels in ((), self.environment.wheels + (self.environment.wheels[0],),
                       self.environment.wheels[::-1], (self.environment.wheels[0],) * 4,
                       (dataclasses.replace(self.environment.wheels[0], sha256="a" * 64),)
                       + self.environment.wheels[1:]):
            self.assert_invalid(module.PythonEnvironmentIntegrityRequirement, **(env | {"wheels": wheels}))
        lock = dataclasses.replace(self.environment.dependency_lock, sha256="a" * 64)
        self.assert_invalid(module.PythonEnvironmentIntegrityRequirement, **(env | {"dependency_lock": lock}))
        for path in ("/tmp/app", "/home/app", "relative"):
            with self.assertRaises(ValueError):
                dataclasses.replace(self.application, root=path)
            with self.assertRaises(ValueError):
                dataclasses.replace(self.environment, root=path)
        with self.assertRaises(TypeError):
            dataclasses.replace(self.application, manifest_entry_fields=(Text("path"), "sha256", "mode"))

    def test_p_immutability(self):
        values = (self.contract, self.application, self.environment, self.environment.dependency_lock)
        values += self.environment.wheels
        for value in values:
            self.assertFalse(hasattr(value, "__dict__"))
            self.assertEqual(hash(value), hash(value))
            for field in dataclasses.fields(value):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(value, field.name, "sensitive")
                self.assertNotIsInstance(getattr(value, field.name), (list, dict, set))
        self.assertEqual(self.contract, module.DevInstallationIntegrityContract(
            configuration=make_configuration(reviewed_commit="7" * 40)))
        self.assertEqual(hash(self.contract), hash(module.DevInstallationIntegrityContract(
            configuration=make_configuration(reviewed_commit="7" * 40))))

    def test_q_pure_operation_allowlist(self):
        tree = ast.parse(inspect.getsource(module))
        imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertEqual(imports, ["dataclasses", "re", "executor_service_config", "host_service_layout"])
        allowed_names = {"next", "_fields", "type", "TypeError", "ValueError", "_text", "_fullmatch",
                         "len", "any", "all", "zip", "_digest", "_same_value", "_is_dataclass", "_closed", "_layout_default", "tuple",
                         "RepositoryFileIntegrityRequirement", "WheelIntegrityRequirement", "getattr",
                         "_parse_configuration", "_DevHostServiceLayout", "ApplicationIntegrityRequirement",
                         "PythonEnvironmentIntegrityRequirement", "_dataclass", "_field"}
        allowed_attributes = {"split", "canonical_bytes", "installation_contract", "__setattr__"}
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, (ast.Import, ast.AsyncFunctionDef, ast.Await))
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertIn(node.func.id, allowed_names)
                else:
                    self.assertIsInstance(node.func, ast.Attribute)
                    self.assertIn(node.func.attr, allowed_attributes)
                    if node.func.attr == "__setattr__":
                        self.assertEqual(node.func.value.id, "object")
        literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and type(n.value) is str}
        self.assertFalse(literals & {self.layout.application_root, self.layout.virtualenv_root,
                                     self.layout.python_executable})

    def test_r_exact_other_field_shapes(self):
        self.assertEqual(tuple(f.name for f in dataclasses.fields(module.RepositoryFileIntegrityRequirement)),
                         ("path", "sha256"))
        self.assertEqual(tuple(f.name for f in dataclasses.fields(module.WheelIntegrityRequirement)),
                         ("filename", "sha256"))
        self.assertEqual(tuple(f.name for f in dataclasses.fields(module.PythonEnvironmentIntegrityRequirement)), (
            "root", "python_executable", "implementation", "python_series", "operating_system", "distribution",
            "architecture", "libc", "dependency_lock", "wheels", "interpreter_integrity_required",
            "source_builds_allowed", "network_install_allowed", "extra_wheels_allowed",
        ))

    def test_nested_forged_requirements(self):
        for cls, name in ((module.RepositoryFileIntegrityRequirement, "dependency_lock"),
                          (module.WheelIntegrityRequirement, "wheels")):
            value = object.__new__(cls)
            changes = {name: value if name == "dependency_lock" else (value,)}
            with self.assertRaises(TypeError) as caught:
                dataclasses.replace(self.environment, **changes)
            self.assertEqual(str(caught.exception), _ERROR)

    def test_error_categories(self):
        with self.assertRaises(TypeError):
            module.RepositoryFileIntegrityRequirement(path=Text("a"), sha256=_LOCK_HASH)
        with self.assertRaises(ValueError):
            module.RepositoryFileIntegrityRequirement(path="../a", sha256=_LOCK_HASH)
        with self.assertRaises(TypeError):
            dataclasses.replace(self.environment, network_install_allowed=1)
        with self.assertRaises(ValueError):
            dataclasses.replace(self.environment, network_install_allowed=True)


if __name__ == "__main__":
    unittest.main()
