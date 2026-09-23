"""Deterministic tests for the closed, inert C21 host-service layout."""

import ast
from contextlib import ExitStack
import dataclasses
import importlib
import inspect
from pathlib import PurePosixPath
import unittest
from unittest.mock import patch

import deployment.host_service_layout as module
from deployment.unix_transport import PRODUCTION_EXECUTOR_SOCKET_PATH


FIELD_NAMES = (
    "installation_root", "application_root", "virtualenv_root",
    "python_executable", "working_directory", "executor_module",
    "executor_exec_argv", "broker_user", "broker_group", "executor_user",
    "executor_group", "replay_group", "socket_group", "executor_socket_path",
    "executor_service_unit_name", "executor_socket_unit_name",
)
EXPECTED = (
    "/opt/omnilyzer/deployment", "/opt/omnilyzer/deployment/app",
    "/opt/omnilyzer/deployment/venv", "/opt/omnilyzer/deployment/venv/bin/python",
    "/opt/omnilyzer/deployment/app", "deployment.executor_service_entrypoint",
    ("/opt/omnilyzer/deployment/venv/bin/python", "-m", "deployment.executor_service_entrypoint"),
    "omnilyzer-broker", "omnilyzer-broker", "omnilyzer-executor",
    "omnilyzer-executor", "omnilyzer-replay", "omnilyzer-deployment",
    "/run/omnilyzer/deployment/executor.sock",
    "omnilyzer-deployment-executor.service", "omnilyzer-deployment-executor.socket",
)


class HostServiceLayoutTests(unittest.TestCase):
    """Prove exact structure, relationships, inertness and authority boundaries."""

    def setUp(self):
        """Construct a fresh immutable layout for each test."""
        self.layout = module.DevHostServiceLayout()

    def test_import_and_construction_are_inert(self):
        operations = (
            "builtins.open", "os.open", "os.stat", "os.getenv", "os.getuid",
            "os.getgid", "subprocess.Popen", "socket.socket",
        )
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch(name, side_effect=AssertionError("host I/O")))
                     for name in operations]
            importlib.import_module("deployment.host_service_layout")
            reloaded = importlib.reload(module)
            reloaded.DevHostServiceLayout()
            for mock in mocks:
                mock.assert_not_called()

    def test_exact_public_api_and_zero_inputs(self):
        self.assertEqual(module.__all__, ("DevHostServiceLayout",))
        self.assertEqual([name for name in vars(module) if not name.startswith("_")],
                         ["DevHostServiceLayout"])
        self.assertEqual(tuple(inspect.signature(module.DevHostServiceLayout).parameters), ())
        for args, kwargs in ((("/tmp",), {}), ((), {"installation_root": "/tmp"}),
                             ((), {"executor_user": "root"}),
                             ((), {"executor_exec_argv": ["python", "-c", "pass"]})):
            with self.assertRaises(TypeError):
                module.DevHostServiceLayout(*args, **kwargs)

    def test_exact_fields_and_defaults(self):
        fields = dataclasses.fields(self.layout)
        self.assertEqual(tuple(field.name for field in fields), FIELD_NAMES)
        self.assertTrue(all(not field.init for field in fields))
        self.assertEqual(tuple(getattr(self.layout, name) for name in FIELD_NAMES), EXPECTED)

    def test_paths_are_canonical_exact_strings(self):
        for name in FIELD_NAMES[:5] + ("executor_socket_path",):
            value = getattr(self.layout, name)
            self.assertIs(type(value), str)
            self.assertTrue(module._valid_path(value))
            self.assertTrue(PurePosixPath(value).is_absolute())
            self.assertEqual(str(PurePosixPath(value)), value)
            for forbidden in ("/home/", "/Users/", "/tmp/", "../", "./", "/repos/"):
                self.assertNotIn(forbidden, value)

    def test_path_relationships(self):
        layout = self.layout
        self.assertEqual(PurePosixPath(layout.application_root).parent,
                         PurePosixPath(layout.installation_root))
        self.assertEqual(PurePosixPath(layout.virtualenv_root).parent,
                         PurePosixPath(layout.installation_root))
        self.assertEqual(layout.python_executable, layout.virtualenv_root + "/bin/python")
        self.assertEqual(layout.working_directory, layout.application_root)

    def test_c20_module_and_argv(self):
        entrypoint = importlib.import_module("deployment.executor_service_entrypoint")
        self.assertEqual(entrypoint.__name__, self.layout.executor_module)
        argv = self.layout.executor_exec_argv
        self.assertIs(type(argv), tuple)
        self.assertEqual(len(argv), 3)
        self.assertTrue(all(type(value) is str for value in argv))
        self.assertEqual(argv, EXPECTED[6])

    def test_symbolic_principals(self):
        names = tuple(getattr(self.layout, name) for name in FIELD_NAMES[7:13])
        self.assertEqual(names, EXPECTED[7:13])
        for name in names:
            self.assertIs(type(name), str)
            self.assertRegex(name, r"\A[a-z][a-z0-9-]{0,30}\Z")
        self.assertEqual(names[0], names[1])
        self.assertEqual(names[2], names[3])
        self.assertEqual(len(set(names)), 4)

    def test_socket_authority_and_unit_names(self):
        self.assertEqual(self.layout.executor_socket_path, PRODUCTION_EXECUTOR_SOCKET_PATH)
        self.assertEqual(self.layout.executor_socket_path, EXPECTED[13])
        for name, suffix in ((self.layout.executor_service_unit_name, ".service"),
                             (self.layout.executor_socket_unit_name, ".socket")):
            self.assertIs(type(name), str)
            self.assertTrue(name.endswith(suffix))
            self.assertEqual(name.removesuffix(suffix), "omnilyzer-deployment-executor")
            self.assertNotIn("/", name)
            self.assertFalse(any(char.isspace() for char in name))

    def test_immutability(self):
        other = module.DevHostServiceLayout()
        self.assertTrue(module.DevHostServiceLayout.__dataclass_params__.frozen)
        self.assertEqual(module.DevHostServiceLayout.__slots__, FIELD_NAMES)
        self.assertFalse(hasattr(self.layout, "__dict__"))
        self.assertEqual(self.layout, other)
        self.assertEqual(hash(self.layout), hash(other))
        for name in FIELD_NAMES:
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(self.layout, name, "/tmp")
            self.assertIn(type(getattr(self.layout, name)), (str, tuple))

    def test_invalid_text_is_rejected_purely(self):
        for path in (None, 1, "", "/", "relative", "//opt/app", "/opt/app/",
                     "/opt/./app", "/opt/../app", "/opt//app", "/opt/\0app",
                     "/home", "/home/user/app", "/tmp", "/var/tmp/app"):
            self.assertFalse(module._valid_path(path))
        for name in (None, 1, "", "root:user", "Upper", "a/b", "a b", "a\0", "1user",
                     "a" * 32, "é"):
            self.assertFalse(module._valid_principal(name))

    def test_no_operational_or_numeric_authority_in_source(self):
        source = inspect.getsource(module)
        tree = ast.parse(source)
        imports = [node for node in ast.walk(tree)
                   if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertTrue(all(isinstance(node, ast.ImportFrom) for node in imports))
        self.assertEqual(tuple(node.module for node in imports),
                         ("dataclasses", "pathlib", "re", "unix_transport"))
        self.assertEqual(imports[-1].names[0].name, "PRODUCTION_EXECUTOR_SOCKET_PATH")
        allowed_calls = {
            "type", "str", "any", "all", "len", "frozenset", "ValueError",
            "_PurePosixPath", "_fullmatch", "_field", "_dataclass",
            "_valid_path", "_valid_principal", "_valid_unit",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertIn(node.func.id, allowed_calls)
                else:
                    self.assertIsInstance(node.func, ast.Attribute)
                    self.assertIn(node.func.attr, ("is_absolute", "startswith", "endswith",
                                                  "split", "is_relative_to"))
        literals = [node.value for node in ast.walk(tree)
                    if isinstance(node, ast.Constant) and type(node.value) is str]
        self.assertNotIn(PRODUCTION_EXECUTOR_SOCKET_PATH, literals)
        for value in literals:
            self.assertNotIn("/home/", value)
            self.assertNotIn("/Users/", value)
            self.assertNotIn("/repos/", value)
            self.assertNotIn("omnilyzer-platform", value)
        self.assertFalse(any("uid" in name or "gid" in name for name in FIELD_NAMES))
        for forbidden in ("docker", "sudo", "capabilities", "sudoers", "acl"):
            self.assertFalse(any(forbidden in name for name in FIELD_NAMES))

    def test_internal_defect_fails_with_fixed_error(self):
        with patch.object(module, "_valid_path", return_value=False):
            with self.assertRaisesRegex(ValueError, r"\ADEV host service layout is invalid\Z"):
                module.DevHostServiceLayout()


if __name__ == "__main__":
    unittest.main()
