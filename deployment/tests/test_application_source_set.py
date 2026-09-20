"""Independent repository-only C25 source, import and runtime-data checks."""

import ast
import builtins
from contextlib import ExitStack
import dataclasses
import hashlib
import inspect
import os
from pathlib import Path, PurePosixPath
import re
import socket
import subprocess
import types
import unittest
from unittest.mock import patch

import deployment.application_source_set as module
from deployment.host_service_layout import DevHostServiceLayout

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = "deployment/runtime/dev/"
DATA = {
    RUNTIME + "canary-runtime.json",
    RUNTIME + "compose.yaml",
    RUNTIME + "nginx/nginx.conf",
}


def local_imports(tree, current):
    """Resolve static deployment imports without importing application modules."""
    found = set()
    package = current.split(".")[:-1]

    def add(name, required=True):
        if name == "deployment" or name.startswith("deployment."):
            path = name.replace(".", "/") + ".py"
            initializer = name.replace(".", "/") + "/__init__.py"
            if (ROOT / path).is_file():
                found.add(path)
            elif (ROOT / initializer).is_file():
                found.add(initializer)
            elif required:
                raise AssertionError("Unresolved local import: " + name)

    importlib_aliases = {"importlib"}
    dynamic_aliases = {"__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name)
                if alias.name == "importlib":
                    importlib_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "importlib":
                dynamic_aliases.update(
                    alias.asname or alias.name for alias in node.names
                    if alias.name == "import_module"
                )
            if node.module == "builtins":
                dynamic_aliases.update(
                    alias.asname or alias.name for alias in node.names
                    if alias.name == "__import__"
                )
            if node.level:
                base = package[:len(package) - node.level + 1]
                name = ".".join(base + ([node.module] if node.module else []))
            else:
                name = node.module or ""
            add(name)
            for alias in node.names:
                if alias.name != "*":
                    add(name + "." + alias.name, required=False)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name) and function.id in dynamic_aliases:
                raise AssertionError("Unreviewed dynamic import")
            if isinstance(function, ast.Attribute) and (
                function.attr == "__import__"
                or (function.attr == "import_module" and isinstance(function.value, ast.Name)
                    and function.value.id in importlib_aliases)
            ):
                raise AssertionError("Unreviewed dynamic import")
    return found


def import_closure():
    pending = {"deployment/executor_service_entrypoint.py", "deployment/__init__.py"}
    visited = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        tree = ast.parse((ROOT / path).read_text(), filename=path)
        name = path[:-3].replace("/", ".")
        pending.update(local_imports(tree, name) - visited)
    return visited


class Text(str):
    pass


class ApplicationSourceSetTests(unittest.TestCase):
    def setUp(self):
        self.selection = module.DevApplicationSourceSet()
        self.paths = tuple(item.repository_path for item in self.selection.files)

    def test_public_api_and_field_shapes(self):
        self.assertEqual(module.__all__, ("ApplicationSourceFile", "DevApplicationSourceSet"))
        self.assertEqual(tuple(f.name for f in dataclasses.fields(module.ApplicationSourceFile)),
                         ("repository_path", "target_relative_path", "kind"))
        self.assertEqual(tuple(f.name for f in dataclasses.fields(module.DevApplicationSourceSet)),
                         ("application_root", "entrypoint_module", "files"))
        self.assertEqual(tuple(inspect.signature(module.DevApplicationSourceSet).parameters), ())
        for cls in (module.ApplicationSourceFile, module.DevApplicationSourceSet):
            self.assertTrue(cls.__dataclass_params__.frozen)
            self.assertEqual(cls.__slots__, tuple(f.name for f in dataclasses.fields(cls)))
            self.assertFalse({"sha256", "digest", "mode", "size", "mtime", "source_commit"}
                             & {f.name for f in dataclasses.fields(cls)})
        for item in (self.selection, self.selection.files[0]):
            self.assertFalse(hasattr(item, "__dict__"))
            name = dataclasses.fields(item)[0].name
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(item, name, "changed")
        with self.assertRaises(TypeError):
            module.DevApplicationSourceSet(files=())

    def test_c21_projection_and_entrypoint(self):
        self.assertEqual(self.selection.application_root, DevHostServiceLayout().application_root)
        self.assertEqual(self.selection.application_root, "/opt/omnilyzer/deployment/app")
        self.assertEqual(self.selection.entrypoint_module, "deployment.executor_service_entrypoint")

    def test_counts_order_uniqueness_and_mapping(self):
        self.assertIs(type(self.selection.files), tuple)
        self.assertEqual(len(self.paths), 28)
        self.assertEqual(self.paths, tuple(sorted(self.paths)))
        self.assertEqual(len(set(self.paths)), 28)
        self.assertEqual(len({f.target_relative_path for f in self.selection.files}), 28)
        self.assertEqual(sum(f.kind == "python-module" for f in self.selection.files), 25)
        self.assertEqual(sum(f.kind == "runtime-data" for f in self.selection.files), 3)
        self.assertEqual(self.selection, module.DevApplicationSourceSet())
        for item in self.selection.files:
            self.assertIs(type(item), module.ApplicationSourceFile)
            self.assertEqual(item.repository_path, item.target_relative_path)
            path = PurePosixPath(item.repository_path)
            self.assertFalse(path.is_absolute())
            self.assertEqual(str(path), item.repository_path)
            self.assertFalse(any(p in ("", ".", "..") for p in item.repository_path.split("/")))
            self.assertNotIn("\\", item.repository_path)
            self.assertNotIn("\0", item.repository_path)
            self.assertEqual(item.kind, "python-module" if path.suffix == ".py" else "runtime-data")

    def test_repository_regular_files_without_symlinks(self):
        for path in self.paths:
            with self.subTest(path=path):
                source = ROOT / path
                self.assertTrue(source.is_file())
                self.assertFalse(source.is_symlink())
                for parent in source.relative_to(ROOT).parents:
                    self.assertFalse((ROOT / parent).is_symlink())

    def test_exclusions(self):
        excluded = {
            "application_source_set.py", "host_service_layout.py", "host_provisioning_contract.py",
            "installation_integrity_contract.py", "pyproject.toml",
            "python_interpreter_provenance.py", "dev_host_qualification.py",
            "requirements-linux-x86_64-py312.lock", "DEPENDENCIES.md", "README.md",
            "runtime/dev/README.md", "runtime/dev/host-nginx.conf", "oidc_verifier.py",
            "broker_composition.py", "runtime.py",
        }
        self.assertFalse(set(self.paths) & {"deployment/" + p for p in excluded})
        for path in self.paths:
            self.assertTrue(path.startswith("deployment/"))
            self.assertFalse(any(path.startswith("deployment/" + prefix + "/")
                                 for prefix in ("tests", "schemas", "systemd", "environments",
                                                "provenance")))
        self.assertIn("deployment/broker.py", self.paths)
        self.assertIn("deployment/jwks.py", self.paths)

    def test_exact_ast_import_closure(self):
        declared = {f.repository_path for f in self.selection.files if f.kind == "python-module"}
        discovered = import_closure()
        self.assertIn("deployment/__init__.py", declared)
        self.assertEqual(len(discovered), 25)
        self.assertEqual(discovered, declared)

    def test_import_resolver_forms(self):
        cases = (
            "from .executor import RestrictedPrivilegedExecutor",
            "from . import executor",
            "from deployment.executor import RestrictedPrivilegedExecutor",
            "import deployment.executor",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertIn("deployment/executor.py",
                              local_imports(ast.parse(source), "deployment.example"))

    def test_dynamic_imports_rejected(self):
        for source in (
            "__import__('deployment.executor')",
            "importlib.import_module('deployment.executor')",
            "import importlib as loader\nloader.import_module('deployment.executor')",
            "from importlib import import_module as load\nload('deployment.executor')",
            "import builtins\nbuiltins.__import__('deployment.executor')",
            "from builtins import __import__ as load\nload('deployment.executor')",
        ):
            with self.subTest(source=source), self.assertRaisesRegex(AssertionError, "dynamic import"):
                local_imports(ast.parse(source), "deployment.example")

    def test_exact_runtime_data_closure(self):
        tree = ast.parse((ROOT / "deployment/docker_runtime.py").read_text())
        assignments = {
            node.targets[0].id: ast.dump(node.value, include_attributes=False)
            for node in tree.body if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        }
        # Compare parsed expressions, never execute DockerRuntimeAdapter or its globals.
        expected = {
            "COMPOSE_FILE": 'Path(__file__).parent / "runtime/dev/compose.yaml"',
            "WORKING_DIRECTORY": "COMPOSE_FILE.parent.resolve()",
            "RUNTIME_CONFIG_FILE": 'WORKING_DIRECTORY / "canary-runtime.json"',
        }
        for name, expression in expected.items():
            self.assertEqual(assignments[name], ast.dump(ast.parse(expression, mode="eval").body,
                                                       include_attributes=False))
        compose = (ROOT / (RUNTIME + "compose.yaml")).read_text()
        self.assertLess(len(compose), 16384)
        # Fixed asset: short bind mounts and config file references only. Inspect
        # every relative token, including future additions outside volumes blocks.
        relative = re.findall(r'(?<![\w/])\.{1,2}/[^\s:\'"#]+', compose)
        self.assertEqual(relative, ["./nginx/nginx.conf"])
        sources = re.findall(r'^\s*-\s*[\'"]?((?:\.{1,2}/|/)[^:\s\'"]+):', compose, re.MULTILINE)
        self.assertIn("./nginx/nginx.conf", sources)
        # Restrict host resource classification to volumes, excluding tmpfs.
        volume_sources = []
        volume_indent = None
        for line in compose.splitlines():
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if stripped == "volumes:":
                volume_indent = indent
                continue
            if volume_indent is not None and stripped and indent <= volume_indent:
                volume_indent = None
            if volume_indent is not None:
                match = re.fullmatch(r"\s*-\s+([^:]+):[^:]+:ro", line)
                self.assertIsNotNone(match, "Unreviewed Compose volume syntax: " + line)
                volume_sources.append(match.group(1))
        self.assertIn("./nginx/nginx.conf", volume_sources)
        host_sources = {p for p in volume_sources if p.startswith("/")}
        self.assertEqual(host_sources, {
            "/var/lib/omnilyzer/deployment/dev/canary-runtime",
            "/var/lib/omnilyzer/deployment/dev/nginx-runtime",
        })
        resolved = {str(PurePosixPath(RUNTIME) / p) for p in relative}
        discovered = {RUNTIME + "compose.yaml", RUNTIME + "canary-runtime.json"} | resolved
        declared = {f.repository_path for f in self.selection.files if f.kind == "runtime-data"}
        self.assertEqual(discovered, DATA)
        self.assertEqual(declared, discovered)
        self.assertNotIn(RUNTIME + "host-nginx.conf", self.paths)
        self.assertFalse(host_sources & set(self.paths))

    def test_malformed_source_values_fail_closed(self):
        valid = {"repository_path": "deployment/example.py",
                 "target_relative_path": "deployment/example.py", "kind": "python-module"}
        for field in valid:
            for value in (None, 1, True, b"deployment/example.py", Text(valid[field])):
                with self.subTest(field=field, value=value), self.assertRaises(TypeError):
                    module.ApplicationSourceFile(**(valid | {field: value}))
        malformed = ("", "/a.py", "//a.py", "a//b.py", "a/", "a\\b.py", "a\0.py",
                     "./a.py", "a/./b.py", "../a.py", "a/../b.py")
        for field in ("repository_path", "target_relative_path"):
            for value in malformed:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    module.ApplicationSourceFile(**(valid | {field: value}))
        for changes in ({"target_relative_path": "other.py"}, {"kind": ""},
                        {"kind": "unknown"}, {"repository_path": "a.json", "target_relative_path": "a.json"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module.ApplicationSourceFile(**(valid | changes))
        self.assertEqual(module.ApplicationSourceFile("a.json", "a.json", "runtime-data").kind,
                         "runtime-data")

    def test_contract_import_and_construction_are_inert(self):
        source = (ROOT / "deployment/application_source_set.py").read_text()
        tree = ast.parse(source)
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {"dataclasses", "host_service_layout"})
        self.assertFalse(any(isinstance(node, ast.Import) for node in ast.walk(tree)))
        forbidden = {"open", "read", "read_bytes", "stat", "lstat", "glob", "rglob",
                     "hashlib", "subprocess", "socket", "getenv", "environ", "__import__"}
        identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(forbidden & (identifiers | attributes))
        code = compile(source, "deployment/application_source_set.py", "exec")
        isolated = types.ModuleType("deployment.tests._c25_inert")
        isolated.__package__ = "deployment"
        import sys
        with patch.dict(sys.modules, {isolated.__name__: isolated}), ExitStack() as stack:
            for owner, name in (
                (builtins, "open"), (os, "open"), (os, "stat"), (os, "lstat"),
                (os, "mkdir"), (os, "makedirs"), (os, "getenv"),
                (Path, "open"), (Path, "read_bytes"), (Path, "read_text"),
                (Path, "resolve"), (subprocess, "Popen"), (subprocess, "run"),
                (socket, "socket"), (socket, "create_connection"),
                (hashlib, "sha256"),
            ):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError("not inert")))
            stack.enter_context(patch.dict(os.environ, {}, clear=True))
            exec(code, isolated.__dict__)
            selection = isolated.DevApplicationSourceSet()
            self.assertEqual(len(selection.files), 28)


if __name__ == "__main__":
    unittest.main()
