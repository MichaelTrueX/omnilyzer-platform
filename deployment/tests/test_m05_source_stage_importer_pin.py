"""File: deployment/tests/test_m05_source_stage_importer_pin.py
Purpose: Source-only validation of the exact root stage operator and closed
         import chain, without root installation, service changes, or Task014.
Related: deployment/operators/m05_source_stage_cfc.py, PR316 immutable cfc
         source and the original protected 330f manifest.
Sections: source fixtures, import-closure checks, tampering, simulated stage.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
REPO_OPERATOR = REPO / "deployment/operators/m05_source_stage_cfc.py"
OP = REPO_OPERATOR if REPO_OPERATOR.is_file() else Path(__file__).with_name(
    "root-source-stage-reviewed.py"
)
REVIEW_SOURCE = Path("/tmp/m05-pr316-review-source-cfc274-20261121")
SOURCE = REVIEW_SOURCE if REVIEW_SOURCE.is_dir() else REPO
ORIGINAL = (SOURCE / "deployment/analytics_isolated_source_install.py").read_bytes()
ROOT = Path("/opt/omnilyzer/deployment/analytics-app-release-330f3255f0067b9ddbe30d50466830bd71a55a11")
MANIFEST = Path("/home/omnigpt/repos/omnilyzer-platform/.delivery/m05-pr316-source-stage-cfc-20261121/manifest.json")
HAS_ROOT_FIXTURE = ROOT.is_dir() and MANIFEST.is_file()


def load():
    """Import the intended operator from the checkout or isolated review file."""
    spec = importlib.util.spec_from_file_location("m05_stage_reviewed_source_only", OP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def imported_local_paths(relative: str, tree: ast.AST):
    """Enumerate statically resolvable local imports, including deferred ones."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                yield name.name.replace(".", "/") + ".py"
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parent = relative.split("/")[:-1]
                stem = parent[:len(parent) - node.level + 1]
                if node.module:
                    stem += node.module.split(".")
            else:
                stem = node.module.split(".") if node.module else []
            if stem:
                yield "/".join(stem) + ".py"
            if not node.module:
                for name in node.names:
                    yield "/".join(stem + [name.name]) + ".py"


def simulated_root_reader(module):
    """Return source fixture bytes and historical root bytes where hashes differ."""
    baseline = json.loads(MANIFEST.read_text())["baseline_files_sha256"]
    normal = module.trusted_root_file

    def read(path: Path, mode: int | None) -> bytes:
        path = Path(path)
        if path == module.INSTALLER and mode == 0o500:
            return ORIGINAL
        try:
            relative = path.relative_to(SOURCE).as_posix()
        except ValueError:
            return normal(path, mode)
        local_bytes = path.read_bytes()
        if relative in baseline and hashlib.sha256(local_bytes).hexdigest() != baseline[relative]:
            return (ROOT / relative).read_bytes()
        return local_bytes

    return read


class RootSourcePinReviewTests(unittest.TestCase):
    """Review exact root importer bytes, dependency closure and fail-closed stage."""

    def setUp(self):
        self.before_modules = set(sys.modules)
        self.before_path = list(sys.path)

    def tearDown(self):
        for name in set(sys.modules) - self.before_modules:
            if name in ("deployment", "release") or name.startswith(("deployment.", "release.")):
                sys.modules.pop(name, None)
        sys.path[:] = self.before_path

    def test_original_root_installer_actual_git_bytes_match_owner_root_sha(self):
        module = load()
        self.assertEqual(
            module.INSTALLER_SHA,
            "cc7dfd7fb022a01772bb2f18fd1705f6e4f15e706903e4b47c8833b7d7f9ac5b",
        )
        self.assertEqual(hashlib.sha256(ORIGINAL).hexdigest(), module.INSTALLER_SHA)

    def test_pinned_closed_import_graph_and_nonbaseline_exact_bytes(self):
        """A source commit may not silently widen root-side imported Python."""
        module = load()
        self.assertEqual(len(module.REQUIRED_IMPORT_SOURCE_PATHS), 61)
        self.assertEqual(len(module.EXTRA_IMPORT_SOURCE_SHA), 16)
        seen = set()
        stack = ["deployment/analytics_isolated_source_install.py"]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            for candidate in imported_local_paths(
                current, ast.parse((SOURCE / current).read_text())
            ):
                if (SOURCE / candidate).is_file() and candidate not in seen:
                    stack.append(candidate)
        for package in ("deployment/__init__.py", "release/__init__.py"):
            if (SOURCE / package).is_file():
                seen.add(package)
        self.assertEqual(seen, module.REQUIRED_IMPORT_SOURCE_PATHS)
        for relative, digest in module.EXTRA_IMPORT_SOURCE_SHA.items():
            self.assertEqual(
                hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest(),
                digest,
                relative,
            )

    @unittest.skipUnless(HAS_ROOT_FIXTURE, "Requires existing DEV 330f root baseline")
    def test_tampered_installer_denied_before_any_python_import_or_root_stage(self):
        module = load()
        normal = module.trusted_root_file

        def read(path, mode):
            if Path(path) == module.INSTALLER:
                self.assertEqual(mode, 0o500)
                return ORIGINAL + b"\n# tampered\n"
            return normal(path, mode)

        with patch.object(module, "trusted_root_file", side_effect=read):
            with self.assertRaisesRegex(ValueError, "installer SHA is not approved"):
                module.reviewed_source()
        self.assertEqual(sys.path, self.before_path)

    @unittest.skipUnless(HAS_ROOT_FIXTURE, "Requires existing DEV 330f root baseline")
    def test_unreviewed_preloaded_deployment_package_denied(self):
        module = load()
        original = module.trusted_root_file

        def read(path, mode):
            return ORIGINAL if Path(path) == module.INSTALLER else original(path, mode)

        with patch.object(module, "trusted_root_file", side_effect=read):
            with patch.dict(sys.modules, {"deployment": object()}):
                with self.assertRaisesRegex(ValueError, "modules already loaded"):
                    module.reviewed_source()

    @unittest.skipUnless(HAS_ROOT_FIXTURE, "Requires existing DEV 330f root baseline")
    def test_tampered_transitive_import_rejected_before_import(self):
        module = load()
        module.SCRATCH = SOURCE
        module.INSTALLER = SOURCE / "deployment/analytics_isolated_source_install.py"
        normal = simulated_root_reader(module)
        poison = SOURCE / "deployment/dev_host_provisioning_mechanics.py"

        def read(path, mode):
            if Path(path) == poison:
                return b"print('tampered privileged import')\n"
            return normal(path, mode)

        with patch.object(module, "trusted_root_file", side_effect=read):
            with self.assertRaisesRegex(ValueError, "dependency SHA is not approved"):
                module.reviewed_source()
        self.assertEqual(sys.path, self.before_path)
        self.assertNotIn("deployment", sys.modules)

    @unittest.skipUnless(HAS_ROOT_FIXTURE, "Requires existing DEV 330f root baseline")
    def test_positive_source_only_import_origin_and_all_76_bytes(self):
        module = load()
        module.SCRATCH = SOURCE
        module.INSTALLER = SOURCE / "deployment/analytics_isolated_source_install.py"
        normal = simulated_root_reader(module)
        with patch.object(module, "trusted_root_file", side_effect=normal):
            installer, files = module.reviewed_source()
        self.assertEqual(Path(installer.__file__), module.INSTALLER)
        self.assertEqual(len(files), 76)
        self.assertEqual(len(set(name for name, _ in files)), 76)
        self.assertEqual(
            {name: hashlib.sha256(raw).hexdigest() for name, raw in files
             if name in module.REPLACEMENTS_SHA},
            module.REPLACEMENTS_SHA,
        )

    def test_nonroot_rejects_root_stage(self):
        module = load()
        with patch.object(module.os, "getuid", return_value=1005):
            with self.assertRaises(PermissionError):
                module.main(["--stage"])


if __name__ == "__main__":
    unittest.main()
