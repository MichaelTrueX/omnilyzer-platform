"""File: deployment/tests/test_c34v_privileged_import_seal.py

Purpose: Re-derive the C34P immutable candidate-Git Python source graph and
audit obvious dynamic import, native loader and SQLite extension entrypoints.
Model a proposed sealed privileged import boundary without constructing or
running any privileged code package.
Related: deployment/c34p_dependency_source_closure.py,
deployment/host_service_layout.py,
deployment/tests/test_c34p_dependency_source_closure.py,
deployment/tests/test_c34u_signed_external_native_provenance.py,
docs/operations/task014-c34v-privileged-import-seal-review.md,
.github/workflows/task014-c34d-review.yml.

All tests are nonprivileged, source-only, review-only. Inspected deployment
modules are never imported or executed. No root, services, network, installs,
config mutation, workflows, source package activation or host runtime changes.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import re
import subprocess
import unittest

from deployment import c34p_dependency_source_closure as c34p
from deployment import host_service_layout as layout


# Section 1: Closed review boundary and future-only root import requirements.
_ERROR = "C34V privileged import seal review is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_EXPECTED_COUNT = 73
_THIRD_PARTY = ("cryptography",)
_SQLITE_DISABLE_COUNT = 3
_PINNED_APP_ROOT = "/opt/omnilyzer/deployment/app"
_PINNED_VENV_ROOT = "/opt/omnilyzer/deployment/venv"
_PINNED_INTERPRETER = _PINNED_VENV_ROOT + "/bin/python"
_ENV_DENY = (
    "LD_AUDIT", "LD_DEBUG", "LD_LIBRARY_PATH", "LD_ORIGIN_PATH",
    "LD_PRELOAD", "PYTHONBREAKPOINT", "PYTHONHOME", "PYTHONINSPECT",
    "PYTHONPATH", "PYTHONSTARTUP", "PYTHONUSERBASE",
)
_BAD_IMPORT_TOPLEVEL = {
    "ctypes", "importlib", "pkgutil", "site", "zipimport",
}
_DIRECT_CALL_DENY = {
    "__import__", "eval", "exec", "compile", "builtins.__import__",
    "builtins.eval", "builtins.exec", "builtins.compile",
    "importlib.import_module", "importlib.util.module_from_spec",
    "importlib.util.spec_from_file_location",
    "ctypes.CDLL", "ctypes.PyDLL", "ctypes.WinDLL",
    "sys.setdlopenflags",
}
_ATTR_CALL_DENY = {
    "load_extension", "load_module", "exec_module", "find_spec",
    "setdlopenflags", "add_dll_directory", "import_module",
}
_PATH_ROOTS = ("sys.path", "sys.meta_path", "sys.path_hooks")
_PATH_MUTATORS = ("append", "extend", "insert", "remove", "pop",
                  "clear", "sort", "reverse")


class C34VSourceSealHold(Exception):
    """One fixed failure message without exposing source or configuration."""


@dataclass(frozen=True, slots=True)
class C34VReviewReceipt:
    """Immutable facts about draft source, never an approved privileged seal."""

    candidate_sha: str
    closure_manifest_sha256: str
    reviewed_source_count: int
    third_party_imports: tuple[str, ...]
    sqlite_extension_disable_calls: int
    proposed_application_root: str
    proposed_virtualenv_root: str
    proposed_python_executable: str
    prohibited_loader_environment: tuple[str, ...]
    ast_dynamic_load_findings: tuple[str, ...]
    source_review_complete: bool
    actual_root_owned_seal_verified: bool = False
    dynamic_loading_closed: bool = False
    protected_main_attested: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Reject forged root/trust approvals or mismatched, fabricated scope."""
        if (
            type(self.candidate_sha) is not str
            or re.fullmatch(r"[a-f0-9]{40}", self.candidate_sha) is None
            or type(self.closure_manifest_sha256) is not str
            or re.fullmatch(r"[a-f0-9]{64}", self.closure_manifest_sha256) is None
            or type(self.reviewed_source_count) is not int
            or self.reviewed_source_count != _EXPECTED_COUNT
            or self.third_party_imports != _THIRD_PARTY
            or self.sqlite_extension_disable_calls != _SQLITE_DISABLE_COUNT
            or self.proposed_application_root != _PINNED_APP_ROOT
            or self.proposed_virtualenv_root != _PINNED_VENV_ROOT
            or self.proposed_python_executable != _PINNED_INTERPRETER
            or self.prohibited_loader_environment != _ENV_DENY
            or type(self.ast_dynamic_load_findings) is not tuple
            or self.ast_dynamic_load_findings
            or self.source_review_complete is not True
            or self.actual_root_owned_seal_verified is not False
            or self.dynamic_loading_closed is not False
            or self.protected_main_attested is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


# Section 2: Static AST load/monkeypatch detection with deliberate limitations.
def _name(node: ast.AST) -> str:
    """Resolve literal Name/Attribute chains only; never evaluate AST source."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return parent + "." + node.attr if parent else ""
    return ""


def _static_dynamic_loader_findings(raw: bytes, path: str) -> tuple[str, ...]:
    """Detect explicit risky Python import and native load sites without imports.

    This is a syntactic supplement to C34P. It cannot prove absence of
    reflection, indirect calls, environment-driven plugins or native dlopen.
    """
    if (
        type(raw) is not bytes or not 0 < len(raw) <= 1024 * 1024
        or type(path) is not str or not path.startswith("deployment/")
        or not path.endswith(".py")
    ):
        raise ValueError(_ERROR)
    tree = ast.parse(raw, filename=path)
    issues: set[str] = set()
    extension_disabled = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name.split(".")[0] in _BAD_IMPORT_TOPLEVEL:
                    issues.add("unsafe-native-import")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _BAD_IMPORT_TOPLEVEL:
                issues.add("unsafe-native-import")
        elif isinstance(node, ast.Call):
            call = _name(node.func)
            if call.endswith(".enable_load_extension"):
                if (
                    len(node.args) != 1 or node.keywords
                    or not isinstance(node.args[0], ast.Constant)
                    or node.args[0].value is not False
                ):
                    issues.add("sqlite-extension-not-false")
                else:
                    extension_disabled += 1
            if call in _DIRECT_CALL_DENY or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _ATTR_CALL_DENY
                and not call.endswith(".enable_load_extension")
            ):
                issues.add("dynamic-import-or-library-loader")
            if any(
                call.startswith(root + ".")
                and call.rsplit(".", 1)[-1] in _PATH_MUTATORS
                for root in _PATH_ROOTS
            ):
                issues.add("runtime-import-path-mutation")
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(_name(target) in _PATH_ROOTS for target in targets):
                issues.add("runtime-import-path-rebinding")
        elif isinstance(node, (ast.Delete,)):
            if any(_name(target) in _PATH_ROOTS for target in node.targets):
                issues.add("runtime-import-path-deletion")
    return tuple(sorted(issues)), extension_disabled


# Section 3: Reuse the existing Git-blob closure and existing service layout.
def inspect_c34v_source_review(
    *, candidate_sha: str, blob_reader,
) -> C34VReviewReceipt:
    """Inspect supplied immutable Git blobs twice via existing C34P machinery.

    Caller-supplied Git blobs are nonauthoritative until a separate final-main
    attestation and root-owned installation seal have been independently
    accepted. This receipt deliberately cannot approve privileged execution.
    """
    try:
        closure = c34p.inspect_c34p_git_blob_closure(
            candidate_sha=candidate_sha, blob_reader=blob_reader,
        )
        if (
            type(closure) is not c34p.C34PSourceClosureReceipt
            or closure.local_module_count != _EXPECTED_COUNT
            or closure.unresolved_third_party != _THIRD_PARTY
            or closure.root_execution_approved is not False
        ):
            raise ValueError
        used = 0
        findings: set[str] = set()
        for name, pinned_sha in closure.local_source_blobs:
            original = blob_reader(name)
            if (
                type(original) is not bytes
                or hashlib.sha256(original).hexdigest() != pinned_sha
            ):
                raise ValueError
            discovered, disabled = _static_dynamic_loader_findings(original, name)
            used += disabled
            findings.update(discovered)
        host_layout = layout.DevHostServiceLayout()
        layout.DevHostServiceLayout.__post_init__(host_layout)
        if (
            host_layout.application_root != _PINNED_APP_ROOT
            or host_layout.virtualenv_root != _PINNED_VENV_ROOT
            or host_layout.python_executable != _PINNED_INTERPRETER
            or findings
        ):
            raise ValueError
        result = C34VReviewReceipt(
            candidate_sha=closure.reviewed_candidate_sha,
            closure_manifest_sha256=closure.closure_manifest_sha256,
            reviewed_source_count=closure.local_module_count,
            third_party_imports=closure.unresolved_third_party,
            sqlite_extension_disable_calls=used,
            proposed_application_root=host_layout.application_root,
            proposed_virtualenv_root=host_layout.virtualenv_root,
            proposed_python_executable=host_layout.python_executable,
            prohibited_loader_environment=_ENV_DENY,
            ast_dynamic_load_findings=tuple(sorted(findings)),
            source_review_complete=True,
        )
        C34VReviewReceipt.__post_init__(result)
        return result
    except _CONTROL:
        raise
    except Exception:
        raise C34VSourceSealHold(_ERROR) from None


# Section 4: Unit-level regressions with source bytes, not installed paths.
class C34VStaticSafetyCases(unittest.TestCase):
    """Block obvious loader, plugin, path and privilege-control substitutions."""

    def test_a_dynamic_loader_and_import_entrypoints_denied(self) -> None:
        """Explicit importlib/ctypes and plugin loading are not quietly allowed."""
        for snippet in (
            "import ctypes\nctypes.CDLL('/tmp/evil.so')\n",
            "from importlib import import_module\nimport_module('evil')\n",
            "import importlib\nimportlib.import_module('evil')\n",
            "import os\nos.add_dll_directory('/tmp')\n",
            "x = __import__('evil')\n",
            "obj.load_extension('evil.so')\n",
            "import sys\nsys.setdlopenflags(2)\n",
        ):
            with self.subTest(snippet=snippet):
                observations, _ = _static_dynamic_loader_findings(
                    snippet.encode(), "deployment/fixture.py",
                )
                self.assertTrue(observations)

    def test_b_import_path_mutations_denied(self) -> None:
        """Path insertion, rebinding and deletion are HOLD for a root runtime."""
        for snippet in (
            "import sys\nsys.path.append('/tmp')\n",
            "import sys\nsys.meta_path = []\n",
            "import sys\ndel sys.path_hooks\n",
        ):
            with self.subTest(snippet=snippet):
                observations, _ = _static_dynamic_loader_findings(
                    snippet.encode(), "deployment/fixture.py",
                )
                self.assertIn(
                    next(x for x in observations if "import-path" in x),
                    observations,
                )

    def test_c_sqlite_extensions_disabled_only(self) -> None:
        """Only literal False qualifies each SQLite extension toggle."""
        for bad in (
            "connection.enable_load_extension(True)",
            "connection.enable_load_extension(enabled)",
            "connection.enable_load_extension(0)",
        ):
            observations, count = _static_dynamic_loader_findings(
                bad.encode(), "deployment/fixture.py",
            )
            self.assertIn("sqlite-extension-not-false", observations)
            self.assertEqual(count, 0)
        observations, count = _static_dynamic_loader_findings(
            b"connection.enable_load_extension(False)", "deployment/fixture.py",
        )
        self.assertEqual((observations, count), ((), 1))

    def test_d_privilege_and_dynamic_flags_cannot_be_forged(self) -> None:
        """Static source evidence never becomes protected-main or root proof."""
        valid = C34VReviewReceipt(
            candidate_sha="a" * 40,
            closure_manifest_sha256="b" * 64,
            reviewed_source_count=73,
            third_party_imports=_THIRD_PARTY,
            sqlite_extension_disable_calls=3,
            proposed_application_root=_PINNED_APP_ROOT,
            proposed_virtualenv_root=_PINNED_VENV_ROOT,
            proposed_python_executable=_PINNED_INTERPRETER,
            prohibited_loader_environment=_ENV_DENY,
            ast_dynamic_load_findings=(), source_review_complete=True,
        )
        for flag in (
            "actual_root_owned_seal_verified", "dynamic_loading_closed",
            "protected_main_attested", "root_execution_approved",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                replace(valid, **{flag: True})

    def test_e_forged_source_scope_or_paths_rejected(self) -> None:
        """Reject a changed closure size, unresolved package or unsafe paths."""
        valid = C34VReviewReceipt(
            candidate_sha="a" * 40,
            closure_manifest_sha256="b" * 64,
            reviewed_source_count=73,
            third_party_imports=_THIRD_PARTY,
            sqlite_extension_disable_calls=3,
            proposed_application_root=_PINNED_APP_ROOT,
            proposed_virtualenv_root=_PINNED_VENV_ROOT,
            proposed_python_executable=_PINNED_INTERPRETER,
            prohibited_loader_environment=_ENV_DENY,
            ast_dynamic_load_findings=(), source_review_complete=True,
        )
        for name, value in (
            ("reviewed_source_count", 72),
            ("third_party_imports", ("unknown",)),
            ("sqlite_extension_disable_calls", 2),
            ("proposed_application_root", "/home/omnigpt/repos"),
            ("prohibited_loader_environment", ("PYTHONPATH",)),
            ("ast_dynamic_load_findings", ("unsafe-native-import",)),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                replace(valid, **{name: value})


# Section 5: Exact current Git-object acceptance, never trusted-root source.
class C34VExactCandidateGitCases(unittest.TestCase):
    """Recheck real proposed Git source without running its contents."""

    def test_c34p_closure_and_loader_controls_exact_git(self) -> None:
        """Read exact immutable candidate commit blobs with lazy fetch disabled."""
        repo = Path(__file__).resolve().parents[2]
        sha = subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=repo, check=True,
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        def blob_reader(path: str) -> bytes:
            """Read only Git blob objects for the exact inspected candidate."""
            return subprocess.run(
                ("git", "cat-file", "blob", sha + ":" + path),
                cwd=repo, check=True, capture_output=True,
                timeout=10, env=dict(os.environ, GIT_NO_LAZY_FETCH="1"),
            ).stdout
        result = inspect_c34v_source_review(
            candidate_sha=sha, blob_reader=blob_reader,
        )
        self.assertEqual(result.reviewed_source_count, 73)
        self.assertEqual(result.sqlite_extension_disable_calls, 3)
        self.assertEqual(result.third_party_imports, ("cryptography",))
        self.assertFalse(result.root_execution_approved)
        self.assertFalse(result.dynamic_loading_closed)
        self.assertFalse(result.actual_root_owned_seal_verified)
        print("C34V_SOURCE_REVIEW_PASS files=73 third_party=cryptography "
              "sqlite_extension_disabled=3 root_approved=false "
              "dynamic_loading_closed=false")


if __name__ == "__main__":
    unittest.main()
