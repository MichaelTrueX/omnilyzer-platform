"""File: deployment/tests/test_c34x_service_recovery_source_reconciliation.py

Purpose: Reconcile current root-owned Omnilyzer DEV broker/executor source files,
three installed runtime resources and the C34P C34O recovery import graph against
immutable draft Git objects; preserve both service and recovery sources without
installation. Classify the three exact historical-vs-draft diagnostics differences.
Related: deployment/tests/test_c34w_installed_source_feasibility.py,
deployment/c34p_dependency_source_closure.py,
deployment/provenance/python-runtime-py312-linux-x86_64-installed.json,
docs/operations/task014-c34x-service-recovery-reconciliation.md,
.github/workflows/task014-c34d-review.yml.

Default CI runs synthetic and candidate-Git tests only. Opt-in
OMNILYZER_C34X_HOST_READONLY=1 reads existing root-owned source and resources as
the nonprivileged audit user. It NEVER installs, invokes inspected modules,
changes service state, merges code, or authorizes root/recovery execution.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

from deployment import c34p_dependency_source_closure as c34p
from deployment.tests import test_c34w_installed_source_feasibility as c34w


# Section 1: Closed host observations and explicitly unapproved merge scope.
_ERROR = "C34X service-recovery source reconciliation is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_HOST_AUDIT = "OMNILYZER_C34X_HOST_READONLY"
_ROOT = Path(__file__).resolve().parents[2]
_RESOURCE = (
    "deployment/runtime/dev/canary-runtime.json",
    "deployment/runtime/dev/compose.yaml",
    "deployment/runtime/dev/nginx/nginx.conf",
)
_PREVIOUS = {
    "deployment/broker.py": (
        "b7728fb25e0c314ad724cd63ac7edc5ec1d24e05a4737cb7af2c8310bc58c34d",
        "4486fc877a2788bca9aeaa56b98790c6cf216c3b80312dd5e9595832d487fc96",
    ),
    "deployment/broker_https_ingress.py": (
        "484b3378f27064a48393a76379249174e30780d4df39c9f4bf5554788f4dc925",
        "f0bd4c9e3e5b890232b780bd8aa01fb47a0b240454fc988106c30ef5f94b39e7",
    ),
    "deployment/broker_integration.py": (
        "8abdda62c81282c07f403bd924f4d41b35ff8d113d2bee6a66e2ff32e8339b13",
        "05441f3edb490cf4ff17ecfdfdd7e547bd96efb64228e606235cfc6c794d6ac6",
    ),
}
_NAMES = tuple(sorted(_PREVIOUS))
_SERVICE_ENTRIES = (
    "deployment/broker_service_entrypoint.py",
    "deployment/executor_service_entrypoint.py",
)
_SOURCE_COUNT = 92
_RESOURCE_COUNT = 3
_FORBIDDEN_ENV_CHANGE = False  # This module never sets host environment or service units.


class C34XReconciliationHold(Exception):
    """Fixed fail-closed error, independent of source contents or privilege."""


@dataclass(frozen=True, slots=True)
class C34XReconciliationReceipt:
    """Source-set and semantic observations; all authority gates stay FALSE."""

    candidate_sha: str
    proposed_union_count: int
    installed_service_count: int
    recovery_graph_count: int
    shared_source_count: int
    missing_from_installed: int
    installed_outside_recovery: int
    candidate_installed_exact_count: int
    candidate_installed_conflicts: tuple[str, ...]
    retained_resource_paths: tuple[str, ...]
    service_external_import_roots: tuple[str, ...]
    diagnostic_only_ast_normalization_observed: bool
    non_destructive_installation_ready: bool = False
    diagnostic_changes_approved: bool = False
    runtime_import_closure_approved: bool = False
    protected_main_approved: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Reject source-count drift and forged promotions from review results."""
        if (
            type(self.candidate_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", self.candidate_sha) is None
            or type(self.proposed_union_count) is not int
            or self.proposed_union_count != 92
            or type(self.installed_service_count) is not int
            or self.installed_service_count != 38
            or type(self.recovery_graph_count) is not int
            or self.recovery_graph_count != 73
            or type(self.shared_source_count) is not int
            or self.shared_source_count != 19
            or type(self.missing_from_installed) is not int
            or self.missing_from_installed != 54
            or type(self.installed_outside_recovery) is not int
            or self.installed_outside_recovery != 19
            or type(self.candidate_installed_exact_count) is not int
            or self.candidate_installed_exact_count != 35
            or self.candidate_installed_conflicts != _NAMES
            or self.retained_resource_paths != _RESOURCE
            or self.service_external_import_roots != ("cryptography", "jwt")
            or self.diagnostic_only_ast_normalization_observed is not True
            or self.non_destructive_installation_ready is not False
            or self.diagnostic_changes_approved is not False
            or self.runtime_import_closure_approved is not False
            or self.protected_main_approved is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


# Section 2: Exact source classifications without import/execution.
def reconcile_file_sets(
    *, recovery: dict[str, str], installed: dict[str, str],
    candidate: dict[str, str],
) -> tuple[int, tuple[str, ...], int]:
    """Require all current service names and all C34O modules in future union.

    Candidate hashes come only from the supplied immutable-Git reader; they are
    not authoritative protected-main attestation. Return union size, all
    installed-vs-candidate conflicts and total exact installed candidates.
    """
    def valid(mapping: object) -> bool:
        """Reject malformed source path/hash pairs and accidental wide scans."""
        return (
            type(mapping) is dict and 0 < len(mapping) <= 192
            and all(
                type(name) is str
                and c34w._LOCAL_PY.fullmatch(name) is not None
                and type(digest) is str
                and c34w._SHA.fullmatch(digest) is not None
                for name, digest in mapping.items()
            )
        )
    if not valid(recovery) or not valid(installed) or not valid(candidate):
        raise ValueError(_ERROR)
    wanted = set(recovery) | set(installed)
    if set(candidate) != wanted or any(
        candidate[name] != recovery[name] for name in recovery
    ):
        raise ValueError(_ERROR)
    conflicts = tuple(sorted(
        name for name in installed if installed[name] != candidate[name]
    ))
    return len(wanted), conflicts, len(installed) - len(conflicts)


# Section 3: STRICTLY observational AST difference classification.
class _RemoveKnownDiagnostics(ast.NodeTransformer):
    """Normalize only named warning/addFilter AST nodes for pinned blob pairs.

    This deliberately cannot approve a future diff: both source byte hashes
    must first be the exact separately reviewed historical and draft pairs.
    """

    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Discard module docstrings, exact diagnostic logger/filter declarations."""
        node.body = [
            item for item in node.body
            if not (
                isinstance(item, ast.ClassDef) and item.name == "_BoundedStageFilter"
            )
            and not (
                isinstance(item, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id in ("_ALLOWED_STAGE_MESSAGES", "_AUTHORITY_LOG")
                    for target in item.targets
                )
            )
            and not (
                isinstance(item, ast.Expr)
                and isinstance(item.value, ast.Call)
                and isinstance(item.value.func, ast.Attribute)
                and item.value.func.attr == "addFilter"
            )
        ]
        return self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> ast.Import | None:
        """Ignore only additional logger/filter utility imports."""
        node.names = [
            alias for alias in node.names
            if alias.name not in ("logging", "time", "threading")
        ]
        return node if node.names else None

    def visit_Expr(self, node: ast.Expr) -> ast.Expr | None:
        """Exclude descriptive docstrings and literal logger.warning calls."""
        if isinstance(node.value, ast.Constant) and type(node.value.value) is str:
            return None
        call = node.value
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "_AUTHORITY_LOG"
            and call.func.attr == "warning"
            and len(call.args) == 1 and not call.keywords
            and isinstance(call.args[0], ast.Constant)
            and type(call.args[0].value) is str
            and call.args[0].value.startswith("task014_diag stage=")
        ):
            return None
        return self.generic_visit(node)


def reviewed_diagnostic_only_delta(
    name: str, installed: bytes, candidate: bytes,
) -> bool:
    """Recognize ONLY three exact pinned diagnostic edits; never approve them."""
    if (
        type(name) is not str or name not in _PREVIOUS
        or type(installed) is not bytes or type(candidate) is not bytes
        or (
            hashlib.sha256(installed).hexdigest(),
            hashlib.sha256(candidate).hexdigest(),
        ) != _PREVIOUS[name]
    ):
        return False
    try:
        first = _RemoveKnownDiagnostics().visit(ast.parse(installed))
        second = _RemoveKnownDiagnostics().visit(ast.parse(candidate))
        return ast.dump(first, include_attributes=False) == ast.dump(
            second, include_attributes=False,
        )
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return False


# Section 4: Git candidate and root-installed resources without code execution.
def _read_candidate(candidate_sha: str, name: str) -> bytes:
    """Read an exact Git blob only; no Git lazy fetching or mutable checkout."""
    if (
        type(candidate_sha) is not str
        or re.fullmatch(r"[a-f0-9]{40}", candidate_sha) is None
        or not (
            c34w._LOCAL_PY.fullmatch(name) is not None
            or name in _RESOURCE
        )
    ):
        raise ValueError(_ERROR)
    return subprocess.run(
        ("git", "cat-file", "blob", candidate_sha + ":" + name),
        cwd=_ROOT, capture_output=True, check=True, timeout=10,
        env=dict(os.environ, GIT_NO_LAZY_FETCH="1"),
    ).stdout


def _installed_resource_hashes() -> dict[str, str]:
    """Check exact three root-owned resources with mode and O_NOFOLLOW rules."""
    roots = (
        c34w._PACKAGE / "runtime", c34w._PACKAGE / "runtime/dev",
        c34w._PACKAGE / "runtime/dev/nginx",
    )
    for directory in roots:
        c34w._require_root_directory(directory)
    observed: dict[str, str] = {}
    for name in _RESOURCE:
        observed[name] = c34w._sha256_root_source(
            c34w._SOURCE_ROOT / name,
        )
    all_resources: set[str] = set()
    for root, directories, filenames in os.walk(c34w._PACKAGE / "runtime",
                                                  followlinks=False):
        for directory in directories:
            c34w._require_root_directory(Path(root) / directory)
        for filename in filenames:
            full = Path(root) / filename
            all_resources.add(str(full.relative_to(c34w._SOURCE_ROOT)))
    if all_resources != set(_RESOURCE):
        raise ValueError(_ERROR)
    return observed


def _installed_import_roots(
    installed: dict[str, bytes],
) -> tuple[str, ...]:
    """Inspect deployed 38-source graph using existing C34P static AST policy."""
    if len(installed) != 38 or not set(_SERVICE_ENTRIES) <= set(installed):
        raise ValueError(_ERROR)
    allowed_stdlib = set(c34p._STDLIB) | {"signal", "shutil", "tarfile"}
    external: set[str] = set()
    for name, raw in sorted(installed.items()):
        local, other = c34p._static_imports(raw, name)
        if not local <= set(installed):
            raise ValueError(_ERROR)
        external.update(other)
    missing_roots = external - allowed_stdlib
    if missing_roots != {"cryptography", "jwt"}:
        raise ValueError(_ERROR)
    return tuple(sorted(missing_roots))


def observe_readonly_c34x_service_recovery_reconciliation() -> C34XReconciliationReceipt:
    """Derive service/recovery union from exact Git + installed source bytes."""
    try:
        previous = c34w.observe_readonly_c34w_installed_gap()
        c34w.C34WInstalledFeasibilityReceipt.__post_init__(previous)
        sha, recovery = c34w._git_candidate_review()
        if sha != previous.candidate_sha:
            raise ValueError
        installed_hashes = c34w._installed_python_sources()
        candidate = {
            name: hashlib.sha256(_read_candidate(sha, name)).hexdigest()
            for name in sorted(set(recovery) | set(installed_hashes))
        }
        count, conflicts, exact = reconcile_file_sets(
            recovery=recovery, installed=installed_hashes, candidate=candidate,
        )
        if count != _SOURCE_COUNT or conflicts != _NAMES or exact != 35:
            raise ValueError
        paths = sorted(set(recovery) | set(installed_hashes))
        if len(paths) - len(recovery) != 19:
            raise ValueError
        for name in conflicts:
            installed = (c34w._SOURCE_ROOT / name).read_bytes()
            reviewed = _read_candidate(sha, name)
            if not reviewed_diagnostic_only_delta(name, installed, reviewed):
                raise ValueError
        resource_hashes = _installed_resource_hashes()
        if any(
            resource_hashes[name] != hashlib.sha256(
                _read_candidate(sha, name),
            ).hexdigest()
            for name in _RESOURCE
        ):
            raise ValueError
        raw_source = {
            name: (c34w._SOURCE_ROOT / name).read_bytes()
            for name in installed_hashes
        }
        roots = _installed_import_roots(raw_source)

        # Reuse the existing signed/retained C31A installed venv manifest; this
        # shows planned coverage for PyJWT and cryptography, not root permission.
        recorded = json.loads((
            _ROOT / "deployment/provenance/"
                    "python-runtime-py312-linux-x86_64-installed.json"
        ).read_bytes())
        distributions = {
            (entry["name"], entry["version"])
            for entry in recorded["distributions"]
        }
        if not {
            ("PyJWT", "2.13.0"), ("cryptography", "50.0.1"),
        } <= distributions or len(recorded["entries"]) != 237:
            raise ValueError

        receipt = C34XReconciliationReceipt(
            candidate_sha=sha, proposed_union_count=count,
            installed_service_count=len(installed_hashes),
            recovery_graph_count=len(recovery),
            shared_source_count=len(set(recovery) & set(installed_hashes)),
            missing_from_installed=len(set(recovery) - set(installed_hashes)),
            installed_outside_recovery=len(set(installed_hashes) - set(recovery)),
            candidate_installed_exact_count=exact,
            candidate_installed_conflicts=conflicts,
            retained_resource_paths=tuple(sorted(resource_hashes)),
            service_external_import_roots=roots,
            diagnostic_only_ast_normalization_observed=True,
        )
        C34XReconciliationReceipt.__post_init__(receipt)
        return receipt
    except _CONTROL:
        raise
    except Exception:
        raise C34XReconciliationHold(_ERROR) from None


# Section 5: CI-safe synthetic, negative and Git-only source tests.
class C34XReviewContracts(unittest.TestCase):
    """Prevent destructive replacement and forged source/semantic approval."""

    def test_a_union_preserves_both_recovery_and_existing_service(self) -> None:
        """Ensure union counts include every source from both scopes."""
        recovery = {"deployment/__init__.py": "a" * 64,
                    "deployment/recovery.py": "b" * 64}
        installed = {"deployment/__init__.py": "a" * 64,
                     "deployment/executor.py": "c" * 64}
        candidate = dict(recovery, **{"deployment/executor.py": "c" * 64})
        count, changes, exact = reconcile_file_sets(
            recovery=recovery, installed=installed, candidate=candidate,
        )
        self.assertEqual((count, changes, exact), (3, (), 2))

    def test_b_missing_service_file_fails_closed(self) -> None:
        """A recovery-only candidate cannot delete any live service import."""
        recovery = {"deployment/recovery.py": "a" * 64}
        installed = {"deployment/service.py": "b" * 64}
        with self.assertRaises(ValueError):
            reconcile_file_sets(
                recovery=recovery, installed=installed, candidate=recovery,
            )

    def test_c_untrusted_change_to_shared_source_fails_closed(self) -> None:
        """A candidate cannot change a recovery-graph hash silently."""
        recovery = {"deployment/recovery.py": "a" * 64}
        with self.assertRaises(ValueError):
            reconcile_file_sets(
                recovery=recovery, installed=recovery,
                candidate={"deployment/recovery.py": "b" * 64},
            )

    def test_d_diagnostic_pins_reject_injected_auth_edits(self) -> None:
        """No unmatched semantics or later edits can inherit C34X approval."""
        for name in _NAMES:
            with self.subTest(name=name):
                self.assertFalse(reviewed_diagnostic_only_delta(
                    name, b"def authorize(): return True\n",
                    b"def authorize(): return False\n",
                ))
        self.assertFalse(reviewed_diagnostic_only_delta(
            "deployment/other.py", b"x = 1", b"x = 1",
        ))

    def test_e_no_readonly_receipt_can_authorize_root(self) -> None:
        """All five future trust gates must be enforced as immutable FALSE."""
        receipt = C34XReconciliationReceipt(
            candidate_sha="a" * 40, proposed_union_count=92,
            installed_service_count=38, recovery_graph_count=73,
            shared_source_count=19, missing_from_installed=54,
            installed_outside_recovery=19, candidate_installed_exact_count=35,
            candidate_installed_conflicts=_NAMES,
            retained_resource_paths=_RESOURCE,
            service_external_import_roots=("cryptography", "jwt"),
            diagnostic_only_ast_normalization_observed=True,
        )
        for flag in (
            "non_destructive_installation_ready",
            "diagnostic_changes_approved", "runtime_import_closure_approved",
            "protected_main_approved", "root_execution_approved",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                replace(receipt, **{flag: True})

    def test_f_resource_changes_not_reviewed_by_python_closure(self) -> None:
        """The runtime compose/nginx/canary resources are separate assets."""
        self.assertEqual(len(_RESOURCE), _RESOURCE_COUNT)
        self.assertTrue(all(name.startswith("deployment/runtime/dev/")
                            for name in _RESOURCE))

    def test_g_candidate_git_contains_existing_and_recovery_paths(self) -> None:
        """Read exact candidate Git blobs; no installed-host source imports."""
        sha, recovery = c34w._git_candidate_review()
        self.assertEqual(len(recovery), 73)
        self.assertEqual(len(_read_candidate(sha, "deployment/broker.py")), 15966)
        for name in (*_SERVICE_ENTRIES, *_RESOURCE):
            self.assertTrue(_read_candidate(sha, name))
        for name, (installed_sha, candidate_sha) in _PREVIOUS.items():
            self.assertEqual(
                hashlib.sha256(_read_candidate(sha, name)).hexdigest(),
                candidate_sha,
            )
            self.assertNotEqual(installed_sha, candidate_sha)


# Section 6: Explicit real-host read-only audit, excluded from default CI.
@unittest.skipUnless(os.environ.get(_HOST_AUDIT) == "1",
                     "no C34X root-owned installed source audit requested")
class C34XActualHostReview(unittest.TestCase):
    """Observe complete service/recovery candidate without changing host."""

    def test_service_recovery_union_is_unapproved(self) -> None:
        """Expected result is non-destructive source HOLD, never deployment GO."""
        result = observe_readonly_c34x_service_recovery_reconciliation()
        self.assertIs(result.root_execution_approved, False)
        self.assertIs(result.diagnostic_changes_approved, False)
        print("C34X_UNION_HOLD installed=38 recovery=73 union=92 "
              "shared=19 candidate_exact=35 divergences=3 "
              "resources=3 third_party=cryptography,jwt "
              "root_approved=false")


if __name__ == "__main__":
    unittest.main()
