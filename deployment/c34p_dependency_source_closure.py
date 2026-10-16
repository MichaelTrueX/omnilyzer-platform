"""File: deployment/c34p_dependency_source_closure.py

Purpose: Deterministic, read-only Python import and Git-blob provenance
inventory for Task 014's proposed C34O root-side recovery inspector.
Related: deployment/c34o_six_prefix_recovery_inspection.py,
deployment/c34n_root_predecessor_adapter.py,
deployment/c34i_final_main_seal.py,
deployment/tests/test_c34p_dependency_source_closure.py.

This module deliberately never loads/imports the inspected files or executes
source code. It has no GitHub API, root, installation, network, service,
authorization or filesystem writer. The supplied immutable blob reader is
only evidence input, NOT trusted protected-main attestation. Its receipts
always contain root_execution_approved=False.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import re
from typing import Callable


# Section 1: Closed root entrypoint and review-only provenance rules.
_ENTRY = "deployment/c34o_six_prefix_recovery_inspection.py"
_PACKAGE = "deployment/__init__.py"
_ERROR = "C34P transitive source closure is unavailable"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MODULE = re.compile(r"[a-z][a-z0-9_]*\Z")
_LIMIT = 1024 * 1024
_MAX_MODULES = 192

# Exact stdlib top-level imports seen in the Task 014 reviewed source graph.
# A newly imported top-level name becomes a review blocker by default.
_STDLIB = frozenset((
    "__future__", "argparse", "base64", "binascii", "dataclasses",
    "datetime", "fcntl", "grp", "gzip", "hashlib", "http",
    "inspect", "io", "ipaddress", "itertools", "json", "logging",
    "math", "os", "pathlib", "platform", "posixpath", "pwd",
    "re", "selectors", "socket", "sqlite3", "ssl", "stat",
    "struct", "subprocess", "sys", "tempfile", "threading",
    "time", "types", "typing", "urllib", "uuid",
))
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class C34PSourceClosureError(Exception):
    """A fixed nonsecret error for malformed, missing or dynamic source."""


@dataclass(frozen=True, slots=True)
class C34PSourceClosureReceipt:
    """Canonical inventory with a permanently blocked root-execution flag."""

    reviewed_candidate_sha: str
    local_source_blobs: tuple[tuple[str, str], ...]
    stdlib_names: tuple[str, ...]
    unresolved_third_party: tuple[str, ...]
    closure_manifest_sha256: str
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Refuse forged approval, unsorted paths or invalid provenance hashes."""
        paths = tuple(name for name, _digest in self.local_source_blobs)
        if (
            type(self.reviewed_candidate_sha) is not str
            or _SHA.fullmatch(self.reviewed_candidate_sha) is None
            or type(self.local_source_blobs) is not tuple
            or not 2 <= len(paths) <= _MAX_MODULES
            or paths != tuple(sorted(set(paths)))
            or _ENTRY not in paths or _PACKAGE not in paths
            or any(
                type(path) is not str or type(digest) is not str
                or not path.startswith("deployment/")
                or not path.endswith(".py")
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for path, digest in self.local_source_blobs
            )
            or type(self.stdlib_names) is not tuple
            or self.stdlib_names != tuple(sorted(set(self.stdlib_names)))
            or type(self.unresolved_third_party) is not tuple
            or self.unresolved_third_party
            != tuple(sorted(set(self.unresolved_third_party)))
            or type(self.closure_manifest_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.closure_manifest_sha256)
            is None
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)

    @property
    def local_module_count(self) -> int:
        """Count immutable source files, without treating them as trusted."""
        return len(self.local_source_blobs)

    @property
    def requires_dependency_review(self) -> bool:
        """Surface any imports needing independent wheel/interpreter attestation."""
        return bool(self.unresolved_third_party)


def _module_path(name: str) -> str:
    """Confine package names to one flat deployment Python module."""
    if type(name) is not str or _MODULE.fullmatch(name) is None:
        raise ValueError
    return "deployment/" + name + ".py"


def _static_imports(raw: bytes, module_path: str) -> tuple[set[str], set[str]]:
    """Inspect source by AST only; refuse dynamic loading or wildcard imports.

    Local relative imports are overapproximated so static provenance cannot
    silently exclude an import guarded behind a runtime conditional.
    """
    if (
        type(raw) is not bytes or not 0 < len(raw) <= _LIMIT
        or type(module_path) is not str
    ):
        raise ValueError
    tree = ast.parse(raw, filename=module_path)
    local: set[str] = set()
    external: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Name)
                and func.id in ("eval", "exec", "__import__", "compile")
            ) or (
                isinstance(func, ast.Attribute)
                and func.attr in ("import_module", "load_module", "exec_module")
            ):
                raise ValueError
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                parts = name.split(".")
                if parts[0] == "deployment":
                    if len(parts) == 1:
                        local.add(_PACKAGE)
                    elif len(parts) == 2:
                        local.add(_module_path(parts[1]))
                    else:
                        raise ValueError
                else:
                    external.add(parts[0])
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                raise ValueError
            if node.level == 1:
                if node.module:
                    if "." in node.module:
                        raise ValueError
                    local.add(_module_path(node.module))
                else:
                    for alias in node.names:
                        local.add(_module_path(alias.name))
            elif node.level == 0:
                package = (node.module or "").split(".")
                if package[0] == "deployment":
                    if len(package) == 1:
                        local.add(_PACKAGE)
                        for alias in node.names:
                            local.add(_module_path(alias.name))
                    elif len(package) == 2:
                        local.add(_module_path(package[1]))
                    else:
                        raise ValueError
                elif package[0]:
                    external.add(package[0])
                else:
                    raise ValueError
            else:
                raise ValueError
    return local, external


def inspect_c34p_git_blob_closure(
    *, candidate_sha: str, blob_reader: Callable[[str], bytes],
) -> C34PSourceClosureReceipt:
    """Hash every statically reachable deployment source blob once.

    The blob_reader MUST be supplied by an independently evaluated immutable
    Git-object authority; this helper itself neither asserts branch provenance
    nor accepts a signature. Unexpected source syntax, imports, missing
    modules, injected dynamic loading and cycles are bounded and fail closed.
    """
    try:
        if (
            type(candidate_sha) is not str
            or _SHA.fullmatch(candidate_sha) is None
            or not callable(blob_reader)
        ):
            raise ValueError
        pending = {_ENTRY, _PACKAGE}
        scanned: dict[str, str] = {}
        external: set[str] = set()
        while pending:
            if len(scanned) >= _MAX_MODULES:
                raise ValueError
            path = min(pending)
            pending.remove(path)
            if path in scanned:
                continue
            if path != _PACKAGE and (
                not path.startswith("deployment/")
                or not path.endswith(".py")
                or _MODULE.fullmatch(path[11:-3]) is None
            ):
                raise ValueError
            raw = blob_reader(path)
            local_imports, other_imports = _static_imports(raw, path)
            scanned[path] = hashlib.sha256(raw).hexdigest()
            pending.update(local_imports - set(scanned))
            external.update(other_imports)

        # A source object changing while assembling the evidence must HOLD,
        # even when the first traversal happened to be self-consistent.
        # A protected Git commit remains the independent trust requirement.
        for path, digest in sorted(scanned.items()):
            second = blob_reader(path)
            if (
                type(second) is not bytes
                or not 0 < len(second) <= _LIMIT
                or hashlib.sha256(second).hexdigest() != digest
            ):
                raise ValueError
        sources = tuple(sorted(scanned.items()))
        stdlib = tuple(sorted(external & _STDLIB))
        unresolved = tuple(sorted(external - _STDLIB))
        canonical = (
            "c34p-python-closure-v1\n"
            + candidate_sha + "\n"
            + "".join(f"{path} {digest}\n" for path, digest in sources)
            + "stdlib " + ",".join(stdlib) + "\n"
            + "unresolved " + ",".join(unresolved) + "\n"
        ).encode("ascii")
        return C34PSourceClosureReceipt(
            reviewed_candidate_sha=candidate_sha,
            local_source_blobs=sources,
            stdlib_names=stdlib,
            unresolved_third_party=unresolved,
            closure_manifest_sha256=hashlib.sha256(canonical).hexdigest(),
            root_execution_approved=False,
        )
    except _CONTROL:
        raise
    except Exception:
        raise C34PSourceClosureError(_ERROR) from None


__all__ = (
    "C34PSourceClosureError",
    "C34PSourceClosureReceipt",
    "inspect_c34p_git_blob_closure",
)
