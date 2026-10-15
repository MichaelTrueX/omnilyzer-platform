"""File: deployment/c34i_final_main_seal.py

Purpose: Verify an independently identified final merged-main Git commit
contains exactly the three previously approved C34E protected application
blobs, and derive its canonical full 41-file manifest hash.
Related: deployment/c34f_application_generation_evidence.py,
deployment/application_source_set.py, deployment/application_manifest.py,
deployment/tests/test_c34i_final_main_seal.py,
deployment/c34i_stopped_host_gate.py.

This is candidate evidence only: the supplied commit SHA MUST be separately
verified against the approved protected GitHub main ref/review. No root,
installed source, network, service mutation, authorization or deploy action.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from . import c34f_application_generation_evidence as evidence
from .application_source_set import DevApplicationSourceSet


# Section 1: Closed review invariants and fixed failure boundary.
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_UNMERGED_OR_CURRENT = frozenset({
    evidence.PREDECESSOR, evidence.C34D_MAIN, evidence.C34E_PROPOSAL,
})
_ERROR = "C34I final-main source seal is unavailable"


class C34IFinalMainSealError(Exception):
    """Return a single fixed nonsecret error for unverified candidate source."""


@dataclass(frozen=True, slots=True)
class C34IFinalMainSourceSeal:
    """Immutable source candidate, explicitly not a deployment authority."""

    proposed_final_main_commit: str
    protected_file_count: int
    source_manifest_sha256: str
    changed_paths: tuple[str, ...]
    approval_granted: bool

    def __post_init__(self) -> None:
        """Disallow caller-forged positive authorization flags and malformed SHAs."""
        if (
            type(self.proposed_final_main_commit) is not str
            or _COMMIT.fullmatch(self.proposed_final_main_commit) is None
            or self.proposed_final_main_commit in _UNMERGED_OR_CURRENT
            or type(self.protected_file_count) is not int
            or self.protected_file_count != 41
            or type(self.source_manifest_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.source_manifest_sha256) is None
            or type(self.changed_paths) is not tuple
            or self.changed_paths != evidence.CHANGED
            or self.approval_granted is not False
        ):
            raise ValueError(_ERROR)


def prepare_c34i_final_main_source_seal(
    *, independently_reviewed_main_sha: str,
) -> C34IFinalMainSourceSeal:
    """Compare 41 raw Git blobs to reviewed old/new contents after merging.

    The caller is responsible for obtaining the final SHA from a separate
    trusted GitHub protected-main query. This function ensures exact *bytes*
    and canonical manifest format. It does not check GitHub branch protection,
    perform network I/O or grant permission for root installation.
    """
    try:
        sha = independently_reviewed_main_sha
        if (
            type(sha) is not str or _COMMIT.fullmatch(sha) is None
            or sha in _UNMERGED_OR_CURRENT
        ):
            raise ValueError
        selected = DevApplicationSourceSet()
        paths = tuple(item.repository_path for item in selected.files)
        if (
            type(selected) is not DevApplicationSourceSet
            or len(paths) != 41
            or paths != tuple(sorted(set(paths)))
            or evidence._digest(("\n".join(paths) + "\n").encode("ascii"))
            != evidence.PATHS_SHA256
        ):
            raise ValueError
        old = evidence._manifest(evidence.PREDECESSOR, paths)
        if evidence._digest(old.canonical_bytes()) != evidence.MANIFESTS[0]:
            raise ValueError
        target = evidence._manifest(sha, paths)
        old_map = {entry.path: entry.sha256 for entry in old.entries}
        future_map = {entry.path: entry.sha256 for entry in target.entries}
        if (
            tuple(item.path for item in target.entries) != paths
            or tuple(path for path in paths
                     if old_map[path] != future_map[path]) != evidence.CHANGED
            or tuple(old_map[p] for p in evidence.CHANGED) != evidence.OLD_BLOBS
            or tuple(future_map[p] for p in evidence.CHANGED) != evidence.NEW_BLOBS
        ):
            raise ValueError

        return C34IFinalMainSourceSeal(
            proposed_final_main_commit=sha,
            protected_file_count=41,
            source_manifest_sha256=evidence._digest(target.canonical_bytes()),
            changed_paths=evidence.CHANGED,
            approval_granted=False,
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise C34IFinalMainSealError(_ERROR) from None


__all__ = (
    "C34IFinalMainSealError",
    "C34IFinalMainSourceSeal",
    "prepare_c34i_final_main_source_seal",
)
