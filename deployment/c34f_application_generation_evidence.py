"""File: deployment/c34f_application_generation_evidence.py

Purpose: Verify the immutable 41-file predecessor/C34D/C34E source manifests
before designing a protected application-generation transition.
Related: application_source_set.py, application_manifest.py,
dev_post_c31_application_update.py, tests/test_c34f_application_generation_evidence.py.

Review only: no host reads, root operations, source installation or deployment.
The proposed C34E commit is unmerged and is not release authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import dev_post_c31_application_update as git_source
from .application_source_set import DevApplicationSourceSet
from .application_manifest import ApplicationManifestEntry, DevApplicationManifest


# Section: Code-owned Git identities, 41-path source set and immutable hashes.
PREDECESSOR = "176ed3a31ffcf23346639ef22ac9bcab3794f0df"
C34D_MAIN = "57919c3b9aca0cb98e85bbb26460f6267d093fa9"
C34E_PROPOSAL = "9289bbc59533e94917ab423a7d29018d011a14a8"
PATHS_SHA256 = "c846e3d863f8c651ffc2de4d3671c9b8c0631c72366a360637d9cc45f98b60ab"
MANIFESTS = (
    "384f5b4e4ca9849da62ab17b624137a52b9292fd3e03d03fefcbabed3bc0ee4b",
    "d3f9f0d27e0a57b8a61f4beb33a9dc925cbc806a80f2ffa38b8ace013391d49b",
    "39d8431d48984754c847159f83ef218b550f78695e9fb87a2cc02058d7ffb706",
)
CHANGED = (
    "deployment/broker.py",
    "deployment/broker_https_ingress.py",
    "deployment/broker_integration.py",
)
OLD_BLOBS = (
    "b7728fb25e0c314ad724cd63ac7edc5ec1d24e05a4737cb7af2c8310bc58c34d",
    "484b3378f27064a48393a76379249174e30780d4df39c9f4bf5554788f4dc925",
    "8abdda62c81282c07f403bd924f4d41b35ff8d113d2bee6a66e2ff32e8339b13",
)
NEW_BLOBS = (
    "4486fc877a2788bca9aeaa56b98790c6cf216c3b80312dd5e9595832d487fc96",
    "f0bd4c9e3e5b890232b780bd8aa01fb47a0b240454fc988106c30ef5f94b39e7",
    "05441f3edb490cf4ff17ecfdfdd7e547bd96efb64228e606235cfc6c794d6ac6",
)
_ERROR = "C34F application-generation evidence is unavailable"


class C34FGenerationEvidenceError(Exception):
    """Expose a single fixed failure without sensitive Git-object details."""


@dataclass(frozen=True, slots=True)
class C34FGenerationEvidence:
    """Immutable review receipt; never a root installation capability."""

    predecessor: str
    workflow_main: str
    proposal: str
    path_count: int
    changed_paths: tuple[str, ...]
    manifest_sha256: tuple[str, str, str]

    def __post_init__(self) -> None:
        """Reject forged, stale, or caller-selected review receipts."""
        if (
            self.predecessor != PREDECESSOR
            or self.workflow_main != C34D_MAIN
            or self.proposal != C34E_PROPOSAL
            or type(self.path_count) is not int
            or self.path_count != 41
            or type(self.changed_paths) is not tuple
            or self.changed_paths != CHANGED
            or type(self.manifest_sha256) is not tuple
            or self.manifest_sha256 != MANIFESTS
        ):
            raise ValueError(_ERROR)


def _digest(data: bytes) -> str:
    """Hash only closed Git object bytes, never live host content."""
    if type(data) is not bytes:
        raise ValueError
    return hashlib.sha256(data).hexdigest()


def _manifest(commit: str, paths: tuple[str, ...]) -> DevApplicationManifest:
    """Reuse the existing fail-closed Git reader and canonical manifest model."""
    blobs = git_source._git_blobs(commit, paths)
    if tuple(path for path, _ in blobs) != paths:
        raise ValueError
    entries = tuple(
        ApplicationManifestEntry(path, _digest(raw), "0644")
        for path, raw in blobs
    )
    return DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", commit, entries,
    )


def review_c34f_generation() -> C34FGenerationEvidence:
    """Compare all 41 exact predecessor/C34D/C34E Git blobs, read-only."""
    try:
        selection = DevApplicationSourceSet()
        paths = tuple(entry.repository_path for entry in selection.files)
        if (
            type(selection) is not DevApplicationSourceSet
            or len(paths) != 41
            or paths != tuple(sorted(set(paths)))
            or _digest(("\n".join(paths) + "\n").encode("ascii")) != PATHS_SHA256
        ):
            raise ValueError

        old, workflow, proposal = (
            _manifest(commit, paths)
            for commit in (PREDECESSOR, C34D_MAIN, C34E_PROPOSAL)
        )
        if tuple(_digest(x.canonical_bytes()) for x in (old, workflow, proposal)) != MANIFESTS:
            raise ValueError
        if old.entries != workflow.entries:
            raise ValueError
        before = {entry.path: entry.sha256 for entry in old.entries}
        after = {entry.path: entry.sha256 for entry in proposal.entries}
        if (
            tuple(path for path in paths if before[path] != after[path]) != CHANGED
            or tuple(before[path] for path in CHANGED) != OLD_BLOBS
            or tuple(after[path] for path in CHANGED) != NEW_BLOBS
        ):
            raise ValueError
        return C34FGenerationEvidence(
            PREDECESSOR, C34D_MAIN, C34E_PROPOSAL, len(paths), CHANGED, MANIFESTS,
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise C34FGenerationEvidenceError(_ERROR) from None


__all__ = ("C34FGenerationEvidenceError", "C34FGenerationEvidence", "review_c34f_generation")
