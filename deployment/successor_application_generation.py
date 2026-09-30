"""Pinned C32ZH Git-object evidence for the successor rootless DEV application.

C32ZG changed only deployment/docker_runtime.py in the selected 41-file
application. This module proves the exact merged source generation that contains
that adapter. Import and construction are inert; explicit review reads only
closed Git objects and never mutates host state.

Related: final_application_generation.py, application_source_set.py,
rootless_docker_authority.py.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os

from . import application_manifest as c26
from . import dev_host_provisioning_mechanics as c31b
from . import dev_post_c31_application_update as c32d
from . import final_application_generation as c32w
from .application_source_set import DevApplicationSourceSet
from .execution import INGRESS_PATHS

PREDECESSOR_REVIEWED_COMMIT = "e4f0030c7a028beb834618254781c2fbff5d6b0d"
TARGET_REVIEWED_COMMIT = "47a602d3f2b97fafd6fb8a18240fd5bbb3857ba9"
TARGET_FIRST_PARENT = "218adfcd64e48dba6defc7e4e2327c50f8e30504"
TARGET_SECOND_PARENT = "a696e10bfb8c2db6c86cf3084dc5bc1c27a8fbbe"
TARGET_PATH_COUNT = 41
TARGET_MANIFEST_SHA256 = "f0fa38089665e48c84f2a0969875d0fd2d069c96e2d079d7e271aea84c7988db"
TARGET_PATHS_SHA256 = "c846e3d863f8c651ffc2de4d3671c9b8c0631c72366a360637d9cc45f98b60ab"
TARGET_RUNTIME_SHA256 = "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f"
TARGET_INGRESS_SHA256 = (
    "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
)
TARGET_PLAN = ("deployment/docker_runtime.py",)
TARGET_PLAN_SHA256 = "ac3447e64f3bfcdeecc8aa0478379fd31f0e574e4eb4f3318e6b1d6d6cb6cb96"
PREDECESSOR_DOCKER_SHA256 = "bed69d1608a497d980d1658b6b6db4b5768a216f99b7c56d21871a6eec304e68"
TARGET_DOCKER_SHA256 = "9bb162e1712a8ec76874c229ce1af1c8a88f527686d4a43376ca93a8b0d00b88"
_RUNTIME_PATH = "deployment/runtime/dev/canary-runtime.json"
_ERROR = "successor DEV application generation evidence is unavailable"
_REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SuccessorApplicationGenerationError(Exception):
    """One fixed external failure for exact successor Git-object evidence."""


@dataclass(frozen=True, slots=True)
class SuccessorApplicationGenerationEvidence:
    """Immutable evidence for the exact C32ZG successor generation."""

    predecessor_reviewed_commit: str
    reviewed_commit: str
    path_count: int
    manifest_sha256: str
    changed_paths: tuple[str, ...]
    plan_sha256: str
    runtime_configuration_sha256: str
    ingress_file_sha256: tuple[str, str, str]
    predecessor_docker_sha256: str
    target_docker_sha256: str

    def __post_init__(self) -> None:
        """Reject any evidence object that differs from the reviewed generation."""

        if (
            type(self.predecessor_reviewed_commit) is not str
            or self.predecessor_reviewed_commit != PREDECESSOR_REVIEWED_COMMIT
            or type(self.reviewed_commit) is not str
            or self.reviewed_commit != TARGET_REVIEWED_COMMIT
            or type(self.path_count) is not int
            or self.path_count != TARGET_PATH_COUNT
            or type(self.manifest_sha256) is not str
            or self.manifest_sha256 != TARGET_MANIFEST_SHA256
            or type(self.changed_paths) is not tuple
            or self.changed_paths != TARGET_PLAN
            or any(type(value) is not str for value in self.changed_paths)
            or type(self.plan_sha256) is not str
            or self.plan_sha256 != TARGET_PLAN_SHA256
            or type(self.runtime_configuration_sha256) is not str
            or self.runtime_configuration_sha256 != TARGET_RUNTIME_SHA256
            or type(self.ingress_file_sha256) is not tuple
            or len(self.ingress_file_sha256) != 3
            or any(type(value) is not str for value in self.ingress_file_sha256)
            or self.ingress_file_sha256 != TARGET_INGRESS_SHA256
            or type(self.predecessor_docker_sha256) is not str
            or self.predecessor_docker_sha256 != PREDECESSOR_DOCKER_SHA256
            or type(self.target_docker_sha256) is not str
            or self.target_docker_sha256 != TARGET_DOCKER_SHA256
        ):
            raise ValueError(_ERROR)


def _commit_parents() -> None:
    """Require the exact merged C32ZG commit and reviewed parents."""

    owned: list[int] = []
    try:
        repository, chain = c31b._open_directory(_REPOSITORY, owned)
        if c31b._run_git(repository, ("cat-file", "-t", TARGET_REVIEWED_COMMIT), 16) != b"commit\n":
            raise OSError
        raw = c31b._run_git(repository, ("cat-file", "commit", TARGET_REVIEWED_COMMIT), 65536)
        header, separator, _body = raw.partition(b"\n\n")
        parents = tuple(
            line[7:].decode("ascii")
            for line in header.split(b"\n")
            if line.startswith(b"parent ")
        )
        if not separator or parents != (TARGET_FIRST_PARENT, TARGET_SECOND_PARENT):
            raise OSError
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def _manifest(commit: str, blobs: tuple[tuple[str, bytes], ...]) -> c26.DevApplicationManifest:
    """Build one canonical manifest from exact already-read Git blobs."""

    entries = tuple(
        c26.ApplicationManifestEntry(path, hashlib.sha256(raw).hexdigest(), "0644")
        for path, raw in blobs
    )
    return c26.DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", commit, entries,
    )


def _reviewed_target() -> tuple[c26.DevApplicationManifest, tuple[tuple[str, bytes], ...]]:
    """Return exact successor blobs after proving the frozen C32W predecessor."""

    try:
        _commit_parents()
        predecessor, predecessor_blobs = c32w._reviewed_target()
        if (
            predecessor.reviewed_commit != PREDECESSOR_REVIEWED_COMMIT
            or hashlib.sha256(predecessor.canonical_bytes()).hexdigest()
            != c32w.TARGET_MANIFEST_SHA256
        ):
            raise OSError
        selection = DevApplicationSourceSet()
        paths = tuple(item.repository_path for item in selection.files)
        if (
            type(selection) is not DevApplicationSourceSet
            or len(paths) != TARGET_PATH_COUNT
            or paths != c26._current_paths()
            or paths != tuple(path for path, _raw in predecessor_blobs)
            or hashlib.sha256(("\n".join(paths) + "\n").encode()).hexdigest()
            != TARGET_PATHS_SHA256
        ):
            raise OSError
        blobs = c32d._git_blobs(TARGET_REVIEWED_COMMIT, paths)
        target = _manifest(TARGET_REVIEWED_COMMIT, blobs)
        if hashlib.sha256(target.canonical_bytes()).hexdigest() != TARGET_MANIFEST_SHA256:
            raise OSError
        predecessor_bytes = dict(predecessor_blobs)
        target_bytes = dict(blobs)
        changed = tuple(path for path in paths if predecessor_bytes[path] != target_bytes[path])
        if (
            changed != TARGET_PLAN
            or hashlib.sha256(("\n".join(changed) + "\n").encode()).hexdigest()
            != TARGET_PLAN_SHA256
            or hashlib.sha256(predecessor_bytes[TARGET_PLAN[0]]).hexdigest()
            != PREDECESSOR_DOCKER_SHA256
            or hashlib.sha256(target_bytes[TARGET_PLAN[0]]).hexdigest()
            != TARGET_DOCKER_SHA256
        ):
            raise OSError
        runtime = c32d._git_blobs(
            TARGET_REVIEWED_COMMIT, (_RUNTIME_PATH, *INGRESS_PATHS),
        )
        if (
            tuple(path for path, _raw in runtime) != (_RUNTIME_PATH, *INGRESS_PATHS)
            or hashlib.sha256(runtime[0][1]).hexdigest() != TARGET_RUNTIME_SHA256
            or tuple(hashlib.sha256(raw).hexdigest() for _path, raw in runtime[1:])
            != TARGET_INGRESS_SHA256
            or any(target_bytes[path] != raw for path, raw in runtime if path in target_bytes)
        ):
            raise OSError
        return target, blobs
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise SuccessorApplicationGenerationError(_ERROR) from None


def review_successor_application_generation() -> SuccessorApplicationGenerationEvidence:
    """Review the exact C32ZG successor generation without host mutation."""

    target, blobs = _reviewed_target()
    target_bytes = dict(blobs)
    return SuccessorApplicationGenerationEvidence(
        PREDECESSOR_REVIEWED_COMMIT,
        target.reviewed_commit,
        len(target.entries),
        hashlib.sha256(target.canonical_bytes()).hexdigest(),
        TARGET_PLAN,
        TARGET_PLAN_SHA256,
        TARGET_RUNTIME_SHA256,
        TARGET_INGRESS_SHA256,
        PREDECESSOR_DOCKER_SHA256,
        hashlib.sha256(target_bytes[TARGET_PLAN[0]]).hexdigest(),
    )
