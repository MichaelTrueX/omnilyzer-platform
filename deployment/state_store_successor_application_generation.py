"""Pinned C33AD Git-object evidence for the state-store successor DEV application.

C33AC changed only deployment/state_store.py relative to the installed C32ZH
successor application generation. This module proves the exact merged C33AC
source generation while preserving C32W/C32ZH as historical predecessors.
Import and construction are inert; explicit review reads only closed Git objects
and never mutates host state.

Related: successor_application_generation.py, application_source_set.py,
state_store.py.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os

from . import application_manifest as c26
from . import dev_host_provisioning_mechanics as c31b
from . import dev_post_c31_application_update as c32d
from . import successor_application_generation as c32zh
from .application_source_set import DevApplicationSourceSet
from .execution import INGRESS_PATHS


PREDECESSOR_REVIEWED_COMMIT = "47a602d3f2b97fafd6fb8a18240fd5bbb3857ba9"
TARGET_REVIEWED_COMMIT = "f2ece4257b84090b1a6fff5d1aa7f0b6047765cd"
TARGET_FIRST_PARENT = "48f1280302f85cb8db1af9bb25f1ab15382ae8cb"
TARGET_SECOND_PARENT = "9a02a829a78502d8bb224a3f6347ba5806d98a11"
TARGET_PATH_COUNT = 41
TARGET_MANIFEST_SHA256 = "3efb117dbaebfefc264d4373e476973aed1dfc9ebb3035998a7778ea229e91e4"
TARGET_PATHS_SHA256 = "c846e3d863f8c651ffc2de4d3671c9b8c0631c72366a360637d9cc45f98b60ab"
TARGET_RUNTIME_SHA256 = "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f"
TARGET_INGRESS_SHA256 = (
    "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
)
TARGET_PLAN = ("deployment/state_store.py",)
TARGET_PLAN_SHA256 = "392ab2b430e40f07d761d948d91bce6721ee2fb0e341a6b92b2e7a5520358fb2"
PREDECESSOR_STATE_STORE_SHA256 = (
    "c88e2d1da35a04e1cd1dbda3271eba4ee08549ab25b0385117ab5711ef7ea331"
)
TARGET_STATE_STORE_SHA256 = (
    "322de4edebd8c9f08f318c23660a1f92d8108d79b18e629352e79bd5d7fce683"
)
_RUNTIME_PATH = "deployment/runtime/dev/canary-runtime.json"
_ERROR = "state-store successor DEV application generation evidence is unavailable"
_REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class StateStoreSuccessorApplicationGenerationError(Exception):
    """One fixed external failure for exact C33AC Git-object evidence."""


@dataclass(frozen=True, slots=True)
class StateStoreSuccessorApplicationGenerationEvidence:
    """Immutable evidence for the exact merged C33AC application generation."""

    predecessor_reviewed_commit: str
    reviewed_commit: str
    path_count: int
    manifest_sha256: str
    changed_paths: tuple[str, ...]
    plan_sha256: str
    runtime_configuration_sha256: str
    ingress_file_sha256: tuple[str, str, str]
    predecessor_state_store_sha256: str
    target_state_store_sha256: str

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
            or self.ingress_file_sha256 != TARGET_INGRESS_SHA256
            or type(self.predecessor_state_store_sha256) is not str
            or self.predecessor_state_store_sha256
            != PREDECESSOR_STATE_STORE_SHA256
            or type(self.target_state_store_sha256) is not str
            or self.target_state_store_sha256 != TARGET_STATE_STORE_SHA256
        ):
            raise ValueError(_ERROR)


def _commit_parents() -> None:
    """Require the exact merged C33AC commit and reviewed parents."""

    owned: list[int] = []
    try:
        repository, chain = c31b._open_directory(_REPOSITORY, owned)
        if (
            c31b._run_git(
                repository, ("cat-file", "-t", TARGET_REVIEWED_COMMIT), 16
            )
            != b"commit\n"
        ):
            raise OSError
        raw = c31b._run_git(
            repository, ("cat-file", "commit", TARGET_REVIEWED_COMMIT), 65536
        )
        header, separator, _body = raw.partition(b"\n\n")
        parents = tuple(
            line[7:].decode("ascii")
            for line in header.split(b"\n")
            if line.startswith(b"parent ")
        )
        if not separator or parents != (
            TARGET_FIRST_PARENT,
            TARGET_SECOND_PARENT,
        ):
            raise OSError
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def _manifest(
    commit: str,
    blobs: tuple[tuple[str, bytes], ...],
) -> c26.DevApplicationManifest:
    """Build one canonical manifest from exact already-read Git blobs."""

    entries = tuple(
        c26.ApplicationManifestEntry(
            path, hashlib.sha256(raw).hexdigest(), "0644"
        )
        for path, raw in blobs
    )
    return c26.DevApplicationManifest(
        "canonical-relative-file-set-v1", "sha256", commit, entries
    )


def _reviewed_target(
) -> tuple[c26.DevApplicationManifest, tuple[tuple[str, bytes], ...]]:
    """Return exact C33AC blobs after proving the C32ZH predecessor."""

    try:
        _commit_parents()
        predecessor, predecessor_blobs = c32zh._reviewed_target()
        if (
            predecessor.reviewed_commit != PREDECESSOR_REVIEWED_COMMIT
            or hashlib.sha256(predecessor.canonical_bytes()).hexdigest()
            != c32zh.TARGET_MANIFEST_SHA256
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
        if (
            hashlib.sha256(target.canonical_bytes()).hexdigest()
            != TARGET_MANIFEST_SHA256
        ):
            raise OSError

        predecessor_bytes = dict(predecessor_blobs)
        target_bytes = dict(blobs)
        changed = tuple(
            path
            for path in paths
            if predecessor_bytes[path] != target_bytes[path]
        )
        if (
            changed != TARGET_PLAN
            or hashlib.sha256(("\n".join(changed) + "\n").encode()).hexdigest()
            != TARGET_PLAN_SHA256
            or hashlib.sha256(
                predecessor_bytes[TARGET_PLAN[0]]
            ).hexdigest()
            != PREDECESSOR_STATE_STORE_SHA256
            or hashlib.sha256(target_bytes[TARGET_PLAN[0]]).hexdigest()
            != TARGET_STATE_STORE_SHA256
        ):
            raise OSError

        runtime = c32d._git_blobs(
            TARGET_REVIEWED_COMMIT,
            (_RUNTIME_PATH, *INGRESS_PATHS),
        )
        if (
            tuple(path for path, _raw in runtime)
            != (_RUNTIME_PATH, *INGRESS_PATHS)
            or hashlib.sha256(runtime[0][1]).hexdigest()
            != TARGET_RUNTIME_SHA256
            or tuple(
                hashlib.sha256(raw).hexdigest()
                for _path, raw in runtime[1:]
            )
            != TARGET_INGRESS_SHA256
            or any(
                target_bytes[path] != raw
                for path, raw in runtime
                if path in target_bytes
            )
        ):
            raise OSError

        return target, blobs
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise StateStoreSuccessorApplicationGenerationError(_ERROR) from None


def review_state_store_successor_application_generation(
) -> StateStoreSuccessorApplicationGenerationEvidence:
    """Review the exact merged C33AC generation without host mutation."""

    target, blobs = _reviewed_target()
    target_bytes = dict(blobs)
    return StateStoreSuccessorApplicationGenerationEvidence(
        PREDECESSOR_REVIEWED_COMMIT,
        target.reviewed_commit,
        len(target.entries),
        hashlib.sha256(target.canonical_bytes()).hexdigest(),
        TARGET_PLAN,
        TARGET_PLAN_SHA256,
        TARGET_RUNTIME_SHA256,
        TARGET_INGRESS_SHA256,
        PREDECESSOR_STATE_STORE_SHA256,
        hashlib.sha256(target_bytes[TARGET_PLAN[0]]).hexdigest(),
    )
