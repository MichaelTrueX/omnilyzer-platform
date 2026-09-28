"""Pinned C32V Git-object evidence for the future C32W application migration.

Import and construction are inert. Explicit review reads only closed Git objects;
it never consults mutable refs, the working tree, network, or host installation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os

from . import application_manifest as c26
from . import dev_host_provisioning_mechanics as c31b
from . import dev_post_c31_application_update as c32d
from .application_source_set import DevApplicationSourceSet
from .execution import INGRESS_PATHS


__all__ = ("FinalApplicationGenerationEvidence", "review_final_application_generation")

TARGET_REVIEWED_COMMIT = "e4f0030c7a028beb834618254781c2fbff5d6b0d"
TARGET_FIRST_PARENT = "fb9927f7a75a636e73800cbe3b3a62ed1e10e6eb"
TARGET_SECOND_PARENT = "02711ed4fab2984282f5e3a860f272b2ef726a71"
TARGET_PATH_COUNT = 41
TARGET_MANIFEST_SHA256 = "774391d16235855222aa4dedb617112cccc9a862d1599d2546c08b5f8b17c8f9"
TARGET_PATHS_SHA256 = "c846e3d863f8c651ffc2de4d3671c9b8c0631c72366a360637d9cc45f98b60ab"
TARGET_RUNTIME_SHA256 = "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f"
TARGET_INGRESS_SHA256 = (
    "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
)
TARGET_PLAN_SHA256 = "5788ba235c82cf8c00318131c9bac9645fa080613f0061922a5c08afb62eb075"
_RUNTIME_PATH = "deployment/runtime/dev/canary-runtime.json"
_ERROR = "final DEV application generation evidence is unavailable"
_REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FinalApplicationGenerationError(Exception):
    """One fixed external failure for reviewed Git-object evidence."""


@dataclass(frozen=True, slots=True)
class FinalApplicationGenerationEvidence:
    reviewed_commit: str
    path_count: int
    python_count: int
    runtime_data_count: int
    manifest_sha256: str
    runtime_configuration_sha256: str
    ingress_file_sha256: tuple[str, str, str]

    def __post_init__(self) -> None:
        if (type(self.reviewed_commit) is not str or self.reviewed_commit != TARGET_REVIEWED_COMMIT
                or type(self.path_count) is not int or self.path_count != TARGET_PATH_COUNT
                or type(self.python_count) is not int or self.python_count != 38
                or type(self.runtime_data_count) is not int or self.runtime_data_count != 3
                or type(self.manifest_sha256) is not str
                or self.manifest_sha256 != TARGET_MANIFEST_SHA256
                or type(self.runtime_configuration_sha256) is not str
                or self.runtime_configuration_sha256 != TARGET_RUNTIME_SHA256
                or type(self.ingress_file_sha256) is not tuple
                or len(self.ingress_file_sha256) != 3
                or any(type(value) is not str for value in self.ingress_file_sha256)
                or self.ingress_file_sha256 != TARGET_INGRESS_SHA256):
            raise ValueError(_ERROR)


def _commit_parents() -> None:
    owned: list[int] = []
    try:
        repository, chain = c31b._open_directory(_REPOSITORY, owned)
        if c31b._run_git(repository, ("cat-file", "-t", TARGET_REVIEWED_COMMIT), 16) != b"commit\n":
            raise OSError
        raw = c31b._run_git(repository, ("cat-file", "commit", TARGET_REVIEWED_COMMIT), 65536)
        header, separator, _body = raw.partition(b"\n\n")
        parents = tuple(line[7:].decode("ascii") for line in header.split(b"\n")
                        if line.startswith(b"parent "))
        if not separator or parents != (TARGET_FIRST_PARENT, TARGET_SECOND_PARENT):
            raise OSError
        c31b._revalidate_chain(chain)
    finally:
        c31b._finish_close(owned)


def _reviewed_target() -> tuple[c26.DevApplicationManifest, tuple[tuple[str, bytes], ...]]:
    """Return exact pinned target blobs for the private migration; no HEAD lookup."""
    try:
        _commit_parents()
        selection = DevApplicationSourceSet()
        paths = tuple(item.repository_path for item in selection.files)
        if (type(selection) is not DevApplicationSourceSet or len(paths) != TARGET_PATH_COUNT
                or paths != c26._current_paths()
                or sum(item.kind == "python-module" for item in selection.files) != 38
                or sum(item.kind == "runtime-data" for item in selection.files) != 3
                or hashlib.sha256(("\n".join(paths) + "\n").encode()).hexdigest()
                != TARGET_PATHS_SHA256):
            raise OSError
        blobs = c32d._git_blobs(TARGET_REVIEWED_COMMIT, paths)
        manifest = c32d._manifest(TARGET_REVIEWED_COMMIT, blobs)
        if hashlib.sha256(manifest.canonical_bytes()).hexdigest() != TARGET_MANIFEST_SHA256:
            raise OSError
        source = dict(blobs)
        runtime = c32d._git_blobs(TARGET_REVIEWED_COMMIT, (_RUNTIME_PATH, *INGRESS_PATHS))
        if (tuple(path for path, _ in runtime) != (_RUNTIME_PATH, *INGRESS_PATHS)
                or hashlib.sha256(runtime[0][1]).hexdigest() != TARGET_RUNTIME_SHA256
                or tuple(hashlib.sha256(raw).hexdigest() for _path, raw in runtime[1:])
                != TARGET_INGRESS_SHA256
                or any(source[path] != raw for path, raw in runtime
                       if path in source)):
            raise OSError
        return manifest, blobs
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise FinalApplicationGenerationError(_ERROR) from None


def review_final_application_generation() -> FinalApplicationGenerationEvidence:
    """Explicit read-only review of the exact C32V merge's Git objects."""
    manifest, _blobs = _reviewed_target()
    return FinalApplicationGenerationEvidence(
        TARGET_REVIEWED_COMMIT, len(manifest.entries), 38, 3,
        TARGET_MANIFEST_SHA256, TARGET_RUNTIME_SHA256, TARGET_INGRESS_SHA256,
    )
