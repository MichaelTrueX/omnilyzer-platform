"""File: deployment/c34m_descriptor_source_observation.py

Purpose: Read-only, descriptor-scoped collection of the complete protected
41-file application digest set and one tightly bounded interrupted-stage
artifact for Task 014 C34L/C34M migration acceptance.
Related: deployment/application_source_set.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/c34l_one_prefix_coordinator.py,
deployment/c34i_merged_migration_authority.py,
deployment/tests/test_c34m_descriptor_source_observation.py.

This module receives independently qualified directory descriptors. It has
NO host path, root action, installer, service controller, credentials, network
calls, or final-main approval. A future privileged adapter must establish
root-only directory lineage, process lock, stopped services and persistence
integrity separately before using these read-only observations.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat

from .application_source_set import DevApplicationSourceSet
from . import c34f_application_generation_evidence as source_evidence
from . import c34j_atomic_file_mechanics as atomic


# Section 1 — Frozen path and staged-target contracts.
_ERROR = "C34M installed source observation unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_DFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_STAGE_ROOTS = (
    ("deployment/.omnilyzer-c34j-broker.py.stage", "broker.py"),
    ("deployment/.omnilyzer-c34j-broker_https_ingress.py.stage",
     "broker_https_ingress.py"),
    ("deployment/.omnilyzer-c34j-broker_integration.py.stage",
     "broker_integration.py"),
    ("dev/.omnilyzer-c34j-executor.json.stage", "executor.json"),
    ("broker/.omnilyzer-c34j-dev.json.stage", "dev.json"),
)
_STAGE_LABELS = tuple(pair[0] for pair in _STAGE_ROOTS)
_APP_STAGE_LABELS = frozenset(_STAGE_LABELS[:3])


class C34MObservationError(Exception):
    """Fixed error; never expose private configuration data or host paths."""


@dataclass(frozen=True, slots=True)
class C34MSourceObservation:
    """Non-authorizing 41-file snapshot and closed staging filename set."""

    source_digests: tuple[tuple[str, str], ...]
    pending_stages: tuple[str, ...]

    def __post_init__(self) -> None:
        """Refuse malformed snapshot shape or unexpected staging labels."""
        if (
            type(self.source_digests) is not tuple
            or len(self.source_digests) != 41
            or any(
                type(x) is not tuple or len(x) != 2
                or type(x[0]) is not str or type(x[1]) is not str
                or len(x[1]) != 64 or any(c not in "0123456789abcdef" for c in x[1])
                for x in self.source_digests
            )
            or tuple(item[0] for item in self.source_digests)
            != tuple(entry.repository_path for entry in DevApplicationSourceSet().files)
            or type(self.pending_stages) is not tuple
            or len(self.pending_stages) > 1
            or any(x not in _STAGE_LABELS for x in self.pending_stages)
        ):
            raise ValueError(_ERROR)


def _files_and_dirs() -> tuple[tuple[str, ...], frozenset[str]]:
    """Require the exact reviewed source allowlist and directory topology."""
    names = tuple(entry.repository_path for entry in DevApplicationSourceSet().files)
    if (
        len(names) != 41
        or names != tuple(sorted(set(names)))
        or hashlib.sha256(("\n".join(names) + "\n").encode("ascii")).hexdigest()
        != source_evidence.PATHS_SHA256
    ):
        raise ValueError
    dirs = frozenset(
        "/".join(path.split("/")[:i])
        for path in names
        for i in range(1, len(path.split("/")))
    )
    return names, dirs


def _scan_app(app_fd: int, owner_uid: int, owner_gid: int,
              names: tuple[str, ...], dirs: frozenset[str],
              ) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
    """Walk no-follow descriptors and reject unknown paths or missing files."""
    atomic._directory(app_fd, uid=owner_uid, gid=owner_gid, mode=0o755)
    found: dict[str, str] = {}
    stages: list[str] = []
    total_bytes = [0]

    def walk(fd: int, prefix: str) -> None:
        """Revalidate every expected child and forbid symlink/directory drift."""
        opened_dir = atomic._directory(
            fd, uid=owner_uid, gid=owner_gid, mode=0o755,
        )
        for basename in os.listdir(fd):
            relative = basename if not prefix else prefix + "/" + basename
            before = os.stat(basename, dir_fd=fd, follow_symlinks=False)
            if relative in dirs:
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or before.st_uid != owner_uid
                    or before.st_gid != owner_gid
                    or stat.S_IMODE(before.st_mode) != 0o755
                ):
                    raise ValueError
                child = os.open(basename, _DFLAGS, dir_fd=fd)
                try:
                    if atomic._fingerprint(os.fstat(child)) != atomic._fingerprint(before):
                        raise ValueError
                    walk(child, relative)
                    if atomic._fingerprint(os.fstat(child)) != atomic._fingerprint(before):
                        raise ValueError
                finally:
                    os.close(child)
            elif relative in names:
                raw, after = atomic._read_file(
                    fd, basename, uid=owner_uid, gid=owner_gid,
                    modes=(0o644,),
                )
                if atomic._fingerprint(before) != atomic._fingerprint(after):
                    raise ValueError
                total_bytes[0] += len(raw)
                if total_bytes[0] > 8 * atomic._MAX:
                    raise ValueError
                found[relative] = hashlib.sha256(raw).hexdigest()
            elif relative in _APP_STAGE_LABELS:
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise ValueError
                stages.append(relative)
            else:
                raise ValueError
        if atomic._fingerprint(os.fstat(fd)) != atomic._fingerprint(opened_dir):
            raise ValueError

    walk(app_fd, "")
    if set(found) != set(names):
        raise ValueError
    return tuple((name, found[name]) for name in names), tuple(stages)


def _config_stages(fd: int, *, basename: str, uid: int, gid: int,
                   ) -> tuple[str, ...]:
    """Detect only an exact C34J stage beside one canonical config file."""
    atomic._directory(fd, uid=uid, gid=gid, mode=0o750)
    found = []
    stage_name = ".omnilyzer-c34j-" + basename + ".stage"
    role = "dev" if basename == "executor.json" else "broker"
    for entry in os.listdir(fd):
        if entry.startswith(".omnilyzer-"):
            if entry != stage_name:
                raise ValueError
            # Do not follow the stage yet; validate bytes only after the
            # complete source/config prefix has been classified.
            st = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError
            found.append(role + "/" + entry)
    return tuple(found)


def observe_c34m_closed_generation(
    *, application_fd: int, executor_configuration_fd: int,
    broker_configuration_fd: int, application_uid: int,
    application_gid: int, configuration_uid: int,
    executor_gid: int, broker_gid: int,
) -> C34MSourceObservation:
    """Collect all 41 real file hashes and at most one closed stage label.

    Caller must independently authenticate the directory descriptors and
    observe typed canonical configurations under a stable stopped-host lock.
    This reader is not a source manifest authority or a live approval.
    """
    try:
        names, dirs = _files_and_dirs()
        digests, app_stages = _scan_app(
            application_fd, application_uid, application_gid, names, dirs,
        )
        ex_stages = _config_stages(
            executor_configuration_fd, basename="executor.json",
            uid=configuration_uid, gid=executor_gid,
        )
        broker_stages = _config_stages(
            broker_configuration_fd, basename="dev.json",
            uid=configuration_uid, gid=broker_gid,
        )
        stages = tuple((*app_stages, *ex_stages, *broker_stages))
        if len(stages) > 1:
            raise ValueError
        return C34MSourceObservation(digests, stages)
    except _CONTROL:
        raise
    except Exception:
        raise C34MObservationError(_ERROR) from None


def attest_c34m_next_stage(
    *, observation: C34MSourceObservation, completed_steps: int,
    approved_target_bytes: bytes | None, application_module_fd: int,
    executor_configuration_fd: int, broker_configuration_fd: int,
    owner_uid: int, application_gid: int,
    executor_gid: int, broker_gid: int,
) -> bool:
    """Prove a pending stage is precisely the current phase's byte prefix.

    Missing stage is an acceptable *clean* prefix. Existing stages must
    match the expected next operation, exact mode/GID policy and approved
    target byte prefix. The target bytes must be obtained from independently
    sealed Git/config authority, not the untrusted observed file contents.
    """
    try:
        if (
            type(observation) is not C34MSourceObservation
            or type(completed_steps) is not int
            or not 0 <= completed_steps <= 5
        ):
            raise ValueError
        if not observation.pending_stages:
            return True
        if (
            completed_steps == 5
            or type(approved_target_bytes) is not bytes
            or not 0 < len(approved_target_bytes) <= atomic._MAX
        ):
            raise ValueError
        role_path, basename = _STAGE_ROOTS[completed_steps]
        if observation.pending_stages != (role_path,):
            raise ValueError
        if completed_steps < 3:
            fd, gid, mode, parent_mode = (
                application_module_fd, application_gid, 0o644, 0o755,
            )
        elif completed_steps == 3:
            fd, gid, mode, parent_mode = (
                executor_configuration_fd, executor_gid, 0o640, 0o750,
            )
        else:
            fd, gid, mode, parent_mode = (
                broker_configuration_fd, broker_gid, 0o640, 0o750,
            )
        atomic._directory(fd, uid=owner_uid, gid=gid, mode=parent_mode)
        stage = ".omnilyzer-c34j-" + basename + ".stage"
        metadata = os.stat(stage, dir_fd=fd, follow_symlinks=False)
        stage_mode = stat.S_IMODE(metadata.st_mode)
        permitted_gids = (gid, 0) if completed_steps >= 3 and stage_mode == 0o600 else (gid,)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != owner_uid
            or metadata.st_gid not in permitted_gids
            or stage_mode not in (0o600, mode)
            or (stage_mode == mode and metadata.st_size != len(approved_target_bytes))
        ):
            raise ValueError
        raw, checked = atomic._read_file(
            fd, stage, uid=owner_uid, gid=metadata.st_gid,
            modes=(stage_mode,),
        )
        if (
            atomic._fingerprint(metadata) != atomic._fingerprint(checked)
            or len(raw) > len(approved_target_bytes)
            or raw != approved_target_bytes[:len(raw)]
        ):
            raise ValueError
        return True
    except _CONTROL:
        raise
    except Exception:
        raise C34MObservationError(_ERROR) from None


__all__ = (
    "C34MObservationError", "C34MSourceObservation",
    "observe_c34m_closed_generation", "attest_c34m_next_stage",
)
