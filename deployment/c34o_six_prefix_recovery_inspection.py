"""File: deployment/c34o_six_prefix_recovery_inspection.py

Purpose: Compose the existing descriptor lineage, 41-source observation,
canonical config readers, five sealed original backups and six-prefix
final-main classifier into a *read-only* recovery-state inspection.
Related: deployment/c34n_root_predecessor_adapter.py,
deployment/c34m_descriptor_source_observation.py,
deployment/c34l_one_prefix_coordinator.py,
deployment/c34k_five_file_backup_barrier.py,
deployment/c34i_merged_migration_authority.py,
deployment/tests/test_c34o_six_prefix_recovery_inspection.py.

This module has no root entrypoint, fixed live-host root opener, installer,
writer, service controller, lock manager, auth token or deployment action.
The caller provides an independently qualified directory-anchor descriptor
and sealed byte payloads. The result NEVER authorizes host mutation; actual
root use additionally requires reviewed immutable transitive import sealing,
stopped units, exclusive lock and separately approved final-main identity.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os

from . import c34g_installed_predecessor_preflight as canonical
from . import c34i_merged_migration_authority as merged
from . import c34j_atomic_file_mechanics as files
from . import c34k_five_file_backup_barrier as backups
from . import c34l_one_prefix_coordinator as coordinator
from . import c34m_descriptor_source_observation as observe
from . import c34n_root_predecessor_adapter as chains
from .broker_service_config import DevBrokerServiceConfiguration
from .executor_service_config import DevExecutorServiceConfiguration


# Section 1: Exact closed-order payloads and bounded, nonsecret errors.
_ERROR = "C34O six-prefix recovery inspection is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class C34ORecoveryInspectionError(Exception):
    """A fixed HOLD message; never include file/config/secret contents."""


@dataclass(frozen=True, slots=True)
class C34OSealedFivePayloads:
    """Exactly five trusted predecessor/target byte pairs in C34K order."""

    originals: tuple[bytes, ...]
    targets: tuple[bytes, ...]

    def __post_init__(self) -> None:
        """Validate shape, count and bounded sizes before descriptor use."""
        if (
            type(self.originals) is not tuple
            or type(self.targets) is not tuple
            or len(self.originals) != 5
            or len(self.targets) != 5
            or any(type(raw) is not bytes or not 0 < len(raw) <= files._MAX
                   for raw in (*self.originals, *self.targets))
        ):
            raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class C34ORecoveryObservation:
    """Read-only result after two stable closed-source/config inspections."""

    completed_steps: int
    next_operation: str
    final_main_sha: str
    protected_file_count: int
    complete_backups: bool
    pending_stage: bool
    recovery_authorized: bool = False

    def __post_init__(self) -> None:
        """Disallow a forged positive permission or malformed prefix."""
        if (
            type(self.completed_steps) is not int
            or not 0 <= self.completed_steps <= 5
            or self.next_operation
            != merged.draft._OPERATIONS[self.completed_steps]
            or type(self.final_main_sha) is not str
            or merged.final._COMMIT.fullmatch(self.final_main_sha) is None
            or self.final_main_sha in merged.final._UNMERGED_OR_CURRENT
            or self.protected_file_count != 41
            or self.complete_backups is not True
            or type(self.pending_stage) is not bool
            or (self.completed_steps == 5 and self.pending_stage)
            or self.recovery_authorized is not False
        ):
            raise ValueError(_ERROR)


def _read_config(parent: int, filename: str, uid: int, gid: int, model: type):
    """Read exact canonical, single-link mode-0640 root-style config bytes."""
    value, _stat = files._read_file(
        parent, filename, uid=uid, gid=gid, modes=(0o640,),
    )
    parsed = canonical.canonical_object(value)
    result = model.from_dict(parsed)
    if result.canonical_bytes() != value:
        raise ValueError
    return result


def _source_bindings(
    *, authority: merged.C34IMergedMigrationAuthority,
    payloads: C34OSealedFivePayloads,
    module_fd: int, executor_fd: int, broker_fd: int,
    uid: int, app_gid: int, executor_gid: int, broker_gid: int,
) -> tuple[backups.C34KOriginalSource, ...]:
    """Bind supplied payload bytes to the *independent* C34I digest authority.

    This step does not trust the bytes merely because the caller labels them
    'sealed'. All five complete original and target hashes must match the
    Git/config provenance in C34I before they may be used for stage checks.
    """
    expected = coordinator._canonical_expected(authority)
    if len(expected) != 5:
        raise ValueError
    result = []
    for index, (name, before, after, hashes) in enumerate(zip(
        backups._ORDER, payloads.originals, payloads.targets,
        expected, strict=True,
    )):
        old_hash, new_hash = hashes
        if (
            hashlib.sha256(before).digest() != old_hash
            or hashlib.sha256(after).digest() != new_hash
        ):
            raise ValueError
        if index < 3:
            fd, gid = module_fd, app_gid
        elif index == 3:
            fd, gid = executor_fd, executor_gid
        else:
            fd, gid = broker_fd, broker_gid
        model = files.C34JFileIdentity(
            name=name, uid=uid, gid=gid,
            mode=0o644 if index < 3 else 0o640,
            original_sha256=old_hash.hex(),
            target_sha256=new_hash.hex(),
        )
        result.append(backups.C34KOriginalSource(
            identity=model, source_dir_fd=fd, original=before,
        ))
    return tuple(result)


def _inspect_once(
    *, anchor_fd: int, authority: merged.C34IMergedMigrationAuthority,
    payloads: C34OSealedFivePayloads, backup_dir_fd: int,
    owner_uid: int, app_gid: int, executor_gid: int, broker_gid: int,
    backup_uid: int, backup_gid: int,
) -> tuple[C34ORecoveryObservation, tuple[int, ...] | None]:
    """Perform one bounded, descriptor-authenticated pass without mutations."""
    anchor_meta = os.fstat(anchor_fd)
    chains._require_directory(
        anchor_meta, uid=owner_uid, gid=None, final_mode=None,
    )
    root_marker = chains._snapshot(anchor_meta)
    opened = []
    try:
        for location, gid, mode in (
            (chains._APP, app_gid, 0o755),
            (chains._MODULE, app_gid, 0o755),
            (chains._EXECUTOR, executor_gid, 0o750),
            (chains._BROKER, broker_gid, 0o750),
        ):
            opened.append(chains._open_chain(
                anchor_fd, location, owner_uid=owner_uid,
                final_gid=gid, final_mode=mode,
            ))
        chainset = tuple(opened)
        chains._revalidate_chains(anchor_fd, chainset, root_marker)
        app = chainset[0][-1][0]
        module = chainset[1][-1][0]
        executor_dir = chainset[2][-1][0]
        broker_dir = chainset[3][-1][0]
        original_backup_marker = files._fingerprint(
            files._directory(
                backup_dir_fd, uid=backup_uid, gid=backup_gid, mode=0o700,
            )
        )
        ex = _read_config(
            executor_dir, "executor.json", owner_uid, executor_gid,
            DevExecutorServiceConfiguration,
        )
        br = _read_config(
            broker_dir, "dev.json", owner_uid, broker_gid,
            DevBrokerServiceConfiguration,
        )
        snapshot = observe.observe_c34m_closed_generation(
            application_fd=app, executor_configuration_fd=executor_dir,
            broker_configuration_fd=broker_dir,
            application_uid=owner_uid, application_gid=app_gid,
            configuration_uid=owner_uid,
            executor_gid=executor_gid, broker_gid=broker_gid,
        )
        sources = _source_bindings(
            authority=authority, payloads=payloads,
            module_fd=module, executor_fd=executor_dir, broker_fd=broker_dir,
            uid=owner_uid, app_gid=app_gid,
            executor_gid=executor_gid, broker_gid=broker_gid,
        )
        plan = coordinator.prepare_c34l_one_prefix(
            authority=authority, observed_application_digests=snapshot.source_digests,
            executor=ex, broker=br, sources=sources,
            backup_dir_fd=backup_dir_fd,
            backup_uid=backup_uid, backup_gid=backup_gid,
        )
        phase = plan.completed_steps
        expected_stage = payloads.targets[phase] if phase < 5 else None
        if not observe.attest_c34m_next_stage(
            observation=snapshot, completed_steps=phase,
            approved_target_bytes=expected_stage,
            application_module_fd=module,
            executor_configuration_fd=executor_dir,
            broker_configuration_fd=broker_dir,
            owner_uid=owner_uid, application_gid=app_gid,
            executor_gid=executor_gid, broker_gid=broker_gid,
        ):
            raise ValueError
        stage_marker = None
        if snapshot.pending_stages:
            _label, filename = observe._STAGE_ROOTS[phase]
            if phase < 3:
                fd = module
            elif phase == 3:
                fd = executor_dir
            else:
                fd = broker_dir
            stage_marker = files._fingerprint(os.stat(
                ".omnilyzer-c34j-" + filename + ".stage",
                dir_fd=fd, follow_symlinks=False,
            ))
        if (
            _read_config(
                executor_dir, "executor.json", owner_uid, executor_gid,
                DevExecutorServiceConfiguration,
            ).canonical_bytes() != ex.canonical_bytes()
            or _read_config(
                broker_dir, "dev.json", owner_uid, broker_gid,
                DevBrokerServiceConfiguration,
            ).canonical_bytes() != br.canonical_bytes()
            or files._fingerprint(os.fstat(backup_dir_fd))
            != original_backup_marker
        ):
            raise ValueError
        chains._revalidate_chains(anchor_fd, chainset, root_marker)
        return C34ORecoveryObservation(
            completed_steps=phase, next_operation=plan.next_operation,
            final_main_sha=plan.final_main_sha, protected_file_count=41,
            complete_backups=True, pending_stage=bool(snapshot.pending_stages),
        ), stage_marker
    finally:
        for chain in reversed(opened):
            for fd, _parent, _name, _marker in reversed(chain):
                os.close(fd)


def inspect_c34o_six_prefix_candidate(
    *, anchor_fd: int, authority: merged.C34IMergedMigrationAuthority,
    payloads: C34OSealedFivePayloads, backup_dir_fd: int,
    owner_uid: int, application_gid: int, executor_gid: int, broker_gid: int,
    backup_uid: int, backup_gid: int,
) -> C34ORecoveryObservation:
    """Read twice and accept only one unchanged, fully classified prefix.

    Requires pre-opened trusted descriptors and an independently approved
    final-main source seal. Does NOT assert that those prerequisites were
    supplied by the host root authority: no root path or lock is opened here.
    Neither a PASS nor a partial-stage receipt permits a file write/restart.
    """
    try:
        if (
            type(authority) is not merged.C34IMergedMigrationAuthority
            or type(payloads) is not C34OSealedFivePayloads
        ):
            raise ValueError
        fields = dict(
            anchor_fd=anchor_fd, authority=authority, payloads=payloads,
            backup_dir_fd=backup_dir_fd, owner_uid=owner_uid,
            app_gid=application_gid, executor_gid=executor_gid,
            broker_gid=broker_gid, backup_uid=backup_uid,
            backup_gid=backup_gid,
        )
        initial = _inspect_once(**fields)
        final = _inspect_once(**fields)
        if initial != final:
            raise ValueError
        return initial[0]
    except _CONTROL:
        raise
    except Exception:
        raise C34ORecoveryInspectionError(_ERROR) from None


__all__ = (
    "C34ORecoveryInspectionError",
    "C34OSealedFivePayloads",
    "C34ORecoveryObservation",
    "inspect_c34o_six_prefix_candidate",
)
