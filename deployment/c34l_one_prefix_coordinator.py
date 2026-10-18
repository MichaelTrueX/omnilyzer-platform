"""File: deployment/c34l_one_prefix_coordinator.py

Purpose: Join the C34I full 41-file source/config prefix classifier with
the C34K all-five original backup gate and the C34J exact file identities.
Related: deployment/c34i_merged_migration_authority.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/c34k_five_file_backup_barrier.py,
deployment/tests/test_c34l_one_prefix_coordinator.py.

Read-only and non-authorizing: no source/config publication, root host paths,
process lock, service control, GitHub dispatch or deploy entrypoint. Observed
file hashes must be separately verified from an approved descriptor-scoped
host reader before a future live orchestrator can use this model.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import c34i_merged_migration_authority as merged
from . import c34j_atomic_file_mechanics as atomic
from . import c34k_five_file_backup_barrier as barrier
from . import c34f_application_generation_evidence as evidence
from .broker_service_config import DevBrokerServiceConfiguration
from .executor_service_config import DevExecutorServiceConfiguration


# Section: Frozen migration identities; never caller-provided path mappings.
_ORDER = barrier._ORDER
_BACKUPS = barrier._BACKUPS
_ERROR = "C34L protected one-prefix readiness is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class C34LOnePrefixError(Exception):
    """Fixed error on unqualified, ambiguous or incomplete migration state."""


@dataclass(frozen=True, slots=True)
class C34LOnePrefixPlan:
    """Non-authorizing next-step projection after a full backup and source check."""

    completed_steps: int
    next_operation: str
    final_main_sha: str
    target_basename: str | None
    original_sha256: str | None
    target_sha256: str | None
    all_five_backups_verified: bool
    live_authorization: bool = False

    def __post_init__(self) -> None:
        """Never let forged receipts turn review evidence into live permission."""
        if (
            type(self.completed_steps) is not int
            or not 0 <= self.completed_steps <= 5
            or self.next_operation
            != merged.draft._OPERATIONS[self.completed_steps]
            or type(self.final_main_sha) is not str
            or merged.final._COMMIT.fullmatch(self.final_main_sha) is None
            or self.final_main_sha in merged.final._UNMERGED_OR_CURRENT
            or self.all_five_backups_verified is not True
            or self.live_authorization is not False
        ):
            raise ValueError(_ERROR)
        if self.completed_steps == 5:
            if any(x is not None for x in (
                self.target_basename, self.original_sha256, self.target_sha256,
            )):
                raise ValueError(_ERROR)
        else:
            expected = _ORDER[self.completed_steps]
            if self.target_basename != expected:
                raise ValueError(_ERROR)
            for digest in (self.original_sha256, self.target_sha256):
                if (type(digest) is not str or len(digest) != 64
                        or any(c not in "0123456789abcdef" for c in digest)):
                    raise ValueError(_ERROR)


def _canonical_expected(
    authority: merged.C34IMergedMigrationAuthority,
) -> tuple[tuple[bytes, bytes], ...]:
    """Bind exact five source/config byte hashes to the final sealed authority.

    Three protected modules are read as immutable Git blobs; the two root
    configuration byte sequences derive from the typed C34I config models.
    Caller-provided source bytes are not trusted as an authority substitute.
    """
    old = dict(authority._old_digests)
    new = dict(authority._new_digests)
    originals, targets = authority.target_configuration_pair()
    return (
        *tuple((
            bytes.fromhex(old[name]),
            bytes.fromhex(new[name]),
        ) for name in evidence.CHANGED),
        (
            hashlib.sha256(authority.predecessor_executor.canonical_bytes()).digest(),
            hashlib.sha256(originals.canonical_bytes()).digest(),
        ),
        (
            hashlib.sha256(authority.predecessor_broker.canonical_bytes()).digest(),
            hashlib.sha256(targets.canonical_bytes()).digest(),
        ),
    )


def prepare_c34l_one_prefix(
    *,
    authority: merged.C34IMergedMigrationAuthority,
    observed_application_digests: tuple[tuple[str, str], ...],
    executor: DevExecutorServiceConfiguration,
    broker: DevBrokerServiceConfiguration,
    sources: tuple[barrier.C34KOriginalSource, ...],
    backup_dir_fd: int,
    backup_uid: int,
    backup_gid: int,
) -> C34LOnePrefixPlan:
    """Check all five original backups and full 41-file prefix before planning.

    No returned value can authorize a host write; the result is a bounded,
    audit-safe expected next operation only. One separately reviewed root
    orchestrator must repeat all checks under its held lock and stopped-unit
    barrier immediately before any future C34J publication.
    """
    try:
        if (
            type(authority) is not merged.C34IMergedMigrationAuthority
            or type(observed_application_digests) is not tuple
            or type(executor) is not DevExecutorServiceConfiguration
            or type(broker) is not DevBrokerServiceConfiguration
            or type(sources) is not tuple
            or len(sources) != 5
        ):
            raise ValueError
        expected = _canonical_expected(authority)
        if len(expected) != 5 or len(_ORDER) != 5:
            raise ValueError

        for index, (source, name, expected_hashes) in enumerate(
            zip(sources, _ORDER, expected, strict=True)
        ):
            if type(source) is not barrier.C34KOriginalSource:
                raise ValueError
            identity = source.identity
            original_hash, target_hash = expected_hashes
            if (
                identity.name != name
                or identity.original_sha256 != original_hash.hex()
                or identity.target_sha256 != target_hash.hex()
                or hashlib.sha256(source.original).digest() != original_hash
                or atomic._TARGET_TO_BACKUP[name] != _BACKUPS[index]
            ):
                raise ValueError

        # A complete cohort must exist and survive re-read, including during
        # recovery from a previously published source/config prefix.
        receipt = barrier.require_complete_original_backups(
            sources=sources,
            backup_dir_fd=backup_dir_fd,
            backup_uid=backup_uid,
            backup_gid=backup_gid,
        )
        if (
            type(receipt) is not barrier.C34KBackupReceipt
            or receipt.all_five_sealed is not True
            or receipt.original_sha256
            != tuple(item.identity.original_sha256 for item in sources)
        ):
            raise ValueError

        # Never infer a phase from the 3 changed files alone. Complete 41-file
        # observations plus both canonical configs determine the only phase.
        state = authority.classify(
            observed_application_digests=observed_application_digests,
            executor=executor,
            broker=broker,
        )
        if type(state) is not merged.C34IMergedMigrationState:
            raise ValueError
        phase = state.completed_steps
        if phase == 5:
            return C34LOnePrefixPlan(
                phase, state.next_operation, state.target_main_commit,
                None, None, None, True,
            )
        return C34LOnePrefixPlan(
            phase, state.next_operation, state.target_main_commit,
            _ORDER[phase], expected[phase][0].hex(),
            expected[phase][1].hex(), True,
        )
    except _CONTROL:
        raise
    except Exception:
        raise C34LOnePrefixError(_ERROR) from None


__all__ = (
    "C34LOnePrefixError", "C34LOnePrefixPlan",
    "prepare_c34l_one_prefix",
)
