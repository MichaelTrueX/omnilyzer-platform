"""File: deployment/c34g_migration_authority.py

Purpose: Classify all six permitted prefixes of the proposed Task 014 C34E
five-file migration (three broker modules, executor config, broker config).
Related: c34f_application_generation_evidence.py, application_manifest.py,
executor_service_config.py, broker_service_config.py,
tests/test_c34g_migration_authority.py.

This is a pure, inert authority/state machine. It neither reads installed
files nor performs installation, systemd, database, network or Docker changes.
Its target remains the unmerged C34E proposal and is NOT deployment approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import re

from . import c34f_application_generation_evidence as evidence
from .application_manifest import DevApplicationManifest
from .executor_service_config import DevExecutorServiceConfiguration
from .broker_service_config import DevBrokerServiceConfiguration


# Section: Closed prefix plan. Only the next transition may be performed.
_OPERATIONS = (
    "replace-deployment-broker-py",
    "replace-deployment-broker-https-ingress-py",
    "replace-deployment-broker-integration-py",
    "replace-executor-configuration",
    "replace-broker-configuration",
    "complete",
)
_ERROR = "C34G protected migration prefix authority is invalid"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHARED = (
    "broker_uid", "broker_gid", "executor_uid", "executor_gid",
    "replay_group_gid", "socket_group_gid",
    "runtime_configuration_sha256", "ingress_file_sha256",
)


@dataclass(frozen=True, slots=True)
class C34GMigrationState:
    """One exact migration prefix; never a host-mutation instruction."""

    completed_steps: int
    next_operation: str
    proposal_commit: str

    def __post_init__(self) -> None:
        """Forbid forged phase numbers, operations and target revisions."""
        if (
            type(self.completed_steps) is not int
            or not 0 <= self.completed_steps <= 5
            or self.next_operation != _OPERATIONS[self.completed_steps]
            or self.proposal_commit != evidence.C34E_PROPOSAL
        ):
            raise ValueError(_ERROR)

    def rollback_operation(self) -> str:
        """Name the sole permitted reverse step; never execute it.

        Reverse order matters because returning the broker's configuration to
        its predecessor before restoring the three source files would create
        a mixed source/config authority. This method provides no I/O ability.
        """
        return (
            "complete",
            "restore-deployment-broker-py",
            "restore-deployment-broker-https-ingress-py",
            "restore-deployment-broker-integration-py",
            "restore-executor-configuration",
            "restore-broker-configuration",
        )[self.completed_steps]


@dataclass(frozen=True, slots=True, kw_only=True)
class C34GMigrationAuthority:
    """Bind immutable source manifests and the exact current config pair."""

    predecessor_manifest: DevApplicationManifest
    proposal_manifest: DevApplicationManifest
    predecessor_executor: DevExecutorServiceConfiguration
    predecessor_broker: DevBrokerServiceConfiguration

    _target_executor: DevExecutorServiceConfiguration = field(init=False, repr=False)
    _target_broker: DevBrokerServiceConfiguration = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Prove only the three allowed blob changes and config field projections."""
        try:
            if (
                type(self.predecessor_manifest) is not DevApplicationManifest
                or type(self.proposal_manifest) is not DevApplicationManifest
                or type(self.predecessor_executor) is not DevExecutorServiceConfiguration
                or type(self.predecessor_broker) is not DevBrokerServiceConfiguration
            ):
                raise TypeError
            previous = self.predecessor_manifest
            target = self.proposal_manifest
            old_exec = DevExecutorServiceConfiguration.from_dict(
                self.predecessor_executor.to_dict()
            )
            old_broker = DevBrokerServiceConfiguration.from_dict(
                self.predecessor_broker.to_dict()
            )
            if (
                previous.reviewed_commit != evidence.PREDECESSOR
                or target.reviewed_commit != evidence.C34E_PROPOSAL
                or evidence._digest(previous.canonical_bytes()) != evidence.MANIFESTS[0]
                or evidence._digest(target.canonical_bytes()) != evidence.MANIFESTS[2]
                or old_exec.reviewed_commit != evidence.PREDECESSOR
                or old_broker.reviewed_commit != evidence.PREDECESSOR
                or old_broker.expected_workflow_sha != evidence.C34D_MAIN
                or any(getattr(old_exec, key) != getattr(old_broker, key)
                       for key in _SHARED)
            ):
                raise ValueError

            names = tuple(item.path for item in previous.entries)
            targets = tuple(item.path for item in target.entries)
            if names != targets or len(names) != 41:
                raise ValueError
            before = {x.path: x.sha256 for x in previous.entries}
            after = {x.path: x.sha256 for x in target.entries}
            if (
                tuple(name for name in names if before[name] != after[name])
                != evidence.CHANGED
                or tuple(before[name] for name in evidence.CHANGED)
                != evidence.OLD_BLOBS
                or tuple(after[name] for name in evidence.CHANGED)
                != evidence.NEW_BLOBS
            ):
                raise ValueError

            next_exec = replace(old_exec, reviewed_commit=evidence.C34E_PROPOSAL)
            next_broker = replace(old_broker, reviewed_commit=evidence.C34E_PROPOSAL)
            # A source update is *not* workflow-authority rotation.
            if (
                next_broker.expected_workflow_sha != evidence.C34D_MAIN
                or {key for key in old_exec.to_dict()
                    if old_exec.to_dict()[key] != next_exec.to_dict()[key]}
                != {"reviewed_commit"}
                or {key for key in old_broker.to_dict()
                    if old_broker.to_dict()[key] != next_broker.to_dict()[key]}
                != {"reviewed_commit"}
            ):
                raise ValueError
            object.__setattr__(self, "predecessor_executor", old_exec)
            object.__setattr__(self, "predecessor_broker", old_broker)
            object.__setattr__(self, "_target_executor", next_exec)
            object.__setattr__(self, "_target_broker", next_broker)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def target_configuration_pair(
        self,
    ) -> tuple[DevExecutorServiceConfiguration, DevBrokerServiceConfiguration]:
        """Return canonical post-transition configs, not a writable host reference."""
        return (self._target_executor, self._target_broker)

    def classify(
        self,
        *,
        observed_application_digests: tuple[tuple[str, str], ...],
        executor: DevExecutorServiceConfiguration,
        broker: DevBrokerServiceConfiguration,
    ) -> C34GMigrationState:
        """Accept exactly six prefixes, refusing all mixed or unlisted states.

        The future root runtime must separately prove each observation comes
        from race-checked, no-follow, regular root-owned installed files.
        Merely passing caller-supplied values here never authorizes mutation.
        """
        try:
            if (
                type(observed_application_digests) is not tuple
                or type(executor) is not DevExecutorServiceConfiguration
                or type(broker) is not DevBrokerServiceConfiguration
            ):
                raise TypeError
            old = self.predecessor_manifest.entries
            target = self.proposal_manifest.entries
            if len(observed_application_digests) != len(old):
                raise ValueError
            for i, item in enumerate(observed_application_digests):
                if (
                    type(item) is not tuple or len(item) != 2
                    or type(item[0]) is not str or item[0] != old[i].path
                    or type(item[1]) is not str
                    or _SHA256.fullmatch(item[1]) is None
                ):
                    raise ValueError

            normalized_executor = DevExecutorServiceConfiguration.from_dict(
                executor.to_dict()
            )
            normalized_broker = DevBrokerServiceConfiguration.from_dict(
                broker.to_dict()
            )
            # Exactly one original source file is advanced per prefix.
            for prefix in range(6):
                sources_complete = min(prefix, 3)
                expected = tuple(
                    (entry.path,
                     target[index].sha256
                     if entry.path in evidence.CHANGED[:sources_complete]
                     else entry.sha256)
                    for index, entry in enumerate(old)
                )
                expected_executor = (
                    self._target_executor if prefix >= 4 else self.predecessor_executor
                )
                expected_broker = (
                    self._target_broker if prefix >= 5 else self.predecessor_broker
                )
                if (
                    observed_application_digests == expected
                    and normalized_executor.canonical_bytes()
                    == expected_executor.canonical_bytes()
                    and normalized_broker.canonical_bytes()
                    == expected_broker.canonical_bytes()
                ):
                    return C34GMigrationState(
                        prefix, _OPERATIONS[prefix], evidence.C34E_PROPOSAL,
                    )
            raise ValueError
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None


__all__ = ("C34GMigrationAuthority", "C34GMigrationState")
