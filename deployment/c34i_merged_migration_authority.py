"""File: deployment/c34i_merged_migration_authority.py

Purpose: Bind the five-file, six-prefix C34G migration contract to a
separately verified *final merged main* source seal rather than the C34E
draft commit. This is pure authorization-model evidence, not host authority.
Related: c34i_final_main_seal.py, c34f_application_generation_evidence.py,
c34g_migration_authority.py, executor_service_config.py,
broker_service_config.py, tests/test_c34i_merged_migration_authority.py.

No filesystem mutation, service lifecycle action, network access, root
operation or deployment. The proposed final-main seal never grants approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from . import c34f_application_generation_evidence as evidence
from . import c34g_migration_authority as draft
from . import c34i_final_main_seal as final
from .broker_service_config import DevBrokerServiceConfiguration
from .executor_service_config import DevExecutorServiceConfiguration


# Section 1: Reuse the reviewed C34G ordering; revise only target revision.
_ERROR = "C34I merged migration authority is invalid"


@dataclass(frozen=True, slots=True)
class C34IMergedMigrationState:
    """One exact source/config prefix for a verified prospective main SHA."""

    completed_steps: int
    next_operation: str
    target_main_commit: str

    def __post_init__(self) -> None:
        """Reject forged operation, invalid prefixes or draft SHA authority."""
        if (
            type(self.completed_steps) is not int
            or not 0 <= self.completed_steps <= 5
            or self.next_operation != draft._OPERATIONS[self.completed_steps]
            or type(self.target_main_commit) is not str
            or final._COMMIT.fullmatch(self.target_main_commit) is None
            or self.target_main_commit in final._UNMERGED_OR_CURRENT
        ):
            raise ValueError(_ERROR)

    def rollback_operation(self) -> str:
        """Give only the corresponding inverse step, without write capability."""
        return (
            "complete",
            "restore-deployment-broker-py",
            "restore-deployment-broker-https-ingress-py",
            "restore-deployment-broker-integration-py",
            "restore-executor-configuration",
            "restore-broker-configuration",
        )[self.completed_steps]


@dataclass(frozen=True, slots=True, kw_only=True)
class C34IMergedMigrationAuthority:
    """Pure fixed-prefix classifier based on an independently reviewed seal."""

    source_seal: final.C34IFinalMainSourceSeal
    predecessor_executor: DevExecutorServiceConfiguration
    predecessor_broker: DevBrokerServiceConfiguration

    _old_digests: tuple[tuple[str, str], ...] = field(init=False, repr=False)
    _new_digests: tuple[tuple[str, str], ...] = field(init=False, repr=False)
    _target_executor: DevExecutorServiceConfiguration = field(init=False, repr=False)
    _target_broker: DevBrokerServiceConfiguration = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Recompute the final seal and require exact predecessor identity."""
        try:
            if (
                type(self.source_seal) is not final.C34IFinalMainSourceSeal
                or type(self.predecessor_executor) is not DevExecutorServiceConfiguration
                or type(self.predecessor_broker) is not DevBrokerServiceConfiguration
            ):
                raise TypeError
            target_sha = self.source_seal.proposed_final_main_commit
            verified = final.prepare_c34i_final_main_source_seal(
                independently_reviewed_main_sha=target_sha,
            )
            if verified != self.source_seal or verified.approval_granted is not False:
                raise ValueError
            executor = DevExecutorServiceConfiguration.from_dict(
                self.predecessor_executor.to_dict()
            )
            broker = DevBrokerServiceConfiguration.from_dict(
                self.predecessor_broker.to_dict()
            )
            if (
                executor.reviewed_commit != evidence.PREDECESSOR
                or broker.reviewed_commit != evidence.PREDECESSOR
                or broker.expected_workflow_sha != evidence.C34D_MAIN
                or any(getattr(executor, key) != getattr(broker, key)
                       for key in draft._SHARED)
            ):
                raise ValueError
            paths = tuple(
                item.repository_path for item in
                final.DevApplicationSourceSet().files
            )
            old = evidence._manifest(evidence.PREDECESSOR, paths)
            new = evidence._manifest(target_sha, paths)
            if (
                len(paths) != 41
                or paths != tuple(sorted(set(paths)))
                or evidence._digest(old.canonical_bytes()) != evidence.MANIFESTS[0]
                or evidence._digest(new.canonical_bytes())
                != verified.source_manifest_sha256
                or tuple(item.path for item in old.entries) != paths
                or tuple(item.path for item in new.entries) != paths
            ):
                raise ValueError

            prior = tuple((item.path, item.sha256) for item in old.entries)
            target = tuple((item.path, item.sha256) for item in new.entries)
            old_map = dict(prior)
            new_map = dict(target)
            if (
                tuple(path for path in paths if old_map[path] != new_map[path])
                != evidence.CHANGED
                or tuple(old_map[p] for p in evidence.CHANGED) != evidence.OLD_BLOBS
                or tuple(new_map[p] for p in evidence.CHANGED) != evidence.NEW_BLOBS
            ):
                raise ValueError

            target_executor = replace(executor, reviewed_commit=target_sha)
            target_broker = replace(broker, reviewed_commit=target_sha)
            for old_config, new_config in (
                (executor, target_executor), (broker, target_broker),
            ):
                left, right = old_config.to_dict(), new_config.to_dict()
                if (
                    left.keys() != right.keys()
                    or {k for k in left if left[k] != right[k]}
                    != {"reviewed_commit"}
                ):
                    raise ValueError
            if target_broker.expected_workflow_sha != evidence.C34D_MAIN:
                raise ValueError
            object.__setattr__(self, "predecessor_executor", executor)
            object.__setattr__(self, "predecessor_broker", broker)
            object.__setattr__(self, "_old_digests", prior)
            object.__setattr__(self, "_new_digests", target)
            object.__setattr__(self, "_target_executor", target_executor)
            object.__setattr__(self, "_target_broker", target_broker)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def classify(
        self,
        *,
        observed_application_digests: tuple[tuple[str, str], ...],
        executor: DevExecutorServiceConfiguration,
        broker: DevBrokerServiceConfiguration,
    ) -> C34IMergedMigrationState:
        """Permit only the six previously reviewed C34G ordered prefixes.

        Installed observations must separately come from the root-only,
        descriptor-validated host reader, never caller-provided guesses.
        """
        try:
            if (
                type(observed_application_digests) is not tuple
                or type(executor) is not DevExecutorServiceConfiguration
                or type(broker) is not DevBrokerServiceConfiguration
                or len(observed_application_digests) != len(self._old_digests)
            ):
                raise ValueError
            ex = DevExecutorServiceConfiguration.from_dict(executor.to_dict())
            br = DevBrokerServiceConfiguration.from_dict(broker.to_dict())
            for phase in range(6):
                sources_advanced = min(phase, 3)
                expected = tuple(
                    (name, new if name in evidence.CHANGED[:sources_advanced] else old)
                    for (name, old), (_, new)
                    in zip(self._old_digests, self._new_digests, strict=True)
                )
                target_ex = (
                    self._target_executor if phase >= 4
                    else self.predecessor_executor
                )
                target_br = (
                    self._target_broker if phase >= 5
                    else self.predecessor_broker
                )
                if (
                    observed_application_digests == expected
                    and ex.canonical_bytes() == target_ex.canonical_bytes()
                    and br.canonical_bytes() == target_br.canonical_bytes()
                ):
                    return C34IMergedMigrationState(
                        phase, draft._OPERATIONS[phase],
                        self.source_seal.proposed_final_main_commit,
                    )
            raise ValueError
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise ValueError(_ERROR) from None

    def target_configuration_pair(
        self,
    ) -> tuple[DevExecutorServiceConfiguration, DevBrokerServiceConfiguration]:
        """Return only canonical target config values, never destination paths."""
        return self._target_executor, self._target_broker


__all__ = (
    "C34IMergedMigrationState",
    "C34IMergedMigrationAuthority",
)
