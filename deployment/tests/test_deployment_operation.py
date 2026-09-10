"""Deterministic, non-live tests for the audited DEV deployment operation."""

from __future__ import annotations

import ast
from dataclasses import replace
import inspect
from pathlib import Path
import unittest

import deployment.audit as audit_module
import deployment.controller as controller_module
import deployment.deployment_operation as operation_module
import deployment.state as state_module
from deployment.audit import AuditEvent
from deployment.deployment_operation import (
    DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE,
    DeploymentOperationError,
    DevDeploymentOperation,
)
from deployment.docker_runtime import MIGRATION_CHECKSUM, MIGRATION_IDENTITY
from deployment.execution import ExecutorRequest
from deployment.state import DeploymentState
from deployment.tests.fixtures import executor_request, state


REVIEWED_COMMIT = "4" * 40
RUNTIME_HASH = "d" * 64
INGRESS_HASHES = ("1" * 64, "2" * 64, "3" * 64)
TIMESTAMPS = tuple(f"2026-09-10T12:00:{index:02d}Z" for index in range(40))


class Runtime:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.fail: str | None = None
        self.false: str | None = None

    def _record(self, name: str, *values: object) -> None:
        self.calls.append((name, *values))
        if self.fail == name:
            raise RuntimeError(f"dependency-marker-{name}")

    def pull_exact_image(self, image: str) -> None:
        self._record("pull", image)

    def verify_local_repo_digest(self, image: str) -> None:
        self._record("verify", image)

    def start_candidate(self, plan: object) -> None:
        self._record("start", plan)

    def execute_migration(
        self, *, stage: str, exact_image_reference: str, identity: str, checksum: str,
    ) -> None:
        self._record("migration", stage, exact_image_reference, identity, checksum)

    def check_liveness(self, stage: str, slot: str) -> bool:
        self._record("liveness", stage, slot)
        return self.false != "liveness"

    def check_readiness(self, stage: str, slot: str) -> bool:
        self._record("readiness", stage, slot)
        return self.false != "readiness"

    def validate_application(self, plan: object) -> bool:
        self._record("application", plan)
        return self.false != "application"

    def validate_nginx(self, stage: str) -> bool:
        self._record("nginx", stage)
        return self.false != "nginx"

    def switch_traffic(self, stage: str, slot: str) -> None:
        self._record("switch", stage, slot)

    def restore_traffic(self, stage: str, previous_slot: str | None) -> None:
        self._record("restore", stage, previous_slot)


class StateStore:
    def __init__(self, initial: DeploymentState | None = None) -> None:
        self.initial = initial or state()
        self.saved: list[DeploymentState] = []
        self.fail_save: int | None = None
        self.load_calls = 0

    def load(self) -> DeploymentState:
        self.load_calls += 1
        return self.initial

    def save(self, value: DeploymentState) -> None:
        self.saved.append(value)
        if self.fail_save == len(self.saved):
            raise RuntimeError("dependency-marker-state")


class AuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.fail_type: str | None = None

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)
        if event.event_type == self.fail_type:
            raise RuntimeError("dependency-marker-audit")


class Clock:
    def __init__(self, values: tuple[object, ...] = TIMESTAMPS) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        return self.values.pop(0)


def operation(
    runtime: Runtime | None = None, store: StateStore | None = None,
    sink: AuditSink | None = None, clock: Clock | None = None,
) -> tuple[DevDeploymentOperation, Runtime, StateStore, AuditSink, Clock]:
    runtime = runtime or Runtime()
    store = store or StateStore()
    sink = sink or AuditSink()
    clock = clock or Clock()
    return (
        DevDeploymentOperation(
            runtime=runtime, state_store=store, audit_sink=sink, clock=clock,
            reviewed_commit=REVIEWED_COMMIT,
            runtime_configuration_sha256=RUNTIME_HASH,
            ingress_file_sha256=INGRESS_HASHES,
        ),
        runtime, store, sink, clock,
    )


class ConstructionTests(unittest.TestCase):
    def test_import_and_construction_are_inert_and_api_is_narrow(self) -> None:
        deployment, runtime, store, sink, clock = operation()
        self.assertEqual(runtime.calls, [])
        self.assertEqual(store.saved, [])
        self.assertEqual(sink.events, [])
        self.assertEqual(clock.calls, 0)
        self.assertEqual(
            tuple(inspect.signature(DevDeploymentOperation.deploy).parameters),
            ("self", "request"),
        )
        self.assertEqual(set(DevDeploymentOperation.__dict__) & {"bind", "listen", "accept"}, set())
        with self.assertRaises(AttributeError):
            deployment.runtime = runtime  # type: ignore[attr-defined]

    def test_constructor_rejects_missing_or_nonordinary_collaborators(self) -> None:
        valid = dict(
            runtime=Runtime(), state_store=StateStore(), audit_sink=AuditSink(),
            clock=Clock(), reviewed_commit=REVIEWED_COMMIT,
            runtime_configuration_sha256=RUNTIME_HASH,
            ingress_file_sha256=INGRESS_HASHES,
        )
        for key in ("runtime", "state_store", "audit_sink", "clock"):
            changed = dict(valid); changed[key] = None
            with self.subTest(key=key), self.assertRaises(TypeError):
                DevDeploymentOperation(**changed)

        class VariadicRuntime(Runtime):
            def pull_exact_image(self, *values: object) -> None:
                return None

        changed = dict(valid); changed["runtime"] = VariadicRuntime()
        with self.assertRaises(TypeError):
            DevDeploymentOperation(**changed)

    def test_constructor_rejects_unreviewed_values_and_subclasses(self) -> None:
        class Text(str):
            pass

        class Hashes(tuple):
            pass

        values = (
            {"reviewed_commit": "bad"},
            {"reviewed_commit": Text(REVIEWED_COMMIT)},
            {"runtime_configuration_sha256": "A" * 64},
            {"ingress_file_sha256": ("1" * 64,)},
            {"ingress_file_sha256": Hashes(INGRESS_HASHES)},
            {"ingress_file_sha256": (Text("1" * 64), "2" * 64, "3" * 64)},
        )
        for changes in values:
            args = dict(
                runtime=Runtime(), state_store=StateStore(), audit_sink=AuditSink(),
                clock=Clock(), reviewed_commit=REVIEWED_COMMIT,
                runtime_configuration_sha256=RUNTIME_HASH,
                ingress_file_sha256=INGRESS_HASHES,
            ); args.update(changes)
            with self.subTest(changes=changes), self.assertRaises(TypeError):
                DevDeploymentOperation(**args)


class SuccessfulDeploymentTests(unittest.TestCase):
    def test_complete_ordered_deployment_and_exact_none(self) -> None:
        deployment, runtime, store, sink, clock = operation()
        self.assertIsNone(deployment.deploy(executor_request()))
        self.assertEqual(
            [call[0] for call in runtime.calls],
            ["pull", "verify", "start", "migration", "liveness", "readiness",
             "application", "nginx", "switch"],
        )
        self.assertEqual(
            [event.event_type for event in sink.events],
            ["promotion_started", "migration_started", "migration_succeeded",
             "liveness_passed", "readiness_passed", "traffic_switch_started",
             "traffic_switch_succeeded", "promotion_succeeded"],
        )
        self.assertEqual([item.migration_state.status for item in store.saved],
                         ["pending", "running", "succeeded", "succeeded"])
        final = store.saved[-1]
        self.assertEqual((final.active_digest, final.active_slot),
                         (executor_request().manifest_digest, "green"))
        self.assertEqual((final.previous_digest, final.previous_slot),
                         (state().active_digest, "blue"))
        self.assertIsNone(final.candidate_digest)
        self.assertEqual(clock.calls, len(sink.events))

    def test_first_deployment_uses_blue_and_completes(self) -> None:
        raw = state(previous=False).to_dict()
        for prefix in ("active", "previous"):
            for suffix in ("release", "source_sha", "digest", "slot"):
                raw[f"{prefix}_{suffix}"] = None
        store = StateStore(DeploymentState.from_dict(raw))
        deployment, runtime, store, _, _ = operation(store=store)
        deployment.deploy(executor_request())
        self.assertEqual(runtime.calls[2][1].candidate_slot, "blue")
        self.assertEqual(store.saved[-1].active_slot, "blue")

    def test_exact_image_migration_and_request_identity_are_preserved(self) -> None:
        request = executor_request()
        deployment, runtime, _, sink, _ = operation()
        deployment.deploy(request)
        self.assertEqual(runtime.calls[0], ("pull", request.exact_image_reference))
        self.assertEqual(runtime.calls[1], ("verify", request.exact_image_reference))
        self.assertEqual(
            runtime.calls[3],
            ("migration", "dev", request.exact_image_reference,
             MIGRATION_IDENTITY, MIGRATION_CHECKSUM),
        )
        hashes = {event.execution_identity.executor_request_sha256 for event in sink.events}
        self.assertEqual(hashes, {request.sha256()})
        for event in sink.events:
            event.require_executor_request(request)
        self.assertEqual(len({event.event_id for event in sink.events}), len(sink.events))
        encoded = b"".join(event.canonical_bytes() for event in sink.events).lower()
        for marker in (
            b"token=", b"secret=", b"credential=", b"canonical_request",
            b"subprocess_output", b"dependency-marker",
        ):
            self.assertNotIn(marker, encoded)

    def test_event_ids_are_deterministic_and_bounded_for_the_same_request(self) -> None:
        first = operation(); second = operation()
        first[0].deploy(executor_request()); second[0].deploy(executor_request())
        first_ids = [event.event_id for event in first[3].events]
        second_ids = [event.event_id for event in second[3].events]
        self.assertEqual(first_ids, second_ids)
        self.assertTrue(all(len(value) <= 128 for value in first_ids))

    def test_caller_request_mutation_after_snapshot_cannot_redirect_runtime(self) -> None:
        request = executor_request()
        expected = request.exact_image_reference

        class MutatingStore(StateStore):
            def load(self) -> DeploymentState:
                object.__setattr__(request, "exact_image_reference", "hostile-marker")
                return self.initial

        deployment, runtime, _, _, _ = operation(store=MutatingStore())
        deployment.deploy(request)
        self.assertEqual(runtime.calls[0][1], expected)

    def test_collaborator_module_mutation_cannot_replace_captured_policy(self) -> None:
        names = (
            "promotion_plan", "prepare_candidate", "complete_promotion",
            "_snapshot_state", "MIGRATION_IDENTITY",
        )
        originals = {name: getattr(operation_module, name) for name in names}

        class MutatingStore(StateStore):
            def load(self) -> DeploymentState:
                operation_module.promotion_plan = lambda *args: "hostile"  # type: ignore[assignment]
                operation_module.prepare_candidate = lambda *args: "hostile"  # type: ignore[assignment]
                operation_module.complete_promotion = lambda *args, **kwargs: "hostile"  # type: ignore[assignment]
                operation_module._snapshot_state = lambda *args, **kwargs: "hostile"  # type: ignore[assignment]
                operation_module.MIGRATION_IDENTITY = "hostile"
                return self.initial

        deployment, runtime, store, sink, _ = operation(store=MutatingStore())
        try:
            deployment.deploy(executor_request())
        finally:
            for name, value in originals.items():
                setattr(operation_module, name, value)
        self.assertEqual(runtime.calls[3][-2:], (MIGRATION_IDENTITY, MIGRATION_CHECKSUM))
        self.assertEqual(store.saved[-1].active_digest, executor_request().manifest_digest)
        self.assertEqual(sink.events[-1].event_type, "promotion_succeeded")

    def test_hostile_controller_prepare_result_cannot_redirect_state(self) -> None:
        original_replace = controller_module.replace

        def hostile_replace(value: object, **changes: object) -> DeploymentState:
            raw = state().to_dict()
            raw.update({
                "candidate_release": "9.9.9", "candidate_source_sha": "e" * 40,
                "candidate_digest": "sha256:" + "f" * 64,
                "candidate_slot": "green",
                "migration_state": {
                    "status": "pending", "identity": MIGRATION_IDENTITY,
                    "checksum": MIGRATION_CHECKSUM,
                    "serialized_lock_required": True,
                },
            })
            return DeploymentState.from_dict(raw)

        class MutatingStore(StateStore):
            def load(self) -> DeploymentState:
                controller_module.replace = hostile_replace  # type: ignore[assignment]
                return self.initial

        deployment, runtime, store, sink, _ = operation(store=MutatingStore())
        try:
            with self.assertRaises(DeploymentOperationError):
                deployment.deploy(executor_request())
        finally:
            controller_module.replace = original_replace
        self.assertEqual((runtime.calls, store.saved, sink.events), ([], [], []))

    def test_hostile_audit_identity_factory_cannot_redirect_actor(self) -> None:
        original_descriptor = audit_module.AuditExecutionIdentity.__dict__[
            "from_executor_request"
        ]

        def hostile_identity(cls: type[object], request: ExecutorRequest) -> object:
            forged = replace(request, requested_by_actor_id=999999)
            return original_descriptor.__func__(audit_module.AuditExecutionIdentity, forged)

        class MutatingStore(StateStore):
            def load(self) -> DeploymentState:
                audit_module.AuditExecutionIdentity.from_executor_request = classmethod(  # type: ignore[method-assign]
                    hostile_identity,
                )
                return self.initial

        deployment, runtime, store, sink, _ = operation(store=MutatingStore())
        try:
            with self.assertRaises(DeploymentOperationError):
                deployment.deploy(executor_request())
        finally:
            audit_module.AuditExecutionIdentity.from_executor_request = original_descriptor  # type: ignore[method-assign]
        self.assertEqual((runtime.calls, store.saved, sink.events), ([], [], []))

    def test_runtime_cannot_mutate_plan_class_to_redirect_later_validation(self) -> None:
        original_plan = controller_module.DeploymentPlan

        class MutatingRuntime(Runtime):
            def start_candidate(self, plan: object) -> None:
                self._record("start", plan)
                controller_module.DeploymentPlan = lambda *args: {"hostile": True}  # type: ignore[assignment,misc]

        runtime = MutatingRuntime()
        deployment, _, store, sink, _ = operation(runtime=runtime)
        try:
            deployment.deploy(executor_request())
        finally:
            controller_module.DeploymentPlan = original_plan
        self.assertEqual(runtime.calls[2][1].exact_image_reference,
                         executor_request().exact_image_reference)
        self.assertEqual(runtime.calls[6][1].exact_image_reference,
                         executor_request().exact_image_reference)
        self.assertEqual(store.saved[-1].active_digest, executor_request().manifest_digest)
        self.assertEqual(sink.events[-1].event_type, "promotion_succeeded")


class RequestAndStateValidationTests(unittest.TestCase):
    def test_request_subclass_and_nested_forgery_fail_before_collaborators(self) -> None:
        class RequestSubclass(ExecutorRequest):
            pass

        base = executor_request()
        forged = RequestSubclass(**vars(base))
        for request in (forged, replace(base, runtime_configuration_reference=object())):
            deployment, runtime, store, sink, clock = operation()
            with self.subTest(request=request), self.assertRaises(DeploymentOperationError):
                deployment.deploy(request)  # type: ignore[arg-type]
            self.assertEqual((runtime.calls, store.saved, sink.events, clock.calls), ([], [], [], 0))

    def test_hostile_request_scalar_subclasses_are_rejected_not_normalized(self) -> None:
        class Text(str):
            pass

        class Integer(int):
            pass

        base = executor_request()
        for request in (
            replace(base, release_version=Text(base.release_version)),
            replace(base, github_run_id=Integer(base.github_run_id)),
            replace(
                base,
                runtime_configuration_reference=replace(
                    base.runtime_configuration_reference,
                    sha256=Text(base.runtime_configuration_reference.sha256),
                ),
            ),
        ):
            deployment, runtime, store, sink, clock = operation()
            with self.subTest(request=request), self.assertRaises(DeploymentOperationError):
                deployment.deploy(request)
            self.assertEqual((runtime.calls, store.saved, sink.events, clock.calls), ([], [], [], 0))

    def test_every_bound_asset_mismatch_fails_before_load(self) -> None:
        mutations = (
            {"reviewed_commit": "5" * 40},
            {"runtime_configuration_sha256": "e" * 64},
            {"ingress_file_sha256": ("9" * 64, "2" * 64, "3" * 64)},
        )
        for changes in mutations:
            runtime, store, sink, clock = Runtime(), StateStore(), AuditSink(), Clock()
            args = dict(
                runtime=runtime, state_store=store, audit_sink=sink, clock=clock,
                reviewed_commit=REVIEWED_COMMIT,
                runtime_configuration_sha256=RUNTIME_HASH,
                ingress_file_sha256=INGRESS_HASHES,
            ); args.update(changes)
            deployment = DevDeploymentOperation(**args)
            with self.subTest(changes=changes), self.assertRaises(DeploymentOperationError):
                deployment.deploy(executor_request())
            self.assertEqual((runtime.calls, store.saved, sink.events, clock.calls), ([], [], [], 0))

    def test_state_must_be_exact_fresh_dev_base_value(self) -> None:
        base = state()

        class StateSubclass(DeploymentState):
            pass

        invalid = [
            StateSubclass(**vars(base)),
            state(candidate=True),
            replace(base, stage="staging"),
            replace(base, migration_state=replace(base.migration_state, status="running",
                                                   identity=MIGRATION_IDENTITY,
                                                   checksum=MIGRATION_CHECKSUM)),
        ]
        for value in invalid:
            deployment, runtime, store, sink, clock = operation(store=StateStore(value))
            with self.subTest(value=value), self.assertRaises(DeploymentOperationError):
                deployment.deploy(executor_request())
            self.assertEqual((runtime.calls, store.saved, sink.events, clock.calls), ([], [], [], 0))

    def test_hostile_state_scalar_subclass_is_rejected_before_mutation(self) -> None:
        class Text(str):
            pass

        deployment, runtime, store, sink, clock = operation(
            store=StateStore(replace(state(), active_slot=Text("blue"))),
        )
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(executor_request())
        self.assertEqual((runtime.calls, store.saved, sink.events, clock.calls), ([], [], [], 0))


class ActiveIdentityRejectionTests(unittest.TestCase):
    @staticmethod
    def active_state(
        request: ExecutorRequest, *, release: str | None = None,
        source: str | None = None, digest: str | None = None,
    ) -> DeploymentState:
        value = state().to_dict()
        value.update({
            "active_release": request.release_version if release is None else release,
            "active_source_sha": request.source_sha if source is None else source,
            "active_digest": request.manifest_digest if digest is None else digest,
        })
        return DeploymentState.from_dict(value)

    def assert_rejected_without_effects(
        self, request: ExecutorRequest, initial: DeploymentState,
    ) -> None:
        runtime, store, sink, clock = Runtime(), StateStore(initial), AuditSink(), Clock()
        deployment, _, _, _, _ = operation(
            runtime=runtime, store=store, sink=sink, clock=clock,
        )
        with self.assertRaisesRegex(
            DeploymentOperationError,
            f"^{DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE}$",
        ) as caught:
            deployment.deploy(request)
        self.assertEqual(store.load_calls, 1)
        self.assertEqual(store.saved, [])
        self.assertEqual(sink.events, [])
        self.assertEqual(runtime.calls, [])
        self.assertEqual(clock.calls, 0)
        exposed = str(caught.exception)
        for marker in (
            request.release_version, request.source_sha, request.manifest_digest,
            "state", "already", "conflict", "injected-marker",
        ):
            self.assertNotIn(marker, exposed)

    def test_exact_active_release_source_digest_is_rejected(self) -> None:
        request = executor_request()
        self.assert_rejected_without_effects(request, self.active_state(request))

    def test_same_active_digest_with_different_release_and_source_is_rejected(self) -> None:
        request = executor_request()
        self.assert_rejected_without_effects(
            request,
            self.active_state(request, release="9.9.9", source="e" * 40),
        )

    def test_same_active_version_with_different_digest_is_rejected(self) -> None:
        request = executor_request()
        self.assert_rejected_without_effects(
            request,
            self.active_state(
                request, source="e" * 40, digest="sha256:" + "f" * 64,
            ),
        )

    def test_first_deployment_and_genuinely_different_candidate_still_succeed(self) -> None:
        request = executor_request()
        empty = state(previous=False).to_dict()
        for prefix in ("active", "previous"):
            for suffix in ("release", "source_sha", "digest", "slot"):
                empty[f"{prefix}_{suffix}"] = None
        first = operation(store=StateStore(DeploymentState.from_dict(empty)))
        self.assertIsNone(first[0].deploy(request))
        self.assertEqual(first[1].calls[-1][0], "switch")

        different = operation(store=StateStore(state()))
        self.assertIsNone(different[0].deploy(request))
        self.assertEqual(different[3].events[-1].event_type, "promotion_succeeded")

    def test_shared_source_with_distinct_version_and_digest_is_allowed(self) -> None:
        request = executor_request()
        initial = self.active_state(
            request, release="0.13.3", source=request.source_sha,
            digest="sha256:" + "f" * 64,
        )
        deployment, _, store, sink, _ = operation(store=StateStore(initial))
        self.assertIsNone(deployment.deploy(request))
        self.assertEqual(store.saved[-1].active_digest, request.manifest_digest)
        self.assertEqual(sink.events[-1].event_type, "promotion_succeeded")

    def test_hostile_string_subclasses_cannot_bypass_identity_checks(self) -> None:
        class EqualText(str):
            def __eq__(self, other: object) -> bool:
                return False

        request = executor_request()
        hostile_request = replace(
            request, manifest_digest=EqualText(request.manifest_digest),
        )
        deployment, runtime, store, sink, clock = operation(
            store=StateStore(self.active_state(request)),
        )
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(hostile_request)
        self.assertEqual((store.load_calls, runtime.calls, store.saved, sink.events, clock.calls),
                         (0, [], [], [], 0))

        hostile_state = replace(
            self.active_state(request),
            active_digest=EqualText(request.manifest_digest),
        )
        deployment, runtime, store, sink, clock = operation(
            store=StateStore(hostile_state),
        )
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(request)
        self.assertEqual((store.load_calls, runtime.calls, store.saved, sink.events, clock.calls),
                         (1, [], [], [], 0))

    def test_request_mutation_after_snapshot_cannot_change_rejection(self) -> None:
        request = executor_request()
        initial = self.active_state(request)

        class MutatingStore(StateStore):
            def load(self) -> DeploymentState:
                self.load_calls += 1
                object.__setattr__(request, "manifest_digest", "sha256:" + "f" * 64)
                object.__setattr__(request, "release_version", "9.9.9")
                return self.initial

        runtime, store, sink, clock = Runtime(), MutatingStore(initial), AuditSink(), Clock()
        deployment, _, _, _, _ = operation(
            runtime=runtime, store=store, sink=sink, clock=clock,
        )
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(request)
        self.assertEqual((store.load_calls, runtime.calls, store.saved, sink.events, clock.calls),
                         (1, [], [], [], 0))

    def test_state_mutation_after_validation_cannot_redirect_identity(self) -> None:
        request = executor_request()
        initial = state()
        original_active = (
            initial.active_release, initial.active_source_sha,
            initial.active_digest, initial.active_slot,
        )

        class MutatingRuntime(Runtime):
            def pull_exact_image(self, image: str) -> None:
                object.__setattr__(initial, "active_release", request.release_version)
                object.__setattr__(initial, "active_source_sha", request.source_sha)
                object.__setattr__(initial, "active_digest", request.manifest_digest)
                self._record("pull", image)

        deployment, _, store, _, _ = operation(
            runtime=MutatingRuntime(), store=StateStore(initial),
        )
        self.assertIsNone(deployment.deploy(request))
        final = store.saved[-1]
        self.assertEqual(
            (final.previous_release, final.previous_source_sha,
             final.previous_digest, final.previous_slot),
            original_active,
        )


class FailureAndCompensationTests(unittest.TestCase):
    def assert_failure(self, runtime: Runtime, *, fail: str | None = None,
                       false: str | None = None) -> tuple[StateStore, AuditSink]:
        runtime.fail, runtime.false = fail, false
        deployment, _, store, sink, _ = operation(runtime=runtime)
        with self.assertRaisesRegex(
            DeploymentOperationError, f"^{DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE}$",
        ) as caught:
            deployment.deploy(executor_request())
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("dependency-marker", str(caught.exception))
        return store, sink

    def test_runtime_failures_stop_and_emit_closed_terminal_evidence(self) -> None:
        cases = {
            "pull": None, "verify": None, "start": None,
            "migration": "migration_failed", "liveness": "liveness_failed",
            "readiness": "readiness_failed", "application": None,
            "nginx": None, "switch": "traffic_switch_failed",
        }
        for step, specific in cases.items():
            runtime = Runtime()
            store, sink = self.assert_failure(
                runtime, fail=step if step not in ("liveness", "readiness", "application") else None,
                false=step if step in ("liveness", "readiness", "application") else None,
            )
            types = [event.event_type for event in sink.events]
            with self.subTest(step=step):
                self.assertEqual(types[-1], "promotion_failed")
                if specific is not None:
                    self.assertIn(specific, types)
                self.assertNotIn("promotion_succeeded", types)
                restores = [call for call in runtime.calls if call[0] == "restore"]
                self.assertEqual(
                    restores,
                    [("restore", "dev", "blue")] if step == "switch" else [],
                )

    def test_post_switch_audit_state_and_success_audit_failures_restore_route_and_state(self) -> None:
        scenarios = (("audit", "traffic_switch_succeeded"), ("state", 4),
                     ("audit", "promotion_succeeded"))
        for kind, marker in scenarios:
            runtime, store, sink = Runtime(), StateStore(), AuditSink()
            if kind == "audit": sink.fail_type = marker  # type: ignore[assignment]
            else: store.fail_save = marker  # type: ignore[assignment]
            deployment, _, _, _, _ = operation(runtime=runtime, store=store, sink=sink)
            with self.subTest(kind=kind, marker=marker), self.assertRaises(DeploymentOperationError):
                deployment.deploy(executor_request())
            self.assertEqual([call for call in runtime.calls if call[0] == "restore"],
                             [("restore", "dev", "blue")])
            self.assertEqual(store.saved[-1], state())
            self.assertIn("promotion_failed", [event.event_type for event in sink.events])

    def test_first_deployment_post_switch_failure_restores_no_active_route(self) -> None:
        raw = state(previous=False).to_dict()
        for prefix in ("active", "previous"):
            for suffix in ("release", "source_sha", "digest", "slot"):
                raw[f"{prefix}_{suffix}"] = None
        runtime, store, sink = Runtime(), StateStore(DeploymentState.from_dict(raw)), AuditSink()
        store.fail_save = 4
        deployment, _, _, _, _ = operation(runtime=runtime, store=store, sink=sink)
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(executor_request())
        self.assertIn(("restore", "dev", None), runtime.calls)
        self.assertEqual(store.saved[-1], store.initial)

    def test_audit_failure_is_not_retried_and_operation_fails(self) -> None:
        sink = AuditSink(); sink.fail_type = "migration_succeeded"
        deployment, _, _, sink, _ = operation(sink=sink)
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(executor_request())
        matching = [event for event in sink.events if event.event_type == "migration_succeeded"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(sink.events[-1].event_type, "promotion_failed")

    def test_uncertain_promotion_started_append_attempts_terminal_once(self) -> None:
        sink = AuditSink(); sink.fail_type = "promotion_started"
        deployment, runtime, store, sink, _ = operation(sink=sink)
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(executor_request())
        types = [event.event_type for event in sink.events]
        self.assertEqual(types.count("promotion_started"), 1)
        self.assertEqual(types.count("promotion_failed"), 1)
        self.assertEqual((runtime.calls, store.saved), ([], []))

    def test_sink_event_mutation_is_detected_before_state_checkpoint(self) -> None:
        class MutatingSink(AuditSink):
            def append(self, event: AuditEvent) -> None:
                self.events.append(event)
                if event.event_type == "promotion_started":
                    object.__setattr__(event, "timestamp", "2026-09-10T12:00:39Z")
                    object.__setattr__(event, "event_id", "hostile-event")

        sink = MutatingSink()
        deployment, runtime, store, sink, _ = operation(sink=sink)
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(executor_request())
        self.assertEqual((runtime.calls, store.saved), ([], []))
        self.assertEqual(sink.events[-1].event_type, "promotion_failed")

    def test_sink_cannot_mutate_state_parser_to_forge_checkpoint(self) -> None:
        original_descriptor = state_module.MigrationState.__dict__["from_dict"]

        def hostile_migration(cls: type[object], value: object) -> object:
            return state_module.MigrationState(
                "succeeded", MIGRATION_IDENTITY, MIGRATION_CHECKSUM, True,
            )

        class MutatingSink(AuditSink):
            def append(self, event: AuditEvent) -> None:
                self.events.append(event)
                if event.event_type == "promotion_started":
                    state_module.MigrationState.from_dict = classmethod(  # type: ignore[method-assign]
                        hostile_migration,
                    )

        sink = MutatingSink()
        deployment, runtime, store, sink, _ = operation(sink=sink)
        try:
            with self.assertRaises(DeploymentOperationError):
                deployment.deploy(executor_request())
        finally:
            state_module.MigrationState.from_dict = original_descriptor  # type: ignore[method-assign]
        self.assertEqual((runtime.calls, store.saved), ([], []))
        self.assertEqual(sink.events[-1].event_type, "promotion_failed")

    def test_hostile_completed_controller_state_is_rejected_and_compensated(self) -> None:
        original_state_type = controller_module.DeploymentState

        class HostileStateType:
            @classmethod
            def from_dict(cls, value: dict[str, object]) -> DeploymentState:
                raw = state().to_dict()
                raw.update({
                    "active_release": "9.9.9", "active_source_sha": "e" * 40,
                    "active_digest": "sha256:" + "f" * 64, "active_slot": "green",
                    "previous_release": state().active_release,
                    "previous_source_sha": state().active_source_sha,
                    "previous_digest": state().active_digest, "previous_slot": "blue",
                    "migration_state": {
                        "status": "succeeded", "identity": MIGRATION_IDENTITY,
                        "checksum": MIGRATION_CHECKSUM, "serialized_lock_required": True,
                    },
                    "updated_at": value["updated_at"], "event_id": value["event_id"],
                })
                return DeploymentState.from_dict(raw)

        class MutatingSink(AuditSink):
            def append(self, event: AuditEvent) -> None:
                self.events.append(event)
                if event.event_type == "traffic_switch_succeeded":
                    controller_module.DeploymentState = HostileStateType  # type: ignore[assignment,misc]

        runtime, store, sink = Runtime(), StateStore(), MutatingSink()
        deployment, _, _, _, _ = operation(runtime=runtime, store=store, sink=sink)
        try:
            with self.assertRaises(DeploymentOperationError):
                deployment.deploy(executor_request())
        finally:
            controller_module.DeploymentState = original_state_type
        self.assertEqual([call for call in runtime.calls if call[0] == "restore"],
                         [("restore", "dev", "blue")])
        self.assertEqual(store.saved[-1], state())
        self.assertNotIn("sha256:" + "f" * 64,
                         [value.active_digest for value in store.saved])

    def test_uncertain_passed_health_append_does_not_fabricate_failed_health(self) -> None:
        sink = AuditSink(); sink.fail_type = "liveness_passed"
        deployment, _, _, sink, _ = operation(sink=sink)
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(executor_request())
        types = [event.event_type for event in sink.events]
        self.assertEqual(types.count("liveness_passed"), 1)
        self.assertNotIn("liveness_failed", types)
        self.assertEqual(types[-1], "promotion_failed")

    def test_health_exception_emits_failed_health_and_terminal_events(self) -> None:
        class HealthRuntime(Runtime):
            def check_liveness(self, stage: str, slot: str) -> bool:
                self._record("liveness", stage, slot)
                raise RuntimeError("health-marker")

        deployment, _, _, sink, _ = operation(runtime=HealthRuntime())
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(executor_request())
        self.assertEqual([event.event_type for event in sink.events][-2:],
                         ["liveness_failed", "promotion_failed"])

    def test_hostile_switch_return_triggers_one_restoration(self) -> None:
        class ReturningRuntime(Runtime):
            def switch_traffic(self, stage: str, slot: str) -> None:
                self._record("switch", stage, slot)
                return "hostile-marker"  # type: ignore[return-value]

        runtime = ReturningRuntime()
        deployment, _, store, sink, _ = operation(runtime=runtime)
        with self.assertRaises(DeploymentOperationError):
            deployment.deploy(executor_request())
        self.assertEqual([call for call in runtime.calls if call[0] == "restore"],
                         [("restore", "dev", "blue")])
        self.assertEqual(store.saved[-1], state())
        self.assertEqual([event.event_type for event in sink.events][-2:],
                         ["traffic_switch_failed", "promotion_failed"])

    def test_post_switch_control_flow_is_preserved_after_compensation(self) -> None:
        class ControlSink(AuditSink):
            def append(self, event: AuditEvent) -> None:
                self.events.append(event)
                if event.event_type == "promotion_succeeded":
                    raise KeyboardInterrupt()

        runtime, store, sink = Runtime(), StateStore(), ControlSink()
        deployment, _, _, _, _ = operation(runtime=runtime, store=store, sink=sink)
        with self.assertRaises(KeyboardInterrupt):
            deployment.deploy(executor_request())
        self.assertEqual([call for call in runtime.calls if call[0] == "restore"],
                         [("restore", "dev", "blue")])
        self.assertEqual(store.saved[-1], state())
        self.assertEqual(sink.events[-1].event_type, "promotion_failed")

    def test_control_exception_after_switch_effect_restores_route_and_state(self) -> None:
        class InterruptingRuntime(Runtime):
            def switch_traffic(self, stage: str, slot: str) -> None:
                self._record("switch", stage, slot)
                raise KeyboardInterrupt()

        runtime, store, sink = InterruptingRuntime(), StateStore(), AuditSink()
        deployment, _, _, _, _ = operation(runtime=runtime, store=store, sink=sink)
        with self.assertRaises(KeyboardInterrupt):
            deployment.deploy(executor_request())
        self.assertEqual([call for call in runtime.calls if call[0] == "restore"],
                         [("restore", "dev", "blue")])
        self.assertEqual(store.saved[-1], state())
        self.assertEqual([event.event_type for event in sink.events][-2:],
                         ["traffic_switch_failed", "promotion_failed"])

    def test_restore_failure_or_hostile_return_is_one_attempt_and_redacted(self) -> None:
        class ReturningRestoreRuntime(Runtime):
            def restore_traffic(self, stage: str, previous_slot: str | None) -> None:
                self._record("restore", stage, previous_slot)
                return "restore-marker"  # type: ignore[return-value]

        for runtime in (Runtime(), ReturningRestoreRuntime()):
            if type(runtime) is Runtime:
                runtime.fail = "restore"
            sink = AuditSink(); sink.fail_type = "traffic_switch_succeeded"
            deployment, _, store, sink, _ = operation(runtime=runtime, sink=sink)
            with self.subTest(runtime=type(runtime).__name__), self.assertRaisesRegex(
                DeploymentOperationError,
                f"^{DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE}$",
            ) as caught:
                deployment.deploy(executor_request())
            self.assertNotIn("restore-marker", str(caught.exception))
            names = [call[0] for call in runtime.calls]
            self.assertEqual(names.count("switch"), 1)
            self.assertEqual(names.count("restore"), 1)
            self.assertEqual(names.count("migration"), 1)
            self.assertEqual(len(store.saved), 3)
            self.assertNotIn("promotion_succeeded", [event.event_type for event in sink.events])

    def test_original_state_recovery_save_failure_is_not_retried(self) -> None:
        runtime, store, sink = Runtime(), StateStore(), AuditSink()
        sink.fail_type = "traffic_switch_succeeded"
        store.fail_save = 4
        deployment, _, _, _, _ = operation(runtime=runtime, store=store, sink=sink)
        with self.assertRaisesRegex(
            DeploymentOperationError, f"^{DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE}$",
        ):
            deployment.deploy(executor_request())
        self.assertEqual([call for call in runtime.calls if call[0] == "restore"],
                         [("restore", "dev", "blue")])
        self.assertEqual(len(store.saved), 4)
        self.assertEqual(store.saved[-1], state())
        self.assertEqual([event.event_type for event in sink.events].count(
            "traffic_switch_succeeded"), 1)
        self.assertNotIn("promotion_succeeded", [event.event_type for event in sink.events])

    def test_clock_failure_non_string_and_invalid_timestamp_are_redacted(self) -> None:
        for value in (RuntimeError("clock-marker"), None, "not-a-timestamp"):
            class BadClock:
                def __call__(self) -> object:
                    if isinstance(value, BaseException):
                        raise value
                    return value
            deployment, runtime, store, sink, _ = operation(clock=BadClock())
            with self.subTest(value=value), self.assertRaisesRegex(
                DeploymentOperationError, f"^{DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE}$",
            ):
                deployment.deploy(executor_request())
            self.assertEqual((runtime.calls, store.saved), ([], []))

    def test_reentrant_deploy_is_rejected_without_redirecting_outer_execution(self) -> None:
        request = executor_request()
        holder: dict[str, DevDeploymentOperation] = {}

        class ReentrantStore(StateStore):
            def load(self) -> DeploymentState:
                with self.assertRaises(DeploymentOperationError):  # type: ignore[attr-defined]
                    holder["operation"].deploy(request)
                return self.initial

        store = ReentrantStore()
        store.assertRaises = self.assertRaises  # type: ignore[attr-defined]
        deployment, runtime, _, sink, _ = operation(store=store)
        holder["operation"] = deployment
        deployment.deploy(request)
        self.assertEqual([call[0] for call in runtime.calls].count("migration"), 1)
        self.assertEqual([event.event_type for event in sink.events].count("promotion_succeeded"), 1)

    def test_control_flow_exceptions_are_preserved(self) -> None:
        for exception in (KeyboardInterrupt(), SystemExit(7), GeneratorExit()):
            class ControlRuntime(Runtime):
                def pull_exact_image(self, image: str) -> None:
                    raise exception

            runtime = ControlRuntime()
            with self.subTest(exception=type(exception).__name__), self.assertRaises(type(exception)):
                operation(runtime=runtime)[0].deploy(executor_request())


class ScopeTests(unittest.TestCase):
    def test_module_contains_no_activation_or_listener_authority(self) -> None:
        path = Path(__file__).resolve().parents[1] / "deployment_operation.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = {
            node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, (ast.Attribute, ast.Name))
        }
        self.assertTrue({"bind", "listen", "accept", "Popen", "system"}.isdisjoint(calls))
        self.assertNotIn("/run/omnilyzer", source)
        self.assertNotIn("/var/lib/omnilyzer", source)
        self.assertNotIn("docker compose", source.lower())
        self.assertNotIn("0.14.2", source)
        self.assertNotIn("sha256:" + "1" * 64, source)


if __name__ == "__main__":
    unittest.main()
