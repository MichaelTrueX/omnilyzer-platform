"""Inert composition of one audited Task 014 DEV deployment operation."""

from __future__ import annotations

import hashlib
import json
import threading
import types
from typing import Any, Callable

from .audit import AuditEvent, AuditExecutionIdentity
from .controller import (
    DeploymentPlan,
    GateResults,
    PROMOTION_STEPS,
    authorize_traffic_switch,
    complete_promotion,
    prepare_candidate,
    promotion_plan,
)
from .docker_runtime import MIGRATION_CHECKSUM, MIGRATION_IDENTITY
from .execution import (
    DEV_LOOPBACK_ADDRESS,
    DEV_LOOPBACK_PORT,
    DEV_PUBLIC_ORIGIN,
    DEV_OCI_REPOSITORY,
    INGRESS_PATHS,
    NO_SECRETS_REASON,
    RUNTIME_CONFIGURATION_PATH,
    ExecutorRequest,
    IngressFileReference,
    IngressReference,
    NoSecretsReference,
    RuntimeConfigurationReference,
)
from .identity import DEV_REPOSITORY_ID
from .policy import canonical_bytes, validate_sha256, validate_source_sha
from .promotion import PromotionRequest
from .state import DeploymentState, MigrationState


DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE = "DEV deployment operation is unavailable"


class DeploymentOperationError(Exception):
    """The closed DEV deployment did not complete trustworthily."""


def _make_gate() -> tuple[Callable[[object], bool], Callable[[object], None]]:
    active: set[int] = set()
    lock = threading.Lock()

    def enter(instance: object) -> bool:
        identity = id(instance)
        with lock:
            if identity in active:
                return False
            active.add(identity)
            return True

    def leave(instance: object) -> None:
        with lock:
            active.remove(id(instance))

    return enter, leave


_ENTER, _LEAVE = _make_gate()


def _ordinary_method(
    instance: object, name: str, *, positional: int,
    keyword_only: tuple[str, ...] = (),
) -> Callable[..., object]:
    if instance is None:
        raise TypeError("deployment operation configuration is invalid")
    try:
        hierarchy = type.__getattribute__(type(instance), "__mro__")
    except (AttributeError, TypeError):
        raise TypeError("deployment operation configuration is invalid") from None
    descriptor: object | None = None
    for base in hierarchy:
        namespace = type.__getattribute__(base, "__dict__")
        if name in namespace:
            descriptor = namespace[name]
            break
    if type(descriptor) is not types.FunctionType:
        raise TypeError("deployment operation configuration is invalid")
    code = descriptor.__code__
    if (
        code.co_posonlyargcount != 0
        or code.co_argcount != positional + 1
        or code.co_kwonlyargcount != len(keyword_only)
        or tuple(code.co_varnames[code.co_argcount:code.co_argcount + code.co_kwonlyargcount])
        != keyword_only
        or code.co_flags & (0x04 | 0x08 | 0x20 | 0x80 | 0x100 | 0x200)
        or descriptor.__defaults__ is not None
        or descriptor.__kwdefaults__ is not None
    ):
        raise TypeError("deployment operation configuration is invalid")
    return types.MethodType(descriptor, instance)


def _clock_function(clock: object) -> Callable[[], object]:
    if type(clock) is types.FunctionType:
        code = clock.__code__
        if (
            code.co_posonlyargcount != 0 or code.co_argcount != 0
            or code.co_kwonlyargcount != 0
            or code.co_flags & (0x04 | 0x08 | 0x20 | 0x80 | 0x100 | 0x200)
            or clock.__defaults__ is not None or clock.__kwdefaults__ is not None
        ):
            raise TypeError("deployment operation configuration is invalid")
        return clock
    return _ordinary_method(clock, "__call__", positional=0)  # type: ignore[return-value]


def _exact_text(value: object, validator: Callable[[Any], str]) -> str:
    if type(value) is not str:
        raise TypeError("deployment operation configuration is invalid")
    try:
        return validator(value)
    except Exception:
        raise TypeError("deployment operation configuration is invalid") from None


def _request_mapping(
    request: ExecutorRequest, *, request_type: type[ExecutorRequest] = ExecutorRequest,
    runtime_type: type[RuntimeConfigurationReference] = RuntimeConfigurationReference,
    secrets_type: type[NoSecretsReference] = NoSecretsReference,
    ingress_type: type[IngressReference] = IngressReference,
    ingress_file_type: type[IngressFileReference] = IngressFileReference,
) -> dict[str, Any]:
    if type(request) is not request_type:
        raise TypeError("invalid executor request")
    runtime = object.__getattribute__(request, "runtime_configuration_reference")
    secrets = object.__getattribute__(request, "secrets_reference")
    ingress = object.__getattribute__(request, "ingress_reference")
    if (
        type(runtime) is not runtime_type
        or type(secrets) is not secrets_type
        or type(ingress) is not ingress_type
        or type(object.__getattribute__(secrets, "required")) is not tuple
        or object.__getattribute__(secrets, "required") != ()
        or type(object.__getattribute__(ingress, "files")) is not tuple
    ):
        raise TypeError("invalid executor request graph")
    files: list[dict[str, object]] = []
    for item in object.__getattribute__(ingress, "files"):
        if type(item) is not ingress_file_type:
            raise TypeError("invalid executor request graph")
        path = object.__getattribute__(item, "path")
        digest = object.__getattribute__(item, "sha256")
        if type(path) is not str or type(digest) is not str:
            raise TypeError("invalid executor request graph")
        files.append({"path": path, "sha256": digest})
    scalar_names = (
        "schema_version", "operation", "stage", "release_version", "source_sha",
        "oci_origin", "oci_repository", "manifest_digest", "exact_image_reference",
        "release_manifest_sha256", "provenance_sha256", "originating_release_run_id",
        "promotion_request_sha256", "requested_by_actor_id", "github_repository_id",
        "github_workflow_ref", "github_workflow_sha", "github_run_id",
        "github_run_attempt", "oidc_jti", "oidc_issued_at", "oidc_expires_at",
    )
    mapping = {
        name: object.__getattribute__(request, name) for name in scalar_names
    }
    integer_names = {
        "schema_version", "originating_release_run_id", "requested_by_actor_id",
        "github_repository_id", "github_run_id", "github_run_attempt",
        "oidc_issued_at", "oidc_expires_at",
    }
    for name, value in mapping.items():
        expected = int if name in integer_names else str
        if type(value) is not expected:
            raise TypeError("invalid executor request graph")
    mapping["runtime_configuration_reference"] = {
        name: object.__getattribute__(runtime, name)
        for name in ("schema_version", "kind", "repository_id", "reviewed_commit", "path", "sha256")
    }
    for name, value in mapping["runtime_configuration_reference"].items():
        expected = int if name in {"schema_version", "repository_id"} else str
        if type(value) is not expected:
            raise TypeError("invalid executor request graph")
    mapping["secrets_reference"] = {
        "schema_version": object.__getattribute__(secrets, "schema_version"),
        "kind": object.__getattribute__(secrets, "kind"),
        "required": [],
        "reason": object.__getattribute__(secrets, "reason"),
    }
    for name in ("schema_version", "kind", "reason"):
        expected = int if name == "schema_version" else str
        if type(mapping["secrets_reference"][name]) is not expected:
            raise TypeError("invalid executor request graph")
    mapping["ingress_reference"] = {
        name: object.__getattribute__(ingress, name)
        for name in (
            "schema_version", "kind", "repository_id", "reviewed_commit",
            "loopback_address", "loopback_port", "public_origin",
        )
    }
    for name, value in mapping["ingress_reference"].items():
        expected = int if name in {"schema_version", "repository_id", "loopback_port"} else str
        if type(value) is not expected:
            raise TypeError("invalid executor request graph")
    mapping["ingress_reference"]["files"] = files
    return mapping


def _snapshot_request(
    request: ExecutorRequest, *, mapping: Callable[..., dict[str, Any]] = _request_mapping,
    parser: Callable[[Any], ExecutorRequest] = ExecutorRequest.from_dict,
    loads: Callable[[str | bytes], Any] = json.loads,
    canonicalizer: Callable[[Any], bytes] = canonical_bytes,
) -> ExecutorRequest:
    first = mapping(request)
    snapshot = parser(loads(canonicalizer(first)))
    second = mapping(request)
    if (
        canonicalizer(first) != canonicalizer(second)
        or canonicalizer(mapping(snapshot)) != canonicalizer(first)
    ):
        raise TypeError("executor request changed during validation")
    return snapshot


def _state_mapping(
    state: DeploymentState, *, state_type: type[DeploymentState] = DeploymentState,
    migration_type: type[MigrationState] = MigrationState,
) -> dict[str, object]:
    if type(state) is not state_type:
        raise TypeError("invalid deployment state")
    migration = object.__getattribute__(state, "migration_state")
    if type(migration) is not migration_type:
        raise TypeError("invalid deployment state")
    names = (
        "schema_version", "stage", "active_release", "active_source_sha",
        "active_digest", "active_slot", "previous_release", "previous_source_sha",
        "previous_digest", "previous_slot", "candidate_release",
        "candidate_source_sha", "candidate_digest", "candidate_slot", "updated_at",
        "event_id",
    )
    value: dict[str, object] = {
        name: object.__getattribute__(state, name) for name in names
    }
    if type(value["schema_version"]) is not int:
        raise TypeError("invalid deployment state")
    for name in names:
        if name == "schema_version":
            continue
        if value[name] is not None and type(value[name]) is not str:
            raise TypeError("invalid deployment state")
    value["migration_state"] = {
        name: object.__getattribute__(migration, name)
        for name in ("status", "identity", "checksum", "serialized_lock_required")
    }
    migration_value = value["migration_state"]
    assert isinstance(migration_value, dict)
    for name in ("status", "identity", "checksum"):
        if migration_value[name] is not None and type(migration_value[name]) is not str:
            raise TypeError("invalid deployment state")
    if migration_value["serialized_lock_required"] is not True:
        raise TypeError("invalid deployment state")
    return value


def _snapshot_state(
    state: DeploymentState, *, fresh: bool = False,
    mapping: Callable[..., dict[str, object]] = _state_mapping,
    parser: Callable[[Any], DeploymentState] = DeploymentState.from_dict,
    loads: Callable[[str | bytes], Any] = json.loads,
    canonicalizer: Callable[[Any], bytes] = canonical_bytes,
) -> DeploymentState:
    first = mapping(state)
    snapshot = parser(loads(canonicalizer(first)))
    if (
        canonicalizer(first) != canonicalizer(mapping(state))
        or canonicalizer(mapping(snapshot)) != canonicalizer(first)
    ):
        raise TypeError("deployment state changed during validation")
    if snapshot.stage != "dev":
        raise TypeError("deployment state stage is invalid")
    if fresh:
        if any(
            value is not None
            for value in (
                snapshot.candidate_release, snapshot.candidate_source_sha,
                snapshot.candidate_digest, snapshot.candidate_slot,
            )
        ):
            raise TypeError("deployment state already has a candidate")
        if snapshot.migration_state.status not in ("none", "succeeded"):
            raise TypeError("deployment state cannot begin a promotion")
        if snapshot.active_slot is None and snapshot.previous_slot is not None:
            raise TypeError("inactive deployment state retains an unsafe previous route")
    return snapshot


def _updated_state(
    state: DeploymentState, *, migration_status: str | None = None,
    updated_at: str, event_id: str,
    mapping: Callable[..., dict[str, object]] = _state_mapping,
    parser: Callable[[Any], DeploymentState] = DeploymentState.from_dict,
) -> DeploymentState:
    value = mapping(state)
    if migration_status is not None:
        migration = dict(value["migration_state"])  # type: ignore[arg-type]
        migration["status"] = migration_status
        value["migration_state"] = migration
    value["updated_at"] = updated_at
    value["event_id"] = event_id
    updated = parser(value)
    if mapping(updated) != value:
        raise TypeError("deployment state update changed during validation")
    return updated


def _promotion_request(
    request: ExecutorRequest,
    parser: Callable[[Any], PromotionRequest] = PromotionRequest.from_dict,
) -> PromotionRequest:
    return parser({
        "schema_version": 1,
        "release_version": request.release_version,
        "source_sha": request.source_sha,
        "oci_repository": request.oci_repository,
        "manifest_digest": request.manifest_digest,
        "exact_image_reference": request.exact_image_reference,
        "release_manifest_sha256": request.release_manifest_sha256,
        "provenance_sha256": request.provenance_sha256,
        "originating_release_run_id": request.originating_release_run_id,
        "target_stage": request.stage,
        "requested_by": f"github:{request.requested_by_actor_id}",
    })


def _validated_plan(
    value: object, state: DeploymentState, request: PromotionRequest, *,
    plan_type: type[DeploymentPlan] = DeploymentPlan,
    required_steps: tuple[str, ...] = PROMOTION_STEPS,
) -> DeploymentPlan:
    candidate_slot = "green" if state.active_slot == "blue" else "blue"
    if (
        type(value) is not plan_type
        or type(value.operation) is not str or value.operation != "promotion"
        or type(value.stage) is not str or value.stage != "dev"
        or type(value.release_version) is not str
        or value.release_version != request.release_version
        or type(value.source_sha) is not str or value.source_sha != request.source_sha
        or type(value.exact_image_reference) is not str
        or value.exact_image_reference != request.exact_image_reference
        or (value.active_slot is not None and type(value.active_slot) is not str)
        or value.active_slot != state.active_slot
        or type(value.candidate_slot) is not str
        or value.candidate_slot != candidate_slot
        or type(value.steps) is not tuple or value.steps != required_steps
        or not all(type(step) is str for step in value.steps)
    ):
        raise TypeError("invalid deployment plan")
    return value


def _copy_plan(
    plan: DeploymentPlan, plan_type: type[DeploymentPlan] = DeploymentPlan,
) -> DeploymentPlan:
    return plan_type(
        plan.operation, plan.stage, plan.release_version, plan.source_sha,
        plan.exact_image_reference, plan.active_slot, plan.candidate_slot,
        plan.steps,
    )


def _validated_prepared_state(
    value: object, original: DeploymentState, request: ExecutorRequest,
    snapshotter: Callable[..., DeploymentState] = _snapshot_state,
    mapping: Callable[..., dict[str, object]] = _state_mapping,
    migration_identity: str = MIGRATION_IDENTITY,
    migration_checksum: str = MIGRATION_CHECKSUM,
) -> DeploymentState:
    prepared = snapshotter(value)  # type: ignore[arg-type]
    expected = mapping(original)
    expected.update({
        "candidate_release": request.release_version,
        "candidate_source_sha": request.source_sha,
        "candidate_digest": request.manifest_digest,
        "candidate_slot": "green" if original.active_slot == "blue" else "blue",
        "migration_state": {
            "status": "pending", "identity": migration_identity,
            "checksum": migration_checksum, "serialized_lock_required": True,
        },
    })
    if mapping(prepared) != expected:
        raise TypeError("prepared deployment state differs from the reviewed transition")
    return prepared


def _validated_completed_state(
    value: object, succeeded: DeploymentState, *, updated_at: str, event_id: str,
    snapshotter: Callable[..., DeploymentState] = _snapshot_state,
    mapping: Callable[..., dict[str, object]] = _state_mapping,
) -> DeploymentState:
    completed = snapshotter(value)  # type: ignore[arg-type]
    expected = mapping(succeeded)
    expected.update({
        "active_release": succeeded.candidate_release,
        "active_source_sha": succeeded.candidate_source_sha,
        "active_digest": succeeded.candidate_digest,
        "active_slot": succeeded.candidate_slot,
        "previous_release": succeeded.active_release,
        "previous_source_sha": succeeded.active_source_sha,
        "previous_digest": succeeded.active_digest,
        "previous_slot": succeeded.active_slot,
        "candidate_release": None, "candidate_source_sha": None,
        "candidate_digest": None, "candidate_slot": None,
        "updated_at": updated_at, "event_id": event_id,
    })
    if mapping(completed) != expected:
        raise TypeError("completed deployment state differs from the reviewed transition")
    return completed


def _event_fingerprint(
    event: AuditEvent, *, event_type: type[AuditEvent] = AuditEvent,
    identity_type: type[AuditExecutionIdentity] = AuditExecutionIdentity,
) -> tuple[object, ...]:
    if type(event) is not event_type:
        raise TypeError("invalid audit event")
    identity = object.__getattribute__(event, "execution_identity")
    if type(identity) is not identity_type:
        raise TypeError("invalid audit event")
    event_names = (
        "schema_version", "event_id", "event_type", "stage", "release_version",
        "source_sha", "oci_repository", "digest", "previous_digest",
        "active_slot", "candidate_slot", "migration_identity", "result", "timestamp",
    )
    identity_names = (
        "schema_version", "requested_by_actor_id", "github_repository_id",
        "github_workflow_ref", "github_workflow_sha", "github_run_id",
        "github_run_attempt", "oidc_jti", "oidc_issued_at", "oidc_expires_at",
        "promotion_request_sha256", "executor_request_sha256",
    )
    return tuple(object.__getattribute__(event, name) for name in event_names) + tuple(
        object.__getattribute__(identity, name) for name in identity_names
    )


class DevDeploymentOperation:
    """Compose one closed, request-bound, audited DEV promotion."""

    __slots__ = ("_configuration",)

    def __init__(
        self, *, runtime: object, state_store: object, audit_sink: object,
        clock: object, reviewed_commit: str, runtime_configuration_sha256: str,
        ingress_file_sha256: tuple[str, str, str],
    ) -> None:
        runtime_methods = (
            _ordinary_method(runtime, "pull_exact_image", positional=1),
            _ordinary_method(runtime, "verify_local_repo_digest", positional=1),
            _ordinary_method(runtime, "start_candidate", positional=1),
            _ordinary_method(
                runtime, "execute_migration", positional=0,
                keyword_only=("stage", "exact_image_reference", "identity", "checksum"),
            ),
            _ordinary_method(runtime, "check_liveness", positional=2),
            _ordinary_method(runtime, "check_readiness", positional=2),
            _ordinary_method(runtime, "validate_application", positional=1),
            _ordinary_method(runtime, "validate_nginx", positional=1),
            _ordinary_method(runtime, "switch_traffic", positional=2),
            _ordinary_method(runtime, "restore_traffic", positional=2),
        )
        store_methods = (
            _ordinary_method(state_store, "load", positional=0),
            _ordinary_method(state_store, "save", positional=1),
        )
        append = _ordinary_method(audit_sink, "append", positional=1)
        captured_clock = _clock_function(clock)
        commit = _exact_text(reviewed_commit, validate_source_sha)
        runtime_hash = _exact_text(
            runtime_configuration_sha256,
            lambda value: validate_sha256(value, "runtime_configuration_sha256"),
        )
        if type(ingress_file_sha256) is not tuple or len(ingress_file_sha256) != len(INGRESS_PATHS):
            raise TypeError("deployment operation configuration is invalid")
        ingress_hashes = tuple(
            _exact_text(value, lambda item: validate_sha256(item, "ingress sha256"))
            for value in ingress_file_sha256
        )
        object.__setattr__(self, "_configuration", (
            runtime_methods, store_methods, append, captured_clock, commit,
            runtime_hash, ingress_hashes, AuditEvent.for_executor_request,
            AuditEvent.require_executor_request, AuditEvent,
            _snapshot_request, _snapshot_state, _updated_state,
            _promotion_request, _validated_plan, _copy_plan,
            _validated_prepared_state, _validated_completed_state,
            _event_fingerprint,
            promotion_plan, prepare_candidate,
            authorize_traffic_switch, complete_promotion,
            GateResults(True, True, True, True, True),
            MIGRATION_IDENTITY, MIGRATION_CHECKSUM,
            _ENTER, _LEAVE,
        ))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("deployment operation configuration is immutable")

    def deploy(self, request: ExecutorRequest) -> None:
        (
            runtime_methods, store_methods, append, clock, reviewed_commit,
            runtime_hash, ingress_hashes, event_factory, require_request,
            audit_event_type, snapshot_request, snapshot_state, updated_state,
            promotion_request, validate_plan, copy_plan, validate_prepared,
            validate_completed, event_fingerprint, make_plan, prepare, authorize_switch,
            finish_promotion, passing_gates,
            migration_identity_value, migration_checksum_value,
            enter, leave,
        ) = object.__getattribute__(self, "_configuration")
        if not enter(self):
            raise DeploymentOperationError(DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE)
        started = False
        switch_attempted = False
        original_state: DeploymentState | None = None
        prepared: DeploymentState | None = None
        snapshot: ExecutorRequest | None = None
        failure_event: str | None = None
        save_state: Callable[[object], object] | None = None
        restore_route: Callable[..., object] | None = None
        emit_event: Callable[..., tuple[AuditEvent, str, str]] | None = None

        def recover() -> None:
            if (
                not started or snapshot is None or original_state is None
                or prepared is None or emit_event is None
            ):
                return
            if switch_attempted and restore_route is not None and save_state is not None:
                try:
                    if restore_route("dev", original_state.active_slot) is not None:
                        raise TypeError("invalid runtime restoration result")
                    if save_state(snapshot_state(original_state)) is not None:
                        raise TypeError("invalid state restoration result")
                except BaseException:
                    pass
            if failure_event is not None:
                try:
                    emit_event(
                        failure_event.replace("_", "-"), failure_event, "failed",
                        migration_identity=(
                            migration_identity_value
                            if failure_event == "migration_failed" else None
                        ),
                    )
                except BaseException:
                    pass
            try:
                emit_event("promotion-failed", "promotion_failed", "failed")
            except BaseException:
                pass

        try:
            snapshot = snapshot_request(request)
            runtime_reference = snapshot.runtime_configuration_reference
            ingress_reference = snapshot.ingress_reference
            if (
                runtime_reference.repository_id != DEV_REPOSITORY_ID
                or runtime_reference.reviewed_commit != reviewed_commit
                or runtime_reference.path != RUNTIME_CONFIGURATION_PATH
                or runtime_reference.sha256 != runtime_hash
                or ingress_reference.repository_id != DEV_REPOSITORY_ID
                or ingress_reference.reviewed_commit != reviewed_commit
                or tuple(item.path for item in ingress_reference.files) != INGRESS_PATHS
                or tuple(item.sha256 for item in ingress_reference.files) != ingress_hashes
                or ingress_reference.loopback_address != DEV_LOOPBACK_ADDRESS
                or ingress_reference.loopback_port != DEV_LOOPBACK_PORT
                or ingress_reference.public_origin != DEV_PUBLIC_ORIGIN
                or snapshot.secrets_reference.reason != NO_SECRETS_REASON
                or snapshot.oci_repository != DEV_OCI_REPOSITORY
            ):
                raise TypeError("executor request assets are not reviewed")
            request_hash = hashlib.sha256(
                canonical_bytes(_request_mapping(snapshot)),
            ).hexdigest()

            load, save = store_methods
            save_state = save
            original_state = snapshot_state(load(), fresh=True)
            same_active_identity = (
                original_state.active_release is not None
                and original_state.active_source_sha is not None
                and original_state.active_digest is not None
                and str.__eq__(
                    original_state.active_release, snapshot.release_version,
                )
                and str.__eq__(
                    original_state.active_source_sha, snapshot.source_sha,
                )
                and str.__eq__(
                    original_state.active_digest, snapshot.manifest_digest,
                )
            )
            same_active_digest = (
                original_state.active_digest is not None
                and str.__eq__(
                    original_state.active_digest, snapshot.manifest_digest,
                )
            )
            active_version_conflict = (
                original_state.active_release is not None
                and str.__eq__(
                    original_state.active_release, snapshot.release_version,
                )
                and original_state.active_digest is not None
                and not str.__eq__(
                    original_state.active_digest, snapshot.manifest_digest,
                )
            )
            if same_active_identity or same_active_digest or active_version_conflict:
                raise TypeError("requested deployment identity is already active or conflicting")
            promotion = promotion_request(snapshot)
            plan = validate_plan(
                make_plan(original_state, promotion), original_state, promotion,
            )
            start_plan = validate_plan(
                copy_plan(plan), original_state, promotion,
            )
            application_plan = validate_plan(
                copy_plan(plan), original_state, promotion,
            )
            prepared = validate_prepared(
                prepare(
                    original_state, promotion, migration_identity_value,
                    migration_checksum_value,
                ),
                original_state, snapshot,
            )
            def make_event(
                step: str, event_type: str, result: str, *,
                migration_identity: str | None = None,
                success: bool = False,
            ) -> AuditEvent:
                timestamp = clock()
                if type(timestamp) is not str:
                    raise TypeError("invalid audit clock")
                event_id = f"c8:{request_hash}:{step}"
                active_slot = (
                    prepared.candidate_slot if success else original_state.active_slot
                )
                candidate_slot = None if success else prepared.candidate_slot
                event = event_factory(
                    snapshot,
                    event_id=event_id,
                    event_type=event_type,
                    previous_digest=original_state.active_digest,
                    active_slot=active_slot,
                    candidate_slot=candidate_slot,
                    migration_identity=migration_identity,
                    result=result,
                    timestamp=timestamp,
                )
                if type(event) is not audit_event_type:
                    raise TypeError("invalid audit event")
                if event_fingerprint(event) != (
                    2, event_id, event_type, snapshot.stage,
                    snapshot.release_version, snapshot.source_sha,
                    snapshot.oci_repository, snapshot.manifest_digest,
                    original_state.active_digest, active_slot, candidate_slot,
                    migration_identity, result, timestamp,
                    1, snapshot.requested_by_actor_id,
                    snapshot.github_repository_id, snapshot.github_workflow_ref,
                    snapshot.github_workflow_sha, snapshot.github_run_id,
                    snapshot.github_run_attempt, snapshot.oidc_jti,
                    snapshot.oidc_issued_at, snapshot.oidc_expires_at,
                    snapshot.promotion_request_sha256, request_hash,
                ):
                    raise TypeError("audit event differs from the closed operation step")
                require_request(event, snapshot)
                return event

            def append_event(event: AuditEvent) -> tuple[AuditEvent, str, str]:
                before = event_fingerprint(event)
                event_id = before[1]
                timestamp = before[13]
                if type(event_id) is not str or type(timestamp) is not str:
                    raise TypeError("invalid audit event identity")
                append_result = append(event)
                if append_result is not None:
                    raise TypeError("invalid audit append result")
                if event_fingerprint(event) != before:
                    raise TypeError("audit event changed during append")
                require_request(event, snapshot)
                return event, event_id, timestamp

            def emit(
                step: str, event_type: str, result: str, *,
                migration_identity: str | None = None,
                success: bool = False,
            ) -> tuple[AuditEvent, str, str]:
                return append_event(make_event(
                    step, event_type, result,
                    migration_identity=migration_identity, success=success,
                ))

            emit_event = emit

            started_event = make_event(
                "promotion-started", "promotion_started", "started",
            )
            started = True
            _, started_event_id, started_timestamp = append_event(started_event)
            prepared = updated_state(
                prepared, updated_at=started_timestamp,
                event_id=started_event_id,
            )
            if save(snapshot_state(prepared)) is not None:
                raise TypeError("invalid state save result")

            (
                pull_exact_image, verify_local_repo_digest, start_candidate,
                execute_migration, check_liveness, check_readiness,
                validate_application, validate_nginx, switch_traffic,
                restore_traffic,
            ) = runtime_methods
            restore_route = restore_traffic
            if pull_exact_image(snapshot.exact_image_reference) is not None:
                raise TypeError("invalid runtime result")
            if verify_local_repo_digest(snapshot.exact_image_reference) is not None:
                raise TypeError("invalid runtime result")
            if start_candidate(start_plan) is not None:
                raise TypeError("invalid runtime result")

            _, migration_started_id, migration_started_timestamp = emit(
                "migration-started", "migration_started", "started",
                migration_identity=migration_identity_value,
            )
            running = updated_state(
                prepared, migration_status="running",
                updated_at=migration_started_timestamp,
                event_id=migration_started_id,
            )
            if save(snapshot_state(running)) is not None:
                raise TypeError("invalid state save result")
            try:
                migration_result = execute_migration(
                    stage="dev", exact_image_reference=snapshot.exact_image_reference,
                    identity=migration_identity_value,
                    checksum=migration_checksum_value,
                )
                if migration_result is not None:
                    raise TypeError("invalid runtime result")
            except Exception:
                failure_event = "migration_failed"
                raise
            migration_succeeded = make_event(
                "migration-succeeded", "migration_succeeded", "succeeded",
                migration_identity=migration_identity_value,
            )
            migration_fingerprint = event_fingerprint(migration_succeeded)
            migration_succeeded_id = migration_fingerprint[1]
            migration_succeeded_timestamp = migration_fingerprint[13]
            if (
                type(migration_succeeded_id) is not str
                or type(migration_succeeded_timestamp) is not str
            ):
                raise TypeError("invalid audit event identity")
            succeeded = updated_state(
                running, migration_status="succeeded",
                updated_at=migration_succeeded_timestamp,
                event_id=migration_succeeded_id,
            )
            if save(snapshot_state(succeeded)) is not None:
                raise TypeError("invalid state save result")
            append_event(migration_succeeded)

            try:
                liveness = check_liveness("dev", prepared.candidate_slot)
            except Exception:
                failure_event = "liveness_failed"
                raise
            if liveness is not True:
                failure_event = "liveness_failed"
                raise TypeError("liveness failed")
            failure_event = None
            emit("liveness-passed", "liveness_passed", "succeeded")
            try:
                readiness = check_readiness("dev", prepared.candidate_slot)
            except Exception:
                failure_event = "readiness_failed"
                raise
            if readiness is not True:
                failure_event = "readiness_failed"
                raise TypeError("readiness failed")
            failure_event = None
            emit("readiness-passed", "readiness_passed", "succeeded")
            if validate_application(application_plan) is not True:
                raise TypeError("application validation failed")
            if validate_nginx("dev") is not True:
                raise TypeError("Nginx validation failed")
            authorize_switch(succeeded, passing_gates)
            emit("traffic-switch-started", "traffic_switch_started", "started")
            failure_event = "traffic_switch_failed"
            switch_attempted = True
            try:
                switch_result = switch_traffic("dev", prepared.candidate_slot)
                if switch_result is not None:
                    raise TypeError("invalid runtime result")
            except Exception:
                raise
            failure_event = None
            emit(
                "traffic-switch-succeeded", "traffic_switch_succeeded", "succeeded",
                success=True,
            )
            promotion_success = make_event(
                "promotion-succeeded", "promotion_succeeded", "succeeded",
                success=True,
            )
            promotion_fingerprint = event_fingerprint(promotion_success)
            promotion_success_id = promotion_fingerprint[1]
            promotion_success_timestamp = promotion_fingerprint[13]
            if (
                type(promotion_success_id) is not str
                or type(promotion_success_timestamp) is not str
            ):
                raise TypeError("invalid audit event identity")
            completed = validate_completed(
                finish_promotion(
                    succeeded, passing_gates,
                    updated_at=promotion_success_timestamp,
                    event_id=promotion_success_id,
                ),
                succeeded, updated_at=promotion_success_timestamp,
                event_id=promotion_success_id,
            )
            if save(snapshot_state(completed)) is not None:
                raise TypeError("invalid state save result")
            append_event(promotion_success)
            return None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            recover()
            raise
        except Exception:
            recover()
            raise DeploymentOperationError(
                DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE,
            ) from None
        finally:
            leave(self)


__all__ = (
    "DEPLOYMENT_OPERATION_UNAVAILABLE_MESSAGE",
    "DeploymentOperationError",
    "DevDeploymentOperation",
)
