"""Pure promotion, gate, state-transition, and rollback planning."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .audit import AuditEvent
from .policy import (
    APPROVED_OCI_REPOSITORIES,
    APPROVED_OCI_ORIGIN,
    SCHEMA_VERSION,
    STAGES,
    DeploymentPolicyError,
    canonical_bytes,
    closed_object,
    exact_image_reference,
    validate_digest,
    validate_stage,
)
from .promotion import PromotionRequest, load_request
from .state import DeploymentState, MigrationState


ENVIRONMENT_FIELDS = {"schema_version", "stage", "promotion_policy", "runtime", "activation"}
PROMOTION_POLICY_FIELDS = {
    "required_prior_stage", "source_registry_origin", "approved_repositories",
    "github_environment", "production_approval_required",
}
RUNTIME_FIELDS = {"configuration_reference", "secrets_reference", "ingress_reference"}
ACTIVATION_FIELDS = {"deployment_enabled", "verified_at"}
LIVENESS_PATH = "/livez"
READINESS_PATH = "/readyz"


@dataclass(frozen=True)
class GateResults:
    migration_succeeded: bool
    liveness_passed: bool
    readiness_passed: bool
    application_validation_passed: bool
    nginx_validation_passed: bool

    def all_passed(self) -> bool:
        return all(asdict(self).values())


@dataclass(frozen=True)
class DeploymentPlan:
    operation: str
    stage: str
    release_version: str
    source_sha: str
    exact_image_reference: str
    active_slot: str | None
    candidate_slot: str
    steps: tuple[str, ...]


PROMOTION_STEPS = (
    "retain_active_traffic", "start_exact_digest_in_inactive_slot",
    "acquire_serialized_migration_lock", "verify_migration_identity_and_checksum",
    "execute_migration", "check_liveness", "check_readiness",
    "validate_application", "validate_nginx_syntax", "switch_nginx_traffic",
    "persist_active_state_atomically", "retain_previous_digest_for_rollback",
)
ROLLBACK_STEPS = (
    "retain_active_traffic", "start_retained_previous_digest_in_inactive_slot",
    "check_liveness", "check_readiness_against_current_schema", "validate_application",
    "validate_nginx_syntax", "switch_nginx_traffic", "persist_active_state_atomically",
    "retain_replaced_digest_for_rollback",
)


def validate_environment(value: Any) -> dict[str, Any]:
    data = closed_object(value, ENVIRONMENT_FIELDS, "deployment environment")
    if data["schema_version"] != SCHEMA_VERSION:
        raise DeploymentPolicyError("unsupported deployment-environment schema_version")
    stage = validate_stage(data["stage"])
    promotion = closed_object(
        data["promotion_policy"], PROMOTION_POLICY_FIELDS, "promotion policy",
    )
    required = None if stage == "dev" else STAGES[STAGES.index(stage) - 1]
    if (promotion["required_prior_stage"] != required
            or promotion["source_registry_origin"] != APPROVED_OCI_ORIGIN
            or promotion["approved_repositories"] != ["omnilyzer/task013-release-canary"]
            or promotion["github_environment"] != f"task014-{stage}"
            or promotion["production_approval_required"] is not (stage == "prod")):
        raise DeploymentPolicyError("environment promotion policy differs from the reviewed stage model")
    runtime = closed_object(data["runtime"], RUNTIME_FIELDS, "runtime references")
    activation = closed_object(data["activation"], ACTIVATION_FIELDS, "activation")
    for key, value_ in runtime.items():
        if value_ is not None:
            raise DeploymentPolicyError(f"Phase 1 runtime reference {key} must remain unset")
    if activation != {"deployment_enabled": False, "verified_at": None}:
        raise DeploymentPolicyError("Phase 1 deployment activation must remain disabled and unverified")
    return data


def require_stage_order(request: PromotionRequest, events: list[AuditEvent]) -> None:
    index = STAGES.index(request.target_stage)
    if index == 0:
        return
    required_stage = STAGES[index - 1]
    matching = [
        event for event in events
        if event.event_type == "promotion_succeeded" and event.result == "succeeded"
        and event.stage == required_stage and event.release_version == request.release_version
        and event.source_sha == request.source_sha and event.oci_repository == request.oci_repository
        and event.digest == request.manifest_digest
    ]
    if len(matching) != 1:
        raise DeploymentPolicyError(
            f"{request.target_stage} promotion requires exactly one matching "
            f"{required_stage} success event"
        )


def prepare_candidate(
    state: DeploymentState,
    request: PromotionRequest,
    migration_identity: str,
    migration_checksum: str,
) -> DeploymentState:
    if state.stage != request.target_stage:
        raise DeploymentPolicyError("promotion request stage differs from deployment state")
    inactive = "green" if state.active_slot == "blue" else "blue"
    migration = MigrationState.from_dict({
        "status": "pending", "identity": migration_identity, "checksum": migration_checksum,
        "serialized_lock_required": True,
    })
    return replace(
        state,
        candidate_release=request.release_version,
        candidate_source_sha=request.source_sha,
        candidate_digest=request.manifest_digest,
        candidate_slot=inactive,
        migration_state=migration,
    )


def promotion_plan(state: DeploymentState, request: PromotionRequest) -> DeploymentPlan:
    if state.stage != request.target_stage:
        raise DeploymentPolicyError("promotion request stage differs from deployment state")
    candidate_slot = "green" if state.active_slot == "blue" else "blue"
    return DeploymentPlan(
        "promotion", state.stage, request.release_version, request.source_sha,
        request.exact_image_reference, state.active_slot, candidate_slot, PROMOTION_STEPS,
    )


def authorize_traffic_switch(state: DeploymentState, gates: GateResults) -> None:
    if state.candidate_digest is None or state.candidate_slot is None:
        raise DeploymentPolicyError("traffic switch requires a complete candidate")
    if state.migration_state.status != "succeeded" or not gates.all_passed():
        raise DeploymentPolicyError("traffic switch blocked by migration or validation gate")


def complete_promotion(
    state: DeploymentState, gates: GateResults, *, updated_at: str, event_id: str,
) -> DeploymentState:
    authorize_traffic_switch(state, gates)
    value = state.to_dict()
    value.update({
        "active_release": state.candidate_release,
        "active_source_sha": state.candidate_source_sha,
        "active_digest": state.candidate_digest,
        "active_slot": state.candidate_slot,
        "previous_release": state.active_release,
        "previous_source_sha": state.active_source_sha,
        "previous_digest": state.active_digest,
        "previous_slot": state.active_slot,
        "candidate_release": None,
        "candidate_source_sha": None,
        "candidate_digest": None,
        "candidate_slot": None,
        "updated_at": updated_at,
        "event_id": event_id,
    })
    return DeploymentState.from_dict(value)


def rollback_plan(state: DeploymentState) -> DeploymentPlan:
    if (state.previous_release is None or state.previous_source_sha is None
            or state.previous_digest is None or state.previous_slot is None):
        raise DeploymentPolicyError("rollback requires a complete retained previous release")
    validate_digest(state.previous_digest, "previous_digest")
    return DeploymentPlan(
        "rollback", state.stage, state.previous_release, state.previous_source_sha,
        exact_image_reference(APPROVED_OCI_REPOSITORIES[0], state.previous_digest),
        state.active_slot, state.previous_slot, ROLLBACK_STEPS,
    )


def complete_rollback(
    state: DeploymentState, gates: GateResults, *, updated_at: str, event_id: str,
) -> DeploymentState:
    if not gates.liveness_passed or not gates.readiness_passed:
        raise DeploymentPolicyError("rollback health validation failed")
    if not gates.application_validation_passed or not gates.nginx_validation_passed:
        raise DeploymentPolicyError("rollback application or Nginx validation failed")
    rollback_plan(state)
    value = state.to_dict()
    value.update({
        "active_release": state.previous_release,
        "active_source_sha": state.previous_source_sha,
        "active_digest": state.previous_digest,
        "active_slot": state.previous_slot,
        "previous_release": state.active_release,
        "previous_source_sha": state.active_source_sha,
        "previous_digest": state.active_digest,
        "previous_slot": state.active_slot,
        "candidate_release": None,
        "candidate_source_sha": None,
        "candidate_digest": None,
        "candidate_slot": None,
        "updated_at": updated_at,
        "event_id": event_id,
    })
    return DeploymentState.from_dict(value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--environment", required=True, type=Path)
    args = parser.parse_args()
    request = load_request(args.request)
    environment = validate_environment(json.loads(args.environment.read_text(encoding="utf-8")))
    if environment["stage"] != request.target_stage:
        raise DeploymentPolicyError("request target differs from selected environment")
    print(canonical_bytes({
        "deployment_enabled": False,
        "request_sha256": request.sha256(),
        "stage": request.target_stage,
        "status": "phase1-validation-only",
    }).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
