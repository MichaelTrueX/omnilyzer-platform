"""deployment/dev_live_activation_policy.py - C33W repository-side DEV activation policy.

Purpose:
- authorize exactly one live DEV environment for the GitHub promotion workflow;
- bind that authorization to the already-qualified successor runtime and ingress
  references without changing the frozen host application source set;
- keep STAGING and PROD on the historical non-live controller path.

Links:
- deployment/dev-live-activation.json contains the reviewed DEV live authority.
- deployment/dev_live_activation_contract.py defines the later host service order.
- deployment/execution.py owns the immutable runtime/ingress reference schemas.
- .github/workflows/platform-promote.yml invokes this module only for DEV.

This module performs validation only. It does not start services, mutate host
state, access secrets, or perform deployment execution.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .execution import (
    DEV_LOOPBACK_ADDRESS,
    DEV_LOOPBACK_PORT,
    DEV_PUBLIC_ORIGIN,
    EXECUTION_SCHEMA_VERSION,
    INGRESS_PATHS,
    NO_SECRETS_REASON,
    RUNTIME_CONFIGURATION_PATH,
    ExecutorRequestError,
    IngressReference,
    NoSecretsReference,
    RuntimeConfigurationReference,
)
from .identity import DEV_REPOSITORY_ID
from .policy import (
    APPROVED_OCI_ORIGIN,
    DeploymentPolicyError,
    SCHEMA_VERSION,
    canonical_bytes,
    closed_object,
)
from .promotion import load_request


ENVIRONMENT_FIELDS = {
    "schema_version",
    "stage",
    "promotion_policy",
    "runtime",
    "activation",
}
PROMOTION_POLICY_FIELDS = {
    "required_prior_stage",
    "source_registry_origin",
    "approved_repositories",
    "github_environment",
    "production_approval_required",
}
RUNTIME_FIELDS = {
    "configuration_reference",
    "secrets_reference",
    "ingress_reference",
}
ACTIVATION_FIELDS = {"deployment_enabled", "verified_at"}

DEV_ACTIVATION_VERIFIED_AT = "2026-10-01T09:48:30Z"
DEV_RUNTIME_REVIEWED_COMMIT = "47a602d3f2b97fafd6fb8a18240fd5bbb3857ba9"
DEV_RUNTIME_CONFIGURATION_SHA256 = (
    "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f"
)
DEV_INGRESS_FILE_SHA256 = (
    "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
)


def expected_dev_runtime_references() -> dict[str, object]:
    """Return the exact C33W successor runtime reference set."""

    return {
        "configuration_reference": {
            "schema_version": EXECUTION_SCHEMA_VERSION,
            "kind": "repository-blob-sha256",
            "repository_id": DEV_REPOSITORY_ID,
            "reviewed_commit": DEV_RUNTIME_REVIEWED_COMMIT,
            "path": RUNTIME_CONFIGURATION_PATH,
            "sha256": DEV_RUNTIME_CONFIGURATION_SHA256,
        },
        "secrets_reference": {
            "schema_version": EXECUTION_SCHEMA_VERSION,
            "kind": "none",
            "required": [],
            "reason": NO_SECRETS_REASON,
        },
        "ingress_reference": {
            "schema_version": EXECUTION_SCHEMA_VERSION,
            "kind": "repository-file-set-sha256",
            "repository_id": DEV_REPOSITORY_ID,
            "reviewed_commit": DEV_RUNTIME_REVIEWED_COMMIT,
            "files": [
                {"path": path, "sha256": digest}
                for path, digest in zip(
                    INGRESS_PATHS,
                    DEV_INGRESS_FILE_SHA256,
                    strict=True,
                )
            ],
            "loopback_address": DEV_LOOPBACK_ADDRESS,
            "loopback_port": DEV_LOOPBACK_PORT,
            "public_origin": DEV_PUBLIC_ORIGIN,
        },
    }


def validate_live_dev_environment(value: Any) -> dict[str, Any]:
    """Validate one exact live DEV environment and no caller-selected authority."""

    data = closed_object(value, ENVIRONMENT_FIELDS, "deployment environment")
    if data["schema_version"] != SCHEMA_VERSION or data["stage"] != "dev":
        raise DeploymentPolicyError("C33W live activation authorizes only DEV")

    promotion = closed_object(
        data["promotion_policy"],
        PROMOTION_POLICY_FIELDS,
        "promotion policy",
    )
    if promotion != {
        "required_prior_stage": None,
        "source_registry_origin": APPROVED_OCI_ORIGIN,
        "approved_repositories": ["omnilyzer/task013-release-canary"],
        "github_environment": "task014-dev",
        "production_approval_required": False,
    }:
        raise DeploymentPolicyError(
            "DEV promotion policy differs from reviewed C33W authority"
        )

    runtime = closed_object(data["runtime"], RUNTIME_FIELDS, "runtime references")
    if runtime != expected_dev_runtime_references():
        raise DeploymentPolicyError(
            "DEV runtime references differ from reviewed successor authority"
        )
    try:
        RuntimeConfigurationReference.from_dict(runtime["configuration_reference"])
        NoSecretsReference.from_dict(runtime["secrets_reference"])
        IngressReference.from_dict(runtime["ingress_reference"])
    except ExecutorRequestError as exc:
        raise DeploymentPolicyError(
            "DEV runtime references are not valid executor authorities"
        ) from exc

    activation = closed_object(data["activation"], ACTIVATION_FIELDS, "activation")
    if activation != {
        "deployment_enabled": True,
        "verified_at": DEV_ACTIVATION_VERIFIED_AT,
    }:
        raise DeploymentPolicyError(
            "DEV live activation differs from reviewed C33W authority"
        )
    return data


def main() -> int:
    """Validate one DEV promotion request against the reviewed live authority."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--environment", required=True, type=Path)
    args = parser.parse_args()

    request = load_request(args.request)
    environment = validate_live_dev_environment(
        json.loads(args.environment.read_text(encoding="utf-8"))
    )
    if request.target_stage != "dev" or environment["stage"] != "dev":
        raise DeploymentPolicyError("C33W live activation authorizes only DEV")

    print(
        canonical_bytes(
            {
                "deployment_enabled": True,
                "request_sha256": request.sha256(),
                "stage": "dev",
                "status": "dev-live-authorized",
                "verified_at": DEV_ACTIVATION_VERIFIED_AT,
            }
        ).decode("ascii"),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
