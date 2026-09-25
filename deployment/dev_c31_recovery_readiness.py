"""Read-only operator preflight for the pinned C31 step-20 recovery generation."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

from . import application_manifest as c26
from . import dev_host_provisioning_orchestration as c31
from . import dev_host_qualification as c29
from . import dev_post_provision_qualification as post
from . import dev_step20_recovery as recovery
from . import executor_service_config as c17
from . import installation_integrity_contract as c24
from . import pip_installer_qualification as pipq
from . import wheelhouse_qualification as c28


def readiness(*, wheelhouse_path: str, pip_installer_staging: str) -> dict[str, object]:
    """Produce bounded facts; never construct or invoke a C31 mutation object."""
    root = str(Path(__file__).resolve().parents[1])
    commit_raw = c26._output(root, ("rev-parse", "--verify", "HEAD^{commit}"), 41)
    if len(commit_raw) != 41 or not commit_raw.endswith(b"\n"):
        raise OSError
    commit = commit_raw[:-1].decode("ascii")
    current_raw = c29._read_small_regular(
        c31._CONFIG_PATH, c17.MAX_EXECUTOR_SERVICE_CONFIG_BYTES,
    )
    installed = c17.parse_canonical_executor_service_configuration(current_raw)
    configuration = replace(installed, reviewed_commit=commit)
    recovery.verify_current_c17(configuration)
    manifest = c26.generate_dev_application_manifest(repository_root=root, reviewed_commit=commit)
    integrity = c24.DevInstallationIntegrityContract(configuration=configuration)
    wheels = c28.qualify_dev_wheelhouse(
        wheelhouse_path=wheelhouse_path, integrity_contract=integrity,
    )
    installer = pipq.qualify_dev_pip_installer(staging_directory=pip_installer_staging)
    # Same pure C31A evidence binding that an eventual separately authorized C31 uses.
    from . import dev_host_provisioning_plan as plan
    plan.build_dev_host_provisioning_plan(
        configuration=configuration, application_manifest=manifest,
        wheelhouse_evidence=wheels, pip_installer_evidence=installer,
    )
    dev_blob = c26._output(root, ("cat-file", "blob", commit + ":deployment/environments/dev.json"), 8192)
    dev = json.loads(dev_blob)
    if (type(dev) is not dict or type(dev.get("activation")) is not dict
        or dev["activation"].get("deployment_enabled") is not False):
        raise OSError
    observed = c31._qualify_step20_recovery(configuration, manifest, wheels, root)
    c31._Step20RecoveryPreflight.__post_init__(observed)
    try:
        converged = post.qualify_dev_provisioned_host(
            configuration=configuration, application_manifest=manifest,
        )
    except post.PostProvisionQualificationError:
        converged = None
    if converged is not None:
        if (observed.c17_state != "current"
            or observed.application.replaced_count != len(recovery.CHANGED)
            or observed.application.stage_length is not None
            or observed.replay_directory != "current"
            or observed.replay_state != "initialized"):
            raise OSError
        return {
            "reviewed_commit": commit, "predecessor": recovery.PREDECESSOR,
            "c17_state": "current", "application_migration_state": "current",
            "replay_directory_mode_state": "current", "deployment_state": "initial",
            "replay_state": "initialized", "audit_state": "pristine",
            "python_manifest": observed.python.payload_manifest_sha256,
            "c26_sha256": hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
            "c31_eligible_for_separate_authorization": False,
            "already_converged": True,
        }
    return {
        "reviewed_commit": commit, "predecessor": recovery.PREDECESSOR,
        "c17_state": observed.c17_state,
        "application_migration_state": (
            "current" if observed.application.replaced_count == len(recovery.CHANGED)
            else "prefix-" + str(observed.application.replaced_count)
        ) + ("-staged" if observed.application.stage_length is not None else ""),
        "replay_directory_mode_state": observed.replay_directory,
        "deployment_state": "initial", "replay_state": observed.replay_state,
        "audit_state": "pristine",
        "python_manifest": observed.python.payload_manifest_sha256,
        "c26_sha256": hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
        "c31_eligible_for_separate_authorization": True,
        "already_converged": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only C31 step-20 recovery readiness")
    parser.add_argument("--wheelhouse-path", required=True)
    parser.add_argument("--pip-installer-staging", required=True)
    arguments = parser.parse_args(argv)
    try:
        result = readiness(wheelhouse_path=arguments.wheelhouse_path,
                           pip_installer_staging=arguments.pip_installer_staging)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        print('{"c31_eligible_for_separate_authorization":false,"status":"unavailable"}')
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
