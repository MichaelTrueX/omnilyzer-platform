"""deployment/tests/test_rootless_docker_staged_preinstall_qualification.py.

Purpose:
- prove C32ZV binds the exact C32ZS bundle to an unchanged C32ZQ host boundary;
- reject interrupted incoming staging, host/bundle drift, forged evidence, and
  any mutation or network surface.

Linked file:
- deployment/rootless_docker_staged_preinstall_qualification.py
"""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment import rootless_docker_staged_preinstall_qualification as module
from deployment.rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from deployment.rootless_docker_package_bundle_qualification import (
    PackageBundleFileEvidence,
    RootlessDockerPackageBundleEvidence,
)
from deployment.rootless_docker_preinstall_qualification import (
    RootlessDockerPreinstallEvidence,
)
from deployment.successor_application_generation import TARGET_REVIEWED_COMMIT


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40


def host_evidence(*, workflow: str = WORKFLOW) -> RootlessDockerPreinstallEvidence:
    """Return one canonical synthetic clean-host observation."""

    return RootlessDockerPreinstallEvidence(
        application_reviewed_commit=TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=workflow,
        executor_uid=991,
        executor_gid=991,
        supplementary_gids=(992,),
        subuid_start=493216,
        subgid_start=493216,
        subordinate_count=65536,
        direct_packages=tuple(
            item.name for item in INSTALLATION_AUTHORITY.packages
        ),
        supplemental_packages=tuple(
            item.name for item in INSTALLATION_AUTHORITY.supplemental_packages
        ),
        host_dependencies=tuple(
            (item.package, "9.9-test", item.architecture)
            for item in INSTALLATION_AUTHORITY.host_dependencies
        ),
        cgroup_controllers=("cpu", "io", "memory", "pids"),
    )


def bundle_evidence(*, directory_inode: int = 99) -> RootlessDockerPackageBundleEvidence:
    """Return one canonical synthetic exact-bundle observation."""

    files = tuple(
        PackageBundleFileEvidence(
            item.package,
            item.filename,
            item.size,
            item.sha256,
            (
                0o100600,
                index + 1,
                10,
                1,
                0,
                0,
                item.size,
                100 + index,
                200 + index,
            ),
        )
        for index, item in enumerate(INSTALLATION_AUTHORITY.payloads)
    )
    return RootlessDockerPackageBundleEvidence(
        INSTALLATION_AUTHORITY.staging_directory,
        "sha256",
        INSTALLATION_AUTHORITY.bundle_size(),
        (0o40700, directory_inode, 10, 2, 0, 0, 0, 300, 400),
        files,
    )


class RootlessDockerStagedPreinstallQualificationTests(unittest.TestCase):
    """Adversarial tests for the C32ZV root-only read boundary."""

    def test_evidence_is_exact_type_bound_and_immutable(self) -> None:
        host = host_evidence()
        bundle = bundle_evidence()
        value = module.RootlessDockerStagedPreinstallEvidence(host, bundle)
        with self.assertRaises(FrozenInstanceError):
            value.host = host_evidence(workflow="b" * 40)
        with self.assertRaises(ValueError):
            module.RootlessDockerStagedPreinstallEvidence(
                SimpleNamespace(),
                bundle,
            )
        with self.assertRaises(ValueError):
            module.RootlessDockerStagedPreinstallEvidence(
                host,
                SimpleNamespace(staging_directory=bundle.staging_directory),
            )

    def test_incoming_object_is_always_rejected(self) -> None:
        with patch.object(
            module.os,
            "lstat",
            return_value=SimpleNamespace(),
        ), self.assertRaises(OSError):
            module._require_incoming_absent()

        with patch.object(
            module.os,
            "lstat",
            side_effect=FileNotFoundError,
        ):
            module._require_incoming_absent()

    def test_one_observation_binds_bundle_between_two_identical_host_checks(self) -> None:
        host = host_evidence()
        bundle = bundle_evidence()
        with patch.object(
            module, "_root_identity", return_value=(0, 0, 0, 0),
        ) as identity, patch.object(
            module, "_require_incoming_absent",
        ) as incoming, patch.object(
            module, "_qualify_host_once", side_effect=(host, host),
        ) as host_check, patch.object(
            module,
            "qualify_rootless_docker_package_bundle",
            return_value=bundle,
        ) as bundle_check:
            self.assertEqual(
                module._qualify_once(),
                module.RootlessDockerStagedPreinstallEvidence(host, bundle),
            )
        self.assertEqual(identity.call_count, 4)
        self.assertEqual(incoming.call_count, 4)
        self.assertEqual(host_check.call_count, 2)
        bundle_check.assert_called_once_with()

    def test_host_drift_around_bundle_fails_closed(self) -> None:
        with patch.object(
            module, "_root_identity", return_value=(0, 0, 0, 0),
        ), patch.object(
            module, "_require_incoming_absent",
        ), patch.object(
            module,
            "_qualify_host_once",
            side_effect=(host_evidence(), host_evidence(workflow="b" * 40)),
        ), patch.object(
            module,
            "qualify_rootless_docker_package_bundle",
            return_value=bundle_evidence(),
        ), self.assertRaises(OSError):
            module._qualify_once()

    def test_identity_drift_fails_before_bundle_acceptance(self) -> None:
        with patch.object(
            module,
            "_root_identity",
            side_effect=((0, 0, 0, 0), (1, 0, 0, 0)),
        ), patch.object(
            module, "_require_incoming_absent",
        ), patch.object(
            module, "_qualify_host_once", return_value=host_evidence(),
        ), patch.object(
            module, "qualify_rootless_docker_package_bundle",
        ) as bundle_check, self.assertRaises(OSError):
            module._qualify_once()
        bundle_check.assert_not_called()

    def test_public_boundary_requires_two_identical_observations(self) -> None:
        first = module.RootlessDockerStagedPreinstallEvidence(
            host_evidence(),
            bundle_evidence(),
        )
        with patch.object(module, "_qualify_once", return_value=first) as qualify:
            self.assertEqual(
                module.qualify_rootless_docker_staged_preinstall(),
                first,
            )
        self.assertEqual(qualify.call_count, 2)

        changed = module.RootlessDockerStagedPreinstallEvidence(
            host_evidence(),
            bundle_evidence(directory_inode=100),
        )
        with patch.object(
            module, "_qualify_once", side_effect=(first, changed),
        ), self.assertRaises(
            module.RootlessDockerStagedPreinstallQualificationError,
        ):
            module.qualify_rootless_docker_staged_preinstall()

    def test_public_boundary_collapses_operational_failure(self) -> None:
        with patch.object(
            module,
            "_qualify_once",
            side_effect=OSError("private"),
        ), self.assertRaises(
            module.RootlessDockerStagedPreinstallQualificationError,
        ) as caught:
            module.qualify_rootless_docker_staged_preinstall()
        self.assertEqual(
            str(caught.exception),
            "rootless Docker staged preinstall qualification is unavailable",
        )
        self.assertNotIn("private", str(caught.exception))

    def test_module_has_no_mutation_network_or_command_surface(self) -> None:
        source = (
            ROOT / "deployment/rootless_docker_staged_preinstall_qualification.py"
        ).read_text()
        for forbidden in (
            "subprocess",
            "http.",
            "https.",
            "socket.",
            "requests",
            "urllib",
            "os.open",
            "O_WRONLY",
            "O_CREAT",
            "mkdir",
            "unlink",
            "remove",
            "rename",
            "chmod",
            "chown",
            "__main__",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
