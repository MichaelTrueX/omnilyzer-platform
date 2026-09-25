"""The repository-side readiness command has no provisioning authority."""

from dataclasses import replace
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment import dev_c31_recovery_readiness as readiness
from deployment import dev_host_provisioning_orchestration as c31
from deployment import dev_step20_recovery as recovery
from deployment import dev_post_provision_qualification as post
from deployment.tests.test_executor_service_config import configuration_values
from deployment.executor_service_config import DevExecutorServiceConfiguration


class ReadinessTests(unittest.TestCase):
    def test_exact_preflight_reports_state_without_invoking_mutators(self):
        commit = "a" * 40
        installed = DevExecutorServiceConfiguration(**configuration_values(
            reviewed_commit=recovery.PREDECESSOR))
        observed = SimpleNamespace(
            c17_state="predecessor",
            application=recovery.ApplicationState(1, None, None),
            replay_directory="old", replay_state="absent",
            python=SimpleNamespace(payload_manifest_sha256="c" * 64),
        )

        def git_output(_root, arguments, _maximum):
            if arguments[0] == "rev-parse":
                return commit.encode() + b"\n"
            return b'{"activation":{"deployment_enabled":false}}'

        with (
            patch.object(readiness.c26, "_output", side_effect=git_output),
            patch.object(readiness.c29, "_read_small_regular", return_value=installed.canonical_bytes()),
            patch.object(recovery, "PREDECESSOR_C17",
                         hashlib.sha256(installed.canonical_bytes()).hexdigest()),
            patch.object(readiness.c26, "generate_dev_application_manifest") as manifest,
            patch.object(readiness.c28, "qualify_dev_wheelhouse") as wheels,
            patch.object(readiness.pipq, "qualify_dev_pip_installer"),
            patch("deployment.dev_host_provisioning_plan.build_dev_host_provisioning_plan"),
            patch.object(readiness.post, "qualify_dev_provisioned_host",
                         side_effect=post.PostProvisionQualificationError()),
            patch.object(c31, "_qualify_step20_recovery", return_value=observed),
            patch.object(c31._Step20RecoveryPreflight, "__post_init__"),
            patch.object(c31.DevHostProvisioningOrchestrator, "provision",
                         side_effect=AssertionError("C31 executed")) as provision,
            patch.object(recovery, "migrate_application",
                         side_effect=AssertionError("application mutated")) as app,
            patch.object(recovery, "migrate_replay_directory",
                         side_effect=AssertionError("directory mutated")) as directory,
        ):
            manifest.return_value.canonical_bytes.return_value = b"manifest"
            result = readiness.readiness(wheelhouse_path="/staging/wheels",
                                         pip_installer_staging="/staging/pip")
        self.assertTrue(result["c31_eligible_for_separate_authorization"])
        self.assertEqual(result["reviewed_commit"], commit)
        self.assertEqual(result["application_migration_state"], "prefix-1")
        self.assertEqual(result["replay_directory_mode_state"], "old")
        self.assertEqual(result["replay_state"], "absent")
        for mutation in (provision, app, directory):
            mutation.assert_not_called()

    def test_altered_installed_c17_cannot_authorize_readiness(self):
        predecessor = DevExecutorServiceConfiguration(**configuration_values(
            reviewed_commit=recovery.PREDECESSOR))
        pinned = hashlib.sha256(predecessor.canonical_bytes()).hexdigest()
        altered = {
            "broker_uid": predecessor.broker_uid + 100,
            "executor_uid": predecessor.executor_uid + 100,
            "replay_group_gid": predecessor.replay_group_gid + 100,
            "canary_image": predecessor.canary_image[:-1] + (
                "b" if predecessor.canary_image.endswith("a") else "a"),
            "runtime_configuration_sha256": "b" * 64,
            "ingress_file_sha256": ("a" * 64, *predecessor.ingress_file_sha256[1:]),
        }

        def git_output(_root, arguments, _maximum):
            if arguments[0] == "rev-parse":
                return b"a" * 40 + b"\n"
            return b'{"activation":{"deployment_enabled":false}}'

        for field, value in altered.items():
            with self.subTest(field=field):
                installed = replace(predecessor, **{field: value})
                with patch.object(recovery, "PREDECESSOR_C17", pinned), \
                     patch.object(readiness.c26, "_output", side_effect=git_output), \
                     patch.object(readiness.c29, "_read_small_regular",
                                  return_value=installed.canonical_bytes()), \
                     patch.object(readiness.c26, "generate_dev_application_manifest") as manifest, \
                     patch.object(readiness.c28, "qualify_dev_wheelhouse"), \
                     patch.object(readiness.pipq, "qualify_dev_pip_installer"), \
                     patch("deployment.dev_host_provisioning_plan.build_dev_host_provisioning_plan"), \
                     patch.object(c31, "_qualify_step20_recovery", return_value=SimpleNamespace(
                         c17_state="current", application=recovery.ApplicationState(0, None, None),
                         replay_directory="old", replay_state="absent",
                         python=SimpleNamespace(payload_manifest_sha256="c" * 64))), \
                     patch.object(c31._Step20RecoveryPreflight, "__post_init__"), \
                     patch.object(readiness.post, "qualify_dev_provisioned_host",
                                  side_effect=post.PostProvisionQualificationError()), \
                     patch("builtins.print"):
                    manifest.return_value.canonical_bytes.return_value = b"manifest"
                    self.assertEqual(readiness.main([
                        "--wheelhouse-path", "/staging/wheels",
                        "--pip-installer-staging", "/staging/pip",
                    ]), 1)
                    manifest.assert_not_called()

    def test_ambiguity_returns_nonzero_without_detail_leak(self):
        with patch.object(readiness, "readiness", side_effect=OSError):
            self.assertEqual(readiness.main([
                "--wheelhouse-path", "/staging/wheels",
                "--pip-installer-staging", "/staging/pip",
            ]), 1)
