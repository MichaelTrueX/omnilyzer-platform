"""File: deployment/tests/test_analytics_dev_activation_inputs.py

Purpose: Verify no-write Task014 Analytics root and systemd review inputs
         using real immutable Git sources: fixed paths, source hashes,
         existing rootless C32ZF mount contract and negative tampering.
Related: deployment/analytics_dev_activation_inputs.py,
         deployment/analytics_source_handoff.py,
         deployment/analytics_source_archive.py,
         deployment/analytics_executor_service_config.py,
         deployment/analytics_isolated_source_install.py,
         deployment/rootless_docker_authority.py.

These tests never grant permissions, stage files, write root paths, use
credentials, start services or claim real signed 0.15.0 acceptance.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from deployment import analytics_dev_activation_inputs as activation
from deployment.analytics_executor_service_config import (
    ANALYTICS_INSTALLED_FILES, parse_analytics_executor_service_config,
)
from deployment.analytics_isolated_source_install import _approval
from deployment.analytics_source_archive import (
    verify_analytics_source_archive,
)
from deployment.policy import canonical_bytes

ROOT = Path(__file__).resolve().parents[2]


class ExactUnsignedActivationInputsTests(unittest.TestCase):
    """One reviewed Git commit is the only source of activation input bytes."""

    @classmethod
    def setUpClass(cls):
        """Generate one complete artifact set without network or host writes."""
        cls.sha = subprocess.check_output(
            ("/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"),
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        cls.artifacts = activation.build_unsigned_analytics_activation_inputs(
            repository_root=str(ROOT), reviewed_commit=cls.sha,
        )

    def test_four_exact_fixed_root_destinations_and_closed_parsers(self):
        """Separate archive, root approval, and equal broker/executor source."""
        self.assertEqual(set(self.artifacts), {
            activation.SOURCE_ARCHIVE, activation.SOURCE_APPROVAL,
            activation.EXECUTOR_CONFIG, activation.BROKER_CONFIG,
        })
        self.assertEqual(
            self.artifacts[activation.EXECUTOR_CONFIG],
            self.artifacts[activation.BROKER_CONFIG],
        )
        approval = self.artifacts[activation.SOURCE_APPROVAL]
        model = _approval(approval)
        self.assertEqual(model["reviewed_commit"], self.sha)
        self.assertEqual(model["destination"], activation.DESTINATION)
        self.assertEqual(
            model["archive_sha256"],
            hashlib.sha256(self.artifacts[activation.SOURCE_ARCHIVE]).hexdigest(),
        )
        self.assertEqual(canonical_bytes(model), approval)
        config = self.artifacts[activation.BROKER_CONFIG]
        result = parse_analytics_executor_service_config(config)
        self.assertEqual(result["reviewed_installed_commit"], self.sha)
        self.assertEqual(len(result["source_sha256"]), 20)
        self.assertEqual(
            tuple(path for path, _sha in result["source_sha256"]),
            ANALYTICS_INSTALLED_FILES,
        )
        self.assertLessEqual(len(config), 4096)
        self.assertTrue(len(self.artifacts[activation.SOURCE_ARCHIVE]) < 14 * 1024 * 1024)

    def test_reviewed_source_archive_bindings_match_real_authority(self):
        """Every one of 20 runtime modules comes from the same exact archive."""
        approval = _approval(self.artifacts[activation.SOURCE_APPROVAL])
        archived = self.artifacts[activation.SOURCE_ARCHIVE]
        entries = dict(verify_analytics_source_archive(
            archived,
            expected_manifest_sha256=approval["manifest_sha256"],
            reviewed_commit=self.sha,
        ))
        parsed = parse_analytics_executor_service_config(
            self.artifacts[activation.EXECUTOR_CONFIG],
        )
        for path, digest in parsed["source_sha256"]:
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256(entries[path]).hexdigest(), digest)
        self.assertEqual(len(entries), 31)
        self.assertNotIn("deployment/analytics_dev_activation_inputs.py", entries)
        self.assertNotIn("deployment/analytics_isolated_source_install.py", entries)

    def test_unsigned_inputs_alone_never_install_or_confer_permission(self):
        """No privileged source/data writes can happen from a review builder."""
        with patch.object(
            activation, "_approval", wraps=_approval,
        ) as expected:
            outputs = activation.build_unsigned_analytics_activation_inputs(
                repository_root=str(ROOT), reviewed_commit=self.sha,
            )
        self.assertEqual(outputs, self.artifacts)
        expected.assert_called_once()
        self.assertNotIn("deployment_authorized", json.loads(
            outputs[activation.EXECUTOR_CONFIG],
        ))
        self.assertEqual(
            json.loads(outputs[activation.SOURCE_APPROVAL])["stage"], "dev",
        )

    def test_four_service_assets_reuse_original_task014_rootless_mount(self):
        """One exact Git object supplies three units and original rootless
        C32ZF supplies the private-directory fragment without duplicate bind.
        """
        services = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
        )
        self.assertEqual(len(services), 4)
        self.assertEqual(set(services), {
            activation._ANALYTICS_RUNTIME_DROPIN,
            *(destination for _src, destination in activation._SERVICE_SOURCES),
        })
        reviewed = dict(verify_analytics_source_archive(
            self.artifacts[activation.SOURCE_ARCHIVE],
            expected_manifest_sha256=_approval(
                self.artifacts[activation.SOURCE_APPROVAL],
            )["manifest_sha256"],
            reviewed_commit=self.sha,
        ))
        for source, destination in activation._SERVICE_SOURCES:
            with self.subTest(source=source):
                self.assertEqual(services[destination], reviewed[source])

        original = (ROOT /
            "deployment/systemd/rootless/rootless-docker-executor-socket.conf"
        ).read_bytes()
        self.assertEqual(
            hashlib.sha256(original).hexdigest(),
            "afef78b7ed57beedc2a8496b602c3f7d6dad7981dd88258f6b7e8c35a7fbed2d",
        )
        self.assertEqual(
            services[activation._ANALYTICS_RUNTIME_DROPIN],
            b"[Service]\\n"
            b"RuntimeDirectory=omnilyzer/deployment/rootless-docker\\n"
            b"RuntimeDirectoryMode=0700\\n",
        )
        self.assertIn(
            activation._ROOTLESS_BIND.encode(),
            services[activation._SERVICE_SOURCES[1][1]],
        )
        self.assertNotIn(
            b"BindReadOnlyPaths", services[activation._ANALYTICS_RUNTIME_DROPIN],
        )
        self.assertNotIn(
            b"ExecStart", services[activation._ANALYTICS_RUNTIME_DROPIN],
        )
        self.assertNotIn(
            b"User=", services[activation._ANALYTICS_RUNTIME_DROPIN],
        )

    def test_original_rootless_source_contract_cannot_be_changed_by_caller(self):
        """No new authority from changing public fixed mount input values."""
        from types import SimpleNamespace
        original = activation.AUTHORITY
        wrong = SimpleNamespace(
            installed_assets=tuple(
                (src, dst, "f" * 64, uid, gid, mode)
                if src == activation._ORIGINAL_ROOTLESS_SOURCE
                else (src, dst, sha, uid, gid, mode)
                for src, dst, sha, uid, gid, mode in original.installed_assets
            ),
            daemon_socket=original.daemon_socket,
            socket=original.socket,
        )
        with patch.object(activation, "AUTHORITY", wrong):
            with self.assertRaises(activation.AnalyticsActivationInputsError):
                activation.build_unsigned_analytics_service_inputs(
                    repository_root=str(ROOT), reviewed_commit=self.sha,
                )
        with patch.object(
            activation, "_RUNTIME_MODE", "RuntimeDirectoryMode=0777",
        ):
            with self.assertRaises(activation.AnalyticsActivationInputsError):
                activation.build_unsigned_analytics_service_inputs(
                    repository_root=str(ROOT), reviewed_commit=self.sha,
                )
        with patch.object(
            activation, "_ROOTLESS_BIND",
            "BindReadOnlyPaths=/run/user/991/other.sock:/tmp/other.sock",
        ):
            with self.assertRaises(activation.AnalyticsActivationInputsError):
                activation.build_unsigned_analytics_service_inputs(
                    repository_root=str(ROOT), reviewed_commit=self.sha,
                )
        self.assertEqual(
            activation.build_unsigned_analytics_service_inputs(
                repository_root=str(ROOT), reviewed_commit=self.sha,
            )["/etc/systemd/system/omnilyzer-deployment-analytics-executor.service.d/rootless-runtime.conf"],
            b"[Service]\\nRuntimeDirectory=omnilyzer/deployment/rootless-docker\\n"
            b"RuntimeDirectoryMode=0700\\n",
        )

    def test_tampered_archive_or_source_model_fails_closed(self):
        """A forged signed claim or altered archive SHA can never be approved."""
        with patch.object(
            activation, "build_analytics_source_archive",
            return_value=self.artifacts[activation.SOURCE_ARCHIVE][:-512]
                         + b"X" * 512,
        ):
            with self.assertRaises(activation.AnalyticsActivationInputsError):
                activation.build_unsigned_analytics_activation_inputs(
                    repository_root=str(ROOT), reviewed_commit=self.sha,
                )
        wrong = self.sha[:-1] + ("0" if self.sha[-1] != "0" else "1")
        with self.assertRaises(activation.AnalyticsActivationInputsError):
            activation.build_unsigned_analytics_activation_inputs(
                repository_root=str(ROOT), reviewed_commit=wrong,
            )

    def test_only_exact_commit_not_mutable_or_path_alias(self):
        """No mutable Git ref or directory alias is a reviewed source grant."""
        for source, commit in (
            (str(ROOT), "main"),
            (str(ROOT), "0" * 40),
            (str(ROOT / "deployment"), self.sha),
            (".", self.sha),
        ):
            with self.subTest(source=source, commit=commit):
                with self.assertRaises(activation.AnalyticsActivationInputsError):
                    activation.build_unsigned_analytics_activation_inputs(
                        repository_root=source, reviewed_commit=commit,
                    )


if __name__ == "__main__":
    unittest.main()
