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

import configparser
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from deployment import analytics_dev_activation_inputs as activation
from deployment.analytics_executor_service_config import (
    ANALYTICS_INSTALLED_FILES, ANALYTICS_SUCCESSOR_INSTALLED_FILES,
    parse_analytics_executor_service_config,
)
from deployment.analytics_isolated_source_install import _approval
from deployment.analytics_source_archive import (
    verify_analytics_source_archive, verify_analytics_successor_source_archive,
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
        self.assertEqual(len(entries), 32)
        self.assertNotIn("deployment/analytics_dev_activation_inputs.py", entries)
        self.assertNotIn("deployment/analytics_isolated_source_install.py", entries)

    def test_v2_exact_git_review_inputs_are_not_installed_authority(self):
        """Tie all 26 successor source hashes to one immutable V2 Git TAR."""
        successor = activation.build_unsigned_analytics_activation_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True,
        )
        self.assertEqual(set(successor), set(self.artifacts))
        self.assertEqual(successor[activation.EXECUTOR_CONFIG],
                         successor[activation.BROKER_CONFIG])
        self.assertEqual(
            activation.build_unsigned_analytics_activation_inputs(
                repository_root=str(ROOT), reviewed_commit=self.sha,
            ), self.artifacts,
        )
        approval = json.loads(successor[activation.SOURCE_APPROVAL])
        self.assertEqual(approval["schema_version"], 2)
        self.assertEqual(approval["reviewed_commit"], self.sha)
        self.assertEqual(approval["destination"], activation.SUCCESSOR_DESTINATION)
        from deployment import analytics_isolated_source_install as stage
        self.assertEqual(activation.SUCCESSOR_DESTINATION,
                         stage._PARENT + "/" + stage._SUCCESSOR_DESTINATION)
        self.assertEqual(
            approval["archive_sha256"],
            hashlib.sha256(successor[activation.SOURCE_ARCHIVE]).hexdigest(),
        )
        archived = dict(verify_analytics_successor_source_archive(
            successor[activation.SOURCE_ARCHIVE],
            expected_manifest_sha256=approval["manifest_sha256"],
            reviewed_commit=self.sha,
        ))
        self.assertEqual(len(archived), 38)
        parsed = parse_analytics_executor_service_config(
            successor[activation.EXECUTOR_CONFIG],
        )
        self.assertEqual(
            parsed["expected_workflow_sha"],
            "9d29fa1a4010e6e72676580c36a94c1e97e8794b",
        )
        self.assertNotIn(
            "expected_workflow_sha",
            parse_analytics_executor_service_config(
                self.artifacts[activation.EXECUTOR_CONFIG],
            ),
        )
        self.assertEqual(
            tuple(name for name, _ in parsed["source_sha256"]),
            ANALYTICS_SUCCESSOR_INSTALLED_FILES,
        )
        for name, expected in parsed["source_sha256"]:
            with self.subTest(path=name):
                self.assertEqual(hashlib.sha256(archived[name]).hexdigest(), expected)
        # Current first-install root approval parses ONLY schema1. This is
        # reviewed source evidence, never a second implicit live installer.
        with self.assertRaises(ValueError):
            _approval(successor[activation.SOURCE_APPROVAL])
        self.assertNotEqual(
            self.artifacts[activation.EXECUTOR_CONFIG],
            successor[activation.EXECUTOR_CONFIG],
        )

    def test_generation_three_unsigned_source_is_separate_and_never_installs(self):
        """Only an explicit root-controlled generation3 may gain a positive path.

        All outputs are source-only review bytes, with no signer, root install,
        Docker, service start, image publish or operator approval implied.
        """
        baseline = activation.build_unsigned_analytics_activation_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True,
        )
        approved = activation.build_unsigned_analytics_activation_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True, owner_authorized_first_successor=True,
        )
        self.assertEqual(set(approved), set(baseline))
        self.assertEqual(approved[activation.SOURCE_ARCHIVE],
                         baseline[activation.SOURCE_ARCHIVE])
        self.assertNotEqual(approved[activation.EXECUTOR_CONFIG],
                            baseline[activation.EXECUTOR_CONFIG])
        import json
        parsed = json.loads(approved[activation.EXECUTOR_CONFIG])
        self.assertEqual(parsed["schema_version"], 3)
        self.assertIs(parsed["owner_authorized_first_successor"], True)
        self.assertEqual(
            activation.parse_analytics_executor_service_config(
                approved[activation.EXECUTOR_CONFIG]
            )["source_generation"], 3,
        )
        original = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True,
        )
        preview = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True, owner_authorized_first_successor=True,
        )
        self.assertEqual(
            set(preview),
            set(original) | {activation._SUCCESSOR_BROKER_OWNER_DROPIN},
        )
        for name in original:
            if name != activation._SUCCESSOR_EXECUTOR_DROPIN:
                self.assertEqual(original[name], preview[name])
        self.assertEqual(
            preview[activation._SUCCESSOR_EXECUTOR_DROPIN],
            original[activation._SUCCESSOR_EXECUTOR_DROPIN]
            + b"Environment=ANALYTICS_REVIEWED_SUPERVISOR_V2=1\n",
        )
        self.assertNotIn(
            b"Environment=ANALYTICS_REVIEWED_SUPERVISOR_V2=1",
            original[activation._SUCCESSOR_EXECUTOR_DROPIN],
        )
        for bad in (
            {"owner_authorized_first_successor": True},
            {"successor_source": True, "owner_authorized_first_successor": 1},
            {"successor_source": True, "owner_authorized_first_successor": "true"},
        ):
            with self.subTest(bad=bad), self.assertRaises(
                activation.AnalyticsActivationInputsError,
            ):
                activation.build_unsigned_analytics_activation_inputs(
                    repository_root=str(ROOT), reviewed_commit=self.sha,
                    **bad,
                )


    def test_v3_broker_only_public_owner_mirrors_preserve_uid991_separation(self):
        """Mount exactly three root-owned public copies, not executor secrets."""
        approved = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True, owner_authorized_first_successor=True,
        )
        payload = approved[activation._SUCCESSOR_BROKER_OWNER_DROPIN]
        self.assertEqual(payload, (
            "[Service]\\n" + activation._SUCCESSOR_BROKER_OWNER_TMPFS
            + "\\n" + activation._SUCCESSOR_BROKER_OWNER_BINDS + "\\n"
        ).encode("ascii"))
        self.assertEqual(payload.count(b"BindReadOnlyPaths="), 1)
        self.assertEqual(payload.count(b"TemporaryFileSystem="), 1)
        self.assertEqual(payload.count(b"/etc/omnilyzer/deployment/dev/"), 3)
        self.assertEqual(payload.count(b"/etc/omnilyzer/deployment/broker/"), 3)
        self.assertIn(b"mode=0750,uid=0,gid=990", payload)
        for prohibited in (
            b"chmod", b"SupplementaryGroups=", b"ExecStart=",
            b"WorkingDirectory=", b"ReadWritePaths=", b"rootless-docker",
            b"token", b"secret", b"uid=991", b"gid=991",
        ):
            self.assertNotIn(prohibited, payload)
        for initial in (False, True):
            source = activation.build_unsigned_analytics_service_inputs(
                repository_root=str(ROOT), reviewed_commit=self.sha,
                successor_source=initial,
                owner_authorized_first_successor=False,
            )
            self.assertNotIn(activation._SUCCESSOR_BROKER_OWNER_DROPIN, source)

    def test_positive_v3_root_workflow_rebind_keeps_original_archive_inert(self):
        """Only explicit owner-selected V3 may rebind the protected Task014 SHA."""
        legacy = activation.build_unsigned_analytics_activation_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True, owner_authorized_first_successor=True,
        )
        current_workflow = "e" * 40
        reviewed = activation.build_unsigned_analytics_activation_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True, owner_authorized_first_successor=True,
            approved_workflow_sha=current_workflow,
        )
        self.assertEqual(
            legacy[activation.SOURCE_ARCHIVE], reviewed[activation.SOURCE_ARCHIVE],
        )
        self.assertEqual(
            legacy[activation.SOURCE_APPROVAL], reviewed[activation.SOURCE_APPROVAL],
        )
        self.assertEqual(
            reviewed[activation.EXECUTOR_CONFIG],
            reviewed[activation.BROKER_CONFIG],
        )
        parsed = parse_analytics_executor_service_config(
            reviewed[activation.EXECUTOR_CONFIG],
        )
        self.assertEqual(parsed["source_generation"], 3)
        self.assertEqual(parsed["expected_workflow_sha"], current_workflow)
        self.assertEqual(
            parsed["reviewed_installed_commit"], self.sha,
        )
        service = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True, owner_authorized_first_successor=True,
            approved_workflow_sha=current_workflow,
        )
        original = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True, owner_authorized_first_successor=True,
        )
        self.assertEqual(service, original)
        for bad in (
            {"approved_workflow_sha": "e" * 40},
            {"successor_source": True, "approved_workflow_sha": "e" * 40},
            {"successor_source": True, "owner_authorized_first_successor": True,
             "approved_workflow_sha": "0" * 40},
            {"successor_source": True, "owner_authorized_first_successor": True,
             "approved_workflow_sha": "INVALID"},
            {"successor_source": True, "owner_authorized_first_successor": True,
             "approved_workflow_sha": False},
        ):
            with self.subTest(bad=bad), self.assertRaises(
                activation.AnalyticsActivationInputsError,
            ):
                activation.build_unsigned_analytics_activation_inputs(
                    repository_root=str(ROOT), reviewed_commit=self.sha, **bad,
                )

    def test_v2_bad_generation_or_changed_git_blob_is_denied(self):
        """No caller-selected generation/manifest or tampered TAR can pass."""
        with self.assertRaises(activation.AnalyticsActivationInputsError):
            activation.build_unsigned_analytics_activation_inputs(
                repository_root=str(ROOT), reviewed_commit=self.sha,
                successor_source=1,
            )
        with self.assertRaises(activation.AnalyticsActivationInputsError):
            activation.build_unsigned_analytics_activation_inputs(
                repository_root=str(ROOT), reviewed_commit="a" * 40,
                successor_source=True,
            )
        successor = activation.build_unsigned_analytics_activation_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True,
        )
        good = verify_analytics_successor_source_archive(
            successor[activation.SOURCE_ARCHIVE],
            expected_manifest_sha256=json.loads(
                successor[activation.SOURCE_APPROVAL]
            )["manifest_sha256"],
            reviewed_commit=self.sha,
        )
        corrupt = tuple(
            (name, b"modified" if name == ANALYTICS_SUCCESSOR_INSTALLED_FILES[-1]
             else blob) for name, blob in good
        )
        with patch.object(activation, "verify_analytics_successor_source_archive",
                          return_value=corrupt), self.assertRaises(
                activation.AnalyticsActivationInputsError):
            activation.build_unsigned_analytics_activation_inputs(
                repository_root=str(ROOT), reviewed_commit=self.sha,
                successor_source=True,
            )

    def test_v2_compose_reset_overlay_is_git_exact_and_tamper_denied(self):
        """An unsigned alternate port mapping never becomes root-owned V2 input.

        Check the real Git blob is present in the fixed candidate bundle,
        then tamper ONLY that YAML while the manifest/source SHA is unchanged.
        The existing activation builder must reject before any installation.
        """
        from deployment.analytics_executor_service_config import (
            ANALYTICS_SUCCESSOR_COMPOSE_FILES,
        )
        self.assertEqual(ANALYTICS_SUCCESSOR_COMPOSE_FILES, (
            "deployment/runtime/dev/analytics.compose.successor-ports.yaml",
        ))
        successor = activation.build_unsigned_analytics_activation_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True,
        )
        approved = json.loads(successor[activation.SOURCE_APPROVAL])
        original = verify_analytics_successor_source_archive(
            successor[activation.SOURCE_ARCHIVE],
            expected_manifest_sha256=approved["manifest_sha256"],
            reviewed_commit=self.sha,
        )
        overlay = ANALYTICS_SUCCESSOR_COMPOSE_FILES[0]
        original_map = dict(original)
        self.assertIn(b"ports: !reset []", original_map[overlay])
        self.assertEqual(
            hashlib.sha256(original_map[overlay]).hexdigest(),
            json.loads(successor[activation.EXECUTOR_CONFIG])[
                "source_sha256"
            ][overlay],
        )
        corrupted = tuple(
            (path, blob.replace(b"ports: !reset []", b"ports: []")
             if path == overlay else blob)
            for path, blob in original
        )
        with (
            patch.object(
                activation, "verify_analytics_successor_source_archive",
                return_value=corrupted,
            ),
            self.assertRaises(activation.AnalyticsActivationInputsError),
        ):
            activation.build_unsigned_analytics_activation_inputs(
                repository_root=str(ROOT), reviewed_commit=self.sha,
                successor_source=True,
            )

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
        C32ZF pins source+destination; Analytics overlays a private mount
        so Canary and Analytics never share a RuntimeDirectory lifecycle.
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
            b"[Service]\n"
            b"TemporaryFileSystem=/run/omnilyzer/deployment:mode=0755,uid=0,gid=0 "
            b"/run/omnilyzer/deployment/rootless-docker:mode=0700,uid=991,gid=991\n"
            b"BindReadOnlyPaths=/run/omnilyzer/deployment/analytics-executor.sock:"
            b"/run/omnilyzer/deployment/analytics-executor.sock\n",
        )
        # Actual INI parser must see distinct lines; a literal escaped
        # backslash+n passed old tests but makes systemd reject the drop-in.
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(
            services[activation._ANALYTICS_RUNTIME_DROPIN].decode("ascii"),
        )
        self.assertEqual(
            list(parser["Service"].keys()), ["temporaryfilesystem", "bindreadonlypaths"],
        )
        self.assertEqual(
            parser["Service"]["temporaryfilesystem"],
            "/run/omnilyzer/deployment:mode=0755,uid=0,gid=0 "
            "/run/omnilyzer/deployment/rootless-docker:mode=0700,uid=991,gid=991",
        )
        self.assertIn(
            activation._ROOTLESS_BIND.encode(),
            services[activation._SERVICE_SOURCES[1][1]],
        )
        self.assertEqual(
            parser["Service"]["bindreadonlypaths"],
            "/run/omnilyzer/deployment/analytics-executor.sock:"
            "/run/omnilyzer/deployment/analytics-executor.sock",
        )
        self.assertNotIn(
            b"RuntimeDirectory=", services[activation._ANALYTICS_RUNTIME_DROPIN],
        )
        self.assertNotIn(
            b"RuntimeDirectoryMode=", services[activation._ANALYTICS_RUNTIME_DROPIN],
        )
        self.assertNotIn(
            b"ExecStart", services[activation._ANALYTICS_RUNTIME_DROPIN],
        )
        self.assertNotIn(
            b"User=", services[activation._ANALYTICS_RUNTIME_DROPIN],
        )

    def test_v2_service_overrides_preserve_original_units_and_authority(self):
        """Review-only broker/executor working dirs change as ONE source pair.

        No active service, port, identity, rootless Docker mount, command or
        root installer is changed by these generated bytes.
        """
        first = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
        )
        second = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True,
        )
        self.assertEqual(len(first), 4)
        self.assertEqual(len(second), 6)
        for path, expected in first.items():
            with self.subTest(path=path):
                self.assertEqual(second[path], expected)
        appended = set(second) - set(first)
        self.assertEqual(appended, {
            activation._SUCCESSOR_BROKER_DROPIN,
            activation._SUCCESSOR_EXECUTOR_DROPIN,
        })
        self.assertEqual(activation.SUCCESSOR_DESTINATION,
                         "/opt/omnilyzer/deployment/analytics-app-candidate")
        self.assertNotEqual(activation.SUCCESSOR_DESTINATION,
                            activation.DESTINATION)
        for path in appended:
            with self.subTest(override=path):
                content = second[path].decode("ascii")
                expected = (
                    "[Service]\nWorkingDirectory="
                    + activation.SUCCESSOR_DESTINATION + "\n"
                )
                if path == activation._SUCCESSOR_EXECUTOR_DROPIN:
                    expected += (
                        activation._SUCCESSOR_VERIFIER_BINDS + "\n"
                        + activation._SUCCESSOR_VERIFIER_TMPFS + "\n"
                    )
                self.assertEqual(content, expected)
                parser = configparser.ConfigParser(interpolation=None, strict=True)
                parser.read_string(content)
                keys = {"workingdirectory": activation.SUCCESSOR_DESTINATION}
                if path == activation._SUCCESSOR_EXECUTOR_DROPIN:
                    keys.update({
                        "bindreadonlypaths": activation._SUCCESSOR_VERIFIER_BINDS.partition("=")[2],
                        "temporaryfilesystem": activation._SUCCESSOR_VERIFIER_TMPFS.partition("=")[2],
                    })
                self.assertEqual(dict(parser["Service"]), keys)
                for forbidden in (
                    "ExecStart", "User=", "Group=", "ReadWritePaths=",
                    "BindPaths=", "Environment=",
                    "RuntimeDirectory=", "Restart=", "ConditionPathExists=",
                ):
                    self.assertNotIn(forbidden, content)
                if path == activation._SUCCESSOR_BROKER_DROPIN:
                    self.assertNotIn("BindReadOnlyPaths=", content)
                    self.assertNotIn("TemporaryFileSystem=", content)
        # Original broker first-install override still selects original V1,
        # so rollback is removal of ONLY both V2 drop-ins after approval.
        self.assertIn(b"WorkingDirectory=/opt/omnilyzer/deployment/analytics-app\n",
            first[activation._SERVICE_SOURCES[0][1]])
        self.assertIn(b"WorkingDirectory=/opt/omnilyzer/deployment/analytics-app\n",
            first[activation._SERVICE_SOURCES[1][1]])
        with self.assertRaises(activation.AnalyticsActivationInputsError):
            activation.build_unsigned_analytics_service_inputs(
                repository_root=str(ROOT), reviewed_commit=self.sha,
                successor_source=1,
            )
        with patch.object(activation, "SUCCESSOR_DESTINATION", "/tmp/attacker"):
            with self.assertRaises(activation.AnalyticsActivationInputsError):
                activation.build_unsigned_analytics_service_inputs(
                    repository_root=str(ROOT), reviewed_commit=self.sha,
                    successor_source=True,
                )

    def test_v2_uid991_private_signer_mounts_preserve_broker_secrecy(self):
        """Exact isolated Cosign and TrustedRoot mirror source, UID991 workspace.

        Existing original read-only blob/OCI verifier expects 0:991 root-held
        sources in its namespace. The V1 and broker bytes MUST NOT change.
        A future approved root installer must separately provision identical
        verified binary and root content under these dedicated directories.
        """
        from deployment.broker_service_config import (
            PRODUCTION_COSIGN_PATH, PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH,
        )
        from deployment import blob_verifier, oci_verifier
        original = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
        )
        successor = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
            successor_source=True,
        )
        candidate = successor[activation._SUCCESSOR_EXECUTOR_DROPIN].decode("ascii")
        broker = successor[activation._SUCCESSOR_BROKER_DROPIN].decode("ascii")
        self.assertEqual(
            PRODUCTION_COSIGN_PATH,
            "/opt/omnilyzer/deployment/tools/cosign-v3.1.2-linux-amd64",
        )
        self.assertEqual(
            PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH,
            "/etc/omnilyzer/deployment/broker/sigstore-trusted-root.json",
        )
        self.assertEqual(blob_verifier.RUNTIME_DIRECTORY,
                         "/run/omnilyzer/deployment/dev/blob-verifier")
        self.assertEqual(oci_verifier._RUNTIME_DIRECTORY,
                         "/run/omnilyzer/deployment/dev/oci-verifier")
        self.assertIn(activation._SUCCESSOR_VERIFIER_BINDS, candidate)
        self.assertIn(activation._SUCCESSOR_VERIFIER_TMPFS, candidate)
        self.assertNotIn("/var/lib/omnilyzer/deployment", candidate)
        self.assertNotIn("Environment=", candidate)
        self.assertNotIn("SupplementaryGroups=", candidate)
        self.assertNotIn("BindReadOnlyPaths=", broker)
        self.assertEqual(
            original[activation._ANALYTICS_RUNTIME_DROPIN],
            successor[activation._ANALYTICS_RUNTIME_DROPIN],
        )
        for key in original:
            self.assertEqual(original[key], successor[key])
        self.assertNotIn("analytics-executor-sigstore", str(original))

    def test_private_tmpfs_is_not_shadowed_by_read_write_paths(self):
        """Regression for real systemd255 226/NAMESPACE while Canary is idle.

        systemd sorts duplicate mount paths by mode and keeps READ_WRITE
        ahead of TMPFS. The old shared path both suppressed the private
        mount and required a nonexistent host directory.
        """
        services = activation.build_unsigned_analytics_service_inputs(
            repository_root=str(ROOT), reviewed_commit=self.sha,
        )
        unit = services[activation._SERVICE_SOURCES[1][1]].decode("ascii")
        write_rows = [
            row.partition("=")[2].split()
            for row in unit.splitlines() if row.startswith("ReadWritePaths=")
        ]
        self.assertEqual(write_rows, [["/var/lib/omnilyzer/deployment"]])
        private_mount = services[activation._ANALYTICS_RUNTIME_DROPIN].decode("ascii")
        mount_specs = next(
            row.partition("=")[2].split()
            for row in private_mount.splitlines()
            if row.startswith("TemporaryFileSystem=")
        )
        mount_paths = [spec.partition(":")[0] for spec in mount_specs]
        self.assertEqual(mount_paths, [
            "/run/omnilyzer/deployment",
            "/run/omnilyzer/deployment/rootless-docker",
        ])
        self.assertFalse(set(mount_paths).intersection(*write_rows))
        self.assertIn(
            activation._LISTENER_BIND, private_mount.splitlines(),
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
            activation, "_PRIVATE_TMPFS",
            "TemporaryFileSystem=/run/omnilyzer/deployment/rootless-docker:"
            "mode=0777,uid=991,gid=991",
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
            b"[Service]\n"
            b"TemporaryFileSystem=/run/omnilyzer/deployment:mode=0755,uid=0,gid=0 "
            b"/run/omnilyzer/deployment/rootless-docker:mode=0700,uid=991,gid=991\n"
            b"BindReadOnlyPaths=/run/omnilyzer/deployment/analytics-executor.sock:"
            b"/run/omnilyzer/deployment/analytics-executor.sock\n",
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

