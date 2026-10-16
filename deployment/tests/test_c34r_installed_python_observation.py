"""File: deployment/tests/test_c34r_installed_python_observation.py

Purpose: Test C34R's strict separation of actual read-only C31A virtualenv
verification, untrusted system-binary byte observations and root authority.
Related: deployment/c34r_installed_python_observation.py,
deployment/c34q_python_runtime_compatibility.py,
deployment/python_environment_qualification.py,
deployment/tests/test_c34q_python_runtime_compatibility.py.

Tests inspect candidate local Git objects but mock host file-tree and binary
observations. No /opt or /etc reads, system services, sudo, venv imports,
runtime execution, network calls, package installation or writes.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deployment import c34r_installed_python_observation as subject
from deployment import c34q_python_runtime_compatibility as requirements
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values


class C34RReadonlyInstalledPythonTests(unittest.TestCase):
    """Demand exact source generation and immutable no-authorization receipts."""

    @classmethod
    def setUpClass(cls) -> None:
        """Build one genuine local-Git C34Q requirements receipt per test class."""
        cls.repo = Path(__file__).resolve().parents[2]
        cls.sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cls.repo, check=True, capture_output=True,
            text=True, timeout=10,
        ).stdout.strip()
        cls.config = DevExecutorServiceConfiguration(
            **configuration_values(reviewed_commit=cls.sha),
        )
        environment = dict(os.environ, GIT_NO_LAZY_FETCH="1")

        def read_blob(path):
            """Read a pinned candidate Git blob, never the mutable worktree."""
            return subprocess.run(
                ["git", "cat-file", "blob", cls.sha + ":" + path],
                cwd=cls.repo, check=True, capture_output=True,
                timeout=10, env=environment,
            ).stdout

        cls.requirements = requirements.qualify_c34q_runtime_requirements(
            candidate_sha=cls.sha, blob_reader=read_blob,
            executor_configuration=cls.config,
        )
        cls.witness = subject.C34RInterpreterWitness(
            subject._INTERPRETER, "a" * 64, 1024,
        )

    def _inspect(self, *, config=None, receipt=None, installed=None):
        """Supply synthetic host evidence only to this review-only function."""
        if installed is None:
            installed = subject.environment.DevPythonEnvironmentEvidence()
        with (
            patch.object(
                subject, "_read_system_interpreter_witness",
                return_value=self.witness,
            ) as binary,
            patch.object(
                subject.environment, "qualify_dev_python_environment",
                return_value=installed,
            ) as venv,
        ):
            result = subject.inspect_c34r_installed_python_readonly(
                executor_configuration=self.config if config is None else config,
                requirement_receipt=(
                    self.requirements if receipt is None else receipt
                ),
            )
        return result, binary, venv

    def test_existing_manifest_evidence_is_bound_but_cannot_approve_root(self):
        """Even a byte-matching venv does not verify native Debian package trust."""
        result, binary, venv = self._inspect()
        self.assertTrue(result.installed_venv_tree_verified)
        self.assertEqual(result.verified_regular_files, 197)
        self.assertEqual(result.verified_directories, 36)
        self.assertEqual(result.verified_symlinks, 4)
        self.assertEqual(
            result.populated_venv_manifest_sha256,
            subject.environment._MANIFEST_SHA256,
        )
        self.assertEqual(result.interpreter, self.witness)
        self.assertFalse(result.interpreter_package_approved)
        self.assertFalse(result.installed_executor_config_verified)
        self.assertFalse(result.root_execution_approved)
        self.assertEqual(binary.call_count, 2)
        venv.assert_called_once_with(configuration=self.config)

    def test_system_binary_change_between_reads_is_a_hold(self):
        """A changing interpreter cannot accompany a successful tree receipt."""
        other = replace(self.witness, sha256="b" * 64)
        with (
            patch.object(
                subject, "_read_system_interpreter_witness",
                side_effect=[self.witness, other],
            ),
            patch.object(
                subject.environment, "qualify_dev_python_environment",
                return_value=subject.environment.DevPythonEnvironmentEvidence(),
            ),
        ):
            with self.assertRaises(subject.C34RRuntimeObservationError):
                subject.inspect_c34r_installed_python_readonly(
                    executor_configuration=self.config,
                    requirement_receipt=self.requirements,
                )

    def test_installed_tree_hold_does_not_escalate_to_source_repair(self):
        """C31A qualification errors must not trigger file writes or promotion."""
        with (
            patch.object(subject, "_read_system_interpreter_witness",
                         return_value=self.witness),
            patch.object(subject.environment, "qualify_dev_python_environment",
                         side_effect=OSError("synthetic missing venv")),
        ):
            with self.assertRaises(subject.C34RRuntimeObservationError):
                subject.inspect_c34r_installed_python_readonly(
                    executor_configuration=self.config,
                    requirement_receipt=self.requirements,
                )

    def test_candidate_executor_sha_mismatch_holds(self):
        """Cannot apply a different revision's config to a frozen Git receipt."""
        wrong = DevExecutorServiceConfiguration(
            **configuration_values(reviewed_commit="f" * 40),
        )
        with self.assertRaises(subject.C34RRuntimeObservationError):
            self._inspect(config=wrong)

    def test_forged_requirement_approval_is_rejected(self):
        """Any attempt to reuse a C34Q receipt as host approval fails closed."""
        with self.assertRaises(ValueError):
            replace(self.requirements, root_execution_approved=True)
        with self.assertRaises(ValueError):
            replace(self.requirements, installed_runtime_qualified=True)
        with self.assertRaises(subject.C34RRuntimeObservationError):
            self._inspect(config={"reviewed_commit": self.sha})

    def test_incorrect_host_evidence_type_is_rejected(self):
        """An arbitrary object cannot stand in for C31A's exact typed evidence."""
        with self.assertRaises(subject.C34RRuntimeObservationError):
            self._inspect(installed=object())

    def test_forged_interpreter_and_final_receipt_rejected(self):
        """Nonsecret binary SHA by itself is never a trusted Debian package seal."""
        with self.assertRaises(ValueError):
            replace(self.witness, sha256="not-sha")
        result, _binary, _venv = self._inspect()
        for field in (
            "interpreter_package_approved",
            "installed_executor_config_verified",
            "root_execution_approved",
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(result, **{field: True})
        self.assertEqual(subject.__all__, (
            "C34RRuntimeObservationError",
            "C34RInterpreterWitness",
            "C34RInstalledRuntimeReceipt",
            "inspect_c34r_installed_python_readonly",
        ))

    def test_readonly_binary_reader_rejects_nonroot_test_binary(self):
        """A synthetic unprivileged executable cannot impersonate /usr/bin."""
        with tempfile.TemporaryDirectory(prefix="c34r-unpriv-") as temp:
            location = Path(temp) / "python3.12"
            location.write_bytes(b"not a signed Ubuntu interpreter")
            location.chmod(0o755)
            with patch.object(subject, "_INTERPRETER", str(location)):
                with self.assertRaises((ValueError, OSError)):
                    subject._read_system_interpreter_witness()

    def test_interpreter_symlink_is_refused(self):
        """The fixed system interpreter must itself be a regular file."""
        with tempfile.TemporaryDirectory(prefix="c34r-link-") as temp:
            original = Path(temp) / "real"
            original.write_bytes(b"not a trusted Python binary")
            linked = Path(temp) / "python3.12"
            linked.symlink_to(original)
            with patch.object(subject, "_INTERPRETER", str(linked)):
                with self.assertRaises(OSError):
                    subject._read_system_interpreter_witness()


if __name__ == "__main__":
    unittest.main()
