"""File: release/tests/test_task014_dev_readonly_attestation.py

Purpose: Offline safety and redaction tests for the independent Task014 DEV
root-only preflight. Uses synthetic canonical configs and disposable directories;
never accesses privileged /etc or live /opt, Docker, systemd, Zot or GitHub.
Related: release/task014_dev_readonly_attestation.py,
release/task014_source_cutover.py,
release/task014_config_cutover.py and Task014 issue #182.

Sections: prepared legitimate fixtures; nofollow/permission checks; source/
configuration identity and systemd sandbox; bounded nonsecret reporting.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_broker_service_config import configuration_values as broker_values
from deployment.tests.test_executor_service_config import configuration_values as executor_values
from release import task014_dev_readonly_attestation as audit
from release import task014_source_cutover as source_cutover

ROOT = Path(__file__).resolve().parents[2]
COMMIT = subprocess.check_output(
    ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
    stderr=subprocess.DEVNULL, timeout=5,
).decode("ascii").strip()
EXPECTED_SOCK_BIND = (
    "/run/user/991/docker.sock:/run/omnilyzer/deployment/rootless-docker/docker.sock"
)
REAL_SYSTEMCTL_PROPERTIES = audit._systemctl_properties
GOOD_SYSTEMD = {
    "User": "omnilyzer-executor",
    "Group": "omnilyzer-executor",
    "RuntimeDirectory": "omnilyzer/deployment/rootless-docker",
    "RuntimeDirectoryMode": "0700",
    "ProtectSystem": "strict",
    "UMask": "0077",
    "BindReadOnlyPaths": EXPECTED_SOCK_BIND + ":rbind",
}
GOOD_BROKER = {
    "User": "omnilyzer-broker", "Group": "omnilyzer-broker",
    "ProtectSystem": "strict", "UMask": "0077",
}
GOOD_SOCKET = {
    "SocketUser": "omnilyzer-executor",
    "SocketGroup": "omnilyzer-deployment",
    "SocketMode": "0660",
    "Listen": "/run/omnilyzer/deployment/executor.sock (Stream)",
}
GOOD_STATES = (
    ("omnilyzer-deployment-broker.service", "active"),
    ("omnilyzer-deployment-executor.socket", "active"),
    ("omnilyzer-deployment-executor.service", "failed"),
    ("nginx.service", "active"),
)


class AttestationTests(unittest.TestCase):
    """Independently reject misleading or secret-disclosing host evidence."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate one audited source plan and compatible canonical schemas."""
        cls.plan = source_cutover.reviewed_plan(ROOT, COMMIT)
        broker = broker_values()
        broker.update({
            "broker_uid": 990, "broker_gid": 990,
            "executor_uid": 991, "executor_gid": 991,
            "replay_group_gid": 992, "socket_group_gid": 993,
        })
        broker["reviewed_commit"] = source_cutover.PRIOR_SOURCE_SHA
        executor = executor_values(**{
            key: broker[key] for key in (
                "broker_uid", "broker_gid", "executor_uid", "executor_gid",
                "replay_group_gid", "socket_group_gid",
                "reviewed_commit", "runtime_configuration_sha256",
                "ingress_file_sha256",
            )
        })
        cls.broker_bytes = DevBrokerServiceConfiguration(**broker).canonical_bytes()
        cls.executor_bytes = DevExecutorServiceConfiguration(**executor).canonical_bytes()

    def setUp(self) -> None:
        """Use one disposable synthetic /etc boundary, never the host paths."""
        self.temp = tempfile.TemporaryDirectory(prefix="task014-readonly-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        bd = root / "broker"
        ed = root / "dev"
        bd.mkdir(mode=0o750)
        ed.mkdir(mode=0o750)
        bd.chmod(0o750)
        ed.chmod(0o750)
        self.b = bd / "dev.json"
        self.e = ed / "executor.json"
        self.b.write_bytes(self.broker_bytes)
        self.e.write_bytes(self.executor_bytes)
        self.b.chmod(0o640)
        self.e.chmod(0o640)
        patches = ExitStack()
        self.addCleanup(patches.close)
        patches.enter_context(patch.object(audit, "BROKER_PATH", self.b))
        patches.enter_context(patch.object(audit, "EXECUTOR_PATH", self.e))
        patches.enter_context(patch.object(audit, "_require_root"))
        patches.enter_context(patch.object(
            audit, "_is_root_service_owned",
            side_effect=lambda state, gid: (
                state.st_uid == os.getuid() and state.st_gid == os.getgid()
            ),
        ))
        patches.enter_context(patch.object(
            source_cutover, "_observed_tree",
            return_value=self.plan.prior_entries,
        ))
        patches.enter_context(patch.object(
            audit, "_systemctl_properties",
            side_effect=self._property_command,
        ))
        self.systemctl_process = patches.enter_context(patch.object(
            audit.subprocess, "run", side_effect=self._state_command,
        ))

    @staticmethod
    def _property_command(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
        """Return only approved synthetic read-only unit metadata."""
        allowed = {
            "omnilyzer-deployment-executor.service": GOOD_SYSTEMD,
            "omnilyzer-deployment-broker.service": GOOD_BROKER,
            "omnilyzer-deployment-executor.socket": GOOD_SOCKET,
        }
        assert unit in allowed
        assert set(properties) == set(allowed[unit])
        return dict(allowed[unit])

    @staticmethod
    def _state_command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        """Simulate only four read-only systemctl is-active invocations."""
        assert argv[:2] == ["/usr/bin/systemctl", "is-active"]
        statuses = dict(GOOD_STATES)
        assert argv[2] in statuses
        status = statuses[argv[2]]
        code = 0 if status == "active" else 3
        return subprocess.CompletedProcess(argv, code, (status + "\n").encode(), b"")

    def test_complete_attestation_exposes_only_pins_and_states(self) -> None:
        """Canonical byte strings remain confined to memory, not JSON evidence."""
        evidence = audit.attest_dev_host(self.plan)
        payload = evidence.to_dict()
        self.assertEqual(evidence.selected_source_count, 43)
        self.assertTrue(evidence.prior_source_matches)
        self.assertTrue(evidence.systemd_sandbox_valid)
        self.assertEqual(payload["installed_reviewed_commit"],
                         source_cutover.PRIOR_SOURCE_SHA)
        self.assertEqual(payload["systemd_unit_states"], dict(GOOD_STATES))
        self.assertEqual(payload["broker_config_sha256"],
                         hashlib.sha256(self.broker_bytes).hexdigest())
        text = str(payload)
        self.assertNotIn(self.broker_bytes.decode(), text)
        self.assertNotIn(self.executor_bytes.decode(), text)
        self.assertNotIn("canary_image", text)
        self.assertEqual(
            evidence.source_manifest_sha256, self.plan.target_manifest_sha256
        )

    def test_root_required_before_any_configuration_or_systemd_read(self) -> None:
        """An unapproved process cannot even start the protected attestation."""
        with patch.object(audit, "_require_root",
                          side_effect=audit.DevAttestationHold("root required")):
            with patch.object(audit, "_validated_pair") as confidential:
                with self.assertRaises(audit.DevAttestationHold):
                    audit.attest_dev_host(self.plan)
                confidential.assert_not_called()

    def test_old_broker_source_pin_drift_is_rejected(self) -> None:
        """Read-only evidence cannot bless old configs bound to the wrong source."""
        from deployment.broker_service_config import parse_canonical_broker_service_configuration
        from deployment.executor_service_config import parse_canonical_executor_service_configuration
        b = parse_canonical_broker_service_configuration(self.broker_bytes)
        e = parse_canonical_executor_service_configuration(self.executor_bytes)
        self.b.write_bytes(replace(b, reviewed_commit="b" * 40).canonical_bytes())
        self.e.write_bytes(replace(e, reviewed_commit="b" * 40).canonical_bytes())
        with self.assertRaisesRegex(audit.DevAttestationHold, "HOLD"):
            audit.attest_dev_host(self.plan)

    def test_cross_service_identity_drift_is_rejected(self) -> None:
        """Broker and executor must agree on the complete UID/GID contract."""
        from deployment.executor_service_config import parse_canonical_executor_service_configuration
        e = parse_canonical_executor_service_configuration(self.executor_bytes)
        self.e.write_bytes(replace(e, reviewed_commit="c" * 40).canonical_bytes())
        with self.assertRaises(audit.DevAttestationHold):
            audit.attest_dev_host(self.plan)

    def test_extra_whitespace_and_noncanonical_json_rejected(self) -> None:
        """Do not accept valid JSON with noncanonical trailing content."""
        self.e.write_bytes(self.executor_bytes + b" ")
        with self.assertRaises(audit.DevAttestationHold):
            audit.attest_dev_host(self.plan)

    def test_config_symlink_rejected_without_reading_target(self) -> None:
        """O_NOFOLLOW and regular file checks prohibit parent/path injection."""
        self.b.unlink()
        self.b.symlink_to(self.e)
        with self.assertRaises(audit.DevAttestationHold):
            audit.attest_dev_host(self.plan)

    def test_config_file_permissions_rejected(self) -> None:
        """Unexpected write permissions block the maintenance preflight."""
        self.b.chmod(0o666)
        with self.assertRaises(audit.DevAttestationHold):
            audit.attest_dev_host(self.plan)

    def test_config_dir_permissions_rejected(self) -> None:
        """Writable configuration directory cannot provide trusted evidence."""
        self.e.parent.chmod(0o777)
        with self.assertRaises(audit.DevAttestationHold):
            audit.attest_dev_host(self.plan)

    def test_extra_hardlink_rejected(self) -> None:
        """A protected config must not be multiply linked to another path."""
        linked = self.b.parent / "dev-copy.json"
        os.link(self.b, linked)
        with self.assertRaises(audit.DevAttestationHold):
            audit.attest_dev_host(self.plan)

    def test_rootless_sandbox_drift_not_reported_as_success(self) -> None:
        """If the read-only rootless bind is removed, host preflight HOLDS."""
        altered = dict(GOOD_SYSTEMD, BindReadOnlyPaths="")
        def altered_properties(unit: str, keys: tuple[str, ...]) -> dict[str, str]:
            """Drift only the executor sandbox and preserve broker/socket evidence."""
            original = self._property_command(unit, keys)
            return altered if unit == "omnilyzer-deployment-executor.service" else original

        with patch.object(audit, "_systemctl_properties",
                          side_effect=altered_properties):
            with self.assertRaisesRegex(audit.DevAttestationHold, "HOLD"):
                audit.attest_dev_host(self.plan)

    def test_socket_permissions_or_broker_sandbox_drift_fail_closed(self) -> None:
        """Enforce the reviewed socket group and strict broker sandbox."""
        for unit, changed in (
            ("omnilyzer-deployment-executor.socket", {"SocketMode": "0666"}),
            ("omnilyzer-deployment-broker.service", {"ProtectSystem": "false"}),
        ):
            def changed_properties(name: str, keys: tuple[str, ...]) -> dict[str, str]:
                """Change exactly one fixed systemd property in a synthetic unit."""
                props = self._property_command(name, keys)
                if name == unit:
                    props.update(changed)
                return props

            with self.subTest(unit=unit):
                with patch.object(audit, "_systemctl_properties",
                                  side_effect=changed_properties):
                    with self.assertRaises(audit.DevAttestationHold):
                        audit.attest_dev_host(self.plan)

    def test_cross_service_replay_gid_drift_rejected(self) -> None:
        """A valid but foreign replay group cannot masquerade as installed UID/GID."""
        from deployment.broker_service_config import parse_canonical_broker_service_configuration
        from deployment.executor_service_config import parse_canonical_executor_service_configuration
        broker = parse_canonical_broker_service_configuration(self.broker_bytes)
        executor = parse_canonical_executor_service_configuration(self.executor_bytes)
        self.b.write_bytes(replace(broker, replay_group_gid=998).canonical_bytes())
        self.e.write_bytes(replace(executor, replay_group_gid=998).canonical_bytes())
        with self.assertRaises(audit.DevAttestationHold):
            audit.attest_dev_host(self.plan)

    def test_old_source_mismatch_detected_without_configuration_access(self) -> None:
        """Unreviewed installed source bytes fail before touching private JSON."""
        with (
            patch.object(source_cutover, "_observed_tree", return_value=()),
            patch.object(audit, "_validated_pair") as private_data,
        ):
            with self.assertRaises(audit.DevAttestationHold):
                audit.attest_dev_host(self.plan)
            private_data.assert_not_called()

    def test_unexpected_systemd_property_is_denied(self) -> None:
        """Never allow an arbitrary requested systemd key to expose secrets."""
        with patch.object(audit, "_systemctl_properties", wraps=REAL_SYSTEMCTL_PROPERTIES):
            with self.assertRaises(audit.DevAttestationHold):
                audit._systemctl_properties(
                    "omnilyzer-deployment-executor.service", ("Environment",),
                )

    def test_unexpected_unit_is_denied(self) -> None:
        """Read-only tool must not become a general systemd inspector."""
        with patch.object(audit, "_systemctl_properties", wraps=REAL_SYSTEMCTL_PROPERTIES):
            with self.assertRaises(audit.DevAttestationHold):
                audit._systemctl_properties(
                    "prod-db.service", ("User",),
                )

    def test_nonsecret_evidence_is_immutable(self) -> None:
        """No config bytes or dicts are stored inside the dataclass."""
        evidence = audit.attest_dev_host(self.plan)
        self.assertFalse(any(
            isinstance(getattr(evidence, name), bytes)
            for name in evidence.__dataclass_fields__
        ))


if __name__ == "__main__":
    unittest.main()
