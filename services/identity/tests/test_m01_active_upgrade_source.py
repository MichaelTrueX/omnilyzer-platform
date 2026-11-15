"""File: services/identity/tests/test_m01_active_upgrade_source.py

Purpose: Check exact Git source archive, immutable successor systemd pins,
    explicit Product Owner GO, and fail-closed source-only operator behavior
    without connecting to production or invoking privileged service commands.
Related: services/identity/ops/m01_active_bff_upgrade_once.py,
    services/identity/omnilyzer-identity.service, PR243 exact 98d74f4.

No real session cookie, identity token, privileged host secret, DB connection,
systemd service change, NGINX reload or learner data is used in these tests.
"""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import json

# Section: Load the operator as code without executing its guarded entrypoint.
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ops" / "m01_active_bff_upgrade_once.py"
SPEC = importlib.util.spec_from_file_location("m01_active_upgrade", SOURCE)
UP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UP)


class SourceOnlyActiveUpgradeTests(unittest.TestCase):
    """Test deterministic source and safety gates at exact PR243 SHA."""

    def test_exact_pins_and_offline_source_sha(self):
        """All executable identity code has an approved immutable version."""
        self.assertEqual(UP.NEW_SHA, "98d74f4093d854ac401d8cb754b1fb40dab007d5")
        self.assertEqual(UP.OLD_SHA, "3481cacbef910a37d87a3c26341b1a8f16a6612f")
        self.assertEqual(UP.SOURCE_ARCHIVE_SHA256,
            "c9d74a9dbadfd6ef4250d74bc5978768fbd903db07037a9f36a3a33d94f405cb")
        self.assertEqual(UP.SOURCE_ARCHIVE_BYTES, 573440)
        self.assertEqual(UP.GO_SCOPE, "M01_PRIVATE_BFF_98D74_UPGRADE_GO")

    def test_exact_source_file_archive_is_read_only_and_bounded(self):
        """Validate the real source-only archive created from canonical Git."""
        if not UP.ARCHIVE.is_file():
            self.skipTest("external source-only Git archive not staged on this runner")
        self.assertEqual(len(UP.validate_archive()), 60)

    def test_one_byte_archive_mutation_fails_closed(self):
        """A changed owner-owned tar must not be accepted by a privileged op."""
        with tempfile.TemporaryDirectory(prefix="m01-review-") as d:
            folder = Path(d)
            folder.chmod(0o700)
            p = folder / "identity-source-98d74f4.tar"
            p.write_bytes(b"not reviewed git source")
            p.chmod(0o400)
            # GitHub runners lack the PROD account. Stub only that UID
            # lookup; retain actual temp-file ownership and hash checks.
            with mock.patch.object(UP.pwd, "getpwnam",
                                   return_value=mock.Mock(pw_uid=os.getuid())):
                with mock.patch.object(UP, "ARCHIVE", p):
                    with self.assertRaisesRegex(UP.UpgradeHold,
                                                "REVIEWED_SOURCE_ARCHIVE_SHA_MISMATCH"):
                        UP.validate_archive()

    def test_derive_unit_changes_only_four_exact_version_pins(self):
        """Full candidate unit retains every existing restriction except SHA."""
        old = (ROOT / "omnilyzer-identity.service").read_bytes()
        new = UP.proposed_unit(old)
        self.assertEqual(new.count(UP.NEW_SHA.encode()), 4)
        self.assertNotIn(UP.OLD_SHA.encode(), new)
        self.assertEqual(hashlib.sha256(new).hexdigest(), UP.NEW_UNIT_SHA256)
        self.assertEqual(new.replace(UP.NEW_SHA.encode(),
                                     UP.OLD_SHA.encode()), old)
        for required in (b"User=omnilyzer-identity", b"ProtectSystem=strict",
                         b"NoNewPrivileges=yes", b"--bind 127.0.0.1:18740",
                         b"ExecCondition=/usr/bin/test",
                         b"EnvironmentFile=/etc/omnilyzer/identity/identity.env"):
            self.assertIn(required, new)

    def test_unexpected_template_refused(self):
        """Unit generator rejects changed source SHA or missing protected guard."""
        original = (ROOT / "omnilyzer-identity.service").read_bytes()
        with self.assertRaisesRegex(UP.UpgradeHold, "CURRENT_UNIT_SOURCE_MISMATCH"):
            UP.proposed_unit(original + b"\n# unreviewed change\n")

    def test_wrong_or_absent_owner_go_never_permits_stage_or_apply(self):
        """Plain 'continue' cannot authorize a protected root/runtime change."""
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(UP.UpgradeHold,
                                        "EXPLICIT_BFF_RUNTIME_OWNER_GO_MISSING"):
                UP.explicit_go()
        with mock.patch.dict(os.environ, {
            "M01_OWNER_GO_SCOPE": "PROD_MIGRATION_108_109_110_GO",
            "M01_OWNER_GO_SOURCE_SHA": UP.NEW_SHA,
            "M01_OWNER_GO_ARCHIVE_SHA256": UP.SOURCE_ARCHIVE_SHA256,
        }, clear=True):
            with self.assertRaises(UP.UpgradeHold):
                UP.explicit_go()
        with mock.patch.dict(os.environ, {
            "M01_OWNER_GO_SCOPE": UP.GO_SCOPE,
            "M01_OWNER_GO_SOURCE_SHA": UP.NEW_SHA,
            "M01_OWNER_GO_ARCHIVE_SHA256": UP.SOURCE_ARCHIVE_SHA256,
        }, clear=True):
            UP.explicit_go()

    def test_preflight_calls_read_only_gates_not_stage_or_apply(self):
        """Non-mutating preflight has no path to privileged cutover helpers."""
        with mock.patch.object(UP, "validate_archive", return_value=[] ) as archive, \
             mock.patch.object(UP, "validate_live_before_upgrade",
                               return_value=(123, 456)) as live, \
             mock.patch.object(UP, "stage_new_release") as stage, \
             mock.patch.object(UP, "apply_once") as apply, \
             mock.patch("sys.argv", [str(SOURCE), "preflight"]):
            UP.main()
        archive.assert_called_once()
        live.assert_called_once()
        stage.assert_not_called()
        apply.assert_not_called()

    def test_operator_cannot_be_executed_as_user_owned_root_copy(self):
        """A root operation must not run from this developer-controlled path."""
        with mock.patch.object(UP.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(UP.UpgradeHold, "ROOT_OPERATOR_MUST_USE_FIXED_PATH"):
                UP.root_operator()

    def _exercise_synthetic_apply(self, *, injected_failure):
        """Exercise original file/unit switching with mocked systemd and HTTP.

        This is a disposable unprivileged filesystem test, not real systemd
        or actual Keycloak session continuity. Root checks stay in production.
        """
        with tempfile.TemporaryDirectory(prefix="m01-upgrade-unit-") as scratch:
            d = Path(scratch)
            old = d / UP.OLD_SHA
            new = d / UP.NEW_SHA
            old.mkdir()
            new.mkdir()
            original = (ROOT / "omnilyzer-identity.service").read_bytes()
            (new / "m01-reviewed-upgrade.service").write_bytes(
                UP.proposed_unit(original))
            unit = d / "omnilyzer-identity.service"
            unit.write_bytes(original)
            unit.chmod(0o644)
            current = d / "current"
            current.symlink_to(old)
            receipts = d / "receipts"
            receipts.mkdir(mode=0o700)
            vhost = d / "app.sumlaude.com.conf"
            vhost.write_text("synthetic existing private vhost\n")
            marker = d / "owner-approved-go"
            actions = []
            first_start_failure = [injected_failure]

            def fake_command(args, **kwargs):
                actions.append(tuple(args))
                if (args[:3] == ["/usr/bin/systemctl", "start", UP.SERVICE]
                        and first_start_failure[0]):
                    first_start_failure[0] = False
                    raise UP.UpgradeHold("INJECTED_NEW_SERVICE_START_FAILURE")
                return ""

            def fake_systemd(prop, service=UP.SERVICE):
                if prop == "MainPID":
                    return "222" if service == UP.NATIVE else "333"
                if prop == "WorkingDirectory":
                    return str(new / "services/identity")
                if prop == "NeedDaemonReload":
                    return "no"
                if prop == "UnitFileState":
                    return "enabled"
                raise AssertionError((prop, service))

            def fake_readiness(target=UP.NEW, **kwargs):
                if target == UP.OLD:
                    self.assertEqual(current.resolve(), old)
                    return 111
                self.assertEqual(current.resolve(), new)
                return 333

            with (
                mock.patch.object(UP, "OLD", old),
                mock.patch.object(UP, "NEW", new),
                mock.patch.object(UP, "UNIT", unit),
                mock.patch.object(UP, "CURRENT", current),
                mock.patch.object(UP, "RECEIPTS", receipts),
                mock.patch.object(UP, "VHOST", vhost),
                mock.patch.object(UP, "GO_MARKER", marker),
                mock.patch.object(UP, "OLD_VHOST_SHA256",
                                  hashlib.sha256(vhost.read_bytes()).hexdigest()),
                mock.patch.object(UP, "root_operator"),
                mock.patch.object(UP, "explicit_go"),
                mock.patch.object(UP, "staged_proof"),
                mock.patch.object(UP, "validate_live_before_upgrade",
                                  return_value=(111, 222)),
                mock.patch.object(UP, "command", side_effect=fake_command),
                mock.patch.object(UP, "systemd", side_effect=fake_systemd),
                mock.patch.object(UP, "service_active", return_value="active"),
                mock.patch.object(UP, "private_http_ready",
                                  side_effect=fake_readiness),
            ):
                if injected_failure:
                    with self.assertRaisesRegex(
                        UP.UpgradeHold, "INJECTED_NEW_SERVICE_START_FAILURE"):
                        UP.apply_once()
                    self.assertEqual(current.resolve(), old)
                    self.assertEqual(hashlib.sha256(unit.read_bytes()).hexdigest(),
                                     UP.OLD_UNIT_SHA256)
                    self.assertTrue((receipts / "rollback.json").is_file())
                    self.assertFalse((receipts / "applied.json").exists())
                    self.assertFalse(marker.exists())
                else:
                    UP.apply_once()
                    self.assertEqual(current.resolve(), new)
                    self.assertEqual(hashlib.sha256(unit.read_bytes()).hexdigest(),
                                     UP.NEW_UNIT_SHA256)
                    applied = json.loads((receipts / "applied.json").read_text())
                    self.assertEqual(applied["new_release"], UP.NEW_SHA)
                    self.assertFalse((receipts / "rollback.json").exists())
                    self.assertTrue(marker.exists())
                self.assertTrue((receipts / "apply-started").is_file())
                self.assertTrue((receipts / "previous-unit").is_file())
            self.assertTrue(any(x[:2] == ("/usr/bin/systemctl", "stop")
                                for x in actions))
            self.assertTrue(any(x[:2] == ("/usr/bin/systemctl", "start")
                                for x in actions))

    def test_synthetic_success_preserves_only_new_selected_unit(self):
        """One-shot committed synthetic BFF cutover retains exact receipts."""
        self._exercise_synthetic_apply(injected_failure=False)

    def test_synthetic_failed_new_start_restores_old_active_source(self):
        """A failed synthetic new systemd start restores unit and link."""
        self._exercise_synthetic_apply(injected_failure=True)

    def test_stop_and_rollback_paths_are_bounded(self):
        """Only root-owned old active BFF can be restarted, not legacy Native."""
        s = SOURCE.read_text()
        self.assertIn('["/usr/bin/systemctl", "stop", SERVICE]', s)
        self.assertIn('["/usr/bin/systemctl", "start", SERVICE]', s)
        self.assertNotIn('["/usr/bin/systemctl", "stop", NATIVE]', s)
        self.assertNotIn('["/usr/bin/systemctl", "start", NATIVE]', s)
        self.assertIn('"--noproxy", "*"', s)
        self.assertIn('"app.sumlaude.com:443:127.0.0.1"', s)
        self.assertIn('"ONE_SHOT_MUTATION_START', s)
        self.assertIn("ONE_SHOT_APPLY_ALREADY_ATTEMPTED_NO_REPLAY", s)


if __name__ == "__main__":
    unittest.main(verbosity=2)
