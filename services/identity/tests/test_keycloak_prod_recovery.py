"""File: services/identity/tests/test_keycloak_prod_recovery.py
Purpose: Offline focused tests for one-time Keycloak production backup,
    disposable restore verification and bounded systemd boot recovery.
Related: services/identity/ops/keycloak_prod_recovery.py,
    services/identity/ops/keycloak_public_prod.py, SECURITY.md.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "ops" / "keycloak_prod_recovery.py"
SPEC = importlib.util.spec_from_file_location("keycloak_prod_recovery", SOURCE)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

ORIGINAL_UNIT = """# File: /etc/systemd/system/omnilyzer-keycloak.service
# Purpose: Dedicated Keycloak 26.8.1 production issuer backend, local-only.
# Related: /etc/omnilyzer/keycloak/keycloak.env, /opt/omnilyzer/keycloak/current
[Unit]
Description=Omnilyzer native Keycloak OIDC issuer (production localhost)
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service
[Service]
Type=simple
User=omnilyzer-keycloak
Group=omnilyzer-keycloak
WorkingDirectory=/opt/omnilyzer/keycloak/current
EnvironmentFile=/etc/omnilyzer/keycloak/keycloak.env
ExecStart=/opt/omnilyzer/keycloak/current/bin/kc.sh start --optimized
Restart=no
RestartSec=15
TimeoutStartSec=180
LimitNOFILE=10240
MemoryMax=1536M
TasksMax=512
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/opt/omnilyzer/keycloak/releases/26.8.1/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
[Install]
WantedBy=multi-user.target
"""


class KeycloakRecoveryTests(unittest.TestCase):
    """No network, no root and no real database mutations."""

    def test_unit_updates_only_restart_and_limit(self):
        updated = MOD.next_unit(ORIGINAL_UNIT)
        self.assertEqual(updated, ORIGINAL_UNIT.replace(
            "[Unit]\n", "[Unit]\nStartLimitIntervalSec=infinity\nStartLimitBurst=3\n",
            1).replace("Restart=no\n", "Restart=on-failure\nRestartSec=20\n", 1))
        self.assertIn("MemoryMax=1536M", updated)
        self.assertIn("ProtectSystem=strict", updated)
        self.assertIn("User=omnilyzer-keycloak", updated)

    def test_existing_restart_policy_or_modified_identity_unit_refused(self):
        for modified in (
            ORIGINAL_UNIT.replace("Restart=no", "Restart=always"),
            ORIGINAL_UNIT.replace("User=omnilyzer-keycloak", "User=root"),
            ORIGINAL_UNIT.replace("Restart=no", "Restart=no\nStartLimitBurst=5"),
            ORIGINAL_UNIT.replace("EnvironmentFile=/etc/omnilyzer/keycloak/keycloak.env",
                                  "EnvironmentFile=/tmp/unsafe.env"),
        ):
            with self.assertRaises(RuntimeError):
                MOD.next_unit(modified)

    def test_preflight_fail_closed_before_backup_and_enable(self):
        with mock.patch.object(MOD, "preflight", return_value=["wrong owner"]), \
             mock.patch.object(MOD, "backup_files") as backup, \
             mock.patch.object(MOD, "enable_service") as enable:
            with self.assertRaisesRegex(RuntimeError, "wrong owner"):
                MOD.execute()
            backup.assert_not_called()
            enable.assert_not_called()

    def test_private_file_created_0600_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "credentials.env"
            MOD.private_file(target, b"TEST_ONLY_KEY=not_a_secret\n")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                MOD.private_file(target, b"other")
            self.assertEqual(target.read_bytes(), b"TEST_ONLY_KEY=not_a_secret\n")

    def test_restore_cleanup_always_drops_temporary_database(self):
        import subprocess
        import io
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "test.pgcustom"
            archive.write_bytes(b"PGDMP" + b"x" * 200)
            events = []
            def fake_pg(*argv, **kwargs):
                events.append(argv[0])
                if argv[0].endswith("pg_restore"):
                    raise subprocess.CalledProcessError(1, argv)
                return mock.Mock(stdout=b"")
            with mock.patch.object(MOD, "pg", side_effect=fake_pg):
                with self.assertRaises(subprocess.CalledProcessError):
                    MOD.restore_verify(archive)
            self.assertEqual(events[0], "/usr/bin/createdb")
            self.assertEqual(events[1], "/usr/bin/pg_restore")
            self.assertEqual(events[2], "/usr/bin/dropdb")

    def test_service_unit_does_not_change_other_products(self):
        source = SOURCE.read_text()
        for bad in ("systemctl restart nginx", "systemctl restart postgresql",
                    "systemctl restart omnilyzer-keycloak",
                    "docker compose", "CREATE DATABASE omnilyzer",
                    "cloudflare.request", "tailscale serve", "kc.sh start-dev"):
            self.assertNotIn(bad, source)
        self.assertIn('"/usr/bin/systemctl", "enable", "omnilyzer-keycloak.service"', source)
        self.assertNotIn('"/usr/bin/systemctl", "start", "omnilyzer-keycloak.service"', source)


if __name__ == "__main__":
    unittest.main()
