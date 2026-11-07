"""File: services/identity/tests/test_keycloak_public_prod.py
Purpose: Offline safety and regression controls for local-only public-host
    Keycloak installation. No sudo, network, Docker, database or service writes.
Related: services/identity/ops/keycloak_public_prod.py, ADR-0003.
"""
from pathlib import Path
import importlib.util
import io
import os
import tarfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "ops/keycloak_public_prod.py"
SPEC = importlib.util.spec_from_file_location("keycloak_public_prod", SOURCE)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class PublicKeycloakTests(unittest.TestCase):
    """Exercise fail-closed plan and immutable installation boundary."""

    def test_approved_runtime_version_and_archive_digest(self):
        self.assertEqual(MOD.VERSION, "26.8.1")
        self.assertEqual(len(MOD.ARTIFACT_SHA256), 64)
        self.assertEqual(MOD.PUBLIC_HOST, "login.omnilyzer.ai")
        self.assertEqual(MOD.PORT, 18742)
        self.assertEqual(MOD.DB, "omnilyzer_keycloak")

    def test_unit_is_nonroot_private_and_resource_bound(self):
        unit = MOD.service_unit()
        for fragment in ("User=omnilyzer-keycloak",
                         "Group=omnilyzer-keycloak",
                         "EnvironmentFile=/etc/omnilyzer/keycloak/keycloak.env",
                         "MemoryMax=1536M", "NoNewPrivileges=true",
                         "ProtectSystem=strict", "ProtectHome=true",
                         "ProtectControlGroups=true", "Restart=on-failure",
                         "kc.sh start --optimized"):
            self.assertIn(fragment, unit)
        self.assertNotIn("ExecStart=/bin/bash -c", unit)

    def test_no_public_dns_nginx_or_existing_auth_changes(self):
        script = SOURCE.read_text()
        for forbidden in ("cloudflare.request", "certbot certonly",
                          "systemctl restart nginx", "docker compose up",
                          "legacy_users", "analytics_blue"):
            self.assertNotIn(forbidden, script)
        self.assertIn('call(["/usr/bin/systemctl", "start", "omnilyzer-keycloak.service"]',
                      script)

    def test_start_requires_exact_hostname_and_root(self):
        with mock.patch.object(MOD.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "owner-root"):
                MOD.start_local()
        with mock.patch.object(MOD.os, "geteuid", return_value=0), \
             mock.patch.object(MOD.socket, "gethostname", return_value="wrong-server"):
            with self.assertRaisesRegex(RuntimeError, "owner-root"):
                MOD.start_local()

    def test_install_requires_root_before_mutations(self):
        with mock.patch.object(MOD.os, "geteuid", return_value=1000), \
             mock.patch.object(MOD, "call") as run:
            with self.assertRaisesRegex(RuntimeError, "owner-root"):
                MOD.install()
            run.assert_not_called()

    def test_install_aborts_for_all_preflight_mismatches(self):
        with mock.patch.object(MOD.os, "geteuid", return_value=0), \
             mock.patch.object(MOD, "preflight", return_value=["wrong host", "service exists"]), \
             mock.patch.object(MOD, "call") as run:
            with self.assertRaisesRegex(RuntimeError, "wrong host; service exists"):
                MOD.install()
            run.assert_not_called()

    def test_archive_rejects_symlink_and_path_traversal(self):
        def make(malicious):
            buffer=io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as t:
                for index in range(310):
                    f=tarfile.TarInfo("keycloak-26.8.1/safe-" + str(index))
                    f.size=0
                    t.addfile(f, io.BytesIO())
                f=tarfile.TarInfo(malicious)
                f.size=0
                t.addfile(f, io.BytesIO())
            return buffer.getvalue()
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            MOD.archive_layout(make("keycloak-26.8.1/../../etc/passwd"))
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            MOD.archive_layout(make("/absolute/path"))

    def test_archive_refuses_symlink_even_inside_release(self):
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode="w:gz") as t:
            for i in range(310):
                f=tarfile.TarInfo("keycloak-26.8.1/file-" + str(i))
                t.addfile(f,io.BytesIO())
            link=tarfile.TarInfo("keycloak-26.8.1/link")
            link.type=tarfile.SYMTYPE
            link.linkname="/etc/passwd"
            t.addfile(link)
        with self.assertRaisesRegex(RuntimeError,"unsafe"):
            MOD.archive_layout(buf.getvalue())


    def test_metrics_repair_preflight_fails_without_changes(self):
        """Any detected host mismatch fails closed before file edits."""
        with mock.patch.object(MOD, "metrics_repair_plan",
                               return_value=["unexpected unit", "active service"]), \
             mock.patch.object(MOD, "replace_file_atomic") as replace:
            with self.assertRaisesRegex(RuntimeError, "preflight failed"):
                MOD.repair_metrics_only()
            replace.assert_not_called()

    def test_metrics_repair_preserves_unrelated_config_and_disables_restart(self):
        """Keep nonsecret environment bytes untouched without opening service."""
        import tempfile
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            env = root / "keycloak.env"
            unit = root / "omnilyzer-keycloak.service"
            preserved = b"KC_LOG_LEVEL=info\n"
            contents = preserved + b"KC_METRICS_ENABLED=false\nKC_HTTP_PORT=18742\n"
            # Private file mode is established at creation, before any write.
            fd = os.open(env, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(contents)
            unit.write_bytes(MOD.service_unit().encode("utf-8"))
            unit.chmod(0o644)
            with mock.patch.object(MOD, "ENV", env), \
                 mock.patch.object(MOD, "UNIT", unit), \
                 mock.patch.object(MOD, "metrics_repair_plan", return_value=[]), \
                 mock.patch.object(MOD, "call") as call:
                MOD.repair_metrics_only()
                self.assertEqual(call.call_args_list,
                                 [mock.call(["/usr/bin/systemctl", "daemon-reload"])])
            self.assertEqual(env.read_bytes(), preserved + b"KC_HTTP_PORT=18742\n")
            self.assertEqual((root / "keycloak.env.m01-pre-metrics-repair").read_bytes(),
                             contents)
            self.assertEqual((root / "omnilyzer-keycloak.service.m01-pre-metrics-repair").read_bytes(),
                             MOD.service_unit().encode("utf-8"))
            self.assertEqual(env.stat().st_mode & 0o777, 0o600)
            self.assertEqual(unit.stat().st_mode & 0o777, 0o644)
            self.assertEqual((root / "keycloak.env.m01-pre-metrics-repair").stat().st_mode & 0o777,
                             0o600)
            self.assertIn("Restart=no", unit.read_text())
            self.assertNotIn("Restart=on-failure", unit.read_text())

    def test_metrics_repair_requires_exact_single_setting(self):
        """A missing, duplicated or non-canonical metrics assignment is a HOLD."""
        import tempfile
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            env = root / "keycloak.env"
            unit = root / "omnilyzer-keycloak.service"
            unit.write_bytes(MOD.service_unit().encode())
            for bad in (b"KC_METRICS_ENABLED=true\n", b"",
                        b"KC_METRICS_ENABLED=false\nKC_METRICS_ENABLED=false\n"):
                env.write_bytes(bad)
                with mock.patch.object(MOD, "ENV", env), \
                     mock.patch.object(MOD, "UNIT", unit), \
                     mock.patch.object(MOD, "metrics_repair_plan", return_value=[]), \
                     mock.patch.object(MOD, "call") as call:
                    with self.assertRaisesRegex(RuntimeError,
                                                "metrics value must appear exactly once"):
                        MOD.repair_metrics_only()
                    call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
