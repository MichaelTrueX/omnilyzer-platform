"""File: services/identity/tests/test_keycloak_private_dev.py
Purpose: Test isolated Keycloak deployment contract without Docker, network,
    credentials or production infrastructure changes.
Related: services/identity/ops/keycloak_private_dev.py,
    services/identity/config/settings.py and ADR-0003.
"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SRC = Path(__file__).resolve().parents[1] / "ops" / "keycloak_private_dev.py"
SPEC = importlib.util.spec_from_file_location("keycloak_private_dev", SRC)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class KeycloakPrivateDevTests(unittest.TestCase):
    """Run offline checks for pinned images, secrets, realm and fail-closed plans."""

    def test_dev_client_is_confidential_pkce_and_no_public_registration(self):
        spec = MOD.realm("test-only-secret")
        self.assertEqual(spec["realm"], "omnilyzer-dev")
        self.assertIs(spec["registrationAllowed"], False)
        client = spec["clients"][0]
        self.assertIs(client["publicClient"], False)
        self.assertIs(client["directAccessGrantsEnabled"], False)
        self.assertIs(client["implicitFlowEnabled"], False)
        self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")
        self.assertEqual(client["redirectUris"], ["https://app.sumlaude.com/auth/callback"])
        self.assertEqual(client["secret"], "test-only-secret")

    def test_only_loopback_keycloak_and_no_published_postgres(self):
        compose = MOD.COMPOSE
        self.assertIn('"127.0.0.1:18080:8080"', compose)
        self.assertNotIn("0.0.0.0:18080", compose)
        self.assertIn("private-db:\n    internal: true", compose)
        self.assertIn("--import-realm", compose)
        self.assertIn('command: ["start", "--import-realm"]', compose)
        self.assertNotIn("start-dev", compose)
        database = compose.split("  keycloak-db:", 1)[1].split("  keycloak:", 1)[0]
        self.assertNotIn("ports:", database)
        self.assertNotIn("POSTGRES_HOST_AUTH_METHOD: trust", compose)
        self.assertIn("pull_policy: never", compose)

    def test_known_image_ids_and_no_unpinned_latest(self):
        self.assertEqual(len(MOD.IMAGE_IDS), 2)
        self.assertTrue(all(x.startswith("sha256:") and len(x) == 71
                            for x in MOD.IMAGE_IDS.values()))
        self.assertNotIn(":latest", MOD.COMPOSE)

    def test_plan_rejects_wrong_local_image(self):
        with mock.patch.object(MOD.os, "geteuid", return_value=1000), \
             mock.patch.object(MOD.shutil, "disk_usage", return_value=mock.Mock(free=20 * 1024**3)), \
             mock.patch.object(MOD, "run", side_effect=[mock.Mock(stdout=""), mock.Mock(stdout="sha256:wrong")]):
            with self.assertRaisesRegex(RuntimeError, "Docker image differs"):
                MOD.plan()

    def test_plan_rejects_root(self):
        with mock.patch.object(MOD.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "not root"):
                MOD.plan()

    def test_prepare_writes_private_files_without_real_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "private-runtime"
            with mock.patch.object(MOD, "BASE", root), \
                 mock.patch.object(MOD, "plan", return_value={"preflight": "ok"}):
                result = MOD.prepare()
            self.assertEqual(result["runtime_dir"], str(root))
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            for f in (".env", "realm.json", "compose.yaml"):
                self.assertEqual((root / f).stat().st_mode & 0o777, 0o600)
            env = (root / ".env").read_text()
            self.assertIn("KEYCLOAK_DB_PASSWORD=", env)
            self.assertIn("KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD=", env)
            realm = json.loads((root / "realm.json").read_text())
            self.assertTrue(len(realm["clients"][0]["secret"]) >= 48)
            self.assertNotIn(realm["clients"][0]["secret"], MOD.COMPOSE)
            self.assertNotIn(env.split("KEYCLOAK_DB_PASSWORD=",1)[1].splitlines()[0], MOD.COMPOSE)

    def test_plan_rejects_wrong_image_before_state_changes(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(MOD, "BASE", Path(root)), \
                 mock.patch.object(MOD.os, "geteuid", return_value=1000), \
                 mock.patch.object(MOD, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "Docker image differs"):
                    with mock.patch.object(MOD.shutil, "disk_usage", return_value=mock.Mock(free=20 * 1024**3)):
                        MOD.plan()
                self.assertEqual(run.call_count, 2)

    def test_no_activation_if_prepared_runtime_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "missing"
            with mock.patch.object(MOD, "BASE", root), mock.patch.object(MOD, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "missing or invalid"):
                    MOD.activate()
                run.assert_not_called()

    def test_activation_refuses_altered_compose(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            root.mkdir(mode=0o700)
            for file, value in ((".env", "x"), ("realm.json", "{}"), ("compose.yaml", "unsafe")):
                (root / file).write_text(value)
                (root / file).chmod(0o600)
            with mock.patch.object(MOD, "BASE", root), mock.patch.object(MOD, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "compose bytes"):
                    MOD.activate()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
