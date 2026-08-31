"""Static security and architecture policy tests for Task 011."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
COMPOSE = (ROOT / "compose.yaml").read_text()
GRAFANA = (ROOT / "grafana" / "grafana.ini").read_text()
DATASOURCE = (ROOT / "grafana" / "provisioning" / "datasources" / "prometheus.yaml").read_text()
PROVIDER = (ROOT / "grafana" / "provisioning" / "dashboards" / "provider.yaml").read_text()
VALIDATOR = (ROOT / "validate_live.py").read_text()


class ContainerPolicyTests(unittest.TestCase):
    def test_exact_oss_image_and_digest(self) -> None:
        expected = "grafana/grafana:13.2.0@sha256:3fd54ae1214669f8355f065ec9f6445d5279a3d77095ab048ca045685272429b"
        self.assertIn(expected, COMPOSE)
        self.assertNotIn("grafana/grafana-oss", COMPOSE)
        self.assertNotRegex(COMPOSE, r"grafana/grafana:(latest|13|13\.2)(?:\s|@)")

    def test_only_in_scope_services(self) -> None:
        services = re.findall(r"^  ([a-z][a-z0-9-]+):\n", COMPOSE, re.MULTILINE)
        self.assertEqual(services[:4], ["synthetic-app", "prometheus", "grafana", "keycloak"])
        forbidden = ("loki", "tempo", "jaeger", "alloy", "alertmanager", "mimir", "thanos", "victoriametrics", "elasticsearch", "kafka", "kubernetes")
        compose_lower = COMPOSE.lower()
        for name in forbidden:
            self.assertNotIn(f"  {name}:", compose_lower)

    def test_private_metrics_network(self) -> None:
        self.assertRegex(COMPOSE, r"application-metrics:\n    internal: true")
        self.assertRegex(COMPOSE, r"metrics-visualization:\n    internal: true")
        self.assertIn('"127.0.0.1:${TASK011_GRAFANA_PORT:-19130}:3000"', COMPOSE)
        prometheus_block = COMPOSE.split("  prometheus:", 1)[1].split("  grafana:", 1)[0]
        app_block = COMPOSE.split("  synthetic-app:", 1)[1].split("  prometheus:", 1)[0]
        self.assertNotIn("ports:", prometheus_block)
        self.assertNotIn("ports:", app_block)
        self.assertNotRegex(COMPOSE, r'-\s+"0\.0\.0\.0:')

    def test_runtime_only_secrets(self) -> None:
        for variable in (
            "TASK011_GRAFANA_ADMIN_PASSWORD", "TASK011_GRAFANA_SECRET_KEY",
            "TASK011_OAUTH_CLIENT_SECRET", "TASK011_KEYCLOAK_ADMIN_PASSWORD",
            "TASK011_REALM_FILE",
        ):
            self.assertIn(f"${{{variable}:?", COMPOSE)
        self.assertNotIn("admin/admin", COMPOSE.lower())
        self.assertNotRegex(COMPOSE, r"(?i)(password|client_secret):\s+[A-Za-z0-9_-]{16,}")

    def test_runtime_artifact_modes_are_exact_and_fail_closed(self) -> None:
        self.assertIn("os.chmod(runtime, 0o700)", VALIDATOR)
        self.assertIn("os.chmod(realm, 0o600)", VALIDATOR)
        self.assertIn("os.chmod(env_file, 0o600)", VALIDATOR)
        self.assertIn("os.chmod(private_key, 0o600)", VALIDATOR)
        self.assertNotIn("os.chmod(private_key, 0o644)", VALIDATOR)
        self.assertIn("os.chmod(certificate, 0o644)", VALIDATOR)
        self.assertIn("stat.S_IMODE(path.stat().st_mode)", VALIDATOR)
        self.assertIn("runtime artifact modes fail closed", VALIDATOR)


class GrafanaSecurityPolicyTests(unittest.TestCase):
    def test_authentication_fails_closed(self) -> None:
        required = (
            "[auth.anonymous]\nenabled = false",
            "[auth.basic]\nenabled = false",
            "disable_login_form = true",
            "allow_sign_up = false",
            "role_attribute_strict = true",
            "allow_assign_grafana_admin = false",
        )
        for value in required:
            self.assertIn(value, GRAFANA)
        role_line = next(line for line in GRAFANA.splitlines() if line.startswith("role_attribute_path"))
        self.assertNotIn("|| 'Viewer'", role_line)
        self.assertNotIn("|| 'None'", role_line)

    def test_public_sharing_and_embedding_are_disabled(self) -> None:
        self.assertIn("allow_embedding = false", GRAFANA)
        self.assertIn("[public_dashboards]\nenabled = false", GRAFANA)
        self.assertIn("[snapshots]\nenabled = false", GRAFANA)
        self.assertIn("external_enabled = false", GRAFANA)
        self.assertIn("public_mode = false", GRAFANA)
        self.assertNotIn("Access-Control-Allow-Origin", GRAFANA)

    def test_no_downloaded_plugins_or_enterprise_configuration(self) -> None:
        self.assertIn("plugin_admin_enabled = false", GRAFANA)
        self.assertIn("preinstall_disabled = true", GRAFANA)
        self.assertNotIn("[enterprise]", GRAFANA)
        self.assertNotIn("license_token", GRAFANA)

    def test_independent_exact_role_mapping(self) -> None:
        for group, role in (("/grafana-viewers", "Viewer"), ("/grafana-editors", "Editor"), ("/grafana-admins", "Admin")):
            self.assertIn(group, GRAFANA)
            self.assertIn(f"'{role}'", GRAFANA)
        self.assertNotIn("workspace", GRAFANA.lower())
        self.assertNotIn("tenant", GRAFANA.lower())

    def test_datasource_is_server_side_and_noneditable(self) -> None:
        self.assertIn("uid: omnilyzer-prometheus", DATASOURCE)
        self.assertIn("access: proxy", DATASOURCE)
        self.assertIn("url: http://prometheus:9090", DATASOURCE)
        self.assertIn("editable: false", DATASOURCE)
        self.assertNotIn("basicAuth: true", DATASOURCE)
        self.assertNotIn("withCredentials: true", DATASOURCE)

    def test_dashboard_is_reproducibly_provisioned(self) -> None:
        dashboard = json.loads((ROOT / "grafana" / "dashboards" / "operations.json").read_text())
        self.assertEqual(dashboard["uid"], "task011-operations")
        self.assertEqual(PROVIDER.count("folderUid: omnilyzer-operations"), 1)
        expressions = [target["expr"] for panel in dashboard["panels"] for target in panel["targets"]]
        self.assertTrue(any('product="valoria"' in expression for expression in expressions))
        self.assertFalse(any("omnilyzer_telemetry_export_failures_total" in expression for expression in expressions))

    def test_negative_and_failure_tests_are_real(self) -> None:
        required = (
            "Viewer arbitrary datasource query", "strict role mapping did not deny unmapped user",
            "organization Admin datasource create", "Grafana restarted during Prometheus outage",
            "application failed during Grafana outage", "fresh provisioned datasource",
        )
        for value in required:
            self.assertIn(value, VALIDATOR)


class MetricsFixtureTests(unittest.TestCase):
    def test_accepted_metric_names_and_bounded_labels(self) -> None:
        source = (ROOT / "target_app.py").read_text()
        for metric in (
            "omnilyzer_http_requests_total", "omnilyzer_http_request_duration_seconds",
            "omnilyzer_build_info", "omnilyzer_telemetry_export_failures_total",
        ):
            self.assertIn(metric, source)
        request_label_line = 'base = dict(service=service, product=product, environment=environment, method="GET", route="/api/users/{id}", status_class="2xx")'
        self.assertIn(request_label_line, source)
        for forbidden in ("workspace_id=", "user_id=", "request_id=", "trace_id=", "authorization="):
            self.assertNotIn(forbidden, source.lower())


if __name__ == "__main__":
    unittest.main()
