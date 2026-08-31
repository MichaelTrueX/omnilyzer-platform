"""Machine-readable Task 011 evidence assertions."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


RESULT = json.loads((Path(__file__).resolve().parents[1] / "results" / "live-validation.json").read_text())


class EvidenceTests(unittest.TestCase):
    def test_classification_and_exact_technology(self) -> None:
        self.assertEqual(RESULT["classification"], "TASK 011 - PASS WITH EXPLICIT AUTHORIZATION BOUNDARY")
        grafana = RESULT["technology"]["grafana"]
        self.assertEqual(grafana["version"], "13.2.0")
        self.assertEqual(grafana["edition"], "OSS")
        self.assertEqual(grafana["digest"], "sha256:3fd54ae1214669f8355f065ec9f6445d5279a3d77095ab048ca045685272429b")

    def test_network_and_anonymous_boundaries(self) -> None:
        self.assertEqual(RESULT["network"]["prometheus_host_published_ports"], 0)
        self.assertEqual(RESULT["network"]["synthetic_app_host_published_ports"], 0)
        self.assertEqual(RESULT["network"]["grafana_host_binding"], "127.0.0.1:19130")
        self.assertFalse(RESULT["anonymous_and_browser_surface"]["anonymous_auth"])
        self.assertFalse(RESULT["anonymous_and_browser_surface"]["wildcard_cors"])
        self.assertEqual(RESULT["anonymous_and_browser_surface"]["x_frame_options"].lower(), "deny")

    def test_strict_roles_and_server_admin_boundary(self) -> None:
        roles = RESULT["authorization"]["roles"]
        self.assertEqual([roles[name]["org_role"] for name in ("viewer", "editor", "admin")], ["Viewer", "Editor", "Admin"])
        self.assertTrue(all(not role["is_grafana_admin"] for role in roles.values()))
        self.assertTrue(RESULT["authorization"]["unmapped_user"]["login_denied"])
        self.assertTrue(all(status == 403 for status in RESULT["authorization"]["server_admin_endpoint_statuses"].values()))

    def test_capability_and_datasource_boundaries(self) -> None:
        capabilities = RESULT["authorization"]["capabilities"]
        self.assertFalse(capabilities["viewer"]["dashboard_edit"])
        self.assertTrue(capabilities["editor"]["dashboard_edit"])
        self.assertFalse(capabilities["viewer"]["datasource_create"])
        self.assertFalse(capabilities["editor"]["datasource_create"])
        self.assertTrue(capabilities["organization_admin"]["datasource_create"])
        self.assertFalse(capabilities["organization_admin"]["provisioned_datasource_edit"])
        self.assertFalse(capabilities["organization_admin"]["provisioned_datasource_delete"])

    def test_viewer_query_authorization_boundary_is_explicit(self) -> None:
        finding = RESULT["authorization"]["viewer_arbitrary_promql"]
        self.assertTrue(finding["query_succeeded"])
        self.assertNotEqual(finding["dashboard_expression"], finding["different_expression"])
        self.assertEqual(RESULT["oss_boundaries"]["shared_datasource_fine_grained_isolation"], "not provided by Grafana OSS")

    def test_failure_isolation_and_recovery(self) -> None:
        prometheus = RESULT["prometheus_outage"]
        self.assertEqual([prometheus["application_domain_status"], prometheus["livez_status"], prometheus["readyz_status"]], [200, 200, 200])
        self.assertFalse(prometheus["grafana_restarted"])
        self.assertTrue(prometheus["query_failed_visibly"] and prometheus["query_recovered"])
        grafana = RESULT["grafana_outage"]
        self.assertEqual(grafana["prometheus_target_up"], 1)
        self.assertTrue(grafana["metrics_count_increased"] and grafana["query_recovered"])
        keycloak = RESULT["keycloak_outage"]
        self.assertEqual(keycloak["existing_session_status"], 200)
        self.assertTrue(keycloak["new_login_failed_cleanly"] and keycloak["new_login_recovered"])

    def test_provisioning_secrets_and_oss_limits(self) -> None:
        self.assertTrue(RESULT["provisioning"]["fresh_database_recreated_from_files"])
        self.assertFalse(RESULT["provisioning"]["datasource_editable"])
        self.assertEqual(RESULT["security"]["runtime_secret_response_leaks"], 0)
        self.assertEqual(RESULT["security"]["downloaded_third_party_plugins"], 0)
        self.assertEqual(RESULT["oss_boundaries"]["dedicated_audit_logging"], "Enterprise or Cloud")

    def test_runtime_artifact_modes_are_precise(self) -> None:
        self.assertEqual(RESULT["security"]["runtime_secret_file_modes"], {
            "runtime_directory": "0700",
            "runtime_env": "0600",
            "rendered_realm": "0600",
            "tls_private_key": "0600",
            "tls_certificate": "0644",
        })


if __name__ == "__main__":
    unittest.main()
