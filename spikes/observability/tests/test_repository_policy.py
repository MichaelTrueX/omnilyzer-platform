"""Repository-boundary and dependency policy evidence for the isolated spike."""

from __future__ import annotations

import ast
from pathlib import Path
import re
import tomllib
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SPIKE_ROOT = REPOSITORY_ROOT / "spikes" / "observability"


class RepositoryPolicyTests(unittest.TestCase):
    """Prove isolation, exact dependencies, and absence of credential material."""

    def test_direct_dependencies_are_minimal_exact_spike_only_pins(self) -> None:
        project = tomllib.loads((SPIKE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            project["project"]["dependencies"],
            [
                "Django==6.1",
                "opentelemetry-api==1.44.0",
                "opentelemetry-sdk==1.44.0",
                "opentelemetry-exporter-otlp-proto-http==1.44.0",
                "prometheus-client==0.26.0",
            ],
        )
        self.assertEqual(project["project"]["name"], "omnilyzer-observability-spike")

    def test_production_source_does_not_import_spike_code(self) -> None:
        for path in REPOSITORY_ROOT.rglob("*.py"):
            relative = path.relative_to(REPOSITORY_ROOT)
            if relative.parts[0] == "spikes" or ".git" in relative.parts:
                continue
            content = path.read_text(encoding="utf-8")
            with self.subTest(path=str(relative)):
                self.assertNotRegex(
                    content,
                    r"(?:from|import)\s+spikes(?:\.|\s)",
                )

    def test_contract_has_no_vendor_collector_or_production_infrastructure_dependency(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((SPIKE_ROOT / "contract").glob("*.py"))
        ).lower()
        for prohibited in (
            "grafana alloy",
            "tempo",
            "jaeger",
            "loki",
            "kafka",
            "kubernetes",
            "prometheus server",
        ):
            self.assertNotIn(prohibited, source)
        self.assertIn("otlp", source)

    def test_application_code_does_not_import_unstable_semantic_convention_apis(self) -> None:
        imported_modules: set[str] = set()
        imported_names: set[tuple[str, str]] = set()
        for directory in (SPIKE_ROOT / "contract", SPIKE_ROOT / "observability_spike"):
            for path in directory.glob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported_modules.update(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        imported_modules.add(module)
                        imported_names.update((module, alias.name) for alias in node.names)
        for module in imported_modules:
            self.assertNotIn("_incubating", module)
            self.assertFalse(module.startswith("opentelemetry.semconv"))
        for module, name in imported_names:
            if module.startswith("opentelemetry"):
                self.assertFalse(name.startswith("_"))

    def test_no_credential_or_private_key_material_is_committed(self) -> None:
        files = [
            path
            for path in SPIKE_ROOT.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        ]
        combined = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore") for path in files
        )
        for prohibited in (
            "-----BEGIN " + "PRIVATE KEY-----",
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "AKIA" + "IOSFODNN7EXAMPLE",
            "ghp_" + "real",
            "CLOUDSMITH" + "_API_KEY=",
        ):
            self.assertNotIn(prohibited, combined)
        self.assertIsNone(
            re.search(r"https://[^/\s:$]+:[^$@\s]+@", combined),
            "a committed HTTPS URL contains a literal credential",
        )

    def test_metrics_endpoint_is_unauthenticated_but_documented_internal_only(self) -> None:
        urls = (SPIKE_ROOT / "observability_spike/urls.py").read_text(encoding="utf-8")
        views = (SPIKE_ROOT / "contract/views.py").read_text(encoding="utf-8")
        readme = (SPIKE_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('path("metrics", views.metrics', urls)
        metrics_view = views.split("def metrics", 1)[1].split("def work", 1)[0]
        self.assertNotIn("Authorization", metrics_view)
        self.assertIn("not an internet", readme)
        self.assertIn("backend/internal Docker network", readme)

    def test_django_startup_owns_bounded_telemetry_shutdown(self) -> None:
        apps = (SPIKE_ROOT / "contract/apps.py").read_text(encoding="utf-8")
        telemetry = (SPIKE_ROOT / "contract/telemetry.py").read_text(encoding="utf-8")
        self.assertIn("atexit.register(runtime.shutdown)", apps)
        self.assertIn("self.provider.shutdown()", telemetry)

    def test_browser_token_storage_and_accepted_security_architecture_are_not_changed(self) -> None:
        implementation = "\n".join(
            path.read_text(encoding="utf-8")
            for directory in (SPIKE_ROOT / "contract", SPIKE_ROOT / "observability_spike")
            for path in directory.glob("*.py")
        )
        self.assertNotIn("localStorage", implementation)
        self.assertNotIn("BYPASSRLS", implementation)
        self.assertNotIn("row_security = off", implementation)
        self.assertNotIn("Access-Control-Allow-Origin", implementation)
