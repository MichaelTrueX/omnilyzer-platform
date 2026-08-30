"""File: spikes/supply-chain/tests/test_supply_chain.py
Purpose: Validate Task 008 release preparation and workflow policy without a network.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SPIKE_ROOT = REPOSITORY_ROOT / "spikes" / "supply-chain"
PUBLISH_WORKFLOW = REPOSITORY_ROOT / ".github/workflows/task008-publish.yml"
CONSUME_WORKFLOW = REPOSITORY_ROOT / ".github/workflows/task008-consume.yml"
PREPARE_SCRIPT = SPIKE_ROOT / "scripts/prepare_release.py"
TRIGGER_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\n")

spec = importlib.util.spec_from_file_location("task008_prepare_release", PREPARE_SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load Task 008 release preparation script")
prepare_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_module)


class ReleasePreparationTests(unittest.TestCase):
    """Exercise the fail-closed, source-preserving preparation boundary."""

    def test_valid_release_coordinates_all_artifacts_without_source_changes(self) -> None:
        fixtures = SPIKE_ROOT / "fixtures"
        before = {
            path.relative_to(fixtures): path.read_bytes()
            for path in fixtures.rglob("*")
            if path.is_file()
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "prepared"
            manifest_path = prepare_module.prepare_release("0.8.0", output)
            record = json.loads(manifest_path.read_text(encoding="utf-8"))

            self.assertEqual(record["version"], "0.8.0")
            self.assertEqual(
                record["python"]["wheel"],
                "omnilyzer_supply_chain_spike-0.8.0-py3-none-any.whl",
            )
            self.assertEqual(
                record["npm"]["tarball"],
                "omnilyzer-supply-chain-spike-0.8.0.tgz",
            )
            self.assertTrue(record["oci"]["image"].endswith(":0.8.0"))
            for relative_path in prepare_module.MUTABLE_FILES:
                content = (output / relative_path).read_text(encoding="utf-8")
                self.assertIn("0.8.0", content)
                self.assertNotIn(prepare_module.PLACEHOLDER, content)

        after = {
            path.relative_to(fixtures): path.read_bytes()
            for path in fixtures.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_oci_fixture_is_layered_scratch_data_with_coordinated_version(self) -> None:
        oci_fixture = SPIKE_ROOT / "fixtures/oci"
        dockerfile = (oci_fixture / "Dockerfile").read_text(encoding="utf-8")

        instructions = [
            line.split(maxsplit=1)[0].upper()
            for line in dockerfile.splitlines()
            if line and not line.startswith("#") and not line[0].isspace()
        ]
        self.assertEqual(instructions.count("FROM"), 1)
        self.assertRegex(dockerfile, r"(?m)^FROM\s+scratch\s*$")
        self.assertRegex(
            dockerfile,
            r"(?m)^COPY\s+artifact\.txt\s+/artifact\.txt\s*$",
        )
        self.assertTrue((oci_fixture / "artifact.txt").is_file())
        for prohibited in ("RUN", "CMD", "ENTRYPOINT"):
            self.assertNotRegex(
                dockerfile,
                rf"(?im)^[ \t]*{prohibited}\b",
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "prepared"
            prepare_module.prepare_release("0.8.1", output)
            prepared_dockerfile = (output / "oci/Dockerfile").read_text(
                encoding="utf-8"
            )
            self.assertIn(
                'org.opencontainers.image.version="0.8.1"',
                prepared_dockerfile,
            )
            self.assertNotIn(prepare_module.PLACEHOLDER, prepared_dockerfile)
            self.assertTrue((output / "oci/artifact.txt").is_file())

    def test_malformed_versions_are_rejected(self) -> None:
        for malformed in ("0.8", "v0.8.0", "0.8.0-dev", "0.8.0\n1.0.0", ""):
            with self.subTest(version=malformed):
                with self.assertRaises(ValueError):
                    prepare_module.validate_version(malformed)

    def test_output_misuse_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            prepare_module.prepare_release("0.8.0", Path("relative/output"))
        with self.assertRaises(ValueError):
            prepare_module.prepare_release("0.8.0", SPIKE_ROOT / "generated")
        with tempfile.TemporaryDirectory() as temporary_directory:
            with self.assertRaises(FileExistsError):
                prepare_module.prepare_release("0.8.0", Path(temporary_directory))


class WorkflowPolicyTests(unittest.TestCase):
    """Inspect the two workflows as narrow text contracts without a YAML dependency."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.publish = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
        cls.consume = CONSUME_WORKFLOW.read_text(encoding="utf-8")

    def test_expected_workflows_and_trigger_state(self) -> None:
        self.assertTrue(PUBLISH_WORKFLOW.is_file())
        self.assertTrue(CONSUME_WORKFLOW.is_file())
        publish_trigger = SPIKE_ROOT / "control/publish.trigger"
        if publish_trigger.exists():
            self.assertIsNotNone(
                TRIGGER_VERSION_PATTERN.fullmatch(
                    publish_trigger.read_text(encoding="utf-8")
                ),
                "publish.trigger must contain exactly one X.Y.Z version plus newline",
            )
        self.assertFalse((SPIKE_ROOT / "control/consume.trigger").exists())

    def test_publish_trigger_accepts_only_one_strict_version_plus_newline(self) -> None:
        self.assertIsNotNone(TRIGGER_VERSION_PATTERN.fullmatch("0.8.1\n"))
        for malformed in (
            "0.8.1",
            "v0.8.1\n",
            "0.8\n",
            "0.8.1-dev\n",
            "0.8.1\n1.0.0\n",
            "",
        ):
            with self.subTest(content=malformed):
                self.assertIsNone(TRIGGER_VERSION_PATTERN.fullmatch(malformed))

    def test_triggers_are_exact_and_consumer_is_dormant(self) -> None:
        cases = (
            (self.publish, "spikes/supply-chain/control/publish.trigger"),
            (self.consume, "spikes/supply-chain/control/consume.trigger"),
        )
        for workflow, trigger_path in cases:
            with self.subTest(trigger=trigger_path):
                trigger = workflow.split("permissions:", 1)[0]
                self.assertIn("on:\n  push:\n", trigger)
                self.assertEqual(trigger.count("- spike/008-supply-chain"), 1)
                self.assertEqual(trigger.count(f"- {trigger_path}"), 1)
                self.assertIn(
                    "if: github.ref == 'refs/heads/spike/008-supply-chain'",
                    workflow,
                )
                for prohibited in ("workflow_dispatch", "pull_request", "schedule"):
                    self.assertNotIn(prohibited, trigger)

    def test_permissions_and_oidc_identities_are_narrow(self) -> None:
        for workflow in (self.publish, self.consume):
            permissions = workflow.split("permissions:\n", 1)[1].split("\n\n", 1)[0]
            self.assertEqual(
                permissions.strip().splitlines(),
                ["contents: read", "  id-token: write"],
            )
        self.assertIn("oidc-service-slug: gha-publisher-u76y", self.publish)
        self.assertIn("oidc-service-slug: gha-consumer", self.consume)
        for workflow in (self.publish, self.consume):
            self.assertIn("oidc-namespace: omnilyzer", workflow)
            self.assertIn("omnilyzer/platform-spike", workflow)
            self.assertEqual(workflow.count("cli-version: '1.26.0'"), 1)
            self.assertIn("export-auth-token: true", workflow)
            self.assertIn("verify-auth: true", workflow)

    def test_publisher_build_contract_precedes_cloudsmith_authentication(self) -> None:
        self.assertIn("python -m build --wheel --no-isolation", self.publish)
        authentication = self.publish.index(
            "- name: Authenticate short-lived Cloudsmith publisher"
        )
        local_steps = (
            "- name: Read and validate coordinated release version",
            "- name: Set up Python",
            "- name: Set up Node",
            "- name: Prepare coordinated build inputs",
            "- name: Install exact Python build tooling",
            "- name: Build standard Python wheel",
            "- name: Build standard npm tarball",
            "- name: Verify prepared artifact names",
            "- name: Build OCI fixture",
        )
        for step in local_steps:
            with self.subTest(step=step):
                self.assertLess(self.publish.index(step), authentication)

    def test_oci_digest_extraction_is_json_safe(self) -> None:
        self.assertIn("--format '{{json .Manifest.Digest}}'", self.publish)
        self.assertNotIn("--format '{{.Manifest.Digest}}'", self.publish)
        self.assertIn("json.load(sys.stdin)", self.publish)
        self.assertIn("^sha256:[0-9a-f]{64}$", self.publish)

    def test_actions_are_exactly_pinned(self) -> None:
        expected = {
            "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/setup-node": "820762786026740c76f36085b0efc47a31fe5020",
            "cloudsmith-io/cloudsmith-cli-action": (
                "ad73fafb92e3e29a5166c529464c2df7658a608e"
            ),
        }
        for workflow in (self.publish, self.consume):
            uses_lines = [
                line.strip().removeprefix("uses: ")
                for line in workflow.splitlines()
                if line.strip().startswith("uses: ")
            ]
            self.assertEqual(len(uses_lines), 4)
            for use in uses_lines:
                action, revision = use.split("@", 1)
                self.assertEqual(revision, expected[action])
                self.assertEqual(len(revision), 40)

    def test_no_committed_cloudsmith_credentials_or_floating_versions(self) -> None:
        combined = self.publish + self.consume
        self.assertNotIn("secrets." + "CLOUDSMITH", combined)
        self.assertNotIn("csa" + "_", combined.lower())
        floating = "lat" + "est"
        for version_syntax in (f":{floating}", f"=={floating}", f"@{floating}"):
            self.assertNotIn(version_syntax, combined.lower())
        self.assertNotIn("@main", combined)
        self.assertNotIn("@v3", combined)
        self.assertNotIn("persist-credentials: true", combined)
        self.assertIsNone(
            re.search(r"https://[^/\s:$]+:[^$@\s]+@", combined),
            "a URL contains a literal credential",
        )
        self.assertIsNone(
            re.search(r"CLOUDSMITH_API_KEY\s*:\s*[A-Za-z0-9]", combined),
            "a Cloudsmith credential is assigned a literal value",
        )
        self.assertIn('"omnilyzer-supply-chain-spike==${RELEASE_VERSION}"', self.consume)
        self.assertIn('"@omnilyzer/supply-chain-spike@${RELEASE_VERSION}"', self.consume)
        self.assertIn("${CLOUDSMITH_API_KEY}", self.consume)

    def test_release_preparation_and_generated_paths_are_controlled(self) -> None:
        self.assertIn("prepare_release.py", self.publish)
        self.assertIn("$RUNNER_TEMP/task008-release", self.publish)
        self.assertNotIn("spikes/supply-chain/fixtures", self.publish)
        for ignored in (
            "spikes/supply-chain/generated/example",
            "spikes/supply-chain/artifacts/example",
        ):
            result = subprocess.run(
                ["git", "check-ignore", "--quiet", ignored],
                cwd=REPOSITORY_ROOT,
                check=False,
            )
            self.assertEqual(result.returncode, 0, ignored)


if __name__ == "__main__":
    unittest.main()
