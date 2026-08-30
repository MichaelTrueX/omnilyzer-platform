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

    @staticmethod
    def job(workflow: str, name: str) -> str:
        match = re.search(
            rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            workflow,
        )
        if match is None:
            raise AssertionError(f"workflow has no {name!r} job")
        return match.group(0)

    def test_expected_workflows_and_trigger_state(self) -> None:
        self.assertTrue(PUBLISH_WORKFLOW.is_file())
        self.assertTrue(CONSUME_WORKFLOW.is_file())
        publish_trigger = SPIKE_ROOT / "control/publish.trigger"
        self.assertEqual(publish_trigger.read_text(encoding="utf-8"), "0.8.1\n")
        consume_trigger = SPIKE_ROOT / "control/consume.trigger"
        self.assertEqual(consume_trigger.read_text(encoding="utf-8"), "0.8.1\n")
        self.assertEqual(
            (SPIKE_ROOT / "control/publisher-permissions.trigger").read_text(
                encoding="utf-8"
            ),
            "task008b-publisher-permission-probe-v1\n",
        )
        self.assertEqual(
            (SPIKE_ROOT / "control/consumer-permissions.trigger").read_text(
                encoding="utf-8"
            ),
            "task008b-consumer-permission-probe-v1\n",
        )

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

    def test_consume_trigger_accepts_only_one_strict_version_plus_newline(self) -> None:
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

    def test_workflow_triggers_are_narrow(self) -> None:
        cases = (
            (
                self.publish,
                "spikes/supply-chain/control/publish.trigger",
                "spikes/supply-chain/control/publisher-permissions.trigger",
            ),
            (
                self.consume,
                "spikes/supply-chain/control/consume.trigger",
                "spikes/supply-chain/control/consumer-permissions.trigger",
            ),
        )
        for workflow, release_trigger, permission_trigger in cases:
            with self.subTest(trigger=release_trigger):
                trigger = workflow.split("permissions:", 1)[0]
                self.assertIn("on:\n  push:\n", trigger)
                self.assertEqual(trigger.count("- spike/008-supply-chain"), 1)
                self.assertEqual(trigger.count(f"- {release_trigger}"), 1)
                self.assertEqual(trigger.count(f"- {permission_trigger}"), 1)
                for prohibited in ("workflow_dispatch", "pull_request", "schedule"):
                    self.assertNotIn(prohibited, trigger)

    def test_pre_auth_gates_classify_complete_push_range_fail_closed(self) -> None:
        cases = (
            (
                self.publish,
                "spikes/supply-chain/control/publish.trigger",
                "spikes/supply-chain/control/publisher-permissions.trigger",
            ),
            (
                self.consume,
                "spikes/supply-chain/control/consume.trigger",
                "spikes/supply-chain/control/consumer-permissions.trigger",
            ),
        )
        for workflow, release_trigger, permission_trigger in cases:
            gate = self.job(workflow, "gate")
            with self.subTest(release_trigger=release_trigger):
                self.assertIn("github.event_name == 'push'", gate)
                self.assertIn(
                    "github.ref == 'refs/heads/spike/008-supply-chain'", gate
                )
                self.assertIn("BEFORE_SHA: ${{ github.event.before }}", gate)
                self.assertIn("AFTER_SHA: ${{ github.sha }}", gate)
                self.assertIn("0000000000000000000000000000000000000000", gate)
                self.assertEqual(gate.count("git cat-file -e"), 2)
                self.assertIn(
                    "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                    gate,
                )
                self.assertIn("fetch-depth: 0", gate)
                self.assertIn("persist-credentials: false", gate)
                self.assertIn(
                    "git diff --name-only --no-renames --diff-filter=ACDMRTUXB",
                    gate,
                )
                self.assertIn(
                    "git diff --name-status --no-renames --diff-filter=ACDMRTUXB",
                    gate,
                )
                self.assertIn('"$BEFORE_SHA" "$AFTER_SHA"', gate)
                self.assertIn('mode=none', gate)
                self.assertIn('"${#changed_paths[@]}" -eq 1', gate)
                self.assertIn(f'"{release_trigger}"', gate)
                self.assertIn(f"$'M\\t{release_trigger}'", gate)
                self.assertNotIn(f"$'A\\t{release_trigger}'", gate)
                self.assertIn(f'"{permission_trigger}"', gate)
                self.assertIn(f"$'A\\t{permission_trigger}'", gate)
                self.assertIn(f"$'M\\t{permission_trigger}'", gate)
                self.assertNotIn("github.event.head_commit", gate)
                self.assertNotIn("cloudsmith", gate.lower())
                self.assertIn("mode=release", gate)
                self.assertIn("mode=permission", gate)

        combined = self.publish + self.consume
        for unsafe in (
            "github.event.head_commit.added",
            "github.event.head_commit.modified",
            "github.event.head_commit.removed",
        ):
            self.assertNotIn(unsafe, combined)

    def test_release_and_permission_jobs_depend_on_gate_mode(self) -> None:
        cases = (
            (self.publish, "publish", "publisher-permission-probe"),
            (self.consume, "consume", "consumer-permission-probe"),
        )
        for workflow, release_job, permission_job in cases:
            release = self.job(workflow, release_job)
            permission = self.job(workflow, permission_job)
            with self.subTest(job=release_job):
                self.assertIn("needs: gate", release)
                self.assertIn("if: needs.gate.outputs.mode == 'release'", release)
            with self.subTest(job=permission_job):
                self.assertIn("needs: gate", permission)
                self.assertIn("if: needs.gate.outputs.mode == 'permission'", permission)

    def test_permissions_and_oidc_identities_are_narrow(self) -> None:
        for workflow in (self.publish, self.consume):
            self.assertIn("permissions: {}", workflow)
            gate = self.job(workflow, "gate")
            gate_permissions = gate.split("    permissions:\n", 1)[1].split(
                "    runs-on:", 1
            )[0]
            self.assertEqual(gate_permissions.strip(), "contents: read")
            self.assertNotIn("id-token: write", gate)
            for job_name in (
                "publish" if workflow is self.publish else "consume",
                "publisher-permission-probe"
                if workflow is self.publish
                else "consumer-permission-probe",
            ):
                job = self.job(workflow, job_name)
                permissions = job.split("    permissions:\n", 1)[1].split(
                    "    runs-on:", 1
                )[0]
                self.assertEqual(
                    permissions.strip().splitlines(),
                    ["contents: read", "      id-token: write"],
                )
        self.assertIn("oidc-service-slug: gha-publisher-u76y", self.publish)
        self.assertIn("oidc-service-slug: gha-consumer", self.consume)
        for workflow in (self.publish, self.consume):
            self.assertIn("oidc-namespace: omnilyzer", workflow)
            self.assertIn("omnilyzer/platform-spike", workflow)
            self.assertEqual(workflow.count("cli-version: '1.26.0'"), 2)
            self.assertIn("export-auth-token: true", workflow)
            self.assertIn("verify-auth: true", workflow)

    def test_consumer_write_denial_probe_is_fail_closed(self) -> None:
        probe = self.job(self.consume, "consumer-permission-probe")
        self.assertIn("oidc-service-slug: gha-consumer", probe)
        self.assertIn('probe_filename="task008b-consumer-${GITHUB_RUN_ID}.txt"', probe)
        self.assertIn(
            'probe_filepath="task008b/permissions/consumer/${GITHUB_RUN_ID}/${probe_filename}"',
            probe,
        )
        self.assertIn('probe_file="$RUNNER_TEMP/$probe_filename"', probe)
        self.assertIn("cloudsmith push generic", probe)
        self.assertNotIn("--name", probe)
        self.assertIn("set +e", probe)
        self.assertIn("upload_status=${PIPESTATUS[0]}", probe)
        self.assertIn("require_authorization_denial", probe)
        self.assertIn("INCONCLUSIVE:", probe)
        self.assertIn(r"\s*403\b", probe)
        self.assertIn(r"\bforbidden\b", probe)
        self.assertIn("do not have permission", probe)
        self.assertIn("permission denied", probe)
        self.assertIn("insufficient permissions?", probe)
        self.assertIn(
            '--query "format:generic AND filename:${probe_filename}"', probe
        )
        self.assertIn('payload.get("data")', probe)
        self.assertIn('package.get("format") == "generic"', probe)
        self.assertIn('package.get("filename") == sys.argv[2]', probe)
        self.assertIn('package.get("filepath") == sys.argv[3]', probe)
        self.assertIn("if matches:", probe)
        self.assertNotIn("cloudsmith delete", probe)
        self.assertNotIn("0.8.1", probe)

    def test_publisher_permission_probe_create_replace_delete_contract(self) -> None:
        probe = self.job(self.publish, "publisher-permission-probe")
        self.assertIn("oidc-service-slug: gha-publisher-u76y", probe)
        self.assertIn('probe_filename="task008b-publisher-${GITHUB_RUN_ID}.txt"', probe)
        self.assertIn('probe_version="0.0.${GITHUB_RUN_ID}"', probe)
        self.assertIn(
            'probe_filepath="task008b/permissions/publisher/${GITHUB_RUN_ID}/${probe_filename}"',
            probe,
        )
        self.assertIn('probe_file="$RUNNER_TEMP/$probe_filename"', probe)
        self.assertNotIn("--name", probe)
        self.assertEqual(probe.count("cloudsmith push generic"), 2)
        self.assertEqual(probe.count('--version "$probe_version"'), 2)
        first_upload = probe.index("cloudsmith push generic")
        denial_handling = probe.index("set +e", first_upload)
        replacement = probe.index("--republish")
        self.assertLess(first_upload, denial_handling)
        self.assertGreater(replacement, denial_handling)
        self.assertIn("for attempt in 1 2 3 4 5", probe)
        self.assertIn("sleep 3", probe)
        self.assertIn(
            '--query "format:generic AND filename:${probe_filename} AND version:${probe_version}"',
            probe,
        )
        self.assertIn('package.get("format") == "generic"', probe)
        self.assertIn('package.get("filename") == sys.argv[2]', probe)
        self.assertIn('package.get("filepath") == sys.argv[3]', probe)
        self.assertIn('package.get("version") == sys.argv[4]', probe)
        self.assertIn("len(matches) != 1", probe)
        self.assertIn('matches[0].get("slug_perm")', probe)
        self.assertNotIn('get("slug")', probe)
        self.assertIn("original_local_sha256=", probe)
        self.assertIn('matches[0].get("checksum_sha256")', probe)
        self.assertIn(
            '"$original_cloudsmith_sha256" != "$original_local_sha256"', probe
        )
        self.assertIn("replace_status=${PIPESTATUS[0]}", probe)
        self.assertIn('replace_result="$(classify_authorization_denial "$replace_log")"', probe)
        self.assertIn("replace_result=FAIL", probe)
        replace_success_block = probe.split(
            'if [[ "$replace_status" -eq 0 ]]; then', 1
        )[1].split("          fi", 1)[0]
        self.assertIn("SECURITY FAILURE", replace_success_block)
        self.assertIn("exit 1", replace_success_block)
        replace_inconclusive_block = probe.split(
            'if [[ "$replace_result" == "INCONCLUSIVE" ]]; then', 1
        )[1].split("          fi", 1)[0]
        self.assertNotIn("exit 1", replace_inconclusive_block)
        self.assertLess(
            probe.index('replace_result="$(classify_authorization_denial'),
            probe.index("cloudsmith delete"),
        )
        self.assertIn("replacement_slug_perm", probe)
        self.assertIn("replacement_sha256", probe)
        self.assertIn('"$replacement_sha256" != "$original_local_sha256"', probe)
        self.assertIn("cloudsmith delete", probe)
        self.assertIn(
            '"$CLOUDSMITH_REPOSITORY/$original_slug_perm" --yes', probe
        )
        self.assertIn("delete_status=${PIPESTATUS[0]}", probe)
        self.assertIn("delete_result=FAIL", probe)
        self.assertIn('delete_result="$(classify_authorization_denial "$delete_log")"', probe)
        delete_success_block = probe.split(
            'if [[ "$delete_status" -eq 0 ]]; then', 1
        )[1].split("          fi", 1)[0]
        self.assertIn("SECURITY FAILURE", delete_success_block)
        self.assertIn("exit 1", delete_success_block)
        self.assertIn("delete_slug_perm", probe)
        self.assertIn("delete_sha256", probe)
        self.assertIn('"$delete_sha256" != "$original_local_sha256"', probe)
        self.assertIn('[[ "$replace_result" != "PASS" ]]', probe)
        self.assertIn('[[ "$delete_result" != "PASS" ]]', probe)
        self.assertIn(
            "replace_result=$replace_result delete_result=$delete_result", probe
        )
        summary = probe.split("          write_probe_summary() {", 1)[1].split(
            "          }", 1
        )[0]
        for field in (
            "Run ID",
            "Probe version",
            "Create: PASS",
            "Replace: $replace_result",
            "Delete: $delete_result",
            "Original package remained unchanged: $original_unchanged",
        ):
            self.assertIn(field, summary)
        self.assertNotIn("CLOUDSMITH_API_KEY", summary)
        self.assertNotIn("0.8.1", probe)
        for release_target in (
            "omnilyzer-supply-chain-spike",
            "@omnilyzer/supply-chain-spike",
            "IMAGE_REPOSITORY",
        ):
            self.assertNotIn(release_target, probe)

    def test_permission_probes_use_standard_library_json_without_jq(self) -> None:
        combined = self.publish + self.consume
        self.assertNotRegex(combined, r"(?m)(?:^|[ |])jq(?:[ |]|$)")
        self.assertIn("import json", self.publish)
        self.assertIn("import json", self.consume)
        self.assertEqual(combined.count("--output-format json"), 2)

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
            self.assertEqual(len(uses_lines), 6)
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
        self.assertNotIn("always-auth=true", self.consume)

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
