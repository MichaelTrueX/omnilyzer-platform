"""File: spikes/supply-chain/tests/test_supply_chain.py
Purpose: Validate Task 008 release preparation and workflow policy without a network.
"""

from __future__ import annotations

import importlib.util
import hashlib
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
        self.assertEqual(publish_trigger.read_text(encoding="utf-8"), "0.8.5\n")
        consume_trigger = SPIKE_ROOT / "control/consume.trigger"
        self.assertEqual(consume_trigger.read_text(encoding="utf-8"), "0.8.5\n")
        self.assertEqual(
            (SPIKE_ROOT / "control/publisher-permissions.trigger").read_text(
                encoding="utf-8"
            ),
            "task008c-forgejo-publisher-permission-probe-v2\n",
        )
        self.assertEqual(
            (SPIKE_ROOT / "control/consumer-permissions.trigger").read_text(
                encoding="utf-8"
            ),
            "task008c-forgejo-consumer-permission-probe-v2\n",
        )
        self.assertEqual(
            (SPIKE_ROOT / "control/pypi-permissions.trigger").read_text(
                encoding="utf-8"
            ),
            "task008c-forgejo-pypi-permission-probe-v4\n",
        )
        self.assertEqual(
            (SPIKE_ROOT / "control/npm-permissions.trigger").read_text(
                encoding="utf-8"
            ),
            "task008c-forgejo-npm-permission-probe-v4\n",
        )
        self.assertEqual(
            (SPIKE_ROOT / "control/oci-permissions.trigger").read_text(
                encoding="utf-8"
            ),
            "task008c-forgejo-oci-permission-probe-v2\n",
        )
        self.assertEqual(
            (SPIKE_ROOT / "control/tamper-negative.trigger").read_text(
                encoding="utf-8"
            ),
            "task008b-phase4b-tamper-negative-v2\n",
        )
        self.assertEqual(
            (SPIKE_ROOT / "control/rollback-retention.trigger").read_text(
                encoding="utf-8"
            ),
            "task008b-phase5-rollback-retention-v2\n",
        )

    def test_publish_trigger_accepts_only_one_strict_version_plus_newline(self) -> None:
        self.assertIsNotNone(TRIGGER_VERSION_PATTERN.fullmatch("0.8.2\n"))
        for malformed in (
            "0.8.2",
            "v0.8.2\n",
            "0.8\n",
            "0.8.2-dev\n",
            "0.8.2\n1.0.0\n",
            "",
        ):
            with self.subTest(content=malformed):
                self.assertIsNone(TRIGGER_VERSION_PATTERN.fullmatch(malformed))

    def test_consume_trigger_accepts_only_one_strict_version_plus_newline(self) -> None:
        self.assertIsNotNone(TRIGGER_VERSION_PATTERN.fullmatch("0.8.2\n"))
        for malformed in (
            "0.8.2",
            "v0.8.2\n",
            "0.8\n",
            "0.8.2-dev\n",
            "0.8.2\n1.0.0\n",
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
                pypi_trigger = "spikes/supply-chain/control/pypi-permissions.trigger"
                self.assertEqual(
                    trigger.count(f"- {pypi_trigger}"),
                    1 if workflow is self.publish else 0,
                )
                npm_trigger = "spikes/supply-chain/control/npm-permissions.trigger"
                self.assertEqual(
                    trigger.count(f"- {npm_trigger}"),
                    1 if workflow is self.publish else 0,
                )
                oci_trigger = "spikes/supply-chain/control/oci-permissions.trigger"
                self.assertEqual(
                    trigger.count(f"- {oci_trigger}"),
                    1 if workflow is self.publish else 0,
                )
                tamper_trigger = "spikes/supply-chain/control/tamper-negative.trigger"
                self.assertEqual(
                    trigger.count(f"- {tamper_trigger}"),
                    1 if workflow is self.consume else 0,
                )
                rollback_trigger = (
                    "spikes/supply-chain/control/rollback-retention.trigger"
                )
                self.assertEqual(
                    trigger.count(f"- {rollback_trigger}"),
                    1 if workflow is self.consume else 0,
                )
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
                tamper_trigger = "spikes/supply-chain/control/tamper-negative.trigger"
                if workflow is self.consume:
                    self.assertIn(f'"{tamper_trigger}"', gate)
                    self.assertIn(f"$'M\\t{tamper_trigger}'", gate)
                    self.assertNotIn(f"$'A\\t{tamper_trigger}'", gate)
                    self.assertIn("mode=tamper", gate)
                    rollback_trigger = (
                        "spikes/supply-chain/control/rollback-retention.trigger"
                    )
                    self.assertIn(f'"{rollback_trigger}"', gate)
                    self.assertIn(f"$'M\\t{rollback_trigger}'", gate)
                    self.assertNotIn(f"$'A\\t{rollback_trigger}'", gate)
                    self.assertIn("mode=rollback", gate)
                else:
                    self.assertNotIn(tamper_trigger, gate)
                    self.assertNotIn("rollback-retention.trigger", gate)
                    pypi_trigger = (
                        "spikes/supply-chain/control/pypi-permissions.trigger"
                    )
                    self.assertIn(f'"{pypi_trigger}"', gate)
                    self.assertIn(f"$'M\\t{pypi_trigger}'", gate)
                    self.assertNotIn(f"$'A\\t{pypi_trigger}'", gate)
                    self.assertIn("mode=pypi-permission", gate)
                    npm_trigger = (
                        "spikes/supply-chain/control/npm-permissions.trigger"
                    )
                    self.assertIn(f'"{npm_trigger}"', gate)
                    self.assertIn(f"$'M\\t{npm_trigger}'", gate)
                    self.assertNotIn(f"$'A\\t{npm_trigger}'", gate)
                    self.assertIn("mode=npm-permission", gate)
                    oci_trigger = (
                        "spikes/supply-chain/control/oci-permissions.trigger"
                    )
                    self.assertIn(f'"{oci_trigger}"', gate)
                    self.assertIn(f"$'M\\t{oci_trigger}'", gate)
                    self.assertNotIn(f"$'A\\t{oci_trigger}'", gate)
                    self.assertIn("mode=oci-permission", gate)

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
                gate_dependency = "- gate" if workflow is self.publish else "needs: gate"
                self.assertIn(gate_dependency, release)
                self.assertIn("if: needs.gate.outputs.mode == 'release'", release)
            with self.subTest(job=permission_job):
                self.assertIn("needs: gate", permission)
                self.assertIn("if: needs.gate.outputs.mode == 'permission'", permission)
        tamper = self.job(self.consume, "tamper-negative-probe")
        self.assertIn("needs: gate", tamper)
        self.assertIn("if: needs.gate.outputs.mode == 'tamper'", tamper)
        rollback = self.job(self.consume, "rollback-retention-probe")
        self.assertIn("needs: gate", rollback)
        self.assertIn("if: needs.gate.outputs.mode == 'rollback'", rollback)

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
        build = self.job(self.publish, "build")
        build_permissions = build.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(build_permissions.strip(), "contents: read")
        self.assertNotIn("id-token: write", build)
        execute = self.job(self.consume, "execute-verified")
        execute_permissions = execute.split("    permissions:", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(execute_permissions.strip(), "{}")
        self.assertNotIn("id-token: write", execute)
        tamper = self.job(self.consume, "tamper-negative-probe")
        tamper_permissions = tamper.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(tamper_permissions.strip(), "id-token: write")
        rollback = self.job(self.consume, "rollback-retention-probe")
        rollback_permissions = rollback.split("    permissions:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(rollback_permissions.strip(), "id-token: write")
        self.assertIn("oidc-service-slug: gha-publisher-u76y", self.publish)
        self.assertIn("oidc-service-slug: gha-consumer", self.consume)
        for workflow in (self.publish, self.consume):
            self.assertIn("oidc-namespace: omnilyzer", workflow)
            self.assertIn("omnilyzer/platform-spike", workflow)
            expected_cli_count = 2 if workflow is self.publish else 4
            self.assertEqual(workflow.count("cli-version: '1.26.0'"), expected_cli_count)
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
        self.assertEqual(combined.count("--output-format json"), 5)

    def test_release_build_job_has_no_oidc_or_cloudsmith_authority(self) -> None:
        build = self.job(self.publish, "build")
        self.assertIn("needs: gate", build)
        self.assertIn("if: needs.gate.outputs.mode == 'release'", build)
        self.assertIn("persist-credentials: false", build)
        self.assertIn("python-version: '3.12'", build)
        self.assertIn("node-version: '24.20.0'", build)
        self.assertIn("prepare_release.py", build)
        self.assertIn("build==1.6.0 hatchling==1.32.0", build)
        self.assertIn("python -m build --wheel --no-isolation", build)
        self.assertIn("npm pack", build)
        self.assertIn("--ignore-scripts", build)
        self.assertIn("docker build --tag", build)
        self.assertIn('local_image_ref="task008-oci-handoff:${RELEASE_VERSION}"', build)
        self.assertIn("docker save", build)
        self.assertIn("task008-oci-image.tar", build)
        self.assertIn('"sha256": sha256("task008-oci-image.tar")', build)
        self.assertNotIn("id-token: write", build)
        self.assertNotIn("cloudsmith-io/", build.lower())
        self.assertNotRegex(build.lower(), r"(?m)^\s*cloudsmith\s")
        self.assertNotIn("CLOUDSMITH_API_KEY", build)
        self.assertNotIn("docker login", build)

    def test_build_generates_exact_sboms_from_built_artifacts_without_oidc(self) -> None:
        build = self.job(self.publish, "build")
        self.assertIn(
            "uses: anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26",
            build,
        )
        self.assertIn("syft-version: v1.51.0", build)
        self.assertIn("SYFT_COMMAND: ${{ steps.syft.outputs.cmd }}", build)
        self.assertEqual(build.count("cyclonedx-json@1.6="), 3)
        for filename in (
            "python-sbom.cdx.json",
            "npm-sbom.cdx.json",
            "oci-sbom.cdx.json",
        ):
            self.assertIn(filename, build)
        self.assertIn("zipfile.ZipFile(wheel)", build)
        self.assertIn("tarfile.open(npm_tarball", build)
        self.assertIn('stat.S_ISLNK(mode)', build)
        self.assertIn("member.issym() or member.islnk()", build)
        self.assertIn('scan "dir:$wheel_root"', build)
        self.assertIn('scan "dir:$npm_root"', build)
        self.assertIn(
            'scan "docker-archive:$handoff_dir/task008-oci-image.tar"', build
        )
        self.assertNotIn("id-token: write", build)
        publish = self.job(self.publish, "publish")
        self.assertNotIn("cyclonedx-json@1.6=", publish)

    def test_release_handoff_is_minimal_checksummed_and_short_lived(self) -> None:
        build = self.job(self.publish, "build")
        self.assertIn(
            "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            build,
        )
        self.assertIn("name: task008-release-${{ github.run_id }}", build)
        self.assertIn("path: ${{ runner.temp }}/task008-handoff", build)
        self.assertIn("if-no-files-found: error", build)
        self.assertIn("include-hidden-files: false", build)
        self.assertIn("retention-days: 1", build)
        for manifest_field in (
            '"release_version"',
            '"source_sha"',
            '"filename"',
            '"sha256"',
            '"archive_format": "docker-image-archive"',
            '"image_reference": f"task008-oci-handoff:{release_version}"',
            '"version_label": release_version',
            '"handoff-manifest.json"',
        ):
            self.assertIn(manifest_field, build)
        upload = build.split("      - name: Upload minimal release handoff", 1)[1]
        for prohibited in (
            "CLOUDSMITH_API_KEY",
            "GITHUB_TOKEN",
            "credentials",
            ".git",
            "spikes/supply-chain",
        ):
            self.assertNotIn(prohibited, upload)

        for field in (
            '"sboms"',
            '"format": "cyclonedx-json"',
            '"spec_version": "1.6"',
            '"syft_version": "1.51.0"',
        ):
            self.assertIn(field, build)
        publish = self.job(self.publish, "publish")
        self.assertIn("handoff does not contain exactly twelve files", publish)
        self.assertIn("missing regular SBOM file", publish)
        self.assertIn('document.get("bomFormat") != "CycloneDX"', publish)
        self.assertIn('document.get("specVersion") != "1.6"', publish)
        for filename in (
            "python-sbom.cdx.json",
            "npm-sbom.cdx.json",
            "oci-sbom.cdx.json",
        ):
            self.assertIn(filename, publish)

    def test_phase3_cosign_policy_is_public_keyless_and_exact(self) -> None:
        release_jobs = self.job(self.publish, "publish") + self.job(
            self.consume, "consume"
        )
        self.assertEqual(
            release_jobs.count(
                "uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6"
            ),
            2,
        )
        self.assertEqual(release_jobs.count("cosign-release: v3.1.2"), 2)
        identity = (
            "https://github.com/MichaelTrueX/omnilyzer-platform/.github/workflows/"
            "task008-publish.yml@refs/heads/spike/008-supply-chain"
        )
        issuer = "https://token.actions.githubusercontent.com"
        self.assertEqual(release_jobs.count(f"SIGNER_IDENTITY: {identity}"), 2)
        self.assertEqual(release_jobs.count(f"OIDC_ISSUER: {issuer}"), 2)
        for prohibited in (
            "certificate-identity-regexp",
            "private-infrastructure",
            "insecure-ignore-tlog",
            "insecure-ignore-sct",
            "COSIGN_PRIVATE_KEY",
            "cosign generate-key-pair",
        ):
            self.assertNotIn(prohibited, release_jobs)

    def test_publisher_signs_verifies_and_publishes_exact_evidence(self) -> None:
        publish = self.job(self.publish, "publish")
        provenance = publish.index("Create SLSA v1-formatted workload provenance")
        signing = publish.index("Keylessly sign release blobs")
        verification = publish.index("Immediately verify signed release content")
        publication = publish.index("Publish versioned Generic release evidence")
        self.assertLess(provenance, signing)
        self.assertLess(signing, verification)
        self.assertLess(verification, publication)
        self.assertEqual(publish.count("cosign sign-blob --yes"), 3)
        self.assertIn('cosign sign --yes "$IMAGE_REPOSITORY@$OCI_DIGEST"', publish)
        self.assertIn('--certificate-identity "$SIGNER_IDENTITY"', publish)
        self.assertIn('--certificate-oidc-issuer "$OIDC_ISSUER"', publish)
        self.assertIn('"_type": "https://in-toto.io/Statement/v1"', publish)
        self.assertIn('"predicateType": "https://slsa.dev/provenance/v1"', publish)
        self.assertIn(
            '"buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"',
            publish,
        )
        self.assertIn('"gitCommit": os.environ["GITHUB_SHA"]', publish)
        self.assertIn('"id": "https://github.com/actions/runner/github-hosted"', publish)
        for unsupported_claim in ("SLSA Build L2", "SLSA Build L3", "reproducible"):
            self.assertNotIn(unsupported_claim, publish)
        for bundle in (
            "python-wheel.sigstore.json",
            "npm-tarball.sigstore.json",
            "python-sbom.sigstore.json",
            "npm-sbom.sigstore.json",
            "oci-sbom.sigstore.json",
            "release-provenance.sigstore.json",
            "evidence-manifest.sigstore.json",
        ):
            self.assertIn(bundle, publish)
        archive_step = publish.split(
            "- name: Create, sign, and verify deterministic evidence archive", 1
        )[1].split("      - name: Publish versioned Generic release evidence", 1)[0]
        allowlist = archive_step.split(
            "          mapfile -t evidence_files <<'EOF'\n", 1
        )[1].split("          EOF", 1)[0]
        self.assertEqual(
            set(allowlist.split()),
            {
                "python-sbom.cdx.json",
                "npm-sbom.cdx.json",
                "oci-sbom.cdx.json",
                "release-provenance.json",
                "evidence-manifest.json",
                "python-wheel.sigstore.json",
                "npm-tarball.sigstore.json",
                "python-sbom.sigstore.json",
                "npm-sbom.sigstore.json",
                "oci-sbom.sigstore.json",
                "release-provenance.sigstore.json",
                "evidence-manifest.sigstore.json",
                "python-vulnerabilities.grype.json",
                "npm-vulnerabilities.grype.json",
                "oci-vulnerabilities.grype.json",
                "grype-db-status.json",
                "vulnerability-policy-result.json",
            },
        )
        self.assertEqual(len(allowlist.split()), 17)
        for excluded in (
            ".whl", ".tgz", "task008-oci-image.tar", ".git",
            "vulnerability-policy.json", "grype.db",
        ):
            self.assertNotIn(excluded, allowlist)
        self.assertIn("exact seventeen-file allowlist", self.consume)
        self.assertIn("tar --sort=name --mtime='UTC 1970-01-01'", publish)
        self.assertIn("--owner=0 --group=0 --numeric-owner", publish)
        self.assertIn("gzip -n", publish)
        generic_upload = publish.split(
            "- name: Publish versioned Generic release evidence", 1
        )[1]
        self.assertEqual(generic_upload.count("cloudsmith push generic"), 2)
        self.assertEqual(generic_upload.count('--version "$RELEASE_VERSION"'), 2)
        self.assertIn(
            '--filepath "task008/evidence/${RELEASE_VERSION}/${archive_name}"',
            generic_upload,
        )
        self.assertNotIn("--republish", generic_upload)
        self.assertNotIn("--name", generic_upload)

    def test_consumer_verifies_before_installing_or_importing(self) -> None:
        consume = self.job(self.consume, "consume")
        wheel_download = consume.index("Download exact Python wheel without installing")
        npm_download = consume.index("Download exact npm tarball without installing")
        archive_verify = consume.index("Verify evidence archive signature before extraction")
        extraction = consume.index("Safely extract exact evidence allowlist")
        signatures = consume.index("Verify all release signatures before code execution")
        handoff = consume.index("Create exact verified execution handoff")
        upload = consume.index("Upload verified execution handoff after all verification")
        self.assertLess(wheel_download, archive_verify)
        self.assertLess(npm_download, archive_verify)
        self.assertLess(archive_verify, extraction)
        self.assertLess(extraction, signatures)
        self.assertLess(signatures, handoff)
        self.assertLess(handoff, upload)
        self.assertIn("python -m pip download", consume)
        self.assertIn("--only-binary=:all: --no-deps", consume)
        self.assertIn("NPM_CONFIG_USERCONFIG", consume)
        self.assertIn("npm pack", consume)
        self.assertIn("--ignore-scripts", consume)
        generic_download = consume.split(
            "- name: Download exact versioned evidence archive and bundle", 1
        )[1].split("      - name: Verify evidence archive signature before extraction", 1)[0]
        self.assertIn("expected exactly one versioned evidence package", generic_download)
        self.assertNotIn("cdn_url", generic_download)
        self.assertIn(
            'generic_url="https://generic.cloudsmith.io/omnilyzer/platform-spike/${filepath}"',
            generic_download,
        )
        self.assertIn(
            'local filepath="task008/evidence/${RELEASE_VERSION}/${filename}"',
            generic_download,
        )
        self.assertIn('--user "token:${CLOUDSMITH_API_KEY}"', generic_download)
        self.assertIn("--location", generic_download)
        self.assertIn("--proto '=https'", generic_download)
        self.assertIn("--proto-redir '=https'", generic_download)
        self.assertIn("--max-redirs 3", generic_download)
        self.assertNotIn("--location-trusted", generic_download)
        self.assertNotRegex(
            generic_download,
            r"https://[^\s\"']*\$\{CLOUDSMITH_API_KEY\}",
        )
        self.assertIn("evidence archive does not match exact seventeen-file allowlist", consume)
        self.assertIn("not member.isfile()", consume)
        self.assertIn("downloaded wheel does not match evidence", consume)
        self.assertIn("downloaded npm tarball does not match evidence", consume)
        self.assertIn("pulled OCI digest does not match evidence", consume)
        self.assertIn("provenance subjects do not match retrieved artifacts", consume)
        self.assertIn("provenance Git dependency does not match publisher source", consume)
        self.assertIn('--certificate-identity "$SIGNER_IDENTITY"', consume)
        self.assertIn('--certificate-oidc-issuer "$OIDC_ISSUER"', consume)
        self.assertIn('"$OCI_REFERENCE"', consume)
        self.assertIn('name: task008-verified-execution-${{ github.run_id }}', consume)
        self.assertIn('path: ${{ runner.temp }}/task008-verified-execution', consume)
        self.assertIn("if-no-files-found: error", consume)
        self.assertIn("retention-days: 1", consume)
        self.assertIn("include-hidden-files: false", consume)
        self.assertIn('"verified-execution-manifest.json"', consume)
        self.assertIn("verified execution handoff is not exactly three files", consume)
        self.assertNotIn("omnilyzer_supply_chain_spike as p", consume)
        self.assertNotIn('import { report } from "@omnilyzer/supply-chain-spike"', consume)
        self.assertNotRegex(consume, r"(?m)^\s*(?:\S+/)?python\S*.*-m pip install\b")
        self.assertNotRegex(consume, r"(?m)^\s*npm install\b")
        self.assertNotRegex(consume, r"(?m)^\s*docker run(?:\s|$)")

    def test_execute_verified_job_is_unprivileged_local_execution_only(self) -> None:
        execute = self.job(self.consume, "execute-verified")
        permissions = execute.split("    permissions:", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertEqual(permissions.strip(), "{}")
        self.assertIn("- gate", execute)
        self.assertIn("- consume", execute)
        self.assertIn("if: needs.gate.outputs.mode == 'release'", execute)
        self.assertIn(
            "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            execute,
        )
        self.assertIn("name: task008-verified-execution-${{ github.run_id }}", execute)
        self.assertNotIn("github-token:", execute)
        self.assertIn("verified execution handoff does not contain exactly three files", execute)
        self.assertIn('set(manifest) != {"release_version", "wheel", "npm"}', execute)
        self.assertIn('r"[0-9]+\\.[0-9]+\\.[0-9]+"', execute)
        self.assertIn("hashlib.sha256(path.read_bytes()).hexdigest()", execute)
        self.assertIn('--no-index --no-deps "$WHEEL_PATH"', execute)
        self.assertIn("npm install --prefix", execute)
        self.assertIn("--ignore-scripts --no-audit --no-fund", execute)
        self.assertIn("omnilyzer_supply_chain_spike as p", execute)
        self.assertIn('import { report } from "@omnilyzer/supply-chain-spike"', execute)
        for prohibited in (
            "id-token: write",
            "actions/checkout",
            "cloudsmith-io/",
            "CLOUDSMITH_API_KEY",
            "cloudsmith ",
            "cosign",
            "docker",
            "PIP_INDEX_URL",
            "pip download",
            "npm pack",
            "registry=",
        ):
            self.assertNotIn(prohibited, execute)
        self.assertEqual(self.consume.count("omnilyzer_supply_chain_spike as p"), 1)
        self.assertEqual(
            self.consume.count('import { report } from "@omnilyzer/supply-chain-spike"'),
            1,
        )

    def test_tamper_probe_has_read_only_consumer_authority_and_cannot_publish(self) -> None:
        probe = self.job(self.consume, "tamper-negative-probe")
        self.assertIn("RELEASE_VERSION: 0.8.4", probe)
        self.assertIn("oidc-service-slug: gha-consumer", probe)
        self.assertNotIn("gha-publisher", probe)
        self.assertNotIn("actions/checkout", probe)
        self.assertNotIn("contents: read", probe)
        for prohibited in (
            "cloudsmith push",
            "npm publish",
            "docker push",
            "cosign sign",
            "--republish",
            "--location-trusted",
            "actions/upload-artifact",
            "CLOUDSMITH_API_KEY:",
        ):
            self.assertNotIn(prohibited, probe)
        self.assertEqual(probe.count("cloudsmith-io/cloudsmith-cli-action@"), 1)
        self.assertIn("verify-auth: true", probe)
        self.assertIn("export-auth-token: true", probe)

    def test_tamper_probe_expected_failures_are_fail_closed(self) -> None:
        probe = self.job(self.consume, "tamper-negative-probe")
        self.assertEqual(probe.count("          set +e\n"), 4)
        for status in (
            "verification_status",
            "substitution_status",
            "handoff_status",
        ):
            self.assertIn(f'if [[ "${status}" -eq 0 ]]; then', probe)
        self.assertEqual(probe.count('if [[ "$verification_status" -eq 0 ]]; then'), 2)
        self.assertEqual(probe.count("SECURITY FAILURE:"), 6)
        self.assertNotIn("|| true", probe)
        self.assertNotIn("continue-on-error", probe)
        self.assertEqual(
            probe.count('test ! -e "$RUNNER_TEMP/task008b-negative-accepted-handoff"'),
            3,
        )

    def test_tampered_wheel_is_rejected_without_execution(self) -> None:
        probe = self.job(self.consume, "tamper-negative-probe")
        case = probe.split("      - name: Prove tampered Python artifact is rejected", 1)[1].split(
            "      - name: Prove signed release metadata rejects version substitution", 1
        )[0]
        self.assertLess(case.index("task008b-wheel-tamper"), case.index("cosign verify-blob"))
        self.assertIn("python-wheel.sigstore.json", case)
        self.assertIn("tampered Python artifact verified", case)
        for prohibited in (
            "pip install",
            "npm install",
            "omnilyzer_supply_chain_spike as p",
            'import { report } from "@omnilyzer/supply-chain-spike"',
        ):
            self.assertNotIn(prohibited, probe)

    def test_tampered_evidence_archive_is_rejected_before_any_extraction(self) -> None:
        probe = self.job(self.consume, "tamper-negative-probe")
        tamper = probe.index("Prove tampered signed evidence archive is rejected before extraction")
        baseline = probe.index("Establish legitimate signed evidence baseline")
        self.assertLess(tamper, baseline)
        case = probe[tamper:baseline]
        self.assertLess(case.index("task008b-archive-tamper"), case.index("cosign verify-blob"))
        self.assertIn("tampered evidence archive verified", case)
        self.assertIn("tampered evidence archive was extracted", case)
        self.assertNotIn("tarfile", case)
        self.assertNotIn("extractall", case)

    def test_signed_release_version_rejects_local_substitution(self) -> None:
        probe = self.job(self.consume, "tamper-negative-probe")
        baseline = probe.index("Establish legitimate signed evidence baseline")
        substitution = probe.index("Prove signed release metadata rejects version substitution")
        self.assertLess(baseline, substitution)
        self.assertIn("evidence-manifest.sigstore.json", probe[baseline:substitution])
        case = probe[substitution:]
        self.assertIn("substituted_request_version=0.8.5", case)
        self.assertIn('manifest.get("release_version") != sys.argv[2]', case)
        self.assertIn("signed release_version rejects substituted release material", case)
        self.assertIn("different-version material passed release binding", case)

    def test_mutated_execution_handoff_is_rejected_before_execution(self) -> None:
        probe = self.job(self.consume, "tamper-negative-probe")
        case = probe.split(
            "      - name: Prove mutated verified-execution handoff is rejected before execution",
            1,
        )[1].split("      - name: Record expected negative-validation results", 1)[0]
        creation = case.index('"verified-execution-manifest.json").write_text')
        baseline = case.index("candidate handoff is invalid before mutation")
        mutation = case.index("task008b-handoff-tamper")
        checksum = case.index('hashlib.sha256(path.read_bytes()).hexdigest()')
        self.assertLess(creation, mutation)
        self.assertLess(baseline, mutation)
        self.assertLess(mutation, checksum)
        self.assertIn("verified execution handoff does not contain exactly three files", case)
        self.assertIn("verified {kind} checksum mismatch", case)
        self.assertIn("mutated execution handoff passed validation", case)
        self.assertIn("mutated handoff reached the execution environment", case)
        self.assertNotRegex(probe, r"(?m)^\s*(?:\S+/)?python\S*.*-m pip install\b")
        self.assertNotRegex(probe, r"(?m)^\s*npm install\b")
        self.assertNotRegex(probe, r"(?m)^\s*docker run(?:\s|$)")

    def test_normal_successful_consumer_jobs_remain_release_only(self) -> None:
        consume = self.job(self.consume, "consume")
        execute = self.job(self.consume, "execute-verified")
        self.assertIn("if: needs.gate.outputs.mode == 'release'", consume)
        self.assertIn("if: needs.gate.outputs.mode == 'release'", execute)
        self.assertNotIn("mode == 'tamper'", consume)
        self.assertNotIn("mode == 'tamper'", execute)
        self.assertIn("Create exact verified execution handoff", consume)
        self.assertIn("Validate exact verified execution handoff", execute)
        self.assertIn("permissions: {}", execute)

    def test_rollback_probe_is_isolated_and_registry_only(self) -> None:
        rollback = self.job(self.consume, "rollback-retention-probe")
        self.assertIn("if: needs.gate.outputs.mode == 'rollback'", rollback)
        self.assertIn("oidc-service-slug: gha-consumer", rollback)
        self.assertEqual(
            rollback.count("cloudsmith-io/cloudsmith-cli-action@"), 1
        )
        for prohibited in (
            "gha-publisher",
            "actions/checkout",
            "actions/download-artifact",
            "actions/upload-artifact",
            "task008-release-",
            "task008-verified-execution-",
            "cloudsmith push",
            "npm publish",
            "docker push",
            "cosign sign",
            "--republish",
            "--location-trusted",
            "cdn_url",
            "cloudsmith delete",
            "cloudsmith replace",
        ):
            self.assertNotIn(prohibited, rollback)
        self.assertNotRegex(rollback, r"/artifacts(?:/|\b)")
        self.assertNotIn("github.run_id", rollback)
        self.assertNotIn("Create exact verified execution handoff", rollback)

    def test_rollback_probe_hard_binds_exact_historical_release(self) -> None:
        rollback = self.job(self.consume, "rollback-retention-probe")
        digest = (
            "sha256:44cdf2855105c824fcad999723ed7cc4f4a0ba276c8b953882413a1c61004967"
        )
        self.assertIn("CURRENT_RELEASE_VERSION: 0.8.5", rollback)
        self.assertIn("ROLLBACK_VERSION: 0.8.4", rollback)
        self.assertIn(f"EXPECTED_ROLLBACK_OCI_DIGEST: {digest}", rollback)
        self.assertIn('test "$CURRENT_RELEASE_VERSION" != "$ROLLBACK_VERSION"', rollback)
        self.assertIn(
            '"omnilyzer-supply-chain-spike==${ROLLBACK_VERSION}"', rollback
        )
        self.assertIn(
            '"@omnilyzer/supply-chain-spike@${ROLLBACK_VERSION}"', rollback
        )
        self.assertIn(
            'image_ref="${IMAGE_REPOSITORY}:${ROLLBACK_VERSION}"', rollback
        )
        self.assertIn(
            'expected_reference="${IMAGE_REPOSITORY}@${EXPECTED_ROLLBACK_OCI_DIGEST}"',
            rollback,
        )
        self.assertIn("EXPECTED_PUBLISHER_RUN_ID: '33294828516'", rollback)
        for floating in (
            ":latest",
            "@latest",
            "==latest",
            "^0.8",
            "~0.8",
            ">=0.8",
            "0.8.*",
            "0.8.x",
        ):
            self.assertNotIn(floating, rollback.lower())

    def test_rollback_probe_retrieves_exact_cloudsmith_material(self) -> None:
        rollback = self.job(self.consume, "rollback-retention-probe")
        for filename in (
            "omnilyzer_supply_chain_spike-${ROLLBACK_VERSION}-py3-none-any.whl",
            "omnilyzer-supply-chain-spike-${ROLLBACK_VERSION}.tgz",
            "omnilyzer-supply-chain-spike-${ROLLBACK_VERSION}-evidence.tar.gz",
            "${archive_name}.sigstore.json",
        ):
            self.assertIn(filename, rollback)
        self.assertIn("--only-binary=:all: --no-deps", rollback)
        self.assertIn("npm pack", rollback)
        self.assertIn("--ignore-scripts", rollback)
        self.assertIn(
            'local filepath="task008/evidence/${ROLLBACK_VERSION}/${filename}"',
            rollback,
        )
        self.assertIn(
            'generic_url="https://generic.cloudsmith.io/omnilyzer/platform-spike/${filepath}"',
            rollback,
        )
        for option in (
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto '=https'",
            "--proto-redir '=https'",
            "--max-redirs 3",
        ):
            self.assertIn(option, rollback)
        self.assertIn("if len(matches) != 1:", rollback)

    def test_rollback_probe_verifies_current_format_before_signatures(self) -> None:
        rollback = self.job(self.consume, "rollback-retention-probe")
        archive_verify = rollback.index(
            "Verify rollback evidence archive signature before extraction"
        )
        extraction = rollback.index(
            "Safely extract exact seventeen-file rollback evidence allowlist"
        )
        manifest_verify = rollback.index("Verify rollback evidence manifest signature")
        validation = rollback.index(
            "Validate exact rollback evidence hashes SBOMs policy and provenance"
        )
        signatures = rollback.index(
            "Verify all rollback release signatures without execution"
        )
        result = rollback.index("Record registry-only rollback verification")
        self.assertLess(archive_verify, extraction)
        self.assertLess(extraction, manifest_verify)
        self.assertLess(manifest_verify, validation)
        self.assertLess(validation, signatures)
        self.assertLess(signatures, result)
        self.assertIn("len(members) != 17", rollback)
        for bundle in (
            "python-wheel.sigstore.json",
            "npm-tarball.sigstore.json",
            "python-sbom.sigstore.json",
            "npm-sbom.sigstore.json",
            "oci-sbom.sigstore.json",
            "release-provenance.sigstore.json",
            "evidence-manifest.sigstore.json",
        ):
            self.assertIn(bundle, rollback)
        self.assertIn(
            "EXPECTED_VULNERABILITY_POLICY_SHA256: "
            "f36c806af62c1920890b6c33ae5dc03aa738af860e73a08b6fea3543c03d6530",
            rollback,
        )
        self.assertIn('["Critical", "High"]', rollback)
        self.assertIn('target.get("blocking_findings") != []', rollback)
        self.assertIn('"spec_version": "1.6"', rollback)
        self.assertIn('"predicate_type": "https://slsa.dev/provenance/v1"', rollback)
        self.assertIn("provenance subjects do not match retrieved artifacts", rollback)
        self.assertIn("--certificate-identity \"$SIGNER_IDENTITY\"", rollback)
        self.assertIn("--certificate-oidc-issuer \"$OIDC_ISSUER\"", rollback)
        self.assertNotIn("--insecure-ignore-tlog", rollback)

    def test_rollback_probe_never_executes_or_creates_a_handoff(self) -> None:
        rollback = self.job(self.consume, "rollback-retention-probe")
        for prohibited in (
            "pip install",
            "npm install",
            "verified-execution-manifest.json",
            "actions/upload-artifact",
            "omnilyzer_supply_chain_spike as p",
            'import { report } from "@omnilyzer/supply-chain-spike"',
        ):
            self.assertNotIn(prohibited, rollback)
        self.assertNotRegex(rollback, r"(?m)^\s*docker run(?:\s|$)")
        self.assertNotRegex(rollback, r"(?m)^\s*node(?:\s|$)")
        self.assertIn("docker pull", rollback)
        self.assertIn("docker image inspect", rollback)

    def test_existing_consumer_jobs_do_not_accept_rollback_mode(self) -> None:
        for name in (
            "consume",
            "execute-verified",
            "tamper-negative-probe",
            "consumer-permission-probe",
        ):
            job = self.job(self.consume, name)
            with self.subTest(job=name):
                self.assertNotIn("mode == 'rollback'", job)
        self.assertIn(
            "if: needs.gate.outputs.mode == 'release'",
            self.job(self.consume, "consume"),
        )
        self.assertIn(
            "if: needs.gate.outputs.mode == 'release'",
            self.job(self.consume, "execute-verified"),
        )
        self.assertIn(
            "if: needs.gate.outputs.mode == 'tamper'",
            self.job(self.consume, "tamper-negative-probe"),
        )
        self.assertIn(
            "if: needs.gate.outputs.mode == 'permission'",
            self.job(self.consume, "consumer-permission-probe"),
        )

    def test_consumer_validates_provenance_invocation_and_empty_internal_parameters(self) -> None:
        consume = self.job(self.consume, "consume")
        self.assertIn('definition.get("internalParameters") != {}', consume)
        self.assertIn('f\'{github["run_id"]}/attempts/{github["run_attempt"]}\'', consume)
        self.assertIn(
            'run_details.get("metadata") != {"invocationId": expected_invocation}',
            consume,
        )
        self.assertIn("provenance invocation does not match signed run metadata", consume)

    def test_release_publisher_verifies_handoff_before_oidc_without_rebuilding_packages(self) -> None:
        publish = self.job(self.publish, "publish")
        self.assertIn("- gate", publish)
        self.assertIn("- build", publish)
        self.assertIn("if: needs.gate.outputs.mode == 'release'", publish)
        self.assertIn(
            "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            publish,
        )
        self.assertIn("name: task008-release-${{ github.run_id }}", publish)
        self.assertIn("path: ${{ runner.temp }}/task008-handoff", publish)
        verification = publish.index("- name: Verify handoff manifest and checksums before OIDC")
        authentication = publish.index(
            "- name: Authenticate short-lived Cloudsmith publisher"
        )
        self.assertLess(verification, authentication)
        self.assertLess(publish.index("hashlib.sha256"), authentication)
        self.assertLess(publish.index("handoff checksum mismatch"), authentication)
        self.assertLess(publish.index("OCI_IMAGE_SHA256"), authentication)
        load_step = publish.index("- name: Load and inspect already-built OCI image")
        self.assertLess(load_step, authentication)
        self.assertLess(publish.index("docker load --input"), authentication)
        self.assertLess(publish.index("docker image inspect"), authentication)
        self.assertIn("actual_entries != expected_files", publish)
        self.assertIn('"archive_format": "docker-image-archive"', publish)
        self.assertIn("loaded OCI image is missing its expected local reference", publish)
        self.assertIn("loaded OCI image has an unexpected version label", publish)
        self.assertIn('docker tag "$LOCAL_IMAGE_REF" "$image_ref"', publish)
        self.assertIn('docker push "$IMAGE_REF"', publish)
        self.assertNotRegex(publish, r"(?m)^\s*docker run(?:\s|$)")
        self.assertNotRegex(publish, r"(?m)^\s*docker build(?:\s|$)")
        self.assertNotRegex(publish, r"(?m)^\s*docker buildx build(?:\s|$)")
        self.assertNotRegex(publish, r"(?m)^\s*(?:buildah|podman) build(?:\s|$)")
        self.assertNotRegex(publish, r"(?m)^\s*npm pack(?:\s|$)")
        for prohibited in (
            "python -m build",
            "prepare_release.py",
            "build==1.6.0",
            "hatchling==1.32.0",
        ):
            self.assertNotIn(prohibited, publish)

    def test_all_oci_image_construction_is_confined_to_non_oidc_build_job(self) -> None:
        build = self.job(self.publish, "build")
        oci_build = self.job(self.publish, "oci-probe-build")
        publish = self.job(self.publish, "publish")
        probe = self.job(self.publish, "publisher-permission-probe")
        oci_probe = self.job(self.publish, "oci-permission-probe")
        image_build_pattern = r"(?m)^\s*(?:docker|docker buildx|buildah|podman) build(?:\s|$)"
        self.assertEqual(len(re.findall(image_build_pattern, build)), 1)
        self.assertEqual(len(re.findall(image_build_pattern, oci_build)), 0)
        self.assertEqual(len(re.findall(image_build_pattern, self.publish)), 1)
        self.assertIn("forgejo_oci_probe.py build", oci_build)
        self.assertNotRegex(publish, image_build_pattern)
        self.assertNotRegex(probe, image_build_pattern)
        self.assertNotRegex(oci_probe, image_build_pattern)
        self.assertNotIn("id-token: write", build)
        self.assertNotIn("id-token: write", oci_build)

    def test_oci_digest_extraction_is_json_safe(self) -> None:
        self.assertIn("--format '{{json .Manifest.Digest}}'", self.publish)
        self.assertNotIn("--format '{{.Manifest.Digest}}'", self.publish)
        self.assertIn("json.load(sys.stdin)", self.publish)
        self.assertIn("^sha256:[0-9a-f]{64}$", self.publish)

    def test_grype_is_exact_and_confined_to_non_oidc_build(self) -> None:
        build = self.job(self.publish, "build")
        publish = self.job(self.publish, "publish")
        execute = self.job(self.consume, "execute-verified")
        self.assertIn(
            "uses: anchore/scan-action/download-grype@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2",
            build,
        )
        self.assertIn("grype-version: v0.118.0", build)
        self.assertIn("cache-db: false", build)
        self.assertIn("GRYPE_COMMAND: ${{ steps.grype.outputs.cmd }}", build)
        self.assertIn('versions == ["0.118.0"]', build)
        self.assertNotIn("id-token: write", build)
        for job in (publish, execute):
            self.assertNotIn("anchore/scan-action/download-grype", job)
            self.assertNotIn("GRYPE_COMMAND", job)
            self.assertNotIn('"$GRYPE_COMMAND" db', job)
            self.assertNotRegex(job, r'"\$GRYPE_COMMAND"\s+"sbom:')

    def test_grype_database_is_updated_once_then_frozen_for_three_sbom_scans(self) -> None:
        build = self.job(self.publish, "build")
        update = build.index('"$GRYPE_COMMAND" db update')
        status = build.index('"$GRYPE_COMMAND" db status -o json')
        scans = build.index("Scan exactly the three existing CycloneDX SBOMs")
        policy = build.index("Evaluate version-controlled vulnerability policy")
        manifest = build.index("Create machine-readable handoff manifest")
        upload = build.index("Upload minimal release handoff")
        self.assertLess(update, status)
        self.assertLess(status, scans)
        self.assertLess(scans, policy)
        self.assertLess(policy, manifest)
        self.assertLess(manifest, upload)
        self.assertEqual(build.count('"$GRYPE_COMMAND" db update'), 1)
        self.assertEqual(build.count('"$GRYPE_COMMAND" db status -o json'), 1)
        scan_step = build.split(
            "      - name: Scan exactly the three existing CycloneDX SBOMs", 1
        )[1].split(
            "      - name: Evaluate version-controlled vulnerability policy", 1
        )[0]
        self.assertIn("GRYPE_DB_AUTO_UPDATE: 'false'", scan_step)
        self.assertEqual(scan_step.count('"$GRYPE_COMMAND" "sbom:'), 3)
        for filename in (
            "python-sbom.cdx.json",
            "npm-sbom.cdx.json",
            "oci-sbom.cdx.json",
        ):
            self.assertEqual(scan_step.count(filename), 1)
        for prohibited in (
            "docker.cloudsmith.io",
            "docker-archive:",
            "dir:",
            "spikes/supply-chain/fixtures",
            "docker pull",
        ):
            self.assertNotIn(prohibited, scan_step)
        update_step = build.split(
            "      - name: Update and validate one Grype vulnerability database", 1
        )[1].split(
            "      - name: Scan exactly the three existing CycloneDX SBOMs", 1
        )[0]
        self.assertNotIn("GRYPE_DB_VALIDATE_AGE", update_step)
        self.assertNotIn("GRYPE_DB_VALIDATE_BY_HASH_ON_START", update_step)
        self.assertIn('raw_status="$RUNNER_TEMP/task008-grype-db-status-raw.json"', update_step)
        self.assertIn('> "$raw_status"', update_step)
        self.assertIn("sanitize-db-status", update_step)
        self.assertIn(
            '"$RUNNER_TEMP/task008-handoff/grype-db-status.json"', update_step
        )
        status_command = update_step.split('"$GRYPE_COMMAND" db status -o json', 1)[1].split(
            "python spikes/supply-chain/evaluate_vulnerabilities.py", 1
        )[0]
        self.assertNotIn("|| true", status_command)
        self.assertNotIn("grype-db-status.json", status_command)

    def test_vulnerability_gate_extends_exact_build_handoff_before_oidc(self) -> None:
        build = self.job(self.publish, "build")
        publish = self.job(self.publish, "publish")
        files = (
            "python-vulnerabilities.grype.json",
            "npm-vulnerabilities.grype.json",
            "oci-vulnerabilities.grype.json",
            "grype-db-status.json",
            "vulnerability-policy-result.json",
        )
        for filename in files:
            self.assertIn(filename, build)
            self.assertIn(filename, publish)
        self.assertIn("build handoff does not contain exactly twelve files", build)
        self.assertIn("handoff does not contain exactly twelve files", publish)
        self.assertIn('"grype_version": "0.118.0"', build)
        self.assertIn('"vulnerability_policy_sha256"', build)
        expected_sha = hashlib.sha256(
            (SPIKE_ROOT / "vulnerability-policy.json").read_bytes()
        ).hexdigest()
        self.assertEqual(
            expected_sha,
            "f36c806af62c1920890b6c33ae5dc03aa738af860e73a08b6fea3543c03d6530",
        )
        self.assertIn(f"EXPECTED_VULNERABILITY_POLICY_SHA256: {expected_sha}", publish)
        verification = publish.index("Verify handoff manifest and checksums before OIDC")
        authentication = publish.index("Authenticate short-lived Cloudsmith publisher")
        self.assertLess(verification, authentication)
        self.assertIn('policy_result["decision"] != "PASS"', publish)
        self.assertIn("handoff vulnerability policy is not bound to workflow source", publish)
        self.assertIn("vulnerability policy decision is not PASS", publish)

    def test_signed_and_consumed_vulnerability_evidence_precedes_execution_handoff(self) -> None:
        publish = self.job(self.publish, "publish")
        consume = self.job(self.consume, "consume")
        execute = self.job(self.consume, "execute-verified")
        self.assertIn('"vulnerability_scanning"', publish)
        self.assertIn('"scanner": {"name": "grype", "version": "0.118.0"}', publish)
        self.assertIn('"block_severities": ["Critical", "High"]', publish)
        self.assertIn('"decision": "PASS"', publish)
        self.assertIn('"status_file"', publish)
        self.assertIn('"policy_result"', publish)
        self.assertNotIn(
            "sign_blob \"$evidence_dir/python-vulnerabilities.grype.json\"",
            publish,
        )
        validate = consume.index("Validate evidence hashes SBOMs and provenance")
        handoff = consume.index("Create exact verified execution handoff")
        self.assertLess(validate, handoff)
        self.assertIn("exact seventeen-file allowlist", consume)
        self.assertIn("Grype DB status hash mismatch", consume)
        self.assertIn("vulnerability policy result hash mismatch", consume)
        self.assertIn("vulnerability policy result is not PASS", consume)
        self.assertIn("vulnerability severity counts", consume)
        self.assertIn("PASS result retains blocking findings", consume)
        for filename in (
            "python-vulnerabilities.grype.json",
            "npm-vulnerabilities.grype.json",
            "oci-vulnerabilities.grype.json",
            "grype-db-status.json",
            "vulnerability-policy-result.json",
        ):
            self.assertNotIn(filename, execute)
        self.assertIn("permissions: {}", execute)
        for prohibited in (
            "id-token: write",
            "cloudsmith",
            "cosign",
            "docker",
            "actions/checkout",
        ):
            self.assertNotIn(prohibited, execute.lower())

    def test_publisher_and_consumer_require_canonical_four_field_database_evidence(self) -> None:
        publish = self.job(self.publish, "publish")
        consume = self.job(self.consume, "consume")
        expected_fields = '"built", "checksum", "schema_version", "valid"'
        for job in (publish, consume):
            self.assertIn(expected_fields, job)
            self.assertIn('database_status["valid"] is not True', job)
            self.assertIn('r"sha256:[0-9a-f]{64}"', job)
            database_validation = job.split(
                'database_status = json.loads(', 1
            )[1].split('policy_result', 1)[0]
            for prohibited in ('"status"', '"path"', '"from"', '"error"'):
                self.assertNotIn(prohibited, database_validation)

    def test_actions_are_exactly_pinned(self) -> None:
        expected = {
            "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/setup-node": "820762786026740c76f36085b0efc47a31fe5020",
            "cloudsmith-io/cloudsmith-cli-action": (
                "ad73fafb92e3e29a5166c529464c2df7658a608e"
            ),
            "actions/upload-artifact": (
                "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
            ),
            "actions/download-artifact": (
                "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
            ),
            "anchore/sbom-action/download-syft": (
                "3ad7283483fc7af8ff2b4ea19663c2d5ca935e26"
            ),
            "anchore/scan-action/download-grype": (
                "e1165082ffb1fe366ebaf02d8526e7c4989ea9d2"
            ),
            "sigstore/cosign-installer": (
                "6f9f17788090df1f26f669e9d70d6ae9567deba6"
            ),
        }
        for workflow in (self.publish, self.consume):
            uses_lines = [
                line.strip().removeprefix("uses: ")
                for line in workflow.splitlines()
                if line.strip().startswith("uses: ")
            ]
            expected_count = 30 if workflow is self.publish else 19
            self.assertEqual(len(uses_lines), expected_count)
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
