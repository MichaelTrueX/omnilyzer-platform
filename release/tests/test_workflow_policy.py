# File: release/tests/test_workflow_policy.py
# Purpose: Defend the Task 013 release and isolated read-only probe boundaries.
# Related: .github/workflows/platform-release.yml,
#          release/forgejo_oidc_probe.py, release/environments/dev.json.
# Sections: baseline workflow assertions; OIDC and packaging policy;
#           no-publish PR canary security checks.

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github/workflows/platform-release.yml"
PROTECTED = {
    ".github/workflows/task008-publish.yml": "0d6bd4a5715e6366250c427c959401e13b1f63b79786717a99b3816fd87a74b8",
    ".github/workflows/task008-consume.yml": "2712a221da0e4c4502fc2bc7dea6096cc015d8e0527a95a37f476c3fe3c7d5d1",
    ".github/workflows/task008-zot-publish.yml": "b0af8b0e017627972624d62c9e434037649200c3c56feae4495ca27469920a2d",
    ".github/workflows/task008-zot-consume.yml": "1d8618b15685f973c0af677f7557833c2e16b3b992571ea186f344532748adf9",
    "spikes/supply-chain/control/consume.trigger": "a92b0248b8baacfaf54e8d59caaca7d5e6b9a0a25ee140c81ea973b4ae25142f",
    "spikes/supply-chain/control/consumer-permissions.trigger": "c59b7e04d4f60d49b58122149dfb0ea9b4203f0716b69af28eb10f6dd8419005",
    "spikes/supply-chain/control/publish.trigger": "a92b0248b8baacfaf54e8d59caaca7d5e6b9a0a25ee140c81ea973b4ae25142f",
    "spikes/supply-chain/control/publisher-permissions.trigger": "ae9900404c8864cf4d8433eaeceafcf31cdbbbbe839d3b1883a64cbf081904ba",
    "spikes/supply-chain/control/rollback-retention.trigger": "8a14bd154b0ffe943349113d01a2bcb5251502ff92306bafe03f9c10bb252044",
    "spikes/supply-chain/control/tamper-negative.trigger": "9e54949c2b2fc014c56181d4da6d8e223766b4f5029155a18c65bed5cf5d8e4a",
    "spikes/supply-chain/control/zot-consume.trigger": "7bdacb65a7a6102e8d2068e2c98f49daf7ebd61d21ffa6c9ecf925a22d3b3027",
    "spikes/supply-chain/control/zot-publish.trigger": "bab946ff93488e2d95589a70b4fa6d5678e1ec5307b0b719424854e0c374cc1e",
}


class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.raw)
        cls.jobs = cls.workflow["jobs"]

    def test_private_cross_repo_analytics_checkout_requires_scoped_deploy_key(self) -> None:
        """Both exact-source checkouts require one source-only Git deploy key."""
        for job_name in ("analytics-source-admission", "analytics-publish-zot"):
            steps = self.jobs[job_name]["steps"]
            checkout = next(step for step in steps if step.get("with", {}).get("repository") == "MichaelTrueX/omnilyzer")
            self.assertEqual(checkout["with"]["ssh-key"], "${{ secrets.ANALYTICS_SOURCE_DEPLOY_KEY }}")
            self.assertNotIn("token", checkout["with"])
            self.assertEqual(checkout["with"]["ref"], "4cdda7faeba57abb3388f9be5c450fe6afb1140d")
            self.assertIs(checkout["with"]["persist-credentials"], False)
            index = steps.index(checkout)
            self.assertGreater(index, 0)
            precheck = steps[index - 1]
            self.assertIn("DEPLOY_KEY_MISSING", precheck["run"])
            self.assertEqual(precheck["env"]["ANALYTICS_DEPLOY_KEY"], "${{ secrets.ANALYTICS_SOURCE_DEPLOY_KEY }}")
            self.assertNotIn("echo $ANALYTICS_DEPLOY_KEY", precheck["run"])
            self.assertNotIn("set -x", precheck["run"])

    def test_private_source_oci_never_uploaded_unencrypted_to_public_repo(self) -> None:
        """Keep source TAR and OCI bytes out of publicly downloadable artifacts."""
        source = self.jobs["analytics-source-admission"]
        steps = source["steps"]
        encrypt = next(step for step in steps if step["name"].startswith("Encrypt private Analytics"))
        upload = next(step for step in steps if step["name"] == "Upload encrypted Analytics handoff ONLY")
        self.assertLess(steps.index(encrypt), steps.index(upload))
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/analytics-task013-transport.gpg")
        self.assertIn("release.analytics_private_handoff encrypt", encrypt["run"])
        self.assertIn('rm -rf -- "$RUNNER_TEMP/analytics-task013-unsigned"', encrypt["run"])
        self.assertNotIn("ANALYTICS_HANDOFF_PRIVATE_KEY", str(source))
        self.assertNotIn("ANALYTICS_HANDOFF_DECRYPT_KEY", str(source))
        self.assertNotIn("ANALYTICS_SOURCE_READ_TOKEN", self.raw)
        for name in ("analytics-publish-zot", "analytics-publish-forgejo"):
            job = self.jobs[name]
            self.assertEqual(job["environment"], "task013-dev-release")
            steps = job["steps"]
            decrypt = next(step for step in steps if step["name"].startswith("Decrypt private handoff"))
            self.assertEqual(decrypt["env"]["ANALYTICS_HANDOFF_PRIVATE_KEY"],
                             "${{ secrets.ANALYTICS_HANDOFF_DECRYPT_KEY }}")
            self.assertIn("release.analytics_private_handoff decrypt", decrypt["run"])
            download = next(step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")
                            and step["with"]["name"].startswith("analytics-task013-handoff-"))
            self.assertLess(steps.index(download), steps.index(decrypt))
            self.assertEqual(download["with"]["path"], "${{ runner.temp }}/analytics-task013-transport")
            self.assertFalse(any("upload-artifact@" in step.get("uses", "") and
                                 "source.tar" in step.get("with", {}).get("path", "")
                                 for step in steps))

    def test_analytics_live_registry_preflight_precedes_private_build(self) -> None:
        """Detect wrong registry ACL or an occupied version before OCI work."""
        job = self.jobs["analytics-registry-preflight"]
        self.assertEqual(job["if"],
                         "${{ inputs.product == 'analytics' && inputs.auth_probe == false }}")
        self.assertEqual(job["environment"], "task013-dev-release")
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write"})
        self.assertEqual(job["timeout-minutes"], 5)
        self.assertNotIn("needs", job)
        self.assertNotIn("secrets.", str(job))
        self.assertEqual(len(job["steps"]), 3)
        checkout, identity, preflight = job["steps"]
        self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
        self.assertIs(checkout["with"]["persist-credentials"], False)
        for exact in (
            "test \"$RELEASE_REPOSITORY\" = 'MichaelTrueX/omnilyzer-platform'",
            "test \"$RELEASE_REF\" = 'refs/heads/main'",
            'test "$REQUESTED_SHA" = "$RELEASE_SHA"',
            'test "$(git rev-parse HEAD)" = "$RELEASE_SHA"',
            "platform-release.yml@refs/heads/main",
        ):
            self.assertIn(exact, identity["run"])
        self.assertIn("release.request_oidc", preflight["run"])
        self.assertIn("--audience https://oci-dev.omnilyzer.ai", preflight["run"])
        self.assertIn("--audience u:2:316bec9a-53e4-4807-9557-7febdc979d0a",
                      preflight["run"])
        self.assertIn("release.registry_absence_preflight --product analytics",
                      preflight["run"])
        self.assertIn('--version "$RELEASE_VERSION"', preflight["run"])
        self.assertIn("trap 'rm -f", preflight["run"])
        self.assertEqual(preflight["env"]["RELEASE_VERSION"], "${{ inputs.version }}")
        for prohibited in ("publish_zot", "publish_forgejo", "cosign sign", "upload-artifact",
                           "docker push", "docker login", "--method POST", "--method PUT"):
            self.assertNotIn(prohibited, str(job))
        self.assertEqual(self.jobs["analytics-source-admission"]["needs"],
                         ["analytics-registry-preflight"])
        self.assertEqual(self.jobs["analytics-publish-zot"]["needs"],
                         ["analytics-source-admission"])
        # Keep final authoritative pre-write preflight, not a stale early check.
        final_publish = next(step for step in self.jobs["analytics-publish-zot"]["steps"]
                             if step["name"].startswith("Verify source, registry absence"))
        self.assertIn("release.registry_absence_preflight --product analytics",
                      final_publish["run"])

    def test_chatgpt_release_checkfile_is_required_and_exposes_source_pin_gap(self) -> None:
        """Instructions must not let the owner mistake 0.15.0 for reusable source admission."""
        guide = (ROOT / "docs/operations/task013-release-readiness.md").read_text()
        agent = (ROOT / "AGENTS.md").read_text()
        self.assertIn("docs/operations/task013-release-readiness.md", agent)
        for item in (
            "HOLD: DO NOT DISPATCH", "4cdda7faeba57abb3388f9be5c450fe6afb1140d",
            "Task014", "truexdevelopment", "truexmainserver",
            "ANALYTICS_SOURCE_DEPLOY_KEY", "ANALYTICS_HANDOFF_DECRYPT_KEY",
            "analytics-registry-preflight", "REGISTRY_PREFLIGHT", "HTTP 404",
            "release.tests.test_workflow_policy", "0 Critical / 0 High",
            "isDraft", "headRefOid", "baseRefName",
            "Open, draft or stacked PRs", "unprotected source `main`",
            "network-none BuildKit", "mutable transitive", "signed base",
            "repeated identical OCI digests",
        ):
            if item == "REGISTRY_PREFLIGHT":
                # The preflight is referenced by Python module, not a log marker.
                self.assertIn("registry_absence_preflight", guide)
            else:
                self.assertIn(item, guide)

    def test_manual_trigger_and_global_permissions_are_closed(self) -> None:
        self.assertEqual(self.workflow["permissions"], {})
        self.assertIn("workflow_dispatch", self.raw)
        self.assertNotRegex(self.raw, r"(?m)^  (?:push|pull_request|schedule):")

    def test_auth_probe_is_explicit_boolean_and_defaults_off(self) -> None:
        """Preserve the original two required release inputs and default behavior."""
        dispatched = self.workflow[True]["workflow_dispatch"]["inputs"]
        self.assertEqual(set(dispatched), {"version", "source_sha", "auth_probe", "product"})
        self.assertEqual(dispatched["product"]["options"], ["canary", "analytics"])
        self.assertEqual(dispatched["product"]["default"], "canary")
        self.assertIs(dispatched["version"]["required"], True)
        self.assertIs(dispatched["source_sha"]["required"], True)
        self.assertEqual(dispatched["auth_probe"],
                         {"description": "Read-only Forgejo OIDC diagnostic, skips build and publication",
                          "required": False, "type": "boolean", "default": False})

    def test_probe_and_release_paths_are_mutually_exclusive(self) -> None:
        """Prove diagnostic mode skips the gate, build, and both publishers."""
        self.assertEqual(self.jobs["forgejo-auth-probe"]["if"],
                         "${{ inputs.auth_probe == true && inputs.product == 'canary' }}")
        self.assertEqual(self.jobs["gate"]["if"], "${{ inputs.auth_probe == false && inputs.product == 'canary' }}")
        self.assertEqual(self.jobs["build"]["needs"], "gate")
        self.assertEqual(self.jobs["publish-zot"]["needs"], ["gate", "build"])
        self.assertEqual(self.jobs["publish-forgejo"]["needs"],
                         ["gate", "build", "publish-zot"])
        self.assertNotIn("needs", self.jobs["forgejo-auth-probe"])
        self.assertEqual(self.jobs["forgejo-auth-probe"]["environment"],
                         "task013-dev-release")
        self.assertEqual(self.jobs["forgejo-auth-probe"]["timeout-minutes"], 5)

    def test_probe_uses_exact_workflow_identity_and_no_writes(self) -> None:
        """Keep the OIDC JWT confined to one read-only package GET."""
        probe = self.jobs["forgejo-auth-probe"]
        self.assertEqual(probe["permissions"], {"contents": "read", "id-token": "write"})
        steps = probe["steps"]
        self.assertEqual(len(steps), 3)
        self.assertEqual(steps[0]["with"]["ref"], "${{ github.sha }}")
        self.assertIs(steps[0]["with"]["persist-credentials"], False)
        validation = steps[1]["run"]
        for check in (
            'test "$SOURCE_REPOSITORY" = "MichaelTrueX/omnilyzer-platform"',
            'test "$SOURCE_REF" = "refs/heads/main"',
            'test "$REQUESTED_SHA" = "$SOURCE_SHA"',
            'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
            'test "$SOURCE_WORKFLOW_REF" = "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main"',
        ):
            self.assertIn(check, validation)
        diagnostic = steps[2]["run"]
        self.assertIn('trap \'rm -f "$token_file"\' EXIT', diagnostic)
        self.assertIn("python3 -m release.request_oidc", diagnostic)
        self.assertIn("--audience u:2:316bec9a-53e4-4807-9557-7febdc979d0a",
                      diagnostic)
        self.assertIn("python3 -m release.forgejo_oidc_probe --token-file", diagnostic)
        for forbidden in ("publish_forgejo", "publish_zot", "docker login", "cosign sign",
                          "upload-artifact", "gh release", "curl -X", "http POST"):
            self.assertNotIn(forbidden, str(steps))
        source = (ROOT / "release/forgejo_oidc_probe.py").read_text(encoding="utf-8")
        self.assertIn('method="GET"', source)
        self.assertIn("https://registry-dev.omnilyzer.ai/api/v1/packages/omnilyzer?type=pypi&limit=1",
                      source)
        self.assertNotIn('method="POST"', source)
        self.assertNotIn('method="PUT"', source)

    def test_build_has_read_only_contents_and_no_oidc(self) -> None:
        self.assertEqual(self.jobs["build"]["permissions"], {"contents": "read"})
        self.assertNotIn("id-token", self.jobs["build"]["permissions"])

    def test_oidc_only_for_publishers_and_read_only_probe(self) -> None:
        """Do not grant id-token permission to the ordinary gate or build."""
        capable = [name for name, job in self.jobs.items()
                   if job.get("permissions", {}).get("id-token") == "write"]
        self.assertEqual(capable, ["forgejo-auth-probe", "analytics-registry-preflight",
                                   "analytics-publish-zot", "analytics-publish-forgejo",
                                   "publish-zot", "publish-forgejo"])
        for name in capable:
            self.assertEqual(self.jobs[name]["permissions"],
                             {"contents": "read", "id-token": "write"})

    def test_publishers_verify_before_oidc_and_do_not_build(self) -> None:
        for name in ("publish-zot", "publish-forgejo"):
            steps = self.jobs[name]["steps"]
            names = [step["name"] for step in steps]
            verify_index = names.index("Verify complete handoff before requesting OIDC")
            oidc_indexes = [index for index, step in enumerate(steps)
                            if index != verify_index and ("OIDC" in step["name"] or "keyless" in step["name"])]
            self.assertTrue(oidc_indexes and min(oidc_indexes) > verify_index)
            text = str(steps)
            self.assertNotIn("build_release artifacts", text)
            self.assertNotIn("npm pack", text)

    def test_exact_repository_ref_sha_and_workflow_identity_are_present(self) -> None:
        self.assertIn('test "$DISPATCH_REPOSITORY" = "MichaelTrueX/omnilyzer-platform"', self.raw)
        self.assertIn('test "$DISPATCH_REF" = "refs/heads/main"', self.raw)
        self.assertIn('test "$REQUESTED_SHA" = "$DISPATCH_SHA"', self.raw)
        environment = (ROOT / "release/environments/dev.json").read_text()
        self.assertIn("MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main", environment)

    def test_phase2_dev_canary_is_enabled_and_destinations_are_not_inputs(self) -> None:
        self.assertIn('"publishing_enabled": true', (ROOT / "release/environments/dev.json").read_text())
        self.assertEqual(self.jobs["publish-zot"]["if"], "needs.gate.outputs.publishing_enabled == 'true'")
        self.assertEqual(self.jobs["publish-forgejo"]["if"], "needs.gate.outputs.publishing_enabled == 'true'")
        # Inspect only YAML dispatch inputs, excluding introductory file comments.
        dispatch = self.raw.split("\non:\n", 1)[1].split("permissions: {}", 1)[0]
        self.assertNotIn("registry", dispatch.lower())
        self.assertNotIn("origin", dispatch.lower())
        self.assertEqual(self.jobs["publish-zot"]["environment"], "task013-dev-release")
        self.assertEqual(self.jobs["publish-forgejo"]["environment"], "task013-dev-release")

    def test_analytics_original_unsigned_build_scan_cannot_publish(self) -> None:
        """Exact PR52 built OCI and Grype evidence do not confer signer authority.

        Preserve canary publication isolation even when the Analytics job
        actually builds and scans an unsigned image with original tools.
        """
        rejected = self.jobs["deny-unsupported-dispatch"]
        self.assertEqual(rejected["permissions"], {"contents": "read"})
        self.assertNotIn("environment", rejected)
        self.assertNotIn("needs", rejected)
        self.assertIn("inputs.product != 'analytics'", rejected["if"])
        self.assertIn("inputs.auth_probe == true", rejected["if"])
        self.assertIn("exit 1", rejected["steps"][0]["run"])
        source_job = self.jobs["analytics-source-admission"]
        self.assertEqual(source_job["permissions"], {"contents": "read"})
        self.assertEqual(source_job["timeout-minutes"], 45)
        self.assertNotIn("environment", source_job)
        self.assertEqual(source_job["needs"], ["analytics-registry-preflight"])
        self.assertEqual(source_job["if"],
                         "${{ inputs.product == 'analytics' && inputs.auth_probe == false }}")
        self.assertEqual(self.jobs["gate"]["if"],
                         "${{ inputs.auth_probe == false && inputs.product == 'canary' }}")
        self.assertEqual(self.jobs["forgejo-auth-probe"]["if"],
                         "${{ inputs.auth_probe == true && inputs.product == 'canary' }}")
        steps = source_job["steps"]
        checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
        self.assertEqual(len(checkouts), 2)
        self.assertEqual(checkouts[1]["with"]["repository"], "MichaelTrueX/omnilyzer")
        self.assertEqual(checkouts[1]["with"]["ref"],
                         "4cdda7faeba57abb3388f9be5c450fe6afb1140d")
        self.assertEqual(checkouts[1]["with"]["fetch-depth"], 0)
        self.assertTrue(all(step["with"]["persist-credentials"] is False
                            for step in checkouts))
        admission = next(step for step in steps if step["name"] ==
                         "Enforce protected main, immutable Git revision, and strict source binding")
        run = admission["run"]
        for required in (
            'test "$DISPATCH_REF" = "refs/heads/main"',
            'test "$REQUESTED_SHA" = "$DISPATCH_SHA"',
            'test "$(git rev-parse HEAD)" = "$DISPATCH_SHA"',
            "python3 -m release.analytics_source_admission",
            "python3 -m release.analytics_task013_build_input",
            "NO SIGNATURE, NO REGISTRY, NO EXECUTOR",
        ):
            self.assertIn(required, run)
        for forbidden in ("id-token", "cosign", "publish_zot", "publish_forgejo",
                          "docker login", "docker push"):
            self.assertNotIn(forbidden, str(source_job))
        self.assertEqual(str(source_job).count('secrets.'), 2)
        self.assertNotIn('secrets.', str([step for step in steps
            if not step['name'].startswith('Require read-only Analytics Git deploy key')
            and step.get('with', {}).get('repository') != 'MichaelTrueX/omnilyzer']))
        names = [step["name"] for step in steps]
        self.assertLess(names.index("Build and verify immutable original Analytics OCI archive"),
                        names.index("Scan exact Analytics OCI and enforce original Critical High policy"))
        builder = next(step for step in steps if step["name"] ==
                       "Set up original pinned Analytics Buildx and BuildKit")
        self.assertEqual(builder["with"]["name"], "m01-analytics-task013")
        self.assertEqual(builder["with"]["version"], "v0.36.1")
        self.assertIn("moby/buildkit:v0.24.0@sha256:", builder["with"]["driver-opts"])
        build = next(step for step in steps if
                     step["name"] == "Build and verify immutable original Analytics OCI archive")
        self.assertIn("--retain-verified-artifacts", build["run"])
        self.assertIn("python3 -m release.analytics_release_source_binding", build["run"])
        self.assertIn("--immutable-context", build["run"])
        self.assertIn("--oci-archive", build["run"])
        self.assertIn("ORIGINAL_ANALYTICS_UNSIGNED_SOURCE_BINDING_PASS", build["run"])
        self.assertEqual(next(step for step in steps if step["name"] ==
                         "Install original pinned Analytics Syft")["with"]["syft-version"], "v1.51.0")
        self.assertEqual(next(step for step in steps if step["name"] ==
                         "Install original pinned Analytics Grype")["with"]["grype-version"], "v0.118.0")
        scan = next(step for step in steps if step["name"] ==
                    "Scan exact Analytics OCI and enforce original Critical High policy")
        for expected in ("release.vulnerability_policy", "validate_database_status",
                         "evaluate(policy_path, {'oci': scanner}",
                         "policy['exceptions'] != []", "'blocked_findings'", "decision",
                         "ORIGINAL_ANALYTICS_REAL_OCI_SYFT_GRYPE_POLICY_PASS_NO_WAIVERS"):
            if expected == "'blocked_findings'":
                self.assertIn("'blocked_findings'", scan["run"])
            else:
                self.assertIn(expected, scan["run"])
        self.assertEqual(self.jobs["publish-zot"]["needs"], ["gate", "build"])
        self.assertEqual(self.jobs["publish-forgejo"]["needs"],
                         ["gate", "build", "publish-zot"])

    def test_all_actions_are_full_sha_pinned_and_checkout_drops_credentials(self) -> None:
        uses = re.findall(r"uses:\s*([^\s#]+)", self.raw)
        self.assertTrue(uses)
        for value in uses:
            with self.subTest(value=value):
                self.assertRegex(value, r"^[^@]+@[0-9a-f]{40}$")
        checkout_count = self.raw.count("uses: actions/checkout@")
        self.assertEqual(self.raw.count("persist-credentials: false"), checkout_count)

    def test_grype_scans_use_pinned_installer_command_output(self) -> None:
        steps = self.jobs["build"]["steps"]
        installer = next(step for step in steps if step["name"] == "Install pinned Grype")
        scan = next(step for step in steps if step["name"] == "Generate CycloneDX 1.6 SBOM and Grype evidence")
        self.assertEqual(installer["id"], "grype")
        self.assertEqual(installer["with"]["grype-version"], "v0.118.0")
        self.assertEqual(scan["env"]["GRYPE_COMMAND"], "${{ steps.grype.outputs.cmd }}")
        script = scan["run"]
        self.assertIn('test -x "$GRYPE_COMMAND"', script)
        self.assertIn('"$GRYPE_COMMAND" version', script)
        self.assertIn('versions == ["0.118.0"]', script)
        self.assertEqual(script.count('"$GRYPE_COMMAND" "sbom:'), 3)
        self.assertIn('"$GRYPE_COMMAND" db status', script)
        self.assertNotRegex(script, r"(?m)^\s*grype(?:\s|$)")

    def test_no_long_lived_registry_credential_reference(self) -> None:
        forbidden = ("secrets.FORGEJO", "secrets.ZOT", "REGISTRY_PASSWORD", "REGISTRY_PAT", "API_KEY")
        for value in forbidden:
            self.assertNotIn(value, self.raw)

    def test_keyless_signatures_are_verified_against_exact_workflow_identity(self) -> None:
        self.assertIn("https://token.actions.githubusercontent.com", self.raw)
        self.assertIn(
            "https://github.com/MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main",
            self.raw,
        )
        self.assertGreaterEqual(self.raw.count("--certificate-identity"), 3)
        self.assertGreaterEqual(self.raw.count("--certificate-oidc-issuer"), 3)

    def test_forgejo_evidence_records_exact_github_context_before_signing(self) -> None:
        steps = self.jobs["publish-forgejo"]["steps"]
        generate = next(step for step in steps if step["name"] == "Verify complete handoff before requesting OIDC")
        sign = next(step for step in steps if step["name"] == "Create keyless signed release evidence")
        self.assertLess(steps.index(generate), steps.index(sign))
        for field, context in {
            "RELEASE_REPOSITORY": "github.repository",
            "RELEASE_REPOSITORY_ID": "github.repository_id",
            "RELEASE_WORKFLOW_REF": "github.workflow_ref",
            "RELEASE_WORKFLOW_SHA": "github.workflow_sha",
            "RELEASE_RUN_ID": "github.run_id",
            "RELEASE_RUN_ATTEMPT": "github.run_attempt",
            "RELEASE_EVENT_NAME": "github.event_name",
            "SOURCE_SHA": "github.sha",
        }.items():
            self.assertEqual(generate["env"][field], "${{ " + context + " }}")
        self.assertIn("python3 -m release.provenance", generate["run"])
        self.assertIn("cosign sign-blob", sign["run"])

    def test_authenticated_absence_gate_precedes_any_external_write(self) -> None:
        """Require read-only OIDC preflight before OCI and package publication."""
        zot = self.jobs["publish-zot"]
        steps = zot["steps"]
        names = [step["name"] for step in steps]
        preflight_index = names.index("Verify unused version on both registries before publication")
        publish_index = names.index("Request short-lived zot OIDC and publish prebuilt OCI")
        verify_index = names.index("Verify complete handoff before requesting OIDC")
        self.assertLess(verify_index, preflight_index)
        self.assertLess(preflight_index, publish_index)
        self.assertEqual(zot["needs"], ["gate", "build"])
        self.assertEqual(self.jobs["publish-forgejo"]["needs"], ["gate", "build", "publish-zot"])
        self.assertEqual(zot["permissions"], {"contents": "read", "id-token": "write"})
        self.assertEqual(zot["environment"], "task013-dev-release")
        step = steps[preflight_index]
        self.assertEqual(step["env"]["RELEASE_VERSION"], "${{ github.event.inputs.version }}")
        shell = step["run"]
        for required in (
            'umask 077',
            '--audience u:2:316bec9a-53e4-4807-9557-7febdc979d0a',
            '--audience https://oci-dev.omnilyzer.ai',
            'python3 -m release.registry_absence_preflight',
            '--version "$RELEASE_VERSION"',
            '--forgejo-token-file "$forgejo_token"',
            '--zot-token-file "$zot_token"',
            "trap 'rm -f",
        ):
            self.assertIn(required, shell)
        for forbidden in ("publish_zot", "publish_forgejo", "curl -X POST",
                          "http POST", "docker push", "npm publish"):
            self.assertNotIn(forbidden, shell)
        code = (ROOT / "release/registry_absence_preflight.py").read_text()
        self.assertIn('method="HEAD"', code)
        self.assertIn('method not in {"GET", "HEAD"}', code)
        self.assertNotIn('method="PUT"', code)
        self.assertNotIn('method="POST"', code)

    def test_forgejo_publisher_reads_back_each_prebuilt_output(self) -> None:
        code = (ROOT / "release/publish_forgejo.py").read_text()
        self.assertIn("PyPI round-trip bytes", code)
        self.assertIn("npm round-trip bytes", code)
        self.assertIn("Generic evidence round-trip bytes", code)
        self.assertNotIn("build_wheel", code)
        self.assertNotIn("build_npm", code)

    def test_oci_refuses_existing_tag_and_requires_exact_digest(self) -> None:
        code = (ROOT / "release/publish_zot.py").read_text()
        self.assertIn("immutable release tag already exists; overwrite refused", code)
        self.assertIn('status != 201', code)
        self.assertIn("sha256:[0-9a-f]{64}", code)
        self.assertNotIn('request("DELETE"', code)

    def test_task008_workflows_and_triggers_are_byte_identical(self) -> None:
        for relative, expected in PROTECTED.items():
            with self.subTest(relative=relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), expected)


class CanarySecurityReviewWorkflowTests(unittest.TestCase):
    """Guard the separate, unprivileged review-only security workflow."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.path = ROOT / ".github/workflows/task013-canary-security-review.yml"
        cls.raw = cls.path.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.raw)
        cls.job = cls.workflow["jobs"]["canary-security"]
        cls.steps = cls.job["steps"]

    def test_event_and_permissions_are_read_only(self) -> None:
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertIn("pull_request:", self.raw)
        self.assertNotRegex(self.raw, r"(?m)^  (?:push|workflow_dispatch|schedule):")
        self.assertNotIn("environment", self.job)
        self.assertNotIn("id-token", self.raw)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository",
                      self.job["if"])

    def test_every_external_action_is_exactly_pinned(self) -> None:
        names = [step["uses"] for step in self.steps if "uses" in step]
        self.assertEqual(len(names), 6)
        for name in names:
            with self.subTest(action=name):
                self.assertRegex(name, r"^[^@]+@[0-9a-f]{40}$")
        checkout = next(item for item in self.steps if item["name"] == "Check out exact PR HEAD")
        self.assertIs(checkout["with"]["persist-credentials"], False)
        self.assertEqual(checkout["with"]["ref"], "${{ github.event.pull_request.head.sha }}")

    def test_build_and_policy_are_fail_closed_without_publishing(self) -> None:
        build = next(item for item in self.steps if item["name"] == "Build private OCI review archive")
        self.assertIs(build["with"]["push"], False)
        self.assertIs(build["with"]["load"], False)
        self.assertEqual(build["with"]["outputs"],
                         "type=oci,dest=${{ runner.temp }}/task013-review-handoff/"
                         "task013-release-canary-0.14.3.oci.tar")
        self.assertIn("network: none", self.raw)
        names = [step["name"] for step in self.steps]
        self.assertLess(names.index("Verify exact executable OCI contract"),
                        names.index("Apply unchanged fail-closed Critical/High policy"))
        self.assertIn("python3 -m release.denial_evidence", self.raw)
        self.assertIn("python3 -m release.vulnerability_policy", self.raw)
        for banned in ("cosign sign", "request_oidc", "publish_zot", "publish_forgejo",
                       "docker login", "docker push", "gh release create"):
            self.assertNotIn(banned, self.raw)


class AnalyticsProtectedPublicationTests(unittest.TestCase):
    """Section: protect the new Analytics-only signers and original canary gates."""
    @classmethod
    def setUpClass(cls):
        cls.jobs = yaml.safe_load(WORKFLOW_PATH.read_text())['jobs']

    def test_analytics_release_depends_on_scanned_source_and_zot(self):
        """Neither publisher may bypass the actual admission/scan job."""
        zot = self.jobs['analytics-publish-zot']
        forgejo = self.jobs['analytics-publish-forgejo']
        self.assertEqual(zot['needs'], ['analytics-source-admission'])
        self.assertEqual(forgejo['needs'], ['analytics-source-admission', 'analytics-publish-zot'])
        self.assertEqual(zot['environment'], 'task013-dev-release')
        self.assertEqual(forgejo['environment'], 'task013-dev-release')
        for job in (zot, forgejo):
            self.assertEqual(job['permissions'], {'contents': 'read', 'id-token': 'write'})
            self.assertIn("inputs.product == 'analytics'", job['if'])
            if job is zot:
                self.assertEqual(str(job).count('secrets.'), 3)
            else:
                self.assertEqual(str(job).count('secrets.'), 1)

    def test_signatures_are_verified_before_forgejo_publication(self):
        """Require the real protected-main signer and digest-specific Cosign."""
        steps = self.jobs['analytics-publish-forgejo']['steps']
        sign = next(s['run'] for s in steps if s['name'].startswith('Sign and cryptographically'))
        self.assertIn('cosign sign-blob', sign)
        self.assertIn('cosign verify-blob', sign)
        self.assertIn('cosign sign --yes "oci-dev.omnilyzer.ai/omnilyzer/analytics@$digest"', sign)
        self.assertIn('cosign verify --certificate-identity', sign)
        self.assertIn('@refs/heads/main', next(s for s in steps if s['name'].startswith('Sign and cryptographically'))['env']['CERTIFICATE_IDENTITY'])
        self.assertLess(next(i for i,s in enumerate(steps) if s['name'].startswith('Sign and cryptographically')),
                        next(i for i,s in enumerate(steps) if s['name'].startswith('Publish signed Analytics')))

    def test_downstream_failure_explicitly_holds_partial_zot_publish(self):
        """Section: never treat a signed-evidence failure as authorized Task014."""
        steps = self.jobs['analytics-publish-forgejo']['steps']
        warning = next(s for s in steps if s['name'].startswith('Warn about immutable partial'))
        self.assertEqual(warning['if'], 'failure()')
        run = warning['run']
        self.assertIn('partial-release HOLD', run)
        self.assertIn('Do not deploy', run)
        self.assertIn('Do not deploy', run)
        self.assertIn('Follow docs/operations/m05-13-analytics-partial-release-recovery', run)
        self.assertNotIn('DELETE ', run)
        self.assertNotIn('docker push', run)
        self.assertNotIn('cosign sign', run)

    def test_no_canary_rewire_and_provenance_is_oci_only(self):
        """Keep legacy canary flow and prohibit fake Python/npm artifacts."""
        self.assertEqual(self.jobs['gate']['if'],
                         "${{ inputs.auth_probe == false && inputs.product == 'canary' }}")
        self.assertEqual(self.jobs['publish-forgejo']['needs'], ['gate', 'build', 'publish-zot'])
        script = (ROOT / 'release/analytics_release_evidence.py').read_text()
        self.assertIn("'oci_manifest_digest'", script)
        self.assertNotIn('python_wheel_sha256', script)
        self.assertNotIn('npm_tarball_sha256', script)
