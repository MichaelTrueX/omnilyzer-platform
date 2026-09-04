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

    def test_manual_trigger_and_global_permissions_are_closed(self) -> None:
        self.assertEqual(self.workflow["permissions"], {})
        self.assertIn("workflow_dispatch", self.raw)
        self.assertNotIn("push:", self.raw)

    def test_build_has_read_only_contents_and_no_oidc(self) -> None:
        self.assertEqual(self.jobs["build"]["permissions"], {"contents": "read"})
        self.assertNotIn("id-token", self.jobs["build"]["permissions"])

    def test_only_publishers_have_oidc(self) -> None:
        capable = [name for name, job in self.jobs.items() if job.get("permissions", {}).get("id-token") == "write"]
        self.assertEqual(capable, ["publish-zot", "publish-forgejo"])
        for name in capable:
            self.assertEqual(self.jobs[name]["permissions"], {"contents": "read", "id-token": "write"})

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
        dispatch = self.raw.split("permissions: {}", 1)[0]
        self.assertNotIn("registry", dispatch.lower())
        self.assertNotIn("origin", dispatch.lower())
        self.assertEqual(self.jobs["publish-zot"]["environment"], "task013-dev-release")
        self.assertEqual(self.jobs["publish-forgejo"]["environment"], "task013-dev-release")

    def test_all_actions_are_full_sha_pinned_and_checkout_drops_credentials(self) -> None:
        uses = re.findall(r"uses:\s*([^\s#]+)", self.raw)
        self.assertTrue(uses)
        for value in uses:
            with self.subTest(value=value):
                self.assertRegex(value, r"^[^@]+@[0-9a-f]{40}$")
        checkout_count = self.raw.count("uses: actions/checkout@")
        self.assertEqual(self.raw.count("persist-credentials: false"), checkout_count)

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
