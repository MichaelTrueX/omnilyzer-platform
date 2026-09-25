from __future__ import annotations

import json
import zipfile
from pathlib import Path
import tempfile
import unittest

from release.build_release import local_canary
from release.provenance import WORKFLOW_REF, create, release_execution
from release.prepare_scan_roots import extract_npm, extract_wheel
from release.release_plan import materialize
from release.verify_handoff import HandoffError, verify

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "release/fixtures/task013-canary/release-plan-template.json"
POLICY = ROOT / "release/vulnerability-policy.json"
SHA = "f2575b9a90c0f3a03ec0730c2a5ff7fea1ed17e5"


class BuildHandoffTests(unittest.TestCase):
    def test_release_execution_rejects_unreviewed_or_malformed_context(self) -> None:
        values = {
            "repository": "MichaelTrueX/omnilyzer-platform", "repository_id": "1350104356",
            "workflow_ref": WORKFLOW_REF, "workflow_sha": SHA,
            "run_id": "34088735049", "run_attempt": "1",
            "event_name": "workflow_dispatch", "source_commit": SHA,
        }
        self.assertEqual(release_execution(**values)["run_id"], 34088735049)
        for field, bad in (
            ("repository", "attacker/repo"), ("repository_id", "1"),
            ("workflow_ref", "attacker/workflow"), ("workflow_sha", "a" * 40),
            ("run_id", "0"), ("run_id", "01"), ("run_id", "9223372036854775808"),
            ("run_id", True), ("run_attempt", "0"), ("run_attempt", "1.0"),
            ("run_attempt", "9223372036854775808"),
            ("event_name", "push"), ("source_commit", "f" * 40),
        ):
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                release_execution(**{**values, field: bad})

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.plan = base / "plan.json"
        self.handoff = base / "handoff"
        materialize(TEMPLATE, "1.2.3", SHA, self.plan, ROOT)
        local_canary(self.plan, self.handoff, ROOT, POLICY, "2026-09-04")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_local_canary_build_is_deterministic(self) -> None:
        second = Path(self.temp.name) / "second"
        local_canary(self.plan, second, ROOT, POLICY, "2026-09-04")
        first_files = {p.name: p.read_bytes() for p in self.handoff.iterdir()}
        second_files = {p.name: p.read_bytes() for p in second.iterdir()}
        self.assertEqual(first_files, second_files)

    def test_release_engine_is_not_hard_coded_to_canary_identities(self) -> None:
        implementation = (ROOT / "release/build_release.py").read_text()
        self.assertNotIn("omnilyzer-release-canary", implementation)
        self.assertNotIn("omnilyzer_release_canary", implementation)
        self.assertNotIn("omnilyzer/task013-release-canary", implementation)

    def test_expected_artifacts_and_three_cyclonedx_16_sboms_exist(self) -> None:
        result = verify(self.handoff, ROOT, "1.2.3", SHA)
        plan = result["plan"]
        for field in ("python_wheel", "npm_tarball", "oci_archive"):
            self.assertTrue((self.handoff / plan["artifacts"][field]).is_file())
        for filename in plan["artifacts"]["sboms"].values():
            sbom = json.loads((self.handoff / filename).read_text())
            self.assertEqual((sbom["bomFormat"], sbom["specVersion"]), ("CycloneDX", "1.6"))
        with zipfile.ZipFile(self.handoff / plan["artifacts"]["python_wheel"]) as wheel:
            self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in wheel.namelist()))

    def test_package_scan_roots_extract_without_execution(self) -> None:
        scan = Path(self.temp.name) / "scan"
        wheel = next(self.handoff.glob("*.whl"))
        npm = next(self.handoff.glob("*.tgz"))
        extract_wheel(wheel, scan / "python")
        extract_npm(npm, scan / "npm")
        self.assertTrue((scan / "python/omnilyzer_release_canary/__init__.py").is_file())
        self.assertTrue((scan / "npm/package/package.json").is_file())

    def test_checksum_tampering_is_rejected(self) -> None:
        wheel = next(self.handoff.glob("*.whl"))
        wheel.write_bytes(wheel.read_bytes() + b"tamper")
        with self.assertRaisesRegex(HandoffError, "checksum"):
            verify(self.handoff, ROOT, "1.2.3", SHA)

    def test_policy_and_database_evidence_tampering_is_rejected(self) -> None:
        result = self.handoff / "vulnerability-policy-result.json"
        result.write_bytes(result.read_bytes() + b" ")
        with self.assertRaisesRegex(HandoffError, "result checksum"):
            verify(self.handoff, ROOT, "1.2.3", SHA)

    def test_unknown_and_missing_handoff_files_are_rejected(self) -> None:
        (self.handoff / "unexpected").write_text("no")
        with self.assertRaisesRegex(HandoffError, "file set"):
            verify(self.handoff, ROOT, "1.2.3", SHA)

    def test_source_and_version_authority_are_rechecked(self) -> None:
        with self.assertRaises(HandoffError):
            verify(self.handoff, ROOT, "1.2.4", SHA)
        with self.assertRaises(HandoffError):
            verify(self.handoff, ROOT, "1.2.3", "1" * 40)

    def test_publishers_reject_synthetic_scanner_evidence(self) -> None:
        with self.assertRaisesRegex(HandoffError, "non-production"):
            verify(self.handoff, ROOT, "1.2.3", SHA, require_production_evidence=True)

    def test_release_manifest_requires_and_records_exact_oci_digest(self) -> None:
        build_path = self.handoff / "build-manifest.json"
        build = json.loads(build_path.read_text())
        build["evidence_mode"] = "production-tools"
        build_path.write_text(json.dumps(build, sort_keys=True, separators=(",", ":")) + "\n")
        publication_root = Path(self.temp.name) / "zot-result"
        publication_root.mkdir()
        publication = publication_root / "oci-publication.json"
        publication.write_text(json.dumps({
            "schema_version": 1, "registry": "https://oci-dev.omnilyzer.ai",
            "repository": "omnilyzer/task013-release-canary", "tag": "1.2.3",
            "manifest_digest": build["expected_oci_manifest_digest"],
        }))
        output = Path(self.temp.name) / "evidence"
        execution = release_execution(
            repository="MichaelTrueX/omnilyzer-platform", repository_id="1350104356",
            workflow_ref=WORKFLOW_REF, workflow_sha=SHA, run_id="34088735049",
            run_attempt="1", event_name="workflow_dispatch", source_commit=SHA,
        )
        create(self.handoff, publication, output, ROOT, "1.2.3", SHA, execution=execution)
        final = json.loads((output / "release-manifest.json").read_text())
        self.assertRegex(final["oci"]["manifest_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(final["oci"]["deployment_identity"],
                         f"omnilyzer/task013-release-canary@{final['oci']['manifest_digest']}")
        self.assertRegex(final["build_manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(final["vulnerability_policy_result_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("no formal SLSA", (output / "release-provenance.json").read_text())
        provenance = json.loads((output / "release-provenance.json").read_text())
        self.assertEqual(provenance["execution"], execution)
        self.assertEqual(provenance["schema_version"], 2)
        self.assertEqual(final["schema_version"], 2)
