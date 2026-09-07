from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

from release.build_release import build_oci, build_packages
from release.denial_evidence import IDENTITY_FILENAME, stage_denial_evidence
from release.release_plan import materialize


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/platform-release.yml"
VERSION = "0.14.2"
SOURCE_SHA = "1" * 40
DENIAL_FILES = {
    IDENTITY_FILENAME,
    "vulnerability-policy.json",
    "python-grype.json", "npm-grype.json", "oci-grype.json",
    "grype-db-status.json",
    "python-sbom.cdx.json", "npm-sbom.cdx.json", "oci-sbom.cdx.json",
}


def grype_report(*, high: bool = False) -> bytes:
    matches = []
    if high:
        matches.append({
            "vulnerability": {"id": "CVE-2026-1", "severity": "High"},
            "artifact": {"name": "python", "version": "3.12.14"},
        })
    return (json.dumps({
        "descriptor": {"name": "grype", "version": "0.118.0"},
        "matches": matches,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()


class DenialEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        plan_path = self.root / "plan.json"
        materialize(
            ROOT / "release/fixtures/task013-canary/release-plan-template.json",
            VERSION, SOURCE_SHA, plan_path, ROOT,
        )
        self.handoff = self.root / "handoff"
        info = build_packages(plan_path, self.handoff, ROOT)
        plan = json.loads((self.handoff / "release-plan.json").read_text())
        oci, self.manifest_digest = build_oci(
            info["oci_source"], plan["packages"]["oci"]["repository"], VERSION,
        )
        info["oci_archive"].write_bytes(oci)
        for filename in plan["artifacts"]["sboms"].values():
            (self.handoff / filename).write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}\n')
        for filename in plan["artifacts"]["vulnerability_reports"].values():
            (self.handoff / filename).write_bytes(grype_report())
        (self.handoff / "grype-db-status.json").write_text(
            '{"built":"2026-09-07T00:00:00Z","checksum":"sha256:' + "2" * 64
            + '","schema_version":"v6","valid":true}\n',
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_identity_is_canonical_and_binds_exact_artifacts(self) -> None:
        output = self.root / "denial"
        identity = stage_denial_evidence(
            self.handoff, ROOT / "release/vulnerability-policy.json", output,
            ROOT, VERSION, SOURCE_SHA,
        )
        self.assertEqual(set(path.name for path in output.iterdir()), DENIAL_FILES)
        self.assertEqual(identity["schema_version"], 1)
        self.assertEqual(identity["release_version"], VERSION)
        self.assertEqual(identity["source_sha"], SOURCE_SHA)
        self.assertEqual(identity["oci_manifest_digest"], self.manifest_digest)
        for prefix, path in (
            ("oci_archive", next(self.handoff.glob("*.oci.tar"))),
            ("python_wheel", next(self.handoff.glob("*.whl"))),
            ("npm_tarball", next(self.handoff.glob("*.tgz"))),
        ):
            self.assertEqual(identity[f"{prefix}_filename"], path.name)
            self.assertEqual(identity[f"{prefix}_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        expected = json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n"
        self.assertEqual((output / IDENTITY_FILENAME).read_text(), expected)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir()))

    def test_policy_deny_exits_nonzero_after_retaining_blocked_findings(self) -> None:
        output = self.root / "denial"
        stage_denial_evidence(
            self.handoff, ROOT / "release/vulnerability-policy.json", output,
            ROOT, VERSION, SOURCE_SHA,
        )
        (output / "oci-grype.json").write_bytes(grype_report(high=True))
        result_path = output / "vulnerability-policy-result.json"
        result = subprocess.run([
            sys.executable, "-m", "release.vulnerability_policy",
            "--policy", str(output / "vulnerability-policy.json"),
            "--python", str(output / "python-grype.json"),
            "--npm", str(output / "npm-grype.json"),
            "--oci", str(output / "oci-grype.json"),
            "--evaluation-date", dt.date(2026, 9, 7).isoformat(),
            "--output", str(result_path),
        ], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result_path.is_file())
        retained = json.loads(result_path.read_text())
        self.assertEqual(retained["decision"], "FAIL")
        self.assertEqual(retained["blocked_findings"], [{
            "package": "python", "severity": "High", "target": "oci",
            "version": "3.12.14", "vulnerability_id": "CVE-2026-1",
        }])


class DenialWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.raw)
        cls.jobs = cls.workflow["jobs"]
        cls.steps = cls.jobs["build"]["steps"]
        cls.by_name = {step["name"]: step for step in cls.steps}

    def test_denial_upload_is_failure_only_and_cannot_clear_failure(self) -> None:
        policy = self.by_name["Apply fail-closed vulnerability policy"]
        upload = self.by_name["Upload denied-release diagnostic evidence"]
        self.assertEqual(policy["id"], "vulnerability_policy")
        self.assertNotIn("continue-on-error", policy)
        self.assertEqual(upload["if"], "always() && steps.vulnerability_policy.outcome == 'failure'")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")

    def test_deny_skips_finalization_and_successful_handoff(self) -> None:
        finalize = self.by_name["Finalize and verify immutable handoff"]
        success_upload = self.by_name["Upload immutable build handoff for transport only"]
        self.assertEqual(finalize["if"], "steps.vulnerability_policy.outcome == 'success'")
        self.assertEqual(
            success_upload["if"],
            "success() && steps.vulnerability_policy.outcome == 'success'",
        )
        names = [step["name"] for step in self.steps]
        self.assertLess(names.index("Apply fail-closed vulnerability policy"), names.index(finalize["name"]))
        self.assertLess(names.index(finalize["name"]), names.index(success_upload["name"]))

    def test_publishers_consume_only_successful_handoff_after_successful_build(self) -> None:
        for name in ("publish-zot", "publish-forgejo"):
            job = self.jobs[name]
            needs = [job["needs"]] if isinstance(job["needs"], str) else job["needs"]
            self.assertIn("build", needs)
            serialized = json.dumps(job, sort_keys=True)
            self.assertIn("platform-release-handoff-", serialized)
            self.assertNotIn("platform-release-denial-evidence", serialized)

    def test_diagnostic_bundle_is_closed_and_excludes_secret_material(self) -> None:
        prepare = self.by_name["Prepare denied-release diagnostic evidence"]
        upload = self.by_name["Upload denied-release diagnostic evidence"]
        self.assertIn("release.denial_evidence", prepare["run"])
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/platform-release-denial-evidence")
        operational_paths = json.dumps({
            "prepare": prepare["run"],
            "upload": upload["with"]["path"],
            "files": sorted(DENIAL_FILES),
        }).lower()
        for forbidden in ("token", "credential", "secret", ".jwt"):
            self.assertNotIn(forbidden, operational_paths)

    def test_build_has_no_oidc_and_pass_path_still_finalizes(self) -> None:
        self.assertEqual(self.jobs["build"]["permissions"], {"contents": "read"})
        self.assertNotIn("id-token", self.jobs["build"]["permissions"])
        finalize = self.by_name["Finalize and verify immutable handoff"]["run"]
        self.assertIn("release.build_release finalize", finalize)
        self.assertIn("release.verify_handoff", finalize)


if __name__ == "__main__":
    unittest.main()
