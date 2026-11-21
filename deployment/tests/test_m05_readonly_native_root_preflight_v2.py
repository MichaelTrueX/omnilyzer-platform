"""File: deployment/tests/test_m05_readonly_native_root_preflight_v2.py
Purpose: Source-only test that M05's native-root read-only diagnostic accepts
         the verified split source graph, rejects tampering, and never reads
         three unqualified historical SCRATCH runtime modules.
Related: deployment/operators/m05_source_stage_cfc.py, PR318 and Issue281.
Sections: fixture source simulation, positive and tampering controls.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
REVIEW=Path("/home/omnigpt/repos/omnilyzer-platform/.delivery/m05-pr316-source-stage-closure-review-20261121")
REVIEW_SOURCE=Path("/tmp/m05-pr316-review-source-cfc274-20261121")
SOURCE=REVIEW_SOURCE if REVIEW_SOURCE.is_dir() else REPO
REPO_OPERATOR=REPO/"deployment/operators/m05_readonly_native_root_preflight_v2.py"
PATH=REPO_OPERATOR if REPO_OPERATOR.is_file() else REVIEW/"m05_readonly_native_root_preflight_v2.py"
HAS_ROOT_FIXTURE=(
    (Path("/opt/omnilyzer/deployment/analytics-app-release-330f3255f0067b9ddbe30d50466830bd71a55a11").is_dir())
    and REVIEW.is_dir() and PATH.is_file()
)


def load():
    """Load the staged preflight for mocked non-root source-only evaluation."""
    spec=importlib.util.spec_from_file_location("m05_root_readonly_v2_review", PATH)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(HAS_ROOT_FIXTURE, "Requires DEV immutable root source and reviewed handoff")
class SplitNativeRootReadOnlyReviewTests(unittest.TestCase):
    """Test the exact 45+16 origin split, failclosed behavior and immutability."""

    def setUp(self):
        self.m=load()
        self.baseline=json.loads(self.m.MANIFEST.read_text())["baseline_files_sha256"]
        self.extra,self.graph=self.m.parse_source_contract(self.m.STAGE.read_bytes())
        self.assertEqual((len(self.graph),len(self.graph&set(self.baseline)),len(self.extra)),(61,45,16))
        self.original=self.m.read_regular

    def run_review(self, bad_source: str | None=None):
        """Simulate root identity and protected SCRATCH bytes without writes."""
        attempted=[]

        def fixture(path, *,uid, gid, mode, max_bytes):
            path=Path(path)
            if path.is_relative_to(self.m.SCRATCH):
                relative=path.relative_to(self.m.SCRATCH).as_posix()
                attempted.append(("scratch",relative))
                if relative in self.baseline:
                    raise AssertionError("unreviewed scratch runtime file accessed")
                source=SOURCE/relative
                self.assertEqual(mode,0o400 if relative=="deployment/analytics_isolated_source_install.py" else None)
                raw=source.read_bytes()
                return b"# source unexpectedly changed" if relative==bad_source else raw
            if path.is_relative_to(self.m.ROOT):
                relative=path.relative_to(self.m.ROOT).as_posix()
                attempted.append(("root",relative))
                self.assertIn(relative,self.baseline)
                self.assertEqual(mode,0o644)
                return b"# source unexpectedly changed" if relative==bad_source else self.original(path,uid=uid,gid=gid,mode=mode,max_bytes=max_bytes)
            return self.original(path,uid=uid,gid=gid,mode=mode,max_bytes=max_bytes)

        output=io.StringIO()
        with (
            patch.object(self.m.os,"getuid",return_value=0),
            patch.object(self.m.os,"geteuid",return_value=0),
            patch.object(self.m.os,"getgid",return_value=0),
            patch.object(self.m.os,"getegid",return_value=0),
            patch.object(self.m.socket,"gethostname",return_value="omnilyzerdev"),
            patch.object(self.m,"read_regular",side_effect=fixture),
            patch.object(self.m,"check_ancestors",return_value=None),
            contextlib.redirect_stdout(output)
        ):
            result=self.m.main()
        return result,output.getvalue(),attempted

    def test_source_only_full_61_graph_positive(self):
        result,output,seen=self.run_review()
        self.assertEqual(result,0,output)
        self.assertIn("M05_NATIVE_ROOT_READONLY_SPLIT_CLOSURE_PASS module_count=61 runtime_330f=45 importer_extras=16",output)
        self.assertEqual(len(seen),61)
        self.assertEqual(sum(1 for p,_ in seen if p=="root"),45)
        self.assertEqual(sum(1 for p,_ in seen if p=="scratch"),16)

    def test_tampered_historical_runtime_rejected(self):
        result,output,_=self.run_review("deployment/analytics_first_install.py")
        self.assertNotEqual(result,0)
        self.assertIn("M05_NATIVE_ROOT_PREFLIGHT_HOLD",output)

    def test_tampered_pinned_installer_extra_rejected(self):
        result,output,_=self.run_review("deployment/analytics_source_archive.py")
        self.assertNotEqual(result,0)
        self.assertIn("M05_NATIVE_ROOT_PREFLIGHT_HOLD",output)

    def test_exact_stage_digest_bound(self):
        self.assertEqual(hashlib.sha256(self.m.STAGE.read_bytes()).hexdigest(),self.m.OP_SHA)
        self.assertEqual(self.m.OP_SHA,"adc601b86738011e7e0903b6e0aa545767d8b089c47af3ae6ac7a81292317fb1")

if __name__=="__main__":
    unittest.main(verbosity=2)
