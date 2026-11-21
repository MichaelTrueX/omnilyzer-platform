"""Independent unprivileged QA of exact-root importer pin, no root install."""
import hashlib
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch

REPO = pathlib.Path(__file__).resolve().parents[2]
REPO_OPERATOR = REPO / "deployment/operators/m05_source_stage_cfc.py"
OP = REPO_OPERATOR if REPO_OPERATOR.is_file() else pathlib.Path(__file__).with_name(
    "root-source-stage-reviewed.py"
)
REVIEW_SOURCE = pathlib.Path("/tmp/m05-pr316-review-source-cfc274-20261121")
SOURCE = REVIEW_SOURCE if REVIEW_SOURCE.is_dir() else REPO
ORIGINAL = (SOURCE / "deployment/analytics_isolated_source_install.py").read_bytes()
HAS_REAL_ROOT_BASELINE = pathlib.Path(
    "/opt/omnilyzer/deployment/analytics-app-release-330f3255f0067b9ddbe30d50466830bd71a55a11"
).is_dir()

def load():
    spec = importlib.util.spec_from_file_location("m05_stage_reviewed_source_only", OP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class RootSourcePinReviewTests(unittest.TestCase):
    def test_original_root_installer_actual_git_bytes_match_owner_root_sha(self):
        module = load()
        self.assertEqual(module.INSTALLER_SHA,
            "cc7dfd7fb022a01772bb2f18fd1705f6e4f15e706903e4b47c8833b7d7f9ac5b")
        self.assertEqual(hashlib.sha256(ORIGINAL).hexdigest(), module.INSTALLER_SHA)

    @unittest.skipUnless(HAS_REAL_ROOT_BASELINE, "Requires DEV 76-file root-owned baseline")
    def test_tampered_installer_denied_before_any_python_import_or_root_stage(self):
        module = load()
        original = module.trusted_root_file
        def read(path,mode):
            if pathlib.Path(path) == module.INSTALLER:
                self.assertEqual(mode,0o500)
                return ORIGINAL + b"\n# CHANGED BY QA\n"
            return original(path,mode)
        with patch.object(module,"trusted_root_file",side_effect=read):
            with self.assertRaisesRegex(ValueError,"installer SHA is not approved"):
                module.reviewed_source()
        self.assertNotIn(str(module.SCRATCH),sys.path)

    @unittest.skipUnless(HAS_REAL_ROOT_BASELINE, "Requires DEV 76-file root-owned baseline")
    def test_unreviewed_preloaded_deployment_package_denied(self):
        module=load()
        original=module.trusted_root_file
        def read(path,mode):
            return ORIGINAL if pathlib.Path(path)==module.INSTALLER else original(path,mode)
        with patch.object(module,"trusted_root_file",side_effect=read),patch.dict(
            sys.modules,{"deployment":object()}
        ):
            with self.assertRaisesRegex(ValueError,"modules already loaded"):
                module.reviewed_source()

    @unittest.skipUnless(HAS_REAL_ROOT_BASELINE, "Requires DEV 76-file root-owned baseline")
    def test_positive_source_only_import_origin_and_all_76_bytes(self):
        module=load()
        original=module.trusted_root_file
        module.SCRATCH=SOURCE
        module.INSTALLER=SOURCE/"deployment/analytics_isolated_source_install.py"
        def read(path,mode):
            return ORIGINAL if pathlib.Path(path)==module.INSTALLER else original(path,mode)
        before=set(sys.modules)
        try:
            with patch.object(module,"trusted_root_file",side_effect=read):
                installer,files=module.reviewed_source()
            self.assertEqual(pathlib.Path(installer.__file__),module.INSTALLER)
            self.assertEqual(len(files),76)
            self.assertEqual(len(set(name for name,_ in files)),76)
            self.assertEqual(len(module.REPLACEMENTS_SHA),2)
            self.assertEqual(
                {name:hashlib.sha256(data).hexdigest() for name,data in files if name in module.REPLACEMENTS_SHA},
                module.REPLACEMENTS_SHA,
            )
        finally:
            for key in set(sys.modules)-before:
                if key=="deployment" or key.startswith("deployment."):
                    sys.modules.pop(key,None)
            sys.path[:]=[x for x in sys.path if x!=str(SOURCE)]

if __name__=="__main__":
    unittest.main()
