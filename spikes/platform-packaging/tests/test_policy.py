import json
import sys
import unittest
from pathlib import Path

SPIKE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SPIKE_ROOT / "scripts"))

from validate_compatibility import major, validate_contract_change
from verify_release import has_sensitive_content, validate_release_set


class PolicyTests(unittest.TestCase):
    def test_release_content_rejects_generic_developer_paths_and_keys(self):
        for content in (
            b"/home/developer/repos/project/file.py",
            b"/Users/developer/workspaces/project/file.py",
            b"/repos/project/file.py",
            b"/workspace/project/file.py",
            b"C:\\Users\\developer\\repos\\project\\file.py",
            b"-----BEGIN PRIVATE " + b"KEY-----",
        ):
            with self.subTest(content=content):
                self.assertTrue(has_sensitive_content(content))
        self.assertFalse(has_sensitive_content(b"public package metadata"))

    def test_semver_shape(self):
        self.assertEqual(major("1.1.0"), 1)
        with self.assertRaises(AssertionError):
            major("1.1")

    def test_same_major_addition(self):
        self.assertTrue(validate_contract_change("1.0.0", {"publicApi": ["a"]}, "1.1.0", {"publicApi": ["a", "b"]}))

    def test_same_major_removal_rejected(self):
        with self.assertRaises(AssertionError):
            validate_contract_change("1.0.0", {"publicApi": ["a", "b"]}, "1.1.0", {"publicApi": ["a"]})

    def test_major_break_allowed(self):
        self.assertTrue(validate_contract_change("1.0.0", {"publicApi": ["a"]}, "2.0.0", {"publicApi": []}))

    def test_mixed_release_rejected(self):
        manifest = {
            "platformReleaseVersion": "1.1.0",
            "artifacts": [
                {"artifactPackageName": "python", "artifactPackageVersion": "1.1.0"},
                {"artifactPackageName": "web", "artifactPackageVersion": "1.0.0"},
                {"artifactPackageName": "governance", "artifactPackageVersion": "1.1.0"},
            ],
        }
        with self.assertRaises(AssertionError):
            validate_release_set(manifest)


if __name__ == "__main__":
    unittest.main()
