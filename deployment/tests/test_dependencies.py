from __future__ import annotations

import importlib.metadata
from pathlib import Path
import re
import sys
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "deployment/pyproject.toml"
LOCK = ROOT / "deployment/requirements-linux-x86_64-py312.lock"
DOCUMENTATION = ROOT / "deployment/DEPENDENCIES.md"

EXPECTED = {
    "PyJWT[crypto]": (
        "2.13.0", "pyjwt-2.13.0-py3-none-any.whl",
        "66adcc2aff09b3f1bbd95fc1e1577df8ac8723c978552fd43304c8a290ac5728",
    ),
    "cryptography": (
        "50.0.1", "cryptography-50.0.1-cp311-abi3-manylinux_2_34_x86_64.whl",
        "51afcfceb15597cf2635068e4ac9a56b2abde622edde17f37d85fd7b5306497a",
    ),
    "cffi": (
        "2.1.1", "cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
        "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf",
    ),
    "pycparser": (
        "3.0", "pycparser-3.0-py3-none-any.whl",
        "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992",
    ),
}


def lock_entries() -> dict[str, tuple[str, str, str]]:
    raw = LOCK.read_text(encoding="utf-8")
    lines = raw.splitlines()
    entries: dict[str, tuple[str, str, str]] = {}
    wheel = None
    for index, line in enumerate(lines):
        if line.startswith("# wheel: "):
            wheel = line.removeprefix("# wheel: ")
        elif line and not line.startswith(("#", " ")):
            match = re.fullmatch(r"([A-Za-z0-9_-]+(?:\[[a-z]+\])?)==([^ \\]+) \\", line)
            if match is None or wheel is None or index + 1 >= len(lines):
                raise AssertionError("lock entry is not an exact two-line pin")
            hash_match = re.fullmatch(r"    --hash=sha256:([0-9a-f]{64})", lines[index + 1])
            if hash_match is None:
                raise AssertionError("lock entry lacks one exact SHA-256")
            entries[match.group(1)] = (match.group(2), wheel, hash_match.group(1))
            wheel = None
    return entries


class DependencyBoundaryTests(unittest.TestCase):
    def test_python_and_direct_dependencies_are_exact(self) -> None:
        project = tomllib.loads(PROJECT.read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["requires-python"], ">=3.12,<3.13")
        self.assertEqual(
            project["dependencies"],
            ["PyJWT[crypto]==2.13.0", "cryptography==50.0.1"],
        )

    def test_complete_lock_is_exact_hashed_and_expected(self) -> None:
        self.assertEqual(lock_entries(), EXPECTED)

    def test_lock_accepts_only_binary_wheel_filenames(self) -> None:
        for _, filename, _ in lock_entries().values():
            self.assertRegex(filename, r"^[A-Za-z0-9_.-]+\.whl$")
            self.assertNotRegex(filename, r"(?i)(\.tar\.gz|\.tar\.bz2|\.zip|sdist)")
        raw = LOCK.read_text(encoding="utf-8")
        self.assertNotRegex(raw, r"(?i)(\.tar\.gz|\.tar\.bz2|sdist)")

    def test_no_unpinned_unhashed_unexpected_or_gunicorn_dependency(self) -> None:
        raw = (PROJECT.read_text() + LOCK.read_text()).lower()
        self.assertNotIn("gunicorn", raw)
        self.assertEqual(set(lock_entries()), set(EXPECTED))
        self.assertEqual(raw.count("--hash=sha256:"), len(EXPECTED))

    def test_documented_target_and_artifacts_equal_lock_target(self) -> None:
        documentation = DOCUMENTATION.read_text(encoding="utf-8")
        lock = LOCK.read_text(encoding="utf-8")
        for marker in ("Ubuntu 24.04", "Linux x86_64", "CPython 3.12", "glibc"):
            self.assertIn(marker, documentation)
            self.assertIn(marker, lock)
        for version, filename, digest in EXPECTED.values():
            self.assertIn(filename, documentation)
            self.assertIn(digest, documentation)
            self.assertIn(version, documentation)

    def test_offline_install_controls_and_non_claim_are_documented(self) -> None:
        documentation = DOCUMENTATION.read_text(encoding="utf-8")
        for option in ("--require-hashes", "--only-binary=:all:", "--no-index", "--find-links <reviewed-wheelhouse>"):
            self.assertIn(option, documentation)
        self.assertIn("do not establish a production wheelhouse", documentation)
        self.assertIn("Source builds remain forbidden", documentation)

    def test_focused_environment_uses_reviewed_versions(self) -> None:
        if sys.version_info[:2] != (3, 12):
            self.skipTest("lock is qualified only for CPython 3.12")
        for distribution, expected in (("PyJWT", "2.13.0"), ("cryptography", "50.0.1"), ("cffi", "2.1.1"), ("pycparser", "3.0")):
            with self.subTest(distribution=distribution):
                self.assertEqual(importlib.metadata.version(distribution), expected)


if __name__ == "__main__":
    unittest.main()
