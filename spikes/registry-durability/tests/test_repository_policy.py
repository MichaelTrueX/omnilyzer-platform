"""Repository and architecture boundaries for the removable Task 012 spike."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest


SPIKE = Path(__file__).resolve().parents[1]
ROOT = SPIKE.parents[1]
sys.path.insert(0, str(SPIKE))


PROTECTED_HASHES = {
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


class RepositoryPolicyTests(unittest.TestCase):
    def test_no_third_party_python_dependencies(self) -> None:
        project = tomllib.loads((SPIKE / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["dependencies"], [])

    def test_task012_scope_does_not_modify_task008_workflows_or_triggers(self) -> None:
        for relative, expected in PROTECTED_HASHES.items():
            with self.subTest(path=relative):
                observed = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(observed, expected)

    def test_historical_task012a_commit_stayed_within_its_documentation_scope(self) -> None:
        tracked = subprocess.run(
            [
                "git", "diff", "--name-only",
                "d0a60345e0bcd21777efbc15738f90ce56d3a80a",
                "797c8f4c8080069a17eb73b958d017fc5c6deafc",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        allowed_files = {"spikes/README.md", "docs/architecture/technology-decisions.md"}
        for path in tracked:
            with self.subTest(path=path):
                self.assertTrue(path.startswith("spikes/registry-durability/") or path in allowed_files)

    def test_no_external_registry_or_live_zot_paths_in_runtime_clients(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((SPIKE / "durability").glob("*.py"))
        ) + (SPIKE / "validate_zot_recovery.py").read_text(encoding="utf-8")
        self.assertNotIn("oci-dev.omnilyzer.ai", sources)
        self.assertNotIn("registry-dev.omnilyzer.ai", sources)
        self.assertNotIn("systemctl", sources)
        self.assertIn('"127.0.0.1"', sources)
        self.assertNotIn('"0.0.0.0"', sources)
        self.assertNotIn('"::"', sources)

    def test_accepted_registry_architecture_is_not_reopened(self) -> None:
        adr = (ROOT / "docs/adr/0010-forgejo-and-zot-package-registries.md").read_text()
        decisions = (ROOT / "docs/architecture/technology-decisions.md").read_text()
        self.assertIn("- Status: Accepted", adr)
        row = next(
            line for line in decisions.splitlines()
            if line.startswith("| Package registry / trusted publishing |")
        )
        self.assertIn("| ACCEPTED DIRECTION |", row)
        self.assertIn("Forgejo + protected Nginx ingress", row)
        self.assertIn("zot for OCI", row)

    def test_no_task012_github_workflow_was_added(self) -> None:
        self.assertEqual(list((ROOT / ".github/workflows").glob("*012*")), [])


if __name__ == "__main__":
    unittest.main()
