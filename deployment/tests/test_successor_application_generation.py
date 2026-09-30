"""C32ZH successor application-generation evidence tests; no host mutation.

These tests prove that merged C32ZG differs from frozen C32W in exactly one
selected application file while runtime and ingress bytes remain unchanged.
"""

from dataclasses import FrozenInstanceError, fields
import hashlib
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from deployment import final_application_generation as c32w
from deployment import successor_application_generation as module
from deployment.application_source_set import DevApplicationSourceSet
from deployment.execution import INGRESS_PATHS


ROOT = Path(__file__).resolve().parents[2]


def git(*args: str) -> bytes:
    """Run deterministic read-only Git plumbing for test evidence."""

    return subprocess.check_output(
        ("/usr/bin/git", "--no-replace-objects", "-C", str(ROOT), *args),
        env={
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
        },
    )


class SuccessorApplicationGenerationTests(unittest.TestCase):
    """Adversarial checks for exact repository-only successor evidence."""

    def test_exact_merge_identity_parents_and_manifest(self) -> None:
        self.assertEqual(
            module.TARGET_REVIEWED_COMMIT,
            "47a602d3f2b97fafd6fb8a18240fd5bbb3857ba9",
        )
        self.assertEqual(
            git("cat-file", "-t", module.TARGET_REVIEWED_COMMIT), b"commit\n",
        )
        raw = git("cat-file", "commit", module.TARGET_REVIEWED_COMMIT)
        parents = tuple(
            line[7:].decode("ascii")
            for line in raw.split(b"\n\n", 1)[0].split(b"\n")
            if line.startswith(b"parent ")
        )
        self.assertEqual(
            parents,
            (
                "218adfcd64e48dba6defc7e4e2327c50f8e30504",
                "a696e10bfb8c2db6c86cf3084dc5bc1c27a8fbbe",
            ),
        )
        evidence = module.review_successor_application_generation()
        self.assertEqual(
            evidence.predecessor_reviewed_commit, c32w.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(evidence.reviewed_commit, module.TARGET_REVIEWED_COMMIT)
        self.assertEqual(evidence.path_count, 41)
        self.assertEqual(
            evidence.manifest_sha256,
            "f0fa38089665e48c84f2a0969875d0fd2d069c96e2d079d7e271aea84c7988db",
        )

    def test_exact_single_application_delta_and_blob_hashes(self) -> None:
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 41)
        changed = tuple(
            path
            for path in paths
            if git("show", f"{c32w.TARGET_REVIEWED_COMMIT}:{path}")
            != git("show", f"{module.TARGET_REVIEWED_COMMIT}:{path}")
        )
        self.assertEqual(changed, ("deployment/docker_runtime.py",))
        self.assertEqual(changed, module.TARGET_PLAN)
        self.assertEqual(
            hashlib.sha256(("\n".join(changed) + "\n").encode()).hexdigest(),
            module.TARGET_PLAN_SHA256,
        )
        predecessor = git(
            "show", f"{c32w.TARGET_REVIEWED_COMMIT}:deployment/docker_runtime.py",
        )
        target = git(
            "show", f"{module.TARGET_REVIEWED_COMMIT}:deployment/docker_runtime.py",
        )
        self.assertEqual(
            hashlib.sha256(predecessor).hexdigest(),
            module.PREDECESSOR_DOCKER_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(target).hexdigest(), module.TARGET_DOCKER_SHA256,
        )

    def test_runtime_and_ingress_are_identical_to_c32w(self) -> None:
        runtime = "deployment/runtime/dev/canary-runtime.json"
        paths = (runtime, *INGRESS_PATHS)
        predecessor = tuple(
            git("show", f"{c32w.TARGET_REVIEWED_COMMIT}:{path}") for path in paths
        )
        target = tuple(
            git("show", f"{module.TARGET_REVIEWED_COMMIT}:{path}") for path in paths
        )
        self.assertEqual(target, predecessor)
        evidence = module.review_successor_application_generation()
        self.assertEqual(
            evidence.runtime_configuration_sha256, c32w.TARGET_RUNTIME_SHA256,
        )
        self.assertEqual(evidence.ingress_file_sha256, c32w.TARGET_INGRESS_SHA256)

    def test_evidence_is_immutable_closed_and_fail_closed(self) -> None:
        evidence = module.review_successor_application_generation()
        for item in fields(evidence):
            with self.assertRaises(FrozenInstanceError):
                setattr(evidence, item.name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(evidence, item.name)
        values = {item.name: getattr(evidence, item.name) for item in fields(evidence)}
        for field, bad in (
            ("reviewed_commit", "a" * 40),
            ("path_count", True),
            ("manifest_sha256", "0" * 64),
            ("changed_paths", ("deployment/state.py",)),
            ("plan_sha256", "0" * 64),
            ("target_docker_sha256", "0" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.SuccessorApplicationGenerationEvidence(
                    **(values | {field: bad})
                )
        with patch.object(module, "TARGET_MANIFEST_SHA256", "0" * 64), self.assertRaises(
            module.SuccessorApplicationGenerationError,
        ):
            module.review_successor_application_generation()
        with patch.object(module, "TARGET_PLAN", ("deployment/state.py",)), self.assertRaises(
            module.SuccessorApplicationGenerationError,
        ):
            module.review_successor_application_generation()

    def test_repository_only_boundary_and_historical_c32w_remain_pinned(self) -> None:
        source = (
            ROOT / "deployment/successor_application_generation.py"
        ).read_text()
        for forbidden in (
            "urllib", "requests", "http.client", "socket.socket",
            "os.environ", "os.getenv", "git pull", "git fetch",
            "systemctl", "docker compose", "__main__",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(
            c32w.TARGET_REVIEWED_COMMIT,
            "e4f0030c7a028beb834618254781c2fbff5d6b0d",
        )
        self.assertEqual(
            c32w.TARGET_MANIFEST_SHA256,
            "774391d16235855222aa4dedb617112cccc9a862d1599d2546c08b5f8b17c8f9",
        )
        self.assertEqual(module.PREDECESSOR_REVIEWED_COMMIT, c32w.TARGET_REVIEWED_COMMIT)
        self.assertEqual(module.TARGET_PATHS_SHA256, c32w.TARGET_PATHS_SHA256)
        self.assertEqual(module.TARGET_RUNTIME_SHA256, c32w.TARGET_RUNTIME_SHA256)
        self.assertEqual(module.TARGET_INGRESS_SHA256, c32w.TARGET_INGRESS_SHA256)
        self.assertNotIn(
            "deployment/successor_application_generation.py",
            tuple(
                item.repository_path for item in DevApplicationSourceSet().files
            ),
        )


if __name__ == "__main__":
    unittest.main()
