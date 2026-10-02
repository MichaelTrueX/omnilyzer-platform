"""C33AD state-store successor application-generation evidence tests."""

from dataclasses import FrozenInstanceError, fields
import hashlib
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from deployment import successor_application_generation as c32zh
from deployment import state_store_successor_application_generation as module
from deployment.application_source_set import DevApplicationSourceSet
from deployment.execution import INGRESS_PATHS


ROOT = Path(__file__).resolve().parents[2]


def git(*args: str) -> bytes:
    """Run deterministic read-only Git plumbing for generation evidence."""

    return subprocess.check_output(
        ("/usr/bin/git", "--no-replace-objects", "-C", str(ROOT), *args),
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
        },
    )


class StateStoreSuccessorApplicationGenerationTests(unittest.TestCase):
    """Adversarial checks for exact repository-only C33AD evidence."""

    def test_exact_merge_identity_parents_and_manifest(self) -> None:
        self.assertEqual(
            module.TARGET_REVIEWED_COMMIT,
            "f2ece4257b84090b1a6fff5d1aa7f0b6047765cd",
        )
        self.assertEqual(
            git("cat-file", "-t", module.TARGET_REVIEWED_COMMIT),
            b"commit\n",
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
                "48f1280302f85cb8db1af9bb25f1ab15382ae8cb",
                "9a02a829a78502d8bb224a3f6347ba5806d98a11",
            ),
        )
        evidence = (
            module.review_state_store_successor_application_generation()
        )
        self.assertEqual(
            evidence.predecessor_reviewed_commit,
            c32zh.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(
            evidence.reviewed_commit,
            module.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(evidence.path_count, 41)
        self.assertEqual(
            evidence.manifest_sha256,
            "3efb117dbaebfefc264d4373e476973aed1dfc9ebb3035998a7778ea229e91e4",
        )

    def test_exact_single_application_delta_and_blob_hashes(self) -> None:
        paths = tuple(
            item.repository_path for item in DevApplicationSourceSet().files
        )
        changed = tuple(
            path
            for path in paths
            if git(
                "show",
                f"{c32zh.TARGET_REVIEWED_COMMIT}:{path}",
            )
            != git("show", f"{module.TARGET_REVIEWED_COMMIT}:{path}")
        )
        self.assertEqual(changed, ("deployment/state_store.py",))
        self.assertEqual(changed, module.TARGET_PLAN)
        self.assertEqual(
            hashlib.sha256(
                ("\n".join(changed) + "\n").encode()
            ).hexdigest(),
            module.TARGET_PLAN_SHA256,
        )

        predecessor = git(
            "show",
            (
                f"{c32zh.TARGET_REVIEWED_COMMIT}:"
                "deployment/state_store.py"
            ),
        )
        target = git(
            "show",
            (
                f"{module.TARGET_REVIEWED_COMMIT}:"
                "deployment/state_store.py"
            ),
        )
        self.assertEqual(
            hashlib.sha256(predecessor).hexdigest(),
            module.PREDECESSOR_STATE_STORE_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(target).hexdigest(),
            module.TARGET_STATE_STORE_SHA256,
        )

    def test_runtime_and_ingress_remain_identical(self) -> None:
        runtime = "deployment/runtime/dev/canary-runtime.json"
        paths = (runtime, *INGRESS_PATHS)
        predecessor = tuple(
            git("show", f"{c32zh.TARGET_REVIEWED_COMMIT}:{path}")
            for path in paths
        )
        target = tuple(
            git("show", f"{module.TARGET_REVIEWED_COMMIT}:{path}")
            for path in paths
        )
        self.assertEqual(target, predecessor)
        evidence = (
            module.review_state_store_successor_application_generation()
        )
        self.assertEqual(
            evidence.runtime_configuration_sha256,
            c32zh.TARGET_RUNTIME_SHA256,
        )
        self.assertEqual(
            evidence.ingress_file_sha256,
            c32zh.TARGET_INGRESS_SHA256,
        )

    def test_predecessor_generation_remains_historically_pinned(self) -> None:
        self.assertEqual(
            c32zh.TARGET_REVIEWED_COMMIT,
            "47a602d3f2b97fafd6fb8a18240fd5bbb3857ba9",
        )
        self.assertEqual(
            module.PREDECESSOR_REVIEWED_COMMIT,
            c32zh.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(
            module.TARGET_PATHS_SHA256,
            c32zh.TARGET_PATHS_SHA256,
        )
        self.assertEqual(
            module.TARGET_RUNTIME_SHA256,
            c32zh.TARGET_RUNTIME_SHA256,
        )
        self.assertEqual(
            module.TARGET_INGRESS_SHA256,
            c32zh.TARGET_INGRESS_SHA256,
        )

    def test_evidence_is_immutable_closed_and_fail_closed(self) -> None:
        evidence = (
            module.review_state_store_successor_application_generation()
        )
        for item in fields(evidence):
            with self.assertRaises(FrozenInstanceError):
                setattr(evidence, item.name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(evidence, item.name)

        values = {
            item.name: getattr(evidence, item.name)
            for item in fields(evidence)
        }
        for field, bad in (
            ("reviewed_commit", "a" * 40),
            ("path_count", True),
            ("manifest_sha256", "0" * 64),
            ("changed_paths", ("deployment/docker_runtime.py",)),
            ("plan_sha256", "0" * 64),
            ("target_state_store_sha256", "0" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.StateStoreSuccessorApplicationGenerationEvidence(
                    **(values | {field: bad})
                )

        with patch.object(
            module,
            "TARGET_MANIFEST_SHA256",
            "0" * 64,
        ), self.assertRaises(
            module.StateStoreSuccessorApplicationGenerationError,
        ):
            module.review_state_store_successor_application_generation()

        with patch.object(
            module,
            "TARGET_PLAN",
            ("deployment/docker_runtime.py",),
        ), self.assertRaises(
            module.StateStoreSuccessorApplicationGenerationError,
        ):
            module.review_state_store_successor_application_generation()

    def test_repository_only_boundary_and_source_set_exclusion(self) -> None:
        source = (
            ROOT
            / "deployment/state_store_successor_application_generation.py"
        ).read_text()
        for forbidden in (
            "urllib",
            "requests",
            "http.client",
            "socket.socket",
            "os.environ",
            "os.getenv",
            "git pull",
            "git fetch",
            "systemctl",
            "docker compose",
            "__main__",
        ):
            self.assertNotIn(forbidden, source)

        selected = tuple(
            item.repository_path
            for item in DevApplicationSourceSet().files
        )
        self.assertNotIn(
            "deployment/state_store_successor_application_generation.py",
            selected,
        )


if __name__ == "__main__":
    unittest.main()
