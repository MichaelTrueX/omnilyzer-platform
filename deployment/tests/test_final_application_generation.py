"""C32W pinned Git-object and source-freeze evidence; no host operations."""

from dataclasses import FrozenInstanceError, fields
import hashlib
import importlib
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from deployment import application_manifest as c26
from deployment import dev_post_c31_application_update as c32d
from deployment.application_source_set import DevApplicationSourceSet
import deployment.final_application_generation as module
from deployment.execution import INGRESS_PATHS


ROOT = Path(__file__).resolve().parents[2]


def git(*args):
    return subprocess.check_output(("/usr/bin/git", "--no-replace-objects", "-C", str(ROOT), *args),
                                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
                                        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                                        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1"})


class FrozenGenerationTests(unittest.TestCase):
    def test_exact_git_target_manifest_and_path_evidence(self):
        self.assertEqual(module.TARGET_REVIEWED_COMMIT,
                         "e4f0030c7a028beb834618254781c2fbff5d6b0d")
        self.assertEqual(git("cat-file", "-t", module.TARGET_REVIEWED_COMMIT), b"commit\n")
        raw = git("cat-file", "commit", module.TARGET_REVIEWED_COMMIT)
        parents = tuple(line[7:].decode() for line in raw.split(b"\n\n", 1)[0].split(b"\n")
                        if line.startswith(b"parent "))
        self.assertEqual(parents, (module.TARGET_FIRST_PARENT, module.TARGET_SECOND_PARENT))
        self.assertEqual(parents, ("fb9927f7a75a636e73800cbe3b3a62ed1e10e6eb",
                                   "02711ed4fab2984282f5e3a860f272b2ef726a71"))
        paths = c26._current_paths()
        self.assertEqual((len(paths), module.TARGET_PATH_COUNT), (41, 41))
        self.assertEqual(hashlib.sha256(("\n".join(paths) + "\n").encode()).hexdigest(),
                         module.TARGET_PATHS_SHA256)
        selected = DevApplicationSourceSet().files
        self.assertEqual((sum(x.kind == "python-module" for x in selected),
                          sum(x.kind == "runtime-data" for x in selected)), (38, 3))
        entries = []
        successor_deltas = []
        for path in paths:
            record = git("ls-tree", "-z", module.TARGET_REVIEWED_COMMIT, "--", path)
            mode, kind, rest = record.split(b" ", 2)
            oid, recorded_path = rest[:-1].split(b"\t")
            self.assertEqual((mode, kind, recorded_path), (b"100644", b"blob", path.encode()))
            data = git("cat-file", "blob", oid.decode())
            entries.append(c26.ApplicationManifestEntry(path, hashlib.sha256(data).hexdigest(), "0644"))
            if (ROOT / path).read_bytes() != data:
                successor_deltas.append(path)
        self.assertEqual(tuple(successor_deltas), ("deployment/docker_runtime.py", "deployment/state_store.py"))
        manifest = c26.DevApplicationManifest("canonical-relative-file-set-v1", "sha256",
                                             module.TARGET_REVIEWED_COMMIT, tuple(entries))
        self.assertEqual(hashlib.sha256(manifest.canonical_bytes()).hexdigest(),
                         module.TARGET_MANIFEST_SHA256)
        self.assertEqual(module.TARGET_MANIFEST_SHA256,
                         "774391d16235855222aa4dedb617112cccc9a862d1599d2546c08b5f8b17c8f9")

    def test_runtime_ingress_hashes_and_outside_app_file(self):
        paths = c26._current_paths()
        runtime = "deployment/runtime/dev/canary-runtime.json"
        self.assertEqual(INGRESS_PATHS, (
            "deployment/runtime/dev/compose.yaml", "deployment/runtime/dev/host-nginx.conf",
            "deployment/runtime/dev/nginx/nginx.conf"))
        self.assertIn(runtime, paths)
        self.assertNotIn(INGRESS_PATHS[1], paths)
        digests = tuple(hashlib.sha256(git("show", f"{module.TARGET_REVIEWED_COMMIT}:{path}"))
                        .hexdigest() for path in (runtime, *INGRESS_PATHS))
        self.assertEqual(digests, (module.TARGET_RUNTIME_SHA256, *module.TARGET_INGRESS_SHA256))
        self.assertEqual(digests, (
            "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f",
            "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
            "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
            "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
        ))
        review = module.review_final_application_generation()
        self.assertEqual((review.path_count, review.python_count, review.runtime_data_count),
                         (41, 38, 3))
        self.assertEqual(review.runtime_configuration_sha256, digests[0])
        self.assertEqual(review.ingress_file_sha256, digests[1:])

    def test_evidence_immutable_closed_and_fail_closed(self):
        result = module.review_final_application_generation()
        for item in fields(result):
            with self.assertRaises(FrozenInstanceError):
                setattr(result, item.name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, item.name)
        for field, bad in (("path_count", True), ("manifest_sha256", "0" * 64),
                           ("runtime_configuration_sha256", "0" * 64),
                           ("ingress_file_sha256", ("0" * 64,) * 3)):
            values = {item.name: getattr(result, item.name) for item in fields(result)}
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.FinalApplicationGenerationEvidence(**(values | {field: bad}))
        with patch.object(module, "TARGET_MANIFEST_SHA256", "0" * 64), \
             self.assertRaises(module.FinalApplicationGenerationError):
            module.review_final_application_generation()
        with patch.object(module, "TARGET_INGRESS_SHA256", ("0" * 64,) * 3), \
             self.assertRaises(module.FinalApplicationGenerationError):
            module.review_final_application_generation()
        with patch.object(module, "TARGET_REVIEWED_COMMIT", c32d.TARGET), \
             self.assertRaises(module.FinalApplicationGenerationError):
            module.review_final_application_generation()

    def test_historical_and_repository_only_freeze(self):
        for path in ("deployment/application_source_set.py", "deployment/application_manifest.py",
                     "deployment/dev_post_c31_application_update.py"):
            self.assertEqual((ROOT / path).read_bytes(),
                             git("show", f"{module.TARGET_REVIEWED_COMMIT}:{path}"))
        self.assertEqual((len(c26._predecessor_paths()), len(c26._paths())), (28, 31))
        self.assertEqual((c32d.PREDECESSOR_C26, c32d.TARGET_C26), (
            "7a89fd0e7f67daa17c772ec9e9058863ff25041ed57b7828d7cce2329ccdb419",
            "4e0079a4528f3cba7669062b38e6b8d899be237dab51fb957d97331f09686c03"))
        selected = set(c26._current_paths())
        self.assertNotIn("deployment/final_application_generation.py", selected)
        self.assertNotIn("deployment/dev_final_application_update.py", selected)
        self.assertNotIn("deployment/runtime/dev/host-nginx.conf", selected)
        self.assertFalse(any("/systemd/" in p or "/ingress/" in p for p in selected))
        source = (ROOT / "deployment/final_application_generation.py").read_text()
        for forbidden in ("urllib", "requests", "http.client", "socket.socket", "time.time",
                          "os.environ", "os.getenv", "git pull", "git fetch", "__main__"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
