"""Deterministic OCI fixture tests."""

from __future__ import annotations

import gzip
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest


SPIKE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SPIKE))

from durability.fixture import (  # noqa: E402
    CONFIG_MEDIA_TYPE,
    LAYER_MEDIA_TYPE,
    MANIFEST_MEDIA_TYPE,
    build_fixture,
    sha256_digest,
)


class FixtureTests(unittest.TestCase):
    def test_fixture_is_deterministic_and_distinct(self) -> None:
        first = build_fixture()
        second = build_fixture()
        self.assertEqual(first, second)
        for attribute in ("manifest", "config", "layer"):
            self.assertNotEqual(getattr(first[0], attribute), getattr(first[1], attribute))

    def test_exact_tags_and_local_digests(self) -> None:
        current, rollback = build_fixture()
        self.assertEqual(current.tag, "task012-current")
        self.assertEqual(rollback.tag, "task012-rollback")
        for release in (current, rollback):
            for kind in ("manifest", "config", "layer"):
                self.assertEqual(
                    sha256_digest(getattr(release, kind)), getattr(release, f"{kind}_digest")
                )

    def test_manifest_descriptors_are_exact(self) -> None:
        for release in build_fixture():
            manifest = json.loads(release.manifest)
            self.assertEqual(manifest["schemaVersion"], 2)
            self.assertEqual(manifest["mediaType"], MANIFEST_MEDIA_TYPE)
            self.assertEqual(manifest["config"], {
                "mediaType": CONFIG_MEDIA_TYPE,
                "digest": release.config_digest,
                "size": len(release.config),
            })
            self.assertEqual(manifest["layers"], [{
                "mediaType": LAYER_MEDIA_TYPE,
                "digest": release.layer_digest,
                "size": len(release.layer),
            }])

    def test_layers_are_harmless_single_file_archives(self) -> None:
        for release in build_fixture():
            with tarfile.open(fileobj=io.BytesIO(gzip.decompress(release.layer)), mode="r:") as archive:
                members = archive.getmembers()
                self.assertEqual([member.name for member in members], ["evidence.txt"])
                self.assertTrue(members[0].isreg())
                content = archive.extractfile(members[0])
                self.assertIsNotNone(content)
                self.assertIn(b"synthetic durability fixture", content.read())

    def test_recorded_lengths_are_exact(self) -> None:
        for release in build_fixture():
            evidence = release.evidence()
            self.assertEqual(evidence["manifest_length"], len(release.manifest))
            self.assertEqual(evidence["config_length"], len(release.config))
            self.assertEqual(evidence["layer_length"], len(release.layer))


if __name__ == "__main__":
    unittest.main()
