"""File: release/tests/test_analytics_oci_archive.py

Purpose: Isolated adversarial OCI-content validation for Analytics PR45 using
the existing original Task013 source admission and runtime review contract.
Links: release/analytics_oci_archive.py, analytics_task013_build_input.py,
release/executable_oci.py and .github/workflows/platform-release.yml.
Tests never sign, publish, deploy or contact protected infrastructure.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from deployment.policy import DeploymentPolicyError, canonical_bytes
from release.analytics_oci_archive import (
    EXPECTED_CMD, OCI_CONFIG, OCI_INDEX, OCI_LAYERS, OCI_MANIFEST, verify_archive,
)
from release.analytics_task013_build_input import build_input

RECEIPT = {
    "input_kind": "task013-analytics-oci-review-only",
    "oci_repository": "omnilyzer/analytics",
    "readiness_path": "/readyz",
    "source_files_verified": 76,
    "release_authorized": False,
    "deployment_authorized": False,
    "analytics_source_commit": "b2a02e54cb5d51f06cb56b9f9d7aa7ca2fae2a50",
    "analytics_tree": "09a4a2a63c1db3bbe8774b8292d78e8d653ece63",
    "dockerfile_sha256": "a" * 64,
    "dockerignore_sha256": "b" * 64,
    "oci_test_source_sha256": "c" * 64,
    "source_manifest_sha256": "d" * 64,
}


def _descriptor(media_type: str, raw: bytes) -> dict:
    """Create a valid content-addressed OCI descriptor for test metadata."""
    return {"mediaType": media_type, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "size": len(raw)}


def build_test_archive(path: Path, *, runtime_patch: dict | None = None,
                       corrupt_layer: bool = False, added_name: str | None = None,
                       duplicate_index: bool = False, double_manifest: bool = False) -> None:
    """Create structural OCI fixtures, never runnable production images."""
    layer = gzip.compress(b"synthetic tar content, never an executable layer")
    runtime = {
        "User": "10001:10001", "WorkingDir": "/srv/omnilyzer",
        "Env": ["NODE_ENV=production", "NEXT_TELEMETRY_DISABLED=1"],
        "Entrypoint": ["docker-entrypoint.sh"], "Cmd": EXPECTED_CMD,
        "ExposedPorts": {"3000/tcp": {}},
    }
    runtime.update(runtime_patch or {})
    config = canonical_bytes({
        "architecture": "amd64", "os": "linux", "config": runtime,
        "rootfs": {"type": "layers", "diff_ids": [
            "sha256:" + hashlib.sha256(b"synthetic tar content, never an executable layer").hexdigest()
        ]},
    })
    layer_desc = _descriptor("application/vnd.oci.image.layer.v1.tar+gzip", layer)
    config_desc = _descriptor(OCI_CONFIG, config)
    manifest = canonical_bytes({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": config_desc, "layers": [layer_desc],
    })
    manifest_desc = _descriptor(OCI_MANIFEST, manifest)
    index = canonical_bytes({
        "schemaVersion": 2, "mediaType": OCI_INDEX,
        "manifests": [manifest_desc, manifest_desc] if double_manifest else [manifest_desc],
    })
    blobs = {
        "blobs/sha256/" + config_desc["digest"][7:]: config,
        "blobs/sha256/" + manifest_desc["digest"][7:]: manifest,
        "blobs/sha256/" + layer_desc["digest"][7:]: (
            layer[:-1] + b"X" if corrupt_layer else layer
        ),
    }
    files = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": index,
        **blobs,
    }
    if added_name is not None:
        files[added_name] = b"extra"
    with tarfile.open(path, "w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if duplicate_index:
            info = tarfile.TarInfo("index.json")
            info.size = len(index)
            tar.addfile(info, io.BytesIO(index))


class AnalyticsOCIArchiveTests(unittest.TestCase):
    """Ensure unsigned product verification remains strict and deterministic."""

    def _run_fixture(self, **options) -> dict:
        """Build one disposable OCI fixture and invoke production validator."""
        with tempfile.TemporaryDirectory() as root:
            image = Path(root) / "source.oci.tar"
            build_test_archive(image, **options)
            return verify_archive(image, dict(RECEIPT))

    def test_valid_structural_fixture_is_explicitly_unsigned(self) -> None:
        """A structurally correct archive returns a local digest, no authority."""
        receipt = self._run_fixture()
        self.assertTrue(receipt["local_manifest_digest"].startswith("sha256:"))
        self.assertEqual(receipt["oci_repository"], "omnilyzer/analytics")
        self.assertFalse(receipt["release_authorized"])
        self.assertFalse(receipt["deployment_authorized"])

    def test_embedded_runtime_secret_is_denied(self) -> None:
        """Reject accidental build-time credentials exposed in image Env."""
        with self.assertRaises(DeploymentPolicyError):
            self._run_fixture(runtime_patch={"Env": ["DATABASE_URL=postgresql://sensitive@host/db"]})

    def test_wrong_uid_and_port_are_denied(self) -> None:
        """Prevent root containers and incorrect port/proxy contracts."""
        for change in ({"User": "0:0"}, {"ExposedPorts": {"8080/tcp": {}}},
                       {"WorkingDir": "/tmp"}, {"Entrypoint": ["/bin/sh"]}, {"Cmd": ["sh", "-c", "sleep infinity"]}):
            with self.subTest(change=change), self.assertRaises(DeploymentPolicyError):
                self._run_fixture(runtime_patch=change)

    def test_modified_blob_without_digest_update_denied(self) -> None:
        """An OCI layer cannot change after its content-addressed manifest."""
        with self.assertRaises(DeploymentPolicyError):
            self._run_fixture(corrupt_layer=True)

    def test_extra_blob_and_traversal_denied(self) -> None:
        """Reject unreferenced artifacts and unsafe tar members."""
        for name in ("../../etc/passwd", "blobs/sha256/" + "e" * 64, "secrets.json"):
            with self.subTest(name=name), self.assertRaises(DeploymentPolicyError):
                self._run_fixture(added_name=name)

    def test_duplicate_tar_entry_denied(self) -> None:
        """Reject ambiguous OCI index overwrites."""
        with self.assertRaises(DeploymentPolicyError):
            self._run_fixture(duplicate_index=True)

    def test_attestation_or_multi_image_index_denied(self) -> None:
        """No unexamined extra images can accompany the signed subject."""
        with self.assertRaises(DeploymentPolicyError):
            self._run_fixture(double_manifest=True)

    def test_authorization_must_remain_false(self) -> None:
        """Caller-supplied approval flags are not legitimate release authority."""
        with tempfile.TemporaryDirectory() as root:
            image = Path(root) / "image.tar"
            build_test_archive(image)
            with self.assertRaises(DeploymentPolicyError):
                verify_archive(image, dict(RECEIPT, release_authorized=True))

    def test_nonregular_archive_denied(self) -> None:
        """Reject symlink archive sources to avoid source switching."""
        with tempfile.TemporaryDirectory() as root:
            image = Path(root) / "image.tar"
            alias = Path(root) / "alias.tar"
            build_test_archive(image)
            alias.symlink_to(image)
            with self.assertRaises(DeploymentPolicyError):
                verify_archive(alias, dict(RECEIPT))

    def test_actual_oci_archive_when_supplied(self) -> None:
        """Exercise exact PR45 on genuine local OCI export, never registry."""
        image = os.environ.get("OMNILYZER_ANALYTICS_OCI_ARCHIVE")
        checkout = os.environ.get("OMNILYZER_ANALYTICS_CHECKOUT")
        if not image or not checkout:
            self.skipTest("optional clean Analytics source and OCI archive not supplied")
        receipt = build_input(Path(checkout))
        checked = verify_archive(Path(image), receipt)
        self.assertEqual(checked["source_commit"], receipt["analytics_source_commit"])
        self.assertFalse(checked["release_authorized"])
        self.assertFalse(checked["deployment_authorized"])


if __name__ == "__main__":
    unittest.main()
